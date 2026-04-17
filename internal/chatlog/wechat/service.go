package wechat

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"

	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/wechat"
	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	"github.com/sjzar/chatlog/internal/wechat/decrypt/common"
	"github.com/sjzar/chatlog/pkg/filemonitor"
	"github.com/sjzar/chatlog/pkg/util"
)

var (
	DebounceTime = 1 * time.Second
	MaxWaitTime  = 10 * time.Second
)

type Service struct {
	conf           Config
	lastEvents     map[string]time.Time
	pendingActions map[string]bool
	pendingEvents  map[string]*pendingEvent
	walStates      map[string]*walState
	mutex          sync.Mutex
	fm             *filemonitor.FileMonitor
	errorHandler   func(error)
}

type pendingEvent struct {
	sawDB  bool
	sawWal bool
}

type walState struct {
	offset int64
	salt1  uint32
	salt2  uint32
}

type walFrame struct {
	pageNo uint32
	data   []byte
}

type Config interface {
	GetDataKey() string
	GetDataDir() string
	GetWorkDir() string
	GetPlatform() string
	GetVersion() int
	GetWalEnabled() bool
	GetAutoDecryptDebounce() int
}

func NewService(conf Config) *Service {
	return &Service{
		conf:           conf,
		lastEvents:     make(map[string]time.Time),
		pendingActions: make(map[string]bool),
		pendingEvents:  make(map[string]*pendingEvent),
		walStates:      make(map[string]*walState),
	}
}

func (s *Service) clearWalState(dbFile string) {
	s.mutex.Lock()
	delete(s.walStates, dbFile)
	s.mutex.Unlock()
}

// SetAutoDecryptErrorHandler sets the callback for auto decryption errors
func (s *Service) SetAutoDecryptErrorHandler(handler func(error)) {
	s.errorHandler = handler
}

// isFileLockedError checks if the error is a file locking error (temporary error that shouldn't stop the service)
func isFileLockedError(err error) bool {
	if err == nil {
		return false
	}

	// Check for Windows file locking errors
	// ERROR_SHARING_VIOLATION (32): The process cannot access the file because it is being used by another process
	// ERROR_LOCK_VIOLATION (33): The process cannot access the file because another process has locked a portion of the file
	if errno, ok := err.(syscall.Errno); ok {
		if errno == 32 || errno == 33 {
			return true
		}
	}

	// Check wrapped errors first (to get to the root cause)
	if wrappedErr := errors.RootCause(err); wrappedErr != nil && wrappedErr != err {
		if isFileLockedError(wrappedErr) {
			return true
		}
	}

	// Check error message for file locking indicators (works across platforms)
	errMsg := strings.ToLower(err.Error())
	fileLockIndicators := []string{
		"the process cannot access the file",
		"being used by another process",
		"file is locked",
		"access is denied",
		"sharing violation",
		"lock violation",
		"resource temporarily unavailable", // Linux/Unix
		"device or resource busy",         // Linux/Unix
	}
	for _, indicator := range fileLockIndicators {
		if strings.Contains(errMsg, indicator) {
			return true
		}
	}

	return false
}

// GetWeChatInstances returns all running WeChat instances
func (s *Service) GetWeChatInstances() []*wechat.Account {
	instances, _ := s.GetWeChatInstancesWithError()
	return instances
}

func (s *Service) GetWeChatInstancesWithError() ([]*wechat.Account, error) {
	if err := wechat.Load(); err != nil {
		return nil, err
	}
	return wechat.GetAccounts(), nil
}

// GetDataKey extracts the encryption key from a WeChat process
func (s *Service) GetDataKey(info *wechat.Account) (string, error) {
	if info == nil {
		return "", fmt.Errorf("no WeChat instance selected")
	}

	key, _, err := info.GetKey(context.Background())
	if err != nil {
		return "", err
	}

	return key, nil
}

// GetImageKey extracts the image key from a WeChat process
func (s *Service) GetImageKey(info *wechat.Account) (string, error) {
	if info == nil {
		return "", fmt.Errorf("no WeChat instance selected")
	}

	return info.GetImageKey(context.Background())
}

func (s *Service) StartAutoDecrypt() error {
	log.Info().Msgf("start auto decrypt, data dir: %s", s.conf.GetDataDir())
	pattern := `.*\.db$`
	if s.conf.GetWalEnabled() {
		pattern = `.*\.db(-wal|-shm)?$`
	}
	dbGroup, err := filemonitor.NewFileGroup("wechat", s.conf.GetDataDir(), pattern, []string{"fts"})
	if err != nil {
		return err
	}
	dbGroup.AddCallback(s.DecryptFileCallback)

	s.fm = filemonitor.NewFileMonitor()
	s.fm.AddGroup(dbGroup)
	if err := s.fm.Start(); err != nil {
		log.Debug().Err(err).Msg("failed to start file monitor")
		return err
	}
	return nil
}

func (s *Service) StopAutoDecrypt() error {
	if s.fm != nil {
		if err := s.fm.Stop(); err != nil {
			return err
		}
	}
	s.fm = nil
	return nil
}

func (s *Service) DecryptFileCallback(event fsnotify.Event) error {
	// Local file system
	// WRITE         "/db_storage/message/message_0.db"
	// WRITE         "/db_storage/message/message_0.db"
	// WRITE|CHMOD   "/db_storage/message/message_0.db"
	// Syncthing
	// REMOVE        "/app/data/db_storage/session/session.db"
	// CREATE        "/app/data/db_storage/session/session.db" ← "/app/data/db_storage/session/.syncthing.session.db.tmp"
	// CHMOD         "/app/data/db_storage/session/session.db"
	if !(event.Op.Has(fsnotify.Write) || event.Op.Has(fsnotify.Create)) {
		return nil
	}

	dbFile := s.normalizeDBFile(event.Name)
	isWal := isWalFile(event.Name)
	s.mutex.Lock()
	s.lastEvents[dbFile] = time.Now()
	flags, ok := s.pendingEvents[dbFile]
	if !ok {
		flags = &pendingEvent{}
		s.pendingEvents[dbFile] = flags
	}
	if isWal {
		flags.sawWal = true
	} else {
		flags.sawDB = true
	}

	if !s.pendingActions[dbFile] {
		s.pendingActions[dbFile] = true
		s.mutex.Unlock()
		go s.waitAndProcess(dbFile)
	} else {
		s.mutex.Unlock()
	}

	return nil
}

func (s *Service) waitAndProcess(dbFile string) {
	start := time.Now()
	for {
		debounce := s.getDebounceTimeForFile(dbFile)
		maxWait := s.getMaxWaitTimeForFile(dbFile)
		time.Sleep(debounce)

		s.mutex.Lock()
		lastEventTime := s.lastEvents[dbFile]
		elapsed := time.Since(lastEventTime)
		totalElapsed := time.Since(start)

		if elapsed >= debounce || totalElapsed >= maxWait {
			s.pendingActions[dbFile] = false
			flags := pendingEvent{}
			if state, ok := s.pendingEvents[dbFile]; ok && state != nil {
				flags = *state
			}
			s.pendingEvents[dbFile] = &pendingEvent{}
			s.mutex.Unlock()

			if _, err := os.Stat(dbFile); err != nil {
				return
			}
			log.Debug().Msgf("Processing file: %s", dbFile)
			workCopyExists := false
			if s.conf.GetWorkDir() != "" {
				if relPath, err := filepath.Rel(s.conf.GetDataDir(), dbFile); err == nil {
					output := filepath.Join(s.conf.GetWorkDir(), relPath)
					if _, err := os.Stat(output); err == nil {
						workCopyExists = true
					}
				}
			}
			// 核心逻辑：优先尝试 WAL 增量解密，失败则回退全量解密
			if flags.sawDB {
				if !s.conf.GetWalEnabled() || !workCopyExists {
					// WAL 未开启或工作目录不存在 → 直接全量解密
					if err := s.DecryptDBFile(dbFile); err != nil {
						if isFileLockedError(err) {
							// 文件锁定错误：只记录警告，不停止服务
							log.Warn().Err(err).Msgf("文件被锁定，跳过解密: %s", dbFile)
						} else if s.errorHandler != nil {
							// 其他严重错误：调用错误处理器
							s.errorHandler(err)
						}
					}
					return
				}
				// WAL 开启且工作目录存在
				if flags.sawWal {
					// 同时看到 .db 和 WAL 变更 → 尝试增量解密
					applied, err := s.IncrementalDecryptDBFile(dbFile)
					if err != nil {
						if isFileLockedError(err) {
							// 文件锁定错误：只记录警告，不停止服务
							log.Warn().Err(err).Msgf("文件被锁定，跳过增量解密: %s", dbFile)
						} else if s.errorHandler != nil {
							// 其他严重错误：调用错误处理器
							s.errorHandler(err)
						}
						// 增量解密出错，不回退全量（可能是密钥问题等严重错误）
						return
					}
					if applied {
						// 增量解密成功应用
						return
					}
					// 增量解密未应用（无新 commit），回退全量解密
					log.Debug().Msgf("WAL incremental not applied, fallback to full decrypt: %s", dbFile)
				}
				// 没有 WAL 事件，或增量未应用 → 全量解密
				if err := s.DecryptDBFile(dbFile); err != nil {
					if isFileLockedError(err) {
						// 文件锁定错误：只记录警告，不停止服务
						log.Warn().Err(err).Msgf("文件被锁定，跳过解密: %s", dbFile)
					} else if s.errorHandler != nil {
						// 其他严重错误：调用错误处理器
						s.errorHandler(err)
					}
				} else {
					s.clearWalState(dbFile)
				}
				return
			}
			if flags.sawWal && s.conf.GetWalEnabled() {
				// 只看到 WAL 变更 → 尝试增量解密
				applied, err := s.IncrementalDecryptDBFile(dbFile)
				if err != nil {
					if isFileLockedError(err) {
						// 文件锁定错误：只记录警告，不停止服务
						log.Warn().Err(err).Msgf("文件被锁定，跳过增量解密: %s", dbFile)
					} else if s.errorHandler != nil {
						// 其他严重错误：调用错误处理器
						s.errorHandler(err)
					}
					return
				}
				if applied {
					// 增量解密成功应用
					return
				}
				// 增量解密未应用 → 回退全量解密
				log.Debug().Msgf("WAL incremental not applied, fallback to full decrypt: %s", dbFile)
				if err := s.DecryptDBFile(dbFile); err != nil {
					if isFileLockedError(err) {
						// 文件锁定错误：只记录警告，不停止服务
						log.Warn().Err(err).Msgf("文件被锁定，跳过解密: %s", dbFile)
					} else if s.errorHandler != nil {
						// 其他严重错误：调用错误处理器
						s.errorHandler(err)
					}
				} else {
					s.clearWalState(dbFile)
				}
				return
			}
			// 既没有 .db 也没有 WAL 事件（理论上不应该到这里）
			if !s.conf.GetWalEnabled() || !workCopyExists {
				if err := s.DecryptDBFile(dbFile); err != nil {
					if isFileLockedError(err) {
						// 文件锁定错误：只记录警告，不停止服务
						log.Warn().Err(err).Msgf("文件被锁定，跳过解密: %s", dbFile)
					} else if s.errorHandler != nil {
						// 其他严重错误：调用错误处理器
						s.errorHandler(err)
					}
				}
			}
			return
		}
		s.mutex.Unlock()
	}
}

func (s *Service) DecryptDBFile(dbFile string) error {

	decryptor, err := decrypt.NewDecryptor(s.conf.GetPlatform(), s.conf.GetVersion())
	if err != nil {
		return err
	}

	relPath, err := filepath.Rel(s.conf.GetDataDir(), dbFile)
	if err != nil {
		return fmt.Errorf("failed to get relative path for %s: %w", dbFile, err)
	}
	output := filepath.Join(s.conf.GetWorkDir(), relPath)
	if err := util.PrepareDir(filepath.Dir(output)); err != nil {
		return err
	}

	outputTemp := output + ".tmp"
	outputFile, err := os.Create(outputTemp)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer func() {
		outputFile.Close()
		if err := os.Rename(outputTemp, output); err != nil {
			log.Debug().Err(err).Msgf("failed to rename %s to %s", outputTemp, output)
		}
	}()

	if err := decryptor.Decrypt(context.Background(), dbFile, s.conf.GetDataKey(), outputFile); err != nil {
		if err == errors.ErrAlreadyDecrypted {
			if data, err := os.ReadFile(dbFile); err == nil {
				outputFile.Write(data)
			}
			if s.conf.GetWalEnabled() {
				// Remove WAL files if they exist to prevent SQLite from reading encrypted WALs
				s.removeWalFiles(output)
			}
			return nil
		}
		log.Err(err).Msgf("failed to decrypt %s", dbFile)
		return err
	}

	log.Debug().Msgf("Decrypted %s to %s", dbFile, output)

	if s.conf.GetWalEnabled() {
		// Remove WAL files if they exist to prevent SQLite from reading encrypted WALs
		s.removeWalFiles(output)
	}

	return nil
}

func (s *Service) removeWalFiles(dbFile string) {
	walFile := dbFile + "-wal"
	shmFile := dbFile + "-shm"
	if err := os.Remove(walFile); err != nil && !os.IsNotExist(err) {
		log.Debug().Err(err).Msgf("failed to remove wal file %s", walFile)
	}
	if err := os.Remove(shmFile); err != nil && !os.IsNotExist(err) {
		log.Debug().Err(err).Msgf("failed to remove shm file %s", shmFile)
	}
}

func (s *Service) getDebounceTime() time.Duration {
	debounce := s.conf.GetAutoDecryptDebounce()
	if debounce <= 0 {
		return DebounceTime
	}
	return time.Duration(debounce) * time.Millisecond
}

func (s *Service) getMaxWaitTime() time.Duration {
	if !s.conf.GetWalEnabled() {
		return MaxWaitTime
	}
	debounce := s.getDebounceTime()
	maxWait := 2 * debounce
	if maxWait < time.Second {
		return time.Second
	}
	if maxWait > 3*time.Second {
		return 3 * time.Second
	}
	return maxWait
}

func (s *Service) getDebounceTimeForFile(dbFile string) time.Duration {
	debounce := s.getDebounceTime()
	if !s.conf.GetWalEnabled() {
		return debounce
	}
	if isRealtimeDBFile(dbFile) {
		if debounce > 300*time.Millisecond {
			return 300 * time.Millisecond
		}
	}
	return debounce
}

func (s *Service) getMaxWaitTimeForFile(dbFile string) time.Duration {
	if !s.conf.GetWalEnabled() {
		return s.getMaxWaitTime()
	}
	if isRealtimeDBFile(dbFile) {
		debounce := s.getDebounceTimeForFile(dbFile)
		maxWait := 2 * debounce
		if maxWait > time.Second {
			return time.Second
		}
		return maxWait
	}
	return s.getMaxWaitTime()
}


func isRealtimeDBFile(dbFile string) bool {
	base := filepath.Base(dbFile)
	if base == "session.db" {
		return true
	}
	return strings.HasPrefix(base, "message_") && strings.HasSuffix(base, ".db")
}

func (s *Service) normalizeDBFile(path string) string {
	if strings.HasSuffix(path, ".db-wal") {
		return strings.TrimSuffix(path, "-wal")
	}
	if strings.HasSuffix(path, ".db-shm") {
		return strings.TrimSuffix(path, "-shm")
	}
	return path
}

func isWalFile(path string) bool {
	return strings.HasSuffix(path, ".db-wal") || strings.HasSuffix(path, ".db-shm")
}

func (s *Service) DecryptDBFiles() error {
	dbGroup, err := filemonitor.NewFileGroup("wechat", s.conf.GetDataDir(), `.*\.db$`, []string{"fts"})
	if err != nil {
		return err
	}

	dbFiles, err := dbGroup.List()
	if err != nil {
		return err
	}
	sort.SliceStable(dbFiles, func(i, j int) bool {
		pi := dbFilePriority(dbFiles[i])
		pj := dbFilePriority(dbFiles[j])
		if pi != pj {
			return pi < pj
		}
		return filepath.Base(dbFiles[i]) < filepath.Base(dbFiles[j])
	})

	var lastErr error
	failCount := 0

	for _, dbFile := range dbFiles {
		if err := s.DecryptDBFile(dbFile); err != nil {
			log.Debug().Msgf("DecryptDBFile %s failed: %v", dbFile, err)
			lastErr = err
			failCount++
			continue
		}
	}

	if len(dbFiles) > 0 && failCount == len(dbFiles) {
		return fmt.Errorf("decryption failed for all %d files, last error: %w", len(dbFiles), lastErr)
	}

	return nil
}

func dbFilePriority(path string) int {
	base := filepath.Base(path)
	if strings.HasPrefix(base, "message_") && strings.HasSuffix(base, ".db") {
		return 0
	}
	if base == "session.db" {
		return 1
	}
	return 2
}

func (s *Service) IncrementalDecryptDBFile(dbFile string) (bool, error) {
	if !s.conf.GetWalEnabled() {
		return false, nil
	}
	walPath := dbFile + "-wal"
	if _, err := os.Stat(walPath); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	relPath, err := filepath.Rel(s.conf.GetDataDir(), dbFile)
	if err != nil {
		return false, fmt.Errorf("failed to get relative path for %s: %w", dbFile, err)
	}
	output := filepath.Join(s.conf.GetWorkDir(), relPath)
	if _, err := os.Stat(output); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	decryptor, err := decrypt.NewDecryptor(s.conf.GetPlatform(), s.conf.GetVersion())
	if err != nil {
		return false, err
	}

	dbInfo, err := common.OpenDBFile(dbFile, decryptor.GetPageSize())
	if err != nil {
		if err == errors.ErrAlreadyDecrypted {
			return false, nil
		}
		return false, err
	}

	keyBytes, err := hex.DecodeString(s.conf.GetDataKey())
	if err != nil {
		return false, errors.DecodeKeyFailed(err)
	}
	if !decryptor.Validate(dbInfo.FirstPage, keyBytes) {
		return false, errors.ErrDecryptIncorrectKey
	}

	encKey, macKey, err := decryptor.DeriveKeys(keyBytes, dbInfo.Salt)
	if err != nil {
		return false, err
	}

	walFile, err := os.Open(walPath)
	if err != nil {
		return false, err
	}
	defer walFile.Close()

	info, err := walFile.Stat()
	if err != nil {
		return false, err
	}
	if info.Size() < walHeaderSize {
		return false, nil
	}

	headerBuf := make([]byte, walHeaderSize)
	if _, err := io.ReadFull(walFile, headerBuf); err != nil {
		return false, err
	}
	order, pageSize, salt1, salt2, err := parseWalHeader(headerBuf)
	if err != nil {
		return false, err
	}
	if pageSize != 0 && pageSize != uint32(decryptor.GetPageSize()) {
		return false, fmt.Errorf("unexpected wal page size: %d", pageSize)
	}

	s.mutex.Lock()
	state := s.walStates[dbFile]
	if state != nil && (state.salt1 != salt1 || state.salt2 != salt2 || info.Size() < state.offset) {
		delete(s.walStates, dbFile)
		state = nil
	}
	startOffset := int64(walHeaderSize)
	if state != nil && state.offset > startOffset {
		startOffset = state.offset
	}
	s.mutex.Unlock()

	if _, err := walFile.Seek(startOffset, io.SeekStart); err != nil {
		return false, err
	}

	outputFile, err := os.OpenFile(output, os.O_RDWR, 0)
	if err != nil {
		return false, err
	}
	defer outputFile.Close()

	frameHeader := make([]byte, walFrameHeaderSize)
	pageBuf := make([]byte, decryptor.GetPageSize())
	txFrames := make([]walFrame, 0)
	var lastCommitOffset int64
	var applied bool
	curOffset := startOffset

	for curOffset+int64(walFrameHeaderSize)+int64(decryptor.GetPageSize()) <= info.Size() {
		if _, err := io.ReadFull(walFile, frameHeader); err != nil {
			break
		}
		curOffset += int64(walFrameHeaderSize)

		frameSalt1 := order.Uint32(frameHeader[8:12])
		frameSalt2 := order.Uint32(frameHeader[12:16])
		if frameSalt1 != salt1 || frameSalt2 != salt2 {
			s.mutex.Lock()
			delete(s.walStates, dbFile)
			s.mutex.Unlock()
			return false, nil
		}

		if _, err := io.ReadFull(walFile, pageBuf); err != nil {
			break
		}
		curOffset += int64(decryptor.GetPageSize())

		pageNo := order.Uint32(frameHeader[0:4])
		commit := order.Uint32(frameHeader[4:8])
		data := make([]byte, len(pageBuf))
		copy(data, pageBuf)
		txFrames = append(txFrames, walFrame{pageNo: pageNo, data: data})

		if commit != 0 {
			if err := applyWalFrames(outputFile, txFrames, decryptor, encKey, macKey); err != nil {
				return false, err
			}
			txFrames = txFrames[:0]
			lastCommitOffset = curOffset
			applied = true
		}
	}

	if lastCommitOffset > 0 {
		s.mutex.Lock()
		s.walStates[dbFile] = &walState{
			offset: lastCommitOffset,
			salt1:  salt1,
			salt2:  salt2,
		}
		s.mutex.Unlock()
	}

	// Remove WAL files if they exist to prevent SQLite from reading encrypted WALs
	s.removeWalFiles(output)

	return applied, nil
}

func parseWalHeader(buf []byte) (binary.ByteOrder, uint32, uint32, uint32, error) {
	if len(buf) < walHeaderSize {
		return nil, 0, 0, 0, fmt.Errorf("wal header too short")
	}
	magic := binary.BigEndian.Uint32(buf[0:4])
	var order binary.ByteOrder
	switch magic {
	case 0x377f0682:
		order = binary.BigEndian
	case 0x377f0683:
		order = binary.LittleEndian
	default:
		return nil, 0, 0, 0, fmt.Errorf("invalid wal magic: %x", magic)
	}
	pageSize := order.Uint32(buf[8:12])
	salt1 := order.Uint32(buf[16:20])
	salt2 := order.Uint32(buf[20:24])
	if pageSize == 0 {
		pageSize = 65536
	}
	return order, pageSize, salt1, salt2, nil
}

func applyWalFrames(output *os.File, frames []walFrame, decryptor decrypt.Decryptor, encKey, macKey []byte) error {
	pageSize := decryptor.GetPageSize()
	reserve := decryptor.GetReserve()
	hmacSize := decryptor.GetHMACSize()
	hashFunc := decryptor.GetHashFunc()
	for _, frame := range frames {
		pageNo := int64(frame.pageNo) - 1
		if pageNo < 0 {
			continue
		}
		allZeros := true
		for _, b := range frame.data {
			if b != 0 {
				allZeros = false
				break
			}
		}
		var pageData []byte
		if allZeros {
			pageData = frame.data
		} else {
			decrypted, err := common.DecryptPage(frame.data, encKey, macKey, pageNo, hashFunc, hmacSize, reserve, pageSize)
			if err != nil {
				return err
			}
			if pageNo == 0 {
				fullPage := make([]byte, pageSize)
				copy(fullPage, []byte(common.SQLiteHeader))
				copy(fullPage[len(common.SQLiteHeader):], decrypted)
				pageData = fullPage
			} else {
				pageData = decrypted
			}
		}
		if _, err := output.WriteAt(pageData, pageNo*int64(pageSize)); err != nil {
			return err
		}
	}
	return nil
}

const (
	walHeaderSize      = 32
	walFrameHeaderSize = 24
)
