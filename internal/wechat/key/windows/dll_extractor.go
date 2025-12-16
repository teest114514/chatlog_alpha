package windows

import (
	"context"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/rs/zerolog/log"
	gopsprocess "github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/windows"

	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	"github.com/sjzar/chatlog/internal/wechat/model"
	"github.com/sjzar/chatlog/pkg/util"
)

// DLL函数定义
var (
	modwxkey *windows.LazyDLL

	procInitializeHook   *windows.LazyProc
	procPollKeyData      *windows.LazyProc
	procGetStatusMessage *windows.LazyProc
	procCleanupHook      *windows.LazyProc
	procGetLastErrorMsg  *windows.LazyProc

	dllAvailable = false // 标记DLL是否可用
)

// DLLExtractor 使用wx_key.dll的密钥提取器
type DLLExtractor struct {
	validator *decrypt.Validator
	mu        sync.Mutex
	initialized bool
	pid        uint32
	lastKey   string // 记录上次获取的密钥，用于简单去重
	logger    *util.DLLLogger // DLL日志记录器
}

// init 初始化DLL函数
func init() {
	// 加载DLL - 使用相对路径
	dllPath := "lib/windows_x64/wx_key.dll"
	modwxkey = windows.NewLazyDLL(dllPath)

	// 尝试加载DLL，检查是否可用
	err := modwxkey.Load()
	if err != nil {
		log.Debug().Err(err).Msg("wx_key.dll 加载失败，将使用原生方式")
		dllAvailable = false
		return
	}

	// 获取函数指针
	procInitializeHook = modwxkey.NewProc("InitializeHook")
	procPollKeyData = modwxkey.NewProc("PollKeyData")
	procGetStatusMessage = modwxkey.NewProc("GetStatusMessage")
	procCleanupHook = modwxkey.NewProc("CleanupHook")
	procGetLastErrorMsg = modwxkey.NewProc("GetLastErrorMsg")

	// 检查所有函数是否都成功获取
	if procInitializeHook != nil && procPollKeyData != nil && procGetStatusMessage != nil &&
		procCleanupHook != nil && procGetLastErrorMsg != nil {
		dllAvailable = true
		log.Debug().Msg("wx_key.dll 加载成功，将使用DLL方式获取密钥")
	} else {
		dllAvailable = false
		log.Debug().Msg("wx_key.dll 函数获取失败，将使用原生方式")
	}
}

// IsDLLAvailable 检查DLL是否可用
func IsDLLAvailable() bool {
	return dllAvailable
}

// NewDLLV4Extractor 创建使用DLL的V4密钥提取器
func NewDLLV4Extractor() *DLLExtractor {
	return &DLLExtractor{
		logger: util.GetDLLLogger(),
	}
}

// Extract 从进程中提取密钥（使用DLL方式）
func (e *DLLExtractor) Extract(ctx context.Context, proc *model.Process) (string, string, error) {
	// 即使状态是offline（未登录），也允许尝试初始化DLL
	// 因为DLL方式可以在用户登录后拦截密钥
	if proc.Status == model.StatusOffline {
		log.Info().Msg("微信进程存在但未登录，将尝试初始化DLL，请登录微信后操作")
		// 不返回错误，继续执行
	}

	e.mu.Lock()
	// 初始化DLL
	// 注意：初始化必须在锁内完成
	if err := e.initialize(proc.PID); err != nil {
		e.mu.Unlock()
		return "", "", err
	}
	// DLL相关的清理函数
	cleanupDLL := func() {
		if e.initialized {
			e.cleanup()
		}
	}
	e.mu.Unlock() // 初始化完成后解锁，允许并行执行
	
	// DLL初始化成功，检查是否有回调需要通知
	if cb, ok := ctx.Value("status_callback").(func(string)); ok {
		cb("Hook安装成功（已完成DLL注入），如未登录请登录微信；然后打开任意聊天窗口以触发密钥加载...")
	}

	// 准备并行执行
	var (
		finalDataKey string
		finalImgKey  string
		keyMu        sync.Mutex // 保护结果更新
		wg           sync.WaitGroup
	)

	// 创建可取消的上下文
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 辅助函数：更新密钥并检查是否完成
	updateKeys := func(dk, ik, source string) {
		keyMu.Lock()
		defer keyMu.Unlock()

		updated := false
		if dk != "" && finalDataKey == "" {
			finalDataKey = dk
			updated = true
			log.Info().Msgf("通过 %s 获取到数据库密钥", source)
		}
		if ik != "" && finalImgKey == "" {
			finalImgKey = ik
			updated = true
			log.Info().Msgf("通过 %s 获取到图片密钥", source)
		}

		// 检查是否所有需要的密钥都已获取
		// 当前仅支持 V4：需要 DataKey + ImgKey
		if updated {
			if finalDataKey != "" && finalImgKey != "" {
				log.Info().Msg("已获取所有所需密钥，提前结束轮询")
				cancel()
			}
		}
	}

	// 任务 1: DLL 轮询 (运行在Goroutine中)
	wg.Add(1)
	go func() {
		defer wg.Done()
		
		// DLL操作需要持有锁以保护状态
		e.mu.Lock()
		defer e.mu.Unlock()
		defer cleanupDLL() // 确保退出时清理

		// 执行轮询，传入回调以便立即报告发现的密钥
		dk, ik, _ := e.pollKeys(ctx, proc.Version, func(d, i string) {
			updateKeys(d, i, "DLL")
		})
		
		// 轮询结束后的最终更新（防止遗漏，虽然回调应该覆盖了大部分情况）
		if dk != "" || ik != "" {
			updateKeys(dk, ik, "DLL")
		}
	}()

	// 任务 2: 原生内存扫描 (仅V4版本，运行在Goroutine中)
	if proc.Version == 4 {
		// 注意：这里不再依赖“调用时刻的 proc.DataDir/validator 状态”来决定是否启动扫描。
		// 原因：DLL 支持用户在获取过程中登录，而 DataDir 往往在登录后才可通过打开的 DB 文件推导出来。
		// 我们在协程中按 PID 轮询解析 DataDir，就绪后再启动 V4 扫描器；扫描器内部会等待 *_t.dat 样本就绪，避免白跑。
		wg.Add(1)
		go func(pid uint32) {
			defer wg.Done()

			scanProc := *proc // copy，避免并发读写外部对象

			// 1) 等待 DataDir 就绪（按 PID 从打开文件推导；登录后很快就会出现 session.db）
			if scanProc.DataDir == "" {
				msg := "等待数据目录就绪（需要登录成功）；就绪后将自动启动内存扫描获取图片密钥..."
				log.Info().Msg(msg)
				if e.logger != nil {
					e.logger.LogInfo(msg)
				}

				dataDir, err := waitForV4DataDirByPID(ctx, pid)
				if err != nil {
					// ctx 取消/超时等情况，直接返回让流程继续（仍可拿到 DataKey）
					if e.logger != nil {
						e.logger.LogWarning("数据目录未就绪，跳过图片密钥扫描: " + err.Error())
					}
					return
				}
				scanProc.DataDir = dataDir
			}

			// 2) 启动 V4 原生扫描器（内部会等待 *_t.dat 样本就绪再扫描）
			log.Info().Msg("并行启动原生内存扫描(Dart模式)以获取图片密钥...")
			v4 := NewV4Extractor()
			v4.SetValidate(e.validator) // 可为空；Extract 内部会按 dataDir 尝试构建 ImgKeyOnlyValidator

			_, ik, _ := v4.Extract(ctx, &scanProc)
			if ik != "" {
				updateKeys("", ik, "内存扫描")
			}
		}(proc.PID)
	}

	// 等待所有任务完成（或超时/被取消）
	wg.Wait()

	// 只要获取到了任意密钥，就算成功
	var err error
	if finalDataKey == "" && finalImgKey == "" {
		err = fmt.Errorf("未获取到有效密钥")
	}

	return finalDataKey, finalImgKey, err
}

// waitForV4DataDirByPID 通过 PID 轮询进程打开的文件，推导出微信 V4 的 DataDir。
// 逻辑与进程 detector 一致：找到 db_storage\session\session.db 后，去掉最后 3 段路径。
func waitForV4DataDirByPID(ctx context.Context, pid uint32) (string, error) {
	const v4SessionDBSuffix = `db_storage\session\session.db`

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
			p, err := gopsprocess.NewProcess(int32(pid))
			if err != nil {
				continue
			}
			files, err := p.OpenFiles()
			if err != nil {
				continue
			}
			for _, f := range files {
				if !strings.HasSuffix(f.Path, v4SessionDBSuffix) {
					continue
				}
				filePath := f.Path
				// 移除 "\\?\" 前缀（与 detector 保持一致）
				if strings.HasPrefix(filePath, `\\?\`) {
					filePath = filePath[4:]
				}
				parts := strings.Split(filePath, string(filepath.Separator))
				// ...\db_storage\session\session.db  至少需要 4 段以上
				if len(parts) < 4 {
					continue
				}
				dataDir := strings.Join(parts[:len(parts)-3], string(filepath.Separator))
				if dataDir != "" {
					return dataDir, nil
				}
			}
		}
	}
}

// initialize 初始化DLL Hook
func (e *DLLExtractor) initialize(pid uint32) error {
	// 调用InitializeHook
	ret, _, err := procInitializeHook.Call(uintptr(pid))
	if ret == 0 {
		// 获取错误信息
		errorMsg := e.getLastError()

		// 记录错误日志
		if e.logger != nil {
			e.logger.LogInitialization(pid, false, errorMsg)
		}

		if errorMsg != "" {
			return fmt.Errorf("初始化DLL失败: %s", errorMsg)
		}
		if err != nil {
			return fmt.Errorf("初始化DLL失败: %v", err)
		}
		return fmt.Errorf("初始化DLL失败")
	}

	e.initialized = true
	e.pid = pid

	// 记录成功日志
	if e.logger != nil {
		e.logger.LogInitialization(pid, true, "")
		e.logger.LogInfo(fmt.Sprintf("DLL初始化成功，PID: %d", pid))
	}

	log.Debug().Msgf("DLL初始化成功，PID: %d", pid)
	return nil
}

// pollKeys 轮询获取密钥
func (e *DLLExtractor) pollKeys(ctx context.Context, version int, onKeyFound func(dataKey, imgKey string)) (string, string, error) {
	if !e.initialized {
		return "", "", fmt.Errorf("DLL未初始化")
	}

	// 设置超时时间 - 改为30秒
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	var dataKey, imgKey string
	loginPromptShown := false // 标记是否已显示登录提示
	pollCount := 0            // 轮询计数器

	for {
		select {
		case <-ctx.Done():
			return dataKey, imgKey, ctx.Err()
		case <-timeout:
			// 检查是否获取到了数据密钥
			if dataKey != "" {
				// 获取到了数据密钥，但没有获取到图片密钥
				warningMsg := "30秒轮询结束，已获取数据库密钥，但未获取到图片密钥\n" +
					"注意：对于微信V4，图片密钥可能不是必需的，或者需要其他方式获取\n" +
					"数据库密钥: " + dataKey
				log.Warn().Msg("30秒轮询结束，已获取数据库密钥，但未获取到图片密钥")
				log.Warn().Msg("注意：对于微信V4，图片密钥可能不是必需的，或者需要其他方式获取")
				log.Warn().Msg("数据库密钥: " + dataKey)

				// 记录到日志文件
				if e.logger != nil {
					e.logger.LogWarning(warningMsg)
				}

				// 返回数据库密钥，图片密钥为空
				return dataKey, "", nil
			} else {
				// 没有获取到任何密钥
				errorMsg := "获取密钥超时（30秒）！可能的原因：\n" +
					"1. 微信未登录 - 请登录微信\n" +
					"2. 未触发数据库读取 - 请打开聊天窗口并查看历史消息\n" +
					"3. DLL Hook失败 - 检查日志文件查看详细错误\n" +
					"4. 微信版本不受支持 - 当前支持: 4.0.x 及以上 4.x 版本"
				log.Error().Msg("获取密钥超时（30秒）！可能的原因：")
				log.Error().Msg("1. 微信未登录 - 请登录微信")
				log.Error().Msg("2. 未触发数据库读取 - 请打开聊天窗口并查看历史消息")
				log.Error().Msg("3. DLL Hook失败 - 检查日志文件查看详细错误")
				log.Error().Msg("4. 微信版本不受支持 - 当前支持: 4.0.x 及以上 4.x 版本")

				// 记录到日志文件
				if e.logger != nil {
					e.logger.LogError(errorMsg)
				}
				return "", "", fmt.Errorf("获取密钥超时（30秒，请查看上方错误提示）")
			}
		case <-ticker.C:
			pollCount++

			// 尝试获取密钥
			key, err := e.pollKeyData()
			if err != nil {
				errorMsg := fmt.Sprintf("轮询密钥失败: %v", err)
				log.Err(err).Msg("轮询密钥失败")
				// 记录到日志文件
				if e.logger != nil {
					e.logger.LogError(errorMsg)
				}
				continue
			}

			if key != "" && key != e.lastKey {
				// 简单去重：避免重复处理相同的密钥
				e.lastKey = key

				// 验证密钥类型
				keyBytes, err := hex.DecodeString(key)
				if err != nil {
					errorMsg := fmt.Sprintf("解码密钥失败: %v", err)
					log.Err(err).Msg("解码密钥失败")
					// 记录到日志文件
					if e.logger != nil {
						e.logger.LogError(errorMsg)
					}
					continue
				}

				foundNew := false

				// 检查是否是数据库密钥（仅当 DB 验证样本就绪时）
				if e.validator != nil && e.validator.DBReady() && e.validator.Validate(keyBytes) {
					if dataKey == "" {
						dataKey = key
						foundNew = true
						msg := "通过DLL找到数据库密钥: " + key
						log.Info().Msg(msg)
						// 记录到日志文件
						if e.logger != nil {
							e.logger.LogPolling(true, key, "数据库")
							e.logger.LogInfo(msg)
						}
					}
				} else if e.validator == nil || !e.validator.DBReady() {
					// DB 验证不可用时，根据密钥长度判断（尽量不阻断 DataKey 获取）
					// 数据库密钥通常是32字节（64字符HEX字符串）
					// 图片密钥通常是16字节（32字符HEX字符串）
					if len(key) == 64 && dataKey == "" {
						dataKey = key
						foundNew = true
						msg := "通过DLL找到数据库密钥（无验证）: " + key
						log.Info().Msg(msg)
						// 记录到日志文件
						if e.logger != nil {
							e.logger.LogPolling(true, key, "数据库")
							e.logger.LogInfo(msg)
						}
					} else if len(key) == 32 && imgKey == "" && (e.validator == nil || !e.validator.ImgKeyReady()) {
						imgKey = key
						foundNew = true
						msg := "通过DLL找到图片密钥（无验证）: " + imgKey
						log.Info().Msg(msg)
						// 记录到日志文件
						if e.logger != nil {
							e.logger.LogPolling(true, imgKey, "图片")
							e.logger.LogInfo(msg)
						}
					}
				}

				// 检查是否是图片密钥（取前16字节；需要 ImgKey 验证样本就绪）
				if e.validator != nil && e.validator.ImgKeyReady() && e.validator.ValidateImgKey(keyBytes) {
					if imgKey == "" {
						imgKey = key[:32] // 16字节的HEX字符串是32个字符
						foundNew = true
						msg := "通过DLL找到图片密钥: " + imgKey
						log.Info().Msg(msg)
						// 记录到日志文件
						if e.logger != nil {
							e.logger.LogPolling(true, imgKey, "图片")
							e.logger.LogInfo(msg)
						}
					}
				}

				// 如果发现了新密钥，立即通过回调报告
				if foundNew && onKeyFound != nil {
					onKeyFound(dataKey, imgKey)
				}

				// 如果两个密钥都找到了，返回
				if dataKey != "" && imgKey != "" {
					return dataKey, imgKey, nil
				}

			} else {
				// 没有获取到密钥，每5秒显示一次操作提示
				// 每100ms轮询一次，50次轮询 = 5秒
				if !loginPromptShown && pollCount%50 == 0 {
					msg := "等待获取密钥... 请按以下步骤操作：\n" +
						"1. 确保微信已登录（不能停留在登录界面）\n" +
						"2. 打开任意聊天窗口\n" +
						"3. 向上滚动查看历史消息（触发数据库读取）\n" +
						"4. 或者发送/接收一条新消息"
					log.Info().Msg("等待获取密钥... 请按以下步骤操作：")
					log.Info().Msg("1. 确保微信已登录（不能停留在登录界面）")
					log.Info().Msg("2. 打开任意聊天窗口")
					log.Info().Msg("3. 向上滚动查看历史消息（触发数据库读取）")
					log.Info().Msg("4. 或者发送/接收一条新消息")

					// 记录到日志文件
					if e.logger != nil {
						e.logger.LogInfo(msg)
					}
					loginPromptShown = true
				}
			}

			// 获取状态信息
			e.getStatusMessages()

			// 每10秒显示一次调试信息
			if pollCount%100 == 0 {
				debugMsg := fmt.Sprintf("轮询中... 已轮询 %d 次，已等待 %.1f 秒", pollCount, float64(pollCount)*0.1)
				log.Debug().Msg(debugMsg)

				// 记录到日志文件
				if e.logger != nil {
					e.logger.LogDebug(debugMsg)
				}
			}
		}
	}
}

// pollKeyData 调用DLL的PollKeyData函数
func (e *DLLExtractor) pollKeyData() (string, error) {
	if !e.initialized {
		return "", fmt.Errorf("DLL未初始化")
	}

	// 分配缓冲区（至少65字节，建议128字节）
	buf := make([]byte, 128)
	ret, _, _ := procPollKeyData.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)

	if ret == 0 {
		// 没有新密钥
		return "", nil
	}

	// 找到以null结尾的字符串
	for i := 0; i < len(buf); i++ {
		if buf[i] == 0 {
			key := string(buf[:i])
			if key != "" {
				debugMsg := fmt.Sprintf("从DLL获取到密钥字符串: %s (长度: %d)", key, len(key))
				log.Debug().Msg(debugMsg)
				// 记录到日志文件
				if e.logger != nil {
					e.logger.LogDebug(debugMsg)
				}
			}
			return key, nil
		}
	}

	key := string(buf)
	if key != "" {
		debugMsg := fmt.Sprintf("从DLL获取到密钥字符串(无null终止): %s (长度: %d)", key, len(key))
		log.Debug().Msg(debugMsg)
		// 记录到日志文件
		if e.logger != nil {
			e.logger.LogDebug(debugMsg)
		}
	}
	return key, nil
}

// getStatusMessages 获取DLL状态信息
func (e *DLLExtractor) getStatusMessages() {
	if !e.initialized {
		return
	}

	buf := make([]byte, 512)
	var level int32

	for {
		ret, _, _ := procGetStatusMessage.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&level)),
		)

		if ret == 0 {
			break
		}

		// 找到以null结尾的字符串
		var msg string
		for i := 0; i < len(buf); i++ {
			if buf[i] == 0 {
				msg = string(buf[:i])
				break
			}
		}

		if msg != "" {
			logLevel := "INFO"
			if level == 1 {
				logLevel = "SUCCESS"
			} else if level == 2 {
				logLevel = "ERROR"
			}
			log.Debug().Msgf("[DLL %s] %s", logLevel, msg)

			// 记录到日志文件
			if e.logger != nil {
				e.logger.LogStatus(int(level), msg)
			}
		}
	}
}

// getLastError 获取DLL最后错误信息
func (e *DLLExtractor) getLastError() string {
	ret, _, _ := procGetLastErrorMsg.Call()
	if ret == 0 {
		return ""
	}

	// 将指针转换为Go字符串
	errorMsgPtr := (*byte)(unsafe.Pointer(ret))
	if errorMsgPtr == nil {
		return ""
	}

	// 计算字符串长度
	length := 0
	for {
		if *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(errorMsgPtr)) + uintptr(length))) == 0 {
			break
		}
		length++
		if length > 1024 {
			break
		}
	}

	if length == 0 {
		return ""
	}

	buf := make([]byte, length)
	for i := 0; i < length; i++ {
		buf[i] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(errorMsgPtr)) + uintptr(i)))
	}

	errorMsg := string(buf)

	// 记录错误信息到日志文件
	if e.logger != nil && errorMsg != "" {
		e.logger.LogError(errorMsg)
	}

	return errorMsg
}

// cleanup 清理DLL资源
func (e *DLLExtractor) cleanup() {
	if !e.initialized {
		return
	}

	procCleanupHook.Call()
	e.initialized = false
	e.lastKey = "" // 清理上次密钥记录

	// 记录清理日志
	if e.logger != nil {
		e.logger.LogCleanup()
	}

	log.Debug().Msg("DLL资源已清理")
}

// SearchKey 在内存中搜索密钥（DLL方式不支持此功能）
func (e *DLLExtractor) SearchKey(ctx context.Context, memory []byte) (string, bool) {
	// DLL方式不支持直接内存搜索
	return "", false
}

// SetValidate 设置验证器
func (e *DLLExtractor) SetValidate(validator *decrypt.Validator) {
	e.validator = validator
}