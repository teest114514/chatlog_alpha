package database

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/sjzar/chatlog/internal/chatlog/conf"
	"github.com/sjzar/chatlog/internal/chatlog/messagehook"
	"github.com/sjzar/chatlog/internal/model"
	"github.com/sjzar/chatlog/internal/wechatdb"
)

const (
	StateInit = iota
	StateDecrypting
	StateReady
	StateError
)

type Service struct {
	State      int
	StateMsg   string
	conf       Config
	db         *wechatdb.DB
	hookSvc    *messagehook.Service
	hookCancel context.CancelFunc
	notifierMu sync.RWMutex
	notifier   func(messagehook.Event)
}

type Config interface {
	GetWorkDir() string
	GetDataDir() string
	GetDataKey() string
	GetPlatform() string
	GetVersion() int
	GetMessageHook() *conf.MessageHook
	GetWalEnabled() bool
}

func NewService(conf Config) *Service {
	return &Service{
		conf: conf,
	}
}

func (s *Service) Start() error {
	dbPath := s.conf.GetWorkDir()
	platform := s.conf.GetPlatform()
	version := s.conf.GetVersion()
	if (platform == "darwin" || platform == "windows") && version == 4 {
		// v4 使用内置 wcdb_api 兼容查询链路，直接面向原始 db_storage。
		dbPath = s.conf.GetDataDir()
	}
	db, err := wechatdb.New(dbPath, platform, version, s.conf.GetWalEnabled(), s.conf.GetDataKey())
	if err != nil {
		return err
	}
	s.SetReady()
	s.db = db
	s.initMessageHook()
	return nil
}

func (s *Service) Stop() error {
	if s.db != nil {
		s.db.Close()
	}
	s.SetInit()
	s.db = nil
	if s.hookCancel != nil {
		s.hookCancel()
		s.hookCancel = nil
	}
	s.hookSvc = nil
	return nil
}

func (s *Service) SetInit() {
	s.State = StateInit
}

func (s *Service) SetDecrypting() {
	s.State = StateDecrypting
}

func (s *Service) SetReady() {
	s.State = StateReady
}

func (s *Service) SetError(msg string) {
	s.State = StateError
	s.StateMsg = msg
}

func (s *Service) GetDB() *wechatdb.DB {
	return s.db
}

func (s *Service) GetMessages(start, end time.Time, talker string, sender string, keyword string, limit, offset int) ([]*model.Message, error) {
	return s.db.GetMessages(start, end, talker, sender, keyword, limit, offset)
}

func (s *Service) GetMessage(talker string, seq int64) (*model.Message, error) {
	return s.db.GetMessage(talker, seq)
}

func (s *Service) GetContacts(key string, limit, offset int) (*wechatdb.GetContactsResp, error) {
	return s.db.GetContacts(key, limit, offset)
}

func (s *Service) GetContact(key string) (*model.Contact, error) {
	return s.db.GetContact(key)
}

func (s *Service) GetChatRooms(key string, limit, offset int) (*wechatdb.GetChatRoomsResp, error) {
	return s.db.GetChatRooms(key, limit, offset)
}

func (s *Service) GetChatRoom(key string) (*model.ChatRoom, error) {
	return s.db.GetChatRoom(key)
}

// GetSession retrieves session information
func (s *Service) GetSessions(key string, limit, offset int) (*wechatdb.GetSessionsResp, error) {
	return s.db.GetSessions(key, limit, offset)
}

func (s *Service) GetMedia(_type string, key string) (*model.Media, error) {
	return s.db.GetMedia(_type, key)
}

func (s *Service) GetDecryptedDBs() (map[string][]string, error) {
	if s.db == nil {
		return nil, nil
	}
	return s.db.GetDBs()
}

func (s *Service) GetTables(group, file string) ([]string, error) {
	if s.db == nil {
		return nil, nil
	}
	return s.db.GetTables(group, file)
}

func (s *Service) GetTableData(group, file, table string, limit, offset int, keyword string) ([]map[string]interface{}, error) {
	if s.db == nil {
		return nil, nil
	}
	return s.db.GetTableData(group, file, table, limit, offset, keyword)
}

func (s *Service) ExecuteSQL(group, file, query string) ([]map[string]interface{}, error) {
	if s.db == nil {
		return nil, nil
	}
	return s.db.ExecuteSQL(group, file, query)
}

func (s *Service) SearchAll(keyword string, limit int, deep bool) ([]map[string]interface{}, error) {
	if s.db == nil {
		return nil, nil
	}
	return s.db.SearchAll(keyword, limit, deep)
}

func (s *Service) initMessageHook() error {
	if s.db == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.hookCancel = cancel
	s.hookSvc = messagehook.New(s.conf, s.db, s.emitHookEvent)
	go s.hookSvc.Run(ctx)
	log.Info().Msg("message hook service started")
	return nil
}

// Close closes the database connection
func (s *Service) Close() {
	// Add cleanup code if needed
	s.db.Close()
	if s.hookCancel != nil {
		s.hookCancel()
		s.hookCancel = nil
	}
}

func (s *Service) SetMessageHookNotifier(fn func(messagehook.Event)) {
	s.notifierMu.Lock()
	defer s.notifierMu.Unlock()
	s.notifier = fn
}

func (s *Service) emitHookEvent(evt messagehook.Event) {
	s.notifierMu.RLock()
	defer s.notifierMu.RUnlock()
	if s.notifier != nil {
		s.notifier(evt)
	}
}

// GetSNSTimeline 获取朋友圈时间线数据
func (s *Service) GetSNSTimeline(username string, limit, offset int) ([]map[string]interface{}, error) {
	if s.db == nil {
		return nil, nil
	}
	return s.db.GetSNSTimeline(username, limit, offset)
}

// GetSNSCount 获取朋友圈数量统计
func (s *Service) GetSNSCount(username string) (int, error) {
	if s.db == nil {
		return 0, nil
	}
	return s.db.GetSNSCount(username)
}
