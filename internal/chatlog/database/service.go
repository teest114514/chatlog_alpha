package database

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/sjzar/chatlog/internal/chatlog/conf"
	"github.com/sjzar/chatlog/internal/chatlog/webhook"
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
	State         int
	StateMsg      string
	conf          Config
	db            *wechatdb.DB
	webhook       *webhook.Service
	webhookCancel context.CancelFunc
}

type Config interface {
	GetWorkDir() string
	GetPlatform() string
	GetVersion() int
	GetWebhook() *conf.Webhook
	GetWalEnabled() bool
}

func NewService(conf Config) *Service {
	return &Service{
		conf:    conf,
		webhook: webhook.New(conf),
	}
}

func (s *Service) Start() error {
	db, err := wechatdb.New(s.conf.GetWorkDir(), s.conf.GetPlatform(), s.conf.GetVersion(), s.conf.GetWalEnabled())
	if err != nil {
		return err
	}
	s.SetReady()
	s.db = db
	s.initWebhook()
	return nil
}

func (s *Service) Stop() error {
	if s.db != nil {
		s.db.Close()
	}
	s.SetInit()
	s.db = nil
	if s.webhookCancel != nil {
		s.webhookCancel()
		s.webhookCancel = nil
	}
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

func (s *Service) GetMediaByName(_type string, name string, size int64) (*model.Media, error) {
	return s.db.GetMediaByName(_type, name, size)
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

func (s *Service) initWebhook() error {
	if s.webhook == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.webhookCancel = cancel
	hooks := s.webhook.GetHooks(ctx, s.db)
	for _, hook := range hooks {
		log.Info().Msgf("set callback %#v", hook)
		if err := s.db.SetCallback(hook.Group(), hook.Callback); err != nil {
			log.Error().Err(err).Msgf("set callback %#v failed", hook)
			return err
		}
	}
	return nil
}

// Close closes the database connection
func (s *Service) Close() {
	// Add cleanup code if needed
	s.db.Close()
	if s.webhookCancel != nil {
		s.webhookCancel()
		s.webhookCancel = nil
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
