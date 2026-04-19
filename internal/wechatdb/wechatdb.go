package wechatdb

import (
	"context"
	"time"

	"github.com/fsnotify/fsnotify"
	_ "github.com/mattn/go-sqlite3"

	"github.com/sjzar/chatlog/internal/model"
	"github.com/sjzar/chatlog/internal/wechatdb/datasource"
	"github.com/sjzar/chatlog/internal/wechatdb/repository"
)

type DB struct {
	path       string
	platform   string
	version    int
	walEnabled bool
	dataKey    string
	ds         datasource.DataSource
	repo       *repository.Repository
}

func New(path string, platform string, version int, walEnabled bool, dataKey string) (*DB, error) {

	w := &DB{
		path:       path,
		platform:   platform,
		version:    version,
		walEnabled: walEnabled,
		dataKey:    dataKey,
	}

	// 初始化，加载数据库文件信息
	if err := w.Initialize(); err != nil {
		return nil, err
	}

	return w, nil
}

func (w *DB) Close() error {
	if w.repo != nil {
		return w.repo.Close()
	}
	return nil
}

func (w *DB) Initialize() error {
	var err error
	w.ds, err = datasource.New(w.path, w.platform, w.version, w.walEnabled, w.dataKey)
	if err != nil {
		return err
	}

	w.repo, err = repository.New(w.ds)
	if err != nil {
		return err
	}

	return nil
}

func (w *DB) GetMessages(start, end time.Time, talker string, sender string, keyword string, limit, offset int) ([]*model.Message, error) {
	ctx := context.Background()

	// 使用 repository 获取消息
	messages, err := w.repo.GetMessages(ctx, start, end, talker, sender, keyword, limit, offset)
	if err != nil {
		return nil, err
	}

	return messages, nil
}

func (w *DB) GetMessage(talker string, seq int64) (*model.Message, error) {
	return w.repo.GetMessage(context.Background(), talker, seq)
}

type GetContactsResp struct {
	Items []*model.Contact `json:"items"`
}

func (w *DB) GetContacts(key string, limit, offset int) (*GetContactsResp, error) {
	ctx := context.Background()

	contacts, err := w.repo.GetContacts(ctx, key, limit, offset)
	if err != nil {
		return nil, err
	}

	return &GetContactsResp{
		Items: contacts,
	}, nil
}

func (w *DB) GetContact(key string) (*model.Contact, error) {
	return w.repo.GetContact(context.Background(), key)
}

type GetChatRoomsResp struct {
	Items []*model.ChatRoom `json:"items"`
}

func (w *DB) GetChatRooms(key string, limit, offset int) (*GetChatRoomsResp, error) {
	ctx := context.Background()

	chatRooms, err := w.repo.GetChatRooms(ctx, key, limit, offset)
	if err != nil {
		return nil, err
	}

	return &GetChatRoomsResp{
		Items: chatRooms,
	}, nil
}

func (w *DB) GetChatRoom(key string) (*model.ChatRoom, error) {
	return w.repo.GetChatRoom(context.Background(), key)
}

type GetSessionsResp struct {
	Items []*model.Session `json:"items"`
}

func (w *DB) GetSessions(key string, limit, offset int) (*GetSessionsResp, error) {
	ctx := context.Background()

	// 使用 repository 获取会话列表
	sessions, err := w.repo.GetSessions(ctx, key, limit, offset)
	if err != nil {
		return nil, err
	}

	return &GetSessionsResp{
		Items: sessions,
	}, nil
}

func (w *DB) GetMedia(_type string, key string) (*model.Media, error) {
	return w.repo.GetMedia(context.Background(), _type, key)
}

func (w *DB) SetCallback(group string, callback func(event fsnotify.Event) error) error {
	return w.ds.SetCallback(group, callback)
}

func (w *DB) GetDBs() (map[string][]string, error) {
	return w.ds.GetDBs()
}

func (w *DB) GetTables(group, file string) ([]string, error) {
	return w.ds.GetTables(group, file)
}

func (w *DB) GetTableData(group, file, table string, limit, offset int, keyword string) ([]map[string]interface{}, error) {
	return w.ds.GetTableData(group, file, table, limit, offset, keyword)
}

func (w *DB) ExecuteSQL(group, file, query string) ([]map[string]interface{}, error) {
	return w.ds.ExecuteSQL(group, file, query)
}

// GetSNSTimeline 获取朋友圈时间线数据
func (w *DB) GetSNSTimeline(username string, limit, offset int) ([]map[string]interface{}, error) {
	return w.ds.GetSNSTimeline(context.Background(), username, limit, offset)
}

// GetSNSCount 获取朋友圈数量统计
func (w *DB) GetSNSCount(username string) (int, error) {
	return w.ds.GetSNSCount(context.Background(), username)
}
