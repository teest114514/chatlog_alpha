package datasource

import (
	"context"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/model"
	"github.com/sjzar/chatlog/internal/wechatdb/datasource/wcdb"
)

type DataSource interface {

	// 消息
	GetMessages(ctx context.Context, startTime, endTime time.Time, talker string, sender string, keyword string, limit, offset int) ([]*model.Message, error)
	GetMessage(ctx context.Context, talker string, seq int64) (*model.Message, error)

	// 联系人
	GetContacts(ctx context.Context, key string, limit, offset int) ([]*model.Contact, error)

	// 群聊
	GetChatRooms(ctx context.Context, key string, limit, offset int) ([]*model.ChatRoom, error)

	// 最近会话
	GetSessions(ctx context.Context, key string, limit, offset int) ([]*model.Session, error)

	// 媒体
	GetMedia(ctx context.Context, _type string, key string) (*model.Media, error)

	// 朋友圈
	GetSNSTimeline(ctx context.Context, username string, limit, offset int) ([]map[string]interface{}, error)
	GetSNSCount(ctx context.Context, username string) (int, error)

	// 设置回调函数
	SetCallback(group string, callback func(event fsnotify.Event) error) error

	// 获取数据库列表
	GetDBs() (map[string][]string, error)

	// 获取指定数据库的表列表
	GetTables(group, file string) ([]string, error)

	// 获取指定表的数据
	GetTableData(group, file, table string, limit, offset int, keyword string) ([]map[string]interface{}, error)

	// 执行 SQL 查询
	ExecuteSQL(group, file, query string) ([]map[string]interface{}, error)

	// 全局搜索所有数据库中可搜索的文本列
	SearchAll(keyword string, limit int, deep bool) ([]map[string]interface{}, error)

	Close() error
}

func New(path string, platform string, version int, walEnabled bool, dataKey string) (DataSource, error) {
	switch {
	case platform == "darwin" && version == 4:
		return wcdb.New(path, dataKey)
	case platform == "windows" && version == 4:
		return wcdb.New(path, dataKey)
	default:
		return nil, errors.PlatformUnsupported(platform, version)
	}
}
