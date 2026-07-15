package repository

import (
	"context"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"

	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/model"
	"github.com/sjzar/chatlog/internal/wechatdb/datasource"
)

// cacheRefreshInterval 缓存周期重新加载间隔。
// 历史 bug：DataSource.SetCallback 目前是空 stub，contactCallback /
// chatroomCallback 从来不会被触发；即便触发，callback 内部也只看
// fsnotify.Create 事件，而联系人改名 / 群改名走的是 Write 事件，不会命中。
// 结果 chatlog 启动后 contact / chatroom 两个 cache 都是一次性快照，运行期
// WeChat 改名 / 新增群聊在 API 上看不到，必须重启 chatlog 才更新。
//
// 在不重写 fsnotify 接线的前提下，最简单可靠的修复是周期性全量重 init：30s
// 足够紧凑（用户基本感知不到 stale），而 contact / chatroom 表都很小，
// 全量重载 CPU/IO 代价可忽略。
const cacheRefreshInterval = 30 * time.Second

// Repository 实现了 repository.Repository 接口
type Repository struct {
	ds datasource.DataSource

	// cacheMu 保护下面所有 cache 字段。周期 refresh goroutine 会整体重建并替换
	// 这些 map / slice，外部 API 并发读取，必须共享同一把 RWMutex，否则会触发
	// "concurrent map read and map write" panic。
	cacheMu sync.RWMutex

	// Cache for contact
	contactCache      map[string]*model.Contact
	aliasToContact    map[string][]*model.Contact
	remarkToContact   map[string][]*model.Contact
	nickNameToContact map[string][]*model.Contact
	chatRoomInContact map[string]*model.Contact
	contactList       []string
	aliasList         []string
	remarkList        []string
	nickNameList      []string

	// Cache for chat room
	chatRoomCache      map[string]*model.ChatRoom
	remarkToChatRoom   map[string][]*model.ChatRoom
	nickNameToChatRoom map[string][]*model.ChatRoom
	chatRoomList       []string
	chatRoomRemark     []string
	chatRoomNickName   []string

	// 快速查找索引
	chatRoomUserToInfo map[string]*model.Contact

	// refresh goroutine 控制：Close 时关闭以通知退出
	refreshDone chan struct{}
}

// New 创建一个新的 Repository
func New(ds datasource.DataSource) (*Repository, error) {
	r := &Repository{
		ds:                 ds,
		contactCache:       make(map[string]*model.Contact),
		aliasToContact:     make(map[string][]*model.Contact),
		remarkToContact:    make(map[string][]*model.Contact),
		nickNameToContact:  make(map[string][]*model.Contact),
		chatRoomUserToInfo: make(map[string]*model.Contact),
		contactList:        make([]string, 0),
		aliasList:          make([]string, 0),
		remarkList:         make([]string, 0),
		nickNameList:       make([]string, 0),
		chatRoomCache:      make(map[string]*model.ChatRoom),
		remarkToChatRoom:   make(map[string][]*model.ChatRoom),
		nickNameToChatRoom: make(map[string][]*model.ChatRoom),
		chatRoomList:       make([]string, 0),
		chatRoomRemark:     make([]string, 0),
		chatRoomNickName:   make([]string, 0),
	}

	// 初始化缓存
	if err := r.initCache(context.Background()); err != nil {
		return nil, errors.InitCacheFailed(err)
	}

	// callback 保留：将来 SetCallback 真正接通 fsnotify Write 事件后可立即用上
	ds.SetCallback("contact", r.contactCallback)
	ds.SetCallback("chatroom", r.chatroomCallback)

	// 启动周期 refresh —— cache 失效的主路径（详见 cacheRefreshInterval 注释）
	r.refreshDone = make(chan struct{})
	go r.runRefreshLoop()

	return r, nil
}

// runRefreshLoop 每 cacheRefreshInterval 重新加载一次 contact / chatroom cache，
// 直到 Close。单次失败只 log，保留上一次 cache 继续服务请求。
func (r *Repository) runRefreshLoop() {
	ticker := time.NewTicker(cacheRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.refreshDone:
			return
		case <-ticker.C:
			ctx := context.Background()
			if err := r.initContactCache(ctx); err != nil {
				log.Warn().Err(err).Msg("repository: periodic contact cache refresh failed")
			}
			if err := r.initChatRoomCache(ctx); err != nil {
				log.Warn().Err(err).Msg("repository: periodic chatroom cache refresh failed")
			}
		}
	}
}

// initCache 初始化缓存
func (r *Repository) initCache(ctx context.Context) error {
	// 初始化联系人缓存
	if err := r.initContactCache(ctx); err != nil {
		return err
	}

	// 初始化群聊缓存
	if err := r.initChatRoomCache(ctx); err != nil {
		return err
	}

	return nil
}

func (r *Repository) contactCallback(event fsnotify.Event) error {
	if !event.Op.Has(fsnotify.Create) {
		return nil
	}
	if err := r.initContactCache(context.Background()); err != nil {
		log.Err(err).Msgf("Failed to reinitialize contact cache: %s", event.Name)
	}
	return nil
}

func (r *Repository) chatroomCallback(event fsnotify.Event) error {
	if !event.Op.Has(fsnotify.Create) {
		return nil
	}
	if err := r.initChatRoomCache(context.Background()); err != nil {
		log.Err(err).Msgf("Failed to reinitialize contact cache: %s", event.Name)
	}
	return nil
}

// Close 实现 Repository 接口的 Close 方法
func (r *Repository) Close() error {
	if r.refreshDone != nil {
		// chatlog 进程只 Close 一次，直接 close 通知 refresh goroutine 退出即可
		close(r.refreshDone)
		r.refreshDone = nil
	}
	return r.ds.Close()
}
