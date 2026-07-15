package repository

import (
	"context"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"

	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/model"
	"github.com/sjzar/chatlog/internal/wechatdb/datasource"
)

// Repository 实现了 repository.Repository 接口
type Repository struct {
	ds datasource.DataSource

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

	// Cache for openim corp_id → corp_name（来自 contact.db.openim_wording 表）
	openimWordingCache map[string]string
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
		openimWordingCache: make(map[string]string),
	}

	// 初始化缓存
	if err := r.initCache(context.Background()); err != nil {
		return nil, errors.InitCacheFailed(err)
	}

	ds.SetCallback("contact", r.contactCallback)
	ds.SetCallback("chatroom", r.chatroomCallback)

	return r, nil
}

// initCache 初始化缓存
func (r *Repository) initCache(ctx context.Context) error {
	// openim_wording 必须先于 contact —— initContactCache 里给 @openim 联系人
	// 注入 CorpName 时要查这张表。顺序反了会导致首次启动企业名为空。
	if err := r.initOpenimWordingCache(ctx); err != nil {
		return err
	}

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

// initOpenimWordingCache 从 datasource 加载 corp_id → corp_name 映射到内存 map。
// 表很小（每个企业一行，通常 < 50），全量加载零成本。表不存在（老版本 WeChat /
// 非企业账户）不算致命错，用空 cache 继续。
func (r *Repository) initOpenimWordingCache(ctx context.Context) error {
	wordings, err := r.ds.GetOpenimWordings(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to load openim_wording (continuing with empty cache)")
		wordings = nil
	}
	m := make(map[string]string, len(wordings))
	for _, w := range wordings {
		if w.WordingID == "" || w.Wording == "" {
			continue
		}
		// 同一 wording_id 可能多语言多行；只在 map 里还没有该 key 时写入。
		if _, ok := m[w.WordingID]; !ok {
			m[w.WordingID] = w.Wording
		}
	}
	r.openimWordingCache = m
	return nil
}

// LookupOpenimCorpName 给 corp_id（形如 "...@im.wxwork"）查企业名。
// 命中返 (name, true)；没命中 / 空 corp_id 返 ("", false)。
func (r *Repository) LookupOpenimCorpName(corpID string) (string, bool) {
	if corpID == "" {
		return "", false
	}
	name, ok := r.openimWordingCache[corpID]
	return name, ok
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
	return r.ds.Close()
}
