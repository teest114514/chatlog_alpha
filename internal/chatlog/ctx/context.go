package ctx

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sjzar/chatlog/internal/chatlog/conf"
	"github.com/sjzar/chatlog/internal/wechat"
	"github.com/sjzar/chatlog/pkg/config"
	"github.com/sjzar/chatlog/pkg/filecopy"
	"github.com/sjzar/chatlog/pkg/util"
)

const (
	DefalutHTTPAddr = "127.0.0.1:5030"
)

// Context is a context for a chatlog.
// It is used to store information about the chatlog.
type Context struct {
	conf *conf.TUIConfig
	cm   *config.Manager
	mu   sync.RWMutex

	History map[string]conf.ProcessConfig

	// 微信账号相关状态
	Account     string
	Platform    string
	Version     int
	FullVersion string
	DataDir     string
	DataKey     string
	DataUsage   string
	ImgKey      string

	// 工作目录相关状态
	WorkDir   string
	WorkUsage string

	// HTTP服务相关状态
	HTTPEnabled bool
	HTTPAddr    string

	// 自动解密
	AutoDecrypt          bool
	LastSession          time.Time
	WalEnabled           bool
	AutoDecryptDebounce  int
	HookKeywords         string
	HookNotifyMode       string
	HookPostURL          string
	HookBeforeCount      int
	HookAfterCount       int
	HookForwardAll       bool
	HookForwardContacts  string
	HookForwardChatRooms string
	Semantic             conf.SemanticConfig

	// 当前选中的微信实例
	Current *wechat.Account
	PID     int
	ExePath string
	Status  string

	// 所有可用的微信实例
	WeChatInstances []*wechat.Account
}

func New(configPath string) (*Context, error) {

	conf, tcm, err := conf.LoadTUIConfig(configPath)
	if err != nil {
		return nil, err
	}

	ctx := &Context{
		conf: conf,
		cm:   tcm,
	}

	ctx.loadConfig()

	return ctx, nil
}

func (c *Context) loadConfig() {
	c.History = c.conf.ParseHistory()
	c.SwitchHistory(c.conf.LastAccount)
	c.Refresh()
}

func (c *Context) SwitchHistory(account string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Current = nil
	c.PID = 0
	c.ExePath = ""
	c.Status = ""
	history, ok := c.History[account]
	if ok {
		c.Account = history.Account
		c.Platform = history.Platform
		c.Version = history.Version
		c.FullVersion = history.FullVersion
		c.DataKey = history.DataKey
		c.ImgKey = history.ImgKey
		c.DataDir = history.DataDir
		c.WorkDir = history.WorkDir
		c.HTTPEnabled = history.HTTPEnabled
		c.HTTPAddr = history.HTTPAddr
		c.WalEnabled = history.WalEnabled
		c.AutoDecryptDebounce = history.AutoDecryptDebounce
		c.HookKeywords = history.HookKeywords
		c.HookNotifyMode = history.HookNotifyMode
		c.HookPostURL = history.HookPostURL
		c.HookBeforeCount = history.HookBeforeCount
		c.HookAfterCount = history.HookAfterCount
		c.HookForwardAll = history.HookForwardAll
		c.HookForwardContacts = history.HookForwardContacts
		c.HookForwardChatRooms = history.HookForwardChatRooms
		c.Semantic = conf.NormalizeSemanticConfig(history.Semantic)
	} else {
		c.Account = ""
		c.Platform = ""
		c.Version = 0
		c.FullVersion = ""
		c.DataKey = ""
		c.ImgKey = ""
		c.DataDir = ""
		c.WorkDir = ""
		c.HTTPEnabled = false
		c.HTTPAddr = ""
		c.WalEnabled = false
		c.AutoDecryptDebounce = 0
		c.HookKeywords = ""
		c.HookNotifyMode = conf.HookNotifyMCP
		c.HookPostURL = ""
		c.HookBeforeCount = 5
		c.HookAfterCount = 5
		c.HookForwardAll = false
		c.HookForwardContacts = ""
		c.HookForwardChatRooms = ""
		c.Semantic = conf.NormalizeSemanticConfig(conf.SemanticConfig{})
	}
}

func (c *Context) SwitchCurrent(info *wechat.Account) {
	c.SwitchHistory(info.Name)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Current = info
	c.Refresh()

}
func (c *Context) Refresh() {
	if c.Current != nil {
		c.Account = c.Current.Name
		c.Platform = c.Current.Platform
		c.Version = c.Current.Version
		c.FullVersion = c.Current.FullVersion
		c.PID = int(c.Current.PID)
		c.ExePath = c.Current.ExePath
		c.Status = c.Current.Status
		// 更新密钥数据 - 总是从Current同步到Context
		// 仅在Current中的密钥为非空时，才更新Context，以避免覆盖已有的有效密钥
		if c.Current.Key != "" {
			c.DataKey = c.Current.Key
		}
		if c.Current.ImgKey != "" {
			c.ImgKey = c.Current.ImgKey
		}
		if c.Current.DataDir != c.DataDir {
			c.DataDir = c.Current.DataDir
		}

	}
	if c.DataUsage == "" && c.DataDir != "" {
		go func() {
			c.DataUsage = util.GetDirSize(c.DataDir)
		}()
	}
	if c.WorkUsage == "" && c.WorkDir != "" {
		go func() {
			workSize := util.GetDirSize(c.WorkDir)
			cacheDir := filecopy.GetCacheDir()
			cacheSize := util.GetDirSize(cacheDir)
			c.WorkUsage = fmt.Sprintf("%s (Cache: %s)", workSize, cacheSize)
		}()
	}
}

func (c *Context) GetDataDir() string {
	return c.DataDir
}

func (c *Context) GetWorkDir() string {
	return c.WorkDir
}

func (c *Context) GetPlatform() string {
	return c.Platform
}

func (c *Context) GetVersion() int {
	return c.Version
}

func (c *Context) GetDataKey() string {
	return c.DataKey
}

func (c *Context) GetWalEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.WalEnabled
}

func (c *Context) GetAutoDecryptDebounce() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.AutoDecryptDebounce
}

func (c *Context) GetHTTPAddr() string {
	if c.HTTPAddr == "" {
		c.HTTPAddr = DefalutHTTPAddr
	}
	return c.HTTPAddr
}

func (c *Context) GetMessageHook() *conf.MessageHook {
	mode := conf.CanonicalHookNotifyMode(c.HookNotifyMode)
	before := c.HookBeforeCount
	after := c.HookAfterCount
	if before < 0 {
		before = 0
	}
	if after < 0 {
		after = 0
	}
	return &conf.MessageHook{
		Keywords:         c.HookKeywords,
		NotifyMode:       mode,
		PostURL:          c.HookPostURL,
		BeforeCount:      before,
		AfterCount:       after,
		ForwardAll:       c.HookForwardAll,
		ForwardContacts:  c.HookForwardContacts,
		ForwardChatRooms: c.HookForwardChatRooms,
	}
}

func (c *Context) GetSemanticConfig() *conf.SemanticConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cfg := conf.NormalizeSemanticConfig(c.Semantic)
	cfg.Enabled = true
	cfg.EnableRerank = true
	cfg.EnableQA = true
	cfg.EnableTopics = true
	cfg.EnableProfiles = true
	cfg.RealtimeIndex = true
	return &cfg
}

func (c *Context) GetSaveDecryptedMedia() bool {
	// Default to true for now, can be made configurable later
	return true
}

func (c *Context) SetHTTPEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.HTTPEnabled == enabled {
		return
	}
	c.HTTPEnabled = enabled
	c.UpdateConfig()
}

func (c *Context) SetHTTPAddr(addr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.HTTPAddr == addr {
		return
	}
	c.HTTPAddr = addr
	c.UpdateConfig()
}

func (c *Context) SetWorkDir(dir string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.WorkDir == dir {
		return
	}
	c.WorkDir = dir
	c.UpdateConfig()
	c.Refresh()
}

func (c *Context) SetDataDir(dir string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.DataDir == dir {
		return
	}
	c.DataDir = dir
	c.UpdateConfig()
	c.Refresh()
}

func (c *Context) SetImgKey(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ImgKey == key {
		return
	}
	c.ImgKey = key
	c.UpdateConfig()
}

func (c *Context) SetAutoDecrypt(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.AutoDecrypt == enabled {
		return
	}
	c.AutoDecrypt = enabled
	c.UpdateConfig()
}

func (c *Context) SetWalEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.WalEnabled == enabled {
		return
	}
	c.WalEnabled = enabled
	c.UpdateConfig()
}

func (c *Context) SetAutoDecryptDebounce(debounce int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.AutoDecryptDebounce == debounce {
		return
	}
	c.AutoDecryptDebounce = debounce
	c.UpdateConfig()
}

func (c *Context) SetHookKeywords(keywords string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.HookKeywords == keywords {
		return
	}
	c.HookKeywords = keywords
	c.UpdateConfig()
}

func (c *Context) SetHookNotifyMode(mode string) {
	mode = conf.CanonicalHookNotifyMode(mode)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.HookNotifyMode == mode {
		return
	}
	c.HookNotifyMode = mode
	c.UpdateConfig()
}

func (c *Context) SetHookPostURL(url string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.HookPostURL == url {
		return
	}
	c.HookPostURL = url
	c.UpdateConfig()
}

func (c *Context) SetHookBeforeCount(n int) {
	if n < 0 {
		n = 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.HookBeforeCount == n {
		return
	}
	c.HookBeforeCount = n
	c.UpdateConfig()
}

func (c *Context) SetHookAfterCount(n int) {
	if n < 0 {
		n = 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.HookAfterCount == n {
		return
	}
	c.HookAfterCount = n
	c.UpdateConfig()
}

func (c *Context) SetHookForwardAll(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.HookForwardAll == enabled {
		return
	}
	c.HookForwardAll = enabled
	c.UpdateConfig()
}

func (c *Context) SetHookForwardContacts(raw string) {
	raw = strings.TrimSpace(raw)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.HookForwardContacts == raw {
		return
	}
	c.HookForwardContacts = raw
	c.UpdateConfig()
}

func (c *Context) SetHookForwardChatRooms(raw string) {
	raw = strings.TrimSpace(raw)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.HookForwardChatRooms == raw {
		return
	}
	c.HookForwardChatRooms = raw
	c.UpdateConfig()
}

func (c *Context) SetSemanticConfig(cfg conf.SemanticConfig) {
	cfg = conf.NormalizeSemanticConfig(cfg)
	cfg.Enabled = true
	cfg.EnableRerank = true
	cfg.EnableQA = true
	cfg.EnableTopics = true
	cfg.EnableProfiles = true
	cfg.RealtimeIndex = true
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Semantic = cfg
	c.UpdateConfig()
}

// 更新配置
func (c *Context) UpdateConfig() {

	pconf := conf.ProcessConfig{
		Type:                 "wechat",
		Account:              c.Account,
		Platform:             c.Platform,
		Version:              c.Version,
		FullVersion:          c.FullVersion,
		DataDir:              c.DataDir,
		DataKey:              c.DataKey,
		ImgKey:               c.ImgKey,
		WorkDir:              c.WorkDir,
		HTTPEnabled:          c.HTTPEnabled,
		HTTPAddr:             c.HTTPAddr,
		WalEnabled:           c.WalEnabled,
		AutoDecryptDebounce:  c.AutoDecryptDebounce,
		HookKeywords:         c.HookKeywords,
		HookNotifyMode:       c.HookNotifyMode,
		HookPostURL:          c.HookPostURL,
		HookBeforeCount:      c.HookBeforeCount,
		HookAfterCount:       c.HookAfterCount,
		HookForwardAll:       c.HookForwardAll,
		HookForwardContacts:  c.HookForwardContacts,
		HookForwardChatRooms: c.HookForwardChatRooms,
		Semantic:             conf.NormalizeSemanticConfig(c.Semantic),
	}

	if c.conf.History == nil {
		c.conf.History = make([]conf.ProcessConfig, 0)
	}
	if len(c.conf.History) == 0 {
		c.conf.History = append(c.conf.History, pconf)
	} else {
		isFind := false
		for i, v := range c.conf.History {
			if v.Account == c.Account {
				isFind = true
				c.conf.History[i] = pconf
				break
			}
		}
		if !isFind {
			c.conf.History = append(c.conf.History, pconf)
		}
	}

	if err := c.cm.SetConfig("last_account", c.Account); err != nil {
		log.Error().Err(err).Msg("set last_account failed")
		return
	}

	if err := c.cm.SetConfig("history", c.conf.History); err != nil {
		log.Error().Err(err).Msg("set history failed")
		return
	}

	if len(pconf.DataDir) != 0 {
		if b, err := json.Marshal(pconf); err == nil {
			if err := os.WriteFile(filepath.Join(pconf.DataDir, "chatlog.json"), b, 0644); err != nil {
				log.Error().Err(err).Msg("save chatlog.json failed")
			}
		}
	}
}
