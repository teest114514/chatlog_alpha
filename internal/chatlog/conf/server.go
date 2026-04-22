package conf

import "strings"

const (
	DefalutHTTPAddr = "0.0.0.0:5030"
)

type ServerConfig struct {
	Type                string       `mapstructure:"type"`
	Platform            string       `mapstructure:"platform"`
	Version             int          `mapstructure:"version"`
	FullVersion         string       `mapstructure:"full_version"`
	DataDir             string       `mapstructure:"data_dir"`
	DataKey             string       `mapstructure:"data_key"`
	ImgKey              string       `mapstructure:"img_key"`
	WorkDir             string       `mapstructure:"work_dir"`
	HTTPAddr            string       `mapstructure:"http_addr"`
	AutoDecrypt         bool         `mapstructure:"auto_decrypt"`
	WalEnabled          bool         `mapstructure:"wal_enabled"`
	AutoDecryptDebounce int          `mapstructure:"auto_decrypt_debounce"`
	SaveDecryptedMedia  bool         `mapstructure:"save_decrypted_media"`
	MessageHook         *MessageHook `mapstructure:"message_hook"`
}

var ServerDefaults = map[string]any{
	"save_decrypted_media": true,
}

func (c *ServerConfig) GetDataDir() string {
	return c.DataDir
}

func (c *ServerConfig) GetWorkDir() string {
	return c.WorkDir
}

func (c *ServerConfig) GetPlatform() string {
	return c.Platform
}

func (c *ServerConfig) GetVersion() int {
	return c.Version
}

func (c *ServerConfig) GetDataKey() string {
	return c.DataKey
}

func (c *ServerConfig) GetImgKey() string {
	return c.ImgKey
}

func (c *ServerConfig) GetAutoDecrypt() bool {
	return c.AutoDecrypt
}

func (c *ServerConfig) GetWalEnabled() bool {
	return c.WalEnabled
}

func (c *ServerConfig) GetAutoDecryptDebounce() int {
	return c.AutoDecryptDebounce
}

func (c *ServerConfig) GetHTTPAddr() string {
	if c.HTTPAddr == "" {
		c.HTTPAddr = DefalutHTTPAddr
	}
	return c.HTTPAddr
}

func (c *ServerConfig) GetMessageHook() *MessageHook {
	if c.MessageHook == nil {
		c.MessageHook = &MessageHook{
			NotifyMode:     HookNotifyMCP,
			BeforeCount:    5,
			AfterCount:     5,
			WeixinInterval: 5,
		}
	}
	return c.MessageHook
}

func (c *ServerConfig) GetSaveDecryptedMedia() bool {
	return c.SaveDecryptedMedia
}

func (c *ServerConfig) SetHookKeywords(keywords string) {
	cfg := c.GetMessageHook()
	cfg.Keywords = strings.TrimSpace(keywords)
}

func (c *ServerConfig) SetHookNotifyMode(mode string) {
	cfg := c.GetMessageHook()
	cfg.NotifyMode = CanonicalHookNotifyMode(mode)
}

func (c *ServerConfig) SetHookPostURL(url string) {
	cfg := c.GetMessageHook()
	cfg.PostURL = strings.TrimSpace(url)
}

func (c *ServerConfig) SetHookBeforeCount(n int) {
	if n < 0 {
		n = 0
	}
	cfg := c.GetMessageHook()
	cfg.BeforeCount = n
}

func (c *ServerConfig) SetHookAfterCount(n int) {
	if n < 0 {
		n = 0
	}
	cfg := c.GetMessageHook()
	cfg.AfterCount = n
}

func (c *ServerConfig) SetHookWeixinInterval(n int) {
	if n <= 0 {
		n = 5
	}
	cfg := c.GetMessageHook()
	cfg.WeixinInterval = n
}

func (c *ServerConfig) SetHookForwardAll(enabled bool) {
	cfg := c.GetMessageHook()
	cfg.ForwardAll = enabled
}

func (c *ServerConfig) SetHookForwardContacts(raw string) {
	cfg := c.GetMessageHook()
	cfg.ForwardContacts = strings.TrimSpace(raw)
}

func (c *ServerConfig) SetHookForwardChatRooms(raw string) {
	cfg := c.GetMessageHook()
	cfg.ForwardChatRooms = strings.TrimSpace(raw)
}
