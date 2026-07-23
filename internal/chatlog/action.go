package chatlog

import (
	"fmt"

	"github.com/sjzar/chatlog/internal/chatlog/conf"
	"github.com/sjzar/chatlog/internal/chatlog/ctx"
	"github.com/sjzar/chatlog/internal/chatlog/database"
	"github.com/sjzar/chatlog/internal/chatlog/http"
	"github.com/sjzar/chatlog/internal/chatlog/wechat"
	iwechat "github.com/sjzar/chatlog/internal/wechat"
	"github.com/sjzar/chatlog/pkg/util"
)

type ActionAccount struct {
	Source      string `json:"source"`
	Account     string `json:"account"`
	PID         uint32 `json:"pid,omitempty"`
	DataDir     string `json:"data_dir,omitempty"`
	WorkDir     string `json:"work_dir,omitempty"`
	Status      string `json:"status,omitempty"`
	Platform    string `json:"platform,omitempty"`
	Version     int    `json:"version,omitempty"`
	FullVersion string `json:"full_version,omitempty"`
	Current     bool   `json:"current"`
}

type ActionStatus struct {
	Account                string `json:"account"`
	PID                    int    `json:"pid"`
	Status                 string `json:"status"`
	ExePath                string `json:"exe_path"`
	Platform               string `json:"platform"`
	Version                int    `json:"version"`
	FullVersion            string `json:"full_version"`
	DataDir                string `json:"data_dir"`
	WorkDir                string `json:"work_dir"`
	DataKey                string `json:"data_key,omitempty"`
	ImageKey               string `json:"image_key,omitempty"`
	DataKeyPresent         bool   `json:"data_key_present"`
	ImageKeyPresent        bool   `json:"image_key_present"`
	HTTPEnabled            bool   `json:"http_enabled"`
	HTTPAddr               string `json:"http_addr"`
	AutoDecompress         bool   `json:"auto_decompress"`
	WalEnabled             bool   `json:"wal_enabled"`
	AutoDecompressDebounce int    `json:"auto_decompress_debounce"`
}

func (m *Manager) InitAction(configPath string) error {
	var err error
	m.ctx, err = ctx.New(configPath)
	if err != nil {
		return err
	}
	m.wechat = wechat.NewService(m.ctx)
	m.db = database.NewService(m.ctx)
	m.http = http.NewService(m.ctx, m.db)
	m.ctx.WeChatInstances = m.loadWeChatInstances()
	if m.ctx.Current == nil && len(m.ctx.WeChatInstances) > 0 {
		m.ctx.SwitchCurrent(m.ctx.WeChatInstances[0])
	} else {
		m.ctx.Refresh()
	}
	return nil
}

func (m *Manager) EnsureCurrentAccount() error {
	if m.ctx == nil {
		return fmt.Errorf("context not initialized")
	}
	if m.ctx.Current != nil {
		return nil
	}
	if m.ctx.Account != "" {
		if _, ok := m.ctx.History[m.ctx.Account]; ok {
			m.ctx.SwitchHistory(m.ctx.Account)
			return nil
		}
	}
	m.ctx.WeChatInstances = m.loadWeChatInstances()
	if len(m.ctx.WeChatInstances) == 0 {
		return fmt.Errorf("未检测到微信进程或历史账号")
	}
	m.ctx.SwitchCurrent(m.ctx.WeChatInstances[0])
	return nil
}

func (m *Manager) SelectAccount(pid int, history string) error {
	if pid != 0 {
		for _, instance := range m.loadWeChatInstances() {
			if int(instance.PID) == pid {
				m.ctx.SwitchCurrent(instance)
				return nil
			}
		}
		return fmt.Errorf("未找到 PID=%d 的微信进程", pid)
	}
	if history != "" {
		if _, ok := m.ctx.History[history]; !ok {
			return fmt.Errorf("未找到历史账号 %s", history)
		}
		m.ctx.SwitchHistory(history)
		return nil
	}
	return m.EnsureCurrentAccount()
}

func (m *Manager) Snapshot() ActionStatus {
	m.ctx.Refresh()
	history := conf.ProcessConfig{}
	if saved, ok := m.ctx.History[m.ctx.Account]; ok {
		history = saved
	}
	dataDir := firstNonEmpty(m.ctx.DataDir, history.DataDir)
	workDir := firstNonEmpty(m.ctx.WorkDir, history.WorkDir)
	if workDir == "" && m.ctx.Account != "" {
		workDir = util.DefaultWorkDir(m.ctx.Account)
	}
	httpAddr := firstNonEmpty(m.ctx.HTTPAddr, history.HTTPAddr)
	if httpAddr == "" {
		httpAddr = m.ctx.GetHTTPAddr()
	}
	dataKey := firstNonEmpty(m.ctx.DataKey, history.DataKey)
	imageKey := firstNonEmpty(m.ctx.ImgKey, history.ImgKey)
	return ActionStatus{
		Account:                m.ctx.Account,
		PID:                    m.ctx.PID,
		Status:                 m.ctx.Status,
		ExePath:                m.ctx.ExePath,
		Platform:               m.ctx.Platform,
		Version:                m.ctx.Version,
		FullVersion:            m.ctx.FullVersion,
		DataDir:                dataDir,
		WorkDir:                workDir,
		DataKey:                redactActionSecret(dataKey),
		ImageKey:               redactActionSecret(imageKey),
		DataKeyPresent:         dataKey != "",
		ImageKeyPresent:        imageKey != "",
		HTTPEnabled:            m.ctx.HTTPEnabled,
		HTTPAddr:               httpAddr,
		AutoDecompress:         m.ctx.AutoDecrypt,
		WalEnabled:             m.ctx.WalEnabled,
		AutoDecompressDebounce: m.ctx.AutoDecryptDebounce,
	}
}

func redactActionSecret(value string) string {
	if value == "" {
		return ""
	}
	return "******"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (m *Manager) ListAccounts() []ActionAccount {
	instances := m.loadWeChatInstances()
	result := make([]ActionAccount, 0, len(instances)+len(m.ctx.History))
	for _, instance := range instances {
		result = append(result, ActionAccount{
			Source:      "process",
			Account:     instance.Name,
			PID:         instance.PID,
			DataDir:     instance.DataDir,
			Status:      instance.Status,
			Platform:    instance.Platform,
			Version:     instance.Version,
			FullVersion: instance.FullVersion,
			Current:     m.ctx.Current != nil && m.ctx.Current.PID == instance.PID,
		})
	}
	for account, history := range m.ctx.History {
		result = append(result, ActionAccount{
			Source:      "history",
			Account:     account,
			DataDir:     history.DataDir,
			WorkDir:     history.WorkDir,
			Platform:    history.Platform,
			Version:     history.Version,
			FullVersion: history.FullVersion,
			Current:     m.ctx.Current == nil && m.ctx.Account == account,
		})
	}
	return result
}

func (m *Manager) GetImageKeyWithStatus(onStatus func(string)) error {
	if err := m.EnsureCurrentAccount(); err != nil {
		return err
	}
	return m.GetImageKey(onStatus)
}

func (m *Manager) SetDataKey(key string) error {
	if m.ctx == nil {
		return fmt.Errorf("context not initialized")
	}
	m.ctx.SetDataKey(key)
	return nil
}

func (m *Manager) SetConfigValues(httpAddr, workDir, dataKey, imageKey, dataDir string, walEnabled *bool, autoDecompressDebounce *int, logRetentionDays *int) error {
	if httpAddr != "" {
		if err := m.SetHTTPAddr(httpAddr); err != nil {
			return err
		}
	}
	if workDir != "" {
		m.ctx.SetWorkDir(workDir)
	}
	if dataKey != "" {
		if err := m.SetDataKey(dataKey); err != nil {
			return err
		}
	}
	if imageKey != "" {
		m.ctx.SetImgKey(imageKey)
	}
	if dataDir != "" {
		m.ctx.SetDataDir(dataDir)
	}
	if walEnabled != nil {
		m.ctx.SetWalEnabled(*walEnabled)
	}
	if autoDecompressDebounce != nil {
		m.ctx.SetAutoDecryptDebounce(*autoDecompressDebounce)
	}
	if logRetentionDays != nil {
		m.ctx.SetLogRetentionDays(*logRetentionDays)
	}
	return nil
}

func (m *Manager) SwitchToAccount(pid int, history string) error {
	if pid != 0 {
		var target *iwechat.Account
		for _, instance := range m.loadWeChatInstances() {
			if int(instance.PID) == pid {
				target = instance
				break
			}
		}
		if target == nil {
			return fmt.Errorf("未找到 PID=%d 的微信进程", pid)
		}
		return m.Switch(target, "")
	}
	if history == "" {
		return fmt.Errorf("缺少切换目标")
	}
	if _, ok := m.ctx.History[history]; !ok {
		return fmt.Errorf("未找到历史账号 %s", history)
	}
	return m.Switch(nil, history)
}
