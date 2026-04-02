package chatlog

import (
	"context"
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
	DataKey                string `json:"data_key"`
	ImageKey               string `json:"image_key"`
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
	m.ctx.WeChatInstances = m.loadWeChatInstances()
	if len(m.ctx.WeChatInstances) == 0 {
		return fmt.Errorf("未检测到微信进程")
	}
	m.ctx.SwitchCurrent(m.ctx.WeChatInstances[0])
	return nil
}

func (m *Manager) SelectAccount(pid int, history string) error {
	if pid != 0 {
		for _, ins := range m.loadWeChatInstances() {
			if int(ins.PID) == pid {
				m.ctx.SwitchCurrent(ins)
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
	history, ok := m.ctx.History[m.ctx.Account]
	if !ok {
		history = conf.ProcessConfig{}
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
		DataKey:                dataKey,
		ImageKey:               imageKey,
		HTTPEnabled:            m.ctx.HTTPEnabled,
		HTTPAddr:               httpAddr,
		AutoDecompress:         m.ctx.AutoDecrypt,
		WalEnabled:             m.ctx.WalEnabled,
		AutoDecompressDebounce: m.ctx.AutoDecryptDebounce,
	}
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
	ret := make([]ActionAccount, 0, len(instances)+len(m.ctx.History))

	for _, ins := range instances {
		ret = append(ret, ActionAccount{
			Source:      "process",
			Account:     ins.Name,
			PID:         ins.PID,
			DataDir:     ins.DataDir,
			Status:      ins.Status,
			Platform:    ins.Platform,
			Version:     ins.Version,
			FullVersion: ins.FullVersion,
			Current:     m.ctx.Current != nil && m.ctx.Current.PID == ins.PID,
		})
	}

	for account, hist := range m.ctx.History {
		ret = append(ret, ActionAccount{
			Source:      "history",
			Account:     account,
			DataDir:     hist.DataDir,
			WorkDir:     hist.WorkDir,
			Platform:    hist.Platform,
			Version:     hist.Version,
			FullVersion: hist.FullVersion,
			Current:     m.ctx.Current == nil && m.ctx.DataDir != "" && m.ctx.DataDir == hist.DataDir,
		})
	}

	return ret
}

func (m *Manager) GetImageKeyWithStatus(onStatus func(string)) error {
	if err := m.EnsureCurrentAccount(); err != nil {
		return err
	}
	if onStatus != nil {
		onStatus("正在准备图片密钥扫描...")
	}
	ctx := context.WithValue(context.Background(), "status_callback", onStatus)
	if _, err := m.ctx.Current.GetImageKey(ctx); err != nil {
		return err
	}
	m.ctx.Refresh()
	m.ctx.UpdateConfig()
	return nil
}

func (m *Manager) SetDataKey(key string) error {
	if m.ctx == nil {
		return fmt.Errorf("context not initialized")
	}
	m.ctx.SetDataKey(key)
	return nil
}

func (m *Manager) SetConfigValues(httpAddr, workDir, dataKey, imageKey, dataDir string, walEnabled *bool, autoDecompressDebounce *int) error {
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
	return nil
}

func (m *Manager) SwitchToAccount(pid int, history string) error {
	if pid != 0 {
		var target *iwechat.Account
		for _, ins := range m.loadWeChatInstances() {
			if int(ins.PID) == pid {
				target = ins
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

func (m *Manager) HistoryConfig(account string) (conf.ProcessConfig, bool) {
	hist, ok := m.ctx.History[account]
	return hist, ok
}
