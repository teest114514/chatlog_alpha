package http

import (
	"github.com/sjzar/chatlog/internal/chatlog/conf"
	"github.com/sjzar/chatlog/internal/chatlog/hermespush"
)

type hermesWeixinStatus struct {
	Installed       bool   `json:"installed"`
	HermesBin       string `json:"hermes_bin,omitempty"`
	Enabled         bool   `json:"enabled"`
	Available       bool   `json:"available"`
	Editable        bool   `json:"editable"`
	HermesHome      string `json:"hermes_home,omitempty"`
	EnvFile         string `json:"env_file,omitempty"`
	ConfigFile      string `json:"config_file,omitempty"`
	ChannelFile     string `json:"channel_file,omitempty"`
	AccountFile     string `json:"account_file,omitempty"`
	AccountID       string `json:"account_id,omitempty"`
	Token           string `json:"token,omitempty"`
	BaseURL         string `json:"base_url,omitempty"`
	CdnBaseURL      string `json:"cdn_base_url,omitempty"`
	HomeChannel     string `json:"home_channel,omitempty"`
	HomeChannelName string `json:"home_channel_name,omitempty"`
	HomeChannelFrom string `json:"home_channel_from,omitempty"`
	Error           string `json:"error,omitempty"`
}

func (s *Service) getHermesWeixinStatus(mode string) hermesWeixinStatus {
	targets, ok := conf.ParseHookNotifyTargets(mode)
	if !ok {
		targets = conf.HookNotifyTargets{MCP: true}
	}
	install := hermespush.DetectInstallation()
	status := hermesWeixinStatus{
		Installed:  install.Installed,
		HermesBin:  install.HermesBin,
		Enabled:    targets.Weixin,
		HermesHome: install.HermesHome,
	}
	cfg, err := hermespush.DiscoverWeixinConfig()
	if err != nil {
		if status.Enabled {
			status.Error = err.Error()
		}
		return status
	}
	status.Available = true
	status.Editable = cfg.EnvFile != "" || cfg.ConfigFile != "" || cfg.AccountFile != ""
	status.HermesHome = cfg.HermesHome
	status.EnvFile = cfg.EnvFile
	status.ConfigFile = cfg.ConfigFile
	status.ChannelFile = cfg.ChannelFile
	status.AccountFile = cfg.AccountFile
	status.AccountID = cfg.AccountID
	status.Token = cfg.Token
	status.BaseURL = cfg.BaseURL
	status.CdnBaseURL = cfg.CdnBaseURL
	status.HomeChannel = cfg.HomeChannel
	status.HomeChannelName = cfg.HomeChannelName
	status.HomeChannelFrom = cfg.HomeChannelFrom
	return status
}
