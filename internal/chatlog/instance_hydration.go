package chatlog

import (
	"strings"

	"github.com/sjzar/chatlog/internal/chatlog/conf"
	iwechat "github.com/sjzar/chatlog/internal/wechat"
)

func (m *Manager) loadWeChatInstances() []*iwechat.Account {
	instances := m.wechat.GetWeChatInstances()
	return hydrateAccountsFromHistory(instances, m.ctx.History, m.ctx.Account)
}

func hydrateAccountsFromHistory(instances []*iwechat.Account, history map[string]conf.ProcessConfig, preferredAccount string) []*iwechat.Account {
	if len(instances) == 0 {
		return instances
	}

	hydrated := make([]*iwechat.Account, 0, len(instances))
	for _, account := range instances {
		if account == nil {
			continue
		}

		copyAccount := *account
		hydratedAccount := &copyAccount

		if len(history) != 0 && strings.HasPrefix(hydratedAccount.Name, "未登录微信_") {
			if candidate, ok := selectHistoryCandidate(history, preferredAccount, len(instances)); ok {
				hydratedAccount.Name = candidate.Account
				if hydratedAccount.DataDir == "" {
					hydratedAccount.DataDir = candidate.DataDir
				}
				if hydratedAccount.Key == "" {
					hydratedAccount.Key = candidate.DataKey
				}
				if hydratedAccount.ImgKey == "" {
					hydratedAccount.ImgKey = candidate.ImgKey
				}
				if hydratedAccount.FullVersion == "" {
					hydratedAccount.FullVersion = candidate.FullVersion
				}
				if hydratedAccount.Version == 0 {
					hydratedAccount.Version = candidate.Version
				}
				if hydratedAccount.Platform == "" {
					hydratedAccount.Platform = candidate.Platform
				}
				if hydratedAccount.Status == "" || hydratedAccount.Status == "offline" {
					hydratedAccount.Status = "online"
				}
			}
		}

		hydrated = append(hydrated, hydratedAccount)
	}

	return hydrated
}

func selectHistoryCandidate(history map[string]conf.ProcessConfig, preferredAccount string, processCount int) (conf.ProcessConfig, bool) {
	if preferredAccount != "" {
		if candidate, ok := history[preferredAccount]; ok {
			return candidate, true
		}
	}

	if processCount == 1 && len(history) == 1 {
		for _, candidate := range history {
			return candidate, true
		}
	}

	return conf.ProcessConfig{}, false
}
