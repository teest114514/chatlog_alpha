package conf

import "strings"

const (
	HookNotifyMCP    = "mcp"
	HookNotifyPost   = "post"
	HookNotifyBoth   = "both"
	HookNotifyWeixin = "weixin"
	HookNotifyAll    = "all"
)

type MessageHook struct {
	Keywords         string `mapstructure:"keywords" json:"keywords"`
	NotifyMode       string `mapstructure:"notify_mode" json:"notify_mode"`
	PostURL          string `mapstructure:"post_url" json:"post_url"`
	BeforeCount      int    `mapstructure:"before_count" json:"before_count"`
	AfterCount       int    `mapstructure:"after_count" json:"after_count"`
	WeixinInterval   int    `mapstructure:"weixin_interval" json:"weixin_interval"`
	ForwardAll       bool   `mapstructure:"forward_all" json:"forward_all"`
	ForwardContacts  string `mapstructure:"forward_contacts" json:"forward_contacts"`
	ForwardChatRooms string `mapstructure:"forward_chatrooms" json:"forward_chatrooms"`
}

type HookNotifyTargets struct {
	MCP    bool
	Post   bool
	Weixin bool
}

func (t HookNotifyTargets) HasAny() bool {
	return t.MCP || t.Post || t.Weixin
}

func ParseHookNotifyTargets(raw string) (HookNotifyTargets, bool) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return HookNotifyTargets{MCP: true}, true
	}

	var targets HookNotifyTargets
	for _, token := range splitHookNotifyMode(raw) {
		switch token {
		case HookNotifyMCP:
			targets.MCP = true
		case HookNotifyPost:
			targets.Post = true
		case HookNotifyWeixin:
			targets.Weixin = true
		case HookNotifyBoth:
			targets.MCP = true
			targets.Post = true
		case HookNotifyAll:
			targets.MCP = true
			targets.Post = true
			targets.Weixin = true
		default:
			return HookNotifyTargets{}, false
		}
	}
	if !targets.HasAny() {
		return HookNotifyTargets{}, false
	}
	return targets, true
}

func CanonicalHookNotifyMode(raw string) string {
	targets, ok := ParseHookNotifyTargets(raw)
	if !ok {
		return HookNotifyMCP
	}
	switch {
	case targets.MCP && targets.Post && targets.Weixin:
		return HookNotifyAll
	case targets.MCP && targets.Post:
		return HookNotifyBoth
	case targets.MCP && targets.Weixin:
		return HookNotifyMCP + "," + HookNotifyWeixin
	case targets.Post && targets.Weixin:
		return HookNotifyPost + "," + HookNotifyWeixin
	case targets.MCP:
		return HookNotifyMCP
	case targets.Post:
		return HookNotifyPost
	case targets.Weixin:
		return HookNotifyWeixin
	default:
		return HookNotifyMCP
	}
}

func splitHookNotifyMode(raw string) []string {
	raw = strings.NewReplacer("|", ",", ";", ",", "+", ",", " ", ",").Replace(raw)
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}
