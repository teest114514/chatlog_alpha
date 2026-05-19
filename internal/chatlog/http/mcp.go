package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/sjzar/chatlog/internal/chatlog/conf"
	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/model"
	"github.com/sjzar/chatlog/pkg/version"
)

func (s *Service) initMCPServer() {
	s.mcpServer = server.NewMCPServer(conf.AppName, version.Version,
		server.WithResourceCapabilities(false, false),
		server.WithToolCapabilities(true),
		server.WithPromptCapabilities(true),
	)
	s.mcpServer.AddTool(CurrentTimeTool, s.handleMCPCurrentTime)
	s.mcpServer.AddTool(SendWebhookNotificationTool, s.handleMCPSendWebhookNotification)
	s.mcpServer.AddTool(GetUserProfileTool, s.handleMCPGetUserProfile)
	s.mcpServer.AddTool(SearchSharedFilesTool, s.handleMCPSearchSharedFiles)
	s.mcpServer.AddTool(WxPingTool, s.handleMCPWxPing)
	s.mcpServer.AddTool(WxContactsTool, s.handleMCPWxContacts)
	s.mcpServer.AddTool(WxChatRoomsTool, s.handleMCPWxChatRooms)
	s.mcpServer.AddTool(WxSessionsTool, s.handleMCPWxSessions)
	s.mcpServer.AddTool(WxHistoryTool, s.handleMCPWxHistory)
	s.mcpServer.AddTool(WxSearchTool, s.handleMCPWxSearch)
	s.mcpServer.AddTool(WxSemanticSearchTool, s.handleMCPWxSemanticSearch)
	s.mcpServer.AddTool(WxUnreadTool, s.handleMCPWxUnread)
	s.mcpServer.AddTool(WxMembersTool, s.handleMCPWxMembers)
	s.mcpServer.AddTool(WxNewMessagesTool, s.handleMCPWxNewMessages)
	s.mcpServer.AddTool(WxStatsTool, s.handleMCPWxStats)
	s.mcpServer.AddTool(WxFavoritesTool, s.handleMCPWxFavorites)
	s.mcpServer.AddTool(WxSNSNotificationsTool, s.handleMCPWxSNSNotifications)
	s.mcpServer.AddTool(WxSNSFeedTool, s.handleMCPWxSNSFeed)
	s.mcpServer.AddTool(WxSNSSearchTool, s.handleMCPWxSNSSearch)
	s.mcpServer.AddPrompt(ChatSummaryDailyPrompt, s.handleMCPChatSummaryDaily)
	s.mcpServer.AddPrompt(ConflictDetectorPrompt, s.handleMCPConflictDetector)
	s.mcpServer.AddPrompt(RelationshipMilestonesPrompt, s.handleMCPRelationshipMilestones)
	s.mcpSSEServer = server.NewSSEServer(s.mcpServer,
		server.WithSSEEndpoint("/sse"),
		server.WithMessageEndpoint("/message"),
	)
	s.mcpStreamableServer = server.NewStreamableHTTPServer(s.mcpServer)
}

var ChatSummaryDailyPrompt = mcp.NewPrompt(
	"chat_summary_daily",
	mcp.WithPromptDescription("生成每日聊天摘要模板。"),
	mcp.WithArgument("date", mcp.ArgumentDescription("摘要日期 (YYYY-MM-DD)"), mcp.RequiredArgument()),
	mcp.WithArgument("talker", mcp.ArgumentDescription("对话方 ID"), mcp.RequiredArgument()),
)

var ConflictDetectorPrompt = mcp.NewPrompt(
	"conflict_detector",
	mcp.WithPromptDescription("情绪与冲突检测模板。"),
	mcp.WithArgument("talker", mcp.ArgumentDescription("对话方 ID"), mcp.RequiredArgument()),
)

var RelationshipMilestonesPrompt = mcp.NewPrompt(
	"relationship_milestones",
	mcp.WithPromptDescription("关系里程碑回顾模板。"),
	mcp.WithArgument("talker", mcp.ArgumentDescription("对话方 ID"), mcp.RequiredArgument()),
)

var SearchSharedFilesTool = mcp.NewTool(
	"search_shared_files",
	mcp.WithDescription(`专门搜索聊天记录中发送的文件元数据。当用户想找某个特定的共享文件时使用。`),
	mcp.WithString("talker", mcp.Description("对话方 ID"), mcp.Required()),
	mcp.WithString("keyword", mcp.Description("文件名搜索关键词")),
)

var GetUserProfileTool = mcp.NewTool(
	"get_user_profile",
	mcp.WithDescription(`获取联系人或群组的详细资料，包括备注、属性、群成员（如果是群组）等背景信息。用于更深入地了解对话方。`),
	mcp.WithString("key", mcp.Description("联系人或群组的 ID 或名称"), mcp.Required()),
)

var SendWebhookNotificationTool = mcp.NewTool(
	"send_webhook_notification",
	mcp.WithDescription(`触发外部 Webhook 通知。当模型完成聊天记录分析、发现重要事项或需要提醒外部系统时使用此工具。`),
	mcp.WithString("url", mcp.Description("Webhook 接收地址"), mcp.Required()),
	mcp.WithString("message", mcp.Description("要发送的通知内容或分析结果"), mcp.Required()),
	mcp.WithString("level", mcp.Description("通知级别 (info, warn, error)")),
)

var CurrentTimeTool = mcp.NewTool(
	"current_time",
	mcp.WithDescription(`获取当前系统时间，返回RFC3339格式的时间字符串（包含用户本地时区信息）。
使用场景：
- 当用户询问"总结今日聊天记录"、"本周都聊了啥"等当前时间问题
- 当用户提及"昨天"、"上周"、"本月"等相对时间概念，需要确定基准时间点
- 需要执行依赖当前时间的计算（如"上个月5号我们有开会吗"）
返回示例：2025-04-18T21:29:00+08:00
注意：此工具不需要任何输入参数，直接调用即可获取当前时间。`),
)

var WxPingTool = mcp.NewTool("wx_ping", mcp.WithDescription("wx-cli 兼容: ping"))
var WxContactsTool = mcp.NewTool(
	"wx_contacts",
	mcp.WithDescription("wx-cli 兼容: contacts"),
	mcp.WithString("query", mcp.Description("联系人关键词")),
	mcp.WithNumber("limit", mcp.Description("返回条数")),
	mcp.WithNumber("offset", mcp.Description("偏移")),
)
var WxChatRoomsTool = mcp.NewTool(
	"wx_chatrooms",
	mcp.WithDescription("wx-cli 兼容: chatrooms"),
	mcp.WithString("query", mcp.Description("群聊关键词")),
	mcp.WithNumber("limit", mcp.Description("返回条数")),
	mcp.WithNumber("offset", mcp.Description("偏移")),
)
var WxSessionsTool = mcp.NewTool(
	"wx_sessions",
	mcp.WithDescription("wx-cli 兼容: sessions"),
	mcp.WithNumber("limit", mcp.Description("返回条数")),
)
var WxHistoryTool = mcp.NewTool(
	"wx_history",
	mcp.WithDescription("wx-cli 兼容: history"),
	mcp.WithString("chat", mcp.Description("会话标识（昵称/备注/wxid）"), mcp.Required()),
	mcp.WithNumber("limit", mcp.Description("返回条数")),
	mcp.WithNumber("offset", mcp.Description("偏移")),
	mcp.WithString("time", mcp.Description("时间范围")),
	mcp.WithString("since", mcp.Description("开始时间戳（秒）")),
	mcp.WithString("until", mcp.Description("结束时间戳（秒）")),
	mcp.WithNumber("msg_type", mcp.Description("消息类型")),
)
var WxSearchTool = mcp.NewTool(
	"wx_search",
	mcp.WithDescription("wx-cli 兼容: search"),
	mcp.WithString("keyword", mcp.Description("关键词"), mcp.Required()),
	mcp.WithString("chats", mcp.Description("逗号分隔会话列表")),
	mcp.WithNumber("limit", mcp.Description("返回条数")),
	mcp.WithString("time", mcp.Description("时间范围")),
	mcp.WithString("since", mcp.Description("开始时间戳（秒）")),
	mcp.WithString("until", mcp.Description("结束时间戳（秒）")),
	mcp.WithNumber("msg_type", mcp.Description("消息类型")),
)
var WxSemanticSearchTool = mcp.NewTool(
	"wx_semantic_search",
	mcp.WithDescription("语义检索（向量索引）: 支持跨群、跨长时间窗口的语义相关消息检索。比 wx_search 关键词匹配召回率高，适合找『过去30天讨论过INTC加仓的群』、『历史上某个KOL的所有发言』、『跨会话的某话题演变』等问题。Embedding 由本地 Ollama qwen3-embedding 提供。"),
	mcp.WithString("query", mcp.Description("自然语言查询（可用中文，如 'INTC 加仓 止损'）"), mcp.Required()),
	mcp.WithString("chats", mcp.Description("逗号分隔的 chatroom_id / 会话标识列表；省略 = 全部已索引会话")),
	mcp.WithString("window", mcp.Description("时间窗口：1d/7d/30d/90d/1y；默认 30d")),
	mcp.WithNumber("limit", mcp.Description("返回 top_k；默认按 depth 自适应")),
	mcp.WithString("depth", mcp.Description("检索深度：shallow/normal/deep；默认 normal")),
	mcp.WithBoolean("rerank", mcp.Description("是否启用 reranker 二次排序（更准但更慢）；默认 true")),
)
var WxUnreadTool = mcp.NewTool(
	"wx_unread",
	mcp.WithDescription("wx-cli 兼容: unread"),
	mcp.WithNumber("limit", mcp.Description("返回条数")),
	mcp.WithString("filter", mcp.Description("private/group/official/folded/all")),
)
var WxMembersTool = mcp.NewTool(
	"wx_members",
	mcp.WithDescription("wx-cli 兼容: members"),
	mcp.WithString("chat", mcp.Description("群聊标识"), mcp.Required()),
)
var WxNewMessagesTool = mcp.NewTool(
	"wx_new_messages",
	mcp.WithDescription("wx-cli 兼容: new_messages"),
	mcp.WithNumber("limit", mcp.Description("返回条数")),
	mcp.WithString("state", mcp.Description("JSON 字符串: {\"username\":timestamp}")),
)
var WxStatsTool = mcp.NewTool(
	"wx_stats",
	mcp.WithDescription("wx-cli 兼容: stats"),
	mcp.WithString("chat", mcp.Description("会话标识"), mcp.Required()),
	mcp.WithString("time", mcp.Description("时间范围")),
	mcp.WithString("since", mcp.Description("开始时间戳（秒）")),
	mcp.WithString("until", mcp.Description("结束时间戳（秒）")),
)
var WxFavoritesTool = mcp.NewTool(
	"wx_favorites",
	mcp.WithDescription("wx-cli 兼容: favorites"),
	mcp.WithNumber("limit", mcp.Description("返回条数")),
	mcp.WithNumber("fav_type", mcp.Description("收藏类型")),
	mcp.WithString("query", mcp.Description("关键词")),
)
var WxSNSNotificationsTool = mcp.NewTool(
	"wx_sns_notifications",
	mcp.WithDescription("wx-cli 兼容: sns_notifications"),
	mcp.WithNumber("limit", mcp.Description("返回条数")),
	mcp.WithString("since", mcp.Description("开始时间戳（秒）")),
	mcp.WithString("until", mcp.Description("结束时间戳（秒）")),
	mcp.WithBoolean("include_read", mcp.Description("是否包含已读")),
)
var WxSNSFeedTool = mcp.NewTool(
	"wx_sns_feed",
	mcp.WithDescription("wx-cli 兼容: sns_feed"),
	mcp.WithNumber("limit", mcp.Description("返回条数")),
	mcp.WithString("since", mcp.Description("开始时间戳（秒）")),
	mcp.WithString("until", mcp.Description("结束时间戳（秒）")),
	mcp.WithString("user", mcp.Description("作者筛选")),
)
var WxSNSSearchTool = mcp.NewTool(
	"wx_sns_search",
	mcp.WithDescription("wx-cli 兼容: sns_search"),
	mcp.WithString("keyword", mcp.Description("关键词"), mcp.Required()),
	mcp.WithNumber("limit", mcp.Description("返回条数")),
	mcp.WithString("since", mcp.Description("开始时间戳（秒）")),
	mcp.WithString("until", mcp.Description("结束时间戳（秒）")),
	mcp.WithString("user", mcp.Description("作者筛选")),
)

func (s *Service) handleMCPCurrentTime(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: time.Now().Local().Format(time.RFC3339),
			},
		},
	}, nil
}

type SendWebhookNotificationRequest struct {
	URL     string `json:"url"`
	Message string `json:"message"`
	Level   string `json:"level"`
}

func (s *Service) handleMCPSendWebhookNotification(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var req SendWebhookNotificationRequest
	if err := request.BindArguments(&req); err != nil {
		return errors.ErrMCPTool(err), nil
	}

	payload := map[string]interface{}{
		"message":   req.Message,
		"level":     req.Level,
		"timestamp": time.Now().Format(time.RFC3339),
		"source":    "chatlog-mcp",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return errors.ErrMCPTool(err), nil
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", req.URL, bytes.NewBuffer(body))
	if err != nil {
		return errors.ErrMCPTool(err), nil
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return errors.ErrMCPTool(err), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.ErrMCPTool(fmt.Errorf("webhook returned status %d", resp.StatusCode)), nil
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: "Webhook 通知发送成功。",
			},
		},
	}, nil
}

type GetUserProfileRequest struct {
	Key string `json:"key"`
}

func (s *Service) handleMCPGetUserProfile(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var req GetUserProfileRequest
	if err := request.BindArguments(&req); err != nil {
		return errors.ErrMCPTool(err), nil
	}

	buf := &bytes.Buffer{}

	// 尝试作为群聊获取
	if chatRoom, err := s.db.GetChatRoom(req.Key); err == nil {
		buf.WriteString(fmt.Sprintf("【群聊资料】\n"))
		buf.WriteString(fmt.Sprintf("ID: %s\n", chatRoom.Name))
		buf.WriteString(fmt.Sprintf("名称: %s\n", chatRoom.NickName))
		if chatRoom.Remark != "" {
			buf.WriteString(fmt.Sprintf("备注: %s\n", chatRoom.Remark))
		}
		buf.WriteString(fmt.Sprintf("群主: %s\n", chatRoom.Owner))
		buf.WriteString(fmt.Sprintf("成员数: %d\n", len(chatRoom.Users)))
		buf.WriteString("\n部分成员列表:\n")
		for i, user := range chatRoom.Users {
			if i >= 20 {
				buf.WriteString("... 等等\n")
				break
			}
			displayName := chatRoom.User2DisplayName[user.UserName]
			buf.WriteString(fmt.Sprintf("- %s (%s)\n", displayName, user.UserName))
		}
	} else if contact, err := s.db.GetContact(req.Key); err == nil {
		// 尝试作为联系人获取
		buf.WriteString(fmt.Sprintf("【联系人资料】\n"))
		buf.WriteString(fmt.Sprintf("ID: %s\n", contact.UserName))
		buf.WriteString(fmt.Sprintf("昵称: %s\n", contact.NickName))
		if contact.Remark != "" {
			buf.WriteString(fmt.Sprintf("备注: %s\n", contact.Remark))
		}
		if contact.Alias != "" {
			buf.WriteString(fmt.Sprintf("微信号: %s\n", contact.Alias))
		}
		buf.WriteString(fmt.Sprintf("是否好友: %v\n", contact.IsFriend))
	} else {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: fmt.Sprintf("未找到相关联系人或群组: %s", req.Key),
				},
			},
		}, nil
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: buf.String(),
			},
		},
	}, nil
}

type SearchSharedFilesRequest struct {
	Talker  string `json:"talker"`
	Keyword string `json:"keyword"`
}

func (s *Service) callCompatEndpoint(path string, q url.Values) (string, error) {
	addr := strings.TrimSpace(s.conf.GetHTTPAddr())
	if addr == "" {
		return "", fmt.Errorf("HTTP address is empty")
	}
	u := fmt.Sprintf("http://%s%s", addr, path)
	if q != nil && len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	// History queries against large message DBs routinely take 30-90 seconds
	// (the handler re-decrypts source DBs from disk, scans up to GBs of
	// media_0.db, etc.). The previous 30s here caused every MCP wx_history
	// call to fail under realistic workloads even though the underlying
	// HTTP /api/v1/history would eventually return 200.
	resp, err := (&http.Client{Timeout: 300 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("request failed: %s", strings.TrimSpace(string(b)))
	}
	return string(b), nil
}

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: text},
		},
	}
}

func setOptionalInt(q url.Values, key string, v int) {
	if v > 0 {
		q.Set(key, strconv.Itoa(v))
	}
}

func setOptionalInt64(q url.Values, key string, v int64) {
	if v > 0 {
		q.Set(key, strconv.FormatInt(v, 10))
	}
}

func (s *Service) handleMCPWxPing(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	body, err := s.callCompatEndpoint("/api/v1/ping", nil)
	if err != nil {
		return errors.ErrMCPTool(err), nil
	}
	return textResult(body), nil
}

func (s *Service) handleMCPWxContacts(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var req struct {
		Query  string `json:"query"`
		Limit  int    `json:"limit"`
		Offset int    `json:"offset"`
	}
	_ = request.BindArguments(&req)
	q := url.Values{}
	if req.Query != "" {
		q.Set("query", req.Query)
	}
	setOptionalInt(q, "limit", req.Limit)
	if req.Offset > 0 {
		q.Set("offset", strconv.Itoa(req.Offset))
	}
	body, err := s.callCompatEndpoint("/api/v1/contacts", q)
	if err != nil {
		return errors.ErrMCPTool(err), nil
	}
	return textResult(body), nil
}

func (s *Service) handleMCPWxChatRooms(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var req struct {
		Query  string `json:"query"`
		Limit  int    `json:"limit"`
		Offset int    `json:"offset"`
	}
	_ = request.BindArguments(&req)
	q := url.Values{}
	if req.Query != "" {
		q.Set("query", req.Query)
	}
	setOptionalInt(q, "limit", req.Limit)
	if req.Offset > 0 {
		q.Set("offset", strconv.Itoa(req.Offset))
	}
	body, err := s.callCompatEndpoint("/api/v1/chatrooms", q)
	if err != nil {
		return errors.ErrMCPTool(err), nil
	}
	return textResult(body), nil
}

func (s *Service) handleMCPWxSessions(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var req struct {
		Limit int `json:"limit"`
	}
	_ = request.BindArguments(&req)
	q := url.Values{}
	setOptionalInt(q, "limit", req.Limit)
	body, err := s.callCompatEndpoint("/api/v1/sessions", q)
	if err != nil {
		return errors.ErrMCPTool(err), nil
	}
	return textResult(body), nil
}

func (s *Service) handleMCPWxHistory(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var req struct {
		Chat    string `json:"chat"`
		Limit   int    `json:"limit"`
		Offset  int    `json:"offset"`
		Time    string `json:"time"`
		Since   string `json:"since"`
		Until   string `json:"until"`
		MsgType int64  `json:"msg_type"`
	}
	if err := request.BindArguments(&req); err != nil {
		return errors.ErrMCPTool(err), nil
	}
	if strings.TrimSpace(req.Chat) == "" {
		return errors.ErrMCPTool(fmt.Errorf("chat is required")), nil
	}
	q := url.Values{}
	q.Set("chat", req.Chat)
	setOptionalInt(q, "limit", req.Limit)
	if req.Offset > 0 {
		q.Set("offset", strconv.Itoa(req.Offset))
	}
	if req.Time != "" {
		q.Set("time", req.Time)
	}
	if req.Since != "" {
		q.Set("since", req.Since)
	}
	if req.Until != "" {
		q.Set("until", req.Until)
	}
	setOptionalInt64(q, "msg_type", req.MsgType)
	body, err := s.callCompatEndpoint("/api/v1/history", q)
	if err != nil {
		return errors.ErrMCPTool(err), nil
	}
	return textResult(body), nil
}

func (s *Service) handleMCPWxSearch(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var req struct {
		Keyword string `json:"keyword"`
		Chats   string `json:"chats"`
		Limit   int    `json:"limit"`
		Time    string `json:"time"`
		Since   string `json:"since"`
		Until   string `json:"until"`
		MsgType int64  `json:"msg_type"`
	}
	if err := request.BindArguments(&req); err != nil {
		return errors.ErrMCPTool(err), nil
	}
	if strings.TrimSpace(req.Keyword) == "" {
		return errors.ErrMCPTool(fmt.Errorf("keyword is required")), nil
	}
	q := url.Values{}
	q.Set("keyword", req.Keyword)
	if req.Chats != "" {
		q.Set("chats", req.Chats)
	}
	setOptionalInt(q, "limit", req.Limit)
	if req.Time != "" {
		q.Set("time", req.Time)
	}
	if req.Since != "" {
		q.Set("since", req.Since)
	}
	if req.Until != "" {
		q.Set("until", req.Until)
	}
	setOptionalInt64(q, "msg_type", req.MsgType)
	body, err := s.callCompatEndpoint("/api/v1/search", q)
	if err != nil {
		return errors.ErrMCPTool(err), nil
	}
	return textResult(body), nil
}

func (s *Service) handleMCPWxSemanticSearch(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var req struct {
		Query  string `json:"query"`
		Chats  string `json:"chats"`
		Window string `json:"window"`
		Limit  int    `json:"limit"`
		Depth  string `json:"depth"`
		Rerank *bool  `json:"rerank"`
	}
	if err := request.BindArguments(&req); err != nil {
		return errors.ErrMCPTool(err), nil
	}
	if strings.TrimSpace(req.Query) == "" {
		return errors.ErrMCPTool(fmt.Errorf("query is required")), nil
	}
	q := url.Values{}
	q.Set("query", req.Query)
	if req.Chats != "" {
		q.Set("chats", req.Chats)
	}
	if req.Window != "" {
		q.Set("window", req.Window)
	}
	setOptionalInt(q, "limit", req.Limit)
	if req.Depth != "" {
		q.Set("depth", req.Depth)
	}
	if req.Rerank != nil {
		if *req.Rerank {
			q.Set("rerank", "1")
		} else {
			q.Set("rerank", "0")
		}
	}
	body, err := s.callCompatEndpoint("/api/v1/semantic/search", q)
	if err != nil {
		return errors.ErrMCPTool(err), nil
	}
	return textResult(body), nil
}

func (s *Service) handleMCPWxUnread(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var req struct {
		Limit  int    `json:"limit"`
		Filter string `json:"filter"`
	}
	_ = request.BindArguments(&req)
	q := url.Values{}
	setOptionalInt(q, "limit", req.Limit)
	if req.Filter != "" {
		q.Set("filter", req.Filter)
	}
	body, err := s.callCompatEndpoint("/api/v1/unread", q)
	if err != nil {
		return errors.ErrMCPTool(err), nil
	}
	return textResult(body), nil
}

func (s *Service) handleMCPWxMembers(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var req struct {
		Chat string `json:"chat"`
	}
	if err := request.BindArguments(&req); err != nil {
		return errors.ErrMCPTool(err), nil
	}
	if strings.TrimSpace(req.Chat) == "" {
		return errors.ErrMCPTool(fmt.Errorf("chat is required")), nil
	}
	q := url.Values{"chat": []string{req.Chat}}
	body, err := s.callCompatEndpoint("/api/v1/members", q)
	if err != nil {
		return errors.ErrMCPTool(err), nil
	}
	return textResult(body), nil
}

func (s *Service) handleMCPWxNewMessages(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var req struct {
		Limit int    `json:"limit"`
		State string `json:"state"`
	}
	_ = request.BindArguments(&req)
	q := url.Values{}
	setOptionalInt(q, "limit", req.Limit)
	if req.State != "" {
		q.Set("state", req.State)
	}
	body, err := s.callCompatEndpoint("/api/v1/new_messages", q)
	if err != nil {
		return errors.ErrMCPTool(err), nil
	}
	return textResult(body), nil
}

func (s *Service) handleMCPWxStats(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var req struct {
		Chat  string `json:"chat"`
		Time  string `json:"time"`
		Since string `json:"since"`
		Until string `json:"until"`
	}
	if err := request.BindArguments(&req); err != nil {
		return errors.ErrMCPTool(err), nil
	}
	if strings.TrimSpace(req.Chat) == "" {
		return errors.ErrMCPTool(fmt.Errorf("chat is required")), nil
	}
	q := url.Values{"chat": []string{req.Chat}}
	if req.Time != "" {
		q.Set("time", req.Time)
	}
	if req.Since != "" {
		q.Set("since", req.Since)
	}
	if req.Until != "" {
		q.Set("until", req.Until)
	}
	body, err := s.callCompatEndpoint("/api/v1/stats", q)
	if err != nil {
		return errors.ErrMCPTool(err), nil
	}
	return textResult(body), nil
}

func (s *Service) handleMCPWxFavorites(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var req struct {
		Limit   int    `json:"limit"`
		FavType int64  `json:"fav_type"`
		Query   string `json:"query"`
	}
	_ = request.BindArguments(&req)
	q := url.Values{}
	setOptionalInt(q, "limit", req.Limit)
	setOptionalInt64(q, "fav_type", req.FavType)
	if req.Query != "" {
		q.Set("query", req.Query)
	}
	body, err := s.callCompatEndpoint("/api/v1/favorites", q)
	if err != nil {
		return errors.ErrMCPTool(err), nil
	}
	return textResult(body), nil
}

func (s *Service) handleMCPWxSNSNotifications(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var req struct {
		Limit       int    `json:"limit"`
		Since       string `json:"since"`
		Until       string `json:"until"`
		IncludeRead bool   `json:"include_read"`
	}
	_ = request.BindArguments(&req)
	q := url.Values{}
	setOptionalInt(q, "limit", req.Limit)
	if req.Since != "" {
		q.Set("since", req.Since)
	}
	if req.Until != "" {
		q.Set("until", req.Until)
	}
	if req.IncludeRead {
		q.Set("include_read", "true")
	}
	body, err := s.callCompatEndpoint("/api/v1/sns_notifications", q)
	if err != nil {
		return errors.ErrMCPTool(err), nil
	}
	return textResult(body), nil
}

func (s *Service) handleMCPWxSNSFeed(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var req struct {
		Limit int    `json:"limit"`
		Since string `json:"since"`
		Until string `json:"until"`
		User  string `json:"user"`
	}
	_ = request.BindArguments(&req)
	q := url.Values{}
	setOptionalInt(q, "limit", req.Limit)
	if req.Since != "" {
		q.Set("since", req.Since)
	}
	if req.Until != "" {
		q.Set("until", req.Until)
	}
	if req.User != "" {
		q.Set("user", req.User)
	}
	body, err := s.callCompatEndpoint("/api/v1/sns_feed", q)
	if err != nil {
		return errors.ErrMCPTool(err), nil
	}
	return textResult(body), nil
}

func (s *Service) handleMCPWxSNSSearch(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var req struct {
		Keyword string `json:"keyword"`
		Limit   int    `json:"limit"`
		Since   string `json:"since"`
		Until   string `json:"until"`
		User    string `json:"user"`
	}
	if err := request.BindArguments(&req); err != nil {
		return errors.ErrMCPTool(err), nil
	}
	if strings.TrimSpace(req.Keyword) == "" {
		return errors.ErrMCPTool(fmt.Errorf("keyword is required")), nil
	}
	q := url.Values{"keyword": []string{req.Keyword}}
	setOptionalInt(q, "limit", req.Limit)
	if req.Since != "" {
		q.Set("since", req.Since)
	}
	if req.Until != "" {
		q.Set("until", req.Until)
	}
	if req.User != "" {
		q.Set("user", req.User)
	}
	body, err := s.callCompatEndpoint("/api/v1/sns_search", q)
	if err != nil {
		return errors.ErrMCPTool(err), nil
	}
	return textResult(body), nil
}

func (s *Service) handleMCPSearchSharedFiles(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var req SearchSharedFilesRequest
	if err := request.BindArguments(&req); err != nil {
		return errors.ErrMCPTool(err), nil
	}

	// 查找 MessageTypeShare (49) 且 MessageSubTypeFile (6)
	messages, err := s.db.GetMessages(time.Time{}, time.Now(), req.Talker, "", req.Keyword, 50, 0)
	if err != nil {
		return errors.ErrMCPTool(err), nil
	}

	buf := &bytes.Buffer{}
	count := 0
	for _, m := range messages {
		if m.Type == model.MessageTypeShare && m.SubType == model.MessageSubTypeFile {
			title, _ := m.Contents["title"].(string)
			buf.WriteString(fmt.Sprintf("[%d] %s - %s\n", m.Seq, m.Time.Format("2006-01-02 15:04"), title))
			count++
		}
	}

	if count == 0 {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: "未找到相关共享文件。",
				},
			},
		}, nil
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: fmt.Sprintf("找到 %d 个文件:\n%s", count, buf.String()),
			},
		},
	}, nil
}

func (s *Service) handleMCPChatSummaryDaily(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	date := request.Params.Arguments["date"]
	talker := request.Params.Arguments["talker"]

	return mcp.NewGetPromptResult(
		"每日聊天摘要指令",
		[]mcp.PromptMessage{
			mcp.NewPromptMessage(mcp.RoleUser, mcp.TextContent{
				Type: "text",
				Text: fmt.Sprintf("请分析并在总结 %s 在 %s 的聊天内容。请先使用 wx_history 获取当天的完整记录，然后从关键话题、重要决策、待办事项三个维度进行总结。", talker, date),
			}),
		},
	), nil
}

func (s *Service) handleMCPConflictDetector(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	talker := request.Params.Arguments["talker"]

	return mcp.NewGetPromptResult(
		"情绪与冲突检测指令",
		[]mcp.PromptMessage{
			mcp.NewPromptMessage(mcp.RoleUser, mcp.TextContent{
				Type: "text",
				Text: fmt.Sprintf("请分析与 %s 最近的聊天记录，识别是否存在潜在的情绪波动或冲突。请关注语气变化、负面词汇频率以及争议性话题。", talker),
			}),
		},
	), nil
}

func (s *Service) handleMCPRelationshipMilestones(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	talker := request.Params.Arguments["talker"]

	return mcp.NewGetPromptResult(
		"关系里程碑回顾指令",
		[]mcp.PromptMessage{
			mcp.NewPromptMessage(mcp.RoleUser, mcp.TextContent{
				Type: "text",
				Text: fmt.Sprintf("请回顾与 %s 的历史聊天记录，找出重要的关系里程碑（如：初次相识、重大合作达成、共同解决的危机等）。", talker),
			}),
		},
	), nil
}
