package http

import (
	"context"
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"github.com/xuri/excelize/v2"
	"gopkg.in/yaml.v3"

	"github.com/sjzar/chatlog/internal/chatlog/conf"
	"github.com/sjzar/chatlog/internal/chatlog/hermespush"
	"github.com/sjzar/chatlog/internal/chatlog/semantic"
	chatwechat "github.com/sjzar/chatlog/internal/chatlog/wechat"
	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/model"
	"github.com/sjzar/chatlog/pkg/util"
	"github.com/sjzar/chatlog/pkg/util/dat2img"
	"github.com/sjzar/chatlog/pkg/util/silk"
)

// EFS holds embedded file system data for static assets.
//
//go:embed static
var EFS embed.FS

var (
	semanticWechatUsernamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{5,}$`)
	semanticDateWindowPattern     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	semanticMonthDayPattern       = regexp.MustCompile(`(\d{1,2})月(\d{1,2})[日号]?`)
	semanticASCIIAlnumTokenRe     = regexp.MustCompile(`^[a-z0-9._-]+$`)
	semanticHasCJKRe              = regexp.MustCompile(`[\p{Han}]`)
	semanticMentionRe             = regexp.MustCompile(`@([^\s@，,。；;：:！!？?\[\]\(\)（）<>《》"']{1,32})`)
)

func (s *Service) initRouter() {
	s.initBaseRouter()
	s.initMediaRouter()
	s.initAPIRouter()
	s.initMCPRouter()
}

func (s *Service) initBaseRouter() {
	staticDir, _ := fs.Sub(EFS, "static")

	s.router.StaticFS("/static", http.FS(staticDir))
	s.router.StaticFileFS("/favicon.ico", "./favicon.ico", http.FS(staticDir))
	s.router.StaticFileFS("/", "./index.htm", http.FS(staticDir))

	s.router.GET("/health", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	// ping 不依赖数据库状态，放在中间件外层，保持可用性。
	s.router.GET("/api/v1/ping", s.handlePing)
	s.router.GET("/api/v1/hook/config", s.handleHookConfigGet)
	s.router.POST("/api/v1/hook/config", s.handleHookConfigSet)
	s.router.GET("/api/v1/hook/status", s.handleHookStatus)
	s.router.GET("/api/v1/hook/events", s.handleHookEvents)
	s.router.POST("/api/v1/hook/events/clear", s.handleHookEventsClear)
	s.router.GET("/api/v1/hook/hermes/weixin", s.handleHookHermesWeixinGet)
	s.router.POST("/api/v1/hook/hermes/weixin", s.handleHookHermesWeixinSet)
	s.router.GET("/api/v1/hook/hermes/qq", s.handleHookHermesQQGet)
	s.router.POST("/api/v1/hook/hermes/qq", s.handleHookHermesQQSet)
	s.router.GET("/api/v1/hook/stream", s.handleHookStream)
	s.router.GET("/api/v1/semantic/config", s.handleSemanticConfigGet)
	s.router.POST("/api/v1/semantic/config", s.handleSemanticConfigSet)
	s.router.POST("/api/v1/semantic/test", s.handleSemanticTest)
	s.router.GET("/api/v1/semantic/index/status", s.handleSemanticIndexStatus)
	s.router.GET("/api/v1/semantic/index/preview", s.handleSemanticIndexPreview)
	s.router.POST("/api/v1/semantic/qa/stream", s.handleSemanticQAStream)

	s.router.NoRoute(s.NoRoute)
}

func (s *Service) initMediaRouter() {
	s.router.GET("/image/*key", func(c *gin.Context) { s.handleMedia(c, "image") })
	s.router.GET("/video/*key", func(c *gin.Context) { s.handleMedia(c, "video") })
	s.router.GET("/file/*key", func(c *gin.Context) { s.handleMedia(c, "file") })
	s.router.GET("/voice/*key", func(c *gin.Context) { s.handleMedia(c, "voice") })
	s.router.GET("/data/*path", s.handleMediaData)
}

func (s *Service) initAPIRouter() {
	api := s.router.Group("/api/v1", s.checkDBStateMiddleware())
	{
		api.GET("/sessions", s.handleSessionsCompat)
		api.GET("/history", s.handleHistory)
		api.GET("/search", s.handleSearchCompat)
		api.GET("/unread", s.handleUnreadCompat)
		api.GET("/members", s.handleMembersCompat)
		api.GET("/new_messages", s.handleNewMessagesCompat)
		api.GET("/stats", s.handleStatsCompat)
		api.GET("/favorites", s.handleFavoritesCompat)
		api.GET("/sns_notifications", s.handleSNSNotificationsCompat)
		api.GET("/sns_feed", s.handleSNSFeedCompat)
		api.GET("/sns_search", s.handleSNSSearchCompat)
		api.GET("/sns/media/proxy", s.handleSNSMediaProxy)
		api.GET("/contacts", s.handleContactsCompat)
		api.GET("/chatrooms", s.handleChatRoomsCompat)
		api.GET("/db", s.handleGetDBs)
		api.GET("/db/search", s.handleSearchAllDBs)
		api.GET("/db/tables", s.handleGetDBTables)
		api.GET("/db/data", s.handleGetDBTableData)
		api.GET("/db/query", s.handleExecuteSQL)
		api.POST("/cache/clear", s.handleClearCache)
		api.POST("/semantic/index/rebuild", s.handleSemanticRebuild)
		api.POST("/semantic/index/pause", s.handleSemanticPause)
		api.POST("/semantic/index/resume", s.handleSemanticResume)
		api.POST("/semantic/index/clear", s.handleSemanticClear)
		api.GET("/semantic/search", s.handleSemanticSearch)
		api.POST("/semantic/qa", s.handleSemanticQA)
		api.GET("/semantic/topics", s.handleSemanticTopics)
		api.GET("/semantic/profiles", s.handleSemanticProfiles)
		api.GET("/dashboard/trend", s.handleDashboardTrend)
	}
}

func (s *Service) handlePing(c *gin.Context) {
	writeByFormat(c, gin.H{"pong": true}, c.Query("format"))
}

func (s *Service) handleHookConfigGet(c *gin.Context) {
	cfg := s.conf.GetMessageHook()
	if cfg == nil {
		cfg = &conf.MessageHook{}
	}
	writeByFormat(c, gin.H{
		"keywords":          strings.TrimSpace(cfg.Keywords),
		"notify_mode":       conf.CanonicalHookNotifyMode(cfg.NotifyMode),
		"post_url":          strings.TrimSpace(cfg.PostURL),
		"before_count":      cfg.BeforeCount,
		"after_count":       cfg.AfterCount,
		"forward_all":       cfg.ForwardAll,
		"forward_contacts":  strings.TrimSpace(cfg.ForwardContacts),
		"forward_chatrooms": strings.TrimSpace(cfg.ForwardChatRooms),
	}, c.Query("format"))
}

type hookConfigReq struct {
	Keywords         string `json:"keywords"`
	NotifyMode       string `json:"notify_mode"`
	PostURL          string `json:"post_url"`
	BeforeCount      int    `json:"before_count"`
	AfterCount       int    `json:"after_count"`
	ForwardAll       bool   `json:"forward_all"`
	ForwardContacts  string `json:"forward_contacts"`
	ForwardChatRooms string `json:"forward_chatrooms"`
}

func (s *Service) handleHookConfigSet(c *gin.Context) {
	var req hookConfigReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.Err(c, errors.InvalidArg("body"))
		return
	}

	if _, ok := conf.ParseHookNotifyTargets(req.NotifyMode); !ok {
		errors.Err(c, errors.InvalidArg("notify_mode"))
		return
	}
	if req.BeforeCount < 0 {
		errors.Err(c, errors.InvalidArg("before_count"))
		return
	}
	if req.AfterCount < 0 {
		errors.Err(c, errors.InvalidArg("after_count"))
		return
	}
	mode := conf.CanonicalHookNotifyMode(req.NotifyMode)
	targets, _ := conf.ParseHookNotifyTargets(mode)
	if targets.Weixin {
		install := hermespush.DetectInstallation()
		if !install.Installed {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Hermes agent 未安装，无法启用 weixin 推送"})
			return
		}
		if _, err := hermespush.DiscoverWeixinConfig(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Hermes agent 未完成微信渠道配置: " + err.Error()})
			return
		}
	}
	if targets.QQ {
		install := hermespush.DetectInstallation()
		if !install.Installed {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Hermes agent 未安装，无法启用 qq 推送"})
			return
		}
		if _, err := hermespush.DiscoverQQConfig(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Hermes agent 未完成 QQ 渠道配置: " + err.Error()})
			return
		}
	}
	keywords := strings.TrimSpace(req.Keywords)
	forwardContacts := strings.TrimSpace(req.ForwardContacts)
	forwardChatRooms := strings.TrimSpace(req.ForwardChatRooms)
	if req.ForwardAll {
		keywords = ""
		forwardContacts = ""
		forwardChatRooms = ""
	}

	s.conf.SetHookKeywords(keywords)
	s.conf.SetHookNotifyMode(mode)
	s.conf.SetHookPostURL(strings.TrimSpace(req.PostURL))
	s.conf.SetHookBeforeCount(req.BeforeCount)
	s.conf.SetHookAfterCount(req.AfterCount)
	s.conf.SetHookForwardAll(req.ForwardAll)
	s.conf.SetHookForwardContacts(forwardContacts)
	s.conf.SetHookForwardChatRooms(forwardChatRooms)
	s.handleHookConfigGet(c)
}

type semanticConfigReq struct {
	Enabled             bool    `json:"enabled"`
	APIKey              string  `json:"api_key"`
	BaseURL             string  `json:"base_url"`
	EmbeddingModel      string  `json:"embedding_model"`
	RerankModel         string  `json:"rerank_model"`
	ChatModel           string  `json:"chat_model"`
	ChatThinking        bool    `json:"chat_thinking"`
	ChatMaxTokens       int     `json:"chat_max_tokens"`
	ChatTemperature     float64 `json:"chat_temperature"`
	EmbeddingDimension  int     `json:"embedding_dimension"`
	EnableRerank        bool    `json:"enable_rerank"`
	EnableQA            bool    `json:"enable_qa"`
	EnableTopics        bool    `json:"enable_topics"`
	EnableProfiles      bool    `json:"enable_profiles"`
	EnableLLMChunk      bool    `json:"enable_llm_chunk"`
	RealtimeIndex       bool    `json:"realtime_index"`
	IndexWorkers        int     `json:"index_workers"`
	RecallK             int     `json:"recall_k"`
	TopN                int     `json:"top_n"`
	SimilarityThreshold float64 `json:"similarity_threshold"`
}

func (s *Service) handleSemanticConfigGet(c *gin.Context) {
	cfg := s.conf.GetSemanticConfig()
	if cfg == nil {
		cfg = &conf.SemanticConfig{}
	}
	norm := conf.NormalizeSemanticConfig(*cfg)
	writeByFormat(c, gin.H{
		"enabled":              norm.Enabled,
		"api_key":              "",
		"has_api_key":          strings.TrimSpace(norm.APIKey) != "",
		"base_url":             norm.BaseURL,
		"embedding_model":      norm.EmbeddingModel,
		"rerank_model":         norm.RerankModel,
		"chat_model":           norm.ChatModel,
		"chat_thinking":        norm.ChatThinking,
		"chat_max_tokens":      norm.ChatMaxTokens,
		"chat_temperature":     norm.ChatTemperature,
		"embedding_dimension":  norm.EmbeddingDimension,
		"enable_rerank":        norm.EnableRerank,
		"enable_qa":            norm.EnableQA,
		"enable_topics":        norm.EnableTopics,
		"enable_profiles":      norm.EnableProfiles,
		"enable_llm_chunk":     norm.EnableLLMChunk,
		"realtime_index":       norm.RealtimeIndex,
		"index_workers":        norm.IndexWorkers,
		"recall_k":             norm.RecallK,
		"top_n":                norm.TopN,
		"similarity_threshold": norm.SimilarityThreshold,
	}, c.Query("format"))
}

func (s *Service) handleSemanticConfigSet(c *gin.Context) {
	var req semanticConfigReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.Err(c, errors.InvalidArg("body"))
		return
	}
	cfg := conf.NormalizeSemanticConfig(conf.SemanticConfig{
		Enabled:             true,
		APIKey:              strings.TrimSpace(req.APIKey),
		BaseURL:             strings.TrimSpace(req.BaseURL),
		EmbeddingModel:      strings.TrimSpace(req.EmbeddingModel),
		RerankModel:         strings.TrimSpace(req.RerankModel),
		ChatModel:           strings.TrimSpace(req.ChatModel),
		ChatThinking:        req.ChatThinking,
		ChatMaxTokens:       req.ChatMaxTokens,
		ChatTemperature:     req.ChatTemperature,
		EmbeddingDimension:  req.EmbeddingDimension,
		EnableRerank:        true,
		EnableQA:            true,
		EnableTopics:        true,
		EnableProfiles:      true,
		EnableLLMChunk:      req.EnableLLMChunk,
		RealtimeIndex:       true,
		IndexWorkers:        req.IndexWorkers,
		RecallK:             req.RecallK,
		TopN:                req.TopN,
		SimilarityThreshold: req.SimilarityThreshold,
	})
	if strings.TrimSpace(cfg.APIKey) == "" {
		if old := s.conf.GetSemanticConfig(); old != nil {
			cfg.APIKey = strings.TrimSpace(old.APIKey)
		}
	}
	if s.semantic == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "semantic manager unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()
	if err := s.semantic.TestConnection(ctx, cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "GLM 连通性测试失败: " + err.Error()})
		return
	}
	s.conf.SetSemanticConfig(cfg)
	s.handleSemanticConfigGet(c)
}

func (s *Service) handleSemanticTest(c *gin.Context) {
	cfg := conf.SemanticConfig{}
	if cur := s.conf.GetSemanticConfig(); cur != nil {
		cfg = *cur
	}
	if err := c.ShouldBindJSON(&cfg); err != nil {
		// body optional: if empty, use saved config
	}
	cfg = conf.NormalizeSemanticConfig(cfg)
	if strings.TrimSpace(cfg.APIKey) == "" {
		if old := s.conf.GetSemanticConfig(); old != nil {
			cfg.APIKey = strings.TrimSpace(old.APIKey)
		}
	}
	if s.semantic == nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "semantic manager unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()
	if err := s.semantic.TestConnection(ctx, cfg); err != nil {
		c.JSON(http.StatusOK, gin.H{"ok": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Service) handleSemanticIndexStatus(c *gin.Context) {
	if s.semantic == nil {
		writeByFormat(c, gin.H{
			"ready":   false,
			"enabled": false,
			"error":   "semantic manager unavailable",
		}, c.Query("format"))
		return
	}
	writeByFormat(c, s.semantic.Status(), c.Query("format"))
}

func (s *Service) handleSemanticIndexPreview(c *gin.Context) {
	if s.semantic == nil {
		errors.Err(c, fmt.Errorf("semantic manager unavailable"))
		return
	}
	kind := strings.TrimSpace(c.Query("kind"))
	talker := strings.TrimSpace(c.Query("talker"))
	limit := parseIntDefault(c.Query("limit"), 20)
	offset := parseIntDefault(c.Query("offset"), 0)
	preview, err := s.semantic.PreviewIndexScoped(kind, talker, limit, offset)
	if err != nil {
		errors.Err(c, err)
		return
	}
	writeByFormat(c, preview, c.Query("format"))
}

func (s *Service) handleSemanticRebuild(c *gin.Context) {
	if s.semantic == nil {
		errors.Err(c, fmt.Errorf("semantic manager unavailable"))
		return
	}
	reset := strings.EqualFold(strings.TrimSpace(c.Query("reset")), "1") ||
		strings.EqualFold(strings.TrimSpace(c.Query("reset")), "true")
	if err := s.semantic.StartRebuild(12*time.Hour, reset); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error(), "status": s.semantic.Status()})
		return
	}
	writeByFormat(c, gin.H{"ok": true, "accepted": true, "status": s.semantic.Status()}, c.Query("format"))
}

func (s *Service) handleSemanticPause(c *gin.Context) {
	if s.semantic == nil {
		errors.Err(c, fmt.Errorf("semantic manager unavailable"))
		return
	}
	if err := s.semantic.Pause(); err != nil {
		errors.Err(c, err)
		return
	}
	writeByFormat(c, gin.H{"ok": true, "status": s.semantic.Status()}, c.Query("format"))
}

func (s *Service) handleSemanticResume(c *gin.Context) {
	if s.semantic == nil {
		errors.Err(c, fmt.Errorf("semantic manager unavailable"))
		return
	}
	if err := s.semantic.Resume(12 * time.Hour); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error(), "status": s.semantic.Status()})
		return
	}
	writeByFormat(c, gin.H{"ok": true, "status": s.semantic.Status()}, c.Query("format"))
}

func (s *Service) handleSemanticClear(c *gin.Context) {
	if s.semantic == nil {
		errors.Err(c, fmt.Errorf("semantic manager unavailable"))
		return
	}
	if err := s.semantic.Clear(); err != nil {
		errors.Err(c, err)
		return
	}
	writeByFormat(c, gin.H{"ok": true, "status": s.semantic.Status()}, c.Query("format"))
}

func (s *Service) handleSemanticSearch(c *gin.Context) {
	if s.semantic == nil {
		errors.Err(c, fmt.Errorf("semantic manager unavailable"))
		return
	}
	if err := s.ensureSemanticIndexReady(); err != nil {
		errors.Err(c, err)
		return
	}
	query := strings.TrimSpace(c.Query("query"))
	if query == "" {
		query = strings.TrimSpace(c.Query("keyword"))
	}
	if query == "" {
		errors.Err(c, errors.InvalidArg("query"))
		return
	}
	limit := 0
	if strings.TrimSpace(c.Query("limit")) != "" {
		limit, _ = strconv.Atoi(c.Query("limit"))
	}
	limit = semanticSearchTopN(limit, c.Query("depth"))
	rerank := strings.EqualFold(strings.TrimSpace(c.DefaultQuery("rerank", "1")), "1") ||
		strings.EqualFold(strings.TrimSpace(c.Query("rerank")), "true")
	talker := strings.TrimSpace(c.Query("chat"))
	sourceLimit, _ := strconv.Atoi(c.DefaultQuery("source_limit", "50"))
	talkers, err := s.semanticTalkerScope(talker, c.Query("chats"), sourceLimit)
	if err != nil {
		errors.Err(c, err)
		return
	}
	windowKey := semanticEffectiveWindow(query, c.DefaultQuery("window", "7d"))
	_, _, start, end := parseSemanticWindow(windowKey)
	result, err := s.semantic.SearchWithMetaScoped(c.Request.Context(), query, talkers, start, end, limit, rerank)
	if err != nil {
		errors.Err(c, err)
		return
	}
	writeByFormat(c, gin.H{
		"query":          query,
		"chat":           talker,
		"source_count":   len(talkers),
		"window":         windowKey,
		"depth":          normalizeSemanticDepth(c.Query("depth")),
		"count":          len(result.Hits),
		"rerank":         rerank,
		"rerank_tried":   result.RerankTried,
		"rerank_applied": result.RerankApplied,
		"rerank_error":   result.RerankError,
		"results":        result.Hits,
	}, c.Query("format"))
}

func (s *Service) handleSemanticQA(c *gin.Context) {
	req, err := s.parseSemanticQARequest(c)
	if err != nil {
		errors.Err(c, err)
		return
	}
	payload, err := s.executeSemanticQA(c.Request.Context(), req, nil)
	if err != nil {
		errors.Err(c, err)
		return
	}
	writeByFormat(c, payload, c.Query("format"))
}

func (s *Service) handleSemanticQAStream(c *gin.Context) {
	req, err := s.parseSemanticQARequest(c)
	if err != nil {
		errors.Err(c, err)
		return
	}

	w := c.Writer
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	writeEvent := func(event string, payload any) error {
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, raw); err != nil {
			return err
		}
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	}
	payload, err := s.executeSemanticQA(c.Request.Context(), req, func(delta string) error {
		return writeEvent("delta", gin.H{"text": delta})
	})
	if err != nil {
		_ = writeEvent("error", gin.H{"error": err.Error()})
		return
	}
	_ = writeEvent("done", payload)
}

func (s *Service) handleSemanticTopics(c *gin.Context) {
	if err := s.ensureSemanticIndexReady(); err != nil {
		errors.Err(c, err)
		return
	}
	chat := strings.TrimSpace(c.Query("chat"))
	windowKey, windowLabel, start, end := parseSemanticWindow(c.Query("window"))
	msgs, truncated, err := s.collectSemanticMessages(chat, start, end)
	if err != nil {
		errors.Err(c, err)
		return
	}
	topics := summarizeTopics(msgs, 50)
	daily := summarizeDailyMessages(msgs, start, end)
	summary, summaryErr := s.summarizeSemantic(c.Request.Context(), "主题趋势分析", gin.H{
		"window": windowLabel,
		"chat":   chat,
		"count":  len(msgs),
		"topics": topics,
		"daily":  daily,
	})
	writeByFormat(c, gin.H{
		"chat":          chat,
		"window":        windowKey,
		"window_label":  windowLabel,
		"from":          formatWindowTime(start),
		"to":            formatWindowTime(end),
		"count":         len(msgs),
		"truncated":     truncated,
		"topics":        topics,
		"daily":         daily,
		"summary":       summary,
		"summary_error": errorString(summaryErr),
	}, c.Query("format"))
}

func (s *Service) handleDashboardTrend(c *gin.Context) {
	chat := strings.TrimSpace(c.Query("chat"))
	windowKey, windowLabel, start, end := parseSemanticWindow(c.Query("window"))
	msgs, truncated, err := s.collectSemanticMessages(chat, start, end)
	if err != nil {
		errors.Err(c, err)
		return
	}
	daily := summarizeDailyMessages(msgs, start, end)
	wantSummary := strings.EqualFold(strings.TrimSpace(c.DefaultQuery("summary", "1")), "1")
	topicsSource := "local_fallback"
	topicsErr := error(nil)
	topics := summarizeTopics(msgs, 50)
	if wantSummary {
		if llmTopics, err := s.extractDashboardTopicsWithLLM(c.Request.Context(), msgs, 50); err == nil && len(llmTopics) > 0 {
			topics = llmTopics
			topicsSource = "llm"
		} else if err != nil {
			topicsErr = err
		}
	}
	mentions := summarizeMentions(msgs, 20)
	summary := ""
	summaryErr := error(nil)
	if wantSummary {
		rawMessages := dashboardSummaryMessageRows(msgs, 260)
		summary, summaryErr = s.summarizeSemanticWithTimeout(c.Request.Context(), "仪表盘热点摘要", gin.H{
			"window":              windowLabel,
			"chat":                chat,
			"count":               len(msgs),
			"raw_message_sampled": len(rawMessages) < len(msgs),
			"raw_message_count":   len(rawMessages),
			"raw_messages":        rawMessages,
			"daily":               lastN(daily, 45),
			"llm_topics":          firstN(topics, 20),
			"topics_source":       topicsSource,
			"top_mentions":        firstN(mentions, 15),
			"instruction":         "请优先基于 raw_messages 原始聊天内容自行提炼热点，llm_topics 是已由模型归并过的候选主题，top_mentions 表示被 @ 最多的人。输出 Markdown 中文仪表盘热点摘要，包含：1. 主要结论；2. 值得关注的变化；3. 被 @ 关注点；4. 不确定性与使用提醒。不要逐条复述原始消息，不要编造统计中没有的信息。",
		}, 45*time.Second)
	}
	writeByFormat(c, gin.H{
		"chat":          chat,
		"window":        windowKey,
		"window_label":  windowLabel,
		"from":          formatWindowTime(start),
		"to":            formatWindowTime(end),
		"count":         len(msgs),
		"truncated":     truncated,
		"topics":        topics,
		"topics_source": topicsSource,
		"topics_error":  errorString(topicsErr),
		"mentions":      mentions,
		"daily":         daily,
		"summary":       summary,
		"summary_error": errorString(summaryErr),
		"source":        "messages",
	}, c.Query("format"))
}

func (s *Service) handleSemanticProfiles(c *gin.Context) {
	if err := s.ensureSemanticIndexReady(); err != nil {
		errors.Err(c, err)
		return
	}
	chat := strings.TrimSpace(c.Query("chat"))
	windowKey, windowLabel, start, end := parseSemanticWindow(c.Query("window"))
	msgs, truncated, err := s.collectSemanticMessages(chat, start, end)
	if err != nil {
		errors.Err(c, err)
		return
	}
	type prof struct {
		Sender      string           `json:"sender"`
		SenderName  string           `json:"sender_name"`
		Messages    int              `json:"messages"`
		TopKeywords []map[string]any `json:"top_keywords"`
	}
	counts := map[string]int{}
	names := map[string]string{}
	texts := map[string][]string{}
	for _, m := range msgs {
		if m == nil {
			continue
		}
		sender := strings.TrimSpace(m.Sender)
		if sender == "" {
			continue
		}
		counts[sender]++
		if n := strings.TrimSpace(m.SenderName); n != "" {
			names[sender] = n
		}
		if txt := semantic.NormalizeMessageText(m); txt != "" {
			texts[sender] = append(texts[sender], txt)
		}
	}
	list := make([]prof, 0, len(counts))
	typeDist := map[string]int{}
	for sender, n := range counts {
		list = append(list, prof{
			Sender:      sender,
			SenderName:  pickText(names[sender], sender),
			Messages:    n,
			TopKeywords: topWords(texts[sender], 6),
		})
	}
	for _, m := range msgs {
		if m == nil {
			continue
		}
		typeDist[strconv.FormatInt(m.Type, 10)]++
	}
	typeRows := make([]map[string]any, 0, len(typeDist))
	for t, n := range typeDist {
		typeRows = append(typeRows, map[string]any{
			"type":  t,
			"count": n,
		})
	}
	sort.Slice(typeRows, func(i, j int) bool {
		return toInt64(typeRows[i]["count"]) > toInt64(typeRows[j]["count"])
	})
	sort.Slice(list, func(i, j int) bool { return list[i].Messages > list[j].Messages })
	summary, summaryErr := s.summarizeSemantic(c.Request.Context(), "联系人画像分析", gin.H{
		"window":            windowLabel,
		"chat":              chat,
		"count":             len(msgs),
		"profiles":          firstN(list, 40),
		"type_distribution": typeRows,
	})
	writeByFormat(c, gin.H{
		"chat":              chat,
		"window":            windowKey,
		"window_label":      windowLabel,
		"from":              formatWindowTime(start),
		"to":                formatWindowTime(end),
		"count":             len(msgs),
		"truncated":         truncated,
		"profiles":          list,
		"type_distribution": typeRows,
		"summary":           summary,
		"summary_error":     errorString(summaryErr),
	}, c.Query("format"))
}

func (s *Service) collectSemanticMessages(chat string, start, end time.Time) ([]*model.Message, bool, error) {
	const maxSemanticAnalyticsMessages = 200000
	chat = strings.TrimSpace(chat)
	if chat != "" {
		msgs, err := s.db.GetMessages(start, end, chat, "", "", 0, 0)
		if err != nil {
			return nil, false, err
		}
		if len(msgs) > maxSemanticAnalyticsMessages {
			return msgs[:maxSemanticAnalyticsMessages], true, nil
		}
		return msgs, false, nil
	}
	sessions, err := s.db.GetSessions("", 2000, 0)
	if err != nil {
		return nil, false, err
	}
	if sessions == nil || len(sessions.Items) == 0 {
		return nil, false, nil
	}
	all := make([]*model.Message, 0, 4096)
	truncated := false
	for _, sess := range sessions.Items {
		if sess == nil || strings.TrimSpace(sess.UserName) == "" {
			continue
		}
		items, err := s.db.GetMessages(start, end, strings.TrimSpace(sess.UserName), "", "", 0, 0)
		if err != nil {
			continue
		}
		all = append(all, items...)
		if len(all) >= maxSemanticAnalyticsMessages {
			all = all[:maxSemanticAnalyticsMessages]
			truncated = true
			break
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Seq > all[j].Seq })
	return all, truncated, nil
}

func parseStartEndTime(c *gin.Context) (time.Time, time.Time) {
	start, end, _, err := parseSinceUntil(
		strings.TrimSpace(c.Query("time")),
		strings.TrimSpace(c.Query("since")),
		strings.TrimSpace(c.Query("until")),
	)
	if err != nil {
		return time.Time{}, time.Time{}
	}
	return start, end
}

func (s *Service) semanticTalkerScope(chat, chats string, limit int) ([]string, error) {
	if strings.TrimSpace(chat) != "" {
		return []string{strings.TrimSpace(chat)}, nil
	}
	out := make([]string, 0)
	seen := map[string]struct{}{}
	for _, item := range util.Str2List(chats, ",") {
		talker := strings.TrimSpace(item)
		if talker == "" {
			continue
		}
		if _, ok := seen[talker]; ok {
			continue
		}
		seen[talker] = struct{}{}
		out = append(out, talker)
	}
	if len(out) > 0 {
		return out, nil
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	sessions, err := s.db.GetSessions("", limit, 0)
	if err != nil {
		return nil, err
	}
	if sessions == nil {
		return nil, nil
	}
	for _, sess := range sessions.Items {
		if sess == nil {
			continue
		}
		talker := strings.TrimSpace(sess.UserName)
		if talker == "" {
			continue
		}
		if _, ok := seen[talker]; ok {
			continue
		}
		seen[talker] = struct{}{}
		out = append(out, talker)
	}
	return out, nil
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

type semanticDirectMessageResult struct {
	Window   string
	Count    int
	Answer   string
	Evidence []gin.H
	Debug    gin.H
	Reason   string
}

type semanticEntityCandidate struct {
	Username string  `json:"username"`
	Display  string  `json:"display"`
	Kind     string  `json:"kind"`
	Source   string  `json:"source"`
	Score    float64 `json:"score,omitempty"`
}

type semanticEntityResolution struct {
	Query      string                    `json:"query"`
	Candidates []semanticEntityCandidate `json:"candidates"`
	Ambiguous  bool                      `json:"ambiguous"`
}

type semanticQueryPlan struct {
	Intent      string  `json:"intent"`
	Entity      string  `json:"entity"`
	Topic       string  `json:"topic"`
	Window      string  `json:"window"`
	Chat        string  `json:"chat"`
	MsgType     string  `json:"msg_type"`
	AnswerMode  string  `json:"answer_mode"`
	NeedsVector bool    `json:"needs_vector"`
	Confidence  float64 `json:"confidence"`
	Reason      string  `json:"reason"`
	Source      string  `json:"source"`
}

func (s *Service) planSemanticQuery(ctx context.Context, query, fallbackWindow string, talkers []string) semanticQueryPlan {
	rule := ruleSemanticPlan(query, fallbackWindow)
	if s.semantic == nil {
		return rule
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	prompt := semanticPlanPrompt(query, fallbackWindow, len(talkers), "")
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		raw, err := s.semantic.PlanJSON(ctx, prompt)
		if err != nil {
			lastErr = err
			break
		}
		plan, err := parseSemanticPlanJSON(raw)
		if err != nil {
			lastErr = err
			prompt = semanticPlanPrompt(query, fallbackWindow, len(talkers), "上次输出不是合法 JSON 或字段不完整，请严格按 schema 只输出 JSON。")
			continue
		}
		plan = normalizeSemanticPlan(plan, fallbackWindow)
		if err := validateSemanticPlan(plan); err != nil || strings.TrimSpace(plan.Intent) == "" || plan.Confidence < 0.35 {
			lastErr = err
			prompt = semanticPlanPrompt(query, fallbackWindow, len(talkers), fmt.Sprintf("上次路由无效: %v。请重新输出合法 JSON。", err))
			continue
		}
		plan.Source = "llm"
		if rule.Intent != "" && rule.Intent != "semantic_search" && rule.Confidence >= 0.9 && plan.Confidence < 0.75 {
			return rule
		}
		return plan
	}
	rule.Reason = strings.TrimSpace(rule.Reason + "；LLM 路由失败，使用规则兜底: " + errorString(lastErr))
	return rule
}

func semanticPlanPrompt(query, fallbackWindow string, sourceCount int, retryHint string) string {
	return fmt.Sprintf(`请把用户问题路由为一个严格 JSON 对象。
可选 intent: sender_messages, sender_semantic_search, chat_summary, stats, keyword_search, semantic_search, media_filter, unknown。
字段:
- intent: 上述之一
- entity: 联系人/群成员/群名，无法确定则空
- topic: 语义主题或关键词，精确列消息可空
- window: today/yesterday/7d/30d/90d/1y/all 或 YYYY-MM-DD，无法判断用 %q
- chat: 明确群/会话名，无法确定则空
- msg_type: image/file/voice/video/sticker/text，非媒体可空
- answer_mode: list/summary/stats，无法判断用 summary
- needs_vector: 是否需要语义向量检索
- confidence: 0-1
- reason: 简短中文理由
规则:
- “某人今天发的消息/说了什么” => sender_messages
- “某人有没有提到某事/说过某事” => sender_semantic_search
- “某群最近聊什么/总结某群” => chat_summary
- “多少条/统计/活跃” => stats
- “包含/查找/搜索关键词” => keyword_search
- “图片/文件/语音/视频/表情” => media_filter
- 模糊语义问题 => semantic_search
禁止输出 Markdown、代码块、解释文字。
只输出 JSON。
%s
当前数据源会话数: %d
用户问题: %s`, fallbackWindow, retryHint, sourceCount, query)
}

func ruleSemanticPlan(query, fallbackWindow string) semanticQueryPlan {
	entity, _, _, _, ok := parseDirectSenderMessageQuery(query, fallbackWindow)
	if ok {
		_, windowKey := stripDirectTimeWord(strings.TrimSpace(strings.Split(query, "发")[0]))
		if windowKey == "" {
			windowKey = fallbackWindow
		}
		return normalizeSemanticPlan(semanticQueryPlan{
			Intent:      "sender_messages",
			Entity:      entity,
			Window:      windowKey,
			NeedsVector: false,
			Confidence:  0.95,
			Reason:      "规则命中发言人消息查询",
			Source:      "rule",
		}, fallbackWindow)
	}
	raw := strings.TrimSpace(query)
	if mediaType, ok := detectMediaIntent(raw); ok {
		_, windowKey := stripDirectTimeWord(raw)
		return normalizeSemanticPlan(semanticQueryPlan{
			Intent:      "media_filter",
			MsgType:     mediaType,
			Window:      defaultString(windowKey, fallbackWindow),
			NeedsVector: false,
			Confidence:  0.78,
			Reason:      "规则命中媒体消息查询",
			Source:      "rule",
		}, fallbackWindow)
	}
	if strings.Contains(raw, "有没有提到") || strings.Contains(raw, "是否提到") || strings.Contains(raw, "说过") {
		for _, marker := range []string{"有没有提到", "是否提到", "说过"} {
			if idx := strings.Index(raw, marker); idx > 0 {
				entity, windowKey := stripDirectTimeWord(strings.TrimSpace(raw[:idx]))
				topic := strings.Trim(strings.TrimSpace(raw[idx+len(marker):]), " ？?。.!！")
				return normalizeSemanticPlan(semanticQueryPlan{
					Intent:      "sender_semantic_search",
					Entity:      entity,
					Topic:       topic,
					Window:      defaultString(windowKey, fallbackWindow),
					NeedsVector: true,
					Confidence:  0.82,
					Reason:      "规则命中发言人语义查询",
					Source:      "rule",
				}, fallbackWindow)
			}
		}
	}
	return normalizeSemanticPlan(semanticQueryPlan{
		Intent:      "semantic_search",
		Topic:       query,
		Window:      fallbackWindow,
		NeedsVector: true,
		Confidence:  0.5,
		Reason:      "默认语义检索",
		Source:      "rule",
	}, fallbackWindow)
}

func detectMediaIntent(raw string) (string, bool) {
	if !(strings.Contains(raw, "哪些") || strings.Contains(raw, "发了") || strings.Contains(raw, "发的") || strings.Contains(raw, "消息") || strings.Contains(raw, "查找")) {
		return "", false
	}
	for _, item := range []struct {
		Word string
		Type string
	}{
		{"图片", "image"},
		{"照片", "image"},
		{"文件", "file"},
		{"语音", "voice"},
		{"视频", "video"},
		{"表情", "sticker"},
	} {
		if strings.Contains(raw, item.Word) {
			return item.Type, true
		}
	}
	return "", false
}

func parseSemanticPlanJSON(raw string) (semanticQueryPlan, error) {
	raw = strings.TrimSpace(raw)
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start >= 0 && end > start {
		raw = raw[start : end+1]
	}
	var plan semanticQueryPlan
	if err := json.Unmarshal([]byte(raw), &plan); err != nil {
		return plan, err
	}
	return plan, nil
}

func normalizeSemanticPlan(plan semanticQueryPlan, fallbackWindow string) semanticQueryPlan {
	plan.Intent = strings.TrimSpace(strings.ToLower(plan.Intent))
	plan.Entity = strings.TrimSpace(plan.Entity)
	plan.Topic = strings.TrimSpace(plan.Topic)
	plan.Window = normalizeSemanticWindowKey(plan.Window)
	plan.Chat = strings.TrimSpace(plan.Chat)
	plan.MsgType = strings.TrimSpace(strings.ToLower(plan.MsgType))
	plan.AnswerMode = strings.TrimSpace(strings.ToLower(plan.AnswerMode))
	if plan.Window == "" {
		plan.Window = fallbackWindow
	}
	if plan.Intent == "" {
		plan.Intent = "semantic_search"
	}
	switch plan.AnswerMode {
	case "", "answer":
		if plan.Intent == "sender_messages" || plan.Intent == "keyword_search" || plan.Intent == "media_filter" {
			plan.AnswerMode = "list"
		} else if plan.Intent == "stats" {
			plan.AnswerMode = "stats"
		} else {
			plan.AnswerMode = "summary"
		}
	case "列表":
		plan.AnswerMode = "list"
	case "总结", "摘要":
		plan.AnswerMode = "summary"
	case "统计":
		plan.AnswerMode = "stats"
	}
	if plan.Confidence < 0 {
		plan.Confidence = 0
	}
	if plan.Confidence > 1 {
		plan.Confidence = 1
	}
	return plan
}

func validateSemanticPlan(plan semanticQueryPlan) error {
	switch plan.Intent {
	case "sender_messages", "sender_semantic_search", "chat_summary", "stats", "keyword_search", "semantic_search", "media_filter", "unknown":
	default:
		return fmt.Errorf("invalid intent %q", plan.Intent)
	}
	switch plan.Window {
	case "", "today", "yesterday", "7d", "30d", "90d", "1y", "all":
	default:
		if !semanticDateWindowPattern.MatchString(plan.Window) {
			return fmt.Errorf("invalid window %q", plan.Window)
		}
	}
	switch plan.AnswerMode {
	case "", "list", "summary", "stats":
	default:
		return fmt.Errorf("invalid answer_mode %q", plan.AnswerMode)
	}
	if plan.Intent == "sender_messages" && strings.TrimSpace(plan.Entity) == "" {
		return fmt.Errorf("sender_messages requires entity")
	}
	if plan.Intent == "sender_semantic_search" && (strings.TrimSpace(plan.Entity) == "" || strings.TrimSpace(plan.Topic) == "") {
		return fmt.Errorf("sender_semantic_search requires entity and topic")
	}
	if plan.Intent == "media_filter" && strings.TrimSpace(plan.MsgType) == "" {
		return fmt.Errorf("media_filter requires msg_type")
	}
	return nil
}

func (s *Service) trySemanticRoutedDirect(ctx context.Context, query string, talkers []string, fallbackWindow string, entityOverride string, topN int) (*semanticDirectMessageResult, semanticQueryPlan, error) {
	plan := s.planSemanticQuery(ctx, query, fallbackWindow, talkers)
	if override := strings.TrimSpace(entityOverride); override != "" {
		plan.Entity = override
		if strings.TrimSpace(plan.Intent) == "" || plan.Intent == "unknown" || plan.Intent == "semantic_search" {
			plan.Intent = "sender_messages"
		}
		plan.Reason = appendChineseReason(plan.Reason, "使用前端确认的实体候选")
	}
	switch plan.Intent {
	case "sender_messages":
		return s.runSenderMessagesPlan(ctx, plan, talkers, fallbackWindow, topN)
	case "sender_semantic_search":
		return s.runSenderTopicPlan(ctx, plan, talkers, fallbackWindow, topN)
	case "keyword_search":
		return s.runKeywordPlan(ctx, plan, query, talkers, fallbackWindow, topN)
	case "chat_summary":
		return s.runChatSummaryPlan(ctx, plan, talkers, fallbackWindow, topN)
	case "stats":
		return s.runStatsPlan(ctx, plan, talkers, fallbackWindow)
	case "media_filter":
		return s.runMediaPlan(ctx, plan, talkers, fallbackWindow, topN)
	}
	return nil, plan, nil
}

func (s *Service) runSenderTopicPlan(ctx context.Context, plan semanticQueryPlan, talkers []string, fallbackWindow string, topN int) (*semanticDirectMessageResult, semanticQueryPlan, error) {
	entity := strings.TrimSpace(plan.Entity)
	topic := strings.TrimSpace(plan.Topic)
	if entity == "" || topic == "" {
		return nil, plan, nil
	}
	_, label, start, end := parseSemanticWindow(defaultString(plan.Window, fallbackWindow))
	if plan.Window == "yesterday" {
		label, start, end = yesterdayWindow()
	}
	raw, err := s.collectSenderMessages(ctx, entity, talkers, start, end, label, 300)
	if err != nil || raw == nil {
		return raw, plan, err
	}
	summary, summaryErr := s.summarizeSemantic(ctx, "判断发言人是否提到主题", gin.H{
		"entity":   entity,
		"topic":    topic,
		"window":   label,
		"messages": raw.Evidence,
	})
	if summaryErr == nil && strings.TrimSpace(summary) != "" {
		raw.Answer = summary
	}
	raw.Debug = mergeDebug(raw.Debug, semanticPlanDebug(plan, talkers, "direct/sender+llm"))
	return raw, plan, nil
}

func (s *Service) runSenderMessagesPlan(ctx context.Context, plan semanticQueryPlan, talkers []string, fallbackWindow string, topN int) (*semanticDirectMessageResult, semanticQueryPlan, error) {
	entity := strings.TrimSpace(plan.Entity)
	if entity == "" {
		return nil, plan, nil
	}
	_, label, start, end := parseSemanticWindow(defaultString(plan.Window, fallbackWindow))
	if plan.Window == "yesterday" {
		label, start, end = yesterdayWindow()
	}
	result, err := s.collectSenderMessages(ctx, entity, talkers, start, end, label, topN)
	if result != nil {
		result.Debug = mergeDebug(result.Debug, semanticPlanDebug(plan, talkers, "direct/sql"))
		s.applyDirectAnswerMode(ctx, plan, result, "发言人消息总结")
	}
	return result, plan, err
}

func (s *Service) runKeywordPlan(ctx context.Context, plan semanticQueryPlan, query string, talkers []string, fallbackWindow string, topN int) (*semanticDirectMessageResult, semanticQueryPlan, error) {
	keyword := strings.TrimSpace(plan.Topic)
	if keyword == "" {
		keyword = strings.TrimSpace(plan.Entity)
	}
	if keyword == "" {
		keyword = strings.Trim(strings.TrimSpace(query), " ？?。.!！")
	}
	_, label, start, end := parseSemanticWindow(defaultString(plan.Window, fallbackWindow))
	msgs, err := s.collectMessagesInTalkers(ctx, talkers, start, end, keyword, topN)
	if err != nil {
		return nil, plan, err
	}
	result := messagesDirectResult(fmt.Sprintf("包含“%s”的消息", keyword), label, msgs, topN)
	result.Debug = semanticPlanDebug(plan, talkers, "direct/keyword")
	s.applyDirectAnswerMode(ctx, plan, result, "关键词消息总结")
	return result, plan, nil
}

func (s *Service) runChatSummaryPlan(ctx context.Context, plan semanticQueryPlan, talkers []string, fallbackWindow string, topN int) (*semanticDirectMessageResult, semanticQueryPlan, error) {
	scopedTalkers := s.resolvePlanTalkers(plan, talkers)
	_, label, start, end := parseSemanticWindow(defaultString(plan.Window, fallbackWindow))
	msgs, err := s.collectMessagesInTalkers(ctx, scopedTalkers, start, end, "", 500)
	if err != nil {
		return nil, plan, err
	}
	summary, summaryErr := s.summarizeSemantic(ctx, "会话聊天总结", gin.H{
		"query":    plan,
		"window":   label,
		"messages": firstN(messagesToPlainRows(msgs), 120),
	})
	if summaryErr != nil || strings.TrimSpace(summary) == "" {
		summary = fmt.Sprintf("找到%s内 %d 条消息，但摘要生成失败: %s", label, len(msgs), errorString(summaryErr))
	}
	result := messagesDirectResult("会话总结证据", label, firstN(msgs, topN), topN)
	result.Answer = summary
	result.Count = len(msgs)
	result.Debug = semanticPlanDebug(plan, scopedTalkers, "direct/summary")
	return result, plan, nil
}

func (s *Service) runStatsPlan(ctx context.Context, plan semanticQueryPlan, talkers []string, fallbackWindow string) (*semanticDirectMessageResult, semanticQueryPlan, error) {
	scopedTalkers := s.resolvePlanTalkers(plan, talkers)
	_, label, start, end := parseSemanticWindow(defaultString(plan.Window, fallbackWindow))
	msgs, err := s.collectMessagesInTalkers(ctx, scopedTalkers, start, end, "", 0)
	if err != nil {
		return nil, plan, err
	}
	result := &semanticDirectMessageResult{
		Window:   label,
		Count:    len(msgs),
		Answer:   fmt.Sprintf("%s内共找到 %d 条消息，数据源会话数 %d。", label, len(msgs), len(scopedTalkers)),
		Evidence: []gin.H{},
		Debug:    semanticPlanDebug(plan, scopedTalkers, "direct/stats"),
	}
	return result, plan, nil
}

func (s *Service) runMediaPlan(ctx context.Context, plan semanticQueryPlan, talkers []string, fallbackWindow string, topN int) (*semanticDirectMessageResult, semanticQueryPlan, error) {
	_, label, start, end := parseSemanticWindow(defaultString(plan.Window, fallbackWindow))
	msgs, err := s.collectMessagesInTalkers(ctx, talkers, start, end, "", 1000)
	if err != nil {
		return nil, plan, err
	}
	msgType, subType, mediaLabel := semanticMediaType(plan.MsgType)
	filtered := make([]*model.Message, 0, len(msgs))
	for _, msg := range msgs {
		if msg == nil {
			continue
		}
		if msgType > 0 && msg.Type != msgType {
			continue
		}
		if subType > 0 && msg.SubType != subType {
			continue
		}
		if msgType == 0 && !messageHasMediaType(msg) {
			continue
		}
		filtered = append(filtered, msg)
	}
	result := messagesDirectResult(mediaLabel+"消息", label, filtered, topN)
	result.Debug = semanticPlanDebug(plan, talkers, "direct/media")
	s.applyDirectAnswerMode(ctx, plan, result, "媒体消息总结")
	return result, plan, nil
}

func (s *Service) applyDirectAnswerMode(ctx context.Context, plan semanticQueryPlan, result *semanticDirectMessageResult, title string) {
	if result == nil || result.Count == 0 || plan.AnswerMode != "summary" {
		return
	}
	summary, err := s.summarizeSemantic(ctx, title, gin.H{
		"plan":     plan,
		"window":   result.Window,
		"evidence": result.Evidence,
	})
	if err == nil && strings.TrimSpace(summary) != "" {
		result.Answer = summary
	}
}

func semanticMediaType(raw string) (int64, int64, string) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "image", "图片":
		return model.MessageTypeImage, 0, "图片"
	case "file", "文件":
		return model.MessageTypeShare, model.MessageSubTypeFile, "文件"
	case "voice", "语音":
		return model.MessageTypeVoice, 0, "语音"
	case "video", "视频":
		return model.MessageTypeVideo, 0, "视频"
	case "sticker", "表情", "动画表情":
		return model.MessageTypeAnimation, 0, "表情"
	case "text", "文本":
		return model.MessageTypeText, 0, "文本"
	default:
		return 0, 0, "媒体"
	}
}

func messageHasMediaType(msg *model.Message) bool {
	if msg == nil {
		return false
	}
	switch msg.Type {
	case model.MessageTypeImage, model.MessageTypeVoice, model.MessageTypeVideo, model.MessageTypeAnimation:
		return true
	case model.MessageTypeShare:
		return msg.SubType == model.MessageSubTypeFile ||
			msg.SubType == model.MessageSubTypeLink ||
			msg.SubType == model.MessageSubTypeMiniProgram ||
			msg.SubType == model.MessageSubTypeChannel
	default:
		return false
	}
}

func (s *Service) resolvePlanTalkers(plan semanticQueryPlan, fallback []string) []string {
	for _, key := range []string{plan.Chat, plan.Entity} {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if room, err := s.db.GetChatRoom(key); err == nil && room != nil {
			return []string{room.Name}
		}
		if contact, err := s.db.GetContact(key); err == nil && contact != nil {
			return []string{contact.UserName}
		}
		if s.semantic != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			hits, err := s.semantic.SearchEntities(ctx, key, fallback, 5)
			cancel()
			if err == nil {
				for _, hit := range hits {
					if hit.Kind == "chatroom" || hit.Kind == "contact" {
						return []string{hit.Username}
					}
				}
			}
		}
	}
	return fallback
}

func semanticPlanDebug(plan semanticQueryPlan, talkers []string, retrieval string) gin.H {
	return gin.H{
		"intent":       plan.Intent,
		"entity":       plan.Entity,
		"topic":        plan.Topic,
		"window":       plan.Window,
		"chat":         plan.Chat,
		"msg_type":     plan.MsgType,
		"answer_mode":  plan.AnswerMode,
		"needs_vector": plan.NeedsVector,
		"confidence":   plan.Confidence,
		"reason":       plan.Reason,
		"source":       plan.Source,
		"retrieval":    retrieval,
		"talker_count": len(talkers),
	}
}

func attachEntityDebug(debug gin.H, resolution semanticEntityResolution) gin.H {
	if debug == nil {
		debug = gin.H{}
	}
	debug["entity_query"] = resolution.Query
	debug["entity_candidates"] = resolution.Candidates
	debug["entity_candidate_count"] = len(resolution.Candidates)
	debug["entity_ambiguous"] = resolution.Ambiguous
	return debug
}

func mergeDebug(base gin.H, extra gin.H) gin.H {
	if base == nil {
		base = gin.H{}
	}
	for k, v := range extra {
		base[k] = v
	}
	return base
}

func attachEmptyReason(debug gin.H, reason string) gin.H {
	if strings.TrimSpace(reason) == "" {
		return debug
	}
	if debug == nil {
		debug = gin.H{}
	}
	debug["empty_reason"] = reason
	return debug
}

func appendChineseReason(base, extra string) string {
	base = strings.Trim(strings.TrimSpace(base), "；; ")
	extra = strings.Trim(strings.TrimSpace(extra), "；; ")
	if base == "" {
		return extra
	}
	if extra == "" {
		return base
	}
	return base + "；" + extra
}

func semanticEffectiveWindow(query, fallback string) string {
	if inferred := inferSemanticWindowFromQuery(query); inferred != "" {
		return inferred
	}
	fallback = normalizeSemanticWindowKey(fallback)
	if fallback == "" {
		return "7d"
	}
	return fallback
}

func semanticPlanWindow(plan semanticQueryPlan, fallback string) string {
	window := normalizeSemanticWindowKey(plan.Window)
	if window == "" {
		return semanticEffectiveWindow("", fallback)
	}
	return window
}

func inferSemanticWindowFromQuery(query string) string {
	raw := strings.TrimSpace(query)
	if raw == "" {
		return ""
	}
	lower := strings.ToLower(raw)
	if semanticDateWindowPattern.MatchString(lower) {
		return lower
	}
	if match := semanticDateWindowPattern.FindString(lower); match != "" {
		return match
	}
	if match := semanticMonthDayPattern.FindStringSubmatch(raw); len(match) == 3 {
		month, _ := strconv.Atoi(match[1])
		day, _ := strconv.Atoi(match[2])
		if month >= 1 && month <= 12 && day >= 1 && day <= 31 {
			now := time.Now()
			return fmt.Sprintf("%04d-%02d-%02d", now.Year(), month, day)
		}
	}
	switch {
	case strings.Contains(raw, "昨天") || strings.Contains(raw, "昨日") || strings.Contains(lower, "yesterday"):
		return "yesterday"
	case strings.Contains(raw, "今天") || strings.Contains(raw, "今日") || strings.Contains(lower, "today"):
		return "today"
	case strings.Contains(raw, "近七天") || strings.Contains(raw, "最近七天") || strings.Contains(raw, "近7天") || strings.Contains(raw, "最近7天") || strings.Contains(raw, "这周") || strings.Contains(raw, "本周"):
		return "7d"
	case strings.Contains(raw, "近一月") || strings.Contains(raw, "最近一月") || strings.Contains(raw, "近1月") || strings.Contains(raw, "最近1月") || strings.Contains(raw, "这个月") || strings.Contains(raw, "本月"):
		return "30d"
	case strings.Contains(raw, "近季度") || strings.Contains(raw, "最近季度") || strings.Contains(raw, "近三月") || strings.Contains(raw, "最近三月") || strings.Contains(raw, "近3月") || strings.Contains(raw, "最近3月"):
		return "90d"
	case strings.Contains(raw, "近一年") || strings.Contains(raw, "最近一年") || strings.Contains(raw, "近1年") || strings.Contains(raw, "最近1年") || strings.Contains(raw, "今年"):
		return "1y"
	case strings.Contains(raw, "全部") || strings.Contains(raw, "所有") || strings.Contains(raw, "历史") || strings.Contains(lower, "all"):
		return "all"
	default:
		return ""
	}
}

func normalizeSemanticWindowKey(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	switch raw {
	case "", "auto", "default":
		return ""
	case "今天", "今日", "today", "1d":
		return "today"
	case "昨天", "昨日", "yesterday":
		return "yesterday"
	case "近七天", "最近七天", "近7天", "最近7天", "week", "7d":
		return "7d"
	case "近一月", "最近一月", "近1月", "最近1月", "month", "1m", "30d":
		return "30d"
	case "近季度", "最近季度", "近三月", "最近三月", "近3月", "最近3月", "quarter", "3m", "90d":
		return "90d"
	case "近一年", "最近一年", "近1年", "最近1年", "year", "1y":
		return "1y"
	case "全部", "所有", "历史", "all":
		return "all"
	default:
		if semanticDateWindowPattern.MatchString(raw) {
			return raw
		}
		return raw
	}
}

func normalizeSemanticDepth(depth string) string {
	switch strings.ToLower(strings.TrimSpace(depth)) {
	case "deep", "深入":
		return "deep"
	case "wide", "广泛":
		return "wide"
	default:
		return "standard"
	}
}

func semanticQATopN(requested int, depth string) int {
	if requested > 0 {
		return clampInt(requested, 1, 60)
	}
	switch normalizeSemanticDepth(depth) {
	case "deep":
		return 16
	case "wide":
		return 30
	default:
		return 8
	}
}

func semanticSearchTopN(requested int, depth string) int {
	if requested > 0 {
		return clampInt(requested, 1, 200)
	}
	switch normalizeSemanticDepth(depth) {
	case "deep":
		return 50
	case "wide":
		return 100
	default:
		return 20
	}
}

func clampInt(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func semanticVectorQuery(query string, plan semanticQueryPlan) string {
	switch plan.Intent {
	case "sender_semantic_search", "chat_semantic_search", "semantic_search":
		if strings.TrimSpace(plan.Topic) != "" {
			return strings.TrimSpace(plan.Topic)
		}
	}
	return query
}

func (s *Service) collectMessagesInTalkers(ctx context.Context, talkers []string, start, end time.Time, keyword string, limit int) ([]*model.Message, error) {
	if len(talkers) == 0 {
		var err error
		talkers, err = s.semanticTalkerScope("", "", 50)
		if err != nil {
			return nil, err
		}
	}
	out := make([]*model.Message, 0)
	perTalkerLimit := limit
	if perTalkerLimit <= 0 {
		perTalkerLimit = 5000
	} else if perTalkerLimit < 200 {
		perTalkerLimit = 200
	}
	for _, talker := range talkers {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		msgs, err := s.db.GetMessages(start, end, talker, "", regexp.QuoteMeta(keyword), perTalkerLimit, 0)
		if err != nil {
			continue
		}
		out = append(out, msgs...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

func messagesDirectResult(title, window string, msgs []*model.Message, topN int) *semanticDirectMessageResult {
	total := len(msgs)
	if topN <= 0 {
		topN = 20
	}
	if len(msgs) > topN {
		msgs = msgs[len(msgs)-topN:]
	}
	evidence := messagesToEvidence(msgs)
	lines := make([]string, 0, len(msgs))
	for i, msg := range msgs {
		lines = append(lines, fmt.Sprintf("%d. [%s][%s/%s] %s",
			i+1,
			msg.Time.Format("2006-01-02 15:04:05"),
			pickText(msg.TalkerName, msg.Talker),
			pickText(msg.SenderName, msg.Sender),
			singleLineText(msg.PlainTextContent()),
		))
	}
	answer := fmt.Sprintf("%s：%s内没有找到匹配消息。", title, window)
	reason := "时间窗和数据源范围内没有匹配消息"
	if total > 0 {
		answer = fmt.Sprintf("%s：%s内找到 %d 条消息，展示最近 %d 条：\n%s", title, window, total, len(msgs), strings.Join(lines, "\n"))
		reason = ""
	}
	return &semanticDirectMessageResult{
		Window:   window,
		Count:    total,
		Answer:   answer,
		Evidence: evidence,
		Reason:   reason,
	}
}

func messagesToEvidence(msgs []*model.Message) []gin.H {
	out := make([]gin.H, 0, len(msgs))
	for _, msg := range msgs {
		if msg == nil {
			continue
		}
		content := singleLineText(msg.PlainTextContent())
		if content == "" {
			content = formatMessageType(msg.Type)
		}
		out = append(out, gin.H{
			"talker":      msg.Talker,
			"talker_name": pickText(msg.TalkerName, msg.Talker),
			"sender":      msg.Sender,
			"sender_name": pickText(msg.SenderName, msg.Sender),
			"seq":         msg.Seq,
			"time":        msg.Time.Unix(),
			"type":        msg.Type,
			"sub_type":    msg.SubType,
			"content":     content,
		})
	}
	return out
}

func messagesToPlainRows(msgs []*model.Message) []gin.H {
	out := make([]gin.H, 0, len(msgs))
	for _, msg := range msgs {
		if msg == nil {
			continue
		}
		out = append(out, gin.H{
			"time":   msg.Time.Format("2006-01-02 15:04:05"),
			"chat":   pickText(msg.TalkerName, msg.Talker),
			"sender": pickText(msg.SenderName, msg.Sender),
			"text":   singleLineText(msg.PlainTextContent()),
		})
	}
	return out
}

func dashboardSummaryMessageRows(msgs []*model.Message, maxRows int) []gin.H {
	if maxRows <= 0 {
		maxRows = 200
	}
	type bucket struct {
		Day    string
		Talker string
		Items  []*model.Message
	}
	buckets := map[string]*bucket{}
	hashSeen := map[string]struct{}{}
	for _, msg := range msgs {
		if msg == nil {
			continue
		}
		text := semantic.NormalizeMessageText(msg)
		if strings.TrimSpace(text) == "" {
			continue
		}
		hash := strings.ToLower(strings.TrimSpace(singleLineText(text)))
		if len([]rune(hash)) > 120 {
			hash = string([]rune(hash)[:120])
		}
		if hash != "" {
			if _, ok := hashSeen[hash]; ok {
				continue
			}
			hashSeen[hash] = struct{}{}
		}
		day := msg.Time.Format("2006-01-02")
		key := day + "\x00" + msg.Talker
		b := buckets[key]
		if b == nil {
			b = &bucket{Day: day, Talker: msg.Talker}
			buckets[key] = b
		}
		b.Items = append(b.Items, msg)
	}
	bucketList := make([]*bucket, 0, len(buckets))
	for _, b := range buckets {
		sort.Slice(b.Items, func(i, j int) bool { return b.Items[i].Time.Before(b.Items[j].Time) })
		bucketList = append(bucketList, b)
	}
	sort.Slice(bucketList, func(i, j int) bool {
		if bucketList[i].Day == bucketList[j].Day {
			return bucketList[i].Talker < bucketList[j].Talker
		}
		return bucketList[i].Day < bucketList[j].Day
	})
	selected := make([]*model.Message, 0, maxRows)
	for _, b := range bucketList {
		if len(selected) >= maxRows {
			break
		}
		quota := 2
		if len(b.Items) >= 20 {
			quota = 3
		}
		for _, msg := range sampleMessagesEvenly(b.Items, quota) {
			selected = append(selected, msg)
			if len(selected) >= maxRows {
				break
			}
		}
	}
	if len(selected) < maxRows {
		all := make([]*model.Message, 0)
		selectedSeen := map[*model.Message]struct{}{}
		for _, msg := range selected {
			selectedSeen[msg] = struct{}{}
		}
		for _, b := range bucketList {
			for _, msg := range b.Items {
				if _, ok := selectedSeen[msg]; ok {
					continue
				}
				all = append(all, msg)
			}
		}
		sort.Slice(all, func(i, j int) bool { return all[i].Time.Before(all[j].Time) })
		for _, msg := range sampleMessagesEvenly(all, maxRows-len(selected)) {
			selected = append(selected, msg)
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Time.Before(selected[j].Time) })
	out := make([]gin.H, 0, len(selected))
	for _, msg := range selected {
		text := semantic.NormalizeMessageText(msg)
		runes := []rune(singleLineText(text))
		if len(runes) > 260 {
			text = string(runes[:260]) + "..."
		} else {
			text = string(runes)
		}
		out = append(out, gin.H{
			"time":   msg.Time.Format("2006-01-02 15:04:05"),
			"chat":   pickText(msg.TalkerName, msg.Talker),
			"sender": pickText(msg.SenderName, msg.Sender),
			"text":   text,
		})
	}
	return out
}

func sampleMessagesEvenly(items []*model.Message, limit int) []*model.Message {
	if limit <= 0 || len(items) == 0 {
		return nil
	}
	if len(items) <= limit {
		return append([]*model.Message(nil), items...)
	}
	out := make([]*model.Message, 0, limit)
	seen := map[int]struct{}{}
	step := float64(len(items)) / float64(limit)
	for i := 0; i < limit; i++ {
		idx := int(float64(i) * step)
		if idx >= len(items) {
			idx = len(items) - 1
		}
		if _, ok := seen[idx]; ok {
			continue
		}
		seen[idx] = struct{}{}
		out = append(out, items[idx])
	}
	return out
}

func yesterdayWindow() (string, time.Time, time.Time) {
	now := time.Now()
	loc := now.Location()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	return "昨天", todayStart.AddDate(0, 0, -1), todayStart.Add(-time.Nanosecond)
}

func (s *Service) trySemanticDirectSenderMessages(ctx context.Context, query string, talkers []string, fallbackWindow string, topN int) (*semanticDirectMessageResult, error) {
	entity, window, start, end, ok := parseDirectSenderMessageQuery(query, fallbackWindow)
	if !ok {
		return nil, nil
	}
	if topN <= 0 {
		topN = 20
	}
	if len(talkers) == 0 {
		var err error
		talkers, err = s.semanticTalkerScope("", "", 50)
		if err != nil {
			return nil, err
		}
	}
	return s.collectSenderMessages(ctx, entity, talkers, start, end, window, topN)
}

func (s *Service) collectSenderMessages(ctx context.Context, entity string, talkers []string, start, end time.Time, window string, topN int) (*semanticDirectMessageResult, error) {
	resolution := s.resolveSenderEntity(entity, talkers)
	senderIDs := map[string]struct{}{}
	for _, candidate := range resolution.Candidates {
		if strings.TrimSpace(candidate.Username) != "" {
			senderIDs[candidate.Username] = struct{}{}
		}
	}
	hits := make([]*model.Message, 0, topN)
	const perTalkerLimit = 3000
	for _, talker := range talkers {
		if strings.TrimSpace(talker) == "" {
			continue
		}
		msgs, err := s.db.GetMessages(start, end, talker, "", "", perTalkerLimit, 0)
		if err != nil {
			continue
		}
		for _, msg := range msgs {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			if senderMessageMatches(msg, entity, senderIDs) {
				hits = append(hits, msg)
			}
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Seq < hits[j].Seq })
	total := len(hits)
	if len(hits) > topN {
		hits = hits[len(hits)-topN:]
	}
	evidence := make([]gin.H, 0, len(hits))
	lines := make([]string, 0, len(hits))
	for i, msg := range hits {
		content := singleLineText(msg.PlainTextContent())
		if content == "" {
			content = formatMessageType(msg.Type)
		}
		ts := msg.Time.Format("2006-01-02 15:04:05")
		talkerName := pickText(msg.TalkerName, msg.Talker)
		senderName := pickText(msg.SenderName, msg.Sender)
		lines = append(lines, fmt.Sprintf("%d. [%s][%s/%s] %s", i+1, ts, talkerName, senderName, content))
		evidence = append(evidence, gin.H{
			"talker":      msg.Talker,
			"talker_name": talkerName,
			"sender":      msg.Sender,
			"sender_name": senderName,
			"seq":         msg.Seq,
			"time":        msg.Time.Unix(),
			"type":        msg.Type,
			"sub_type":    msg.SubType,
			"content":     content,
		})
	}
	answer := fmt.Sprintf("没有找到 %s 在%s发的消息。", entity, window)
	reason := "实体未解析到候选，或候选在时间窗和数据源范围内没有发言"
	if total > 0 {
		answer = fmt.Sprintf("找到 %s 在%s发的 %d 条消息，展示最近 %d 条：\n%s", entity, window, total, len(hits), strings.Join(lines, "\n"))
		reason = ""
	}
	return &semanticDirectMessageResult{
		Window:   window,
		Count:    total,
		Answer:   answer,
		Evidence: evidence,
		Debug:    attachEntityDebug(nil, resolution),
		Reason:   reason,
	}, nil
}

func parseDirectSenderMessageQuery(query, fallbackWindow string) (string, string, time.Time, time.Time, bool) {
	raw := strings.TrimSpace(query)
	if raw == "" {
		return "", "", time.Time{}, time.Time{}, false
	}
	raw = strings.Trim(raw, " ？?。.!！")
	needMessageIntent := strings.Contains(raw, "发的消息") ||
		strings.Contains(raw, "发送的消息") ||
		strings.Contains(raw, "说的消息") ||
		strings.Contains(raw, "讲的消息") ||
		strings.Contains(raw, "发了什么") ||
		strings.Contains(raw, "说了什么") ||
		strings.Contains(raw, "讲了什么")
	if !needMessageIntent {
		return "", "", time.Time{}, time.Time{}, false
	}
	verbIdx := len(raw)
	for _, marker := range []string{"发的消息", "发送的消息", "说的消息", "讲的消息", "发了什么", "说了什么", "讲了什么"} {
		if idx := strings.Index(raw, marker); idx >= 0 && idx < verbIdx {
			verbIdx = idx
		}
	}
	if verbIdx <= 0 || verbIdx >= len(raw) {
		return "", "", time.Time{}, time.Time{}, false
	}
	entityPart := strings.TrimSpace(raw[:verbIdx])
	entity, windowKey := stripDirectTimeWord(entityPart)
	if strings.TrimSpace(entity) == "" {
		return "", "", time.Time{}, time.Time{}, false
	}
	if windowKey == "" {
		windowKey = fallbackWindow
	}
	window, label, start, end := parseSemanticWindow(windowKey)
	if windowKey == "yesterday" {
		now := time.Now()
		loc := now.Location()
		todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
		start = todayStart.AddDate(0, 0, -1)
		end = todayStart.Add(-time.Nanosecond)
		window = "yesterday"
		label = "昨天"
	}
	return entity, labelOrKey(label, window), start, end, true
}

func stripDirectTimeWord(s string) (string, string) {
	s = strings.TrimSpace(s)
	if window := inferSemanticWindowFromQuery(s); window != "" {
		clean := strings.TrimSpace(strings.ReplaceAll(s, window, ""))
		for _, word := range []string{"今天", "今日", "昨天", "昨日", "近七天", "最近七天", "近7天", "最近7天", "近一月", "最近一月", "近1月", "最近1月", "本周", "这周", "本月", "这个月", "全部", "所有", "历史"} {
			clean = strings.TrimSpace(strings.ReplaceAll(clean, word, ""))
		}
		if m := semanticMonthDayPattern.FindString(s); m != "" {
			clean = strings.TrimSpace(strings.ReplaceAll(clean, m, ""))
		}
		return clean, window
	}
	timeWords := []struct {
		Word string
		Key  string
	}{
		{"今天", "today"},
		{"昨日", "yesterday"},
		{"昨天", "yesterday"},
		{"近七天", "7d"},
		{"最近七天", "7d"},
		{"近7天", "7d"},
		{"最近7天", "7d"},
		{"近一月", "30d"},
		{"近1月", "30d"},
		{"最近一月", "30d"},
		{"最近1月", "30d"},
	}
	for _, item := range timeWords {
		if strings.HasSuffix(s, item.Word) {
			return strings.TrimSpace(strings.TrimSuffix(s, item.Word)), item.Key
		}
		if strings.HasPrefix(s, item.Word) {
			return strings.TrimSpace(strings.TrimPrefix(s, item.Word)), item.Key
		}
	}
	return s, ""
}

func (s *Service) resolveSenderIDs(entity string) map[string]struct{} {
	out := map[string]struct{}{}
	entity = strings.TrimSpace(entity)
	if entity == "" {
		return out
	}
	if contact, err := s.db.GetContact(entity); err == nil && contact != nil {
		out[contact.UserName] = struct{}{}
	}
	if contacts, err := s.db.GetContacts(entity, 20, 0); err == nil && contacts != nil {
		for _, contact := range contacts.Items {
			if contact != nil && strings.TrimSpace(contact.UserName) != "" {
				out[contact.UserName] = struct{}{}
			}
		}
	}
	if s.semantic != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if hits, err := s.semantic.SearchEntities(ctx, entity, nil, 8); err == nil {
			for _, hit := range hits {
				if hit.Kind == "contact" || hit.Kind == "room_member" {
					out[hit.Username] = struct{}{}
				}
			}
		}
	}
	return out
}

func (s *Service) resolveSenderEntity(entity string, talkers []string) semanticEntityResolution {
	res := semanticEntityResolution{Query: strings.TrimSpace(entity)}
	seen := map[string]int{}
	add := func(username, display, kind, source string, score float64) {
		username = strings.TrimSpace(username)
		if username == "" {
			return
		}
		key := senderEntityCandidateKey(username, kind, source)
		rank := senderEntityCandidateRank(source, kind)
		if prev, ok := seen[key]; ok && prev >= rank {
			return
		}
		seen[key] = rank
		candidate := semanticEntityCandidate{
			Username: username,
			Display:  strings.TrimSpace(display),
			Kind:     kind,
			Source:   source,
			Score:    score,
		}
		for i := range res.Candidates {
			if senderEntityCandidateKey(res.Candidates[i].Username, res.Candidates[i].Kind, res.Candidates[i].Source) == key {
				res.Candidates[i] = candidate
				return
			}
		}
		res.Candidates = append(res.Candidates, candidate)
	}
	entity = strings.TrimSpace(entity)
	if entity == "" {
		return res
	}
	if entity == "我" || entity == "自己" || strings.EqualFold(entity, "me") {
		add("self", "我", "self", "builtin", 1)
		return res
	}
	if looksLikeWechatUsername(entity) {
		add(entity, entity, "username", "direct", 1)
	}
	if contact, err := s.db.GetContact(entity); err == nil && contact != nil {
		add(contact.UserName, contact.DisplayName(), "contact", "exact", 1)
	}
	if contacts, err := s.db.GetContacts(entity, 20, 0); err == nil && contacts != nil {
		for _, contact := range contacts.Items {
			if contact == nil {
				continue
			}
			add(contact.UserName, contact.DisplayName(), "contact", "search", 0.75)
		}
	}
	if s.semantic != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if hits, err := s.semantic.SearchEntities(ctx, entity, talkers, 8); err == nil {
			for _, hit := range hits {
				if hit.Kind == "contact" || hit.Kind == "room_member" {
					add(hit.Username, hit.Display, hit.Kind, hit.Source, hit.Score)
				}
			}
		}
	}
	for _, talker := range talkers {
		room, err := s.db.GetChatRoom(talker)
		if err != nil || room == nil {
			continue
		}
		for _, user := range room.Users {
			display := strings.TrimSpace(room.User2DisplayName[user.UserName])
			if display == "" {
				display = strings.TrimSpace(user.DisplayName)
			}
			if directNameMatch(entity, display) || directNameMatch(entity, user.UserName) {
				add(user.UserName, display, "room_member", "room_exact", 0.95)
			}
		}
	}
	sort.SliceStable(res.Candidates, func(i, j int) bool {
		ri := senderEntityCandidateRank(res.Candidates[i].Source, res.Candidates[i].Kind)
		rj := senderEntityCandidateRank(res.Candidates[j].Source, res.Candidates[j].Kind)
		if ri == rj {
			if res.Candidates[i].Score == res.Candidates[j].Score {
				return res.Candidates[i].Display < res.Candidates[j].Display
			}
			return res.Candidates[i].Score > res.Candidates[j].Score
		}
		return ri > rj
	})
	res.Ambiguous = senderEntityAmbiguous(res.Candidates)
	return res
}

func senderEntityCandidateKey(username, kind, source string) string {
	scope := kind
	if source == "room_exact" || kind == "room_member" {
		scope = "room_member"
	}
	return strings.TrimSpace(username) + "\x00" + scope
}

func senderEntityCandidateRank(source, kind string) int {
	switch source {
	case "builtin":
		return 120
	case "direct":
		return 115
	case "exact":
		return 110
	case "room_exact":
		return 105
	case "entity_exact":
		if kind == "room_member" {
			return 102
		}
		return 100
	case "search":
		return 85
	case "entity_fuzzy":
		return 75
	case "entity_vector":
		return 55
	default:
		return 50
	}
}

func senderEntityAmbiguous(candidates []semanticEntityCandidate) bool {
	if len(candidates) <= 1 {
		return false
	}
	first := candidates[0]
	for _, item := range candidates[1:] {
		if item.Username == first.Username {
			continue
		}
		if senderEntityCandidateRank(first.Source, first.Kind)-senderEntityCandidateRank(item.Source, item.Kind) >= 20 {
			continue
		}
		if first.Score > 0 && item.Score > 0 && first.Score-item.Score >= 0.08 {
			continue
		}
		return true
	}
	return false
}

func looksLikeWechatUsername(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "wxid_") ||
		strings.HasSuffix(s, "@chatroom") ||
		strings.Contains(s, "@") ||
		semanticWechatUsernamePattern.MatchString(s)
}

func senderMessageMatches(msg *model.Message, entity string, senderIDs map[string]struct{}) bool {
	if msg == nil {
		return false
	}
	entity = strings.TrimSpace(entity)
	if entity == "" {
		return false
	}
	if entity == "我" || entity == "自己" || strings.EqualFold(entity, "me") {
		return msg.IsSelf
	}
	if _, ok := senderIDs["self"]; ok && msg.IsSelf {
		return true
	}
	if _, ok := senderIDs[msg.Sender]; ok {
		return true
	}
	candidates := []string{msg.Sender, msg.SenderName}
	if !msg.IsChatRoom && !msg.IsSelf {
		candidates = append(candidates, msg.Talker, msg.TalkerName)
	}
	for _, item := range candidates {
		if directNameMatch(entity, item) {
			return true
		}
	}
	return false
}

func directNameMatch(queryName, candidate string) bool {
	queryName = strings.TrimSpace(strings.ToLower(queryName))
	candidate = strings.TrimSpace(strings.ToLower(candidate))
	if queryName == "" || candidate == "" {
		return false
	}
	return queryName == candidate || strings.Contains(candidate, queryName)
}

func labelOrKey(label, key string) string {
	if strings.TrimSpace(label) != "" {
		return label
	}
	return key
}

func parseIntDefault(raw string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return n
}

func (s *Service) ensureSemanticIndexReady() error {
	if s.semantic == nil {
		return fmt.Errorf("semantic manager unavailable")
	}
	st := s.semantic.Status()
	if st.Running {
		return fmt.Errorf("semantic index is building, please wait")
	}
	if st.IndexedCount <= 0 {
		return fmt.Errorf("semantic index is empty, please build index first")
	}
	if st.Pending > 0 {
		return fmt.Errorf("semantic index not ready: pending=%d failed=%d", st.Pending, st.Failed)
	}
	return nil
}

func summarizeTopics(msgs []*model.Message, topN int) []map[string]any {
	texts := make([]string, 0, len(msgs))
	for _, m := range msgs {
		if m == nil {
			continue
		}
		txt := semantic.NormalizeMessageText(m)
		if txt != "" {
			txt = stripMentionsForTopics(txt)
			texts = append(texts, txt)
		}
	}
	return topWords(texts, topN)
}

type llmTopicExtraction struct {
	Topics []llmTopicItem `json:"topics"`
}

type llmTopicItem struct {
	Topic        string   `json:"topic"`
	Aliases      []string `json:"aliases"`
	SupportCount int      `json:"support_count"`
	Reason       string   `json:"reason"`
}

func (s *Service) extractDashboardTopicsWithLLM(ctx context.Context, msgs []*model.Message, topN int) ([]map[string]any, error) {
	if s.semantic == nil {
		return nil, fmt.Errorf("semantic manager unavailable")
	}
	if topN <= 0 {
		topN = 30
	}
	rawMessages := dashboardSummaryMessageRows(msgs, 320)
	if len(rawMessages) == 0 {
		return nil, nil
	}
	payload := gin.H{
		"total_message_count": len(msgs),
		"sample_count":        len(rawMessages),
		"sampled":             len(rawMessages) < len(msgs),
		"messages":            rawMessages,
	}
	instruction := fmt.Sprintf(`请从 messages 中抽取最多 %d 个中文热点主题，完成中文分词、同义归并和噪声过滤。
要求：
- 主题必须是有业务或语义价值的短语，不要输出“图片/视频/文件/pdf/日期/头像/聊天记录/合并转发”等媒体或格式词。
- 不要输出纯数字、无意义英文、单字词、URL、文件后缀、@昵称。
- aliases 放可用于匹配原文的同义词或原始表达，最多 5 个。
- support_count 是该主题在样本中被多少条消息支持的估计值，必须是整数。
- reason 用一句话说明主题依据。
- 只能输出 JSON：{"topics":[{"topic":"...","aliases":["..."],"support_count":3,"reason":"..."}]}`, topN)

	sumCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	raw, err := s.semantic.AnalyzeJSON(sumCtx, "仪表盘热点主题抽取", toJSONString(payload), instruction)
	if err != nil {
		return nil, err
	}
	parsed, err := parseLLMTopicExtraction(raw)
	if err != nil {
		return nil, err
	}
	return rankLLMTopicsByMessages(parsed.Topics, msgs, topN), nil
}

func parseLLMTopicExtraction(raw string) (llmTopicExtraction, error) {
	var out llmTopicExtraction
	raw = strings.TrimSpace(raw)
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start >= 0 && end > start {
		raw = raw[start : end+1]
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return out, err
	}
	return out, nil
}

func rankLLMTopicsByMessages(items []llmTopicItem, msgs []*model.Message, topN int) []map[string]any {
	seen := map[string]struct{}{}
	type rankedTopic struct {
		Topic     string
		Count     int
		Reason    string
		CountMode string
	}
	ranked := make([]rankedTopic, 0, len(items))
	for _, item := range items {
		topic := cleanLLMTopicLabel(item.Topic)
		if topic == "" {
			continue
		}
		key := strings.ToLower(topic)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		terms := append([]string{topic}, item.Aliases...)
		count := countTopicSupportMessages(msgs, terms)
		countMode := "full_text_match"
		if count <= 0 && item.SupportCount > 0 {
			count = item.SupportCount
			countMode = "llm_sample_estimate"
		}
		if count <= 0 {
			continue
		}
		ranked = append(ranked, rankedTopic{
			Topic:     topic,
			Count:     count,
			Reason:    strings.TrimSpace(item.Reason),
			CountMode: countMode,
		})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].Count == ranked[j].Count {
			return ranked[i].Topic < ranked[j].Topic
		}
		return ranked[i].Count > ranked[j].Count
	})
	if topN > 0 && len(ranked) > topN {
		ranked = ranked[:topN]
	}
	out := make([]map[string]any, 0, len(ranked))
	for _, item := range ranked {
		row := map[string]any{
			"topic":      item.Topic,
			"count":      item.Count,
			"source":     "llm",
			"count_mode": item.CountMode,
		}
		if item.Reason != "" {
			row["reason"] = item.Reason
		}
		out = append(out, row)
	}
	return out
}

func cleanLLMTopicLabel(topic string) string {
	topic = strings.Trim(strings.TrimSpace(topic), " /\\|_-·~：:，,。.!！?？#*`\"'")
	if topic == "" {
		return ""
	}
	runes := []rune(topic)
	if len(runes) < 2 || len(runes) > 32 {
		return ""
	}
	if strings.HasPrefix(topic, "@") || strings.Contains(topic, "http") {
		return ""
	}
	if !isUsefulTopicToken(topic) {
		return ""
	}
	return topic
}

func countTopicSupportMessages(msgs []*model.Message, terms []string) int {
	cleanTerms := make([]string, 0, len(terms))
	for _, term := range terms {
		term = strings.ToLower(strings.TrimSpace(term))
		if term == "" || !isUsefulTopicToken(term) {
			continue
		}
		cleanTerms = append(cleanTerms, term)
	}
	if len(cleanTerms) == 0 {
		return 0
	}
	count := 0
	for _, msg := range msgs {
		if msg == nil {
			continue
		}
		text := strings.ToLower(stripMentionsForTopics(semantic.NormalizeMessageText(msg)))
		if strings.TrimSpace(text) == "" {
			continue
		}
		for _, term := range cleanTerms {
			if strings.Contains(text, term) {
				count++
				break
			}
		}
	}
	return count
}

func summarizeMentions(msgs []*model.Message, topN int) []map[string]any {
	counter := map[string]int{}
	for _, m := range msgs {
		if m == nil {
			continue
		}
		txt := semantic.NormalizeMessageText(m)
		for _, name := range extractMentions(txt) {
			counter[name]++
		}
	}
	type kv struct {
		Key string
		Val int
	}
	rows := make([]kv, 0, len(counter))
	for k, v := range counter {
		rows = append(rows, kv{k, v})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Val > rows[j].Val })
	if topN <= 0 {
		topN = 10
	}
	if len(rows) > topN {
		rows = rows[:topN]
	}
	out := make([]map[string]any, 0, len(rows))
	for _, item := range rows {
		out = append(out, map[string]any{
			"name":  item.Key,
			"count": item.Val,
		})
	}
	return out
}

func extractMentions(text string) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	matches := semanticMentionRe.FindAllStringSubmatch(text, -1)
	out := make([]string, 0, len(matches))
	seen := map[string]struct{}{}
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		name := cleanMentionName(match[1])
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func stripMentionsForTopics(text string) string {
	return semanticMentionRe.ReplaceAllString(text, " ")
}

func cleanMentionName(name string) string {
	name = strings.Trim(strings.TrimSpace(name), " @\t\r\n，,。；;：:！!？?()（）[]【】<>《》\"'")
	if name == "" {
		return ""
	}
	if !isUsefulTopicToken(name) {
		return ""
	}
	return name
}

func topWords(texts []string, topN int) []map[string]any {
	counter := map[string]int{}
	for _, text := range texts {
		for _, token := range splitTopicTokens(text) {
			counter[token]++
		}
	}
	type kv struct {
		Key string
		Val int
	}
	rows := make([]kv, 0, len(counter))
	for k, v := range counter {
		rows = append(rows, kv{k, v})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Val > rows[j].Val })
	if topN <= 0 {
		topN = 10
	}
	if len(rows) > topN {
		rows = rows[:topN]
	}
	out := make([]map[string]any, 0, len(rows))
	for _, item := range rows {
		out = append(out, map[string]any{
			"topic": item.Key,
			"count": item.Val,
		})
	}
	return out
}

func splitTopicTokens(text string) []string {
	text = strings.ToLower(strings.TrimSpace(text))
	replacer := strings.NewReplacer(
		"\n", " ", "\r", " ", "\t", " ",
		"，", " ", "。", " ", "；", " ", "：", " ", "！", " ", "？", " ",
		",", " ", ".", " ", ";", " ", ":", " ", "!", " ", "?", " ",
		"(", " ", ")", " ", "[", " ", "]", " ", "{", " ", "}", " ",
		"\"", " ", "'", " ", "`", " ",
	)
	text = replacer.Replace(text)
	parts := strings.Fields(text)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if len([]rune(part)) < 2 {
			continue
		}
		if len([]rune(part)) > 24 {
			continue
		}
		if !isUsefulTopicToken(part) {
			continue
		}
		out = append(out, part)
	}
	return out
}

func isUsefulTopicToken(token string) bool {
	token = strings.Trim(strings.TrimSpace(strings.ToLower(token)), " /\\|_-·~：:，,。.!！?？")
	if token == "" {
		return false
	}
	if _, ok := semanticStopTopicTokens[token]; ok {
		return false
	}
	if strings.HasPrefix(token, "http") || strings.HasPrefix(token, "www.") {
		return false
	}
	if semanticASCIIAlnumTokenRe.MatchString(token) {
		if _, ok := semanticAllowedASCIIKeywords[token]; ok {
			return true
		}
		return false
	}
	if strings.ContainsAny(token, "0123456789") && !semanticHasCJKRe.MatchString(token) {
		return false
	}
	if strings.Contains(token, "聊天记录") || strings.Contains(token, "合并转发") {
		return false
	}
	return true
}

var semanticStopTopicTokens = map[string]struct{}{
	"图片":          {},
	"视频":          {},
	"语音":          {},
	"文件":          {},
	"表情":          {},
	"动画表情":        {},
	"gif表情":       {},
	"红包":          {},
	"红包封面":        {},
	"链接":          {},
	"分享":          {},
	"小程序":         {},
	"公众号":         {},
	"聊天记录":        {},
	"合并转发":        {},
	"合并转发群聊的聊天记录": {},
	"日期":          {},
	"头像":          {},
	"pdf":         {},
	"doc":         {},
	"docx":        {},
	"xls":         {},
	"xlsx":        {},
	"ppt":         {},
	"pptx":        {},
	"zip":         {},
	"rar":         {},
	"jpg":         {},
	"jpeg":        {},
	"png":         {},
	"gif":         {},
	"mp4":         {},
	"mov":         {},
	"mp3":         {},
	"m4a":         {},
	"silk":        {},
	"txt":         {},
	"csv":         {},
	"dat":         {},
}

var semanticAllowedASCIIKeywords = map[string]struct{}{
	"ai":  {},
	"api": {},
	"ios": {},
	"mac": {},
	"sql": {},
	"glm": {},
}

func parseSemanticWindow(raw string) (string, string, time.Time, time.Time) {
	now := time.Now()
	loc := now.Location()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	raw = normalizeSemanticWindowKey(raw)
	if semanticDateWindowPattern.MatchString(raw) {
		if day, err := time.ParseInLocation("2006-01-02", raw, loc); err == nil {
			return raw, raw, day, day.AddDate(0, 0, 1).Add(-time.Nanosecond)
		}
	}
	switch raw {
	case "", "today", "1d":
		return "today", "今天", todayStart, now
	case "yesterday":
		label, start, end := yesterdayWindow()
		return "yesterday", label, start, end
	case "7d", "week":
		return "7d", "近7天", todayStart.AddDate(0, 0, -6), now
	case "30d", "month", "1m":
		return "30d", "近1月", todayStart.AddDate(0, 0, -29), now
	case "90d", "quarter", "3m":
		return "90d", "近季度", todayStart.AddDate(0, -3, 0), now
	case "1y", "year":
		return "1y", "近1年", todayStart.AddDate(-1, 0, 0), now
	case "all":
		return "all", "全部", time.Time{}, time.Time{}
	default:
		return "today", "今天", todayStart, now
	}
}

func formatWindowTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func summarizeDailyMessages(msgs []*model.Message, start, end time.Time) []map[string]any {
	type row struct {
		Date  string
		Count int
	}
	counter := map[string]int{}
	for _, m := range msgs {
		if m == nil {
			continue
		}
		day := m.Time.Format("2006-01-02")
		counter[day]++
	}
	out := make([]row, 0, len(counter))
	for d, n := range counter {
		out = append(out, row{Date: d, Count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Date < out[j].Date })

	// Ensure contiguous day axis for bounded windows.
	if !start.IsZero() && !end.IsZero() {
		loc := start.Location()
		cur := time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, loc)
		last := time.Date(end.Year(), end.Month(), end.Day(), 0, 0, 0, 0, loc)
		filled := make([]row, 0, int(last.Sub(cur).Hours()/24)+1)
		existing := map[string]int{}
		for _, r := range out {
			existing[r.Date] = r.Count
		}
		for !cur.After(last) {
			d := cur.Format("2006-01-02")
			filled = append(filled, row{Date: d, Count: existing[d]})
			cur = cur.AddDate(0, 0, 1)
		}
		out = filled
	}

	resp := make([]map[string]any, 0, len(out))
	for _, r := range out {
		resp = append(resp, map[string]any{
			"date":  r.Date,
			"count": r.Count,
		})
	}
	return resp
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func pickText(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}

func singleLineText(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.Join(strings.Fields(s), " ")
	if len([]rune(s)) > 200 {
		return string([]rune(s)[:200]) + "..."
	}
	return s
}

func toJSONString(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(raw)
}

func (s *Service) summarizeSemantic(ctx context.Context, title string, payload any) (string, error) {
	return s.summarizeSemanticWithTimeout(ctx, title, payload, 12*time.Second)
}

func (s *Service) summarizeSemanticWithTimeout(ctx context.Context, title string, payload any, timeout time.Duration) (string, error) {
	if s.semantic == nil {
		return "", nil
	}
	raw := toJSONString(payload)
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	sumCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return s.semantic.Summarize(sumCtx, title, raw)
}

func firstN[T any](items []T, n int) []T {
	if n <= 0 || len(items) <= n {
		return items
	}
	return items[:n]
}

func lastN[T any](items []T, n int) []T {
	if n <= 0 || len(items) <= n {
		return items
	}
	return items[len(items)-n:]
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

type hookHermesWeixinReq struct {
	HermesHome      string `json:"hermes_home"`
	AccountID       string `json:"account_id"`
	Token           string `json:"token"`
	BaseURL         string `json:"base_url"`
	CdnBaseURL      string `json:"cdn_base_url"`
	HomeChannel     string `json:"home_channel"`
	HomeChannelName string `json:"home_channel_name"`
}

type hookHermesQQReq struct {
	HermesHome      string `json:"hermes_home"`
	AppID           string `json:"app_id"`
	ClientSecret    string `json:"client_secret"`
	HomeChannel     string `json:"home_channel"`
	HomeChannelName string `json:"home_channel_name"`
}

func (s *Service) handleHookHermesWeixinGet(c *gin.Context) {
	mode := ""
	if cfg := s.conf.GetMessageHook(); cfg != nil {
		mode = conf.CanonicalHookNotifyMode(cfg.NotifyMode)
	}
	status := s.getHermesWeixinStatus(mode)
	c.JSON(http.StatusOK, status)
}

func (s *Service) handleHookHermesWeixinSet(c *gin.Context) {
	var req hookHermesWeixinReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.Err(c, errors.InvalidArg("body"))
		return
	}
	install := hermespush.DetectInstallation()
	if !install.Installed {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Hermes agent 未安装，无法保存微信渠道配置"})
		return
	}
	if _, err := hermespush.DiscoverWeixinConfig(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "当前无法读取 Hermes Weixin 配置，已禁止编辑: " + err.Error()})
		return
	}
	cfg, err := hermespush.SaveWeixinConfig(hermespush.WeixinConfig{
		HermesHome:      strings.TrimSpace(req.HermesHome),
		AccountID:       strings.TrimSpace(req.AccountID),
		Token:           strings.TrimSpace(req.Token),
		BaseURL:         strings.TrimSpace(req.BaseURL),
		CdnBaseURL:      strings.TrimSpace(req.CdnBaseURL),
		HomeChannel:     strings.TrimSpace(req.HomeChannel),
		HomeChannelName: strings.TrimSpace(req.HomeChannelName),
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	status := s.getHermesWeixinStatus("")
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
	c.JSON(http.StatusOK, status)
}

func (s *Service) handleHookHermesQQGet(c *gin.Context) {
	mode := ""
	if cfg := s.conf.GetMessageHook(); cfg != nil {
		mode = conf.CanonicalHookNotifyMode(cfg.NotifyMode)
	}
	status := s.getHermesQQStatus(mode)
	c.JSON(http.StatusOK, status)
}

func (s *Service) handleHookHermesQQSet(c *gin.Context) {
	var req hookHermesQQReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.Err(c, errors.InvalidArg("body"))
		return
	}
	install := hermespush.DetectInstallation()
	if !install.Installed {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Hermes agent 未安装，无法保存 QQ 渠道配置"})
		return
	}
	if _, err := hermespush.DiscoverQQConfig(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "当前无法读取 Hermes QQ 配置，已禁止编辑: " + err.Error()})
		return
	}
	cfg, err := hermespush.SaveQQConfig(hermespush.QQConfig{
		HermesHome:      strings.TrimSpace(req.HermesHome),
		AppID:           strings.TrimSpace(req.AppID),
		ClientSecret:    strings.TrimSpace(req.ClientSecret),
		HomeChannel:     strings.TrimSpace(req.HomeChannel),
		HomeChannelName: strings.TrimSpace(req.HomeChannelName),
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	status := s.getHermesQQStatus("")
	status.Available = true
	status.Editable = cfg.EnvFile != "" || cfg.ConfigFile != ""
	status.HermesHome = cfg.HermesHome
	status.EnvFile = cfg.EnvFile
	status.ConfigFile = cfg.ConfigFile
	status.AppID = cfg.AppID
	status.ClientSecret = cfg.ClientSecret
	status.HomeChannel = cfg.HomeChannel
	status.HomeChannelName = cfg.HomeChannelName
	c.JSON(http.StatusOK, status)
}

func splitHookKeywords(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	raw = strings.ReplaceAll(raw, "|", "｜")
	parts := strings.Split(raw, "｜")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		k := strings.TrimSpace(p)
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

func (s *Service) handleHookStatus(c *gin.Context) {
	cfg := s.conf.GetMessageHook()
	eventCount, lastEventAt, subscribers := s.getHookStats()
	running := s.db != nil && s.db.GetDB() != nil
	var keywords []string
	mode := ""
	postURL := ""
	before := 5
	after := 5
	keywordsRaw := ""
	forwardAll := false
	forwardContacts := ""
	forwardChatRooms := ""
	if cfg != nil {
		keywordsRaw = strings.TrimSpace(cfg.Keywords)
		keywords = splitHookKeywords(cfg.Keywords)
		mode = conf.CanonicalHookNotifyMode(cfg.NotifyMode)
		postURL = strings.TrimSpace(cfg.PostURL)
		if cfg.BeforeCount >= 0 {
			before = cfg.BeforeCount
		}
		if cfg.AfterCount >= 0 {
			after = cfg.AfterCount
		}
		forwardAll = cfg.ForwardAll
		forwardContacts = strings.TrimSpace(cfg.ForwardContacts)
		forwardChatRooms = strings.TrimSpace(cfg.ForwardChatRooms)
	}
	c.JSON(http.StatusOK, gin.H{
		"running":                 running,
		"keywords":                keywords,
		"keywords_raw":            keywordsRaw,
		"keywords_count":          len(keywords),
		"notify_mode":             mode,
		"post_url":                postURL,
		"before_count":            before,
		"after_count":             after,
		"forward_all":             forwardAll,
		"forward_contacts":        splitHookTargets(forwardContacts),
		"forward_contacts_raw":    forwardContacts,
		"forward_chatrooms":       splitHookTargets(forwardChatRooms),
		"forward_chatrooms_raw":   forwardChatRooms,
		"mcp_notification_method": "notifications/chatlog/keyword_hit",
		"sse_clients":             subscribers,
		"event_count":             eventCount,
		"last_event_at":           lastEventAt,
		"events_store_file":       s.hookEventsStorePath(),
		"weixin":                  s.getHermesWeixinStatus(mode),
		"qq":                      s.getHermesQQStatus(mode),
	})
}

func splitHookTargets(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	replacer := strings.NewReplacer("\n", ",", "，", ",", ";", ",", "|", ",")
	parts := strings.Split(replacer.Replace(raw), ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key := strings.ToLower(part)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, part)
	}
	return out
}

func (s *Service) handleHookEvents(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	c.JSON(http.StatusOK, gin.H{
		"events": s.getRecentHookEvents(limit),
	})
}

func (s *Service) handleHookEventsClear(c *gin.Context) {
	deleted := s.clearHookEvents()
	s.saveHookEventsToDisk()
	c.JSON(http.StatusOK, gin.H{
		"ok":          true,
		"deleted":     deleted,
		"store_file":  s.hookEventsStorePath(),
		"event_count": 0,
	})
}

func (s *Service) handleHookStream(c *gin.Context) {
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no")

	ch := s.addHookSubscriber()
	defer s.removeHookSubscriber(ch)

	c.SSEvent("snapshot", gin.H{"events": s.getRecentHookEvents(20)})
	c.Writer.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	clientGone := c.Request.Context().Done()

	c.Stream(func(w io.Writer) bool {
		select {
		case <-clientGone:
			return false
		case evt := <-ch:
			c.SSEvent("hook_event", evt)
			return true
		case <-ticker.C:
			c.SSEvent("keepalive", gin.H{"ts": time.Now().Format(time.RFC3339)})
			return true
		}
	})
}

func (s *Service) initMCPRouter() {
	s.router.Any("/mcp", func(c *gin.Context) {
		s.mcpStreamableServer.ServeHTTP(c.Writer, c.Request)
	})
	s.router.Any("/mcp/", func(c *gin.Context) {
		s.mcpStreamableServer.ServeHTTP(c.Writer, c.Request)
	})
	s.router.Any("/sse", func(c *gin.Context) {
		s.mcpSSEServer.ServeHTTP(c.Writer, c.Request)
	})
	s.router.Any("/message", func(c *gin.Context) {
		s.mcpSSEServer.ServeHTTP(c.Writer, c.Request)
	})
}

// NoRoute handles 404 Not Found errors. If the request URL starts with "/api"
// or "/static", it responds with a JSON error. Otherwise, it redirects to the root path.
func (s *Service) NoRoute(c *gin.Context) {
	path := c.Request.URL.Path
	switch {
	case strings.HasPrefix(path, "/api"), strings.HasPrefix(path, "/static"):
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
	default:
		c.Header("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate, value")
		c.Redirect(http.StatusFound, "/")
	}
}

func formatMessageType(t int64) string {
	switch t {
	case model.MessageTypeText:
		return "text"
	case model.MessageTypeImage:
		return "image"
	case model.MessageTypeVoice:
		return "voice"
	case model.MessageTypeCard:
		return "card"
	case model.MessageTypeVideo:
		return "video"
	case model.MessageTypeAnimation:
		return "sticker"
	case model.MessageTypeLocation:
		return "location"
	case model.MessageTypeShare:
		return "share"
	case model.MessageTypeVOIP:
		return "voip"
	case model.MessageTypeSystem:
		return "system"
	default:
		return strconv.FormatInt(t, 10)
	}
}

func normalizeOutputFormat(raw string) (string, error) {
	f := strings.ToLower(strings.TrimSpace(raw))
	if f == "" {
		return "yaml", nil
	}
	if f == "yaml" || f == "yml" {
		return "yaml", nil
	}
	if f == "json" {
		return "json", nil
	}
	return "", errors.InvalidArg("format")
}

func writeByFormat(c *gin.Context, payload interface{}, rawFormat string) {
	format, err := normalizeOutputFormat(rawFormat)
	if err != nil {
		errors.Err(c, err)
		return
	}
	if format == "json" {
		c.JSON(http.StatusOK, payload)
		return
	}
	out, err := yaml.Marshal(payload)
	if err != nil {
		errors.Err(c, err)
		return
	}
	c.Data(http.StatusOK, "application/x-yaml; charset=utf-8", out)
}

func parseSinceUntil(qTime, qSince, qUntil string) (time.Time, time.Time, bool, error) {
	qTime = strings.TrimSpace(qTime)
	if qTime != "" {
		start, end, ok := util.TimeRangeOf(qTime)
		if !ok {
			return time.Time{}, time.Time{}, false, errors.InvalidArg("time")
		}
		return start, end, true, nil
	}

	var (
		start time.Time
		end   time.Time
		ok    bool
	)
	if strings.TrimSpace(qSince) != "" {
		ts, err := strconv.ParseInt(strings.TrimSpace(qSince), 10, 64)
		if err != nil {
			return time.Time{}, time.Time{}, false, errors.InvalidArg("since")
		}
		start = time.Unix(ts, 0)
		ok = true
	}
	if strings.TrimSpace(qUntil) != "" {
		ts, err := strconv.ParseInt(strings.TrimSpace(qUntil), 10, 64)
		if err != nil {
			return time.Time{}, time.Time{}, false, errors.InvalidArg("until")
		}
		end = time.Unix(ts, 0)
		ok = true
	}
	return start, end, ok, nil
}

func toInt64(v interface{}) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case int:
		return int64(t)
	case float64:
		return int64(t)
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		return n
	case []byte:
		n, _ := strconv.ParseInt(strings.TrimSpace(string(t)), 10, 64)
		return n
	default:
		return 0
	}
}

func toString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	default:
		return fmt.Sprint(v)
	}
}

func appendUnique(list []string, v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return list
	}
	for _, it := range list {
		if it == v {
			return list
		}
	}
	return append(list, v)
}

func extractMediaRef(m *model.Message) (mediaType string, keys []string) {
	if m == nil || m.Contents == nil {
		return "", nil
	}
	get := func(k string) string {
		v, ok := m.Contents[k]
		if !ok {
			return ""
		}
		return strings.TrimSpace(toString(v))
	}

	switch m.Type {
	case model.MessageTypeImage:
		mediaType = "image"
		keys = appendUnique(keys, get("md5"))
		keys = appendUnique(keys, get("path"))
	case model.MessageTypeVideo:
		mediaType = "video"
		keys = appendUnique(keys, get("md5"))
		keys = appendUnique(keys, get("rawmd5"))
		keys = appendUnique(keys, get("path"))
	case model.MessageTypeVoice:
		mediaType = "voice"
		keys = appendUnique(keys, get("voice"))
		keys = appendUnique(keys, get("voice_local_id"))
		if m.Seq > 0 {
			keys = appendUnique(keys, fmt.Sprintf("%d", m.Seq%1000000))
		}
	case model.MessageTypeShare:
		if m.SubType == model.MessageSubTypeFile {
			mediaType = "file"
			keys = appendUnique(keys, get("md5"))
			keys = appendUnique(keys, get("path"))
		}
	}
	return mediaType, keys
}

func buildMediaPath(mediaType, key string) string {
	mediaType = strings.TrimSpace(mediaType)
	key = strings.TrimSpace(key)
	if mediaType == "" || key == "" {
		return ""
	}
	return "/" + mediaType + "/" + key
}

func filterByMsgType(messages []*model.Message, msgType int64) []*model.Message {
	if msgType == 0 {
		return messages
	}
	out := make([]*model.Message, 0, len(messages))
	for _, m := range messages {
		if m.Type == msgType {
			out = append(out, m)
		}
	}
	return out
}

func parseOptionalBool(raw string) (*bool, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return nil, nil
	}
	switch v {
	case "1", "true", "yes", "y":
		b := true
		return &b, nil
	case "0", "false", "no", "n":
		b := false
		return &b, nil
	default:
		return nil, errors.InvalidArg(raw)
	}
}

func parseOptionalHour(raw string) (int, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return -1, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return -1, errors.InvalidArg("hour")
	}
	if n < 0 || n > 23 {
		return -1, errors.InvalidArg("hour")
	}
	return n, nil
}

func filterHistoryMessages(messages []*model.Message, msgType, subType int64, hour int, isSelf, hasMedia *bool) []*model.Message {
	out := make([]*model.Message, 0, len(messages))
	for _, m := range messages {
		if m == nil {
			continue
		}
		if msgType != 0 && m.Type != msgType {
			continue
		}
		if subType != 0 && m.SubType != subType {
			continue
		}
		if hour >= 0 && m.Time.Hour() != hour {
			continue
		}
		if isSelf != nil && m.IsSelf != *isSelf {
			continue
		}
		if hasMedia != nil {
			mediaType, keys := extractMediaRef(m)
			has := mediaType != "" && len(keys) > 0
			if has != *hasMedia {
				continue
			}
		}
		out = append(out, m)
	}
	return out
}

func paginateMessages(messages []*model.Message, limit, offset int) []*model.Message {
	if offset < 0 {
		offset = 0
	}
	if offset >= len(messages) {
		return []*model.Message{}
	}
	if offset > 0 {
		messages = messages[offset:]
	}
	if limit > 0 && len(messages) > limit {
		messages = messages[:limit]
	}
	return messages
}

func paginateRows(rows []gin.H, limit, offset int) []gin.H {
	if offset < 0 {
		offset = 0
	}
	if offset >= len(rows) {
		return []gin.H{}
	}
	if offset > 0 {
		rows = rows[offset:]
	}
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

type historyMessageOut struct {
	Timestamp int64    `json:"timestamp" yaml:"timestamp"`
	Time      string   `json:"time,omitempty" yaml:"time,omitempty"`
	Sender    string   `json:"sender,omitempty" yaml:"sender,omitempty"`
	Type      string   `json:"type,omitempty" yaml:"type,omitempty"`
	Content   string   `json:"content,omitempty" yaml:"content,omitempty"`
	LocalID   int64    `json:"local_id,omitempty" yaml:"local_id,omitempty"`
	MediaType string   `json:"media_type,omitempty" yaml:"media_type,omitempty"`
	MediaKey  string   `json:"media_key,omitempty" yaml:"media_key,omitempty"`
	MediaKeys []string `json:"media_keys,omitempty" yaml:"media_keys,omitempty"`
	MediaPath string   `json:"media_path,omitempty" yaml:"media_path,omitempty"`
	MediaURL  string   `json:"media_url,omitempty" yaml:"media_url,omitempty"`
	ImageKey  string   `json:"image_key,omitempty" yaml:"image_key,omitempty"`
	ImageKeys []string `json:"image_keys,omitempty" yaml:"image_keys,omitempty"`
	ImagePath string   `json:"image_path,omitempty" yaml:"image_path,omitempty"`
	ImageURL  string   `json:"image_url,omitempty" yaml:"image_url,omitempty"`
	Chat      string   `json:"chat,omitempty" yaml:"chat,omitempty"`
	UserName  string   `json:"username,omitempty" yaml:"username,omitempty"`
	IsGroup   bool     `json:"is_group,omitempty" yaml:"is_group,omitempty"`
	ChatType  string   `json:"chat_type,omitempty" yaml:"chat_type,omitempty"`
}

type historyResponse struct {
	Chat       string              `json:"chat,omitempty" yaml:"chat,omitempty"`
	UserName   string              `json:"username,omitempty" yaml:"username,omitempty"`
	IsGroup    bool                `json:"is_group" yaml:"is_group"`
	ChatType   string              `json:"chat_type,omitempty" yaml:"chat_type,omitempty"`
	TotalCount int                 `json:"total_count" yaml:"total_count"`
	Count      int                 `json:"count" yaml:"count"`
	Limit      int                 `json:"limit,omitempty" yaml:"limit,omitempty"`
	Offset     int                 `json:"offset,omitempty" yaml:"offset,omitempty"`
	Messages   []historyMessageOut `json:"messages" yaml:"messages"`
}

type searchResponse struct {
	TotalCount int                 `json:"total_count" yaml:"total_count"`
	Count      int                 `json:"count" yaml:"count"`
	Limit      int                 `json:"limit,omitempty" yaml:"limit,omitempty"`
	Offset     int                 `json:"offset,omitempty" yaml:"offset,omitempty"`
	Messages   []historyMessageOut `json:"messages" yaml:"messages"`
}

type statsCountByType struct {
	Type  string `json:"type" yaml:"type"`
	Count int64  `json:"count" yaml:"count"`
}

type statsCountBySender struct {
	Sender string `json:"sender" yaml:"sender"`
	Count  int64  `json:"count" yaml:"count"`
}

type statsCountByHour struct {
	Hour  int `json:"hour" yaml:"hour"`
	Count int `json:"count" yaml:"count"`
}

type statsResponse struct {
	Chat             string               `json:"chat" yaml:"chat"`
	UserName         string               `json:"username" yaml:"username"`
	IsGroup          bool                 `json:"is_group" yaml:"is_group"`
	ChatType         string               `json:"chat_type" yaml:"chat_type"`
	Total            int                  `json:"total" yaml:"total"`
	SentCount        int                  `json:"sent_count" yaml:"sent_count"`
	ReceivedCount    int                  `json:"received_count" yaml:"received_count"`
	ActiveSenders    int                  `json:"active_senders" yaml:"active_senders"`
	ActiveDays       int                  `json:"active_days" yaml:"active_days"`
	FirstMessageTime int64                `json:"first_message_time" yaml:"first_message_time"`
	LastMessageTime  int64                `json:"last_message_time" yaml:"last_message_time"`
	QuerySince       int64                `json:"query_since" yaml:"query_since"`
	QueryUntil       int64                `json:"query_until" yaml:"query_until"`
	QueryRangeLabel  string               `json:"query_range_label" yaml:"query_range_label"`
	ByType           []statsCountByType   `json:"by_type" yaml:"by_type"`
	TopSenders       []statsCountBySender `json:"top_senders" yaml:"top_senders"`
	ByHour           []statsCountByHour   `json:"by_hour" yaml:"by_hour"`
}

func toStringSlice(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			s := strings.TrimSpace(toString(item))
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func toHistoryMessageOut(row gin.H) historyMessageOut {
	return historyMessageOut{
		Timestamp: toInt64(row["timestamp"]),
		Time:      strings.TrimSpace(toString(row["time"])),
		Sender:    strings.TrimSpace(toString(row["sender"])),
		Type:      strings.TrimSpace(toString(row["type"])),
		Content:   toString(row["content"]),
		LocalID:   toInt64(row["local_id"]),
		MediaType: strings.TrimSpace(toString(row["media_type"])),
		MediaKey:  strings.TrimSpace(toString(row["media_key"])),
		MediaKeys: toStringSlice(row["media_keys"]),
		MediaPath: strings.TrimSpace(toString(row["media_path"])),
		MediaURL:  strings.TrimSpace(toString(row["media_url"])),
		ImageKey:  strings.TrimSpace(toString(row["image_key"])),
		ImageKeys: toStringSlice(row["image_keys"]),
		ImagePath: strings.TrimSpace(toString(row["image_path"])),
		ImageURL:  strings.TrimSpace(toString(row["image_url"])),
		Chat:      strings.TrimSpace(toString(row["chat"])),
		UserName:  strings.TrimSpace(toString(row["username"])),
		IsGroup:   toInt64(row["is_group"]) == 1 || strings.EqualFold(strings.TrimSpace(toString(row["is_group"])), "true"),
		ChatType:  strings.TrimSpace(toString(row["chat_type"])),
	}
}

func toHistoryMessageOutList(rows []gin.H) []historyMessageOut {
	out := make([]historyMessageOut, 0, len(rows))
	for _, row := range rows {
		out = append(out, toHistoryMessageOut(row))
	}
	return out
}

func toHistoryMessage(m *model.Message, host string) gin.H {
	if strings.TrimSpace(host) != "" {
		m.SetContent("host", host)
	}
	content := m.Content
	if content == "" {
		content = m.PlainTextContent()
	}
	sender := m.SenderName
	if sender == "" {
		sender = m.Sender
	}
	out := gin.H{
		"timestamp": m.Time.Unix(),
		"time":      m.Time.Format("2006-01-02 15:04"),
		"sender":    sender,
		"content":   content,
		"type":      formatMessageType(m.Type),
		"local_id":  m.ID,
	}
	mediaType, mediaKeys := extractMediaRef(m)
	if mediaType != "" && len(mediaKeys) > 0 {
		mediaKey := mediaKeys[0]
		mediaPath := buildMediaPath(mediaType, mediaKey)
		out["media_type"] = mediaType
		out["media_key"] = mediaKey
		out["media_keys"] = mediaKeys
		out["media_path"] = mediaPath
		if strings.TrimSpace(host) != "" {
			out["media_url"] = "http://" + host + mediaPath
		}
		if mediaType == "image" {
			out["image_key"] = mediaKey
			out["image_keys"] = mediaKeys
			out["image_path"] = mediaPath
			if strings.TrimSpace(host) != "" {
				out["image_url"] = "http://" + host + mediaPath
			}
		}
	}
	return out
}

func (s *Service) handleChatlog(c *gin.Context) {

	q := struct {
		Time     string `form:"time"`
		Since    string `form:"since"`
		Until    string `form:"until"`
		Chat     string `form:"chat"`
		Talker   string `form:"talker"`
		Sender   string `form:"sender"`
		Keyword  string `form:"keyword"`
		MsgType  int64  `form:"msg_type"`
		SubType  int64  `form:"sub_type"`
		Hour     string `form:"hour"`
		IsSelf   string `form:"is_self"`
		HasMedia string `form:"has_media"`
		Limit    int    `form:"limit"`
		Offset   int    `form:"offset"`
		Format   string `form:"format"`
	}{}

	if err := c.BindQuery(&q); err != nil {
		errors.Err(c, err)
		return
	}

	talker := strings.TrimSpace(q.Talker)
	if talker == "" {
		talker = strings.TrimSpace(q.Chat)
	}
	if talker == "" {
		errors.Err(c, errors.InvalidArg("talker"))
		return
	}
	start, end, _, err := parseSinceUntil(q.Time, q.Since, q.Until)
	if err != nil {
		errors.Err(c, err)
		return
	}
	if q.Limit < 0 {
		q.Limit = 0
	}

	if q.Offset < 0 {
		q.Offset = 0
	}
	hour, err := parseOptionalHour(q.Hour)
	if err != nil {
		errors.Err(c, err)
		return
	}
	isSelfFilter, err := parseOptionalBool(q.IsSelf)
	if err != nil {
		errors.Err(c, errors.InvalidArg("is_self"))
		return
	}
	hasMediaFilter, err := parseOptionalBool(q.HasMedia)
	if err != nil {
		errors.Err(c, errors.InvalidArg("has_media"))
		return
	}

	keyword := q.Keyword
	if strings.TrimSpace(keyword) != "" {
		keyword = regexp.QuoteMeta(keyword)
	}
	needPostFilter := q.MsgType != 0 || q.SubType != 0 || hour >= 0 || isSelfFilter != nil || hasMediaFilter != nil
	fetchLimit := q.Limit
	fetchOffset := q.Offset
	if needPostFilter {
		// Ensure filters are applied on full result set, then paginate locally.
		fetchLimit = 0
		fetchOffset = 0
	}
	messages, err := s.db.GetMessages(start, end, talker, q.Sender, keyword, fetchLimit, fetchOffset)
	if err != nil {
		errors.Err(c, err)
		return
	}
	messages = filterHistoryMessages(messages, q.MsgType, q.SubType, hour, isSelfFilter, hasMediaFilter)
	if needPostFilter {
		messages = paginateMessages(messages, q.Limit, q.Offset)
	}

	// Populate md5->path cache for media files
	s.populateMD5PathCache(messages)

	switch strings.ToLower(q.Format) {
	case "csv":
		c.Writer.Header().Set("Content-Type", "text/csv; charset=utf-8")
		c.Writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s_%s_%s.csv", q.Talker, start.Format("2006-01-02"), end.Format("2006-01-02")))
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Header().Set("Connection", "keep-alive")
		c.Writer.Flush()

		csvWriter := csv.NewWriter(c.Writer)
		csvWriter.Write([]string{"MessageID", "Time", "SenderName", "Sender", "TalkerName", "Talker", "Content"})
		for _, m := range messages {
			csvWriter.Write(m.CSV(c.Request.Host))
		}
		csvWriter.Flush()
	case "xlsx", "excel":
		f := excelize.NewFile()
		defer func() {
			if err := f.Close(); err != nil {
				log.Error().Err(err).Msg("Failed to close excel file")
			}
		}()
		// Create a new sheet.
		index, err := f.NewSheet("Sheet1")
		if err != nil {
			errors.Err(c, err)
			return
		}
		// Set value of a cell.
		headers := []string{"MessageID", "Time", "SenderName", "Sender", "TalkerName", "Talker", "Content"}
		for i, header := range headers {
			cell, _ := excelize.CoordinatesToCellName(i+1, 1)
			f.SetCellValue("Sheet1", cell, header)
		}
		for i, m := range messages {
			row := m.CSV(c.Request.Host)
			for j, val := range row {
				cell, _ := excelize.CoordinatesToCellName(j+1, i+2)
				f.SetCellValue("Sheet1", cell, val)
			}
		}
		f.SetActiveSheet(index)
		// Set headers
		c.Writer.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		c.Writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s_%s_%s.xlsx", q.Talker, start.Format("2006-01-02"), end.Format("2006-01-02")))
		if err := f.Write(c.Writer); err != nil {
			errors.Err(c, err)
			return
		}
	case "json":
		// json
		for _, m := range messages {
			if m.Content == "" {
				m.Content = m.PlainTextContent()
			}
		}
		c.JSON(http.StatusOK, messages)
	default:
		// plain text
		c.Writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Header().Set("Connection", "keep-alive")
		c.Writer.Flush()

		for _, m := range messages {
			// format=text 时，不传入 host，只显示 [图片] 等标签，保持简洁
			c.Writer.WriteString(m.PlainText(strings.Contains(talker, ","), util.PerfectTimeFormat(start, end), ""))
			c.Writer.WriteString("\n")
			c.Writer.Flush()
		}
	}
}

func (s *Service) handleSessionsCompat(c *gin.Context) {
	q := struct {
		Query  string `form:"query"`
		Limit  int    `form:"limit"`
		Format string `form:"format"`
	}{}
	if err := c.BindQuery(&q); err != nil {
		errors.Err(c, err)
		return
	}
	if q.Limit <= 0 {
		q.Limit = 20
	}
	sessions, err := s.db.GetSessions(q.Query, q.Limit, 0)
	if err != nil {
		errors.Err(c, err)
		return
	}
	items := make([]gin.H, 0, len(sessions.Items))
	for _, sess := range sessions.Items {
		isGroup := strings.HasSuffix(sess.UserName, "@chatroom")
		chatType := "private"
		if isGroup {
			chatType = "group"
		}
		chat := sess.NickName
		if isGroup {
			if room, _ := s.db.GetChatRoom(sess.UserName); room != nil {
				if display := strings.TrimSpace(room.DisplayName()); display != "" {
					chat = display
				}
			}
		} else {
			if contact, _ := s.db.GetContact(sess.UserName); contact != nil {
				if display := strings.TrimSpace(contact.DisplayName()); display != "" {
					chat = display
				}
			}
		}
		if chat == "" {
			chat = sess.UserName
		}
		items = append(items, gin.H{
			"chat":          chat,
			"username":      sess.UserName,
			"is_group":      isGroup,
			"chat_type":     chatType,
			"unread":        0,
			"last_msg_type": "",
			"last_sender":   "",
			"summary":       sess.Content,
			"timestamp":     sess.NTime.Unix(),
			"time":          sess.NTime.Format("01-02 15:04"),
		})
	}
	writeByFormat(c, gin.H{"sessions": items}, q.Format)
}

func (s *Service) handleHistory(c *gin.Context) {
	q := struct {
		Chat     string `form:"chat"`
		Time     string `form:"time"`
		Since    string `form:"since"`
		Until    string `form:"until"`
		MsgType  int64  `form:"msg_type"`
		SubType  int64  `form:"sub_type"`
		Hour     string `form:"hour"`
		IsSelf   string `form:"is_self"`
		HasMedia string `form:"has_media"`
		Limit    int    `form:"limit"`
		Offset   int    `form:"offset"`
		Format   string `form:"format"`
	}{}
	if err := c.BindQuery(&q); err != nil {
		errors.Err(c, err)
		return
	}
	if strings.TrimSpace(q.Chat) == "" {
		errors.Err(c, errors.InvalidArg("chat"))
		return
	}
	if q.Limit <= 0 {
		q.Limit = 50
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	hour, err := parseOptionalHour(q.Hour)
	if err != nil {
		errors.Err(c, err)
		return
	}
	isSelfFilter, err := parseOptionalBool(q.IsSelf)
	if err != nil {
		errors.Err(c, errors.InvalidArg("is_self"))
		return
	}
	hasMediaFilter, err := parseOptionalBool(q.HasMedia)
	if err != nil {
		errors.Err(c, errors.InvalidArg("has_media"))
		return
	}
	start, end, _, err := parseSinceUntil(q.Time, q.Since, q.Until)
	if err != nil {
		errors.Err(c, err)
		return
	}
	needPostFilter := q.MsgType != 0 || q.SubType != 0 || hour >= 0 || isSelfFilter != nil || hasMediaFilter != nil
	fetchLimit := q.Limit + q.Offset
	if needPostFilter {
		// Ensure filters are applied on full result set, then paginate locally.
		fetchLimit = 0
	}
	messages, err := s.db.GetMessages(start, end, q.Chat, "", "", fetchLimit, 0)
	if err != nil {
		errors.Err(c, err)
		return
	}
	messages = filterHistoryMessages(messages, q.MsgType, q.SubType, hour, isSelfFilter, hasMediaFilter)
	totalCount := len(messages)
	if needPostFilter {
		messages = paginateMessages(messages, q.Limit, q.Offset)
	} else {
		// Keep previous behavior when no post-filter is used.
		messages = paginateMessages(messages, q.Limit, q.Offset)
	}
	chat := q.Chat
	username := q.Chat
	if len(messages) > 0 {
		if messages[0].TalkerName != "" {
			chat = messages[0].TalkerName
		}
		if messages[0].Talker != "" {
			username = messages[0].Talker
		}
	}
	isGroup := strings.HasSuffix(username, "@chatroom")
	chatType := "private"
	if isGroup {
		chatType = "group"
	}
	rows := make([]gin.H, 0, len(messages))
	// Keep media key/path cache warm for direct /image/{md5} access.
	s.populateMD5PathCache(messages)
	for _, m := range messages {
		rows = append(rows, toHistoryMessage(m, c.Request.Host))
	}
	writeByFormat(c, historyResponse{
		Chat:       chat,
		UserName:   username,
		IsGroup:    isGroup,
		ChatType:   chatType,
		TotalCount: totalCount,
		Count:      len(rows),
		Limit:      q.Limit,
		Offset:     q.Offset,
		Messages:   toHistoryMessageOutList(rows),
	}, q.Format)
}

func (s *Service) handleSearchCompat(c *gin.Context) {
	q := struct {
		Keyword string `form:"keyword"`
		Chats   string `form:"chats"`
		Time    string `form:"time"`
		Since   string `form:"since"`
		Until   string `form:"until"`
		MsgType int64  `form:"msg_type"`
		Limit   int    `form:"limit"`
		Offset  int    `form:"offset"`
		Format  string `form:"format"`
	}{}
	if err := c.BindQuery(&q); err != nil {
		errors.Err(c, err)
		return
	}
	if strings.TrimSpace(q.Keyword) == "" {
		errors.Err(c, errors.InvalidArg("keyword"))
		return
	}
	if q.Limit <= 0 {
		q.Limit = 20
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	start, end, _, err := parseSinceUntil(q.Time, q.Since, q.Until)
	if err != nil {
		errors.Err(c, err)
		return
	}

	chats := util.Str2List(q.Chats, ",")
	if len(chats) == 0 {
		sessions, err := s.db.GetSessions("", 300, 0)
		if err == nil {
			for _, sess := range sessions.Items {
				chats = append(chats, sess.UserName)
			}
		}
	}

	target := q.Limit + q.Offset
	if target <= 0 {
		target = q.Limit
	}
	out := make([]gin.H, 0, target*2)
	kwPattern := regexp.QuoteMeta(q.Keyword)
	for _, chat := range chats {
		fetchLimit := target * 3
		if fetchLimit < 60 {
			fetchLimit = 60
		}
		if q.MsgType != 0 {
			// Keep search semantics aligned with history/stats:
			// when type filter is applied, avoid pre-truncation before filtering.
			fetchLimit = 0
		}
		msgs, err := s.db.GetMessages(start, end, chat, "", kwPattern, fetchLimit, 0)
		if err != nil {
			continue
		}
		msgs = filterByMsgType(msgs, q.MsgType)
		for _, m := range msgs {
			row := toHistoryMessage(m, c.Request.Host)
			row["chat"] = m.TalkerName
			if row["chat"] == "" {
				row["chat"] = m.Talker
			}
			row["username"] = m.Talker
			out = append(out, row)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ti := toInt64(out[i]["timestamp"])
		tj := toInt64(out[j]["timestamp"])
		if ti == tj {
			return toInt64(out[i]["local_id"]) > toInt64(out[j]["local_id"])
		}
		return ti > tj
	})
	totalCount := len(out)
	out = paginateRows(out, q.Limit, q.Offset)
	writeByFormat(c, searchResponse{
		TotalCount: totalCount,
		Count:      len(out),
		Limit:      q.Limit,
		Offset:     q.Offset,
		Messages:   toHistoryMessageOutList(out),
	}, q.Format)
}

func classifyChatType(username string) string {
	u := strings.ToLower(strings.TrimSpace(username))
	switch {
	case strings.HasSuffix(u, "@chatroom"):
		return "group"
	case strings.HasPrefix(u, "gh_"):
		return "official_account"
	case strings.HasPrefix(u, "notifymessage"), strings.HasPrefix(u, "notification_messages"), strings.HasPrefix(u, "floatbottle"):
		return "folded"
	default:
		return "private"
	}
}

func parseFilterSet(c *gin.Context) map[string]bool {
	parts := make([]string, 0, 4)
	parts = append(parts, c.QueryArray("filter")...)
	if v := strings.TrimSpace(c.Query("filter")); v != "" {
		parts = append(parts, util.Str2List(v, ",")...)
	}
	set := map[string]bool{}
	for _, p := range parts {
		x := strings.ToLower(strings.TrimSpace(p))
		switch x {
		case "", "all":
			return nil
		case "private":
			set["private"] = true
		case "group":
			set["group"] = true
		case "official", "official_account":
			set["official_account"] = true
		case "folded", "fold":
			set["folded"] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

func (s *Service) findDBFile(group string, preferContains ...string) (string, error) {
	db := s.db.GetDB()
	if db == nil {
		return "", fmt.Errorf("database not ready")
	}
	dbs, err := db.GetDBs()
	if err != nil {
		return "", err
	}
	files := dbs[strings.ToLower(group)]
	if len(files) == 0 {
		return "", fmt.Errorf("%s database not found", group)
	}
	for _, prefer := range preferContains {
		for _, f := range files {
			if strings.Contains(strings.ToLower(filepath.Base(f)), strings.ToLower(prefer)) {
				return f, nil
			}
		}
	}
	return files[0], nil
}

func (s *Service) handleUnreadCompat(c *gin.Context) {
	format := c.Query("format")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit <= 0 {
		limit = 20
	}
	filterSet := parseFilterSet(c)

	file, err := s.findDBFile("session", "session.db")
	if err != nil {
		errors.Err(c, err)
		return
	}
	sql := fmt.Sprintf(`SELECT username, unread_count, summary, last_timestamp, last_msg_type, last_msg_sender, last_sender_display_name
FROM SessionTable
WHERE unread_count > 0
ORDER BY last_timestamp DESC
LIMIT %d`, limit*4)
	rows, err := s.db.ExecuteSQL("session", file, sql)
	if err != nil {
		errors.Err(c, err)
		return
	}

	out := make([]gin.H, 0, limit)
	for _, row := range rows {
		username := toString(row["username"])
		chatType := classifyChatType(username)
		if filterSet != nil && !filterSet[chatType] {
			continue
		}
		display := username
		if contact, _ := s.db.GetContact(username); contact != nil {
			display = contact.DisplayName()
		} else if room, _ := s.db.GetChatRoom(username); room != nil {
			display = room.DisplayName()
		}
		ts := toInt64(row["last_timestamp"])
		lastSender := toString(row["last_sender_display_name"])
		if lastSender == "" {
			lastSender = toString(row["last_msg_sender"])
		}
		out = append(out, gin.H{
			"chat":          display,
			"username":      username,
			"is_group":      chatType == "group",
			"chat_type":     chatType,
			"unread":        toInt64(row["unread_count"]),
			"last_msg_type": formatMessageType(toInt64(row["last_msg_type"])),
			"last_sender":   lastSender,
			"summary":       toString(row["summary"]),
			"timestamp":     ts,
			"time":          time.Unix(ts, 0).Format("01-02 15:04"),
		})
		if len(out) >= limit {
			break
		}
	}
	writeByFormat(c, gin.H{"sessions": out, "total": len(out)}, format)
}

func (s *Service) handleMembersCompat(c *gin.Context) {
	chat := strings.TrimSpace(c.Query("chat"))
	format := c.Query("format")
	if chat == "" {
		errors.Err(c, errors.InvalidArg("chat"))
		return
	}
	room, err := s.db.GetChatRoom(chat)
	if err != nil {
		errors.Err(c, err)
		return
	}
	members := make([]gin.H, 0, len(room.Users))
	for _, u := range room.Users {
		display := room.User2DisplayName[u.UserName]
		if display == "" {
			display = u.UserName
		}
		members = append(members, gin.H{
			"username": u.UserName,
			"display":  display,
			"is_owner": room.Owner != "" && room.Owner == u.UserName,
		})
	}
	writeByFormat(c, gin.H{
		"chat":     room.DisplayName(),
		"username": room.Name,
		"count":    len(members),
		"members":  members,
	}, format)
}

func (s *Service) handleNewMessagesCompat(c *gin.Context) {
	format := c.Query("format")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "200"))
	if limit <= 0 {
		limit = 200
	}
	state := map[string]int64{}
	if raw := strings.TrimSpace(c.Query("state")); raw != "" {
		_ = json.Unmarshal([]byte(raw), &state)
	}
	now := time.Now().Unix()
	fallback := now - 24*3600

	sessions, err := s.db.GetSessions("", 500, 0)
	if err != nil {
		errors.Err(c, err)
		return
	}
	newState := make(map[string]int64, len(sessions.Items))
	changed := make([]*model.Session, 0, len(sessions.Items))
	for _, sess := range sessions.Items {
		ts := sess.NTime.Unix()
		newState[sess.UserName] = ts
		last := fallback
		if v, ok := state[sess.UserName]; ok {
			last = v
		}
		if ts > last {
			changed = append(changed, sess)
		}
	}
	if len(changed) == 0 {
		writeByFormat(c, gin.H{"count": 0, "messages": []gin.H{}, "new_state": newState}, format)
		return
	}
	out := make([]gin.H, 0, limit)
	for _, sess := range changed {
		last := fallback
		if v, ok := state[sess.UserName]; ok {
			last = v
		}
		msgs, err := s.db.GetMessages(time.Unix(last+1, 0), time.Now(), sess.UserName, "", "", limit*3, 0)
		if err != nil {
			continue
		}
		for _, m := range msgs {
			row := toHistoryMessage(m, c.Request.Host)
			row["chat"] = m.TalkerName
			if row["chat"] == "" {
				row["chat"] = m.Talker
			}
			row["username"] = m.Talker
			row["is_group"] = m.IsChatRoom
			row["chat_type"] = classifyChatType(m.Talker)
			out = append(out, row)
			if len(out) >= limit {
				break
			}
		}
		if len(out) >= limit {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return toInt64(out[i]["timestamp"]) < toInt64(out[j]["timestamp"])
	})
	writeByFormat(c, gin.H{
		"count":     len(out),
		"messages":  out,
		"new_state": newState,
	}, format)
}

func (s *Service) handleStatsCompat(c *gin.Context) {
	chat := strings.TrimSpace(c.Query("chat"))
	format := c.Query("format")
	rawTime := strings.TrimSpace(c.Query("time"))
	if chat == "" {
		errors.Err(c, errors.InvalidArg("chat"))
		return
	}
	start, end, _, err := parseSinceUntil(c.Query("time"), c.Query("since"), c.Query("until"))
	if err != nil {
		errors.Err(c, err)
		return
	}
	sinceUnix := int64(0)
	untilUnix := int64(0)
	if !start.IsZero() {
		sinceUnix = start.Unix()
	}
	if !end.IsZero() {
		untilUnix = end.Unix()
	}
	msgs, err := s.db.GetMessages(start, end, chat, "", "", 0, 0)
	if err != nil {
		errors.Err(c, err)
		return
	}
	byType := map[string]int64{}
	topSenders := map[string]int64{}
	activeSenders := map[string]struct{}{}
	sentCount := 0
	receivedCount := 0
	activeDaysSet := map[string]struct{}{}
	var firstMessageTime int64
	var lastMessageTime int64
	byHour := make([]gin.H, 24)
	for i := 0; i < 24; i++ {
		byHour[i] = gin.H{"hour": i, "count": 0}
	}
	for _, m := range msgs {
		byType[formatMessageType(m.Type)]++
		if m.IsSelf {
			sentCount++
		} else {
			receivedCount++
		}
		dayKey := m.Time.Format("2006-01-02")
		activeDaysSet[dayKey] = struct{}{}
		ts := m.Time.Unix()
		if firstMessageTime == 0 || ts < firstMessageTime {
			firstMessageTime = ts
		}
		if ts > lastMessageTime {
			lastMessageTime = ts
		}
		if m.IsChatRoom {
			sender := m.SenderName
			if sender == "" {
				sender = m.Sender
			}
			topSenders[sender]++
			if strings.TrimSpace(sender) != "" {
				activeSenders[sender] = struct{}{}
			}
		}
		h := m.Time.Hour()
		byHour[h]["count"] = byHour[h]["count"].(int) + 1
	}
	typeRows := make([]statsCountByType, 0, len(byType))
	for t, n := range byType {
		typeRows = append(typeRows, statsCountByType{Type: t, Count: n})
	}
	sort.Slice(typeRows, func(i, j int) bool { return typeRows[i].Count > typeRows[j].Count })
	senderRows := make([]statsCountBySender, 0, len(topSenders))
	for sdr, n := range topSenders {
		senderRows = append(senderRows, statsCountBySender{Sender: sdr, Count: n})
	}
	sort.Slice(senderRows, func(i, j int) bool { return senderRows[i].Count > senderRows[j].Count })
	if len(senderRows) > 10 {
		senderRows = senderRows[:10]
	}
	username := chat
	display := chat
	chatType := "private"
	if len(msgs) > 0 {
		username = msgs[0].Talker
		chatType = classifyChatType(username)
		if chatType == "group" {
			if room, _ := s.db.GetChatRoom(username); room != nil {
				if name := strings.TrimSpace(room.DisplayName()); name != "" {
					display = name
				}
			}
		} else {
			if contact, _ := s.db.GetContact(username); contact != nil {
				if name := strings.TrimSpace(contact.DisplayName()); name != "" {
					display = name
				}
			}
		}
		if display == chat && msgs[0].TalkerName != "" {
			display = msgs[0].TalkerName
		}
	}
	queryRangeLabel := "全部时间"
	if !strings.EqualFold(rawTime, "all") {
		switch {
		case sinceUnix > 0 && untilUnix > 0:
			queryRangeLabel = fmt.Sprintf("%s - %s", time.Unix(sinceUnix, 0).Format("2006-01-02 15:04"), time.Unix(untilUnix, 0).Format("2006-01-02 15:04"))
		case sinceUnix > 0:
			queryRangeLabel = fmt.Sprintf("自 %s 起", time.Unix(sinceUnix, 0).Format("2006-01-02 15:04"))
		case untilUnix > 0:
			queryRangeLabel = fmt.Sprintf("截至 %s", time.Unix(untilUnix, 0).Format("2006-01-02 15:04"))
		}
	}
	hourRows := make([]statsCountByHour, 0, len(byHour))
	for _, item := range byHour {
		hourRows = append(hourRows, statsCountByHour{
			Hour:  int(toInt64(item["hour"])),
			Count: int(toInt64(item["count"])),
		})
	}
	payload := statsResponse{
		Chat:             display,
		UserName:         username,
		IsGroup:          chatType == "group",
		ChatType:         chatType,
		Total:            len(msgs),
		SentCount:        sentCount,
		ReceivedCount:    receivedCount,
		ActiveSenders:    len(activeSenders),
		ActiveDays:       len(activeDaysSet),
		FirstMessageTime: firstMessageTime,
		LastMessageTime:  lastMessageTime,
		QuerySince:       sinceUnix,
		QueryUntil:       untilUnix,
		QueryRangeLabel:  queryRangeLabel,
		ByType:           typeRows,
		TopSenders:       senderRows,
		ByHour:           hourRows,
	}
	writeByFormat(c, payload, format)
}

func (s *Service) handleFavoritesCompat(c *gin.Context) {
	format := c.Query("format")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit <= 0 {
		limit = 50
	}
	favType, _ := strconv.ParseInt(strings.TrimSpace(c.Query("fav_type")), 10, 64)
	queryKw := strings.TrimSpace(c.Query("query"))

	file, err := s.findDBFile("favorite", "favorite.db")
	if err != nil {
		errors.Err(c, err)
		return
	}
	rows, err := s.db.ExecuteSQL("favorite", file, fmt.Sprintf("SELECT * FROM fav_db_item ORDER BY rowid DESC LIMIT %d", limit*4))
	if err != nil {
		errors.Err(c, err)
		return
	}
	items := make([]gin.H, 0, limit)
	for _, r := range rows {
		ft := toInt64(r["type"])
		if favType != 0 && ft != favType {
			continue
		}
		content := toString(r["content"])
		if queryKw != "" && !strings.Contains(strings.ToLower(content), strings.ToLower(queryKw)) {
			continue
		}
		ts := toInt64(r["update_time"])
		if ts > 9_999_999_999 {
			ts /= 1000
		}
		typeName := map[int64]string{1: "文本", 2: "图片", 5: "文章", 19: "名片", 20: "视频"}[ft]
		if typeName == "" {
			typeName = "其他"
		}
		preview := content
		if len([]rune(preview)) > 100 {
			preview = string([]rune(preview)[:100]) + "..."
		}
		items = append(items, gin.H{
			"id":        toInt64(r["local_id"]),
			"type":      typeName,
			"type_num":  ft,
			"time":      time.Unix(ts, 0).Format("2006-01-02 15:04"),
			"timestamp": ts,
			"preview":   preview,
			"from":      toString(r["fromusr"]),
			"chat":      toString(r["realchatname"]),
		})
		if len(items) >= limit {
			break
		}
	}
	writeByFormat(c, gin.H{"count": len(items), "items": items}, format)
}

func (s *Service) handleSNSNotificationsCompat(c *gin.Context) {
	format := c.Query("format")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit <= 0 {
		limit = 50
	}
	start, end, hasRange, err := parseSinceUntil(c.Query("time"), c.Query("since"), c.Query("until"))
	if err != nil {
		errors.Err(c, err)
		return
	}
	includeRead := strings.EqualFold(c.DefaultQuery("include_read", "false"), "true")
	file, err := s.findDBFile("sns", "sns.db")
	if err != nil {
		errors.Err(c, err)
		return
	}
	rows, err := s.db.ExecuteSQL("sns", file, fmt.Sprintf(`SELECT local_id, create_time, type, feed_id, from_username, from_nickname, content, is_unread
FROM SnsMessage_tmp3 ORDER BY create_time DESC LIMIT %d`, limit*4))
	if err != nil {
		errors.Err(c, err)
		return
	}
	out := make([]gin.H, 0, limit)
	for _, r := range rows {
		if !includeRead && toInt64(r["is_unread"]) == 0 {
			continue
		}
		ts := toInt64(r["create_time"])
		tm := time.Unix(ts, 0)
		if hasRange {
			if !start.IsZero() && tm.Before(start) {
				continue
			}
			if !end.IsZero() && tm.After(end) {
				continue
			}
		}
		content := toString(r["content"])
		kind := "comment"
		if strings.TrimSpace(content) == "" {
			kind = "like"
		}
		out = append(out, gin.H{
			"type":                 kind,
			"time":                 tm.Format("01-02 15:04"),
			"timestamp":            ts,
			"from_username":        toString(r["from_username"]),
			"from_nickname":        toString(r["from_nickname"]),
			"content":              content,
			"feed_id":              toInt64(r["feed_id"]),
			"feed_author":          "",
			"feed_author_username": "",
			"feed_preview":         "",
		})
		if len(out) >= limit {
			break
		}
	}
	writeByFormat(c, gin.H{"notifications": out, "total": len(out)}, format)
}

func extractXMLTagValue(xmlText, tag string) string {
	startTag := "<" + tag + ">"
	endTag := "</" + tag + ">"
	start := strings.Index(xmlText, startTag)
	if start < 0 {
		return ""
	}
	start += len(startTag)
	end := strings.Index(xmlText[start:], endTag)
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(xmlText[start : start+end])
}

func (s *Service) handleSNSFeedCompat(c *gin.Context) {
	format := c.Query("format")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit <= 0 {
		limit = 20
	}
	user := strings.TrimSpace(c.Query("user"))
	start, end, hasRange, err := parseSinceUntil(c.Query("time"), c.Query("since"), c.Query("until"))
	if err != nil {
		errors.Err(c, err)
		return
	}
	rows, err := s.db.GetSNSTimeline("", limit*8, 0)
	if err != nil {
		errors.Err(c, err)
		return
	}
	out := make([]gin.H, 0, limit)
	for _, r := range rows {
		tid := toInt64(r["tid"])
		content := toString(r["content"])
		post, parseErr := model.ParseSNSContent(content)
		if parseErr != nil || post == nil {
			post = &model.SNSPost{XMLContent: content}
		}
		author := toString(r["user_name"])
		if author == "" {
			author = extractXMLTagValue(content, "username")
		}
		desc := extractXMLTagValue(content, "contentDesc")
		if post.ContentDesc != "" {
			desc = post.ContentDesc
		}
		cts := toInt64(extractXMLTagValue(content, "createTime"))
		if post.CreateTime > 0 {
			cts = post.CreateTime
		}
		if cts == 0 {
			cts = tid / 1000000
		}
		tm := time.Unix(cts, 0)
		if hasRange {
			if !start.IsZero() && tm.Before(start) {
				continue
			}
			if !end.IsZero() && tm.After(end) {
				continue
			}
		}
		if user != "" && !strings.Contains(strings.ToLower(author), strings.ToLower(user)) {
			disp := author
			if contact, _ := s.db.GetContact(author); contact != nil {
				disp = contact.DisplayName()
			}
			if !strings.Contains(strings.ToLower(disp), strings.ToLower(user)) {
				continue
			}
		}
		out = append(out, gin.H{
			"id":           tid,
			"timestamp":    cts,
			"time":         tm.Format("2006-01-02 15:04"),
			"username":     author,
			"display":      author,
			"content":      desc,
			"raw_content":  content,
			"content_type": post.ContentType,
			"location":     post.Location,
			"media_list":   s.enrichSNSPostMedia(c, post),
			"article":      post.Article,
			"finder_feed":  post.FinderFeed,
		})
		if len(out) >= limit {
			break
		}
	}
	writeByFormat(c, gin.H{"count": len(out), "items": out}, format)
}

func (s *Service) handleSNSSearchCompat(c *gin.Context) {
	keyword := strings.TrimSpace(c.Query("keyword"))
	format := c.Query("format")
	if keyword == "" {
		errors.Err(c, errors.InvalidArg("keyword"))
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit <= 0 {
		limit = 20
	}
	user := strings.TrimSpace(c.Query("user"))
	start, end, hasRange, err := parseSinceUntil(c.Query("time"), c.Query("since"), c.Query("until"))
	if err != nil {
		errors.Err(c, err)
		return
	}
	rows, err := s.db.GetSNSTimeline("", limit*10, 0)
	if err != nil {
		errors.Err(c, err)
		return
	}
	out := make([]gin.H, 0, limit)
	for _, r := range rows {
		tid := toInt64(r["tid"])
		content := toString(r["content"])
		post, parseErr := model.ParseSNSContent(content)
		if parseErr != nil || post == nil {
			post = &model.SNSPost{XMLContent: content}
		}
		desc := extractXMLTagValue(content, "contentDesc")
		if post.ContentDesc != "" {
			desc = post.ContentDesc
		}
		if !strings.Contains(strings.ToLower(desc), strings.ToLower(keyword)) {
			continue
		}
		author := toString(r["user_name"])
		if author == "" {
			author = extractXMLTagValue(content, "username")
		}
		cts := toInt64(extractXMLTagValue(content, "createTime"))
		if post.CreateTime > 0 {
			cts = post.CreateTime
		}
		if cts == 0 {
			cts = tid / 1000000
		}
		tm := time.Unix(cts, 0)
		if hasRange {
			if !start.IsZero() && tm.Before(start) {
				continue
			}
			if !end.IsZero() && tm.After(end) {
				continue
			}
		}
		if user != "" && !strings.Contains(strings.ToLower(author), strings.ToLower(user)) {
			continue
		}
		out = append(out, gin.H{
			"id":           tid,
			"timestamp":    cts,
			"time":         tm.Format("2006-01-02 15:04"),
			"username":     author,
			"content":      desc,
			"raw_content":  content,
			"content_type": post.ContentType,
			"location":     post.Location,
			"media_list":   s.enrichSNSPostMedia(c, post),
			"article":      post.Article,
			"finder_feed":  post.FinderFeed,
		})
		if len(out) >= limit {
			break
		}
	}
	writeByFormat(c, gin.H{"count": len(out), "items": out}, format)
}

func (s *Service) handleContactsCompat(c *gin.Context) {
	q := struct {
		Query    string `form:"query"`
		Limit    int    `form:"limit"`
		Offset   int    `form:"offset"`
		IsFriend string `form:"is_friend"`
		Format   string `form:"format"`
	}{}
	if err := c.BindQuery(&q); err != nil {
		errors.Err(c, err)
		return
	}
	if q.Limit <= 0 {
		q.Limit = 500
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	isFriendFilter, err := parseOptionalBool(q.IsFriend)
	if err != nil {
		errors.Err(c, errors.InvalidArg("is_friend"))
		return
	}
	fetchLimit, fetchOffset := q.Limit, q.Offset
	if isFriendFilter != nil {
		// Apply friend filter before pagination.
		fetchLimit, fetchOffset = 0, 0
	}
	list, err := s.db.GetContacts(q.Query, fetchLimit, fetchOffset)
	if err != nil {
		errors.Err(c, err)
		return
	}
	out := make([]gin.H, 0, len(list.Items))
	for _, ct := range list.Items {
		if isFriendFilter != nil && ct.IsFriend != *isFriendFilter {
			continue
		}
		display := ct.DisplayName()
		if display == "" {
			display = ct.UserName
		}
		out = append(out, gin.H{
			"username":  ct.UserName,
			"alias":     ct.Alias,
			"remark":    ct.Remark,
			"nickname":  ct.NickName,
			"display":   display,
			"is_friend": ct.IsFriend,
		})
	}
	if isFriendFilter != nil {
		out = paginateRows(out, q.Limit, q.Offset)
	}
	writeByFormat(c, gin.H{"count": len(out), "contacts": out}, q.Format)
}

func (s *Service) handleChatRoomsCompat(c *gin.Context) {
	q := struct {
		Query  string `form:"query"`
		Limit  int    `form:"limit"`
		Offset int    `form:"offset"`
		Format string `form:"format"`
	}{}
	if err := c.BindQuery(&q); err != nil {
		errors.Err(c, err)
		return
	}
	if q.Limit <= 0 {
		q.Limit = 500
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	list, err := s.db.GetChatRooms(q.Query, q.Limit, q.Offset)
	if err != nil {
		errors.Err(c, err)
		return
	}
	out := make([]gin.H, 0, len(list.Items))
	for _, room := range list.Items {
		display := room.DisplayName()
		if display == "" {
			display = room.Name
		}
		out = append(out, gin.H{
			"name":       room.Name,
			"remark":     room.Remark,
			"nickname":   room.NickName,
			"display":    display,
			"owner":      room.Owner,
			"user_count": len(room.Users),
		})
	}
	writeByFormat(c, gin.H{"count": len(out), "chatrooms": out}, q.Format)
}

func (s *Service) handleMedia(c *gin.Context, _type string) {
	key := strings.TrimPrefix(c.Param("key"), "/")
	if key == "" {
		errors.Err(c, errors.InvalidArg(key))
		return
	}

	keys := util.Str2List(key, ",")
	if len(keys) == 0 {
		errors.Err(c, errors.InvalidArg(key))
		return
	}

	var _err error
	for _, k := range keys {
		if strings.Contains(k, "/") {
			if absolutePath, err := s.findPath(_type, k); err == nil {
				if _type == "image" {
					s.handleImageFile(c, filepath.Join(s.conf.GetDataDir(), absolutePath))
					return
				}
				c.Redirect(http.StatusFound, "/data/"+absolutePath)
				return
			}
		}
		media, err := s.db.GetMedia(_type, k)
		if err != nil {
			// Fallback 1: try to find path from md5->path cache
			if cachedPath := s.getMD5FromCache(k); cachedPath != "" {
				// Try to find the actual file with different suffixes
				if absolutePath := s.tryFindFileWithSuffixes(_type, cachedPath); absolutePath != "" {
					if _type == "image" {
						s.handleImageFile(c, absolutePath)
						return
					}
					relativePath, relErr := s.relativeDataPath(absolutePath)
					if relErr == nil {
						c.Redirect(http.StatusFound, "/data/"+relativePath)
						return
					}
					return
				}
			}

			// Fallback 2: try to find file by md5 in msg/attach directory
			if _type == "image" && !strings.Contains(k, "/") {
				// Build md5->path map from recent messages on demand if cache is cold.
				if cachedPath := s.resolveImagePathFromRecentMessages(k); cachedPath != "" {
					if absolutePath := s.tryFindFileWithSuffixes("image", cachedPath); absolutePath != "" {
						s.handleImageFile(c, absolutePath)
						return
					}
				}
				if foundPath := s.findImageByMD5(k); foundPath != "" {
					// Process the found image file
					s.handleImageFile(c, foundPath)
					return
				}
			}

			_err = err
			continue
		}
		if c.Query("info") != "" {
			c.JSON(http.StatusOK, media)
			return
		}
		switch media.Type {
		case "voice":
			s.HandleVoice(c, media.Data)
			return
		case "image":
			s.handleImageFile(c, filepath.Join(s.conf.GetDataDir(), media.Path))
			return
		default:
			// For other types, keep the old redirect logic
			c.Redirect(http.StatusFound, "/data/"+media.Path)
			return
		}
	}

	if _err != nil {
		errors.Err(c, _err)
		return
	}
}

func (s *Service) findPath(_type string, key string) (string, error) {
	absolutePath, relativePath, err := s.safeDataPath(key)
	if err != nil {
		return "", errors.ErrMediaNotFound
	}
	if _, err := os.Stat(absolutePath); err == nil {
		return relativePath, nil
	}
	switch _type {
	case "image":
		for _, suffix := range imageDATSuffixesByPriority() {
			candidate := absolutePath + suffix
			if _, err := os.Stat(candidate); err == nil {
				if rel, relErr := s.relativeDataPath(candidate); relErr == nil {
					return rel, nil
				}
			}
		}
	case "video":
		for _, suffix := range []string{".mp4", "_thumb.jpg"} {
			candidate := absolutePath + suffix
			if _, err := os.Stat(candidate); err == nil {
				if rel, relErr := s.relativeDataPath(candidate); relErr == nil {
					return rel, nil
				}
			}
		}
	}
	return "", errors.ErrMediaNotFound
}

type imageDATFileCandidate struct {
	path  string
	tier  int
	size  int64
	mtime int64
}

func imageDATSuffixTier(name string) int {
	lower := strings.ToLower(strings.TrimSpace(name))
	base := strings.TrimSuffix(lower, ".dat")
	switch {
	case strings.HasSuffix(base, "_h"), strings.HasSuffix(base, ".h"), strings.HasSuffix(base, "_hd"), strings.HasSuffix(base, ".hd"):
		return 4
	case strings.HasSuffix(base, "_b"), strings.HasSuffix(base, ".b"):
		return 3
	case strings.HasSuffix(base, "_t"), strings.HasSuffix(base, ".t"), strings.HasSuffix(base, "_thumb"), strings.HasSuffix(base, ".thumb"):
		return 1
	case strings.HasSuffix(lower, ".dat"):
		return 2
	default:
		return 0
	}
}

func imageDATSuffixesByPriority() []string {
	// WeFlow order: H/HD -> B -> base -> T/thumb
	return []string{
		"_h.dat", ".h.dat", "_hd.dat", ".hd.dat",
		"_b.dat", ".b.dat",
		".dat",
		"_t.dat", ".t.dat", "_thumb.dat", ".thumb.dat",
	}
}

func collectImageDATCandidates(dataDir, basePath string) []string {
	fullBase := filepath.Join(dataDir, basePath)
	out := make([]string, 0, 16)
	seen := map[string]struct{}{}
	add := func(path string) {
		if path == "" {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}
		if _, err := os.Stat(path); err != nil {
			return
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	add(fullBase)
	for _, suffix := range imageDATSuffixesByPriority() {
		add(fullBase + suffix)
	}
	return out
}

func isImageHardlinkCandidateName(fileName, baseMD5 string) bool {
	lower := strings.ToLower(strings.TrimSpace(fileName))
	baseMD5 = strings.ToLower(strings.TrimSpace(baseMD5))
	if !strings.HasSuffix(lower, ".dat") || baseMD5 == "" {
		return false
	}
	base := strings.TrimSuffix(lower, ".dat")
	if base == baseMD5 {
		return true
	}
	if strings.HasPrefix(base, baseMD5+"_") || strings.HasPrefix(base, baseMD5+".") {
		return true
	}
	if len(base) == len(baseMD5)+1 && strings.HasPrefix(base, baseMD5) {
		return true
	}
	return false
}

func pickBetterImageDATCandidate(cur, next *imageDATFileCandidate) *imageDATFileCandidate {
	if cur == nil {
		return next
	}
	if next == nil {
		return cur
	}
	if next.tier > cur.tier {
		return next
	}
	if next.tier < cur.tier {
		return cur
	}
	if next.size > cur.size {
		return next
	}
	if next.size < cur.size {
		return cur
	}
	if next.mtime > cur.mtime {
		return next
	}
	if next.mtime < cur.mtime {
		return cur
	}
	if next.path < cur.path {
		return next
	}
	return cur
}

func buildImageDATCandidate(path string, info os.FileInfo) *imageDATFileCandidate {
	tier := imageDATSuffixTier(filepath.Base(path))
	if tier <= 0 {
		return nil
	}
	return &imageDATFileCandidate{
		path:  path,
		tier:  tier,
		size:  info.Size(),
		mtime: info.ModTime().Unix(),
	}
}

func imageSessionMonthRootFromPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	cleaned := filepath.ToSlash(filepath.Clean(path))
	parts := strings.Split(cleaned, "/")
	for i := 0; i+3 < len(parts); i++ {
		if strings.EqualFold(parts[i], "msg") && strings.EqualFold(parts[i+1], "attach") {
			if strings.TrimSpace(parts[i+2]) == "" || strings.TrimSpace(parts[i+3]) == "" {
				continue
			}
			return filepath.FromSlash(strings.Join(parts[:i+4], "/"))
		}
	}
	return ""
}

func (s *Service) imageSessionMonthRoots(token string) []string {
	token = strings.ToLower(strings.TrimSpace(token))
	dataDir := s.conf.GetDataDir()
	dedup := make(map[string]struct{})
	matched := make([]string, 0, 16)
	all := make([]string, 0, 32)

	s.md5PathMu.RLock()
	defer s.md5PathMu.RUnlock()
	for _, p := range s.md5PathCache {
		if strings.TrimSpace(p) == "" {
			continue
		}
		absPath := p
		if !filepath.IsAbs(absPath) {
			absPath = filepath.Join(dataDir, p)
		}
		root := imageSessionMonthRootFromPath(absPath)
		if root == "" {
			continue
		}
		if _, ok := dedup[root]; ok {
			continue
		}
		dedup[root] = struct{}{}
		all = append(all, root)

		if token == "" {
			matched = append(matched, root)
			continue
		}
		lowerPath := strings.ToLower(filepath.ToSlash(p))
		lowerBase := strings.ToLower(filepath.Base(p))
		if strings.Contains(lowerPath, token) || strings.Contains(lowerBase, token) {
			matched = append(matched, root)
		}
	}
	if len(matched) > 0 {
		return matched
	}
	return all
}

// findImageByMD5 searches encrypted image DAT in msg/attach directory.
// Key can be md5, dat basename, or numeric file token.
func (s *Service) findImageByMD5(md5 string) string {
	token := strings.ToLower(strings.TrimSpace(md5))
	if token == "" {
		return ""
	}
	roots := s.imageSessionMonthRoots(token)
	if len(roots) == 0 {
		return ""
	}

	var best *imageDATFileCandidate

	for _, root := range roots {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		// Walk only session-month scoped directories to match WeFlow candidate selection.
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				if os.IsPermission(err) {
					return filepath.SkipDir
				}
				return nil
			}
			if info.IsDir() {
				return nil
			}
			baseName := strings.ToLower(filepath.Base(path))
			if !isImageHardlinkCandidateName(baseName, token) {
				return nil
			}
			candidate := buildImageDATCandidate(path, info)
			if candidate == nil {
				return nil
			}
			best = pickBetterImageDATCandidate(best, candidate)
			return nil
		})
	}
	if best != nil {
		return best.path
	}

	return ""
}

// getMD5FromCache retrieves path from md5->path cache
func (s *Service) getMD5FromCache(md5 string) string {
	s.md5PathMu.RLock()
	defer s.md5PathMu.RUnlock()

	if path, ok := s.md5PathCache[md5]; ok {
		log.Debug().Str("md5", md5).Str("path", path).Msg("Cache hit for md5")
		return path
	}

	log.Debug().Str("md5", md5).Msg("Cache miss for md5")
	return ""
}

func (s *Service) resolveImagePathFromRecentMessages(md5 string) string {
	md5 = strings.ToLower(strings.TrimSpace(md5))
	if md5 == "" {
		return ""
	}
	if p := s.getMD5FromCache(md5); p != "" {
		return p
	}

	sessions, err := s.db.GetSessions("", 80, 0)
	if err != nil || sessions == nil || len(sessions.Items) == 0 {
		return ""
	}
	for _, sess := range sessions.Items {
		talker := strings.TrimSpace(sess.UserName)
		if talker == "" {
			continue
		}
		msgs, err := s.db.GetMessages(time.Time{}, time.Time{}, talker, "", "", 200, 0)
		if err != nil || len(msgs) == 0 {
			continue
		}
		s.populateMD5PathCache(msgs)

		for _, msg := range msgs {
			if msg == nil || msg.Type != model.MessageTypeImage || msg.Contents == nil {
				continue
			}
			md5Val := strings.ToLower(strings.TrimSpace(fmt.Sprint(msg.Contents["md5"])))
			if md5Val != md5 {
				continue
			}
			pathVal := strings.TrimSpace(fmt.Sprint(msg.Contents["path"]))
			if pathVal != "" {
				s.md5PathMu.Lock()
				s.md5PathCache[md5] = pathVal
				s.md5PathMu.Unlock()
				return pathVal
			}
		}
	}
	return ""
}

// tryFindFileWithSuffixes tries to find media files from cached basePath.
func (s *Service) tryFindFileWithSuffixes(mediaType, basePath string) string {
	dataDir := s.conf.GetDataDir()

	switch mediaType {
	case "image":
		var best *imageDATFileCandidate
		for _, testPath := range collectImageDATCandidates(dataDir, basePath) {
			info, err := os.Stat(testPath)
			if err == nil {
				if candidate := buildImageDATCandidate(testPath, info); candidate != nil {
					best = pickBetterImageDATCandidate(best, candidate)
				}
			}
		}
		if best != nil {
			log.Debug().Str("path", best.path).Msg("Found best image file with suffix")
			return best.path
		}
	case "video":
		for _, suffix := range []string{".mp4", ".mov", ".m4v", "_thumb.jpg"} {
			testPath := filepath.Join(dataDir, basePath+suffix)
			if _, err := os.Stat(testPath); err == nil {
				log.Debug().Str("path", testPath).Str("media_type", mediaType).Msg("Found file with suffix")
				return testPath
			}
		}
	case "file":
		// file fallback relies on exact cached path or DB-provided path.
	}

	// Try without any suffix (might already have extension)
	testPath := filepath.Join(dataDir, basePath)
	if _, err := os.Stat(testPath); err == nil {
		log.Debug().Str("path", testPath).Msg("Found file without suffix")
		return testPath
	}

	log.Debug().Str("basePath", basePath).Msg("File not found with any suffix")
	return ""
}

// populateMD5PathCache populates the md5->path cache from messages
func (s *Service) populateMD5PathCache(messages []*model.Message) {
	s.md5PathMu.Lock()
	defer s.md5PathMu.Unlock()

	for _, msg := range messages {
		if msg.Contents == nil {
			continue
		}

		// Only cache for image, video, and file types
		if msg.Type != model.MessageTypeImage &&
			msg.Type != model.MessageTypeVideo &&
			msg.Type != model.MessageTypeVoice {
			continue
		}

		// Get md5 from contents
		md5Value, md5Ok := msg.Contents["md5"].(string)
		if !md5Ok || md5Value == "" {
			continue
		}

		// Get path from contents
		pathValue, pathOk := msg.Contents["path"].(string)
		if pathOk && pathValue != "" {
			s.md5PathCache[md5Value] = pathValue
			log.Debug().Str("md5", md5Value).Str("path", pathValue).Msg("Cached md5->path mapping")
		}
	}
}

// handleImageFile processes an image file, handling decryption if it's a .dat file or file without extension
func (s *Service) handleImageFile(c *gin.Context, absolutePath string) {
	// Check if the file needs decryption (either .dat extension or no extension)
	needsDecryption := strings.HasSuffix(strings.ToLower(absolutePath), ".dat") ||
		filepath.Ext(absolutePath) == ""

	// If it doesn't need decryption, redirect to the data handler
	if !needsDecryption {
		relativePath, err := s.relativeDataPath(absolutePath)
		if err != nil {
			errors.Err(c, errors.ErrMediaNotFound)
			return
		}
		c.Redirect(http.StatusFound, "/data/"+relativePath)
		return
	}

	// Determine the base path for converted files
	var outputPath string
	if filepath.Ext(absolutePath) == "" {
		// No extension, use the path as is
		outputPath = absolutePath
	} else {
		// Has .dat extension, remove it
		outputPath = strings.TrimSuffix(absolutePath, filepath.Ext(absolutePath))
	}

	var newRelativePath string
	relativePathBase, relErr := s.relativeDataPath(outputPath)
	if relErr != nil {
		errors.Err(c, errors.ErrMediaNotFound)
		return
	}

	// Check if a converted file already exists
	for _, ext := range []string{".jpg", ".png", ".gif", ".jpeg", ".bmp"} {
		if _, err := os.Stat(outputPath + ext); err == nil {
			newRelativePath = relativePathBase + ext
			break
		}
	}

	// If a converted file is found, redirect to it immediately
	if newRelativePath != "" {
		c.Redirect(http.StatusFound, "/data/"+newRelativePath)
		return
	}

	// Try to decrypt and convert the file
	b, err := os.ReadFile(absolutePath)
	if err != nil {
		// If file doesn't exist or can't be read, fallback to redirect
		relativePath, relErr := s.relativeDataPath(absolutePath)
		if relErr != nil {
			errors.Err(c, errors.ErrMediaNotFound)
			return
		}
		c.Redirect(http.StatusFound, "/data/"+relativePath)
		return
	}

	out, ext, err := dat2img.Dat2Image(b)
	if err != nil {
		// If decryption fails, fallback to serving the file as-is
		relativePath, relErr := s.relativeDataPath(absolutePath)
		if relErr != nil {
			errors.Err(c, errors.ErrMediaNotFound)
			return
		}
		c.Redirect(http.StatusFound, "/data/"+relativePath)
		return
	}

	// Save the decrypted file
	s.saveDecryptedFile(absolutePath, out, ext)

	// Build the new relative path and redirect
	newRelativePath = relativePathBase + "." + ext
	c.Redirect(http.StatusFound, "/data/"+newRelativePath)
}

func (s *Service) handleMediaData(c *gin.Context) {
	rawPath := strings.TrimPrefix(c.Param("path"), "/")
	absolutePath, _, err := s.safeDataPath(rawPath)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Forbidden",
		})
		return
	}

	if _, err := os.Stat(absolutePath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "File not found",
		})
		return
	}

	ext := strings.ToLower(filepath.Ext(absolutePath))
	switch {
	case ext == ".dat", ext == "":
		// Try to decrypt .dat files or files without extension
		s.HandleDatFile(c, absolutePath)
	default:
		// 直接返回文件
		c.File(absolutePath)
	}

}

func (s *Service) safeDataPath(input string) (absolutePath, relativePath string, err error) {
	base := filepath.Clean(s.conf.GetDataDir())
	if base == "" || base == "." {
		return "", "", errors.ErrMediaNotFound
	}

	cleaned := filepath.Clean(strings.TrimPrefix(input, "/"))
	if cleaned == "." || cleaned == "" {
		return "", "", errors.ErrMediaNotFound
	}

	absolutePath = filepath.Join(base, cleaned)
	relativePath, err = filepath.Rel(base, absolutePath)
	if err != nil {
		return "", "", errors.ErrMediaNotFound
	}
	if relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
		return "", "", errors.ErrMediaNotFound
	}
	return absolutePath, filepath.ToSlash(relativePath), nil
}

func (s *Service) relativeDataPath(absolutePath string) (string, error) {
	base := filepath.Clean(s.conf.GetDataDir())
	if base == "" || base == "." {
		return "", errors.ErrMediaNotFound
	}
	cleaned := filepath.Clean(absolutePath)
	relativePath, err := filepath.Rel(base, cleaned)
	if err != nil {
		return "", errors.ErrMediaNotFound
	}
	if relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
		return "", errors.ErrMediaNotFound
	}
	return filepath.ToSlash(relativePath), nil
}

func (s *Service) HandleDatFile(c *gin.Context, path string) {

	b, err := os.ReadFile(path)
	if err != nil {
		errors.Err(c, err)
		return
	}
	out, ext, err := dat2img.Dat2Image(b)
	if err != nil {
		// WeFlow-style auto self-heal:
		// on AES padding mismatch, refresh ImgKey from current WeChat process once and retry.
		if s.shouldRetryImageDecryptAfterKeyRefresh(err) {
			if refreshedKey, refreshErr := s.tryRefreshImageKeyFromWeChat(); refreshErr == nil && refreshedKey != "" {
				if out2, ext2, err2 := dat2img.Dat2Image(b); err2 == nil {
					out, ext, err = out2, ext2, nil
				} else {
					err = err2
				}
			}
		}
	}
	if err != nil {
		// If decryption fails, check if this is a file without extension
		// If so, try to return it as-is
		if filepath.Ext(path) == "" {
			// Try to detect the file type and return appropriately
			http.DetectContentType(b)
			c.Data(http.StatusOK, http.DetectContentType(b), b)
			return
		}

		// For .dat files that fail to decrypt, return error
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":  "Failed to parse .dat file",
			"reason": err.Error(),
			"path":   path,
		})
		return
	}

	// Save decrypted file to local disk
	if s.conf.GetSaveDecryptedMedia() {
		s.saveDecryptedFile(path, out, ext)
	}

	switch ext {
	case "jpg", "jpeg":
		c.Data(http.StatusOK, "image/jpeg", out)
	case "png":
		c.Data(http.StatusOK, "image/png", out)
	case "gif":
		c.Data(http.StatusOK, "image/gif", out)
	case "bmp":
		c.Data(http.StatusOK, "image/bmp", out)
	case "mp4":
		c.Data(http.StatusOK, "video/mp4", out)
	default:
		c.Data(http.StatusOK, "image/jpg", out)
		// c.File(path)
	}
}

func (s *Service) shouldRetryImageDecryptAfterKeyRefresh(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "aes decryption failed") ||
		strings.Contains(msg, "pkcs7 padding") ||
		strings.Contains(msg, "invalid padding")
}

func (s *Service) tryRefreshImageKeyFromWeChat() (string, error) {
	s.imgKeyRefreshMu.Lock()
	if time.Since(s.lastImgKeyRefresh) < 10*time.Second {
		s.imgKeyRefreshMu.Unlock()
		return "", nil
	}
	s.lastImgKeyRefresh = time.Now()
	s.imgKeyRefreshMu.Unlock()

	ws := chatwechat.NewService(s.conf)
	instances, err := ws.GetWeChatInstancesWithError()
	if err != nil || len(instances) == 0 {
		return "", fmt.Errorf("wechat instance unavailable: %w", err)
	}

	target := instances[0]
	dataDir := filepath.Clean(s.conf.GetDataDir())
	for _, ins := range instances {
		insDir := strings.TrimSpace(ins.DataDir)
		if insDir == "" {
			continue
		}
		cleanInsDir := filepath.Clean(insDir)
		if strings.Contains(dataDir, cleanInsDir) || strings.Contains(cleanInsDir, dataDir) {
			target = ins
			break
		}
	}

	imgKey, err := ws.GetImageKey(target)
	if err != nil {
		return "", err
	}
	imgKey = strings.TrimSpace(imgKey)
	if imgKey == "" {
		return "", nil
	}

	dat2img.SetAesKey(imgKey)
	if s.conf.GetDataDir() != "" {
		go dat2img.ScanAndSetXorKey(s.conf.GetDataDir())
	}
	log.Info().Str("img_key", imgKey).Msg("refreshed image key for media decryption retry")
	return imgKey, nil
}

func (s *Service) HandleVoice(c *gin.Context, data []byte) {
	out, err := silk.Silk2MP3(data)
	if err != nil {
		c.Data(http.StatusOK, "audio/silk", data)
		return
	}
	c.Data(http.StatusOK, "audio/mp3", out)
}

// saveDecryptedFile saves the decrypted media file to local disk
func (s *Service) saveDecryptedFile(datPath string, data []byte, ext string) {
	// Generate target file path: replace .dat with actual extension
	outputPath := strings.TrimSuffix(datPath, filepath.Ext(datPath)) + "." + ext

	// Check if file already exists to avoid duplicate writes
	if _, err := os.Stat(outputPath); err == nil {
		return
	}

	// Write file
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		log.Error().
			Err(err).
			Str("dat_path", datPath).
			Str("output_path", outputPath).
			Msg("Failed to save decrypted file")
		return
	}

	log.Debug().
		Str("dat_path", datPath).
		Str("output_path", outputPath).
		Str("format", ext).
		Int("size", len(data)).
		Msg("Decrypted file saved successfully")
}

func (s *Service) handleClearCache(c *gin.Context) {
	dataDir := s.conf.GetDataDir()
	if dataDir == "" {
		errors.Err(c, fmt.Errorf("data directory not configured"))
		return
	}

	deletedCount := 0

	err := filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil // Skip directories
		}

		ext := strings.ToLower(filepath.Ext(path))
		// List of generated extensions
		generatedExts := map[string]struct{}{
			".jpg": {}, ".jpeg": {}, ".png": {}, ".gif": {}, ".bmp": {}, ".mp4": {},
		}

		if _, isGenerated := generatedExts[ext]; isGenerated {
			baseName := strings.TrimSuffix(path, ext)
			// Check for corresponding .dat file. Keep suffix order aligned with media selection.
			datSuffixes := []string{"_h.dat", ".dat", "_t.dat"}
			for _, datSuffix := range datSuffixes {
				datPath := baseName + datSuffix
				if _, statErr := os.Stat(datPath); statErr == nil {
					// Found a corresponding .dat file, so this is a cached file.
					if removeErr := os.Remove(path); removeErr == nil {
						deletedCount++
					} else {
						log.Warn().Err(removeErr).Str("path", path).Msg("Failed to remove cached file")
					}
					// Once we find a .dat pair and delete, no need to check other suffixes
					return nil
				}
			}
		}
		return nil
	})

	if err != nil {
		errors.Err(c, fmt.Errorf("failed to walk data directory: %w", err))
		return
	}

	log.Info().Int("count", deletedCount).Msg("Cleared decrypted file cache")
	c.JSON(http.StatusOK, gin.H{
		"message":      "Cache cleared successfully",
		"deletedCount": deletedCount,
	})
}

func (s *Service) handleGetDBs(c *gin.Context) {
	dbs, err := s.db.GetDecryptedDBs()
	if err != nil {
		errors.Err(c, err)
		return
	}
	c.JSON(http.StatusOK, dbs)
}

func (s *Service) handleSearchAllDBs(c *gin.Context) {
	keyword := strings.TrimSpace(c.Query("keyword"))
	if keyword == "" {
		errors.Err(c, errors.InvalidArg("keyword"))
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	deep := strings.EqualFold(strings.TrimSpace(c.DefaultQuery("mode", "quick")), "deep")

	items, err := s.db.SearchAll(keyword, limit, deep)
	if err != nil {
		errors.Err(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"keyword": keyword,
		"mode":    map[bool]string{true: "deep", false: "quick"}[deep],
		"total":   len(items),
		"items":   items,
	})
}

func (s *Service) handleGetDBTables(c *gin.Context) {
	group := c.Query("group")
	file := c.Query("file")

	if group == "" || file == "" {
		errors.Err(c, errors.InvalidArg("group or file"))
		return
	}

	tables, err := s.db.GetTables(group, file)
	if err != nil {
		errors.Err(c, err)
		return
	}
	c.JSON(http.StatusOK, tables)
}

func (s *Service) handleGetDBTableData(c *gin.Context) {
	group := c.Query("group")
	file := c.Query("file")
	table := c.Query("table")
	keyword := c.Query("keyword")
	limitStr := c.DefaultQuery("limit", "20")
	offsetStr := c.DefaultQuery("offset", "0")
	format := strings.ToLower(c.Query("format"))

	if group == "" || file == "" || table == "" {
		errors.Err(c, errors.InvalidArg("group, file or table"))
		return
	}

	limit := 20
	offset := 0
	fmt.Sscanf(limitStr, "%d", &limit)
	fmt.Sscanf(offsetStr, "%d", &offset)

	// If exporting, fetch all matching rows (ignore pagination if user wants all? or respect pagination?)
	// Usually export means "export all matching".
	if format == "csv" || format == "xlsx" || format == "excel" {
		limit = -1 // No limit
		offset = 0
	}

	data, err := s.db.GetTableData(group, file, table, limit, offset, keyword)
	if err != nil {
		errors.Err(c, err)
		return
	}

	if format == "csv" || format == "xlsx" || format == "excel" {
		s.exportData(c, data, format, table)
		return
	}

	c.JSON(http.StatusOK, data)
}

func (s *Service) handleExecuteSQL(c *gin.Context) {
	group := c.Query("group")
	file := c.Query("file")
	query := c.Query("sql")
	format := strings.ToLower(c.Query("format"))

	if group == "" || file == "" || query == "" {
		errors.Err(c, errors.InvalidArg("group, file or sql"))
		return
	}

	data, err := s.db.ExecuteSQL(group, file, query)
	if err != nil {
		errors.Err(c, err)
		return
	}

	if format == "csv" || format == "xlsx" || format == "excel" {
		s.exportData(c, data, format, "query_result")
		return
	}

	c.JSON(http.StatusOK, data)
}

func (s *Service) exportData(c *gin.Context, data []map[string]interface{}, format string, filename string) {
	if len(data) == 0 {
		c.String(http.StatusOK, "")
		return
	}

	// Extract headers
	var headers []string
	for k := range data[0] {
		headers = append(headers, k)
	}
	// Sort headers for consistency
	// sort.Strings(headers) // We need sort package

	if format == "csv" {
		c.Writer.Header().Set("Content-Type", "text/csv; charset=utf-8")
		c.Writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.csv", filename))
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Flush()

		w := csv.NewWriter(c.Writer)
		w.Write(headers)
		for _, row := range data {
			var record []string
			for _, h := range headers {
				val := row[h]
				if val == nil {
					record = append(record, "")
				} else {
					record = append(record, fmt.Sprintf("%v", val))
				}
			}
			w.Write(record)
		}
		w.Flush()
	} else {
		// Excel
		f := excelize.NewFile()
		defer func() {
			if err := f.Close(); err != nil {
				log.Error().Err(err).Msg("Failed to close excel file")
			}
		}()

		sheet := "Sheet1"
		index, _ := f.NewSheet(sheet)

		// Write headers
		for i, h := range headers {
			cell, _ := excelize.CoordinatesToCellName(i+1, 1)
			f.SetCellValue(sheet, cell, h)
		}

		// Write data
		for r, row := range data {
			for cIdx, h := range headers {
				val := row[h]
				cell, _ := excelize.CoordinatesToCellName(cIdx+1, r+2)
				f.SetCellValue(sheet, cell, val)
			}
		}

		f.SetActiveSheet(index)
		c.Writer.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		c.Writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.xlsx", filename))
		if err := f.Write(c.Writer); err != nil {
			log.Error().Err(err).Msg("Failed to write excel file")
		}
	}
}
