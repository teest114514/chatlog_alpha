package http

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog/log"

	"github.com/sjzar/chatlog/internal/chatlog/conf"
	"github.com/sjzar/chatlog/internal/chatlog/database"
	"github.com/sjzar/chatlog/internal/chatlog/messagehook"
	"github.com/sjzar/chatlog/internal/chatlog/semantic"
	"github.com/sjzar/chatlog/internal/chatlog/temporalgraph"
	"github.com/sjzar/chatlog/internal/errors"
)

type Service struct {
	conf Config
	db   *database.Service

	router *gin.Engine
	server *http.Server

	mcpServer           *server.MCPServer
	mcpSSEServer        *server.SSEServer
	mcpStreamableServer *server.StreamableHTTPServer

	// md5 到 path 的缓存（用于图片、视频等媒体文件）
	md5PathCache map[string]string
	md5PathMu    sync.RWMutex

	// 朋友圈媒体 URL 到解密 key 的缓存
	snsMediaKeyCache map[string]string
	snsMediaKeyMu    sync.RWMutex

	// 失败时自动刷新图片密钥的节流控制
	imgKeyRefreshMu   sync.Mutex
	lastImgKeyRefresh time.Time

	// 关键词触发事件缓存与前端实时推送
	hookMu          sync.RWMutex
	hookEvents      []messagehook.Event
	hookEventCount  int64
	hookLastEventAt string
	hookSubscribers map[chan messagehook.Event]struct{}

	statsCacheMu sync.RWMutex
	statsCache   map[string]statsCacheEntry

	semantic *semantic.Manager
	graph    *temporalgraph.Manager

	semanticWatchMu      sync.Mutex
	semanticWatchCancel  context.CancelFunc
	semanticLastSessionN int
}

type statsCacheEntry struct {
	Payload   gin.H
	ExpiresAt time.Time
}

type Config interface {
	GetHTTPAddr() string
	GetDataDir() string
	GetSaveDecryptedMedia() bool
	GetDataKey() string
	GetWorkDir() string
	GetPlatform() string
	GetVersion() int
	GetWalEnabled() bool
	GetAutoDecryptDebounce() int
	GetMessageHook() *conf.MessageHook
	SetHookKeywords(keywords string)
	SetHookNotifyMode(mode string)
	SetHookPostURL(url string)
	SetHookBeforeCount(n int)
	SetHookAfterCount(n int)
	SetHookForwardAll(enabled bool)
	SetHookForwardContacts(raw string)
	SetHookForwardChatRooms(raw string)
	GetSemanticConfig() *conf.SemanticConfig
	SetSemanticConfig(cfg conf.SemanticConfig)
}

func NewService(conf Config, db *database.Service) *Service {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	// Handle error from SetTrustedProxies
	if err := router.SetTrustedProxies(nil); err != nil {
		log.Err(err).Msg("Failed to set trusted proxies")
	}

	// Middleware
	router.Use(
		errors.RecoveryMiddleware(),
		errors.ErrorHandlerMiddleware(),
		gin.LoggerWithWriter(log.Logger, "/health"),
		corsMiddleware(),
	)

	s := &Service{
		conf:             conf,
		db:               db,
		router:           router,
		md5PathCache:     make(map[string]string),
		snsMediaKeyCache: make(map[string]string),
		hookEvents:       make([]messagehook.Event, 0, 200),
		hookSubscribers:  map[chan messagehook.Event]struct{}{},
		statsCache:       map[string]statsCacheEntry{},
	}
	sem, err := semantic.NewManager(conf, db)
	if err != nil {
		log.Warn().Err(err).Msg("semantic manager init failed")
	} else {
		s.semantic = sem
	}
	graph, err := temporalgraph.NewManager(conf, db)
	if err != nil {
		log.Warn().Err(err).Msg("temporal graph manager init failed")
	} else {
		s.graph = graph
	}
	s.loadHookEventsFromDisk()
	s.db.SetMessageHookNotifier(s.pushMessageHookEvent)

	s.initMCPServer()
	s.initRouter()
	return s
}

func (s *Service) Start() error {

	s.server = &http.Server{
		Addr:    s.conf.GetHTTPAddr(),
		Handler: s.router,
	}

	go func() {
		// Handle error from Run
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Err(err).Msg("Failed to start HTTP server")
		}
	}()
	s.startSemanticIncrementalWatcher()

	log.Info().Msg("Starting HTTP server on " + s.conf.GetHTTPAddr())

	return nil
}

func (s *Service) ListenAndServe() error {

	s.server = &http.Server{
		Addr:    s.conf.GetHTTPAddr(),
		Handler: s.router,
	}
	s.startSemanticIncrementalWatcher()

	log.Info().Msg("Starting HTTP server on " + s.conf.GetHTTPAddr())
	return s.server.ListenAndServe()
}

func (s *Service) Stop() error {

	if s.server == nil {
		return nil
	}
	if s.semantic != nil {
		_ = s.semantic.Close()
	}
	if s.graph != nil {
		_ = s.graph.Close()
	}
	s.stopSemanticIncrementalWatcher()

	// 使用超时上下文优雅关闭
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		log.Debug().Err(err).Msg("Failed to shutdown HTTP server")
		return nil
	}

	log.Info().Msg("HTTP server stopped")
	return nil
}

func (s *Service) startSemanticIncrementalWatcher() {
	if s.semantic == nil || s.db == nil {
		return
	}
	// Gate ticker spawn on semantic.enabled. Without this gate the 3s ticker
	// runs even when the user has explicitly turned semantic off, hammering
	// CPU (3-6 cores observed) and acquiring SQL locks that block unrelated
	// /api/v1/history reads. Audit fix #1 — see ouyadi/chatlog_alpha NOTES.
	cfg := s.conf.GetSemanticConfig()
	if !cfg.Enabled {
		return
	}
	s.semanticWatchMu.Lock()
	defer s.semanticWatchMu.Unlock()
	if s.semanticWatchCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.semanticWatchCancel = cancel
	go s.runSemanticIncrementalWatcher(ctx)
}

func (s *Service) stopSemanticIncrementalWatcher() {
	s.semanticWatchMu.Lock()
	defer s.semanticWatchMu.Unlock()
	if s.semanticWatchCancel != nil {
		s.semanticWatchCancel()
		s.semanticWatchCancel = nil
	}
}

func (s *Service) runSemanticIncrementalWatcher(ctx context.Context) {
	const pollEvery = 3 * time.Second
	ticker := time.NewTicker(pollEvery)
	defer ticker.Stop()

	tryIncremental := func() {
		cfg := s.conf.GetSemanticConfig()
		if cfg == nil || !cfg.Enabled || !cfg.RealtimeIndex {
			return
		}
		if s.semantic == nil || s.db == nil {
			return
		}
		sessions, err := s.db.GetSessions("", 200, 0)
		if err != nil || sessions == nil || len(sessions.Items) == 0 {
			return
		}
		latest := 0
		for _, item := range sessions.Items {
			if item == nil {
				continue
			}
			if item.NOrder > latest {
				latest = item.NOrder
			}
		}
		if latest <= 0 {
			return
		}
		// 首轮仅建立基线，避免启动时重复触发。
		if s.semanticLastSessionN <= 0 {
			s.semanticLastSessionN = latest
			return
		}
		if latest <= s.semanticLastSessionN {
			return
		}
		s.semanticLastSessionN = latest

		runCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		if err := s.semantic.Incremental(runCtx); err != nil {
			log.Debug().Err(err).Msg("semantic auto incremental failed")
		}
	}

	// 启动后主动跑一次增量，补齐服务关闭期间产生的消息。
	runCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	if err := s.semantic.Incremental(runCtx); err != nil {
		log.Debug().Err(err).Msg("semantic startup incremental failed")
	}
	cancel()
	tryIncremental()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tryIncremental()
		}
	}
}

func (s *Service) GetRouter() *gin.Engine {
	return s.router
}

func (s *Service) pushMessageHookEvent(evt messagehook.Event) {
	s.appendHookEvent(evt)
	s.saveHookEventsToDisk()
	s.broadcastHookEvent(evt)
	if eventHasDeliveryTarget(evt, "mcp") {
		params := map[string]any{}
		raw, err := json.Marshal(evt)
		if err == nil {
			_ = json.Unmarshal(raw, &params)
		}
		if len(params) == 0 {
			params = map[string]any{
				"created_at":  evt.CreatedAt,
				"keyword":     evt.Keyword,
				"talker":      evt.Talker,
				"trigger_seq": evt.TriggerSeq,
			}
		}
		s.mcpServer.SendNotificationToAllClients("notifications/chatlog/keyword_hit", params)
	}
}

func eventHasDeliveryTarget(evt messagehook.Event, target string) bool {
	target = strings.TrimSpace(strings.ToLower(target))
	if target == "" {
		return false
	}
	for _, item := range evt.Deliveries {
		if strings.TrimSpace(strings.ToLower(item.Target)) == target {
			return true
		}
	}
	return false
}

func (s *Service) appendHookEvent(evt messagehook.Event) {
	s.hookMu.Lock()
	defer s.hookMu.Unlock()
	s.hookEventCount++
	s.hookLastEventAt = time.Now().Format(time.RFC3339)
	s.hookEvents = append(s.hookEvents, evt)
	if len(s.hookEvents) > 200 {
		s.hookEvents = s.hookEvents[len(s.hookEvents)-200:]
	}
}

func (s *Service) clearHookEvents() int {
	s.hookMu.Lock()
	defer s.hookMu.Unlock()
	n := len(s.hookEvents)
	s.hookEvents = s.hookEvents[:0]
	s.hookEventCount = 0
	s.hookLastEventAt = ""
	return n
}

func (s *Service) broadcastHookEvent(evt messagehook.Event) {
	s.hookMu.RLock()
	defer s.hookMu.RUnlock()
	for ch := range s.hookSubscribers {
		select {
		case ch <- evt:
		default:
		}
	}
}

func (s *Service) addHookSubscriber() chan messagehook.Event {
	ch := make(chan messagehook.Event, 32)
	s.hookMu.Lock()
	s.hookSubscribers[ch] = struct{}{}
	s.hookMu.Unlock()
	return ch
}

func (s *Service) removeHookSubscriber(ch chan messagehook.Event) {
	s.hookMu.Lock()
	delete(s.hookSubscribers, ch)
	s.hookMu.Unlock()
	close(ch)
}

func (s *Service) getHookStats() (eventCount int64, lastEventAt string, subscribers int) {
	s.hookMu.RLock()
	defer s.hookMu.RUnlock()
	return s.hookEventCount, s.hookLastEventAt, len(s.hookSubscribers)
}

func (s *Service) getRecentHookEvents(limit int) []messagehook.Event {
	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}
	s.hookMu.RLock()
	defer s.hookMu.RUnlock()
	if len(s.hookEvents) == 0 {
		return []messagehook.Event{}
	}
	start := len(s.hookEvents) - limit
	if start < 0 {
		start = 0
	}
	out := make([]messagehook.Event, 0, len(s.hookEvents)-start)
	for i := len(s.hookEvents) - 1; i >= start; i-- {
		out = append(out, s.hookEvents[i])
	}
	return out
}

func (s *Service) getStatsCache(key string) (gin.H, bool) {
	if strings.TrimSpace(key) == "" {
		return nil, false
	}
	now := time.Now()
	s.statsCacheMu.RLock()
	entry, ok := s.statsCache[key]
	s.statsCacheMu.RUnlock()
	if !ok || now.After(entry.ExpiresAt) {
		return nil, false
	}
	return cloneStatsPayload(entry.Payload), true
}

func (s *Service) setStatsCache(key string, payload gin.H, ttl time.Duration) {
	if strings.TrimSpace(key) == "" || payload == nil {
		return
	}
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	now := time.Now()
	expireAt := now.Add(ttl)

	s.statsCacheMu.Lock()
	defer s.statsCacheMu.Unlock()
	for k, item := range s.statsCache {
		if now.After(item.ExpiresAt) {
			delete(s.statsCache, k)
		}
	}
	s.statsCache[key] = statsCacheEntry{
		Payload:   cloneStatsPayload(payload),
		ExpiresAt: expireAt,
	}
}

func cloneStatsPayload(in gin.H) gin.H {
	if in == nil {
		return nil
	}
	raw, err := json.Marshal(in)
	if err != nil {
		out := make(gin.H, len(in))
		for k, v := range in {
			out[k] = v
		}
		return out
	}
	var out gin.H
	if err := json.Unmarshal(raw, &out); err != nil {
		out = make(gin.H, len(in))
		for k, v := range in {
			out[k] = v
		}
	}
	return out
}

func (s *Service) hookEventsStorePath() string {
	base := strings.TrimSpace(s.conf.GetDataDir())
	if base == "" {
		base = strings.TrimSpace(s.conf.GetWorkDir())
	}
	if base == "" {
		return ""
	}
	return filepath.Join(base, "chatlog_hook_events.json")
}

func (s *Service) loadHookEventsFromDisk() {
	path := s.hookEventsStorePath()
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var events []messagehook.Event
	if err := json.Unmarshal(data, &events); err != nil {
		log.Warn().Err(err).Str("path", path).Msg("load hook events failed")
		return
	}
	if len(events) > 200 {
		events = events[len(events)-200:]
	}
	s.hookMu.Lock()
	s.hookEvents = events
	s.hookEventCount = int64(len(events))
	if len(events) > 0 {
		s.hookLastEventAt = strings.TrimSpace(events[len(events)-1].CreatedAt)
	}
	s.hookMu.Unlock()
}

func (s *Service) saveHookEventsToDisk() {
	path := s.hookEventsStorePath()
	if path == "" {
		return
	}
	s.hookMu.RLock()
	events := make([]messagehook.Event, len(s.hookEvents))
	copy(events, s.hookEvents)
	s.hookMu.RUnlock()

	data, err := json.Marshal(events)
	if err != nil {
		log.Warn().Err(err).Msg("marshal hook events failed")
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		log.Warn().Err(err).Str("path", path).Msg("create hook events dir failed")
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		log.Warn().Err(err).Str("path", tmp).Msg("write hook events temp file failed")
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Warn().Err(err).Str("path", path).Msg("save hook events failed")
	}
}
