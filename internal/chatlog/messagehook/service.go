package messagehook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sjzar/chatlog/internal/chatlog/conf"
	"github.com/sjzar/chatlog/internal/chatlog/hermespush"
	"github.com/sjzar/chatlog/internal/model"
	"github.com/sjzar/chatlog/internal/wechatdb"
)

const (
	defaultPollInterval = 2 * time.Second
	maxTalkerScan       = 300
	maxMsgScanPerTalker = 200
	maxContextScan      = 2000
)

type Config interface {
	GetMessageHook() *conf.MessageHook
	GetDataDir() string
}

type ContextMessage struct {
	Seq      int64  `json:"seq"`
	Time     string `json:"time"`
	Sender   string `json:"sender"`
	IsSelf   bool   `json:"is_self"`
	Type     int64  `json:"type"`
	Content  string `json:"content"`
	Position string `json:"position"`
}

type Event struct {
	ID             int64            `json:"id"`
	CreatedAt      string           `json:"created_at"`
	RuleType       string           `json:"rule_type"`
	RuleLabel      string           `json:"rule_label"`
	Keyword        string           `json:"keyword"`
	Talker         string           `json:"talker"`
	TalkerName     string           `json:"talker_name"`
	Sender         string           `json:"sender"`
	SenderName     string           `json:"sender_name"`
	TriggerSeq     int64            `json:"trigger_seq"`
	TriggerType    int64            `json:"trigger_type"`
	TriggerTime    string           `json:"trigger_time"`
	TriggerContent string           `json:"trigger_content"`
	Context        []ContextMessage `json:"context"`
	Deliveries     []DeliveryResult `json:"deliveries,omitempty"`
}

type DeliveryResult struct {
	Target  string `json:"target"`
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
	Success bool   `json:"success"`
}

type Service struct {
	conf       Config
	db         *wechatdb.DB
	httpClient *http.Client
	notify     func(Event)
	seenSeq    map[string]int64
	startAt    time.Time
	weixinMu   sync.Mutex
	lastWeixin time.Time
}

func New(conf Config, db *wechatdb.DB, notify func(Event)) *Service {
	return &Service{
		conf:       conf,
		db:         db,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		notify:     notify,
		seenSeq:    make(map[string]int64),
		startAt:    time.Now(),
	}
}

func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(defaultPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.scanOnce(); err != nil {
				log.Debug().Err(err).Msg("message hook scan failed")
			}
		}
	}
}

func (s *Service) scanOnce() error {
	cfg := s.conf.GetMessageHook()
	if cfg == nil {
		return nil
	}
	keywords := parseKeywords(cfg.Keywords)
	forwardContacts := parseTargetList(cfg.ForwardContacts)
	forwardChatRooms := parseTargetList(cfg.ForwardChatRooms)
	if len(keywords) == 0 && !cfg.ForwardAll && len(forwardContacts) == 0 && len(forwardChatRooms) == 0 {
		return nil
	}
	sessions, err := s.db.GetSessions("", maxTalkerScan, 0)
	if err != nil || sessions == nil {
		return err
	}
	now := time.Now()
	for _, sess := range sessions.Items {
		if sess == nil || strings.TrimSpace(sess.UserName) == "" {
			continue
		}
		_ = s.scanTalker(now, sess.UserName, keywords, forwardContacts, forwardChatRooms, cfg)
	}
	return nil
}

func (s *Service) scanTalker(now time.Time, talker string, keywords []string, forwardContacts, forwardChatRooms map[string]struct{}, cfg *conf.MessageHook) error {
	start := s.startAt.Add(-15 * time.Second)
	if lastSeq := s.lastSeenSeq(talker); lastSeq > 0 {
		start = now.Add(-10 * time.Minute)
		_ = lastSeq
	}

	msgs, err := s.db.GetMessages(start, now.Add(time.Minute), talker, "", "", maxMsgScanPerTalker, 0)
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if m == nil {
			continue
		}
		if s.isSeen(talker, m.Seq) {
			continue
		}
		s.markSeen(talker, m.Seq)
		if m.Time.Before(s.startAt) || m.IsSelf {
			continue
		}

		content := strings.TrimSpace(m.PlainTextContent())
		if content == "" {
			content = strings.TrimSpace(m.Content)
		}
		if content == "" {
			continue
		}
		rules := s.matchRules(m, content, keywords, forwardContacts, forwardChatRooms, cfg.ForwardAll)
		if len(rules) == 0 {
			continue
		}
		for _, rule := range rules {
			evt := s.buildEvent(m, rule.RuleType, rule.RuleLabel, rule.Keyword, content, cfg)
			evt = s.dispatch(cfg, evt, m)
			if s.notify != nil {
				s.notify(evt)
			}
		}
	}
	return nil
}

type matchedRule struct {
	RuleType  string
	RuleLabel string
	Keyword   string
}

func (s *Service) buildEvent(trigger *model.Message, ruleType, ruleLabel, keyword, triggerContent string, cfg *conf.MessageHook) Event {
	talker := trigger.Talker
	if strings.TrimSpace(talker) == "" {
		talker = trigger.TalkerName
	}
	talkerName := trigger.TalkerName
	if talkerName == "" {
		talkerName = talker
	}
	sender := trigger.Sender
	if sender == "" {
		sender = trigger.SenderName
	}
	senderName := trigger.SenderName
	if senderName == "" {
		senderName = sender
	}
	beforeCount := 5
	afterCount := 5
	if cfg != nil && cfg.BeforeCount >= 0 {
		beforeCount = cfg.BeforeCount
	}
	if cfg != nil && cfg.AfterCount >= 0 {
		afterCount = cfg.AfterCount
	}
	evt := Event{
		ID:             time.Now().UnixNano(),
		CreatedAt:      time.Now().Format(time.RFC3339),
		RuleType:       ruleType,
		RuleLabel:      ruleLabel,
		Keyword:        keyword,
		Talker:         talker,
		TalkerName:     talkerName,
		Sender:         sender,
		SenderName:     senderName,
		TriggerSeq:     trigger.Seq,
		TriggerType:    trigger.Type,
		TriggerTime:    trigger.Time.Format("2006-01-02 15:04:05"),
		TriggerContent: triggerContent,
	}
	evt.Context = s.loadContext(trigger, beforeCount, afterCount)
	return evt
}

func (s *Service) loadContext(trigger *model.Message, beforeCount, afterCount int) []ContextMessage {
	if beforeCount == 0 && afterCount == 0 {
		return nil
	}
	msgs, err := s.db.GetMessages(trigger.Time.Add(-24*time.Hour), trigger.Time.Add(24*time.Hour), trigger.Talker, "", "", maxContextScan, 0)
	if err != nil || len(msgs) == 0 {
		return nil
	}
	idx := -1
	for i, m := range msgs {
		if m != nil && m.Seq == trigger.Seq {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil
	}
	start := idx - beforeCount
	if start < 0 {
		start = 0
	}
	end := idx + afterCount + 1
	if end > len(msgs) {
		end = len(msgs)
	}

	out := make([]ContextMessage, 0, end-start)
	for i := start; i < end; i++ {
		m := msgs[i]
		if m == nil {
			continue
		}
		content := strings.TrimSpace(m.PlainTextContent())
		if content == "" {
			content = strings.TrimSpace(m.Content)
		}
		position := "before"
		if i == idx {
			position = "trigger"
		} else if i > idx {
			position = "after"
		}
		sender := m.SenderName
		if sender == "" {
			sender = m.Sender
		}
		out = append(out, ContextMessage{
			Seq:      m.Seq,
			Time:     m.Time.Format("2006-01-02 15:04:05"),
			Sender:   sender,
			IsSelf:   m.IsSelf,
			Type:     m.Type,
			Content:  content,
			Position: position,
		})
	}
	return out
}

func (s *Service) dispatch(cfg *conf.MessageHook, evt Event, trigger *model.Message) Event {
	targets, ok := conf.ParseHookNotifyTargets(cfg.NotifyMode)
	if !ok {
		targets = conf.HookNotifyTargets{MCP: true}
	}
	if targets.MCP {
		evt.Deliveries = append(evt.Deliveries, DeliveryResult{Target: "mcp", Status: "queued", Success: true})
	}
	if targets.Post {
		url := strings.TrimSpace(cfg.PostURL)
		if url == "" {
			evt.Deliveries = append(evt.Deliveries, DeliveryResult{Target: "post", Status: "skipped", Detail: "post_url empty", Success: false})
		} else {
			body, err := json.Marshal(evt)
			if err == nil {
				req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(body))
				if err == nil {
					req.Header.Set("Content-Type", "application/json")
					resp, err := s.httpClient.Do(req)
					if err != nil {
						log.Debug().Err(err).Str("url", url).Msg("message hook post failed")
						evt.Deliveries = append(evt.Deliveries, DeliveryResult{Target: "post", Status: "failed", Detail: err.Error(), Success: false})
					} else {
						defer resp.Body.Close()
						evt.Deliveries = append(evt.Deliveries, DeliveryResult{Target: "post", Status: "sent", Detail: resp.Status, Success: resp.StatusCode >= 200 && resp.StatusCode < 300})
					}
				} else {
					evt.Deliveries = append(evt.Deliveries, DeliveryResult{Target: "post", Status: "failed", Detail: err.Error(), Success: false})
				}
			} else {
				evt.Deliveries = append(evt.Deliveries, DeliveryResult{Target: "post", Status: "failed", Detail: err.Error(), Success: false})
			}
		}
	}
	if targets.Weixin {
		weixinCfg, err := hermespush.DiscoverWeixinConfig()
		if err != nil {
			log.Warn().Err(err).Msg("keyword hook weixin config unavailable")
			evt.Deliveries = append(evt.Deliveries, DeliveryResult{Target: "weixin", Status: "failed", Detail: err.Error(), Success: false})
		} else {
			s.waitWeixinInterval(cfg.WeixinInterval)
			mediaPaths, cleanup, mediaErr := s.resolveTriggerMedia(trigger)
			if mediaErr != nil {
				log.Warn().Err(mediaErr).Msg("keyword hook media resolve failed")
			}
			if err := hermespush.SendWeixin(s.httpClient, weixinCfg, hermespush.WeixinSendRequest{
				Text:       buildWeixinMessage(evt),
				MediaPaths: mediaPaths,
			}); err != nil {
				log.Warn().Err(err).Msg("keyword hook weixin notify failed")
				evt.Deliveries = append(evt.Deliveries, DeliveryResult{Target: "weixin", Status: "failed", Detail: err.Error(), Success: false})
			} else {
				detail := ""
				if len(mediaPaths) > 0 {
					detail = fmt.Sprintf("media=%d", len(mediaPaths))
				}
				evt.Deliveries = append(evt.Deliveries, DeliveryResult{Target: "weixin", Status: "sent", Detail: detail, Success: true})
			}
			for _, path := range cleanup {
				_ = os.Remove(path)
			}
		}
	}
	return evt
}

func (s *Service) waitWeixinInterval(intervalSeconds int) {
	interval := time.Duration(intervalSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	s.weixinMu.Lock()
	defer s.weixinMu.Unlock()
	if !s.lastWeixin.IsZero() {
		if wait := time.Until(s.lastWeixin.Add(interval)); wait > 0 {
			time.Sleep(wait)
		}
	}
	s.lastWeixin = time.Now()
}

func (s *Service) resolveTriggerMedia(trigger *model.Message) ([]string, []string, error) {
	mediaType, keys := extractTriggerMediaRef(trigger)
	if mediaType == "" || len(keys) == 0 {
		return nil, nil, nil
	}
	for _, key := range keys {
		media, err := s.db.GetMedia(mediaType, key)
		if err != nil || media == nil {
			continue
		}
		if mediaType == "voice" && len(media.Data) > 0 {
			tmp, err := os.CreateTemp("", "chatlog-weixin-voice-*"+voiceExtForData(media.Data))
			if err != nil {
				return nil, nil, err
			}
			if _, err := tmp.Write(media.Data); err != nil {
				tmp.Close()
				_ = os.Remove(tmp.Name())
				return nil, nil, err
			}
			if err := tmp.Close(); err != nil {
				_ = os.Remove(tmp.Name())
				return nil, nil, err
			}
			return []string{tmp.Name()}, []string{tmp.Name()}, nil
		}
		path := strings.TrimSpace(media.Path)
		if path == "" {
			continue
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(s.conf.GetDataDir(), path)
		}
		if _, err := os.Stat(path); err == nil {
			return []string{path}, nil, nil
		}
	}
	return nil, nil, fmt.Errorf("media file not found")
}

func extractTriggerMediaRef(m *model.Message) (string, []string) {
	if m == nil || m.Contents == nil {
		return "", nil
	}
	get := func(key string) string {
		if v, ok := m.Contents[key]; ok {
			return strings.TrimSpace(fmt.Sprint(v))
		}
		return ""
	}
	appendUnique := func(list []string, v string) []string {
		v = strings.TrimSpace(v)
		if v == "" {
			return list
		}
		for _, item := range list {
			if item == v {
				return list
			}
		}
		return append(list, v)
	}

	keys := make([]string, 0, 3)
	switch m.Type {
	case model.MessageTypeImage:
		keys = appendUnique(keys, get("md5"))
		keys = appendUnique(keys, get("path"))
		return "image", keys
	case model.MessageTypeVideo:
		keys = appendUnique(keys, get("md5"))
		keys = appendUnique(keys, get("rawmd5"))
		keys = appendUnique(keys, get("path"))
		return "video", keys
	case model.MessageTypeVoice:
		keys = appendUnique(keys, get("voice"))
		return "voice", keys
	case model.MessageTypeShare:
		if m.SubType == model.MessageSubTypeFile {
			keys = appendUnique(keys, get("md5"))
			keys = appendUnique(keys, get("path"))
			return "file", keys
		}
	}
	return "", nil
}

func voiceExtForData(data []byte) string {
	if len(data) >= 4 && string(data[:4]) == "#!AM" {
		return ".amr"
	}
	return ".silk"
}

func (s *Service) matchRules(m *model.Message, content string, keywords []string, forwardContacts, forwardChatRooms map[string]struct{}, forwardAll bool) []matchedRule {
	out := make([]matchedRule, 0, 4)
	if kw := matchKeyword(content, keywords); kw != "" {
		out = append(out, matchedRule{RuleType: "keyword", RuleLabel: kw, Keyword: kw})
	}
	talker := strings.TrimSpace(m.Talker)
	talkerName := strings.TrimSpace(m.TalkerName)
	isChatRoom := strings.HasSuffix(talker, "@chatroom")
	if forwardAll {
		out = append(out, matchedRule{RuleType: "forward_all", RuleLabel: "all"})
	}
	if isChatRoom {
		if targetListContains(forwardChatRooms, talker, talkerName) {
			out = append(out, matchedRule{RuleType: "forward_chatroom", RuleLabel: fallbackText(talkerName, talker)})
		}
	} else {
		if targetListContains(forwardContacts, talker, talkerName) {
			out = append(out, matchedRule{RuleType: "forward_contact", RuleLabel: fallbackText(talkerName, talker)})
		}
	}
	return dedupeRules(out)
}

func parseTargetList(raw string) map[string]struct{} {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	replacer := strings.NewReplacer("\n", ",", "，", ",", ";", ",", "|", ",")
	parts := strings.Split(replacer.Replace(raw), ",")
	out := map[string]struct{}{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out[strings.ToLower(part)] = struct{}{}
	}
	return out
}

func targetListContains(targets map[string]struct{}, values ...string) bool {
	if len(targets) == 0 {
		return false
	}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := targets[value]; ok {
			return true
		}
	}
	return false
}

func dedupeRules(in []matchedRule) []matchedRule {
	seen := map[string]struct{}{}
	out := make([]matchedRule, 0, len(in))
	for _, item := range in {
		key := item.RuleType + "\x00" + item.RuleLabel + "\x00" + item.Keyword
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func buildWeixinMessage(evt Event) string {
	lines := []string{
		"【chatlog 关键词命中】",
		"关键词: " + fallbackText(evt.Keyword),
		"会话: " + fallbackText(evt.TalkerName, evt.Talker),
		"发送者: " + fallbackText(evt.SenderName, evt.Sender),
		"时间: " + fallbackText(evt.TriggerTime),
		"内容: " + singleLine(evt.TriggerContent),
	}
	ctx := summarizeWeixinContext(evt.Context, 6)
	if ctx != "" {
		lines = append(lines, "上下文:", ctx)
	}
	msg := strings.Join(lines, "\n")
	runes := []rune(msg)
	if len(runes) > 3500 {
		return string(runes[:3500]) + "\n...(已截断)"
	}
	return msg
}

func summarizeWeixinContext(items []ContextMessage, limit int) string {
	if len(items) == 0 || limit <= 0 {
		return ""
	}
	if len(items) > limit {
		items = items[:limit]
	}
	lines := make([]string, 0, len(items))
	for _, item := range items {
		tag := "上下文"
		switch strings.ToLower(strings.TrimSpace(item.Position)) {
		case "before":
			tag = "前文"
		case "trigger":
			tag = "命中"
		case "after":
			tag = "后文"
		}
		lines = append(lines, " - ["+tag+"] "+strings.TrimSpace(item.Time)+" "+strings.TrimSpace(item.Sender)+": "+singleLine(item.Content))
	}
	return strings.Join(lines, "\n")
}

func fallbackText(values ...string) string {
	for _, item := range values {
		item = strings.TrimSpace(item)
		if item != "" {
			return item
		}
	}
	return "-"
}

func singleLine(text string) string {
	text = strings.TrimSpace(text)
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\n", " ")
	return strings.Join(strings.Fields(text), " ")
}

func (s *Service) lastSeenSeq(talker string) int64 {
	return s.seenSeq[talker]
}

func (s *Service) isSeen(talker string, seq int64) bool {
	return seq <= s.seenSeq[talker]
}

func (s *Service) markSeen(talker string, seq int64) {
	if seq > s.seenSeq[talker] {
		s.seenSeq[talker] = seq
	}
}

func parseKeywords(raw string) []string {
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

func matchKeyword(content string, keywords []string) string {
	for _, k := range keywords {
		if strings.Contains(content, k) {
			return k
		}
	}
	return ""
}
