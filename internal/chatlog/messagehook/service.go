package messagehook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sjzar/chatlog/internal/chatlog/conf"
	"github.com/sjzar/chatlog/internal/chatlog/hermespush"
	"github.com/sjzar/chatlog/internal/model"
	"github.com/sjzar/chatlog/internal/wechatdb"
)

const (
	defaultPollInterval  = 2 * time.Second
	maxTalkerScan        = 300
	maxMsgScanPerTalker  = 200
	maxContextScan       = 2000
	voiceResolveRetries  = 20
	voiceResolveInterval = 500 * time.Millisecond
)

type Config interface {
	GetMessageHook() *conf.MessageHook
	GetDataDir() string
	GetHTTPAddr() string
	GetSemanticConfig() *conf.SemanticConfig
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
			mediaPaths, cleanup, mediaErr := s.resolveTriggerMedia(trigger)
			mediaResolveDetail := ""
			if mediaErr != nil {
				log.Warn().Err(mediaErr).Msg("keyword hook media resolve failed")
				mediaResolveDetail = mediaErr.Error()
			}
			if err := hermespush.SendWeixin(s.httpClient, weixinCfg, hermespush.WeixinSendRequest{
				Text:       buildWeixinMessage(evt),
				MediaPaths: mediaPaths,
			}); err != nil {
				log.Warn().Err(err).Msg("keyword hook weixin notify failed")
				detail := err.Error()
				if mediaResolveDetail != "" {
					detail += "; media_resolve=" + mediaResolveDetail
				}
				evt.Deliveries = append(evt.Deliveries, DeliveryResult{Target: "weixin", Status: "failed", Detail: detail, Success: false})
			} else {
				detail := ""
				if len(mediaPaths) > 0 {
					detail = fmt.Sprintf("media=%d", len(mediaPaths))
				} else if mediaResolveDetail != "" {
					detail = "media_resolve_failed=" + mediaResolveDetail
				}
				evt.Deliveries = append(evt.Deliveries, DeliveryResult{Target: "weixin", Status: "sent", Detail: detail, Success: true})
			}
			for _, path := range cleanup {
				_ = os.Remove(path)
			}
		}
	}
	if targets.QQ {
		qqCfg, err := hermespush.DiscoverQQConfig()
		if err != nil {
			log.Warn().Err(err).Msg("keyword hook qq config unavailable")
			evt.Deliveries = append(evt.Deliveries, DeliveryResult{Target: "qq", Status: "failed", Detail: err.Error(), Success: false})
		} else {
			mediaPaths, cleanup, mediaErr := s.resolveTriggerMedia(trigger)
			mediaResolveDetail := ""
			if mediaErr != nil {
				log.Warn().Err(mediaErr).Msg("keyword hook qq media resolve failed")
				mediaResolveDetail = mediaErr.Error()
			}
			if err := hermespush.SendQQ(qqCfg, hermespush.QQSendRequest{
				Text:       buildWeixinMessage(evt),
				MediaPaths: mediaPaths,
			}); err != nil {
				log.Warn().Err(err).Msg("keyword hook qq notify failed")
				detail := err.Error()
				if mediaResolveDetail != "" {
					detail += "; media_resolve=" + mediaResolveDetail
				}
				evt.Deliveries = append(evt.Deliveries, DeliveryResult{Target: "qq", Status: "failed", Detail: detail, Success: false})
			} else {
				detail := ""
				if len(mediaPaths) > 0 {
					detail = fmt.Sprintf("media=%d", len(mediaPaths))
				} else if mediaResolveDetail != "" {
					detail = "media_resolve_failed=" + mediaResolveDetail
				}
				evt.Deliveries = append(evt.Deliveries, DeliveryResult{Target: "qq", Status: "sent", Detail: detail, Success: true})
			}
			for _, path := range cleanup {
				_ = os.Remove(path)
			}
		}
	}
	return evt
}

func (s *Service) resolveTriggerMedia(trigger *model.Message) ([]string, []string, error) {
	mediaType, _ := extractTriggerMediaRef(trigger)
	paths, cleanup, err := s.resolveTriggerMediaOnce(trigger)
	if err == nil || mediaType != "voice" {
		return paths, cleanup, err
	}
	// Voice blobs may land in VoiceInfo slightly after the text row is visible.
	// Retry briefly to avoid degrading to text-only forwarding.
	lastErr := err
	for i := 0; i < voiceResolveRetries; i++ {
		time.Sleep(voiceResolveInterval)
		paths, cleanup, err = s.resolveTriggerMediaOnce(trigger)
		if err == nil {
			return paths, cleanup, nil
		}
		lastErr = err
	}
	return nil, nil, lastErr
}

func (s *Service) resolveTriggerMediaOnce(trigger *model.Message) ([]string, []string, error) {
	mediaType, keys := extractTriggerMediaRef(trigger)
	if mediaType == "" || len(keys) == 0 {
		return nil, nil, nil
	}
	if mediaType == "voice" {
		// Voice forwarding requirement: always fetch via media_url first and
		// transcode to m4a before sending.
		for _, key := range keys {
			path, err := s.downloadTriggerMedia(mediaType, key)
			if err == nil && path != "" {
				return []string{path}, []string{path}, nil
			}
		}
		// Fallback when /voice/{key} is temporarily unavailable.
		for _, key := range keys {
			media, err := s.db.GetMedia(mediaType, key)
			if err != nil || media == nil || len(media.Data) == 0 {
				continue
			}
			path, err := s.writeVoiceAsM4A(media.Data, "")
			if err == nil && path != "" {
				return []string{path}, []string{path}, nil
			}
		}
		return nil, nil, fmt.Errorf("media file not found")
	}
	for _, key := range keys {
		path, err := s.downloadTriggerMedia(mediaType, key)
		if err == nil && path != "" {
			return []string{path}, []string{path}, nil
		}
	}
	for _, key := range keys {
		media, err := s.db.GetMedia(mediaType, key)
		if err != nil || media == nil {
			continue
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

func (s *Service) downloadTriggerMedia(mediaType, key string) (string, error) {
	url := s.buildTriggerMediaURL(mediaType, key)
	if url == "" {
		return "", fmt.Errorf("media url unavailable")
	}
	resp, err := s.httpClient.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("media download failed: status=%d", resp.StatusCode)
	}
	dir, err := s.ensureMediaDownloadDir()
	if err != nil {
		return "", err
	}
	if mediaType == "voice" {
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		return s.writeVoiceAsM4A(raw, resp.Header.Get("Content-Type"))
	}
	pattern := "chatlog-weixin-media-*"
	if name := filenameFromResponse(resp); name != "" {
		if filepath.Ext(name) == "" {
			if ext := extensionFromContentType(resp.Header.Get("Content-Type")); ext != "" {
				name += ext
			} else {
				name += mediaSuffix(mediaType)
			}
		}
		pattern = "chatlog-weixin-media-*-" + name
	} else if ext := extensionFromContentType(resp.Header.Get("Content-Type")); ext != "" {
		pattern += ext
	} else {
		pattern += mediaSuffix(mediaType)
	}
	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	if _, err := tmp.ReadFrom(resp.Body); err != nil {
		tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

func (s *Service) ensureMediaDownloadDir() (string, error) {
	dir := filepath.Join(s.conf.GetDataDir(), "tmp", "weixin_media")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return dir, nil
}

func filenameFromResponse(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	if cd := strings.TrimSpace(resp.Header.Get("Content-Disposition")); cd != "" {
		_, params, err := mime.ParseMediaType(cd)
		if err == nil {
			if name := sanitizeFilename(params["filename*"]); name != "" {
				return name
			}
			if name := sanitizeFilename(params["filename"]); name != "" {
				return name
			}
		}
	}
	if resp.Request != nil && resp.Request.URL != nil {
		escapedPath := strings.TrimSpace(resp.Request.URL.EscapedPath())
		if escapedPath == "" {
			escapedPath = strings.TrimSpace(resp.Request.URL.Path)
		}
		if escapedPath != "" {
			base := path.Base(escapedPath)
			if name, err := neturl.PathUnescape(base); err == nil {
				if name = sanitizeFilename(name); name != "" {
					return name
				}
			}
			if name := sanitizeFilename(base); name != "" {
				return name
			}
		}
	}
	return ""
}

func sanitizeFilename(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	// RFC 5987 style: UTF-8''encoded_name
	if idx := strings.Index(name, "''"); idx >= 0 {
		name = name[idx+2:]
	}
	name = filepath.Base(filepath.Clean(name))
	name = strings.ReplaceAll(name, string(os.PathSeparator), "_")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "*", "_")
	if name == "." || name == ".." {
		return ""
	}
	return name
}

func (s *Service) writeVoiceAsM4A(data []byte, contentType string) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("voice data empty")
	}
	dir, err := s.ensureMediaDownloadDir()
	if err != nil {
		return "", err
	}
	srcExt := extensionFromContentType(contentType)
	if srcExt == "" {
		srcExt = voiceExtForData(data)
	}
	src, err := os.CreateTemp(dir, "chatlog-weixin-voice-src-*"+srcExt)
	if err != nil {
		return "", err
	}
	if _, err := src.Write(data); err != nil {
		src.Close()
		_ = os.Remove(src.Name())
		return "", err
	}
	if err := src.Close(); err != nil {
		_ = os.Remove(src.Name())
		return "", err
	}
	dst, err := s.transcodeToM4A(src.Name())
	_ = os.Remove(src.Name())
	if err != nil {
		return "", err
	}
	return dst, nil
}

func (s *Service) transcodeToM4A(srcPath string) (string, error) {
	dir := filepath.Dir(srcPath)
	tmp, err := os.CreateTemp(dir, "chatlog-weixin-voice-*.m4a")
	if err != nil {
		return "", err
	}
	dstPath := tmp.Name()
	_ = tmp.Close()
	_ = os.Remove(dstPath)

	var lastErr error
	if ffmpeg, err := exec.LookPath("ffmpeg"); err == nil {
		cmd := exec.Command(ffmpeg, "-y", "-loglevel", "error", "-i", srcPath, "-vn", "-c:a", "aac", "-b:a", "64k", dstPath)
		if out, err := cmd.CombinedOutput(); err == nil {
			return dstPath, nil
		} else {
			lastErr = fmt.Errorf("ffmpeg transcode failed: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	if afconvert, err := exec.LookPath("afconvert"); err == nil {
		cmd := exec.Command(afconvert, "-f", "m4af", "-d", "aac", srcPath, dstPath)
		if out, err := cmd.CombinedOutput(); err == nil {
			return dstPath, nil
		} else {
			lastErr = fmt.Errorf("afconvert transcode failed: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	_ = os.Remove(dstPath)
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("no audio transcoder available (need ffmpeg or afconvert)")
}

func extensionFromContentType(contentType string) string {
	ct := strings.TrimSpace(contentType)
	if ct == "" {
		return ""
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		mediaType = ct
	}
	exts, _ := mime.ExtensionsByType(mediaType)
	for _, ext := range exts {
		ext = strings.ToLower(strings.TrimSpace(ext))
		if ext != "" && strings.HasPrefix(ext, ".") {
			return ext
		}
	}
	return ""
}

func (s *Service) buildTriggerMediaURL(mediaType, key string) string {
	addr := strings.TrimSpace(s.conf.GetHTTPAddr())
	if addr == "" || strings.TrimSpace(key) == "" {
		return ""
	}
	host := addr
	if strings.HasPrefix(host, "0.0.0.0:") {
		host = "127.0.0.1:" + strings.TrimPrefix(host, "0.0.0.0:")
	} else if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	return "http://" + host + "/" + strings.TrimSpace(mediaType) + "/" + strings.TrimSpace(key)
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
		keys = appendUnique(keys, get("voice_local_id"))
		if m.Seq > 0 {
			keys = appendUnique(keys, fmt.Sprintf("%d", m.Seq%1000000))
		}
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

func mediaSuffix(mediaType string) string {
	switch mediaType {
	case "image":
		return ".jpg"
	case "video":
		return ".mp4"
	case "voice":
		return ".silk"
	case "file":
		return ".bin"
	default:
		return ".dat"
	}
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
