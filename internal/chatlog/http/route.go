package http

import (
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
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
		api.GET("/contacts", s.handleContactsCompat)
		api.GET("/chatrooms", s.handleChatRoomsCompat)
		api.GET("/db", s.handleGetDBs)
		api.GET("/db/tables", s.handleGetDBTables)
		api.GET("/db/data", s.handleGetDBTableData)
		api.GET("/db/query", s.handleExecuteSQL)
		api.POST("/cache/clear", s.handleClearCache)
	}
}

func (s *Service) handlePing(c *gin.Context) {
	writeByFormat(c, gin.H{"pong": true}, c.Query("format"))
}

func (s *Service) initMCPRouter() {
	s.router.Any("/mcp", func(c *gin.Context) {
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

func toHistoryMessage(m *model.Message, host string) gin.H {
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
		Time    string `form:"time"`
		Since   string `form:"since"`
		Until   string `form:"until"`
		Chat    string `form:"chat"`
		Talker  string `form:"talker"`
		Sender  string `form:"sender"`
		Keyword string `form:"keyword"`
		MsgType int64  `form:"msg_type"`
		Limit   int    `form:"limit"`
		Offset  int    `form:"offset"`
		Format  string `form:"format"`
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

	keyword := q.Keyword
	if strings.TrimSpace(keyword) != "" {
		keyword = regexp.QuoteMeta(keyword)
	}
	messages, err := s.db.GetMessages(start, end, talker, q.Sender, keyword, q.Limit, q.Offset)
	if err != nil {
		errors.Err(c, err)
		return
	}
	messages = filterByMsgType(messages, q.MsgType)

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
		Chat    string `form:"chat"`
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
	start, end, _, err := parseSinceUntil(q.Time, q.Since, q.Until)
	if err != nil {
		errors.Err(c, err)
		return
	}
	messages, err := s.db.GetMessages(start, end, q.Chat, "", "", q.Limit+q.Offset, 0)
	if err != nil {
		errors.Err(c, err)
		return
	}
	messages = filterByMsgType(messages, q.MsgType)
	if q.Offset > 0 {
		if q.Offset >= len(messages) {
			messages = []*model.Message{}
		} else {
			messages = messages[q.Offset:]
		}
	}
	if q.Limit > 0 && len(messages) > q.Limit {
		messages = messages[:q.Limit]
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
	for _, m := range messages {
		rows = append(rows, toHistoryMessage(m, c.Request.Host))
	}
	writeByFormat(c, gin.H{
		"chat":      chat,
		"username":  username,
		"is_group":  isGroup,
		"chat_type": chatType,
		"count":     len(rows),
		"messages":  rows,
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

	out := make([]gin.H, 0, q.Limit*2)
	kwPattern := regexp.QuoteMeta(q.Keyword)
	for _, chat := range chats {
		msgs, err := s.db.GetMessages(start, end, chat, "", kwPattern, q.Limit*3, 0)
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
			if len(out) >= q.Limit {
				break
			}
		}
		if len(out) >= q.Limit {
			break
		}
	}
	writeByFormat(c, gin.H{"count": len(out), "messages": out}, q.Format)
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
	if chat == "" {
		errors.Err(c, errors.InvalidArg("chat"))
		return
	}
	start, end, _, err := parseSinceUntil(c.Query("time"), c.Query("since"), c.Query("until"))
	if err != nil {
		errors.Err(c, err)
		return
	}
	msgs, err := s.db.GetMessages(start, end, chat, "", "", 0, 0)
	if err != nil {
		errors.Err(c, err)
		return
	}
	byType := map[string]int64{}
	topSenders := map[string]int64{}
	byHour := make([]gin.H, 24)
	for i := 0; i < 24; i++ {
		byHour[i] = gin.H{"hour": i, "count": 0}
	}
	for _, m := range msgs {
		byType[formatMessageType(m.Type)]++
		if m.IsChatRoom {
			sender := m.SenderName
			if sender == "" {
				sender = m.Sender
			}
			topSenders[sender]++
		}
		h := m.Time.Hour()
		byHour[h]["count"] = byHour[h]["count"].(int) + 1
	}
	typeRows := make([]gin.H, 0, len(byType))
	for t, n := range byType {
		typeRows = append(typeRows, gin.H{"type": t, "count": n})
	}
	sort.Slice(typeRows, func(i, j int) bool { return toInt64(typeRows[i]["count"]) > toInt64(typeRows[j]["count"]) })
	senderRows := make([]gin.H, 0, len(topSenders))
	for sdr, n := range topSenders {
		senderRows = append(senderRows, gin.H{"sender": sdr, "count": n})
	}
	sort.Slice(senderRows, func(i, j int) bool { return toInt64(senderRows[i]["count"]) > toInt64(senderRows[j]["count"]) })
	if len(senderRows) > 10 {
		senderRows = senderRows[:10]
	}
	username := chat
	display := chat
	chatType := "private"
	if len(msgs) > 0 {
		username = msgs[0].Talker
		chatType = classifyChatType(username)
		if msgs[0].TalkerName != "" {
			display = msgs[0].TalkerName
		}
	}
	writeByFormat(c, gin.H{
		"chat":        display,
		"username":    username,
		"is_group":    chatType == "group",
		"chat_type":   chatType,
		"total":       len(msgs),
		"by_type":     typeRows,
		"top_senders": senderRows,
		"by_hour":     byHour,
	}, format)
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
		author := toString(r["user_name"])
		if author == "" {
			author = extractXMLTagValue(content, "username")
		}
		desc := extractXMLTagValue(content, "contentDesc")
		cts := toInt64(extractXMLTagValue(content, "createTime"))
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
			"id":          tid,
			"timestamp":   cts,
			"time":        tm.Format("2006-01-02 15:04"),
			"username":    author,
			"display":     author,
			"content":     desc,
			"raw_content": content,
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
		desc := extractXMLTagValue(content, "contentDesc")
		if !strings.Contains(strings.ToLower(desc), strings.ToLower(keyword)) {
			continue
		}
		author := toString(r["user_name"])
		if author == "" {
			author = extractXMLTagValue(content, "username")
		}
		cts := toInt64(extractXMLTagValue(content, "createTime"))
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
			"id":          tid,
			"timestamp":   cts,
			"time":        tm.Format("2006-01-02 15:04"),
			"username":    author,
			"content":     desc,
			"raw_content": content,
		})
		if len(out) >= limit {
			break
		}
	}
	writeByFormat(c, gin.H{"count": len(out), "items": out}, format)
}

func (s *Service) handleContactsCompat(c *gin.Context) {
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
		q.Limit = 50
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	list, err := s.db.GetContacts(q.Query, q.Limit, q.Offset)
	if err != nil {
		errors.Err(c, err)
		return
	}
	out := make([]gin.H, 0, len(list.Items))
	for _, ct := range list.Items {
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
		q.Limit = 50
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
				c.Redirect(http.StatusFound, "/data/"+absolutePath)
				return
			}
		}
		media, err := s.db.GetMedia(_type, k)
		if err != nil {
			// Fallback 1: try to find path from md5->path cache
			if cachedPath := s.getMD5FromCache(k); cachedPath != "" {
				// Try to find the actual file with different suffixes
				if absolutePath := s.tryFindFileWithSuffixes(cachedPath); absolutePath != "" {
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
		for _, suffix := range []string{"_h.dat", ".dat", "_t.dat"} {
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

// findImageByMD5 searches for an image-like file token in msg/attach directory.
// Key can be md5, dat basename, or numeric file token.
func (s *Service) findImageByMD5(md5 string) string {
	dataDir := s.conf.GetDataDir()
	attachDir := filepath.Join(dataDir, "msg", "attach")

	// Check if attach directory exists
	if _, err := os.Stat(attachDir); os.IsNotExist(err) {
		return ""
	}

	var foundPath string
	bestScore := -1
	scoreOf := func(name string) int {
		lower := strings.ToLower(name)
		switch {
		case strings.HasSuffix(lower, "_h.dat"):
			return 5
		case strings.HasSuffix(lower, ".dat"):
			return 4
		case strings.HasSuffix(lower, "_t.dat"):
			return 3
		case filepath.Ext(lower) == "":
			return 2
		case strings.HasSuffix(lower, ".jpg"), strings.HasSuffix(lower, ".jpeg"), strings.HasSuffix(lower, ".png"), strings.HasSuffix(lower, ".gif"), strings.HasSuffix(lower, ".bmp"), strings.HasSuffix(lower, ".webp"):
			return 1
		default:
			return 0
		}
	}

	// Walk through the attach directory to find files matching the md5
	err := filepath.Walk(attachDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip directories we can't access
			if os.IsPermission(err) {
				return filepath.SkipDir
			}
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Check if file name contains the md5
		baseName := strings.ToLower(filepath.Base(path))
		if !strings.Contains(baseName, strings.ToLower(md5)) {
			return nil
		}

		// Accept dat/no-ext/common image file for fallback.
		score := scoreOf(baseName)
		if score == 0 {
			return nil
		}

		// Try to read and verify the file
		if _, err := os.Stat(path); err == nil {
			if score > bestScore {
				bestScore = score
				foundPath = path
			}
		}

		return nil
	})

	if err != nil {
		return ""
	}
	if foundPath != "" {
		return foundPath
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

// tryFindFileWithSuffixes tries to find a file with different suffixes
// Priority: .dat (original) -> _h.dat (HD) -> _t.dat (thumbnail)
func (s *Service) tryFindFileWithSuffixes(basePath string) string {
	dataDir := s.conf.GetDataDir()

	// Try different suffixes with priority: original -> HD -> thumbnail
	suffixes := []string{".dat", "_h.dat", "_t.dat"}

	for _, suffix := range suffixes {
		testPath := filepath.Join(dataDir, basePath+suffix)
		if _, err := os.Stat(testPath); err == nil {
			log.Debug().Str("path", testPath).Str("suffix", suffix).Msg("Found file with suffix")
			return testPath
		}
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
			// Check for corresponding .dat file. WeChat can use various suffixes.
			datSuffixes := []string{".dat", "_h.dat", "_t.dat"}
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
