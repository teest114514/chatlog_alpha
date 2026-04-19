package wcdb

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/model"
	"github.com/sjzar/chatlog/internal/wechatdb/wcdbapi"
	"github.com/sjzar/chatlog/pkg/util"
)

type DataSource struct {
	dataDir string
	client  *wcdbapi.Client
}

func New(dataDir, dataKey string) (*DataSource, error) {
	c, err := wcdbapi.NewClient(dataDir, dataKey)
	if err != nil {
		return nil, err
	}
	if err := c.OpenAccount(filepath.Join(c.DataDir(), "session", "session.db"), dataKey); err != nil {
		return nil, err
	}
	return &DataSource{
		dataDir: c.DataDir(),
		client:  c,
	}, nil
}

func toInt64(v interface{}) int64 {
	switch t := v.(type) {
	case int:
		return int64(t)
	case int64:
		return t
	case float64:
		return int64(t)
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
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

func toBytes(v interface{}) []byte {
	switch t := v.(type) {
	case []byte:
		return t
	case string:
		return []byte(t)
	default:
		return nil
	}
}

func (ds *DataSource) SetCallback(group string, callback func(event fsnotify.Event) error) error {
	_ = group
	_ = callback
	return nil
}

func (ds *DataSource) GetMessages(ctx context.Context, startTime, endTime time.Time, talker, sender, keyword string, limit, offset int) ([]*model.Message, error) {
	if talker == "" {
		return nil, errors.ErrTalkerEmpty
	}

	var regex *regexp.Regexp
	var err error
	if keyword != "" {
		regex, err = regexp.Compile(keyword)
		if err != nil {
			return nil, errors.QueryFailed("invalid regex pattern", err)
		}
	}
	senders := util.Str2List(sender, ",")
	talkers := util.Str2List(talker, ",")
	if len(talkers) == 0 {
		return nil, errors.ErrTalkerEmpty
	}

	since := int64(0)
	until := int64(0)
	if !startTime.IsZero() {
		since = startTime.Unix()
	}
	if !endTime.IsZero() {
		until = endTime.Unix()
	}

	perTalkerLimit := 0
	if limit > 0 {
		perTalkerLimit = (limit + offset) * 5
	}
	if perTalkerLimit < 1000 {
		perTalkerLimit = 1000
	}
	if perTalkerLimit > 50000 {
		perTalkerLimit = 50000
	}

	out := make([]*model.Message, 0, perTalkerLimit*len(talkers))
	dedup := make(map[string]struct{}, perTalkerLimit*len(talkers))

	for _, tk := range talkers {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		rows, err := ds.client.GetMessagesInRange(tk, since, until, perTalkerLimit, 0)
		if err != nil {
			continue
		}

		for _, row := range rows {
			msgV4 := model.MessageV4{
				LocalID:        toInt64(row["local_id"]),
				SortSeq:        toInt64(row["sort_seq"]),
				ServerID:       toInt64(row["server_id"]),
				LocalType:      toInt64(row["local_type"]),
				UserName:       toString(row["user_name"]),
				CreateTime:     toInt64(row["create_time"]),
				MessageContent: toBytes(row["message_content"]),
				PackedInfoData: toBytes(row["packed_info_data"]),
				Status:         int(toInt64(row["status"])),
			}
			msg := msgV4.Wrap(tk)
			if msg == nil {
				continue
			}
			if !startTime.IsZero() && msg.Time.Before(startTime) {
				continue
			}
			if !endTime.IsZero() && msg.Time.After(endTime) {
				continue
			}
			if len(senders) > 0 {
				match := false
				for _, s := range senders {
					if msg.Sender == s {
						match = true
						break
					}
				}
				if !match {
					continue
				}
			}
			if regex != nil && !regex.MatchString(msg.PlainTextContent()) {
				continue
			}
			dedupKey := fmt.Sprintf("%s:%d", msg.Talker, msg.Seq)
			if _, ok := dedup[dedupKey]; ok {
				continue
			}
			dedup[dedupKey] = struct{}{}
			out = append(out, msg)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Seq < out[j].Seq
	})
	if limit > 0 {
		if offset >= len(out) {
			return []*model.Message{}, nil
		}
		end := offset + limit
		if end > len(out) {
			end = len(out)
		}
		return out[offset:end], nil
	}
	if offset > 0 && offset < len(out) {
		return out[offset:], nil
	}
	return out, nil
}

func (ds *DataSource) GetMessage(ctx context.Context, talker string, seq int64) (*model.Message, error) {
	msgs, err := ds.GetMessages(ctx, time.Unix(0, 0), time.Now().Add(time.Hour), talker, "", "", 2000, 0)
	if err != nil {
		return nil, err
	}
	for _, m := range msgs {
		if m.Seq == seq {
			return m, nil
		}
	}
	return nil, errors.ErrMessageNotFound
}

func (ds *DataSource) GetContacts(ctx context.Context, key string, limit, offset int) ([]*model.Contact, error) {
	_ = ctx
	rows, err := ds.client.Query("contact", "", `SELECT username, local_type, alias, remark, nick_name FROM contact ORDER BY username`)
	if err != nil {
		return nil, err
	}
	items := make([]*model.Contact, 0, len(rows))
	for _, row := range rows {
		c := (&model.ContactV4{
			UserName:  toString(row["username"]),
			LocalType: int(toInt64(row["local_type"])),
			Alias:     toString(row["alias"]),
			Remark:    toString(row["remark"]),
			NickName:  toString(row["nick_name"]),
		}).Wrap()
		if key != "" && !(c.UserName == key || c.Alias == key || c.Remark == key || c.NickName == key) {
			continue
		}
		items = append(items, c)
	}
	if offset > len(items) {
		return []*model.Contact{}, nil
	}
	if offset > 0 {
		items = items[offset:]
	}
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (ds *DataSource) GetChatRooms(ctx context.Context, key string, limit, offset int) ([]*model.ChatRoom, error) {
	_ = ctx
	rows, err := ds.client.Query("contact", "", `SELECT username, owner, ext_buffer FROM chat_room ORDER BY username`)
	if err != nil {
		return nil, err
	}
	items := make([]*model.ChatRoom, 0, len(rows))
	for _, row := range rows {
		chat := (&model.ChatRoomV4{
			UserName:  toString(row["username"]),
			Owner:     toString(row["owner"]),
			ExtBuffer: toBytes(row["ext_buffer"]),
		}).Wrap()
		if key != "" && chat.Name != key {
			continue
		}
		items = append(items, chat)
	}
	if offset > len(items) {
		return []*model.ChatRoom{}, nil
	}
	if offset > 0 {
		items = items[offset:]
	}
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (ds *DataSource) GetSessions(ctx context.Context, key string, limit, offset int) ([]*model.Session, error) {
	_ = ctx
	rows, err := ds.client.GetSessions()
	if err != nil {
		return nil, err
	}
	items := make([]*model.Session, 0, len(rows))
	for _, row := range rows {
		s := (&model.SessionV4{
			Username:              toString(row["username"]),
			Summary:               toString(row["summary"]),
			LastTimestamp:         int(toInt64(row["last_timestamp"])),
			LastMsgSender:         toString(row["last_msg_sender"]),
			LastSenderDisplayName: toString(row["last_sender_display_name"]),
			LastMsgType:           int(toInt64(row["last_msg_type"])),
			LastMsgSubType:        int(toInt64(row["last_msg_sub_type"])),
		}).Wrap()
		if key != "" && !strings.Contains(s.UserName, key) && !strings.Contains(s.NickName, key) && !strings.Contains(s.Content, key) {
			continue
		}
		items = append(items, s)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].NOrder > items[j].NOrder
	})
	if offset > len(items) {
		return []*model.Session{}, nil
	}
	if offset > 0 {
		items = items[offset:]
	}
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (ds *DataSource) GetMedia(ctx context.Context, _type, key string) (*model.Media, error) {
	_ = ctx
	if _type == "voice" {
		sql := `SELECT voice_data FROM VoiceInfo WHERE svr_id = ` + strconv.Quote(key) + ` LIMIT 1`
		rows, err := ds.client.Query("voice", "", sql)
		if err != nil || len(rows) == 0 {
			return nil, errors.ErrMediaNotFound
		}
		data := toBytes(rows[0]["voice_data"])
		if len(data) == 0 {
			return nil, errors.ErrMediaNotFound
		}
		return &model.Media{Type: "voice", Key: key, Data: data}, nil
	}

	table := "image_hardlink_info_v4"
	switch _type {
	case "image":
		table = "image_hardlink_info_v4"
	case "video":
		table = "video_hardlink_info_v4"
	case "file":
		table = "file_hardlink_info_v4"
	default:
		return nil, errors.MediaTypeUnsupported(_type)
	}
	sql := fmt.Sprintf(`
SELECT
	f.md5,
	f.file_name,
	f.file_size,
	f.modify_time,
	f.extra_buffer,
	IFNULL(d1.username,"") AS dir1,
	IFNULL(d2.username,"") AS dir2
FROM %s f
LEFT JOIN dir2id d1 ON d1.rowid = f.dir1
LEFT JOIN dir2id d2 ON d2.rowid = f.dir2
WHERE f.md5 = %s OR f.file_name LIKE %s || '%%'
`, table, strconv.Quote(key), strconv.Quote(key))
	rows, err := ds.client.Query("media", "", sql)
	if err != nil || len(rows) == 0 {
		return nil, errors.ErrMediaNotFound
	}
	best := rows[0]
	if _type == "image" {
		for _, r := range rows {
			if strings.HasSuffix(toString(r["file_name"]), "_h.dat") {
				best = r
				break
			}
		}
	}
	mv4 := model.MediaV4{
		Type:        _type,
		Key:         toString(best["md5"]),
		Name:        toString(best["file_name"]),
		Size:        toInt64(best["file_size"]),
		ModifyTime:  toInt64(best["modify_time"]),
		ExtraBuffer: toString(best["extra_buffer"]),
		Dir1:        toString(best["dir1"]),
		Dir2:        toString(best["dir2"]),
	}
	return mv4.Wrap(), nil
}

func (ds *DataSource) GetSNSTimeline(ctx context.Context, username string, limit, offset int) ([]map[string]interface{}, error) {
	_ = ctx
	sql := `SELECT tid, user_name, content, pack_info_buf FROM SnsTimeLine`
	if username != "" {
		sql += ` WHERE user_name = ` + strconv.Quote(username)
	}
	sql += ` ORDER BY tid DESC`
	if limit > 0 {
		sql += fmt.Sprintf(" LIMIT %d", limit)
		if offset > 0 {
			sql += fmt.Sprintf(" OFFSET %d", offset)
		}
	}
	return ds.client.Query("sns", "", sql)
}

func (ds *DataSource) GetSNSCount(ctx context.Context, username string) (int, error) {
	_ = ctx
	sql := `SELECT COUNT(*) AS cnt FROM SnsTimeLine`
	if username != "" {
		sql += ` WHERE user_name = ` + strconv.Quote(username)
	}
	rows, err := ds.client.Query("sns", "", sql)
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	return int(toInt64(rows[0]["cnt"])), nil
}

func (ds *DataSource) GetDBs() (map[string][]string, error) {
	result := make(map[string][]string)
	seen := map[string]map[string]struct{}{}
	add := func(group, file string) {
		group = strings.TrimSpace(strings.ToLower(group))
		file = strings.TrimSpace(file)
		if group == "" || file == "" {
			return
		}
		if _, ok := seen[group]; !ok {
			seen[group] = map[string]struct{}{}
		}
		if _, ok := seen[group][file]; ok {
			return
		}
		seen[group][file] = struct{}{}
		result[group] = append(result[group], file)
	}

	// 1) 按 all_keys.json 全量展示（仅存在于磁盘的数据库）
	for _, file := range ds.client.ListAllKeyDBs() {
		rel, err := filepath.Rel(ds.dataDir, file)
		if err != nil || strings.HasPrefix(rel, "..") {
			add("misc", file)
			continue
		}
		rel = strings.ReplaceAll(filepath.ToSlash(rel), "\\", "/")
		parts := strings.Split(rel, "/")
		group := "misc"
		if len(parts) > 1 && parts[0] != "" {
			group = parts[0]
		}
		add(group, file)
	}

	// 2) 兜底补充（兼容无 all_keys 或明文可查场景）
	msg, _ := ds.client.ListMessageDBs()
	for _, f := range msg {
		add("message", f)
	}
	media, _ := ds.client.ListMediaDBs()
	for _, f := range media {
		add("media", f)
	}

	session := filepath.Join(ds.dataDir, "session", "session.db")
	if ds.client.CanQueryDB(session) {
		add("session", session)
	}

	contact := filepath.Join(ds.dataDir, "contact", "contact.db")
	if ds.client.CanQueryDB(contact) {
		add("contact", contact)
	}

	sns := filepath.Join(ds.dataDir, "sns", "sns.db")
	if ds.client.CanQueryDB(sns) {
		add("sns", sns)
	}

	for g := range result {
		sort.Strings(result[g])
	}
	return result, nil
}

func normalizeGroupKind(group string) string {
	switch strings.ToLower(group) {
	case "chatroom":
		return "contact"
	default:
		return strings.ToLower(group)
	}
}

func (ds *DataSource) GetTables(group, file string) ([]string, error) {
	group = normalizeGroupKind(group)
	rows, err := ds.client.Query(group, file, `SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	tables := make([]string, 0, len(rows))
	for _, row := range rows {
		if name := toString(row["name"]); name != "" {
			tables = append(tables, name)
		}
	}
	return tables, nil
}

func (ds *DataSource) GetTableData(group, file, table string, limit, offset int, keyword string) ([]map[string]interface{}, error) {
	group = normalizeGroupKind(group)
	escapedTable := strings.ReplaceAll(table, `"`, `""`)
	sql := fmt.Sprintf(`SELECT * FROM "%s"`, escapedTable)

	// 与原控制台兼容：keyword 不为空时，对该表所有列做 LIKE 过滤。
	if strings.TrimSpace(keyword) != "" {
		infoSQL := fmt.Sprintf(`PRAGMA table_info("%s")`, escapedTable)
		cols, err := ds.client.Query(group, file, infoSQL)
		if err == nil && len(cols) > 0 {
			conds := make([]string, 0, len(cols))
			kw := strings.ReplaceAll(keyword, `'`, `''`)
			for _, col := range cols {
				name := toString(col["name"])
				if name == "" {
					continue
				}
				escapedCol := strings.ReplaceAll(name, `"`, `""`)
				conds = append(conds, fmt.Sprintf(`CAST("%s" AS TEXT) LIKE '%%%s%%'`, escapedCol, kw))
			}
			if len(conds) > 0 {
				sql += " WHERE " + strings.Join(conds, " OR ")
			}
		}
	}

	// 与原控制台兼容：limit < 0 表示导出全量。
	switch {
	case limit < 0:
		// no limit
	case limit == 0:
		limit = 200
		sql += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	default:
		sql += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	}
	return ds.client.Query(group, file, sql)
}

func (ds *DataSource) ExecuteSQL(group, file, query string) ([]map[string]interface{}, error) {
	group = normalizeGroupKind(group)
	return ds.client.Query(group, file, query)
}

func (ds *DataSource) Close() error {
	return nil
}
