package wcdb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/fsnotify/fsnotify"
	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/model"
	"github.com/sjzar/chatlog/internal/wechatdb/wcdbapi"
	"github.com/sjzar/chatlog/pkg/util"
	"github.com/sjzar/chatlog/pkg/util/zstd"
)

type DataSource struct {
	dataDir string
	client  *wcdbapi.Client

	searchSchemaMu sync.RWMutex
	searchSchema   map[string][]searchTableMeta
}

type searchTableMeta struct {
	Name          string
	Columns       []string
	AllColumns    []searchColumnMeta
	DeepCandidate []searchColumnMeta
}

type searchColumnMeta struct {
	Name string
	Type string
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
		dataDir:      c.DataDir(),
		client:       c,
		searchSchema: make(map[string][]searchTableMeta),
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

func (ds *DataSource) SearchAll(keyword string, limit int, deep bool) ([]map[string]interface{}, error) {
	keyword = strings.TrimSpace(keyword)
	if keyword == "" {
		return nil, fmt.Errorf("keyword is empty")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}

	dbs, err := ds.GetDBs()
	if err != nil {
		return nil, err
	}

	groups := make([]string, 0, len(dbs))
	for group, files := range dbs {
		if len(files) == 0 {
			continue
		}
		groups = append(groups, group)
	}
	sort.Strings(groups)

	results := make([]map[string]interface{}, 0, minInt(limit, 64))
	for _, group := range groups {
		files := append([]string(nil), dbs[group]...)
		sort.Strings(files)
		for _, file := range files {
			tables, err := ds.getSearchSchema(group, file)
			if err != nil {
				continue
			}
			for _, table := range tables {
				remaining := limit - len(results)
				if remaining <= 0 {
					return results, nil
				}
				var hits []map[string]interface{}
				var err error
				if deep {
					hits, err = ds.deepSearchTable(group, file, table, keyword, remaining)
				} else {
					hits, err = ds.searchTable(group, file, table, keyword, minInt(remaining, 5))
				}
				if err != nil {
					continue
				}
				for _, hit := range hits {
					results = append(results, hit)
					if len(results) >= limit {
						return results, nil
					}
				}
			}
		}
	}

	return results, nil
}

func (ds *DataSource) getSearchSchema(group, file string) ([]searchTableMeta, error) {
	group = normalizeGroupKind(group)
	cacheKey := group + "::" + file

	ds.searchSchemaMu.RLock()
	if cached, ok := ds.searchSchema[cacheKey]; ok {
		out := make([]searchTableMeta, len(cached))
		copy(out, cached)
		ds.searchSchemaMu.RUnlock()
		return out, nil
	}
	ds.searchSchemaMu.RUnlock()

	tableNames, err := ds.GetTables(group, file)
	if err != nil {
		return nil, err
	}

	metas := make([]searchTableMeta, 0, len(tableNames))
	for _, tableName := range tableNames {
		if tableName == "" || strings.HasPrefix(strings.ToLower(tableName), "sqlite_") {
			continue
		}
		escapedTable := strings.ReplaceAll(tableName, `"`, `""`)
		infoSQL := fmt.Sprintf(`PRAGMA table_info("%s")`, escapedTable)
		cols, err := ds.client.Query(group, file, infoSQL)
		if err != nil {
			continue
		}
		searchable := make([]string, 0, len(cols))
		allColumns := make([]searchColumnMeta, 0, len(cols))
		deepCandidates := make([]searchColumnMeta, 0, len(cols))
		for _, col := range cols {
			name := toString(col["name"])
			typ := toString(col["type"])
			if name == "" {
				continue
			}
			meta := searchColumnMeta{Name: name, Type: typ}
			allColumns = append(allColumns, meta)
			if isSearchableColumn(name, typ) {
				searchable = append(searchable, name)
			}
			if isDeepSearchCandidate(name, typ) {
				deepCandidates = append(deepCandidates, meta)
			}
		}
		if len(searchable) == 0 && len(deepCandidates) == 0 {
			continue
		}
		metas = append(metas, searchTableMeta{
			Name:          tableName,
			Columns:       searchable,
			AllColumns:    allColumns,
			DeepCandidate: deepCandidates,
		})
	}

	ds.searchSchemaMu.Lock()
	ds.searchSchema[cacheKey] = metas
	ds.searchSchemaMu.Unlock()

	out := make([]searchTableMeta, len(metas))
	copy(out, metas)
	return out, nil
}

func (ds *DataSource) searchTable(group, file string, table searchTableMeta, keyword string, limit int) ([]map[string]interface{}, error) {
	if limit <= 0 {
		return nil, nil
	}

	quotedCols := make([]string, 0, len(table.Columns))
	conds := make([]string, 0, len(table.Columns))
	kw := strings.ReplaceAll(strings.ToLower(keyword), `'`, `''`)

	for _, col := range table.Columns {
		escapedCol := strings.ReplaceAll(col, `"`, `""`)
		quoted := fmt.Sprintf(`"%s"`, escapedCol)
		quotedCols = append(quotedCols, quoted)
		conds = append(conds, fmt.Sprintf(`INSTR(LOWER(CAST(%s AS TEXT)), '%s') > 0`, quoted, kw))
	}
	if len(conds) == 0 {
		return nil, nil
	}

	escapedTable := strings.ReplaceAll(table.Name, `"`, `""`)
	sql := fmt.Sprintf(
		`SELECT rowid AS "__rowid__", %s FROM "%s" WHERE %s LIMIT %d`,
		strings.Join(quotedCols, ", "),
		escapedTable,
		strings.Join(conds, " OR "),
		limit,
	)
	rows, err := ds.client.Query(group, file, sql)
	if err != nil {
		return nil, err
	}
	return ds.rowsToSearchHits(group, file, table.Name, table.Columns, rows, strings.ToLower(keyword)), nil
}

func (ds *DataSource) deepSearchTable(group, file string, table searchTableMeta, keyword string, limit int) ([]map[string]interface{}, error) {
	if limit <= 0 || len(table.DeepCandidate) == 0 {
		return nil, nil
	}

	escapedTable := strings.ReplaceAll(table.Name, `"`, `""`)
	allCols := make([]string, 0, len(table.AllColumns))
	for _, col := range table.AllColumns {
		escapedCol := strings.ReplaceAll(col.Name, `"`, `""`)
		allCols = append(allCols, fmt.Sprintf(`"%s"`, escapedCol))
	}
	if len(allCols) == 0 {
		return nil, nil
	}

	const batchSize = 200
	out := make([]map[string]interface{}, 0, minInt(limit, 16))
	lastRowID := int64(-1)
	needle := strings.ToLower(keyword)

	for len(out) < limit {
		sql := fmt.Sprintf(
			`SELECT rowid AS "__rowid__", %s FROM "%s" WHERE rowid > %d ORDER BY rowid LIMIT %d`,
			strings.Join(allCols, ", "),
			escapedTable,
			lastRowID,
			batchSize,
		)
		rows, err := ds.client.Query(group, file, sql)
		if err != nil {
			return out, err
		}
		if len(rows) == 0 {
			break
		}

		for _, row := range rows {
			rowIDVal := extractRowID(row["__rowid__"])
			if id, ok := rowIDVal.(int64); ok {
				lastRowID = id
			}
			matchedRow := make(map[string]interface{}, 4)
			matchedCols := make([]string, 0, 2)
			for _, col := range table.DeepCandidate {
				raw, ok := row[col.Name]
				if !ok {
					continue
				}
				val := extractDeepSearchText(col, raw)
				if val == "" || !strings.Contains(strings.ToLower(val), needle) {
					continue
				}
				matchedRow[col.Name] = val
				matchedCols = append(matchedCols, col.Name)
			}
			if len(matchedCols) == 0 {
				continue
			}
			sort.Strings(matchedCols)
			for _, colName := range matchedCols {
				out = append(out, map[string]interface{}{
					"group":   group,
					"file":    file,
					"db_name": filepath.Base(file),
					"table":   table.Name,
					"column":  colName,
					"row_id":  rowIDVal,
					"preview": matchedRow[colName],
					"row":     matchedRow,
				})
				if len(out) >= limit {
					return out, nil
				}
			}
		}

		if len(rows) < batchSize {
			break
		}
	}

	return out, nil
}

func (ds *DataSource) rowsToSearchHits(group, file, table string, columns []string, rows []map[string]interface{}, needle string) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(rows))
	for _, row := range rows {
		rowID := extractRowID(row["__rowid__"])
		matchedRow := make(map[string]interface{}, len(columns))
		for _, col := range columns {
			raw, ok := row[col]
			if !ok {
				continue
			}
			val := sanitizeSearchValue(raw)
			if val == "" || !strings.Contains(strings.ToLower(val), needle) {
				continue
			}
			matchedRow[col] = val
		}
		if len(matchedRow) == 0 {
			continue
		}

		cols := make([]string, 0, len(matchedRow))
		for col := range matchedRow {
			cols = append(cols, col)
		}
		sort.Strings(cols)
		for _, col := range cols {
			out = append(out, map[string]interface{}{
				"group":   group,
				"file":    file,
				"db_name": filepath.Base(file),
				"table":   table,
				"column":  col,
				"row_id":  rowID,
				"preview": matchedRow[col],
				"row":     matchedRow,
			})
		}
	}
	return out
}

func isSearchableColumn(name, typ string) bool {
	colName := strings.ToLower(strings.TrimSpace(name))
	colType := strings.ToLower(strings.TrimSpace(typ))
	if colName == "" {
		return false
	}
	if strings.Contains(colType, "blob") || strings.Contains(colType, "binary") {
		return false
	}
	if strings.HasSuffix(colName, "_buffer") || strings.HasSuffix(colName, "_blob") {
		return false
	}
	if strings.Contains(colName, "packed_info") || strings.Contains(colName, "ext_buffer") {
		return false
	}
	if strings.Contains(colName, "message_content") || strings.Contains(colName, "bytes_extra") {
		return false
	}
	return true
}

func isDeepSearchCandidate(name, typ string) bool {
	colName := strings.ToLower(strings.TrimSpace(name))
	colType := strings.ToLower(strings.TrimSpace(typ))
	if colName == "" {
		return false
	}
	if strings.Contains(colName, "voice_data") || strings.Contains(colName, "thumbdata") {
		return false
	}
	if strings.Contains(colName, "image") && strings.Contains(colType, "blob") {
		return false
	}
	if strings.Contains(colName, "data") && strings.Contains(colType, "blob") &&
		!strings.Contains(colName, "message_content") &&
		!strings.Contains(colName, "packed_info") &&
		!strings.Contains(colName, "bytes_extra") {
		return false
	}
	return true
}

func sanitizeSearchValue(v interface{}) string {
	s := strings.TrimSpace(toString(v))
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.ReplaceAll(s, "\n", " ")
	runes := []rune(s)
	if len(runes) > 240 {
		s = string(runes[:240]) + "..."
	}
	return s
}

func extractDeepSearchText(col searchColumnMeta, v interface{}) string {
	name := strings.ToLower(strings.TrimSpace(col.Name))
	switch t := v.(type) {
	case nil:
		return ""
	case []byte:
		return sanitizeSearchValue(extractBytesText(name, t))
	default:
		return sanitizeSearchValue(v)
	}
}

func extractBytesText(colName string, data []byte) string {
	if len(data) == 0 {
		return ""
	}
	if bytes.HasPrefix(data, []byte{0x28, 0xb5, 0x2f, 0xfd}) {
		if b, err := zstd.Decompress(data); err == nil {
			return string(b)
		}
	}
	if strings.Contains(colName, "packed_info") {
		if packed := model.ParsePackedInfo(data); packed != nil {
			if b, err := json.Marshal(packed); err == nil {
				return string(b)
			}
		}
	}
	if utf8.Valid(data) {
		return string(data)
	}
	return ""
}

func extractRowID(v interface{}) interface{} {
	switch t := v.(type) {
	case int64:
		return t
	case int:
		return t
	case float64:
		return int64(t)
	default:
		s := strings.TrimSpace(toString(v))
		if s == "" {
			return nil
		}
		return s
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (ds *DataSource) Close() error {
	return nil
}
