package v4

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
	"github.com/klauspost/compress/zstd"

	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/model"
	"github.com/sjzar/chatlog/internal/wechatdb/datasource/dbm"
	"github.com/sjzar/chatlog/pkg/util"
)

const (
	Message = "message"
	Contact = "contact"
	Session = "session"
	Media   = "media"
	Voice   = "voice"
	SNS     = "sns"
)

var Groups = []*dbm.Group{
	{
		Name:      Message,
		Pattern:   `^message_([0-9]?[0-9])?\.db(-wal|-shm)?$`,
		BlackList: []string{},
	},
	{
		Name:      Contact,
		Pattern:   `^contact\.db(-wal|-shm)?$`,
		BlackList: []string{},
	},
	{
		Name:      Session,
		Pattern:   `^session\.db(-wal|-shm)?$`,
		BlackList: []string{},
	},
	{
		Name:      Media,
		Pattern:   `^hardlink\.db(-wal|-shm)?$`,
		BlackList: []string{},
	},
	{
		Name:      Voice,
		Pattern:   `^media_([0-9]?[0-9])?\.db(-wal|-shm)?$`,
		BlackList: []string{},
	},
	{
		Name:      SNS,
		Pattern:   `^sns\.db(-wal|-shm)?$`,
		BlackList: []string{},
	},
}

// MessageDBInfo 存储消息数据库的信息
type MessageDBInfo struct {
	FilePath  string
	StartTime time.Time
	EndTime   time.Time
}

type DataSource struct {
	path string
	dbm  *dbm.DBManager

	// 消息数据库信息
	messageInfos []MessageDBInfo
}

func New(path string, walEnabled bool) (*DataSource, error) {

	ds := &DataSource{
		path:         path,
		dbm:          dbm.NewDBManager(path, walEnabled),
		messageInfos: make([]MessageDBInfo, 0),
	}

	for _, g := range Groups {
		ds.dbm.AddGroup(g)
	}

	if err := ds.dbm.Start(); err != nil {
		return nil, err
	}

	if err := ds.initMessageDbs(); err != nil {
		return nil, errors.DBInitFailed(err)
	}

	ds.dbm.AddCallback(Message, func(event fsnotify.Event) error {
		if !event.Op.Has(fsnotify.Create) {
			return nil
		}
		if err := ds.initMessageDbs(); err != nil {
			log.Err(err).Msgf("Failed to reinitialize message DBs: %s", event.Name)
		}
		return nil
	})

	return ds, nil
}

func (ds *DataSource) SetCallback(group string, callback func(event fsnotify.Event) error) error {
	if group == "chatroom" {
		group = Contact
	}
	return ds.dbm.AddCallback(group, callback)
}

func (ds *DataSource) initMessageDbs() error {
	dbPaths, err := ds.dbm.GetDBPath(Message)
	if err != nil {
		if strings.Contains(err.Error(), "db file not found") {
			ds.messageInfos = make([]MessageDBInfo, 0)
			return nil
		}
		return err
	}

	// 处理每个数据库文件
	infos := make([]MessageDBInfo, 0)
	for _, filePath := range dbPaths {
		db, err := ds.dbm.OpenDB(filePath)
		if err != nil {
			log.Err(err).Msgf("获取数据库 %s 失败", filePath)
			continue
		}

		// 获取 Timestamp 表中的开始时间
		var startTime time.Time
		var timestamp int64

		row := db.QueryRow("SELECT timestamp FROM Timestamp LIMIT 1")
		if err := row.Scan(&timestamp); err != nil {
			log.Err(err).Msgf("获取数据库 %s 的时间戳失败", filePath)
			continue
		}
		startTime = time.Unix(timestamp, 0)

		// 保存数据库信息
		infos = append(infos, MessageDBInfo{
			FilePath:  filePath,
			StartTime: startTime,
		})
	}

	// 按照 StartTime 排序数据库文件
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].StartTime.Before(infos[j].StartTime)
	})

	// 设置结束时间
	for i := range infos {
		if i == len(infos)-1 {
			infos[i].EndTime = time.Now().Add(time.Hour)
		} else {
			infos[i].EndTime = infos[i+1].StartTime
		}
	}
	if len(ds.messageInfos) > 0 && len(infos) < len(ds.messageInfos) {
		log.Warn().Msgf("message db count decreased from %d to %d, skip init", len(ds.messageInfos), len(infos))
		return nil
	}
	ds.messageInfos = infos
	return nil
}

// getDBInfosForTimeRange 获取时间范围内的数据库信息
func (ds *DataSource) getDBInfosForTimeRange(startTime, endTime time.Time) []MessageDBInfo {
	now := time.Now()
	var dbs []MessageDBInfo
	for i, info := range ds.messageInfos {
		dbEndTime := info.EndTime
		// 最后一个数据库仍在接收新消息，动态使用当前时间 + 1小时作为 EndTime
		// 避免 initMessageDbs 设置的静态 EndTime 过期导致查询失败
		if i == len(ds.messageInfos)-1 {
			dbEndTime = now.Add(time.Hour)
		}
		if info.StartTime.Before(endTime) && dbEndTime.After(startTime) {
			dbs = append(dbs, info)
		}
	}
	return dbs
}

func (ds *DataSource) GetMessages(ctx context.Context, startTime, endTime time.Time, talker string, sender string, keyword string, limit, offset int) ([]*model.Message, error) {
	if talker == "" {
		return nil, errors.ErrTalkerEmpty
	}

	// 解析talker参数，支持多个talker（以英文逗号分隔）
	talkers := util.Str2List(talker, ",")
	if len(talkers) == 0 {
		return nil, errors.ErrTalkerEmpty
	}

	// 找到时间范围内的数据库文件
	dbInfos := ds.getDBInfosForTimeRange(startTime, endTime)
	if len(dbInfos) == 0 {
		return nil, errors.TimeRangeNotFound(startTime, endTime)
	}

	// 解析sender参数，支持多个发送者（以英文逗号分隔）
	senders := util.Str2List(sender, ",")

	// 预编译正则表达式（如果有keyword）
	var regex *regexp.Regexp
	if keyword != "" {
		var err error
		regex, err = regexp.Compile(keyword)
		if err != nil {
			return nil, errors.QueryFailed("invalid regex pattern", err)
		}
	}

	// 从每个相关数据库中查询消息，并在读取时进行过滤
	filteredMessages := []*model.Message{}

	for _, dbInfo := range dbInfos {
		// 检查上下文是否已取消
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		db, err := ds.dbm.OpenDB(dbInfo.FilePath)
		if err != nil {
			log.Error().Msgf("数据库 %s 未打开", dbInfo.FilePath)
			continue
		}

		// 对每个talker进行查询
		for _, talkerItem := range talkers {
			// 构建表名
			_talkerMd5Bytes := md5.Sum([]byte(talkerItem))
			talkerMd5 := hex.EncodeToString(_talkerMd5Bytes[:])
			tableName := "Msg_" + talkerMd5

			// 检查表是否存在
			var exists bool
			err = db.QueryRowContext(ctx,
				"SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
				tableName).Scan(&exists)

			if err != nil {
				if err == sql.ErrNoRows {
					// 表不存在，继续下一个talker
					continue
				}
				return nil, errors.QueryFailed("", err)
			}

			// 构建查询条件
			conditions := []string{"create_time >= ? AND create_time <= ?"}
			args := []interface{}{startTime.Unix(), endTime.Unix()}
			log.Debug().Msgf("Table name: %s", tableName)
			log.Debug().Msgf("Start time: %d, End time: %d", startTime.Unix(), endTime.Unix())

			query := fmt.Sprintf(`
				SELECT m.local_id, m.sort_seq, m.server_id, m.local_type, n.user_name, m.create_time, m.message_content, m.packed_info_data, m.status
				FROM %s m
				LEFT JOIN Name2Id n ON m.real_sender_id = n.rowid
				WHERE %s 
				ORDER BY m.sort_seq ASC
			`, tableName, strings.Join(conditions, " AND "))

			// 执行查询
			rows, err := db.QueryContext(ctx, query, args...)
			if err != nil {
				// 如果表不存在，SQLite 会返回错误
				if strings.Contains(err.Error(), "no such table") {
					continue
				}
				log.Err(err).Msgf("从数据库 %s 查询消息失败", dbInfo.FilePath)
				continue
			}

			// 处理查询结果，在读取时进行过滤
			for rows.Next() {
				var msg model.MessageV4
				err := rows.Scan(
					&msg.LocalID,
					&msg.SortSeq,
					&msg.ServerID,
					&msg.LocalType,
					&msg.UserName,
					&msg.CreateTime,
					&msg.MessageContent,
					&msg.PackedInfoData,
					&msg.Status,
				)
				if err != nil {
					rows.Close()
					return nil, errors.ScanRowFailed(err)
				}

				// 将消息转换为标准格式
				message := msg.Wrap(talkerItem)

				// 应用sender过滤
				if len(senders) > 0 {
					senderMatch := false
					for _, s := range senders {
						if message.Sender == s {
							senderMatch = true
							break
						}
					}
					if !senderMatch {
						continue // 不匹配sender，跳过此消息
					}
				}

				// 应用keyword过滤
				if regex != nil {
					plainText := message.PlainTextContent()
					if !regex.MatchString(plainText) {
						continue // 不匹配keyword，跳过此消息
					}
				}

				// 通过所有过滤条件，保留此消息
				filteredMessages = append(filteredMessages, message)

				// 检查是否已经满足分页处理数量
				if limit > 0 && len(filteredMessages) >= offset+limit {
					// 已经获取了足够的消息，可以提前返回
					rows.Close()

					// 对所有消息按时间排序
					sort.Slice(filteredMessages, func(i, j int) bool {
						return filteredMessages[i].Seq < filteredMessages[j].Seq
					})

					// 处理分页
					if offset >= len(filteredMessages) {
						return []*model.Message{}, nil
					}
					end := offset + limit
					if end > len(filteredMessages) {
						end = len(filteredMessages)
					}
					return filteredMessages[offset:end], nil
				}
			}
			rows.Close()
		}
	}

	// 对所有消息按时间排序
	sort.Slice(filteredMessages, func(i, j int) bool {
		return filteredMessages[i].Seq < filteredMessages[j].Seq
	})

	// 处理分页
	if limit > 0 {
		if offset >= len(filteredMessages) {
			return []*model.Message{}, nil
		}
		end := offset + limit
		if end > len(filteredMessages) {
			end = len(filteredMessages)
		}
		return filteredMessages[offset:end], nil
	}

	return filteredMessages, nil
}

func (ds *DataSource) GetMessage(ctx context.Context, talker string, seq int64) (*model.Message, error) {
	if talker == "" {
		return nil, errors.ErrTalkerEmpty
	}

	// Seq = (create_time * 1000000) + local_id
	createTime := seq / 1000000
	localID := seq % 1000000
	t := time.Unix(createTime, 0)

	dbInfos := ds.getDBInfosForTimeRange(t, t.Add(time.Second))
	if len(dbInfos) == 0 {
		return nil, errors.TimeRangeNotFound(t, t.Add(time.Second))
	}

	_talkerMd5Bytes := md5.Sum([]byte(talker))
	talkerMd5 := hex.EncodeToString(_talkerMd5Bytes[:])
	tableName := "Msg_" + talkerMd5

	for _, dbInfo := range dbInfos {
		db, err := ds.dbm.OpenDB(dbInfo.FilePath)
		if err != nil {
			continue
		}

		query := fmt.Sprintf(`
			SELECT m.local_id, m.sort_seq, m.server_id, m.local_type, n.user_name, m.create_time, m.message_content, m.packed_info_data, m.status
			FROM %s m
			LEFT JOIN Name2Id n ON m.real_sender_id = n.rowid
			WHERE m.local_id = ?
		`, tableName)

		var msg model.MessageV4
		err = db.QueryRowContext(ctx, query, localID).Scan(
			&msg.LocalID,
			&msg.SortSeq,
			&msg.ServerID,
			&msg.LocalType,
			&msg.UserName,
			&msg.CreateTime,
			&msg.MessageContent,
			&msg.PackedInfoData,
			&msg.Status,
		)
		if err != nil {
			if err == sql.ErrNoRows {
				continue
			}
			return nil, errors.QueryFailed("", err)
		}

		return msg.Wrap(talker), nil
	}

	return nil, errors.ErrMessageNotFound
}

// 联系人
func (ds *DataSource) GetContacts(ctx context.Context, key string, limit, offset int) ([]*model.Contact, error) {
	var query string
	var args []interface{}

	if key != "" {
		// 按照关键字查询
		query = `SELECT username, local_type, alias, remark, nick_name 
				FROM contact 
				WHERE username = ? OR alias = ? OR remark = ? OR nick_name = ?`
		args = []interface{}{key, key, key, key}
	} else {
		// 查询所有联系人
		query = `SELECT username, local_type, alias, remark, nick_name FROM contact`
	}

	// 添加排序、分页
	query += ` ORDER BY username`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	}

	// 执行查询
	db, err := ds.dbm.GetDB(Contact)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.QueryFailed(query, err)
	}
	defer rows.Close()

	contacts := []*model.Contact{}
	for rows.Next() {
		var contactV4 model.ContactV4
		err := rows.Scan(
			&contactV4.UserName,
			&contactV4.LocalType,
			&contactV4.Alias,
			&contactV4.Remark,
			&contactV4.NickName,
		)

		if err != nil {
			return nil, errors.ScanRowFailed(err)
		}

		contacts = append(contacts, contactV4.Wrap())
	}

	return contacts, nil
}

// 群聊
func (ds *DataSource) GetChatRooms(ctx context.Context, key string, limit, offset int) ([]*model.ChatRoom, error) {
	var query string
	var args []interface{}

	// 执行查询
	db, err := ds.dbm.GetDB(Contact)
	if err != nil {
		return nil, err
	}

	if key != "" {
		// 按照关键字查询
		query = `SELECT username, owner, ext_buffer FROM chat_room WHERE username = ?`
		args = []interface{}{key}

		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, errors.QueryFailed(query, err)
		}
		defer rows.Close()

		chatRooms := []*model.ChatRoom{}
		for rows.Next() {
			var chatRoomV4 model.ChatRoomV4
			err := rows.Scan(
				&chatRoomV4.UserName,
				&chatRoomV4.Owner,
				&chatRoomV4.ExtBuffer,
			)

			if err != nil {
				return nil, errors.ScanRowFailed(err)
			}

			chatRooms = append(chatRooms, chatRoomV4.Wrap())
		}

		// 如果没有找到群聊，尝试通过联系人查找
		if len(chatRooms) == 0 {
			contacts, err := ds.GetContacts(ctx, key, 1, 0)
			if err == nil && len(contacts) > 0 && strings.HasSuffix(contacts[0].UserName, "@chatroom") {
				// 再次尝试通过用户名查找群聊
				rows, err := db.QueryContext(ctx,
					`SELECT username, owner, ext_buffer FROM chat_room WHERE username = ?`,
					contacts[0].UserName)

				if err != nil {
					return nil, errors.QueryFailed(query, err)
				}
				defer rows.Close()

				for rows.Next() {
					var chatRoomV4 model.ChatRoomV4
					err := rows.Scan(
						&chatRoomV4.UserName,
						&chatRoomV4.Owner,
						&chatRoomV4.ExtBuffer,
					)

					if err != nil {
						return nil, errors.ScanRowFailed(err)
					}

					chatRooms = append(chatRooms, chatRoomV4.Wrap())
				}

				// 如果群聊记录不存在，但联系人记录存在，创建一个模拟的群聊对象
				if len(chatRooms) == 0 {
					chatRooms = append(chatRooms, &model.ChatRoom{
						Name:             contacts[0].UserName,
						Users:            make([]model.ChatRoomUser, 0),
						User2DisplayName: make(map[string]string),
					})
				}
			}
		}

		return chatRooms, nil
	} else {
		// 查询所有群聊
		query = `SELECT username, owner, ext_buffer FROM chat_room`

		// 添加排序、分页
		query += ` ORDER BY username`
		if limit > 0 {
			query += fmt.Sprintf(" LIMIT %d", limit)
			if offset > 0 {
				query += fmt.Sprintf(" OFFSET %d", offset)
			}
		}

		// 执行查询
		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, errors.QueryFailed(query, err)
		}
		defer rows.Close()

		chatRooms := []*model.ChatRoom{}
		for rows.Next() {
			var chatRoomV4 model.ChatRoomV4
			err := rows.Scan(
				&chatRoomV4.UserName,
				&chatRoomV4.Owner,
				&chatRoomV4.ExtBuffer,
			)

			if err != nil {
				return nil, errors.ScanRowFailed(err)
			}

			chatRooms = append(chatRooms, chatRoomV4.Wrap())
		}

		return chatRooms, nil
	}
}

// 最近会话
func (ds *DataSource) GetSessions(ctx context.Context, key string, limit, offset int) ([]*model.Session, error) {
	var query string
	var args []interface{}

	if key != "" {
		// 按照关键字查询
		query = `SELECT username, summary, last_timestamp, last_msg_sender, last_sender_display_name, last_msg_type, last_msg_sub_type 
				FROM SessionTable 
				WHERE username = ? OR last_sender_display_name = ?
				ORDER BY sort_timestamp DESC`
		args = []interface{}{key, key}
	} else {
		// 查询所有会话
		query = `SELECT username, summary, last_timestamp, last_msg_sender, last_sender_display_name, last_msg_type, last_msg_sub_type 
				FROM SessionTable 
				ORDER BY sort_timestamp DESC`
	}

	// 添加分页
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	}

	// 执行查询
	db, err := ds.dbm.GetDB(Session)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.QueryFailed(query, err)
	}
	defer rows.Close()

	sessions := []*model.Session{}
	for rows.Next() {
		var sessionV4 model.SessionV4
		err := rows.Scan(
			&sessionV4.Username,
			&sessionV4.Summary,
			&sessionV4.LastTimestamp,
			&sessionV4.LastMsgSender,
			&sessionV4.LastSenderDisplayName,
			&sessionV4.LastMsgType,
			&sessionV4.LastMsgSubType,
		)

		if err != nil {
			return nil, errors.ScanRowFailed(err)
		}

		sessions = append(sessions, sessionV4.Wrap())
	}

	return sessions, nil
}

func (ds *DataSource) GetMedia(ctx context.Context, _type string, key string) (*model.Media, error) {
	if key == "" {
		return nil, errors.ErrKeyEmpty
	}

	var table string
	switch _type {
	case "image":
		table = "image_hardlink_info_v3"
		// 4.1.0 版本开始使用 v4 表
		if !ds.IsExist(Media, table) {
			table = "image_hardlink_info_v4"
		}
	case "video":
		table = "video_hardlink_info_v3"
		if !ds.IsExist(Media, table) {
			table = "video_hardlink_info_v4"
		}
	case "file":
		table = "file_hardlink_info_v3"
		if !ds.IsExist(Media, table) {
			table = "file_hardlink_info_v4"
		}
	case "voice":
		return ds.GetVoice(ctx, key)
	default:
		return nil, errors.MediaTypeUnsupported(_type)
	}

	query := fmt.Sprintf(`
	SELECT
		f.md5,
		f.file_name,
		f.file_size,
		f.modify_time,
		f.extra_buffer,
		IFNULL(d1.username,""),
		IFNULL(d2.username,"")
	FROM
		%s f
	LEFT JOIN
		dir2id d1 ON d1.rowid = f.dir1
	LEFT JOIN
		dir2id d2 ON d2.rowid = f.dir2
	`, table)
	query += " WHERE f.md5 = ? OR f.file_name LIKE ? || '%'"
	args := []interface{}{key, key}

	// 执行查询
	db, err := ds.dbm.GetDB(Media)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.QueryFailed(query, err)
	}
	defer rows.Close()

	var media *model.Media
	for rows.Next() {
		var mediaV4 model.MediaV4
		err := rows.Scan(
			&mediaV4.Key,
			&mediaV4.Name,
			&mediaV4.Size,
			&mediaV4.ModifyTime,
			&mediaV4.ExtraBuffer,
			&mediaV4.Dir1,
			&mediaV4.Dir2,
		)
		if err != nil {
			return nil, errors.ScanRowFailed(err)
		}
		mediaV4.Type = _type
		media = mediaV4.Wrap()

		// 优先返回高清图
		if _type == "image" && strings.HasSuffix(mediaV4.Name, "_h.dat") {
			break
		}
	}

	if media == nil {
		return nil, errors.ErrMediaNotFound
	}

	return media, nil
}

func (ds *DataSource) IsExist(_db string, table string) bool {
	db, err := ds.dbm.GetDB(_db)
	if err != nil {
		return false
	}
	var tableName string
	query := "SELECT name FROM sqlite_master WHERE type='table' AND name=?;"
	if err = db.QueryRow(query, table).Scan(&tableName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false
		}
		return false
	}
	return true
}

func (ds *DataSource) GetVoice(ctx context.Context, key string) (*model.Media, error) {
	if key == "" {
		return nil, errors.ErrKeyEmpty
	}

	query := `
	SELECT voice_data
	FROM VoiceInfo
	WHERE svr_id = ? 
	`
	args := []interface{}{key}

	dbs, err := ds.dbm.GetDBs(Voice)
	if err != nil {
		return nil, errors.DBConnectFailed("", err)
	}

	for _, db := range dbs {
		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, errors.QueryFailed(query, err)
		}
		defer rows.Close()

		for rows.Next() {
			var voiceData []byte
			err := rows.Scan(
				&voiceData,
			)
			if err != nil {
				return nil, errors.ScanRowFailed(err)
			}
			if len(voiceData) > 0 {
				return &model.Media{
					Type: "voice",
					Key:  key,
					Data: voiceData,
				}, nil
			}
		}
	}

	return nil, errors.ErrMediaNotFound
}

func (ds *DataSource) GetDBs() (map[string][]string, error) {
	result := make(map[string][]string)
	for _, group := range Groups {
		paths, err := ds.dbm.GetDBPath(group.Name)
		if err != nil {
			// Ignore groups with no files
			continue
		}
		result[group.Name] = paths
	}
	return result, nil
}

func (ds *DataSource) GetTables(group, file string) ([]string, error) {
	// Verify file belongs to group
	paths, err := ds.dbm.GetDBPath(group)
	if err != nil {
		return nil, err
	}
	found := false
	for _, p := range paths {
		if p == file {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("file %s not found in group %s", file, group)
	}

	db, err := ds.dbm.OpenDB(file)
	if err != nil {
		return nil, err
	}

	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		tables = append(tables, name)
	}
	return tables, nil
}

func (ds *DataSource) GetTableData(group, file, table string, limit, offset int, keyword string) ([]map[string]interface{}, error) {
	// Verify file belongs to group
	paths, err := ds.dbm.GetDBPath(group)
	if err != nil {
		return nil, err
	}
	found := false
	for _, p := range paths {
		if p == file {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("file %s not found in group %s", file, group)
	}

	db, err := ds.dbm.OpenDB(file)
	if err != nil {
		return nil, err
	}

	// 1. Get columns to build search query if keyword provided
	var columns []string
	if keyword != "" {
		rows, err := db.Query(fmt.Sprintf("SELECT * FROM \"%s\" LIMIT 0", table))
		if err != nil {
			return nil, err
		}
		columns, err = rows.Columns()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}

	// 2. Build Query
	query := fmt.Sprintf("SELECT * FROM \"%s\"", table)
	var args []interface{}
	
	if keyword != "" && len(columns) > 0 {
		var conditions []string
		for _, col := range columns {
			conditions = append(conditions, fmt.Sprintf("\"%s\" LIKE ?", col))
			args = append(args, "%"+keyword+"%")
		}
		query += " WHERE " + strings.Join(conditions, " OR ")
	}
	
	query += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Get columns again (in case * returns diff order or something, though standard is consistent)
	resCols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	// 为消息表创建 ZSTD 解码器（如果需要）
	var zstdDecoder *zstd.Decoder
	if group == "message" {
		zstdDecoder, _ = zstd.NewReader(nil)
		defer zstdDecoder.Close()
	}

	result := make([]map[string]interface{}, 0)
	for rows.Next() {
		values := make([]interface{}, len(resCols))
		valuePtrs := make([]interface{}, len(resCols))
		for i := range resCols {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}

		entry := make(map[string]interface{})
		for i, col := range resCols {
			var v interface{}
			val := values[i]
			b, ok := val.([]byte)
			if ok {
				// 特殊处理消息表的 message_content 字段
				if group == "message" && col == "message_content" && len(b) > 0 {
					// 检查是否是 ZSTD 压缩数据 (magic bytes: 0x28, 0xb5, 0x2f, 0xfd)
					if len(b) >= 4 && b[0] == 0x28 && b[1] == 0xb5 && b[2] == 0x2f && b[3] == 0xfd {
						// 尝试解压 ZSTD 数据
						if zstdDecoder != nil {
							decompressed, err := zstdDecoder.DecodeAll(b, nil)
							if err == nil {
								v = string(decompressed)
							} else {
								v = fmt.Sprintf("[Binary data: %d bytes, ZSTD decompress failed: %v]", len(b), err)
							}
						} else {
							v = fmt.Sprintf("[Binary data: %d bytes, ZSTD decoder not available]", len(b))
						}
					} else {
						// 不是 ZSTD 压缩数据，尝试作为普通文本显示
						v = string(b)
					}
				} else {
					// 其他字段，直接转换为字符串
					v = string(b)
				}
			} else {
				v = val
			}
			entry[col] = v
		}
		result = append(result, entry)
	}

	return result, nil
}

func (ds *DataSource) ExecuteSQL(group, file, query string) ([]map[string]interface{}, error) {
	// Verify file belongs to group
	paths, err := ds.dbm.GetDBPath(group)
	if err != nil {
		return nil, err
	}
	found := false
	for _, p := range paths {
		if p == file {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("file %s not found in group %s", file, group)
	}

	db, err := ds.dbm.OpenDB(file)
	if err != nil {
		return nil, err
	}

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	result := make([]map[string]interface{}, 0)
	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range columns {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}

		entry := make(map[string]interface{})
		for i, col := range columns {
			var v interface{}
			val := values[i]
			b, ok := val.([]byte)
			if ok {
				v = string(b)
			} else {
				v = val
			}
			entry[col] = v
		}
		result = append(result, entry)
	}

	return result, nil
}

func (ds *DataSource) Close() error {
	return ds.dbm.Close()
}

// GetSNSTimeline 获取朋友圈时间线数据
func (ds *DataSource) GetSNSTimeline(ctx context.Context, username string, limit, offset int) ([]map[string]interface{}, error) {
	db, err := ds.dbm.GetDB(SNS)
	if err != nil {
		return nil, err
	}

	var query string
	var args []interface{}

	if username != "" {
		query = `SELECT tid, user_name, content, pack_info_buf FROM SnsTimeLine WHERE user_name = ? ORDER BY tid DESC`
		args = []interface{}{username}
	} else {
		query = `SELECT tid, user_name, content, pack_info_buf FROM SnsTimeLine ORDER BY tid DESC`
	}

	// 添加分页
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	}

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.QueryFailed(query, err)
	}
	defer rows.Close()

	result := make([]map[string]interface{}, 0)
	for rows.Next() {
		var tid int64
		var userName string
		var content string
		var packInfoBuf string

		err := rows.Scan(&tid, &userName, &content, &packInfoBuf)
		if err != nil {
			return nil, errors.ScanRowFailed(err)
		}

		// 解析 XML 内容
		parsedPost, err := model.ParseSNSContent(content)
		if err != nil {
			// 如果解析失败，返回原始数据
			result = append(result, map[string]interface{}{
				"tid":          tid,
				"user_name":    userName,
				"content":      content,
				"pack_info_buf": packInfoBuf,
				"parse_error":  err.Error(),
			})
			continue
		}

		// 转换为 map[string]interface{}
		postMap := map[string]interface{}{
			"tid":            tid,
			"user_name":      userName,
			"nickname":       parsedPost.NickName,
			"create_time":    parsedPost.CreateTime,
			"create_time_str": parsedPost.CreateTimeStr,
			"content_desc":   parsedPost.ContentDesc,
			"content_type":   parsedPost.ContentType,
		}

		if parsedPost.Location != nil {
			postMap["location"] = parsedPost.Location
		}

		if len(parsedPost.MediaList) > 0 {
			postMap["media_list"] = parsedPost.MediaList
		}

		if parsedPost.Article != nil {
			postMap["article"] = parsedPost.Article
		}

		if parsedPost.FinderFeed != nil {
			postMap["finder_feed"] = parsedPost.FinderFeed
		}

		result = append(result, postMap)
	}

	return result, nil
}

// GetSNSCount 统计朋友圈数量
func (ds *DataSource) GetSNSCount(ctx context.Context, username string) (int, error) {
	db, err := ds.dbm.GetDB(SNS)
	if err != nil {
		return 0, err
	}

	var query string
	var args []interface{}

	if username != "" {
		query = `SELECT COUNT(*) FROM SnsTimeLine WHERE user_name = ?`
		args = []interface{}{username}
	} else {
		query = `SELECT COUNT(*) FROM SnsTimeLine`
	}

	var count int
	err = db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, errors.QueryFailed(query, err)
	}

	return count, nil
}
