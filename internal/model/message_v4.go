package model

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/sjzar/chatlog/internal/model/wxproto"
	"github.com/sjzar/chatlog/pkg/util/zstd"
	"google.golang.org/protobuf/proto"
)

// atMsgXML 解析 compress_content 里的 <msg><atuserlist><item>wxid</item>... 老格式。
// WeChat v3 / 少数 v4 路径会落这里。
type atMsgXML struct {
	XMLName xml.Name `xml:"msg"`
	AtItems []string `xml:"atuserlist>item"`
}

// msgSourceXML 解析 source 列的 <msgsource><atuserlist>wxid1,wxid2</atuserlist>...
// 这是 WeChat 4.x 真正存 @ wxid 列表的位置。source 可能是 zstd 压缩或者纯文本 XML。
// 注意 atuserlist 这里是逗号分隔的字符串，**不是** <item> 子节点 —— 跟 atMsgXML 不同。
type msgSourceXML struct {
	XMLName    xml.Name `xml:"msgsource"`
	AtUserList string   `xml:"atuserlist"`
}

// CREATE TABLE Msg_md5(talker)(
// local_id INTEGER PRIMARY KEY AUTOINCREMENT,
// server_id INTEGER,
// local_type INTEGER,
// sort_seq INTEGER,
// real_sender_id INTEGER,
// create_time INTEGER,
// status INTEGER,
// upload_status INTEGER,
// download_status INTEGER,
// server_seq INTEGER,
// origin_source INTEGER,
// source TEXT,
// message_content TEXT,
// compress_content TEXT,
// packed_info_data BLOB,
// WCDB_CT_message_content INTEGER DEFAULT NULL,
// WCDB_CT_source INTEGER DEFAULT NULL
// )
type MessageV4 struct {
	LocalID         int64  `json:"local_id"`         // 本地唯一 ID
	SortSeq         int64  `json:"sort_seq"`         // 消息序号，10位时间戳 + 3位序号
	ServerID        int64  `json:"server_id"`        // 消息 ID，用于关联 voice
	LocalType       int64  `json:"local_type"`       // 消息类型
	UserName        string `json:"user_name"`        // 发送人，通过 Join Name2Id 表获得
	CreateTime      int64  `json:"create_time"`      // 消息创建时间，10位时间戳
	MessageContent  []byte `json:"message_content"`  // 消息内容，文字聊天内容 或 zstd 压缩内容
	PackedInfoData  []byte `json:"packed_info_data"` // 额外数据，类似 proto，格式与 v3 有差异
	CompressContent string `json:"-"`                // 兼容旧格式 XML，用于解析 at_user_list（v3 路径）
	Source          []byte `json:"-"`                // Msg_*.source 列：<msgsource> XML（zstd 压缩或纯文本），v4 真正存 @ 列表的位置
	Status          int    `json:"status"`           // 消息状态，2 是已发送，4 是已接收，可以用于判断 IsSender（FIXME 不准, 需要判断 UserName）
}

func (m *MessageV4) Wrap(talker string) *Message {

	uniqueID := (m.CreateTime * 1000000) + m.LocalID
	_m := &Message{
		Seq:        uniqueID,
		ID:         uniqueID,
		Time:       time.Unix(m.CreateTime, 0),
		Talker:     talker,
		IsChatRoom: strings.HasSuffix(talker, "@chatroom"),
		Sender:     m.UserName,
		Type:       m.LocalType,
		Contents:   make(map[string]interface{}),
		Version:    WeChatV4,
	}

	// FIXME 后续通过 UserName 判断是否是自己发送的消息，目前可能不准确
	_m.IsSelf = m.Status == 2 || (!_m.IsChatRoom && talker != m.UserName)

	content := ""
	if bytes.HasPrefix(m.MessageContent, []byte{0x28, 0xb5, 0x2f, 0xfd}) {
		if b, err := zstd.Decompress(m.MessageContent); err == nil {
			content = string(b)
		}
	} else {
		content = string(m.MessageContent)
	}

	if _m.IsChatRoom {
		split := strings.SplitN(content, ":\n", 2)
		if len(split) == 2 {
			_m.Sender = split[0]
			content = split[1]
		}
	}

	_m.ParseMediaInfo(content)

	// 语音消息
	if _m.Type == 34 {
		_m.Contents["voice"] = fmt.Sprint(m.ServerID)
		_m.Contents["voice_local_id"] = fmt.Sprint(m.LocalID)
	}

	if len(m.PackedInfoData) != 0 {
		if packedInfo := ParsePackedInfo(m.PackedInfoData); packedInfo != nil {
			// FIXME 尝试解决 v4 版本 xml 数据无法匹配到 hardlink 记录的问题
			if _m.Type == 3 && packedInfo.Image != nil {
				_talkerMd5Bytes := md5.Sum([]byte(talker))
				talkerMd5 := hex.EncodeToString(_talkerMd5Bytes[:])
				_m.Contents["path"] = filepath.Join("msg", "attach", talkerMd5, _m.Time.Format("2006-01"), "Img", packedInfo.Image.Md5)
			}
			if _m.Type == 43 && packedInfo.Video != nil {
				_m.Contents["path"] = filepath.Join("msg", "video", _m.Time.Format("2006-01"), packedInfo.Video.Md5)
			}
		}
	}

	_m.RefreshProxyFields()

	// 解析 at_user_list —— 两个来源都试：
	//   1. compress_content 老格式 <msg><atuserlist><item>wxid</item></atuserlist></msg>
	//      （v3 路径，v4 极少数情况）
	//   2. source 列 <msgsource><atuserlist>wxid1,wxid2</atuserlist></msgsource>
	//      （v4 真正存的位置；可能 zstd 压缩 OR 纯文本）
	if _m.Type == 1 {
		if m.CompressContent != "" {
			var atXML atMsgXML
			if err := xml.Unmarshal([]byte(m.CompressContent), &atXML); err == nil && len(atXML.AtItems) > 0 {
				_m.AtUserList = atXML.AtItems
			}
		}
		if len(_m.AtUserList) == 0 && len(m.Source) > 0 {
			_m.AtUserList = parseAtUserListFromSource(m.Source)
		}
	}

	return _m
}

// parseAtUserListFromSource 从 Msg_*.source 列解析 @ wxid 列表。
// source 在 WeChat 4.x 上要么是纯文本 <msgsource> XML，要么是 zstd 压缩后的同样 XML
// （zstd magic 0x28 0xB5 0x2F 0xFD）。解析失败 / 没有 atuserlist 节点都返回 nil。
func parseAtUserListFromSource(src []byte) []string {
	if len(src) == 0 {
		return nil
	}
	xmlBytes := src
	// zstd 头：28 B5 2F FD，先解压
	if len(src) >= 4 && src[0] == 0x28 && src[1] == 0xB5 && src[2] == 0x2F && src[3] == 0xFD {
		decoded, err := zstd.Decompress(src)
		if err != nil {
			return nil
		}
		xmlBytes = decoded
	}
	// 防御：source 可能根本不是 XML（旧版微信、某些 system 消息）—— 出错就放过
	var ms msgSourceXML
	if err := xml.Unmarshal(xmlBytes, &ms); err != nil {
		return nil
	}
	if strings.TrimSpace(ms.AtUserList) == "" {
		return nil
	}
	parts := strings.Split(ms.AtUserList, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func ParsePackedInfo(b []byte) *wxproto.PackedInfo {
	var pbMsg wxproto.PackedInfo
	if err := proto.Unmarshal(b, &pbMsg); err != nil {
		return nil
	}
	return &pbMsg
}
