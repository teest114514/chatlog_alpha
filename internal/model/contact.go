package model

type Contact struct {
	UserName    string `json:"userName"`
	Alias       string `json:"alias"`
	Remark      string `json:"remark"`
	NickName    string `json:"nickName"`
	Description string `json:"description"`
	IsFriend    bool   `json:"isFriend"`

	// Enterprise WeChat (企业微信，@openim 后缀) 联系人专属。普通 wxid 这两个字段一直空。
	// CorpID 来自 contact.extra_buffer 的 protobuf JSON 里的 "...@im.wxwork" 字段，
	// 对应 openim_wording.wording_id；CorpName 是 openim_wording.wording。
	CorpID   string `json:"corpId,omitempty"`
	CorpName string `json:"corpName,omitempty"`
}

// CREATE TABLE Contact(
// UserName TEXT PRIMARY KEY ,
// Alias TEXT,
// EncryptUserName TEXT,
// DelFlag INTEGER DEFAULT 0,
// Type INTEGER DEFAULT 0,
// VerifyFlag INTEGER DEFAULT 0,
// Reserved1 INTEGER DEFAULT 0,
// Reserved2 INTEGER DEFAULT 0,
// Reserved3 TEXT,
// Reserved4 TEXT,
// Remark TEXT,
// NickName TEXT,
// LabelIDList TEXT,
// DomainList TEXT,
// ChatRoomType int,
// PYInitial TEXT,
// QuanPin TEXT,
// RemarkPYInitial TEXT,
// RemarkQuanPin TEXT,
// BigHeadImgUrl TEXT,
// SmallHeadImgUrl TEXT,
// HeadImgMd5 TEXT,
// ChatRoomNotify INTEGER DEFAULT 0,
// Reserved5 INTEGER DEFAULT 0,
// Reserved6 TEXT,
// Reserved7 TEXT,
// ExtraBuf BLOB,
// Reserved8 INTEGER DEFAULT 0,
// Reserved9 INTEGER DEFAULT 0,
// Reserved10 TEXT,
// Reserved11 TEXT
// )
type ContactV3 struct {
	UserName  string `json:"UserName"`
	Alias     string `json:"Alias"`
	Remark    string `json:"Remark"`
	NickName  string `json:"NickName"`
	Reserved1 int    `json:"Reserved1"` // 1 自己好友或自己加入的群聊; 0 群聊成员(非好友)
}

func (c *ContactV3) Wrap() *Contact {
	return &Contact{
		UserName: c.UserName,
		Alias:    c.Alias,
		Remark:   c.Remark,
		NickName: c.NickName,
		IsFriend: c.Reserved1 == 1,
	}
}

func (c *Contact) DisplayName() string {
	switch {
	case c.Remark != "":
		return c.Remark
	case c.NickName != "":
		return c.NickName
	}
	return ""
}
