package model

// CREATE TABLE contact(
// id INTEGER PRIMARY KEY,
// username TEXT,
// local_type INTEGER,
// alias TEXT,
// encrypt_username TEXT,
// flag INTEGER,
// delete_flag INTEGER,
// verify_flag INTEGER,
// remark TEXT,
// remark_quan_pin TEXT,
// remark_pin_yin_initial TEXT,
// nick_name TEXT,
// pin_yin_initial TEXT,
// quan_pin TEXT,
// big_head_url TEXT,
// small_head_url TEXT,
// head_img_md5 TEXT,
// chat_room_notify INTEGER,
// is_in_chat_room INTEGER,
// description TEXT,
// extra_buffer BLOB,
// chat_room_type INTEGER
// )
type ContactV4 struct {
	UserName    string `json:"username"`
	Alias       string `json:"alias"`
	Remark      string `json:"remark"`
	NickName    string `json:"nick_name"`
	Description string `json:"description"`
	LocalType   int    `json:"local_type"` // 2 群聊; 3 群聊成员(非好友); 5,6 企业微信;
	ExtraBuffer []byte `json:"-"`          // 企业微信 corp_id 藏在这里，用 ExtractOpenimCorpID 提取
}

func (c *ContactV4) Wrap() *Contact {
	out := &Contact{
		UserName:    c.UserName,
		Alias:       c.Alias,
		Remark:      c.Remark,
		NickName:    c.NickName,
		Description: c.Description,
		IsFriend:    c.LocalType != 3,
	}
	// 仅对企业微信 (@openim) 联系人解析 corp_id —— extra_buffer 普通好友也有但内容
	// 是别的（位置、地区等），白白调用 regex 浪费 CPU。
	if isOpenim(c.UserName) {
		out.CorpID = ExtractOpenimCorpID(c.ExtraBuffer)
	}
	return out
}

func isOpenim(username string) bool {
	const suffix = "@openim"
	return len(username) > len(suffix) && username[len(username)-len(suffix):] == suffix
}
