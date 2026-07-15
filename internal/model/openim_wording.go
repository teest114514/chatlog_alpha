package model

// WeChat 本地 contact.db 里有一张 openim_wording 表，存企业微信 (@openim) 用户所属的
// 企业名字。表结构：
//
//   CREATE TABLE openim_wording(
//     lang_id     INTEGER,
//     app_id      TEXT,
//     wording_id  TEXT,         -- 形如 "XXXXXXXXXXXXXXXX....@im.wxwork"，即 corp_id
//     wording     TEXT,         -- 企业名，如 "示例企业"
//     pinyin      TEXT,         -- 简拼 e.g. "SLQY"
//     quan_pin    TEXT,         -- 全拼 e.g. "shiliqiye"
//     update_time INTEGER,
//     ext_buffer  BLOB
//   );
//
// 每个 @openim 联系人 contact.extra_buffer 的 protobuf JSON 里有一段 desc 形如
// "XXXXXXXXXXXXXXXX....@im.wxwork"，对照 openim_wording.wording_id 取 wording 即得到
// 企业名。Repository 维护一份 wording_id -> wording 的 cache，initContactCache 时把
// corp_id 抽出来塞进 Contact.CorpID/CorpName。
type OpenimWording struct {
	LangID    int    `json:"lang_id"`
	AppID     string `json:"app_id"`
	WordingID string `json:"wording_id"` // corp_id（与 contact extra_buffer 里 @im.wxwork 字符串对应）
	Wording   string `json:"wording"`    // 企业名
	Pinyin    string `json:"pinyin"`
	QuanPin   string `json:"quan_pin"`
}
