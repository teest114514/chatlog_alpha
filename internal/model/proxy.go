package model

import (
	"net/url"
	"strconv"
	"strings"
)

type RecordAsset struct {
	Index          string `json:"index"`
	DataType       string `json:"dataType,omitempty"`
	DataFmt        string `json:"dataFmt,omitempty"`
	MessageType    int64  `json:"messageType"`
	MessageSubType int64  `json:"messageSubType"`
	Title          string `json:"title,omitempty"`
	Content        string `json:"content,omitempty"`
	SourceName     string `json:"sourceName,omitempty"`
	SourceTime     string `json:"sourceTime,omitempty"`
	Size           int64  `json:"size,omitempty"`
	ProxyType      string `json:"proxyType,omitempty"`
	ProxyKey       string `json:"proxyKey,omitempty"`
	ProxyURL       string `json:"proxyUrl,omitempty"`
	Resolved       bool   `json:"resolved"`
	KeySource      string `json:"keySource,omitempty"`
}

func BuildProxyURL(proxyType, key string) string {
	if proxyType == "" || key == "" {
		return ""
	}
	return "/" + proxyType + "/" + url.PathEscape(key)
}

func (m *Message) RefreshProxyFields() {
	if m.Contents == nil {
		return
	}

	var proxyType string
	var proxyKey string
	var keySource string

	switch m.Type {
	case MessageTypeImage:
		proxyType = "image"
		if md5, _ := m.Contents["md5"].(string); md5 != "" {
			proxyKey = md5
			keySource = "contents.md5"
		} else if path, _ := m.Contents["path"].(string); path != "" {
			proxyKey = path
			keySource = "contents.path"
		}
	case MessageTypeVoice:
		proxyType = "voice"
		if voice, _ := m.Contents["voice"].(string); voice != "" {
			proxyKey = voice
			keySource = "contents.voice"
		}
	case MessageTypeVideo:
		proxyType = "video"
		if md5, _ := m.Contents["md5"].(string); md5 != "" {
			proxyKey = md5
			keySource = "contents.md5"
		} else if path, _ := m.Contents["path"].(string); path != "" {
			proxyKey = path
			keySource = "contents.path"
		}
	case MessageTypeShare:
		if m.SubType == MessageSubTypeFile {
			proxyType = "file"
			if md5, _ := m.Contents["md5"].(string); md5 != "" {
				proxyKey = md5
				keySource = "contents.md5"
			}
		}
	}

	if proxyType == "" {
		return
	}

	m.Contents["proxyType"] = proxyType
	m.Contents["proxyKey"] = proxyKey
	m.Contents["proxyUrl"] = BuildProxyURL(proxyType, proxyKey)
	m.Contents["resolved"] = proxyKey != ""
	m.Contents["keySource"] = keySource
}

func (d *DataItem) DataSizeInt64() int64 {
	if strings.TrimSpace(d.DataSize) == "" {
		return 0
	}
	value, err := strconv.ParseInt(strings.TrimSpace(d.DataSize), 10, 64)
	if err != nil {
		return 0
	}
	return value
}

func (d *DataItem) SourceTimeValue() string {
	if d.SourceTime != "" {
		return d.SourceTime
	}
	return d.SrcMsgCreateTime
}

func (d *DataItem) DefaultMessageType() (int64, int64) {
	switch d.DataType {
	case "1":
		return MessageTypeText, 0
	case "2":
		return MessageTypeImage, 0
	case "3":
		return MessageTypeVoice, 0
	case "4":
		return MessageTypeVideo, 0
	case "8":
		return MessageTypeShare, MessageSubTypeFile
	case "17":
		return MessageTypeShare, MessageSubTypeMergeForward
	default:
		return 0, 0
	}
}

func (d *DataItem) SetResolvedProxy(proxyType, key, keySource string) {
	d.ProxyType = proxyType
	d.ProxyKey = key
	d.ProxyURL = BuildProxyURL(proxyType, key)
	d.Resolved = key != ""
	d.KeySource = keySource
	if proxyType != "voice" {
		d.MD5 = key
	}
}

func (d *DataItem) SetUnresolvedProxy(proxyType, keySource string) {
	d.ProxyType = proxyType
	d.ProxyKey = ""
	d.ProxyURL = ""
	d.Resolved = false
	d.KeySource = keySource
	d.MD5 = ""
}

func (d *DataItem) ContentText() string {
	switch d.DataType {
	case "1":
		return d.DataDesc
	case "8":
		if d.DataTitle != "" {
			return "发送了文件：" + d.DataTitle
		}
		return "[文件]"
	case "2":
		return "[图片]"
	case "3":
		return "[语音]"
	case "4":
		return "[视频]"
	}
	if d.DataDesc != "" {
		return d.DataDesc
	}
	if d.DataTitle != "" {
		return d.DataTitle
	}
	return ""
}

func (d *DataItem) ToAsset(index string) RecordAsset {
	messageType, messageSubType := d.DefaultMessageType()
	return RecordAsset{
		Index:          index,
		DataType:       d.DataType,
		DataFmt:        d.DataFmt,
		MessageType:    messageType,
		MessageSubType: messageSubType,
		Title:          d.DataTitle,
		Content:        d.ContentText(),
		SourceName:     d.SourceName,
		SourceTime:     d.SourceTimeValue(),
		Size:           d.DataSizeInt64(),
		ProxyType:      d.ProxyType,
		ProxyKey:       d.ProxyKey,
		ProxyURL:       d.ProxyURL,
		Resolved:       d.Resolved,
		KeySource:      d.KeySource,
	}
}
