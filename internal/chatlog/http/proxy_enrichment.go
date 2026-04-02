package http

import (
	"strconv"
	"strings"

	"github.com/sjzar/chatlog/internal/model"
)

func (s *Service) enrichMessages(messages []*model.Message) {
	for _, msg := range messages {
		if msg == nil {
			continue
		}

		msg.RefreshProxyFields()
		if msg.Contents == nil {
			continue
		}

		recordInfo, ok := msg.Contents["recordInfo"].(*model.RecordInfo)
		if !ok || recordInfo == nil {
			continue
		}

		assets := s.enrichRecordInfo(recordInfo, "")
		if len(assets) > 0 {
			msg.Contents["assets"] = assets
		}
	}
}

func (s *Service) enrichRecordInfo(recordInfo *model.RecordInfo, prefix string) []model.RecordAsset {
	if recordInfo == nil {
		return nil
	}

	assets := make([]model.RecordAsset, 0, len(recordInfo.DataList.DataItems))
	for i := range recordInfo.DataList.DataItems {
		item := &recordInfo.DataList.DataItems[i]
		index := strconv.Itoa(i)
		if prefix != "" {
			index = prefix + "." + index
		}

		s.enrichRecordDataItem(item)

		if item.DataType == "17" && item.RecordXML != nil {
			nestedAssets := s.enrichRecordInfo(&item.RecordXML.RecordInfo, index)
			if len(nestedAssets) > 0 {
				item.RecordXML.RecordInfo.Assets = nestedAssets
				assets = append(assets, nestedAssets...)
			}
			continue
		}

		assets = append(assets, item.ToAsset(index))
	}

	recordInfo.Assets = assets
	return assets
}

func (s *Service) enrichRecordDataItem(item *model.DataItem) {
	if item == nil {
		return
	}

	switch item.DataType {
	case "2":
		if item.FullMD5 != "" {
			item.SetResolvedProxy("image", item.FullMD5, "fullmd5")
		} else {
			item.SetUnresolvedProxy("image", "missing_fullmd5")
		}
	case "4":
		if item.FullMD5 != "" {
			item.SetResolvedProxy("video", item.FullMD5, "fullmd5")
		} else {
			item.SetUnresolvedProxy("video", "missing_fullmd5")
		}
	case "8":
		if item.FullMD5 != "" {
			item.SetResolvedProxy("file", item.FullMD5, "fullmd5")
			return
		}

		title := strings.TrimSpace(item.DataTitle)
		if title == "" {
			item.SetUnresolvedProxy("file", "missing_fullmd5")
			return
		}

		size := item.DataSizeInt64()
		media, err := s.db.GetMediaByName("file", title, size)
		if err == nil && media != nil && media.Key != "" {
			source := "hardlink_by_name"
			if size > 0 {
				source = "hardlink_by_name_size"
			}
			item.SetResolvedProxy("file", media.Key, source)
			return
		}

		item.SetUnresolvedProxy("file", "missing_fullmd5")
	case "3":
		item.SetUnresolvedProxy("voice", "unsupported_record_voice")
	default:
		item.SetUnresolvedProxy("", "")
	}
}
