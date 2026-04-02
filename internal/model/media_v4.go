package model

import (
	"path/filepath"
	"regexp"
	"strings"
)

type MediaV4 struct {
	Type         string `json:"type"`
	Key          string `json:"key"`
	Dir1         string `json:"dir1"`
	Dir2         string `json:"dir2"`
	ExtraBuffer  string `json:"extraBuffer"` // Extra buffer for Rec subdirectory
	Name         string `json:"name"`
	Size         int64  `json:"size"`
	ModifyTime   int64  `json:"modifyTime"`
	HardLinkType int    `json:"-"`
}

func (m *MediaV4) Wrap() *Media {

	var path string
	switch m.Type {
	case "image":
		extraParts := m.extraBufferParts()
		if len(extraParts) > 0 {
			path = filepath.Join("msg", "attach", m.Dir1, m.Dir2, "Rec", extraParts[0], "Img", m.Name)
		} else {
			path = filepath.Join("msg", "attach", m.Dir1, m.Dir2, "Img", m.Name)
		}
	case "video":
		extraParts := m.extraBufferParts()
		if m.HardLinkType == 5 && len(extraParts) > 0 {
			path = filepath.Join("msg", "attach", m.Dir1, m.Dir2, "Rec", extraParts[0], "V", m.Name)
		} else {
			path = filepath.Join("msg", "video", m.Dir1, m.Name)
		}
	case "file":
		extraParts := m.extraBufferParts()
		if m.HardLinkType == 6 && len(extraParts) > 0 {
			dirName := "F"
			if filepath.Ext(m.Name) == "" {
				dirName = "Dat"
			}
			if len(extraParts) > 1 {
				path = filepath.Join("msg", "attach", m.Dir1, m.Dir2, "Rec", extraParts[0], dirName, extraParts[1], m.Name)
			} else {
				path = filepath.Join("msg", "attach", m.Dir1, m.Dir2, "Rec", extraParts[0], dirName, m.Name)
			}
		} else {
			path = filepath.Join("msg", "file", m.Dir1, m.Name)
		}
	}

	return &Media{
		Type:       m.Type,
		Key:        m.Key,
		Path:       path,
		Name:       m.Name,
		Size:       m.Size,
		ModifyTime: m.ModifyTime,
	}
}

// extraBufferParts extracts ASCII-like segments from extra_buffer.
// v4 hardlink rows store record subdirectories and, for some files, nested indexes here.
func (m *MediaV4) extraBufferParts() []string {
	if m.ExtraBuffer == "" {
		return nil
	}

	re := regexp.MustCompile(`[a-zA-Z0-9]+`)
	matches := re.FindAllString(m.ExtraBuffer, -1)
	if len(matches) == 0 {
		return nil
	}

	parts := make([]string, 0, len(matches))
	for _, part := range matches {
		if strings.TrimSpace(part) != "" {
			parts = append(parts, part)
		}
	}
	return parts
}
