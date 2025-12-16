package key

import (
	"context"
	"fmt"

	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	"github.com/sjzar/chatlog/internal/wechat/key/windows"
	"github.com/sjzar/chatlog/internal/wechat/model"
)

// Extractor 定义密钥提取器接口
type Extractor interface {
	// Extract 从进程中提取密钥
	// dataKey, imgKey, error
	Extract(ctx context.Context, proc *model.Process) (string, string, error)

	// SearchKey 在内存中搜索密钥
	SearchKey(ctx context.Context, memory []byte) (string, bool)

	SetValidate(validator *decrypt.Validator)
}

// NewExtractor 创建适合当前平台的密钥提取器
// 对于Windows平台，优先使用DLL方式（如果DLL存在）
func NewExtractor(platform string, version int) (Extractor, error) {
	switch {
	case platform == "windows" && version == 4:
		// 尝试使用DLL方式
		if extractor, err := NewDLLExtractor(platform, version); err == nil {
			return extractor, nil
		}
		// 如果DLL方式失败，回退到原来的方式
		return windows.NewV4Extractor(), nil
	default:
		return nil, errors.PlatformUnsupported(platform, version)
	}
}

// NewDLLExtractor 创建使用DLL的密钥提取器（仅支持Windows）
func NewDLLExtractor(platform string, version int) (Extractor, error) {
	if platform != "windows" {
		return nil, errors.PlatformUnsupported(platform, version)
	}

	// 检查DLL是否可用
	if !windows.IsDLLAvailable() {
		return nil, fmt.Errorf("wx_key.dll 不可用")
	}

	switch version {
	case 3, 4:
		// V3和V4都使用相同的DLL提取器
		return windows.NewDLLV4Extractor(), nil
	default:
		return nil, errors.PlatformUnsupported(platform, version)
	}
}
