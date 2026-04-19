package key

import (
	"context"

	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	"github.com/sjzar/chatlog/internal/wechat/key/darwin"
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

// NewExtractor 创建适合当前平台的密钥提取器（内置实现，不依赖外部 DLL）。
func NewExtractor(platform string, version int) (Extractor, error) {
	switch {
	case platform == "darwin" && version == 4:
		return darwin.NewV4Extractor(), nil
	default:
		return nil, errors.PlatformUnsupported(platform, version)
	}
}
