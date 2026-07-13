//go:build !windows

package windows

import (
	"context"
	"fmt"

	"github.com/sjzar/chatlog/internal/wechat/model"
)

func (e *V4Extractor) Extract(ctx context.Context, proc *model.Process) (string, string, error) {
	_ = e
	_ = ctx
	_ = proc
	return "", "", fmt.Errorf("Windows 密钥提取器仅支持 Windows")
}
