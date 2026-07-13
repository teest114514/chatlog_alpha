//go:build !darwin

package darwin

import (
	"context"
	"fmt"
)

func ExtractImageKeyWithAuthorization(ctx context.Context, pid uint32, dataDir string, status func(string)) (string, error) {
	_ = ctx
	_ = pid
	_ = dataDir
	_ = status
	return "", fmt.Errorf("自动管理员授权仅支持 macOS")
}
