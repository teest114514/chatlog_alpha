package darwin

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/sjzar/chatlog/internal/wechat/model"
)

var (
	ErrImageKeyPermission            = errors.New("图片密钥内存扫描权限不足")
	ErrAuthorizationCanceled         = errors.New("用户取消了管理员授权")
	ErrImageKeyAuthorizationCanceled = ErrAuthorizationCanceled
)

const PrivilegedImageKeyHelperCommand = "internal-image-key-helper"

type PrivilegedImageKeyResult struct {
	Key   string `json:"key,omitempty"`
	Error string `json:"error,omitempty"`
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func isAuthorizationCanceled(message string) bool {
	lower := strings.ToLower(message)
	return strings.Contains(lower, "-128") ||
		strings.Contains(lower, "user canceled") ||
		strings.Contains(message, "用户已取消") ||
		strings.Contains(message, "用户取消")
}

// ExtractImageKeyForPID performs only image-key extraction for an explicit
// process and data directory. It never starts the TUI or extracts a data key.
func ExtractImageKeyForPID(ctx context.Context, pid uint32, dataDir string, status func(string)) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if pid == 0 {
		return "", fmt.Errorf("微信进程 PID 无效")
	}
	if strings.TrimSpace(dataDir) == "" {
		return "", fmt.Errorf("微信数据目录为空")
	}

	extractor := NewV4Extractor()
	return extractor.pickImageKeyWithTiming(ctx, &model.Process{
		PID:      pid,
		DataDir:  dataDir,
		Platform: model.PlatformDarwin,
		Version:  4,
	}, status, true)
}
