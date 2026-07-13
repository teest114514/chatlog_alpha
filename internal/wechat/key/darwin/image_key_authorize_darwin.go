//go:build darwin

package darwin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// ExtractImageKeyWithAuthorization asks macOS for administrator authorization
// and runs only the hidden image-key helper. The TUI itself remains unprivileged.
func ExtractImageKeyWithAuthorization(ctx context.Context, pid uint32, dataDir string, status func(string)) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("定位当前 chatlog 可执行文件失败: %w", err)
	}

	appleScript := buildPrivilegedImageKeyAppleScript(executable, pid, dataDir)

	if status != nil {
		status("即将弹出 macOS 管理员授权窗口；授权后仅临时扫描微信内存")
		status("等待系统授权；确认后会自动开始临时扫描（最长约 60 秒）")
	}
	out, err := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", appleScript).CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(out))
		if isAuthorizationCanceled(message) {
			return "", ErrImageKeyAuthorizationCanceled
		}
		if message == "" {
			message = err.Error()
		}
		return "", fmt.Errorf("管理员授权或临时图片密钥扫描失败: %s", message)
	}

	result, err := parsePrivilegedImageKeyResult(out)
	if err != nil {
		return "", err
	}
	if result.Error != "" {
		return "", fmt.Errorf("临时管理员扫描失败: %s", result.Error)
	}
	if strings.TrimSpace(result.Key) == "" {
		return "", fmt.Errorf("临时管理员扫描未返回图片密钥")
	}
	if status != nil {
		status("管理员权限扫描完成；临时权限子进程已退出")
	}
	return result.Key, nil
}

func buildPrivilegedImageKeyAppleScript(executable string, pid uint32, dataDir string) string {
	commandLine := strings.Join([]string{
		shellQuote(executable),
		shellQuote(PrivilegedImageKeyHelperCommand),
		"--pid", strconv.FormatUint(uint64(pid), 10),
		"--data-dir", shellQuote(dataDir),
	}, " ")
	return fmt.Sprintf(
		"do shell script \"%s\" with administrator privileges",
		escapeAppleScriptForOSA(commandLine),
	)
}

func parsePrivilegedImageKeyResult(output []byte) (PrivilegedImageKeyResult, error) {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		var result PrivilegedImageKeyResult
		if json.Unmarshal([]byte(strings.TrimSpace(lines[i])), &result) == nil && (result.Key != "" || result.Error != "") {
			return result, nil
		}
	}
	return PrivilegedImageKeyResult{}, fmt.Errorf("无法解析临时管理员扫描结果")
}
