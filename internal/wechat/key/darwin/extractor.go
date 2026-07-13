package darwin

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	keyshared "github.com/sjzar/chatlog/internal/wechat/key/shared"
	"github.com/sjzar/chatlog/internal/wechat/model"
)

type V4Extractor struct{}

func NewV4Extractor() *V4Extractor {
	return &V4Extractor{}
}

// Extract obtains the database key via Frida (CCKeyDerivationPBKDF) only.
// Memory scanning for data keys has been removed (broken on WeChat 4.1.8+).
//
// Context keys:
//   - status_callback: func(string)
//   - force_rescan_memory / force_key_refresh: skip all_keys.json cache and re-run Frida
//   - image_key_only: only image key path (skips data-key Frida when cache has data key)
//   - data_key_only: never attempt image-key derivation or task_for_pid memory scanning
func (e *V4Extractor) Extract(ctx context.Context, proc *model.Process) (string, string, error) {
	statusCB, _ := ctx.Value("status_callback").(func(string))
	imageOnly, _ := ctx.Value("image_key_only").(bool)
	dataOnly, _ := ctx.Value("data_key_only").(bool)
	forceRescan, _ := ctx.Value("force_rescan_memory").(bool)
	forceRefresh, _ := ctx.Value("force_key_refresh").(bool)
	forceRescan = forceRescan || forceRefresh

	if proc == nil {
		return "", "", fmt.Errorf("进程信息为空")
	}

	// Image-only: do not re-extract data key via Frida unless missing from cache.
	if imageOnly {
		if proc.DataDir == "" {
			return "", "", fmt.Errorf("macOS 数据目录未就绪，请确保微信已登录")
		}
		dataKey := ""
		if key, err := loadAndValidateMessageKey(proc.DataDir, statusCB); err == nil {
			dataKey = key
		}
		imgKey, err := e.pickImageKeyWithTiming(ctx, proc, statusCB, true)
		if err != nil {
			return dataKey, "", err
		}
		return strings.ToLower(dataKey), imgKey, nil
	}

	// 1) Cache: all_keys.json (already extracted earlier)
	if !forceRescan && proc.DataDir != "" {
		if statusCB != nil {
			statusCB("检查 all_keys.json...")
		}
		if key, err := loadAndValidateMessageKey(proc.DataDir, statusCB); err == nil && key != "" {
			if statusCB != nil {
				statusCB("已从 all_keys.json 获取密钥")
			}
			if dataOnly {
				return strings.ToLower(key), "", nil
			}
			imgKey, err := e.pickImageKeyWithTiming(ctx, proc, statusCB, false)
			if err != nil {
				return strings.ToLower(key), "", nil
			}
			return strings.ToLower(key), imgKey, nil
		}
	} else if forceRescan && proc.DataDir != "" {
		if statusCB != nil {
			statusCB("强制刷新：将通过 Frida 重新提取并逐库校验数据库密钥...")
		}
	}

	// 2) Only extraction backend: Frida Hook CCKeyDerivationPBKDF
	if !FridaAvailable() {
		return "", "", fmt.Errorf(
			"提取数据库密钥需要 Frida：请先执行 pip3 install frida-tools\n" +
				"然后运行: chatlog key --frida\n" +
				"或在 TUI 选择「重启并获取数据库密钥」",
		)
	}
	if statusCB != nil {
		statusCB("使用 Frida Hook CCKeyDerivationPBKDF 提取数据库密钥（将重启微信，请登录）...")
	}
	dataDir := ""
	if proc != nil {
		dataDir = proc.DataDir
	}
	key, candidates, err := ExtractKeysViaFrida(ctx, dataDir, statusCB)
	if err != nil {
		return "", "", fmt.Errorf("Frida 提取密钥失败: %w", err)
	}
	key = strings.ToLower(key)

	// If dataDir became available later, Apply is already attempted inside ExtractKeyViaFrida.
	// Re-apply when we now know dataDir.
	if dataDir != "" {
		if _, _, applyErr := ApplyCapturedKeysToDataDir(dataDir, candidates, statusCB); applyErr != nil {
			log.Debug().Err(applyErr).Msg("apply frida key after extract")
		}
	}
	if dataOnly {
		return key, "", nil
	}

	imgKey, imgErr := e.pickImageKeyWithTiming(ctx, proc, statusCB, false)
	if imgErr != nil {
		log.Debug().Err(imgErr).Msg("image key optional after frida data key")
		return key, "", nil
	}
	return key, imgKey, nil
}

func removeAllKeysFile(dataDir string) error {
	accountDir, _ := resolveDBDirs(dataDir)
	paths := []string{
		filepath.Join(accountDir, "all_keys.json"),
		filepath.Join(dataDir, "all_keys.json"),
	}
	var lastErr error
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			lastErr = err
		}
	}
	return lastErr
}

func (e *V4Extractor) SearchKey(ctx context.Context, memory []byte) (string, bool) {
	_ = ctx
	_ = memory
	// Data-key memory patterns removed (WeChat 4.1.8+).
	return "", false
}

func (e *V4Extractor) SetValidate(validator *decrypt.Validator) {
	_ = e
	_ = validator // Data-key memory pattern scanning is intentionally disabled.
}

func loadAllKeys(dataDir string, status func(string)) (map[string]string, error) {
	return keyshared.LoadAllKeys(dataDir, "请先用 chatlog key --frida 提取", repairAllKeysPermission, status)
}

func repairAllKeysPermission(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("empty all_keys path")
	}
	if os.Geteuid() == 0 {
		_ = normalizeAllKeysOwnership(path)
		return nil
	}

	uid := os.Getuid()
	gid := os.Getgid()
	quotedPath := shellQuote(path)
	cmdLine := fmt.Sprintf("chown %d:%d %s && chmod 600 %s", uid, gid, quotedPath, quotedPath)
	script := fmt.Sprintf("do shell script \"%s\" with administrator privileges", escapeAppleScriptForOSA(cmdLine))
	if out, err := exec.Command("/usr/bin/osascript", "-e", script).CombinedOutput(); err != nil {
		if isAuthorizationCanceled(string(out) + " " + err.Error()) {
			return ErrAuthorizationCanceled
		}
		return fmt.Errorf("修复 all_keys.json 权限失败: %v, output: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func escapeAppleScriptForOSA(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}
