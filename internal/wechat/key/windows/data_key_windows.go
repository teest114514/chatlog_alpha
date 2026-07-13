package windows

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	"github.com/sjzar/chatlog/internal/wechat/decrypt/common"
	keyshared "github.com/sjzar/chatlog/internal/wechat/key/shared"
	"github.com/sjzar/chatlog/internal/wechat/model"
)

type keyFileEntry = keyshared.KeyFileEntry
type dbSaltEntry = keyshared.DBSaltEntry

func (e *V4Extractor) Extract(ctx context.Context, proc *model.Process) (string, string, error) {
	statusCB, _ := ctx.Value("status_callback").(func(string))
	imageOnly, _ := ctx.Value("image_key_only").(bool)
	dataOnly, _ := ctx.Value("data_key_only").(bool)
	forceRescan, _ := ctx.Value("force_rescan_memory").(bool)
	if proc == nil || proc.PID == 0 {
		return "", "", fmt.Errorf("windows 微信进程未就绪")
	}

	if proc.DataDir == "" {
		return "", "", fmt.Errorf("windows 数据目录未就绪，请确保微信已登录")
	}

	if !forceRescan {
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
			imgKey, err := e.pickImageKeyWithTiming(ctx, proc, statusCB, imageOnly)
			if err != nil {
				return "", "", err
			}
			return strings.ToLower(key), imgKey, nil
		}
	} else {
		if statusCB != nil {
			statusCB("已启用强制重扫：跳过旧 all_keys.json，重新扫描进程内存...")
		}
		_ = removeAllKeysFile(proc.DataDir)
	}

	if statusCB != nil {
		statusCB("开始 init 风格扫描：收集 DB salt -> 内存扫描 -> 写入 all_keys.json")
	}
	key, _, err := InitAllKeysByPID(proc.PID, proc.DataDir, statusCB)
	if err != nil {
		return "", "", err
	}
	if forceRescan && statusCB != nil {
		statusCB("本轮已完成内存重扫，all_keys.json 已更新，正在选取可用密钥...")
	}
	if dataOnly {
		return strings.ToLower(key), "", nil
	}
	imgKey, err := e.pickImageKeyWithTiming(ctx, proc, statusCB, imageOnly)
	if err != nil {
		return "", "", err
	}
	return strings.ToLower(key), imgKey, nil
}

func InitAllKeysByPID(pid uint32, dataDir string, status func(string)) (string, int, error) {
	if pid == 0 {
		return "", 0, fmt.Errorf("invalid pid")
	}
	if dataDir == "" {
		return "", 0, fmt.Errorf("invalid dataDir")
	}

	accountDir, dbStorageDir := resolveDBDirs(dataDir)
	dbSalts, err := collectDBSalts(dbStorageDir)
	if err != nil {
		return "", 0, err
	}
	if len(dbSalts) == 0 {
		return "", 0, fmt.Errorf("未找到可用加密数据库（db_storage）")
	}
	if status != nil {
		status(fmt.Sprintf("已收集加密数据库 salt：%d 个", len(dbSalts)))
	}

	pairs, err := scanKeySaltPairsByPID(pid)
	if err != nil {
		return "", 0, err
	}
	if len(pairs) == 0 {
		return "", 0, fmt.Errorf("内存扫描未发现候选 key/salt")
	}
	if status != nil {
		status(fmt.Sprintf("内存扫描完成：候选 key/salt %d 组", len(pairs)))
	}

	out := map[string]keyFileEntry{}
	for _, pair := range pairs {
		for _, ds := range dbSalts {
			if pair.SaltHex != ds.SaltHex {
				continue
			}
			if _, exists := out[ds.DBRel]; !exists {
				out[ds.DBRel] = keyFileEntry{EncKey: strings.ToLower(pair.KeyHex)}
			}
		}
	}
	if len(out) == 0 {
		return "", 0, fmt.Errorf("扫描到候选 key，但未匹配到任意数据库 salt")
	}

	keysPath := filepath.Join(accountDir, "all_keys.json")
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", 0, fmt.Errorf("序列化 all_keys.json 失败: %w", err)
	}
	if err := os.WriteFile(keysPath, raw, 0600); err != nil {
		return "", 0, fmt.Errorf("写入 %s 失败: %w", keysPath, err)
	}
	if status != nil {
		status(fmt.Sprintf("已写入 all_keys.json：%s（%d 条）", keysPath, len(out)))
	}

	key, err := loadAndValidateMessageKey(accountDir, status)
	if err != nil {
		return "", len(out), err
	}
	return key, len(out), nil
}

func removeAllKeysFile(dataDir string) error {
	accountDir, _ := resolveDBDirs(dataDir)
	paths := []string{filepath.Join(accountDir, "all_keys.json"), filepath.Join(dataDir, "all_keys.json")}
	var lastErr error
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			lastErr = err
		}
	}
	return lastErr
}

func loadAndValidateMessageKey(dataDir string, status func(string)) (string, error) {
	keys, err := keyshared.LoadAllKeys(dataDir, "请先获取数据库密钥", nil, status)
	if err != nil {
		return "", err
	}
	if status != nil {
		status(fmt.Sprintf("检查 all_keys.json（共 %d 条）...", len(keys)))
	}
	if key, ok := keyshared.PickPreferredMessageKey(dataDir, keys, validateKeyOnDBPath, status); ok {
		if status != nil {
			status("已从 all_keys.json 选中可用密钥")
		}
		return key, nil
	}
	return "", fmt.Errorf("all_keys.json 中没有有效 enc_key")
}

func validateKeyOnDBPath(dataDir, dbRelativePath, keyHex string) bool {
	keyHex = strings.TrimSpace(strings.ToLower(keyHex))
	if len(keyHex) != 64 {
		return false
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return false
	}
	database, err := common.OpenDBFile(keyshared.ResolveDBPath(dataDir, dbRelativePath), 4096)
	if err != nil {
		return false
	}
	decryptor, err := decrypt.NewDecryptor(model.PlatformWindows, 4)
	return err == nil && decryptor.Validate(database.FirstPage, key)
}

func resolveDBDirs(dataDir string) (accountDir, storageDir string) {
	return keyshared.ResolveDBDirs(dataDir)
}

func collectDBSalts(storageDir string) ([]dbSaltEntry, error) {
	return keyshared.CollectDBSalts(storageDir)
}
