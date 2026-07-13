package shared

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type DBSaltEntry struct {
	SaltHex string
	DBRel   string
}

type KeyFileEntry struct {
	EncKey string `json:"enc_key"`
}

type ValidateDBKey func(dataDir, dbRelativePath, keyHex string) bool

func NormalizeDBPath(path string) string {
	normalized := strings.ToLower(filepath.ToSlash(filepath.Clean(strings.TrimSpace(path))))
	return strings.TrimPrefix(normalized, "./")
}

func ResolveDBDirs(dataDir string) (accountDir, dbStorageDir string) {
	cleaned := filepath.Clean(dataDir)
	if cleaned == "." || cleaned == "" {
		return dataDir, filepath.Join(dataDir, "db_storage")
	}
	if strings.EqualFold(filepath.Base(cleaned), "db_storage") {
		return filepath.Dir(cleaned), cleaned
	}
	return cleaned, filepath.Join(cleaned, "db_storage")
}

func ResolveDBPath(dataDir, relativePath string) string {
	_, storageDir := ResolveDBDirs(dataDir)
	if filepath.IsAbs(relativePath) {
		return relativePath
	}
	normalized := NormalizeDBPath(relativePath)
	if strings.HasPrefix(normalized, "db_storage/") {
		return filepath.Join(filepath.Dir(storageDir), filepath.FromSlash(normalized))
	}
	return filepath.Join(storageDir, filepath.FromSlash(normalized))
}

func CollectDBSalts(storageDir string) ([]DBSaltEntry, error) {
	stat, err := os.Stat(storageDir)
	if err != nil || !stat.IsDir() {
		return nil, fmt.Errorf("数据库目录不存在: %s", storageDir)
	}
	result := make([]DBSaltEntry, 0, 64)
	err = filepath.WalkDir(storageDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry == nil || entry.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".db") {
			return nil
		}
		salt, ok := ReadDBSalt(path)
		if !ok {
			return nil
		}
		relative, err := filepath.Rel(storageDir, path)
		if err == nil {
			result = append(result, DBSaltEntry{SaltHex: salt, DBRel: NormalizeDBPath(relative)})
		}
		return nil
	})
	return result, err
}

func ReadDBSalt(path string) (string, bool) {
	file, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer file.Close()
	buffer := make([]byte, 16)
	if _, err := io.ReadFull(file, buffer); err != nil || string(buffer[:15]) == "SQLite format 3" {
		return "", false
	}
	return strings.ToLower(hex.EncodeToString(buffer)), true
}

func LoadAllKeys(dataDir, missingHint string, repairPermission func(string) error, status func(string)) (map[string]string, error) {
	candidates := []string{filepath.Join(dataDir, "all_keys.json"), "all_keys.json"}
	if strings.EqualFold(filepath.Base(filepath.Clean(dataDir)), "db_storage") {
		candidates = append([]string{filepath.Join(filepath.Dir(filepath.Clean(dataDir)), "all_keys.json")}, candidates...)
	}

	var content []byte
	var used, permissionPath string
	for _, candidate := range candidates {
		value, err := os.ReadFile(candidate)
		if err == nil {
			content, used = value, candidate
			break
		}
		if os.IsPermission(err) {
			permissionPath = candidate
		}
	}
	if used == "" && permissionPath != "" && repairPermission != nil {
		if status != nil {
			status("all_keys.json 权限不足，即将请求管理员授权进行修复")
		}
		if err := repairPermission(permissionPath); err != nil {
			return nil, err
		}
		value, err := os.ReadFile(permissionPath)
		if err == nil {
			content, used = value, permissionPath
			if status != nil {
				status("all_keys.json 权限修复完成，临时管理员授权已结束")
			}
		}
	}
	if used == "" {
		return nil, fmt.Errorf("未找到 all_keys.json（%s）", missingHint)
	}

	var raw map[string]any
	if err := json.Unmarshal(content, &raw); err != nil {
		return nil, fmt.Errorf("解析 %s 失败: %w", used, err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s 为空", used)
	}

	result := make(map[string]string, len(raw))
	for dbPath, value := range raw {
		var key string
		switch typed := value.(type) {
		case string:
			key = typed
		case map[string]any:
			key, _ = typed["enc_key"].(string)
		}
		key = strings.TrimSpace(strings.ToLower(key))
		if len(key) == 64 {
			result[NormalizeDBPath(dbPath)] = key
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("%s 中没有有效 enc_key", used)
	}
	return result, nil
}

func PickPreferredMessageKey(dataDir string, keys map[string]string, validate ValidateDBKey, status func(string)) (string, bool) {
	if len(keys) == 0 {
		return "", false
	}
	for dbPath, key := range keys {
		normalized := NormalizeDBPath(dbPath)
		if (normalized == "message/message_0.db" || strings.HasSuffix(normalized, "/message/message_0.db")) && validate(dataDir, dbPath, key) {
			return strings.ToLower(key), true
		}
	}
	for dbPath, key := range keys {
		normalized := NormalizeDBPath(dbPath)
		isMessageDB := strings.Contains(normalized, "/message/") || strings.HasPrefix(normalized, "message/")
		if isMessageDB && strings.HasSuffix(normalized, ".db") && validate(dataDir, dbPath, key) {
			return strings.ToLower(key), true
		}
	}

	counts := map[string]int{}
	for _, key := range keys {
		key = strings.TrimSpace(strings.ToLower(key))
		if len(key) == 64 {
			counts[key]++
		}
	}
	if len(counts) == 0 {
		return "", false
	}
	type keyCount struct {
		key   string
		count int
	}
	ranked := make([]keyCount, 0, len(counts))
	for key, count := range counts {
		ranked = append(ranked, keyCount{key: key, count: count})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].count == ranked[j].count {
			return ranked[i].key < ranked[j].key
		}
		return ranked[i].count > ranked[j].count
	})
	if status != nil {
		status(fmt.Sprintf("message库未命中，按频次回退选择候选 key（top=%d）", ranked[0].count))
	}
	return ranked[0].key, true
}
