package darwin

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	"github.com/sjzar/chatlog/internal/wechat/decrypt/common"
	keyshared "github.com/sjzar/chatlog/internal/wechat/key/shared"
	"github.com/sjzar/chatlog/internal/wechat/model"
)

type dbSaltEntry = keyshared.DBSaltEntry
type keyFileEntry = keyshared.KeyFileEntry

// loadAndValidateMessageKey picks a usable data key from all_keys.json.
// Data-key process-memory scanning is intentionally not used on modern WeChat.
func loadAndValidateMessageKey(dataDir string, status func(string)) (string, error) {
	keys, err := loadAllKeys(dataDir, status)
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
	decryptor, err := decrypt.NewDecryptor(model.PlatformDarwin, 4)
	return err == nil && decryptor.Validate(database.FirstPage, key)
}

func resolveDBPath(dataDir, dbRelativePath string) string {
	return keyshared.ResolveDBPath(dataDir, dbRelativePath)
}

func collectDBSalts(storageDir string) ([]dbSaltEntry, error) {
	return keyshared.CollectDBSalts(storageDir)
}

func resolveDBDirs(dataDir string) (accountDir, storageDir string) {
	return keyshared.ResolveDBDirs(dataDir)
}

func normalizeAllKeysOwnership(keysPath string) error {
	_ = os.Chmod(keysPath, 0o600)
	if os.Geteuid() != 0 {
		return nil
	}
	uidString := strings.TrimSpace(os.Getenv("SUDO_UID"))
	gidString := strings.TrimSpace(os.Getenv("SUDO_GID"))
	if uidString == "" || gidString == "" {
		return nil
	}
	uid, uidErr := strconv.Atoi(uidString)
	gid, gidErr := strconv.Atoi(gidString)
	if uidErr != nil || gidErr != nil || uid <= 0 || gid <= 0 {
		return nil
	}
	if err := os.Chown(keysPath, uid, gid); err != nil {
		return err
	}
	return os.Chmod(keysPath, 0o600)
}
