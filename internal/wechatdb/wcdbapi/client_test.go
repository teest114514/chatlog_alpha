package wcdbapi

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sjzar/chatlog/internal/wechat/decrypt"
)

func TestResolveDataKeyFallsBackToAnotherVerifiedSavedKey(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("fixture uses the macOS WeChat v4 database format")
	}
	accountDir := t.TempDir()
	messageDir := filepath.Join(accountDir, "db_storage", "message")
	if err := os.MkdirAll(messageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	correctKey := strings.Repeat("44", 32)
	wrongKey := strings.Repeat("55", 32)
	dbPath := filepath.Join(messageDir, "weclaw.db")
	writeWCDBEncryptedTestPage(t, dbPath, correctKey, []byte("weclaw--salt-002"))

	allKeys := map[string]any{
		// The path-specific mapping is stale, while another saved DB carries
		// the correct candidate. resolveDataKey must validate and recover.
		"message/weclaw.db":    map[string]string{"enc_key": wrongKey},
		"message/message_0.db": map[string]string{"enc_key": correctKey},
	}
	content, err := json.Marshal(allKeys)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(accountDir, "all_keys.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(accountDir, "")
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := client.resolveDataKey(dbPath)
	if err != nil {
		t.Fatalf("resolveDataKey: %v", err)
	}
	if resolved != correctKey {
		t.Fatalf("resolved key = %q, want verified fallback", resolved)
	}
	// The second call must use the validated cache and remain stable.
	resolvedAgain, err := client.resolveDataKey(dbPath)
	if err != nil || resolvedAgain != correctKey {
		t.Fatalf("cached resolution = %q, %v", resolvedAgain, err)
	}
}

func TestNewClientRecoversMissingEmptyDatabaseMapping(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("fixture uses the macOS WeChat v4 database format")
	}
	accountDir := t.TempDir()
	messageDir := filepath.Join(accountDir, "db_storage", "message")
	if err := os.MkdirAll(messageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("66", 32)
	dbPath := filepath.Join(messageDir, "weclaw.db")
	writeWCDBEncryptedTestPage(t, dbPath, key, []byte("weclaw--salt-003"))
	content, err := json.Marshal(map[string]any{
		"message/message_0.db": map[string]string{"enc_key": key},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(accountDir, "all_keys.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(accountDir, "")
	if err != nil {
		t.Fatal(err)
	}
	if client.allKeys["message/weclaw.db"] != key {
		t.Fatalf("missing DB mapping was not recovered: %#v", client.allKeys)
	}
	found := false
	for _, path := range client.ListAllKeyDBs() {
		if filepath.Clean(path) == filepath.Clean(dbPath) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("recovered DB is absent from ListAllKeyDBs")
	}
}

func writeWCDBEncryptedTestPage(t *testing.T, path, keyHex string, salt []byte) {
	t.Helper()
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	decryptor, err := decrypt.NewDecryptor(runtime.GOOS, 4)
	if err != nil {
		t.Fatal(err)
	}
	encKey, _, err := decryptor.DeriveKeys(key, salt)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, decryptor.GetPageSize())
	copy(plain, []byte("SQLite format 3\x00"))
	binary.BigEndian.PutUint16(plain[16:18], uint16(decryptor.GetPageSize()))
	plain[18], plain[19], plain[20] = 1, 1, byte(decryptor.GetReserve())
	plain[21], plain[22], plain[23] = 64, 32, 32
	// Exercise WeChat's initialized-but-empty DB header (weclaw/solitaire):
	// encoding and schema format remain zero until the first table is created.
	binary.BigEndian.PutUint32(plain[56:60], 0)
	plain[100] = 13

	page := make([]byte, decryptor.GetPageSize())
	copy(page[:16], salt)
	ivOffset := len(page) - decryptor.GetReserve()
	iv := []byte("test-page-one-iv")
	copy(page[ivOffset:ivOffset+aes.BlockSize], iv)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatal(err)
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(page[16:ivOffset], plain[16:ivOffset])
	if err := os.WriteFile(path, page, 0o600); err != nil {
		t.Fatal(err)
	}
}
