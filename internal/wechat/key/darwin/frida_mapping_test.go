//go:build darwin

package darwin

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	"github.com/sjzar/chatlog/internal/wechat/model"
)

func TestApplyCapturedKeysMapsEachDatabaseByValidation(t *testing.T) {
	accountDir := t.TempDir()
	storageDir := filepath.Join(accountDir, "db_storage")
	keyA := strings.Repeat("11", 32)
	keyB := strings.Repeat("22", 32)
	keyC := strings.Repeat("33", 32)
	dbs := []struct {
		rel      string
		key      string
		salt     []byte
		encoding uint32
	}{
		{rel: "message/message_0.db", key: keyA, salt: []byte("message-salt-001"), encoding: 1},
		{rel: "message/weclaw.db", key: keyB, salt: []byte("weclaw--salt-001"), encoding: 0},
		{rel: "solitaire/solitaire.db", key: keyC, salt: []byte("solitair-salt001"), encoding: 0},
	}
	for _, database := range dbs {
		path := filepath.Join(storageDir, filepath.FromSlash(database.rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		writeEncryptedTestPage(t, path, database.key, database.salt, database.encoding)
	}

	// Reproduce the old broken state: the primary message key was assigned to
	// every DB without verifying the individual page.
	wrong := map[string]keyFileEntry{}
	for _, database := range dbs {
		wrong[database.rel] = keyFileEntry{EncKey: keyA}
	}
	content, err := json.Marshal(wrong)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(accountDir, "all_keys.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}

	candidates := make([]CapturedDBKey, 0, len(dbs))
	for _, database := range dbs {
		candidates = append(candidates, CapturedDBKey{
			Key:  database.key,
			Salt: hex.EncodeToString(database.salt),
		})
	}
	primary, count, err := ApplyCapturedKeysToDataDir(accountDir, candidates, nil)
	if err != nil {
		t.Fatalf("ApplyCapturedKeysToDataDir: %v", err)
	}
	if primary != keyA {
		t.Fatalf("primary key = %q, want message key", primary)
	}
	if count != len(dbs) {
		t.Fatalf("mapped DB count = %d, want %d", count, len(dbs))
	}

	actual := readExistingKeyMap(filepath.Join(accountDir, "all_keys.json"))
	for _, database := range dbs {
		if actual[database.rel] != database.key {
			t.Fatalf("%s mapped to %q, want its verified key", database.rel, actual[database.rel])
		}
	}
}

func writeEncryptedTestPage(t *testing.T, path, keyHex string, salt []byte, encoding uint32) {
	t.Helper()
	if len(salt) != 16 {
		t.Fatalf("test salt length = %d, want 16", len(salt))
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	decryptor, err := decrypt.NewDecryptor(model.PlatformDarwin, 4)
	if err != nil {
		t.Fatal(err)
	}
	encKey, _, err := decryptor.DeriveKeys(key, salt)
	if err != nil {
		t.Fatal(err)
	}

	plain := make([]byte, 4096)
	copy(plain, []byte("SQLite format 3\x00"))
	binary.BigEndian.PutUint16(plain[16:18], 4096)
	plain[18], plain[19], plain[20] = 1, 1, 80
	plain[21], plain[22], plain[23] = 64, 32, 32
	binary.BigEndian.PutUint32(plain[56:60], encoding)
	if encoding == 0 {
		plain[100] = 13 // empty sqlite_schema leaf page
	}

	page := make([]byte, 4096)
	copy(page[:16], salt)
	iv := []byte("test-page-one-iv")
	copy(page[4016:4032], iv)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatal(err)
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(page[16:4016], plain[16:4016])
	if err := os.WriteFile(path, page, 0o600); err != nil {
		t.Fatal(err)
	}
}
