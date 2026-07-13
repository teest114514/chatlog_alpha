package shared

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAllKeysSupportsObjectAndStringEntries(t *testing.T) {
	directory := t.TempDir()
	keyA := strings.Repeat("a", 64)
	keyB := strings.Repeat("b", 64)
	content, err := json.Marshal(map[string]any{
		"message/message_0.db": map[string]any{"enc_key": keyA},
		"contact/contact.db":   keyB,
		"invalid.db":           "short",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "all_keys.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := LoadAllKeys(directory, "test", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if keys["message/message_0.db"] != keyA || keys["contact/contact.db"] != keyB || len(keys) != 2 {
		t.Fatalf("unexpected keys: %#v", keys)
	}
}

func TestPickPreferredMessageKeyFallsBackByFrequency(t *testing.T) {
	keyA := strings.Repeat("a", 64)
	keyB := strings.Repeat("b", 64)
	keys := map[string]string{"one.db": keyA, "two.db": keyA, "three.db": keyB}
	selected, ok := PickPreferredMessageKey("", keys, func(string, string, string) bool { return false }, nil)
	if !ok || selected != keyA {
		t.Fatalf("selected=%q ok=%v", selected, ok)
	}
}

func TestCollectDBSaltsSkipsPlainSQLite(t *testing.T) {
	directory := t.TempDir()
	plain := append([]byte("SQLite format 3"), 0)
	if err := os.WriteFile(filepath.Join(directory, "plain.db"), plain, 0o600); err != nil {
		t.Fatal(err)
	}
	encrypted := []byte("0123456789abcdefpayload")
	if err := os.WriteFile(filepath.Join(directory, "encrypted.db"), encrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := CollectDBSalts(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].DBRel != "encrypted.db" {
		t.Fatalf("unexpected entries: %#v", entries)
	}
}
