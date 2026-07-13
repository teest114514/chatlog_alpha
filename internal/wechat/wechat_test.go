package wechat

import (
	"context"
	"testing"
)

func TestGetKeyDataOnlyUsesCachedDataKeyWithoutImageKey(t *testing.T) {
	account := &Account{
		Name:    "test-account",
		Version: 4,
		Key:     "cached-data-key",
	}
	ctx := context.WithValue(context.Background(), "data_key_only", true)

	dataKey, imageKey, err := account.GetKey(ctx)
	if err != nil {
		t.Fatalf("GetKey returned an error: %v", err)
	}
	if dataKey != account.Key {
		t.Fatalf("data key = %q, want %q", dataKey, account.Key)
	}
	if imageKey != "" {
		t.Fatalf("image key = %q, want empty for data-key-only request", imageKey)
	}
}
