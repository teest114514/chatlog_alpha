package windows

import (
	"context"

	"github.com/sjzar/chatlog/internal/wechat/decrypt"
)

type V4Extractor struct{}

func NewV4Extractor() *V4Extractor {
	return &V4Extractor{}
}

func (e *V4Extractor) SearchKey(ctx context.Context, memory []byte) (string, bool) {
	_ = ctx
	_ = memory
	return "", false
}

func (e *V4Extractor) SetValidate(validator *decrypt.Validator) {
	_ = e
	_ = validator // Windows validation happens against database pages after scanning.
}
