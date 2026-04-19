package decrypt

import (
	"context"
	"hash"
	"io"

	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/wechat/decrypt/darwin"
)

// Decryptor 定义数据库解密的接口
type Decryptor interface {
	// Decrypt 解密数据库
	Decrypt(ctx context.Context, dbfile string, key string, output io.Writer) error

	// Validate 验证密钥是否有效
	Validate(page1 []byte, key []byte) bool

	// GetPageSize 返回页面大小
	GetPageSize() int

	// GetReserve 返回保留字节数
	GetReserve() int

	// GetHMACSize 返回HMAC大小
	GetHMACSize() int

	GetHashFunc() func() hash.Hash
	DeriveKeys(key []byte, salt []byte) ([]byte, []byte, error)

	// GetVersion 返回解密器版本
	GetVersion() string
}

// NewDecryptor 创建一个新的解密器
func NewDecryptor(platform string, version int) (Decryptor, error) {
	// 根据平台返回对应的实现
	switch {
	case platform == "darwin" && version == 4:
		return darwin.NewV4Decryptor(), nil
	default:
		return nil, errors.PlatformUnsupported(platform, version)
	}
}
