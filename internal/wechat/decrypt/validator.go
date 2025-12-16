package decrypt

import (
	"path/filepath"

	"github.com/sjzar/chatlog/internal/wechat/decrypt/common"
	"github.com/sjzar/chatlog/pkg/util/dat2img"
)

type Validator struct {
	platform        string
	version         int
	dbPath          string
	decryptor       Decryptor
	dbFile          *common.DBFile
	imgKeyValidator *dat2img.AesKeyValidator
}

// NewValidator 创建一个仅用于验证的验证器
func NewValidator(platform string, version int, dataDir string) (*Validator, error) {
	return NewValidatorWithFile(platform, version, dataDir)
}

func NewValidatorWithFile(platform string, version int, dataDir string) (*Validator, error) {
	dbFile := GetSimpleDBFile(platform, version)
	dbPath := filepath.Join(dataDir, dbFile)
	decryptor, err := NewDecryptor(platform, version)
	if err != nil {
		return nil, err
	}
	d, err := common.OpenDBFile(dbPath, decryptor.GetPageSize())
	if err != nil {
		return nil, err
	}

	validator := &Validator{
		platform:  platform,
		version:   version,
		dbPath:    dbPath,
		decryptor: decryptor,
		dbFile:    d,
	}

	if version == 4 {
		validator.imgKeyValidator = dat2img.NewImgKeyValidator(dataDir)
	}

	return validator, nil
}

// NewImgKeyOnlyValidator 创建一个仅用于图片密钥验证的验证器（不依赖数据库文件存在）
// 主要用于：微信V4图片密钥的内存扫描阶段，在未能打开 message_0.db 时仍可验证图片密钥候选值。
func NewImgKeyOnlyValidator(platform string, version int, dataDir string) (*Validator, error) {
	validator := &Validator{
		platform: platform,
		version:  version,
		dbPath:   "",
		dbFile:   nil,
	}
	if version == 4 {
		validator.imgKeyValidator = dat2img.NewImgKeyValidator(dataDir)
	}
	return validator, nil
}

// DBReady 表示是否具备数据库密钥验证所需的样本（已成功打开 dbFile）
func (v *Validator) DBReady() bool {
	return v != nil && v.dbFile != nil && v.decryptor != nil
}

// ImgKeyReady 表示是否具备图片密钥验证所需的样本（已找到可用的 *_t.dat 或备用模板）
func (v *Validator) ImgKeyReady() bool {
	if v == nil || v.imgKeyValidator == nil {
		return false
	}
	// 为了稳定：仅当样本来自 *_t.dat 时才认为“就绪”
	// 备用 *.dat 样本在某些时机会不匹配，导致“扫描很多轮也无法验证通过”的现象。
	if v.imgKeyValidator.TemplateSource != "t.dat" {
		return false
	}
	// AES block size is 16 bytes; EncryptedData 为空表示尚未找到验证样本文件
	return len(v.imgKeyValidator.EncryptedData) >= 16
}

// ImgKeyTemplateSource 返回图片验证样本来源（t.dat / fallback / none）
func (v *Validator) ImgKeyTemplateSource() string {
	if v == nil || v.imgKeyValidator == nil {
		return ""
	}
	return v.imgKeyValidator.TemplateSource
}

func (v *Validator) Validate(key []byte) bool {
	if !v.DBReady() {
		return false
	}
	return v.decryptor.Validate(v.dbFile.FirstPage, key)
}

func (v *Validator) ValidateImgKey(key []byte) bool {
	if v.imgKeyValidator == nil {
		return false
	}
	return v.imgKeyValidator.Validate(key)
}

func GetSimpleDBFile(platform string, version int) string {
	switch {
	case platform == "windows" && version == 4:
		return "db_storage\\message\\message_0.db"
	}
	return ""

}
