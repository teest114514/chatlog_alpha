package dat2img

import (
	"bytes"
	"crypto/aes"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
)

type AesKeyValidator struct {
	Path          string
	EncryptedData []byte
	TemplateFile  string // 用于验证的样本文件路径
	// TemplateSource:
	// - "t.dat": 来自 *_t.dat（优先且稳定）
	// - "fallback": 来自普通 .dat 的备用样本（可能不稳定/不匹配）
	// - "none": 未找到样本
	TemplateSource string
}

func NewImgKeyValidator(path string) *AesKeyValidator {
	validator := &AesKeyValidator{
		Path:           path,
		TemplateSource: "none",
	}

	log.Info().Msgf("开始在 %s 查找验证样本文件", path)

	// 1. First try to find *_t.dat files (Dart implementation priority)
	foundTemplate := false
	filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Look for *_t.dat files
		if !strings.HasSuffix(info.Name(), "_t.dat") {
			return nil
		}

		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil
		}

		// Header check: 07 08 56 32 08 07 (V4Format2)
		if len(data) >= 0x1F && bytes.Equal(data[:6], V4Format2.Header) {
			// Extract 16 bytes starting at offset 0xF (15)
			validator.EncryptedData = make([]byte, aes.BlockSize)
			copy(validator.EncryptedData, data[0xF:0xF+aes.BlockSize])
			validator.TemplateFile = filePath
			validator.TemplateSource = "t.dat"
			foundTemplate = true
			log.Info().Msgf("找到模板文件: %s", filePath)
			return filepath.SkipAll
		}

		return nil
	})

	if foundTemplate {
		return validator
	}

	// 2. Fallback: Walk the directory to find *.dat files (excluding *_t.dat files)
	filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Only process *.dat files but exclude *_t.dat files
		if !strings.HasSuffix(info.Name(), ".dat") || strings.HasSuffix(info.Name(), "_t.dat") {
			return nil
		}

		// Read file content
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil
		}

		// Check if header matches V4Format2.Header
		// Get aes.BlockSize (16) bytes starting from position 15
		if len(data) >= 15+aes.BlockSize && bytes.Equal(data[:4], V4Format2.Header[:4]) {
			validator.EncryptedData = make([]byte, aes.BlockSize)
			copy(validator.EncryptedData, data[15:15+aes.BlockSize])
			validator.TemplateFile = filePath
			validator.TemplateSource = "fallback"
			log.Info().Msgf("找到备用模板文件: %s", filePath)
			return filepath.SkipAll // Found what we need, stop walking
		}

		return nil
	})

	if len(validator.EncryptedData) == 0 {
		log.Warn().Msg("未找到任何可用的验证样本文件")
		validator.TemplateSource = "none"
	}

	return validator
}

func (v *AesKeyValidator) Validate(key []byte) bool {
	// 16 bytes for AES-128, 32 bytes for AES-256 (but we only use first 16 bytes for V4 image key)
	if len(key) < 16 {
		return false
	}
	
	// Dart implementation explicitly uses first 16 bytes
	aesKey := key[:16]

	cipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return false
	}

	if len(v.EncryptedData) < aes.BlockSize {
		return false
	}

	decrypted := make([]byte, len(v.EncryptedData))
	cipher.Decrypt(decrypted, v.EncryptedData)

	// Dart implementation checks for JPG header: FF D8 FF
	if bytes.HasPrefix(decrypted, []byte{0xFF, 0xD8, 0xFF}) {
		return true
	}
	
	// Keep existing checks for backward compatibility
	return bytes.HasPrefix(decrypted, JPG.Header) || bytes.HasPrefix(decrypted, WXGF.Header)
}
