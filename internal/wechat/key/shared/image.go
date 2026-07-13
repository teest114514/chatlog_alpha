package shared

import (
	"crypto/aes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/sjzar/chatlog/pkg/util/dat2img"
)

type TemplateData struct {
	Ciphertext   []byte
	XorKey       *byte
	TemplateData []byte
}

func VerifyImageKeyStrong(aes16, templateData []byte) bool {
	if len(aes16) != aes.BlockSize || len(templateData) < 15 {
		return false
	}
	_, _, err := dat2img.Dat2ImageV4(templateData, aes16)
	return err == nil
}

func VerifyImageKeyHeader(aes16, ciphertext []byte) bool {
	if len(aes16) != aes.BlockSize || len(ciphertext) != aes.BlockSize {
		return false
	}
	block, err := aes.NewCipher(aes16)
	if err != nil {
		return false
	}
	plain := make([]byte, aes.BlockSize)
	block.Decrypt(plain, ciphertext)
	return hasSupportedImageHeader(plain)
}

func hasSupportedImageHeader(plain []byte) bool {
	return hasPrefix(plain, []byte{0xFF, 0xD8, 0xFF}) || // JPG
		hasPrefix(plain, []byte{0x89, 0x50, 0x4E, 0x47}) || // PNG
		hasPrefix(plain, []byte{0x52, 0x49, 0x46, 0x46}) || // RIFF
		hasPrefix(plain, []byte{0x77, 0x78, 0x67, 0x66}) || // WXGF
		hasPrefix(plain, []byte{0x47, 0x49, 0x46}) // GIF
}

func hasPrefix(value, prefix []byte) bool {
	if len(value) < len(prefix) {
		return false
	}
	for i := range prefix {
		if value[i] != prefix[i] {
			return false
		}
	}
	return true
}

func FindTemplateData(dataDir string, limit int) (TemplateData, bool) {
	const sampleOffset = 0x0F
	const sampleLen = aes.BlockSize
	magic := []byte{0x07, 0x08, 0x56, 0x32, 0x08, 0x07}

	files := make([]string, 0, limit)
	_ = filepath.WalkDir(dataDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry == nil || entry.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(entry.Name()), "_t.dat") {
			files = append(files, path)
		}
		return nil
	})
	if len(files) == 0 {
		return TemplateData{}, false
	}
	sort.Slice(files, func(i, j int) bool {
		left, leftErr := os.Stat(files[i])
		right, rightErr := os.Stat(files[j])
		if leftErr != nil || rightErr != nil {
			return files[i] < files[j]
		}
		return left.ModTime().After(right.ModTime())
	})
	if limit > 0 && len(files) > limit {
		files = files[:limit]
	}

	var ciphertext, templateRaw []byte
	tailCounts := map[string]int{}
	maxProbe := min(32, len(files))
	for _, name := range files[:maxProbe] {
		content, err := os.ReadFile(name)
		if err != nil || len(content) < 8 || !hasPrefix(content, magic) {
			continue
		}
		if len(content) >= sampleOffset+sampleLen && ciphertext == nil {
			ciphertext = append([]byte(nil), content[sampleOffset:sampleOffset+sampleLen]...)
			templateRaw = append([]byte(nil), content...)
		}
		key := fmt.Sprintf("%d_%d", content[len(content)-2], content[len(content)-1])
		tailCounts[key]++
	}
	if ciphertext == nil {
		return TemplateData{}, false
	}

	var xorKey *byte
	bestCount := 0
	for key, count := range tailCounts {
		if count <= bestCount {
			continue
		}
		parts := strings.Split(key, "_")
		if len(parts) != 2 {
			continue
		}
		x, errX := strconv.Atoi(parts[0])
		y, errY := strconv.Atoi(parts[1])
		if errX != nil || errY != nil {
			continue
		}
		candidate := byte(x) ^ 0xFF
		if candidate == (byte(y) ^ 0xD9) {
			value := candidate
			xorKey = &value
			bestCount = count
		}
	}
	return TemplateData{Ciphertext: ciphertext, XorKey: xorKey, TemplateData: templateRaw}, true
}

func NormalizeAccountID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(value), "wxid_") {
		if index := strings.Index(value[5:], "_"); index >= 0 {
			return value[:5+index]
		}
		return value
	}
	if match := regexp.MustCompile(`^(.+)_([a-zA-Z0-9]{4})$`).FindStringSubmatch(value); len(match) == 3 {
		return match[1]
	}
	return value
}

func IsReasonableAccountID(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, `/\`) {
		return false
	}
	switch strings.ToLower(value) {
	case "xwechat_files", "wechat files", "all_users", "backup", "wmpf", "app_data":
		return false
	default:
		return true
	}
}

func AppendAccountIDCandidate(values *[]string, value string) {
	if !IsReasonableAccountID(value) {
		return
	}
	appendUnique(values, strings.TrimSpace(value))
	normalized := NormalizeAccountID(value)
	if normalized != value && IsReasonableAccountID(normalized) {
		appendUnique(values, normalized)
	}
}

func AppendUniquePath(values *[]string, value string) {
	appendUnique(values, strings.TrimSpace(value))
}

func appendUnique(values *[]string, value string) {
	if value == "" {
		return
	}
	for _, existing := range *values {
		if existing == value {
			return
		}
	}
	*values = append(*values, value)
}

func IsAccountDir(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	for _, child := range []string{
		"db_storage",
		"msg",
		filepath.Join("FileStorage", "Image"),
		filepath.Join("FileStorage", "Image2"),
	} {
		if stat, err := os.Stat(filepath.Join(path, child)); err == nil && stat.IsDir() {
			return true
		}
	}
	return false
}

func CollectKvcommCodes(directories []string) []int {
	codes := map[int]struct{}{}
	pattern := regexp.MustCompile(`^key_(\d+)_.+\.statistic$`)
	for _, directory := range directories {
		entries, err := os.ReadDir(directory)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			match := pattern.FindStringSubmatch(entry.Name())
			if len(match) != 2 {
				continue
			}
			code, err := strconv.ParseUint(match[1], 10, 32)
			if err == nil && code != 0 {
				codes[int(code)] = struct{}{}
			}
		}
	}
	result := make([]int, 0, len(codes))
	for code := range codes {
		result = append(result, code)
	}
	sort.Ints(result)
	return result
}

func DeriveImageKeyFromCode(code int, accountID string) (byte, string) {
	cleaned := NormalizeAccountID(accountID)
	xorKey := byte(code & 0xFF)
	sum := md5.Sum([]byte(strconv.Itoa(code) + cleaned))
	return xorKey, hex.EncodeToString(sum[:])[:16]
}

func DeriveImageKey(codes []int, accountIDs, accountPaths []string, status func(string)) (string, bool) {
	if status != nil {
		status(fmt.Sprintf("正在校验 code+wxid 组合... code=%d, wxid=%d, account=%d", len(codes), len(accountIDs), len(accountPaths)))
	}
	if len(codes) == 0 || len(accountIDs) == 0 {
		return "", false
	}

	for _, accountPath := range accountPaths {
		template, ok := FindTemplateData(accountPath, 32)
		if !ok || len(template.Ciphertext) != aes.BlockSize {
			continue
		}
		orderedIDs := make([]string, 0, len(accountIDs)+2)
		AppendAccountIDCandidate(&orderedIDs, filepath.Base(filepath.Clean(accountPath)))
		for _, accountID := range accountIDs {
			AppendAccountIDCandidate(&orderedIDs, accountID)
		}
		for _, accountID := range orderedIDs {
			for _, code := range codes {
				xorKey, aesKey := DeriveImageKeyFromCode(code, accountID)
				key := []byte(aesKey)
				if !VerifyImageKeyHeader(key, template.Ciphertext) {
					continue
				}
				previousXOR := dat2img.V4XorKey
				dat2img.V4XorKey = xorKey
				if !VerifyImageKeyStrong(key, template.TemplateData) {
					dat2img.V4XorKey = previousXOR
					continue
				}
				if status != nil {
					status(fmt.Sprintf("命中 code=%d, wxid=%s", code, accountID))
				}
				return aesKey, true
			}
		}
	}

	xorKey, aesKey := DeriveImageKeyFromCode(codes[0], accountIDs[0])
	dat2img.V4XorKey = xorKey
	if status != nil {
		reason := "模板验真未命中"
		if len(accountPaths) == 0 {
			reason = "模板缺失"
		}
		status(fmt.Sprintf("%s，回退使用首个 code+wxid（code=%d, wxid=%s）", reason, codes[0], accountIDs[0]))
	}
	return aesKey, true
}
