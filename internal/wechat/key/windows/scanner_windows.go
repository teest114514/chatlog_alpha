package windows

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	keyshared "github.com/sjzar/chatlog/internal/wechat/key/shared"
)

const (
	hexPatternLen = 96
	chunkSize     = 2 * 1024 * 1024
	chunkOverlap  = hexPatternLen + 3
)

type keySaltPair struct {
	KeyHex  string
	SaltHex string
}

func scanKeySaltPairsByPID(pid uint32) ([]keySaltPair, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return nil, fmt.Errorf("open process failed: %w", err)
	}
	defer windows.CloseHandle(handle)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return scanKeySaltCandidates(ctx, handle)
}

func scanKeySaltCandidates(ctx context.Context, handle windows.Handle) ([]keySaltPair, error) {
	results := make([]keySaltPair, 0, 128)
	seen := make(map[string]struct{})
	var address uintptr
	for {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}
		var region windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(handle, address, &region, unsafe.Sizeof(region)); err != nil {
			break
		}
		if region.State == windows.MEM_COMMIT && isRWProtect(region.Protect) && region.RegionSize > 0 {
			scanRegionForKeySalt(ctx, handle, uintptr(region.BaseAddress), uintptr(region.RegionSize), &results, seen)
		}
		next := uintptr(region.BaseAddress) + uintptr(region.RegionSize)
		if next <= address {
			break
		}
		address = next
	}
	return results, nil
}

func scanRegionForKeySalt(ctx context.Context, handle windows.Handle, base, size uintptr, out *[]keySaltPair, seen map[string]struct{}) {
	for offset := uintptr(0); offset < size; {
		select {
		case <-ctx.Done():
			return
		default:
		}
		readSize := uintptr(chunkSize)
		if remaining := size - offset; remaining < readSize {
			readSize = remaining
		}
		buffer := make([]byte, readSize)
		var bytesRead uintptr
		if err := windows.ReadProcessMemory(handle, base+offset, &buffer[0], readSize, &bytesRead); err == nil && bytesRead > 0 {
			searchKeySaltPattern(buffer[:bytesRead], out, seen)
		}
		if readSize > chunkOverlap {
			offset += readSize - chunkOverlap
		} else {
			offset += readSize
		}
	}
}

func searchKeySaltPattern(buffer []byte, out *[]keySaltPair, seen map[string]struct{}) {
	total := hexPatternLen + 3
	for index := 0; index+total <= len(buffer); index++ {
		if buffer[index] != 'x' || buffer[index+1] != '\'' {
			continue
		}
		hexStart := index + 2
		valid := true
		for offset := 0; offset < hexPatternLen; offset++ {
			if !isHexByte(buffer[hexStart+offset]) {
				valid = false
				break
			}
		}
		if !valid || buffer[hexStart+hexPatternLen] != '\'' {
			continue
		}
		keyHex := strings.ToLower(string(buffer[hexStart : hexStart+64]))
		saltHex := strings.ToLower(string(buffer[hexStart+64 : hexStart+96]))
		id := keyHex + ":" + saltHex
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		*out = append(*out, keySaltPair{KeyHex: keyHex, SaltHex: saltHex})
	}
}

func scanImageKeyByPIDAndCiphertext(pid uint32, ciphertext []byte) (string, int, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return "", 0, fmt.Errorf("open process failed: %w", err)
	}
	defer windows.CloseHandle(handle)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return scanImageKeyByPIDAndCiphertextHandle(ctx, handle, ciphertext)
}

func scanImageKeyByPIDAndCiphertextHandle(ctx context.Context, handle windows.Handle, ciphertext []byte) (string, int, error) {
	if len(ciphertext) != 16 {
		return "", 0, fmt.Errorf("invalid ciphertext length: %d", len(ciphertext))
	}
	checked := 0
	var address uintptr
	for {
		select {
		case <-ctx.Done():
			return "", checked, ctx.Err()
		default:
		}
		var region windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(handle, address, &region, unsafe.Sizeof(region)); err != nil {
			break
		}
		if region.State == windows.MEM_COMMIT && isRWProtect(region.Protect) && region.RegionSize > 0 {
			if key := searchImageKeyInRegion(ctx, handle, uintptr(region.BaseAddress), uintptr(region.RegionSize), ciphertext, &checked); key != "" {
				return key, checked, nil
			}
		}
		next := uintptr(region.BaseAddress) + uintptr(region.RegionSize)
		if next <= address {
			break
		}
		address = next
	}
	return "", checked, nil
}

func searchImageKeyInRegion(ctx context.Context, handle windows.Handle, base, size uintptr, ciphertext []byte, checked *int) string {
	var trailing []byte
	for offset := uintptr(0); offset < size; {
		select {
		case <-ctx.Done():
			return ""
		default:
		}
		readSize := uintptr(4 * 1024 * 1024)
		if remaining := size - offset; remaining < readSize {
			readSize = remaining
		}
		buffer := make([]byte, readSize)
		var bytesRead uintptr
		if err := windows.ReadProcessMemory(handle, base+offset, &buffer[0], readSize, &bytesRead); err == nil && bytesRead > 0 {
			data := prependTrailing(trailing, buffer[:bytesRead])
			if key := searchASCIIKey(data, ciphertext, checked); key != "" {
				return key
			}
			if key := searchUTF16Key(data, ciphertext, checked); key != "" {
				return key
			}
			trailing = copyTail(data, 65)
		} else {
			trailing = nil
		}
		offset += readSize
	}
	return ""
}

func searchASCIIKey(data, ciphertext []byte, checked *int) string {
	for index := 0; index+34 <= len(data); index++ {
		if isAlphaNum(data[index]) {
			continue
		}
		valid := true
		for offset := 1; offset <= 32; offset++ {
			if !isAlphaNum(data[index+offset]) {
				valid = false
				break
			}
		}
		if !valid || (index+33 < len(data) && isAlphaNum(data[index+33])) {
			continue
		}
		*checked++
		key := data[index+1 : index+17]
		if keyshared.VerifyImageKeyHeader(key, ciphertext) {
			return string(key)
		}
	}
	return ""
}

func searchUTF16Key(data, ciphertext []byte, checked *int) string {
	for index := 0; index+64 <= len(data); index++ {
		key := make([]byte, 32)
		valid := true
		for offset := 0; offset < 32; offset++ {
			char := data[index+offset*2]
			if data[index+offset*2+1] != 0 || !isAlphaNum(char) {
				valid = false
				break
			}
			key[offset] = char
		}
		if !valid {
			continue
		}
		*checked++
		if keyshared.VerifyImageKeyHeader(key[:16], ciphertext) {
			return string(key[:16])
		}
	}
	return ""
}

func scanImageKeyCandidatesByPID(pid uint32) ([]string, int, error) {
	return scanAlphaNumCandidatesByPID(pid, 32)
}

func scanImageAny16CandidatesByPID(pid uint32) ([]string, int, error) {
	return scanAlphaNumCandidatesByPID(pid, 16)
}

func scanAlphaNumCandidatesByPID(pid uint32, length int) ([]string, int, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return nil, 0, fmt.Errorf("open process failed: %w", err)
	}
	defer windows.CloseHandle(handle)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	seen := map[string]struct{}{}
	checked := 0
	var address uintptr
	for {
		select {
		case <-ctx.Done():
			return candidateStrings(seen), checked, nil
		default:
		}
		var region windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(handle, address, &region, unsafe.Sizeof(region)); err != nil {
			break
		}
		if region.State == windows.MEM_COMMIT && isRWProtect(region.Protect) && region.RegionSize > 0 {
			collectCandidatesInRegion(ctx, handle, uintptr(region.BaseAddress), uintptr(region.RegionSize), length, seen, &checked)
		}
		next := uintptr(region.BaseAddress) + uintptr(region.RegionSize)
		if next <= address {
			break
		}
		address = next
	}
	return candidateStrings(seen), checked, nil
}

func collectCandidatesInRegion(ctx context.Context, handle windows.Handle, base, size uintptr, length int, seen map[string]struct{}, checked *int) {
	var trailing []byte
	tailLength := length*2 + 2
	for offset := uintptr(0); offset < size; {
		select {
		case <-ctx.Done():
			return
		default:
		}
		readSize := uintptr(4 * 1024 * 1024)
		if remaining := size - offset; remaining < readSize {
			readSize = remaining
		}
		buffer := make([]byte, readSize)
		var bytesRead uintptr
		if err := windows.ReadProcessMemory(handle, base+offset, &buffer[0], readSize, &bytesRead); err == nil && bytesRead > 0 {
			data := prependTrailing(trailing, buffer[:bytesRead])
			collectASCIICandidates(data, length, seen, checked)
			collectUTF16Candidates(data, length, seen, checked)
			trailing = copyTail(data, tailLength)
		} else {
			trailing = nil
		}
		offset += readSize
	}
}

func collectASCIICandidates(data []byte, length int, seen map[string]struct{}, checked *int) {
	for index := 0; index+length <= len(data); index++ {
		if index > 0 && isAlphaNum(data[index-1]) {
			continue
		}
		valid := true
		for offset := 0; offset < length; offset++ {
			if !isAlphaNum(data[index+offset]) {
				valid = false
				break
			}
		}
		if !valid || (index+length < len(data) && isAlphaNum(data[index+length])) {
			continue
		}
		*checked++
		seen[string(data[index:index+length])] = struct{}{}
	}
}

func collectUTF16Candidates(data []byte, length int, seen map[string]struct{}, checked *int) {
	needed := length * 2
	for index := 0; index+needed <= len(data); index++ {
		candidate := make([]byte, length)
		valid := true
		for offset := 0; offset < length; offset++ {
			char := data[index+offset*2]
			if data[index+offset*2+1] != 0 || !isAlphaNum(char) {
				valid = false
				break
			}
			candidate[offset] = char
		}
		if !valid {
			continue
		}
		*checked++
		seen[string(candidate)] = struct{}{}
	}
}

func prependTrailing(trailing, data []byte) []byte {
	if len(trailing) == 0 {
		return data
	}
	merged := make([]byte, 0, len(trailing)+len(data))
	merged = append(merged, trailing...)
	return append(merged, data...)
}

func copyTail(data []byte, length int) []byte {
	if len(data) > length {
		data = data[len(data)-length:]
	}
	return append([]byte(nil), data...)
}

func candidateStrings(seen map[string]struct{}) []string {
	result := make([]string, 0, len(seen))
	for candidate := range seen {
		result = append(result, candidate)
	}
	return result
}

func isAlphaNum(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func isRWProtect(protection uint32) bool {
	const (
		pageReadWrite     = 0x04
		pageWriteCopy     = 0x08
		pageExecReadWrite = 0x40
		pageExecWriteCopy = 0x80
		pageGuard         = 0x100
		pageNoAccess      = 0x01
	)
	if protection == pageNoAccess || protection&pageGuard != 0 {
		return false
	}
	return protection&pageReadWrite != 0 || protection&pageWriteCopy != 0 || protection&pageExecReadWrite != 0 || protection&pageExecWriteCopy != 0
}

func isHexByte(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}
