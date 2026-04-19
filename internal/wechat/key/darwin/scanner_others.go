//go:build !darwin

package darwin

import "fmt"

type keySaltPair struct {
	KeyHex  string
	SaltHex string
}

type fastScanStats struct {
	Regions    int
	Candidates int
}

func scanKeyBySaltFast(pid uint32, targetSaltHex string) (string, *fastScanStats, error) {
	_ = pid
	_ = targetSaltHex
	return "", nil, fmt.Errorf("仅支持 darwin 平台扫描")
}

func scanKeySaltPairsByPID(pid uint32) ([]keySaltPair, error) {
	_ = pid
	return nil, fmt.Errorf("仅支持 darwin 平台扫描")
}

func scanImageKeyCandidatesByPID(pid uint32) ([]string, int, error) {
	_ = pid
	return nil, 0, fmt.Errorf("仅支持 darwin 平台扫描")
}

func scanImageAny16CandidatesByPID(pid uint32) ([]string, int, error) {
	_ = pid
	return nil, 0, fmt.Errorf("仅支持 darwin 平台扫描")
}

func scanImageKeyByPIDAndCiphertext(pid uint32, ciphertext []byte) (string, int, error) {
	_ = pid
	_ = ciphertext
	return "", 0, fmt.Errorf("仅支持 darwin 平台扫描")
}
