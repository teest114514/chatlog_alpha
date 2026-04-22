package http

import (
	"context"
	"embed"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
)

//go:embed wasm/wasm_video_decode.js wasm/wasm_video_decode.wasm wasm/wasm_keystream_helper.js
var snsWasmAssets embed.FS

var (
	snsWasmInitMu  sync.Mutex
	snsWasmBaseDir string
)

func (s *Service) getSNSWasmKeystream(ctx context.Context, key string, size int, mode string) ([]byte, error) {
	baseDir, err := s.ensureSNSWasmAssets()
	if err != nil {
		return nil, err
	}
	if mode == "" {
		mode = "reversed"
	}

	cmd := exec.CommandContext(ctx, "node", filepath.Join(baseDir, "wasm_keystream_helper.js"), key, strconv.Itoa(size), mode)
	cmd.Env = os.Environ()
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("sns wasm helper failed: %s", string(ee.Stderr))
		}
		return nil, err
	}

	decoded, err := base64.StdEncoding.DecodeString(string(out))
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func (s *Service) ensureSNSWasmAssets() (string, error) {
	snsWasmInitMu.Lock()
	defer snsWasmInitMu.Unlock()

	if snsWasmBaseDir != "" {
		return snsWasmBaseDir, nil
	}

	baseDir := filepath.Join(os.TempDir(), "chatlog_sns_wasm")
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return "", err
	}

	files := []string{
		"wasm_video_decode.js",
		"wasm_video_decode.wasm",
		"wasm_keystream_helper.js",
	}
	for _, name := range files {
		data, err := snsWasmAssets.ReadFile("wasm/" + name)
		if err != nil {
			return "", err
		}
		target := filepath.Join(baseDir, name)
		if _, err := os.Stat(target); err == nil {
			continue
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			return "", err
		}
	}

	snsWasmBaseDir = baseDir
	return snsWasmBaseDir, nil
}
