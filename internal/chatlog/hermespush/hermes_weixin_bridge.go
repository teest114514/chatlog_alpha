package hermespush

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed hermes_weixin_bridge.py
var hermesWeixinBridgeScript string

type hermesBridgePayload struct {
	AccountID  string   `json:"account_id"`
	Token      string   `json:"token"`
	BaseURL    string   `json:"base_url"`
	CdnBaseURL string   `json:"cdn_base_url"`
	ChatID     string   `json:"chat_id"`
	Text       string   `json:"text"`
	MediaPaths []string `json:"media_paths"`
	HermesHome string   `json:"hermes_home"`
	HermesRoot string   `json:"hermes_root"`
}

type hermesBridgeResult struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

func sendWeixinViaHermesPython(cfg *WeixinConfig, req WeixinSendRequest) error {
	pythonBin, hermesRoot, err := discoverHermesPython()
	if err != nil {
		return err
	}
	scriptPath, cleanup, err := ensureHermesBridgeScript()
	if err != nil {
		return err
	}
	defer cleanup()

	payload := hermesBridgePayload{
		AccountID:  strings.TrimSpace(cfg.AccountID),
		Token:      strings.TrimSpace(cfg.Token),
		BaseURL:    strings.TrimSpace(cfg.BaseURL),
		CdnBaseURL: strings.TrimSpace(cfg.CdnBaseURL),
		ChatID:     strings.TrimSpace(cfg.HomeChannel),
		Text:       strings.TrimSpace(req.Text),
		MediaPaths: compactMediaPaths(req.MediaPaths),
		HermesHome: strings.TrimSpace(cfg.HermesHome),
		HermesRoot: hermesRoot,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	cmd := exec.Command(pythonBin, scriptPath)
	cmd.Env = append(os.Environ(), "HERMES_HOME="+payload.HermesHome)
	cmd.Stdin = bytes.NewReader(body)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("Hermes Weixin media send failed: %s", msg)
	}
	var result hermesBridgeResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return fmt.Errorf("Hermes Weixin media send invalid response: %w", err)
	}
	if !result.Success {
		if strings.TrimSpace(result.Error) == "" {
			result.Error = "unknown error"
		}
		return fmt.Errorf(result.Error)
	}
	return nil
}

func discoverHermesPython() (string, string, error) {
	if hermesBin, err := exec.LookPath("hermes"); err == nil {
		if data, err := os.ReadFile(hermesBin); err == nil {
			line := strings.SplitN(string(data), "\n", 2)[0]
			if strings.HasPrefix(line, "#!") {
				pythonBin := strings.TrimSpace(strings.TrimPrefix(line, "#!"))
				if pythonBin != "" {
					hermesRoot := filepath.Clean(filepath.Join(filepath.Dir(pythonBin), "..", ".."))
					return pythonBin, hermesRoot, nil
				}
			}
		}
	}
	home, _ := os.UserHomeDir()
	pythonBin := filepath.Join(home, ".hermes", "hermes-agent", "venv", "bin", "python3")
	if _, err := os.Stat(pythonBin); err != nil {
		return "", "", fmt.Errorf("未找到 Hermes Python 运行时")
	}
	return pythonBin, filepath.Clean(filepath.Join(filepath.Dir(pythonBin), "..", "..")), nil
}

func ensureHermesBridgeScript() (string, func(), error) {
	tmpFile, err := os.CreateTemp("", "chatlog-hermes-weixin-bridge-*.py")
	if err != nil {
		return "", nil, err
	}
	if _, err := tmpFile.WriteString(hermesWeixinBridgeScript); err != nil {
		tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return "", nil, err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpFile.Name())
		return "", nil, err
	}
	return tmpFile.Name(), func() { _ = os.Remove(tmpFile.Name()) }, nil
}
