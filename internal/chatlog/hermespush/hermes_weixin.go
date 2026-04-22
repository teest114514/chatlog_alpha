package hermespush

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

const (
	WeixinDefaultBaseURL   = "https://ilinkai.weixin.qq.com"
	weixinSendMessageEP    = "ilink/bot/sendmessage"
	weixinAppID            = "bot"
	weixinAppClientVersion = (2 << 16) | (2 << 8) | 0
)

type WeixinConfig struct {
	HermesHome      string `json:"hermes_home"`
	EnvFile         string `json:"env_file,omitempty"`
	ConfigFile      string `json:"config_file,omitempty"`
	ChannelFile     string `json:"channel_file,omitempty"`
	AccountFile     string `json:"account_file,omitempty"`
	AccountID       string `json:"account_id,omitempty"`
	Token           string `json:"-"`
	BaseURL         string `json:"base_url,omitempty"`
	CdnBaseURL      string `json:"cdn_base_url,omitempty"`
	HomeChannel     string `json:"home_channel,omitempty"`
	HomeChannelName string `json:"home_channel_name,omitempty"`
	HomeChannelFrom string `json:"home_channel_from,omitempty"`
}

type WeixinSendRequest struct {
	Text       string
	MediaPaths []string
}

type InstallStatus struct {
	Installed   bool   `json:"installed"`
	HermesBin   string `json:"hermes_bin,omitempty"`
	HermesHome  string `json:"hermes_home,omitempty"`
	ConfigFound bool   `json:"config_found"`
}

type hermesConfigYAML struct {
	Platforms struct {
		Weixin struct {
			Token string         `yaml:"token"`
			Extra map[string]any `yaml:"extra"`
		} `yaml:"weixin"`
	} `yaml:"platforms"`
}

type weixinAccountFile struct {
	AccountID string `json:"account_id"`
	Token     string `json:"token"`
	BaseURL   string `json:"base_url"`
	UserID    string `json:"user_id"`
}

type channelDirectory struct {
	Platforms map[string][]channelDirectoryEntry `json:"platforms"`
}

type channelDirectoryEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

func DiscoverWeixinConfig() (*WeixinConfig, error) {
	for _, home := range hermesHomeCandidates() {
		cfg, err := loadWeixinConfig(home)
		if err == nil {
			return cfg, nil
		}
	}
	return nil, fmt.Errorf("未找到可用的 Hermes Weixin 配置（需要 HERMES_HOME 或 ~/.hermes 下存在 WEIXIN_HOME_CHANNEL、account_id、token）")
}

func DiscoverWeixinConfigAt(hermesHome string) (*WeixinConfig, error) {
	hermesHome = strings.TrimSpace(hermesHome)
	if hermesHome == "" {
		return DiscoverWeixinConfig()
	}
	return loadWeixinConfig(hermesHome)
}

func DetectInstallation() InstallStatus {
	status := InstallStatus{}
	if bin, err := exec.LookPath("hermes"); err == nil {
		status.Installed = true
		status.HermesBin = bin
	}
	for _, home := range hermesHomeCandidates() {
		if _, err := os.Stat(home); err == nil {
			status.ConfigFound = true
			if status.HermesHome == "" {
				status.HermesHome = home
			}
		}
	}
	if status.HermesHome == "" {
		candidates := hermesHomeCandidates()
		if len(candidates) > 0 {
			status.HermesHome = candidates[0]
		}
	}
	return status
}

func SaveWeixinConfig(input WeixinConfig) (*WeixinConfig, error) {
	home := strings.TrimSpace(input.HermesHome)
	if home == "" {
		status := DetectInstallation()
		home = strings.TrimSpace(status.HermesHome)
	}
	if home == "" {
		return nil, fmt.Errorf("未找到 Hermes Home，无法保存微信配置")
	}
	if err := os.MkdirAll(home, 0o755); err != nil {
		return nil, err
	}
	envPath := filepath.Join(home, ".env")
	updates := map[string]string{
		"WEIXIN_HOME_CHANNEL":      strings.TrimSpace(input.HomeChannel),
		"WEIXIN_HOME_CHANNEL_NAME": strings.TrimSpace(input.HomeChannelName),
		"WEIXIN_ACCOUNT_ID":        strings.TrimSpace(input.AccountID),
		"WEIXIN_TOKEN":             strings.TrimSpace(input.Token),
		"WEIXIN_BASE_URL":          strings.TrimSpace(input.BaseURL),
		"WEIXIN_CDN_BASE_URL":      strings.TrimSpace(input.CdnBaseURL),
	}
	if strings.TrimSpace(updates["WEIXIN_BASE_URL"]) == "" {
		updates["WEIXIN_BASE_URL"] = WeixinDefaultBaseURL
	}
	if err := upsertEnvFile(envPath, updates); err != nil {
		return nil, err
	}
	return DiscoverWeixinConfigAt(home)
}

func NewHTTPClient() *http.Client {
	return &http.Client{Timeout: 12 * time.Second}
}

func SendWeixinText(client *http.Client, cfg *WeixinConfig, text string) error {
	return SendWeixin(client, cfg, WeixinSendRequest{Text: text})
}

func SendWeixin(client *http.Client, cfg *WeixinConfig, req WeixinSendRequest) error {
	req.Text = strings.TrimSpace(req.Text)
	req.MediaPaths = compactMediaPaths(req.MediaPaths)
	if req.Text == "" && len(req.MediaPaths) == 0 {
		return nil
	}
	if len(req.MediaPaths) > 0 {
		if err := sendWeixinViaHermesPython(cfg, req); err != nil {
			return err
		}
		return nil
	}
	return sendWeixinTextDirect(client, cfg, req.Text)
}

func sendWeixinTextDirect(client *http.Client, cfg *WeixinConfig, text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	payload := map[string]any{
		"msg": map[string]any{
			"from_user_id":  "",
			"to_user_id":    cfg.HomeChannel,
			"client_id":     uuid.NewString(),
			"message_type":  2,
			"message_state": 2,
			"item_list":     []map[string]any{{"type": 1, "text_item": map[string]any{"text": text}}},
		},
	}
	if contextToken := loadContextToken(cfg.HermesHome, cfg.AccountID, cfg.HomeChannel); contextToken != "" {
		payload["msg"].(map[string]any)["context_token"] = contextToken
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	url := strings.TrimRight(cfg.BaseURL, "/") + "/" + weixinSendMessageEP
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("AuthorizationType", "ilink_bot_token")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	req.Header.Set("X-WECHAT-UIN", randomWeixinUIN())
	req.Header.Set("iLink-App-Id", weixinAppID)
	req.Header.Set("iLink-App-ClientVersion", fmt.Sprintf("%d", weixinAppClientVersion))

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("weixin send failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if len(bytes.TrimSpace(respBody)) == 0 {
		return nil
	}
	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil
	}
	if errCode, ok := numberToInt(result["errcode"]); ok && errCode != 0 {
		return fmt.Errorf("weixin send failed: errcode=%d errmsg=%v", errCode, result["errmsg"])
	}
	if ret, ok := numberToInt(result["ret"]); ok && ret != 0 {
		return fmt.Errorf("weixin send failed: ret=%d errmsg=%v", ret, result["errmsg"])
	}
	return nil
}

func compactMediaPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := map[string]struct{}{}
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	return out
}

func hermesHomeCandidates() []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 4)
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}

	add(os.Getenv("HERMES_HOME"))
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		root := filepath.Join(home, ".hermes")
		add(root)
		profilesDir := filepath.Join(root, "profiles")
		if entries, err := os.ReadDir(profilesDir); err == nil {
			names := make([]string, 0, len(entries))
			for _, entry := range entries {
				if entry.IsDir() {
					names = append(names, entry.Name())
				}
			}
			sort.Strings(names)
			for _, name := range names {
				add(filepath.Join(profilesDir, name))
			}
		}
	}
	return out
}

func loadWeixinConfig(hermesHome string) (*WeixinConfig, error) {
	cfg := &WeixinConfig{
		HermesHome: hermesHome,
		BaseURL:    WeixinDefaultBaseURL,
		CdnBaseURL: "https://novac2c.cdn.weixin.qq.com/c2c",
	}

	envPath := filepath.Join(hermesHome, ".env")
	envMap, err := parseEnvFile(envPath)
	if err == nil {
		cfg.EnvFile = envPath
	}
	cfg.HomeChannel = strings.TrimSpace(envMap["WEIXIN_HOME_CHANNEL"])
	cfg.HomeChannelName = strings.TrimSpace(envMap["WEIXIN_HOME_CHANNEL_NAME"])
	if cfg.HomeChannel != "" {
		cfg.HomeChannelFrom = ".env"
	}
	cfg.AccountID = strings.TrimSpace(envMap["WEIXIN_ACCOUNT_ID"])
	cfg.Token = strings.TrimSpace(envMap["WEIXIN_TOKEN"])
	if baseURL := strings.TrimSpace(envMap["WEIXIN_BASE_URL"]); baseURL != "" {
		cfg.BaseURL = strings.TrimRight(baseURL, "/")
	}
	if cdnBaseURL := strings.TrimSpace(envMap["WEIXIN_CDN_BASE_URL"]); cdnBaseURL != "" {
		cfg.CdnBaseURL = strings.TrimRight(cdnBaseURL, "/")
	}

	configPath := filepath.Join(hermesHome, "config.yaml")
	yamlCfg, err := parseHermesConfigYAML(configPath)
	if err == nil {
		cfg.ConfigFile = configPath
		extra := yamlCfg.Platforms.Weixin.Extra
		if cfg.Token == "" {
			cfg.Token = strings.TrimSpace(yamlCfg.Platforms.Weixin.Token)
		}
		if cfg.AccountID == "" {
			cfg.AccountID = strings.TrimSpace(anyToString(extra["account_id"]))
		}
		if cfg.Token == "" {
			cfg.Token = strings.TrimSpace(anyToString(extra["token"]))
		}
		if cfg.BaseURL == "" || cfg.BaseURL == WeixinDefaultBaseURL {
			if baseURL := strings.TrimSpace(anyToString(extra["base_url"])); baseURL != "" {
				cfg.BaseURL = strings.TrimRight(baseURL, "/")
			}
		}
		if cfg.CdnBaseURL == "" || cfg.CdnBaseURL == "https://novac2c.cdn.weixin.qq.com/c2c" {
			if cdnBaseURL := strings.TrimSpace(anyToString(extra["cdn_base_url"])); cdnBaseURL != "" {
				cfg.CdnBaseURL = strings.TrimRight(cdnBaseURL, "/")
			}
		}
	}

	accountFile, accountCfg, err := loadWeixinAccountFile(hermesHome, cfg.AccountID)
	if err == nil && accountCfg != nil {
		cfg.AccountFile = accountFile
		if cfg.AccountID == "" {
			cfg.AccountID = strings.TrimSpace(accountCfg.AccountID)
		}
		if cfg.Token == "" {
			cfg.Token = strings.TrimSpace(accountCfg.Token)
		}
		if cfg.BaseURL == "" || cfg.BaseURL == WeixinDefaultBaseURL {
			if baseURL := strings.TrimSpace(accountCfg.BaseURL); baseURL != "" {
				cfg.BaseURL = strings.TrimRight(baseURL, "/")
			}
		}
		if cfg.HomeChannel == "" {
			if userID := strings.TrimSpace(accountCfg.UserID); userID != "" {
				cfg.HomeChannel = userID
				cfg.HomeChannelName = userID
				cfg.HomeChannelFrom = "account.user_id"
			}
		}
	}

	if cfg.HomeChannel == "" {
		channelFile, channelID, channelName, err := loadWeixinHomeChannelFromDirectory(hermesHome)
		if err == nil && strings.TrimSpace(channelID) != "" {
			cfg.ChannelFile = channelFile
			cfg.HomeChannel = strings.TrimSpace(channelID)
			if strings.TrimSpace(channelName) != "" {
				cfg.HomeChannelName = strings.TrimSpace(channelName)
			} else {
				cfg.HomeChannelName = cfg.HomeChannel
			}
			cfg.HomeChannelFrom = "channel_directory"
		}
	}

	if cfg.BaseURL == "" {
		cfg.BaseURL = WeixinDefaultBaseURL
	}
	if strings.TrimSpace(cfg.HomeChannelName) == "" {
		cfg.HomeChannelName = strings.TrimSpace(cfg.HomeChannel)
	}
	switch {
	case cfg.HomeChannel == "":
		return nil, fmt.Errorf("Hermes Weixin 配置缺少 WEIXIN_HOME_CHANNEL")
	case cfg.AccountID == "":
		return nil, fmt.Errorf("Hermes Weixin 配置缺少 WEIXIN_ACCOUNT_ID/account_id")
	case cfg.Token == "":
		return nil, fmt.Errorf("Hermes Weixin 配置缺少 WEIXIN_TOKEN/token")
	default:
		return cfg, nil
	}
}

func loadContextToken(hermesHome, accountID, chatID string) string {
	hermesHome = strings.TrimSpace(hermesHome)
	accountID = strings.TrimSpace(accountID)
	chatID = strings.TrimSpace(chatID)
	if hermesHome == "" || accountID == "" || chatID == "" {
		return ""
	}
	path := filepath.Join(hermesHome, "weixin", "accounts", accountID+".context-tokens.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var payload map[string]string
	if err := json.Unmarshal(data, &payload); err != nil {
		return ""
	}
	return strings.TrimSpace(payload[chatID])
}

func parseEnvFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	out := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		out[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func upsertEnvFile(path string, updates map[string]string) error {
	existingLines := []string{}
	if data, err := os.ReadFile(path); err == nil {
		existingLines = strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	}
	keys := make([]string, 0, len(updates))
	for key := range updates {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	seen := map[string]bool{}
	out := make([]string, 0, len(existingLines)+len(updates))
	for _, line := range existingLines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			out = append(out, line)
			continue
		}
		prefix := trimmed
		if strings.HasPrefix(prefix, "export ") {
			prefix = strings.TrimSpace(strings.TrimPrefix(prefix, "export "))
		}
		key, _, ok := strings.Cut(prefix, "=")
		if !ok {
			out = append(out, line)
			continue
		}
		key = strings.TrimSpace(key)
		value, shouldManage := updates[key]
		if !shouldManage {
			out = append(out, line)
			continue
		}
		seen[key] = true
		out = append(out, key+"="+quoteEnvValue(value))
	}
	for _, key := range keys {
		if seen[key] {
			continue
		}
		out = append(out, key+"="+quoteEnvValue(updates[key]))
	}
	content := strings.Join(out, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func parseHermesConfigYAML(path string) (*hermesConfigYAML, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg hermesConfigYAML
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func loadWeixinHomeChannelFromDirectory(hermesHome string) (string, string, string, error) {
	path := filepath.Join(hermesHome, "channel_directory.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", "", err
	}
	var directory channelDirectory
	if err := json.Unmarshal(data, &directory); err != nil {
		return "", "", "", err
	}
	entries := directory.Platforms["weixin"]
	for _, entry := range entries {
		id := strings.TrimSpace(entry.ID)
		if id == "" {
			continue
		}
		return path, id, strings.TrimSpace(entry.Name), nil
	}
	return path, "", "", fmt.Errorf("no weixin channel in channel_directory")
}

func loadWeixinAccountFile(hermesHome, accountID string) (string, *weixinAccountFile, error) {
	if strings.TrimSpace(accountID) != "" {
		path := filepath.Join(hermesHome, "weixin", "accounts", accountID+".json")
		account, err := parseWeixinAccountFile(path)
		return path, account, err
	}
	dir := filepath.Join(hermesHome, "weixin", "accounts")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".json") {
			continue
		}
		if strings.Contains(name, ".context-tokens.") || strings.Contains(name, ".sync.") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(dir, name)
		account, err := parseWeixinAccountFile(path)
		if err == nil && account != nil && strings.TrimSpace(account.Token) != "" {
			return path, account, nil
		}
	}
	return "", nil, fmt.Errorf("未找到可用的 Hermes Weixin account 文件")
}

func parseWeixinAccountFile(path string) (*weixinAccountFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg weixinAccountFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.Token) == "" && strings.TrimSpace(cfg.AccountID) == "" {
		return nil, fmt.Errorf("empty account file")
	}
	return &cfg, nil
}

func anyToString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case fmt.Stringer:
		return x.String()
	case int:
		return fmt.Sprintf("%d", x)
	case int8:
		return fmt.Sprintf("%d", x)
	case int16:
		return fmt.Sprintf("%d", x)
	case int32:
		return fmt.Sprintf("%d", x)
	case int64:
		return fmt.Sprintf("%d", x)
	case uint:
		return fmt.Sprintf("%d", x)
	case uint8:
		return fmt.Sprintf("%d", x)
	case uint16:
		return fmt.Sprintf("%d", x)
	case uint32:
		return fmt.Sprintf("%d", x)
	case uint64:
		return fmt.Sprintf("%d", x)
	case float32:
		return fmt.Sprintf("%.0f", x)
	case float64:
		return fmt.Sprintf("%.0f", x)
	default:
		return ""
	}
}

func quoteEnvValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return `""`
	}
	if strings.ContainsAny(v, " #\"'") {
		return `"` + strings.ReplaceAll(v, `"`, `\"`) + `"`
	}
	return v
}

func numberToInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int8:
		return int64(x), true
	case int16:
		return int64(x), true
	case int32:
		return int64(x), true
	case int64:
		return x, true
	case uint:
		return int64(x), true
	case uint8:
		return int64(x), true
	case uint16:
		return int64(x), true
	case uint32:
		return int64(x), true
	case uint64:
		if x > math.MaxInt64 {
			return 0, false
		}
		return int64(x), true
	case float32:
		return int64(x), true
	case float64:
		return int64(x), true
	default:
		return 0, false
	}
}

func randomWeixinUIN() string {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "0"
	}
	return fmt.Sprintf("%d", binary.BigEndian.Uint32(buf[:]))
}
