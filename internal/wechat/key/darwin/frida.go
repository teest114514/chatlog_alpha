//go:build darwin

package darwin

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	"github.com/sjzar/chatlog/internal/wechat/decrypt/common"
	keyshared "github.com/sjzar/chatlog/internal/wechat/key/shared"
	"github.com/sjzar/chatlog/internal/wechat/model"
)

const (
	defaultFridaTimeout = 180 * time.Second
	fridaCleanupGrace   = 3 * time.Second
	fridaExitGrace      = 2 * time.Second
	defaultWeChatExe    = "/Applications/WeChat.app/Contents/MacOS/WeChat"
	fridaScriptFileName = "wechat_key_frida.py"
)

// FridaAvailable reports whether python3 + frida can be used for key capture.
func FridaAvailable() bool {
	py, err := findPython3()
	if err != nil {
		return false
	}
	cmd := exec.Command(py, "-c", "import frida; print(frida.__version__)")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != ""
}

// ExtractKeyViaFrida is the compatibility wrapper for callers that only need
// the primary message-database key.
func ExtractKeyViaFrida(ctx context.Context, dataDir string, status func(string)) (string, error) {
	primary, _, err := ExtractKeysViaFrida(ctx, dataDir, status)
	return primary, err
}

// ExtractKeysViaFrida launches WeChat via LaunchServices (`open -a`), attaches
// Frida ASAP, hooks CCKeyDerivationPBKDF, briefly collects every 32-byte DB
// password, validates each candidate against db_storage, and writes per-DB
// mappings to all_keys.json.
//
// Why not frida.spawn(raw binary)? Spawning the executable bypasses macOS
// LaunchServices / sandbox container setup, so WeChat often starts with an
// empty profile instead of ~/Library/Containers/com.tencent.xinWeChat/...
//
// status may be nil. dataDir may be empty at start (filled after login); when
// empty, the key is still returned if captured, but all_keys.json is only
// written when a dataDir can be resolved and at least one DB validates.
func ExtractKeysViaFrida(ctx context.Context, dataDir string, status func(string)) (string, []CapturedDBKey, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if status != nil {
		status("[1/6] 检查 Frida 环境")
	}
	if !FridaAvailable() {
		return "", nil, fmt.Errorf("Frida 不可用：请先执行 pip3 install frida-tools")
	}

	scriptPath, cleanup, err := resolveFridaScript()
	if err != nil {
		return "", nil, err
	}
	if cleanup != nil {
		defer cleanup()
	}

	exe := strings.TrimSpace(os.Getenv("WECHAT_EXE"))
	if exe == "" {
		exe = defaultWeChatExe
	}
	if st, err := os.Stat(exe); err != nil || st.IsDir() {
		return "", nil, fmt.Errorf("未找到微信可执行文件: %s", exe)
	}

	timeout := defaultFridaTimeout
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem > 5*time.Second {
			timeout = rem
		}
	}

	py, err := findPython3()
	if err != nil {
		return "", nil, err
	}

	// Default --mode open: open -a WeChat (sandbox container / user data intact)
	// then attach. Override with CHATLOG_FRIDA_MODE=spawn only if you accept empty profile.
	mode := strings.TrimSpace(os.Getenv("CHATLOG_FRIDA_MODE"))
	if mode == "" {
		mode = "open"
	}
	args := []string{
		scriptPath,
		"--mode", mode,
		"--json",
		"--timeout", fmt.Sprintf("%d", int(timeout.Seconds())),
		"--exe", exe,
	}
	cmd := exec.CommandContext(ctx, py, args...)
	// Ensure child is not left in a broken root-only environment when possible.
	cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", nil, fmt.Errorf("创建 Frida 输出管道失败: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", nil, fmt.Errorf("创建 Frida 错误管道失败: %w", err)
	}

	if status != nil {
		if mode == "open" {
			status("[2/6] 正在重启并通过 LaunchServices 启动微信")
		} else {
			status(fmt.Sprintf("[2/6] 正在通过 Frida mode=%s 定位微信进程", mode))
		}
	}
	log.Info().Str("script", scriptPath).Str("exe", exe).Str("mode", mode).Msg("starting frida key capture")

	if err := cmd.Start(); err != nil {
		return "", nil, fmt.Errorf("启动 Frida 脚本失败: %w", err)
	}
	var closeOutputOnce sync.Once
	closeInjectorOutput := func() {
		closeOutputOnce.Do(func() {
			// A Frida helper may inherit the pipe. Closing our read end after the
			// structured cleanup event guarantees Scanner cannot wait on it.
			_ = stdout.Close()
		})
	}
	var stopInjectorOnce sync.Once
	stopInjectorHost := func(reason string) {
		stopInjectorOnce.Do(func() {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			closeInjectorOutput()
			log.Debug().Str("reason", reason).Msg("stopped frida injector host")
		})
	}
	contextMonitorDone := make(chan struct{})
	defer close(contextMonitorDone)
	if ctxDone := ctx.Done(); ctxDone != nil {
		go func() {
			select {
			case <-ctxDone:
				stopInjectorHost("context canceled")
			case <-contextMonitorDone:
			}
		}()
	}

	// Drain stderr so the process cannot block on a full pipe.
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			log.Debug().Str("frida_stderr", line).Msg("frida")
			if status != nil && (strings.Contains(line, "ERROR") || strings.Contains(line, "error")) {
				status("Frida: " + line)
			}
		}
	}()

	var (
		capturedKey        string
		capturedCandidates []CapturedDBKey
		candidateSeen      = make(map[string]struct{})
		lastErr            string
		cleanupTimer       *time.Timer
	)
	appendCandidate := func(msg fridaMsg) bool {
		key := strings.ToLower(strings.TrimSpace(msg.Key))
		if len(key) != 64 {
			return false
		}
		if _, err := hex.DecodeString(key); err != nil {
			return false
		}
		salt := strings.ToLower(strings.TrimSpace(msg.Salt))
		signature := key + "|" + salt
		if _, ok := candidateSeen[signature]; ok {
			return false
		}
		candidateSeen[signature] = struct{}{}
		capturedCandidates = append(capturedCandidates, CapturedDBKey{
			Key:        key,
			DerivedKey: strings.ToLower(strings.TrimSpace(msg.DerivedKey)),
			Salt:       salt,
			Rounds:     msg.Rounds,
			Len:        msg.Len,
			DerivedLen: msg.DerivedLen,
			PRF:        msg.PRF,
			Algorithm:  msg.Algorithm,
		})
		if capturedKey == "" {
			capturedKey = key
		}
		return true
	}
	sc := bufio.NewScanner(stdout)
	// keys are short JSON lines; allow larger just in case
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var msg fridaMsg
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			log.Debug().Str("line", line).Msg("frida non-json line")
			continue
		}
		switch msg.Type {
		case "log", "status":
			if status != nil && msg.Message != "" {
				status(msg.Message)
			}
		case "cleanup":
			if status != nil {
				status("[5/6] Frida Hook、会话和运行时均已释放")
			}
			if capturedKey != "" {
				// The structured event is emitted only after script unload, session
				// detach, and frida.shutdown. Close the potentially inherited pipe,
				// then allow Python to perform its immediate os._exit. Kill it only
				// if that bounded exit still fails.
				closeInjectorOutput()
				if cleanupTimer != nil {
					cleanupTimer.Stop()
				}
				cleanupTimer = time.AfterFunc(fridaExitGrace, func() {
					log.Warn().Msg("frida host exit grace expired; forcing injector host shutdown")
					stopInjectorHost("host exit grace expired")
				})
			}
		case "error":
			if msg.Message != "" {
				lastErr = msg.Message
				if status != nil {
					status("Frida: " + msg.Message)
				}
			}
		case "key":
			if appendCandidate(msg) && status != nil {
				status(fmt.Sprintf("[4/6] 已捕获 %d 条数据库密钥候选，继续短时收集其他数据库密钥", len(capturedCandidates)))
			}
		case "done":
			_ = appendCandidate(msg)
			key := strings.ToLower(strings.TrimSpace(msg.Key))
			if len(key) == 64 {
				if _, err := hex.DecodeString(key); err == nil {
					capturedKey = key
				}
			}
			if capturedKey != "" {
				if status != nil {
					status(fmt.Sprintf("[5/6] 候选收集完成（%d 条），正在卸载 Frida Hook", len(capturedCandidates)))
				}
				// Start the fallback only after Python reports collection complete.
				// Starting it on the first key would cut off per-database keys.
				if cleanupTimer == nil {
					cleanupTimer = time.AfterFunc(fridaCleanupGrace, func() {
						log.Warn().Msg("frida cleanup grace expired; forcing injector host shutdown")
						stopInjectorHost("cleanup grace expired")
					})
				}
			}
		}
	}
	scanErr := sc.Err()

	// Wait may return "signal: killed" if bounded cleanup needed its fallback.
	waitErr := cmd.Wait()
	if cleanupTimer != nil {
		cleanupTimer.Stop()
	}
	if capturedKey == "" {
		if lastErr != "" {
			return "", nil, fmt.Errorf("Frida 未捕获到密钥: %s", lastErr)
		}
		if scanErr != nil {
			return "", nil, fmt.Errorf("读取 Frida 输出失败: %w", scanErr)
		}
		if waitErr != nil {
			return "", nil, fmt.Errorf("Frida 提 key 失败: %w", waitErr)
		}
		return "", nil, fmt.Errorf("Frida 未捕获到密钥（请登录微信并打开聊天窗口后重试）")
	}
	_ = waitErr
	if status != nil {
		status("[6/6] 正在验证数据库密钥并保存配置")
	}

	// Optional: persist all_keys.json when dataDir is known.
	if dataDir != "" {
		if n, err := writeAllKeysFromCapturedKeys(dataDir, capturedCandidates, status); err != nil {
			log.Warn().Err(err).Msg("write all_keys.json from frida keys failed")
			if status != nil {
				status(fmt.Sprintf("候选密钥已捕获但写入 all_keys.json 失败: %v（仍返回主密钥）", err))
			}
		} else if status != nil {
			status(fmt.Sprintf("[6/6] 逐库校验完成，已写入 all_keys.json（%d 条有效映射）", n))
		}
	}

	return capturedKey, capturedCandidates, nil
}

// ApplyCapturedKeyToDataDir validates a key against DBs under dataDir and writes all_keys.json.
func ApplyCapturedKeyToDataDir(dataDir, keyHex string, status func(string)) (string, int, error) {
	return ApplyCapturedKeysToDataDir(dataDir, []CapturedDBKey{{Key: keyHex}}, status)
}

// ApplyCapturedKeysToDataDir validates each captured candidate against every DB
// and writes only verified per-database mappings. Existing verified mappings are
// retained, so a refresh cannot destroy a special-purpose DB key that was not
// observed during this short capture window.
func ApplyCapturedKeysToDataDir(dataDir string, candidates []CapturedDBKey, status func(string)) (string, int, error) {
	candidates = normalizeCapturedKeys(candidates)
	if len(candidates) == 0 {
		return "", 0, fmt.Errorf("没有有效的数据库密钥候选")
	}
	n, err := writeAllKeysFromCapturedKeys(dataDir, candidates, status)
	if err != nil {
		return "", 0, err
	}
	key, err := loadAndValidateMessageKey(dataDir, status)
	if err != nil {
		// Still return the captured key if message preference failed but file was written.
		if n > 0 {
			return candidates[0].Key, n, nil
		}
		return "", n, err
	}
	return key, n, nil
}

type fridaMsg struct {
	Type       string `json:"type"`
	Message    string `json:"message"`
	Key        string `json:"key"`
	DerivedKey string `json:"derived_key"`
	Salt       string `json:"salt"`
	Rounds     int    `json:"rounds"`
	Len        int    `json:"len"`
	DerivedLen int    `json:"dk_len"`
	PRF        int    `json:"prf"`
	Algorithm  int    `json:"algo"`
	Count      int    `json:"count"`
	UniqueKeys int    `json:"unique_keys"`
}

func normalizeCapturedKeys(candidates []CapturedDBKey) []CapturedDBKey {
	result := make([]CapturedDBKey, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		candidate.Key = strings.ToLower(strings.TrimSpace(candidate.Key))
		candidate.Salt = strings.ToLower(strings.TrimSpace(candidate.Salt))
		candidate.DerivedKey = strings.ToLower(strings.TrimSpace(candidate.DerivedKey))
		if len(candidate.Key) != 64 {
			continue
		}
		if decoded, err := hex.DecodeString(candidate.Key); err != nil || len(decoded) != 32 {
			continue
		}
		signature := candidate.Key + "|" + candidate.Salt
		if _, ok := seen[signature]; ok {
			continue
		}
		seen[signature] = struct{}{}
		result = append(result, candidate)
	}
	return result
}

type candidateKey struct {
	key      string
	salt     string
	captured bool
}

func writeAllKeysFromCapturedKeys(dataDir string, captured []CapturedDBKey, status func(string)) (int, error) {
	captured = normalizeCapturedKeys(captured)
	if len(captured) == 0 {
		return 0, fmt.Errorf("没有有效的数据库密钥候选")
	}
	accountDir, dbStorageDir := resolveDBDirs(dataDir)
	dbSalts, err := collectDBSalts(dbStorageDir)
	if err != nil {
		return 0, err
	}
	if len(dbSalts) == 0 {
		return 0, fmt.Errorf("未找到可用加密数据库（db_storage）")
	}

	d, err := decrypt.NewDecryptor(model.PlatformDarwin, 4)
	if err != nil {
		return 0, err
	}

	keysPath := filepath.Join(accountDir, "all_keys.json")
	existing := readExistingKeyMap(keysPath)
	allCandidates := make([]candidateKey, 0, len(captured)+len(existing))
	for _, candidate := range captured {
		allCandidates = append(allCandidates, candidateKey{
			key:      candidate.Key,
			salt:     candidate.Salt,
			captured: true,
		})
	}
	for _, key := range existing {
		allCandidates = append(allCandidates, candidateKey{key: key})
	}

	out := make(map[string]keyFileEntry, len(dbSalts))
	validatedCaptured := 0
	preservedUnreadable := 0
	unmatched := make([]string, 0)
	for _, ds := range dbSalts {
		dbRel := keyshared.NormalizeDBPath(ds.DBRel)
		dbPath := resolveDBPath(dataDir, dbRel)
		dbInfo, openErr := common.OpenDBFile(dbPath, 4096)
		if openErr != nil {
			// Do not erase a prior mapping merely because a DB is temporarily
			// truncated, locked, or unreadable during WeChat startup.
			if oldKey := normalizeHexKey(existing[dbRel]); oldKey != "" {
				out[dbRel] = keyFileEntry{EncKey: oldKey}
				preservedUnreadable++
			}
			continue
		}

		ordered := orderCandidatesForDB(allCandidates, existing[dbRel], ds.SaltHex)
		matched := false
		for _, candidate := range ordered {
			keyBytes, decodeErr := hex.DecodeString(candidate.key)
			if decodeErr != nil || len(keyBytes) != 32 || !d.Validate(dbInfo.FirstPage, keyBytes) {
				continue
			}
			out[dbRel] = keyFileEntry{EncKey: candidate.key}
			if candidate.captured {
				validatedCaptured++
			}
			matched = true
			break
		}
		if !matched {
			unmatched = append(unmatched, dbRel)
		}
	}

	if len(out) == 0 {
		return 0, fmt.Errorf("候选密钥未通过任何数据库页校验，未修改 all_keys.json")
	}
	if status != nil {
		status(fmt.Sprintf("逐库校验：%d 个数据库已匹配（本次候选命中 %d 个）", len(out), validatedCaptured))
		if preservedUnreadable > 0 {
			status(fmt.Sprintf("另有 %d 个暂不可读数据库保留原有映射", preservedUnreadable))
		}
		if len(unmatched) > 0 {
			shown := unmatched
			if len(shown) > 4 {
				shown = shown[:4]
			}
			detail := strings.Join(shown, "、")
			if len(shown) < len(unmatched) {
				detail += " 等"
			}
			status(fmt.Sprintf("仍有 %d 个数据库未匹配（%s）；不会写入未经验证的密钥", len(unmatched), detail))
		}
	}

	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("序列化 all_keys.json 失败: %w", err)
	}
	if err := writeFileAtomic(keysPath, raw, 0600); err != nil {
		return 0, fmt.Errorf("写入 %s 失败: %w", keysPath, err)
	}
	if err := normalizeAllKeysOwnership(keysPath); err != nil && status != nil {
		status(fmt.Sprintf("警告：all_keys.json 权限归一化失败：%v", err))
	}
	return len(out), nil
}

func normalizeHexKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	if len(key) != 64 {
		return ""
	}
	decoded, err := hex.DecodeString(key)
	if err != nil || len(decoded) != 32 {
		return ""
	}
	return key
}

func readExistingKeyMap(path string) map[string]string {
	content, err := os.ReadFile(path)
	if err != nil {
		return map[string]string{}
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(content, &raw); err != nil {
		return map[string]string{}
	}
	result := make(map[string]string, len(raw))
	for dbPath, value := range raw {
		var key string
		if err := json.Unmarshal(value, &key); err != nil {
			var entry keyFileEntry
			if err := json.Unmarshal(value, &entry); err != nil {
				continue
			}
			key = entry.EncKey
		}
		if key = normalizeHexKey(key); key != "" {
			result[keyshared.NormalizeDBPath(dbPath)] = key
		}
	}
	return result
}

func orderCandidatesForDB(candidates []candidateKey, existingKey, salt string) []candidateKey {
	salt = strings.ToLower(strings.TrimSpace(salt))
	existingKey = normalizeHexKey(existingKey)
	result := make([]candidateKey, 0, len(candidates)+1)
	seen := make(map[string]struct{}, len(candidates)+1)
	appendKey := func(candidate candidateKey) {
		candidate.key = normalizeHexKey(candidate.key)
		if candidate.key == "" {
			return
		}
		if _, ok := seen[candidate.key]; ok {
			return
		}
		seen[candidate.key] = struct{}{}
		result = append(result, candidate)
	}
	// A PBKDF call carrying this DB's page salt is the strongest candidate.
	for _, candidate := range candidates {
		if candidate.captured && candidate.salt != "" && candidate.salt == salt {
			appendKey(candidate)
		}
	}
	// Preserve a previously verified path-specific mapping before trying
	// unrelated historical keys.
	if existingKey != "" {
		appendKey(candidateKey{key: existingKey})
	}
	for _, candidate := range candidates {
		appendKey(candidate)
	}
	return result
}

func writeFileAtomic(path string, content []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	tmp, err := os.CreateTemp(directory, ".all_keys_*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func findPython3() (string, error) {
	candidates := []string{"python3", "python"}
	for _, c := range candidates {
		if p, err := exec.LookPath(c); err == nil {
			// Prefer a python that can import nothing at least runs.
			return p, nil
		}
	}
	return "", fmt.Errorf("未找到 python3")
}

func resolveFridaScript() (path string, cleanup func(), err error) {
	// 1) Explicit env
	if p := strings.TrimSpace(os.Getenv("CHATLOG_FRIDA_SCRIPT")); p != "" {
		if st, e := os.Stat(p); e == nil && !st.IsDir() {
			return p, nil, nil
		}
	}

	// 2) Next to executable / cwd / repo scripts/
	search := []string{}
	if exe, e := os.Executable(); e == nil {
		dir := filepath.Dir(exe)
		search = append(search,
			filepath.Join(dir, "scripts", fridaScriptFileName),
			filepath.Join(dir, fridaScriptFileName),
		)
	}
	if wd, e := os.Getwd(); e == nil {
		search = append(search,
			filepath.Join(wd, "scripts", fridaScriptFileName),
			filepath.Join(wd, fridaScriptFileName),
		)
	}
	// walk up a few levels from cwd (dev: repo root)
	if wd, e := os.Getwd(); e == nil {
		cur := wd
		for i := 0; i < 5; i++ {
			search = append(search, filepath.Join(cur, "scripts", fridaScriptFileName))
			parent := filepath.Dir(cur)
			if parent == cur {
				break
			}
			cur = parent
		}
	}
	for _, p := range search {
		if st, e := os.Stat(p); e == nil && !st.IsDir() {
			return p, nil, nil
		}
	}

	// 3) Materialize embedded script to temp file
	tmp, e := os.CreateTemp("", "chatlog_wechat_key_frida_*.py")
	if e != nil {
		return "", nil, fmt.Errorf("创建临时 Frida 脚本失败: %w", e)
	}
	if _, e := io.WriteString(tmp, embeddedFridaScript); e != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", nil, fmt.Errorf("写入临时 Frida 脚本失败: %w", e)
	}
	if e := tmp.Close(); e != nil {
		os.Remove(tmp.Name())
		return "", nil, e
	}
	if e := os.Chmod(tmp.Name(), 0700); e != nil {
		os.Remove(tmp.Name())
		return "", nil, e
	}
	return tmp.Name(), func() { _ = os.Remove(tmp.Name()) }, nil
}
