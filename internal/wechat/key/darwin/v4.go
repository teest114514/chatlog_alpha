package darwin

import (
	"context"
	"crypto/aes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	"github.com/sjzar/chatlog/internal/wechat/model"
	"github.com/sjzar/chatlog/pkg/util/dat2img"
)

type V4Extractor struct {
	validator *decrypt.Validator
}

func NewV4Extractor() *V4Extractor {
	return &V4Extractor{}
}

func (e *V4Extractor) Extract(ctx context.Context, proc *model.Process) (string, string, error) {
	statusCB, _ := ctx.Value("status_callback").(func(string))
	imageOnly, _ := ctx.Value("image_key_only").(bool)
	forceRescan, _ := ctx.Value("force_rescan_memory").(bool)
	if proc == nil || proc.DataDir == "" {
		return "", "", fmt.Errorf("macOS 数据目录未就绪，请确保微信已登录")
	}

	// 1) 非强制模式：优先使用已有 all_keys.json（wx-cli 模式）。
	if !forceRescan {
		if statusCB != nil {
			statusCB("检查 all_keys.json...")
		}
		if key, err := loadAndValidateMessageKey(proc.DataDir, statusCB); err == nil && key != "" {
			if statusCB != nil {
				statusCB("已从 all_keys.json 获取密钥")
			}
			imgKey, err := e.pickImageKeyWithTiming(ctx, proc, statusCB, imageOnly)
			if err != nil {
				return "", "", err
			}
			return strings.ToLower(key), imgKey, nil
		}
	} else {
		if statusCB != nil {
			statusCB("已启用强制重扫：跳过旧 all_keys.json，重新扫描进程内存...")
		}
		_ = removeAllKeysFile(proc.DataDir)
	}

	// 2) 不存在/无效时，执行一次 init 风格全库扫描并落盘 all_keys.json。
	if statusCB != nil {
		statusCB("开始 init 风格扫描：收集 DB salt -> 内存扫描 -> 写入 all_keys.json")
	}
	key, _, err := InitAllKeysByPID(proc.PID, proc.DataDir, statusCB)
	if err != nil {
		return "", "", err
	}
	if forceRescan && statusCB != nil {
		statusCB("本轮已完成内存重扫，all_keys.json 已更新，正在选取可用密钥...")
	}
	imgKey, err := e.pickImageKeyWithTiming(ctx, proc, statusCB, imageOnly)
	if err != nil {
		return "", "", err
	}
	return strings.ToLower(key), imgKey, nil
}

func removeAllKeysFile(dataDir string) error {
	accountDir, _ := resolveDBDirs(dataDir)
	paths := []string{
		filepath.Join(accountDir, "all_keys.json"),
		filepath.Join(dataDir, "all_keys.json"),
	}
	var lastErr error
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			lastErr = err
		}
	}
	return lastErr
}

func (e *V4Extractor) SearchKey(ctx context.Context, memory []byte) (string, bool) {
	_ = ctx
	_ = memory
	return "", false
}

func (e *V4Extractor) SetValidate(validator *decrypt.Validator) {
	e.validator = validator
}

func (e *V4Extractor) pickImageKeyWithTiming(ctx context.Context, proc *model.Process, status func(string), imageOnly bool) (string, error) {
	// 与 Windows 一致：仅“获取图片密钥”流程执行 60 秒等待/轮询。
	if !imageOnly {
		return e.pickImageKeyWeFlow(proc.PID, proc.DataDir, status)
	}

	if status != nil {
		status("正在查找模板文件...")
	}
	resultTpl, ok := findTemplateData(proc.DataDir, 32)
	ciphertext := resultTpl.Ciphertext
	xorKey := resultTpl.XorKey
	if len(ciphertext) > 0 && xorKey == nil {
		if status != nil {
			status("未找到有效密钥，尝试扫描更多文件...")
		}
		resultTpl, ok = findTemplateData(proc.DataDir, 100)
		if ok {
			xorKey = resultTpl.XorKey
			ciphertext = resultTpl.Ciphertext
		}
	}
	if len(ciphertext) == 0 {
		return "", fmt.Errorf("未找到 V2 模板文件，请先在微信中查看几张图片")
	}
	if xorKey == nil {
		return "", fmt.Errorf("未能从模板文件中计算出有效的 XOR 密钥")
	}
	dat2img.V4XorKey = *xorKey
	if status != nil {
		status(fmt.Sprintf("XOR 密钥: 0x%02x，正在查找微信进程...", *xorKey))
	}
	if key, ok := deriveImageKeyByCodeAndWxid(proc.DataDir, status); ok {
		if status != nil {
			status("通过 kvcomm(code+wxid) 推导并验真成功")
		}
		return key, nil
	}

	deadline := time.Now().Add(60 * time.Second)
	scanRound := 0
	lastPID := uint32(0)
	for {
		if time.Now().After(deadline) {
			return "", fmt.Errorf("60 秒内未找到 AES 密钥")
		}

		currentPID, err := findWeChatPID()
		if err != nil || currentPID == 0 {
			if status != nil {
				status("暂未检测到微信主进程，请确认微信已经重新打开...")
			}
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(2 * time.Second):
				continue
			}
		}
		if currentPID != lastPID {
			lastPID = currentPID
			if status != nil {
				status(fmt.Sprintf("已找到微信进程 PID=%d，正在扫描内存...", currentPID))
			}
		}

		scanRound++
		if status != nil {
			status(fmt.Sprintf("第 %d 次扫描内存，请在微信中打开图片大图...", scanRound))
		}

		imgKey, checked, err := scanImageKeyByWeFlow(currentPID, ciphertext, resultTpl.TemplateData)
		if err != nil {
			log.Debug().Err(err).Msg("扫描图片密钥失败，准备重试")
		}
		if status != nil {
			status(fmt.Sprintf("正在扫描图片密钥... 已检查 %d 个候选字符串", checked))
		}
		if imgKey != "" {
			if status != nil {
				status(fmt.Sprintf("通过字符串扫描找到图片密钥! (在检查了 %d 个候选后)", checked))
			}
			return imgKey, nil
		}

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func findWeChatPID() (uint32, error) {
	if pid, ok := pgrepMaxPID("-x", "WeChat"); ok {
		return pid, nil
	}
	if pid, ok := pgrepMaxPID("-f", "WeChat.app/Contents/MacOS/WeChat"); ok {
		return pid, nil
	}

	out, err := exec.Command("/bin/ps", "-A", "-o", "pid,comm,command").Output()
	if err != nil {
		return 0, fmt.Errorf("failed to get process list: %w", err)
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) > 0 {
		lines = lines[1:]
	}

	type procEntry struct {
		pid     uint32
		comm    string
		command string
	}
	cands := make([]procEntry, 0)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		pid64, err := strconv.ParseUint(parts[0], 10, 32)
		if err != nil || pid64 == 0 {
			continue
		}
		comm := parts[1]
		command := ""
		if len(parts) > 2 {
			command = strings.Join(parts[2:], " ")
		}

		pathMatch := strings.Contains(command, "/Applications/WeChat.app/Contents/MacOS/WeChat") ||
			strings.Contains(command, "/Contents/MacOS/WeChat") ||
			comm == "WeChat"
		if !pathMatch {
			continue
		}

		if strings.Contains(command, "WeChatAppEx.app/") ||
			strings.Contains(command, "/WeChatAppEx") ||
			strings.Contains(command, " WeChatAppEx") ||
			strings.Contains(command, "crashpad_handler") ||
			strings.Contains(command, "Helper") ||
			comm == "WeChat Helper" {
			continue
		}

		cands = append(cands, procEntry{
			pid:     uint32(pid64),
			comm:    comm,
			command: command,
		})
	}
	if len(cands) == 0 {
		return 0, fmt.Errorf("wechat process not found")
	}

	var selected uint32
	for _, c := range cands {
		preferred := strings.Contains(c.command, "/Contents/MacOS/WeChat") || c.comm == "WeChat"
		if !preferred {
			continue
		}
		if c.pid > selected {
			selected = c.pid
		}
	}
	if selected != 0 {
		return selected, nil
	}

	for _, c := range cands {
		if c.pid > selected {
			selected = c.pid
		}
	}
	if selected == 0 {
		return 0, fmt.Errorf("wechat process not found")
	}
	return selected, nil
}

func pgrepMaxPID(flag, pattern string) (uint32, bool) {
	out, err := exec.Command("/usr/bin/pgrep", flag, pattern).Output()
	if err != nil {
		return 0, false
	}
	var maxPID uint32
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pid64, err := strconv.ParseUint(line, 10, 32)
		if err != nil || pid64 == 0 {
			continue
		}
		if uint32(pid64) > maxPID {
			maxPID = uint32(pid64)
		}
	}
	return maxPID, maxPID != 0
}

func (e *V4Extractor) pickImageKeyWeFlow(pid uint32, dataDir string, status func(string)) (string, error) {
	tpl, ok := findTemplateData(dataDir, 32)
	if !ok || len(tpl.Ciphertext) == 0 || tpl.XorKey == nil {
		tpl, ok = findTemplateData(dataDir, 100)
	}
	if !ok || len(tpl.Ciphertext) == 0 || tpl.XorKey == nil {
		return "", nil
	}
	dat2img.V4XorKey = *tpl.XorKey
	if key, ok := deriveImageKeyByCodeAndWxid(dataDir, status); ok {
		if status != nil {
			status("通过 kvcomm(code+wxid) 推导并验真成功")
		}
		return key, nil
	}
	imgKey, checked, err := scanImageKeyByWeFlow(pid, tpl.Ciphertext, tpl.TemplateData)
	if status != nil {
		status(fmt.Sprintf("正在扫描图片密钥... 已检查 %d 个候选字符串", checked))
	}
	if err != nil {
		return "", err
	}
	if imgKey != "" && status != nil {
		status(fmt.Sprintf("通过字符串扫描找到图片密钥! (在检查了 %d 个候选后)", checked))
	}
	return imgKey, nil
}

func scanImageKeyByWeFlow(pid uint32, ciphertext []byte, templateDat []byte) (string, int, error) {
	if key, checked, err := scanImageKeyByPIDAndCiphertext(pid, ciphertext); err == nil || key != "" {
		if key != "" && verifyImageAesKeyStrong([]byte(key), templateDat) {
			return key, checked, nil
		}
	}

	cands, checked, err := scanImageKeyCandidatesByPID(pid)
	if err != nil {
		return "", checked, err
	}
	for _, c := range cands {
		if len(c) < 16 {
			continue
		}
		k := c[:16]
		if verifyImageAesKeyWeFlow([]byte(k), ciphertext) && verifyImageAesKeyStrong([]byte(k), templateDat) {
			return k, checked, nil
		}
	}
	any16, checkedAny16, err := scanImageAny16CandidatesByPID(pid)
	checked += checkedAny16
	if err != nil {
		return "", checked, nil
	}
	for _, k := range any16 {
		if verifyImageAesKeyWeFlow([]byte(k), ciphertext) && verifyImageAesKeyStrong([]byte(k), templateDat) {
			return k, checked, nil
		}
	}
	return "", checked, nil
}

func verifyImageAesKeyStrong(aes16 []byte, templateDat []byte) bool {
	if len(aes16) != aes.BlockSize || len(templateDat) < 15 {
		return false
	}
	_, _, err := dat2img.Dat2ImageV4(templateDat, aes16)
	return err == nil
}

func verifyImageAesKeyWeFlow(aes16 []byte, ciphertext []byte) bool {
	if len(aes16) != 16 || len(ciphertext) != 16 {
		return false
	}
	block, err := aes.NewCipher(aes16)
	if err != nil {
		return false
	}
	out := make([]byte, 16)
	block.Decrypt(out, ciphertext)

	if out[0] == 0xFF && out[1] == 0xD8 && out[2] == 0xFF {
		return true // JPG
	}
	if out[0] == 0x89 && out[1] == 0x50 && out[2] == 0x4E && out[3] == 0x47 {
		return true // PNG
	}
	if out[0] == 0x52 && out[1] == 0x49 && out[2] == 0x46 && out[3] == 0x46 {
		return true // RIFF
	}
	if out[0] == 0x77 && out[1] == 0x78 && out[2] == 0x67 && out[3] == 0x66 {
		return true // WXGF
	}
	if out[0] == 0x47 && out[1] == 0x49 && out[2] == 0x46 {
		return true // GIF
	}
	return false
}

type templateData struct {
	Ciphertext   []byte
	XorKey       *byte
	TemplateData []byte
}

func findTemplateData(dataDir string, limit int) (templateData, bool) {
	const sampleOffset = 0x0F
	const sampleLen = 16
	magic := []byte{0x07, 0x08, 0x56, 0x32, 0x08, 0x07}

	files := make([]string, 0, limit)
	_ = filepath.WalkDir(dataDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), "_t.dat") {
			files = append(files, path)
		}
		return nil
	})
	if len(files) == 0 {
		return templateData{}, false
	}
	sort.Slice(files, func(i, j int) bool {
		ai, erri := os.Stat(files[i])
		aj, errj := os.Stat(files[j])
		if erri != nil || errj != nil {
			return files[i] < files[j]
		}
		return ai.ModTime().After(aj.ModTime())
	})
	if limit > 0 && len(files) > limit {
		files = files[:limit]
	}

	var ciphertext []byte
	var templateRaw []byte
	tailCounts := map[string]int{}

	maxProbe := 32
	if len(files) < maxProbe {
		maxProbe = len(files)
	}
	for _, f := range files[:maxProbe] {
		b, err := os.ReadFile(f)
		if err != nil || len(b) < 8 {
			continue
		}
		if len(b) >= 6 && bytesEqual(b[:6], magic) {
			if len(b) >= sampleOffset+sampleLen && ciphertext == nil {
				ciphertext = make([]byte, sampleLen)
				copy(ciphertext, b[sampleOffset:sampleOffset+sampleLen])
				templateRaw = make([]byte, len(b))
				copy(templateRaw, b)
			}
			key := fmt.Sprintf("%d_%d", b[len(b)-2], b[len(b)-1])
			tailCounts[key]++
		}
	}
	if ciphertext == nil {
		return templateData{}, false
	}

	var (
		bestCount int
		xorKey    *byte
	)
	for k, count := range tailCounts {
		if count <= bestCount {
			continue
		}
		parts := strings.Split(k, "_")
		if len(parts) != 2 {
			continue
		}
		x, errX := strconv.Atoi(parts[0])
		y, errY := strconv.Atoi(parts[1])
		if errX != nil || errY != nil {
			continue
		}
		kv := byte(x) ^ 0xFF
		if kv == (byte(y) ^ 0xD9) {
			tmp := kv
			xorKey = &tmp
			bestCount = count
		}
	}
	return templateData{Ciphertext: ciphertext, XorKey: xorKey, TemplateData: templateRaw}, true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func loadAllKeys(dataDir string) (map[string]string, error) {
	candidates := []string{
		filepath.Join(dataDir, "all_keys.json"),
		"all_keys.json",
	}
	if strings.EqualFold(filepath.Base(filepath.Clean(dataDir)), "db_storage") {
		candidates = append([]string{filepath.Join(filepath.Dir(filepath.Clean(dataDir)), "all_keys.json")}, candidates...)
	}

	var (
		content     []byte
		err         error
		used        string
		permErrPath string
	)
	for _, p := range candidates {
		content, err = os.ReadFile(p)
		if err == nil {
			used = p
			break
		}
		if os.IsPermission(err) {
			permErrPath = p
		}
	}
	if used == "" && permErrPath != "" {
		// 兼容历史 root:600 场景：尝试自动提权修复权限后再读一次。
		if fixErr := repairAllKeysPermission(permErrPath); fixErr == nil {
			content, err = os.ReadFile(permErrPath)
			if err == nil {
				used = permErrPath
			}
		}
	}
	if used == "" {
		return nil, fmt.Errorf("未找到 all_keys.json（请先用 mac 提 key 工具生成）")
	}

	raw := map[string]keyFileEntry{}
	if err := json.Unmarshal(content, &raw); err != nil {
		return nil, fmt.Errorf("解析 %s 失败: %w", used, err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s 为空", used)
	}

	out := make(map[string]string, len(raw))
	for dbPath, entry := range raw {
		key := strings.TrimSpace(strings.ToLower(entry.EncKey))
		if len(key) != 64 {
			continue
		}
		out[normalizePath(dbPath)] = key
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s 中没有有效 enc_key", used)
	}
	return out, nil
}

func repairAllKeysPermission(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("empty all_keys path")
	}
	if os.Geteuid() == 0 {
		// root 进程直接修复为当前用户（若存在 SUDO_UID/SUDO_GID 则转回调用用户）
		_ = normalizeAllKeysOwnership(path)
		return nil
	}

	uid := os.Getuid()
	gid := os.Getgid()
	cmdLine := fmt.Sprintf("chown %d:%d %q && chmod 600 %q", uid, gid, path, path)
	script := fmt.Sprintf("do shell script \"%s\" with administrator privileges", escapeAppleScriptForOSA(cmdLine))
	if out, err := exec.Command("osascript", "-e", script).CombinedOutput(); err != nil {
		return fmt.Errorf("repair all_keys permission failed: %v, output: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func escapeAppleScriptForOSA(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}

func isMessageDB(p string) bool {
	p = normalizePath(p)
	return strings.HasSuffix(p, "/message/message_0.db") || p == "message/message_0.db"
}

func normalizePath(p string) string {
	return strings.ReplaceAll(strings.ToLower(p), "\\", "/")
}

func normalizeAccountID(value string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return ""
	}
	lv := strings.ToLower(v)
	if strings.HasPrefix(lv, "wxid_") {
		if idx := strings.Index(v[5:], "_"); idx >= 0 {
			return v[:5+idx]
		}
		return v
	}
	if m := regexp.MustCompile(`^(.+)_([a-zA-Z0-9]{4})$`).FindStringSubmatch(v); len(m) == 3 {
		return m[1]
	}
	return v
}

func isIgnoredAccountName(v string) bool {
	lv := strings.ToLower(strings.TrimSpace(v))
	switch lv {
	case "", "xwechat_files", "all_users", "backup", "wmpf", "app_data":
		return true
	default:
		return false
	}
}

func isReasonableAccountID(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || strings.Contains(v, "/") || strings.Contains(v, "\\") {
		return false
	}
	return !isIgnoredAccountName(v)
}

func pushAccountIDCandidate(out *[]string, v string) {
	push := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		for _, e := range *out {
			if e == s {
				return
			}
		}
		*out = append(*out, s)
	}
	if !isReasonableAccountID(v) {
		return
	}
	push(v)
	nv := normalizeAccountID(v)
	if nv != "" && nv != v && isReasonableAccountID(nv) {
		push(nv)
	}
}

func isAccountDirPath(dir string) bool {
	if dir == "" {
		return false
	}
	checks := []string{
		filepath.Join(dir, "db_storage"),
		filepath.Join(dir, "msg"),
		filepath.Join(dir, "FileStorage", "Image"),
		filepath.Join(dir, "FileStorage", "Image2"),
	}
	for _, p := range checks {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return true
		}
	}
	return false
}

func resolveXwechatRootFromPath(p string) string {
	p = strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")
	p = strings.TrimRight(p, "/")
	if p == "" {
		return ""
	}
	if idx := strings.Index(p, "/xwechat_files"); idx >= 0 {
		return p[:idx+len("/xwechat_files")]
	}
	re := regexp.MustCompile(`^(.*\/com\.tencent\.xinWeChat\/(?:\d+\.\d+b\d+\.\d+|\d+\.\d+\.\d+))(\/|$)`)
	if m := re.FindStringSubmatch(p); len(m) >= 2 {
		return m[1]
	}
	return ""
}

func collectWxidCandidates(dataDir string) []string {
	out := make([]string, 0, 8)
	pushAccountIDCandidate(&out, filepath.Base(filepath.Clean(dataDir)))
	root := resolveXwechatRootFromPath(dataDir)
	if root != "" {
		entries, err := os.ReadDir(root)
		if err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				entryPath := filepath.Join(root, e.Name())
				if !isAccountDirPath(entryPath) {
					continue
				}
				pushAccountIDCandidate(&out, e.Name())
			}
		}
	}
	if len(out) == 0 {
		pushAccountIDCandidate(&out, "unknown")
	}
	return out
}

func collectAccountPathCandidates(dataDir string) []string {
	out := make([]string, 0, 8)
	uniqueAppendPath(&out, dataDir)
	root := resolveXwechatRootFromPath(dataDir)
	if root != "" {
		entries, err := os.ReadDir(root)
		if err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				if !isReasonableAccountID(e.Name()) {
					continue
				}
				entryPath := filepath.Join(root, e.Name())
				if !isAccountDirPath(entryPath) {
					continue
				}
				uniqueAppendPath(&out, entryPath)
			}
		}
	}
	return out
}

func uniqueAppendPath(out *[]string, v string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return
	}
	for _, e := range *out {
		if e == v {
			return
		}
	}
	*out = append(*out, v)
}

func getKvcommCandidates(dataDir string) []string {
	out := make([]string, 0, 16)
	home, _ := os.UserHomeDir()
	if home != "" {
		uniqueAppendPath(&out, filepath.Join(home, "Library", "Containers", "com.tencent.xinWeChat", "Data", "Documents", "app_data", "net", "kvcomm"))
		uniqueAppendPath(&out, filepath.Join(home, "Library", "Containers", "com.tencent.xinWeChat", "Data", "Library", "Application Support", "com.tencent.xinWeChat", "xwechat", "net", "kvcomm"))
		uniqueAppendPath(&out, filepath.Join(home, "Library", "Containers", "com.tencent.xinWeChat", "Data", "Library", "Application Support", "com.tencent.xinWeChat", "net", "kvcomm"))
		uniqueAppendPath(&out, filepath.Join(home, "Library", "Containers", "com.tencent.xinWeChat", "Data", "Documents", "xwechat", "net", "kvcomm"))
	}
	if dataDir != "" {
		normalized := strings.ReplaceAll(strings.TrimRight(dataDir, "/"), "\\", "/")
		if idx := strings.Index(normalized, "/xwechat_files"); idx >= 0 {
			base := normalized[:idx]
			uniqueAppendPath(&out, filepath.FromSlash(base+"/app_data/net/kvcomm"))
		}
		re := regexp.MustCompile(`^(.*\/com\.tencent\.xinWeChat\/(?:\d+\.\d+b\d+\.\d+|\d+\.\d+\.\d+))`)
		if m := re.FindStringSubmatch(normalized); len(m) >= 2 {
			vbase := m[1]
			uniqueAppendPath(&out, filepath.FromSlash(vbase+"/net/kvcomm"))
			if pidx := strings.LastIndex(vbase, "/"); pidx > 0 {
				uniqueAppendPath(&out, filepath.FromSlash(vbase[:pidx]+"/net/kvcomm"))
			}
		}
		cursor := dataDir
		for i := 0; i < 6; i++ {
			uniqueAppendPath(&out, filepath.Join(cursor, "net", "kvcomm"))
			next := filepath.Dir(cursor)
			if next == cursor {
				break
			}
			cursor = next
		}
	}
	return out
}

func collectKvcommCodes(dataDir string) []int {
	codeSet := map[int]struct{}{}
	pat := regexp.MustCompile(`^key_(\d+)_.+\.statistic$`)
	for _, dir := range getKvcommCandidates(dataDir) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			m := pat.FindStringSubmatch(e.Name())
			if len(m) != 2 {
				continue
			}
			code64, err := strconv.ParseUint(m[1], 10, 32)
			if err != nil || code64 == 0 {
				continue
			}
			codeSet[int(code64)] = struct{}{}
		}
	}
	if len(codeSet) == 0 {
		return nil
	}
	out := make([]int, 0, len(codeSet))
	for k := range codeSet {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func deriveImageKeyFromCodeWxid(code int, wxid string) (byte, string) {
	cleaned := normalizeAccountID(wxid)
	xorKey := byte(code & 0xFF)
	sum := md5.Sum([]byte(strconv.Itoa(code) + cleaned))
	aesKey := hex.EncodeToString(sum[:])[:16]
	return xorKey, aesKey
}

func deriveImageKeyByCodeAndWxid(dataDir string, status func(string)) (string, bool) {
	codes := collectKvcommCodes(dataDir)
	wxids := collectWxidCandidates(dataDir)
	accountPaths := collectAccountPathCandidates(dataDir)
	if status != nil {
		status(fmt.Sprintf("正在校验 code+wxid 组合... code=%d, wxid=%d, account=%d", len(codes), len(wxids), len(accountPaths)))
	}
	if len(codes) == 0 || len(wxids) == 0 {
		return "", false
	}

	// WeFlow 对齐：优先在可用账号目录中拿模板密文做验真。
	for _, accountPath := range accountPaths {
		tpl, ok := findTemplateData(accountPath, 32)
		if !ok || len(tpl.Ciphertext) != 16 {
			continue
		}

		orderedWxids := make([]string, 0, len(wxids)+2)
		pushAccountIDCandidate(&orderedWxids, filepath.Base(filepath.Clean(accountPath)))
		for _, w := range wxids {
			pushAccountIDCandidate(&orderedWxids, w)
		}

		for _, wxid := range orderedWxids {
			for _, code := range codes {
				xorKey, aesKey := deriveImageKeyFromCodeWxid(code, wxid)
				keyBytes := []byte(aesKey)
				if !verifyImageAesKeyWeFlow(keyBytes, tpl.Ciphertext) {
					continue
				}
				// 强验真：要求完整模板 dat 可解，避免误命中。
				oldXor := dat2img.V4XorKey
				dat2img.V4XorKey = xorKey
				okStrong := verifyImageAesKeyStrong(keyBytes, tpl.TemplateData)
				if !okStrong {
					dat2img.V4XorKey = oldXor
					continue
				}
				if status != nil {
					status(fmt.Sprintf("命中 code=%d, wxid=%s", code, wxid))
				}
				return aesKey, true
			}
		}
	}

	// WeFlow 对齐：拿不到模板时，回退到“首个 code + 首个 wxid”未验真结果。
	// 这样行为与 WeFlow 一致，但可靠性低于模板验真路径。
	if len(accountPaths) == 0 {
		xorKey, aesKey := deriveImageKeyFromCodeWxid(codes[0], wxids[0])
		dat2img.V4XorKey = xorKey
		if status != nil {
			status(fmt.Sprintf("模板缺失，回退使用首个 code+wxid（code=%d, wxid=%s）", codes[0], wxids[0]))
		}
		return aesKey, true
	}
	// 如果有账号目录但都无法形成模板验真，也和 WeFlow一致走回退。
	xorKey, aesKey := deriveImageKeyFromCodeWxid(codes[0], wxids[0])
	dat2img.V4XorKey = xorKey
	if status != nil {
		status(fmt.Sprintf("模板验真未命中，回退使用首个 code+wxid（code=%d, wxid=%s）", codes[0], wxids[0]))
	}
	return aesKey, true
}
