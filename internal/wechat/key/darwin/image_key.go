package darwin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	keyshared "github.com/sjzar/chatlog/internal/wechat/key/shared"
	"github.com/sjzar/chatlog/internal/wechat/model"
	"github.com/sjzar/chatlog/pkg/util/dat2img"
)

func (e *V4Extractor) pickImageKeyWithTiming(ctx context.Context, proc *model.Process, status func(string), imageOnly bool) (string, error) {
	// 与 Windows 一致：仅“获取图片密钥”流程执行 60 秒等待/轮询。
	if !imageOnly {
		return e.pickImageKeyWeFlow(proc.PID, proc.DataDir, status)
	}

	if status != nil {
		status("正在查找模板文件...")
	}
	resultTpl, ok := keyshared.FindTemplateData(proc.DataDir, 32)
	if !ok || len(resultTpl.Ciphertext) == 0 || resultTpl.XorKey == nil {
		if status != nil {
			status("未找到有效密钥，尝试扫描更多文件...")
		}
		resultTpl, ok = keyshared.FindTemplateData(proc.DataDir, 100)
	}
	if !ok || len(resultTpl.Ciphertext) == 0 {
		return "", fmt.Errorf("未找到 V2 模板文件，请先在微信中查看几张图片")
	}
	if resultTpl.XorKey == nil {
		return "", fmt.Errorf("未能从模板文件中计算出有效的 XOR 密钥")
	}
	dat2img.V4XorKey = *resultTpl.XorKey
	if status != nil {
		status(fmt.Sprintf("XOR 密钥: 0x%02x，正在查找微信进程...", *resultTpl.XorKey))
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

		imgKey, checked, err := scanImageKeyByWeFlow(currentPID, resultTpl.Ciphertext, resultTpl.TemplateData)
		if err != nil {
			if errors.Is(err, ErrImageKeyPermission) {
				if status != nil {
					status("检测到微信内存读取权限不足，需要管理员授权")
				}
				return "", err
			}
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
	tpl, ok := keyshared.FindTemplateData(dataDir, 32)
	if !ok || len(tpl.Ciphertext) == 0 || tpl.XorKey == nil {
		tpl, ok = keyshared.FindTemplateData(dataDir, 100)
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
		if key != "" && keyshared.VerifyImageKeyStrong([]byte(key), templateDat) {
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
		if keyshared.VerifyImageKeyHeader([]byte(k), ciphertext) && keyshared.VerifyImageKeyStrong([]byte(k), templateDat) {
			return k, checked, nil
		}
	}
	any16, checkedAny16, err := scanImageAny16CandidatesByPID(pid)
	checked += checkedAny16
	if err != nil {
		return "", checked, nil
	}
	for _, k := range any16 {
		if keyshared.VerifyImageKeyHeader([]byte(k), ciphertext) && keyshared.VerifyImageKeyStrong([]byte(k), templateDat) {
			return k, checked, nil
		}
	}
	return "", checked, nil
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
	keyshared.AppendAccountIDCandidate(&out, filepath.Base(filepath.Clean(dataDir)))
	root := resolveXwechatRootFromPath(dataDir)
	if root != "" {
		entries, err := os.ReadDir(root)
		if err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				entryPath := filepath.Join(root, e.Name())
				if !keyshared.IsAccountDir(entryPath) {
					continue
				}
				keyshared.AppendAccountIDCandidate(&out, e.Name())
			}
		}
	}
	if len(out) == 0 {
		keyshared.AppendAccountIDCandidate(&out, "unknown")
	}
	return out
}

func collectAccountPathCandidates(dataDir string) []string {
	out := make([]string, 0, 8)
	keyshared.AppendUniquePath(&out, dataDir)
	root := resolveXwechatRootFromPath(dataDir)
	if root != "" {
		entries, err := os.ReadDir(root)
		if err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				if !keyshared.IsReasonableAccountID(e.Name()) {
					continue
				}
				entryPath := filepath.Join(root, e.Name())
				if !keyshared.IsAccountDir(entryPath) {
					continue
				}
				keyshared.AppendUniquePath(&out, entryPath)
			}
		}
	}
	return out
}

func getKvcommCandidates(dataDir string) []string {
	out := make([]string, 0, 16)
	home, _ := os.UserHomeDir()
	if home != "" {
		keyshared.AppendUniquePath(&out, filepath.Join(home, "Library", "Containers", "com.tencent.xinWeChat", "Data", "Documents", "app_data", "net", "kvcomm"))
		keyshared.AppendUniquePath(&out, filepath.Join(home, "Library", "Containers", "com.tencent.xinWeChat", "Data", "Library", "Application Support", "com.tencent.xinWeChat", "xwechat", "net", "kvcomm"))
		keyshared.AppendUniquePath(&out, filepath.Join(home, "Library", "Containers", "com.tencent.xinWeChat", "Data", "Library", "Application Support", "com.tencent.xinWeChat", "net", "kvcomm"))
		keyshared.AppendUniquePath(&out, filepath.Join(home, "Library", "Containers", "com.tencent.xinWeChat", "Data", "Documents", "xwechat", "net", "kvcomm"))
	}
	if dataDir != "" {
		normalized := strings.ReplaceAll(strings.TrimRight(dataDir, "/"), "\\", "/")
		if idx := strings.Index(normalized, "/xwechat_files"); idx >= 0 {
			base := normalized[:idx]
			keyshared.AppendUniquePath(&out, filepath.FromSlash(base+"/app_data/net/kvcomm"))
		}
		re := regexp.MustCompile(`^(.*\/com\.tencent\.xinWeChat\/(?:\d+\.\d+b\d+\.\d+|\d+\.\d+\.\d+))`)
		if m := re.FindStringSubmatch(normalized); len(m) >= 2 {
			vbase := m[1]
			keyshared.AppendUniquePath(&out, filepath.FromSlash(vbase+"/net/kvcomm"))
			if pidx := strings.LastIndex(vbase, "/"); pidx > 0 {
				keyshared.AppendUniquePath(&out, filepath.FromSlash(vbase[:pidx]+"/net/kvcomm"))
			}
		}
		cursor := dataDir
		for i := 0; i < 6; i++ {
			keyshared.AppendUniquePath(&out, filepath.Join(cursor, "net", "kvcomm"))
			next := filepath.Dir(cursor)
			if next == cursor {
				break
			}
			cursor = next
		}
	}
	return out
}

func deriveImageKeyByCodeAndWxid(dataDir string, status func(string)) (string, bool) {
	return keyshared.DeriveImageKey(
		keyshared.CollectKvcommCodes(getKvcommCandidates(dataDir)),
		collectWxidCandidates(dataDir),
		collectAccountPathCandidates(dataDir),
		status,
	)
}
