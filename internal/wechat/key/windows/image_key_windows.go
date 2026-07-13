package windows

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v4/process"

	keyshared "github.com/sjzar/chatlog/internal/wechat/key/shared"
	"github.com/sjzar/chatlog/internal/wechat/model"
	"github.com/sjzar/chatlog/pkg/util/dat2img"
)

func (e *V4Extractor) pickImageKeyWithTiming(ctx context.Context, proc *model.Process, status func(string), imageOnly bool) (string, error) {
	if !imageOnly {
		return e.pickImageKeyWeFlow(proc.PID, proc.DataDir, status)
	}

	if status != nil {
		status("正在查找模板文件...")
	}
	template, ok := keyshared.FindTemplateData(proc.DataDir, 32)
	if !ok || len(template.Ciphertext) == 0 || template.XorKey == nil {
		if status != nil {
			status("未找到有效密钥，尝试扫描更多文件...")
		}
		template, ok = keyshared.FindTemplateData(proc.DataDir, 100)
	}
	if !ok || len(template.Ciphertext) == 0 {
		return "", fmt.Errorf("未找到 V2 模板文件，请先在微信中查看几张图片")
	}
	if template.XorKey == nil {
		return "", fmt.Errorf("未能从模板文件中计算出有效的 XOR 密钥")
	}
	dat2img.V4XorKey = *template.XorKey
	if status != nil {
		status(fmt.Sprintf("XOR 密钥: 0x%02x，正在查找微信进程...", *template.XorKey))
	}
	if key, derived := deriveImageKeyByCodeAndWxid(proc.DataDir, status); derived {
		if status != nil {
			status("通过 kvcomm(code+wxid) 推导并验真成功")
		}
		return key, nil
	}

	deadline := time.Now().Add(60 * time.Second)
	var lastPID uint32
	for scanRound := 1; ; scanRound++ {
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
		if status != nil {
			status(fmt.Sprintf("第 %d 次扫描内存，请在微信中打开图片大图...", scanRound))
		}

		imageKey, checked, err := scanImageKeyByWeFlow(currentPID, template.Ciphertext, template.TemplateData)
		if err != nil {
			log.Debug().Err(err).Msg("扫描图片密钥失败，准备重试")
		}
		if status != nil {
			status(fmt.Sprintf("正在扫描图片密钥... 已检查 %d 个候选字符串", checked))
		}
		if imageKey != "" {
			if status != nil {
				status(fmt.Sprintf("通过字符串扫描找到图片密钥! (在检查了 %d 个候选后)", checked))
			}
			return imageKey, nil
		}

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func (e *V4Extractor) pickImageKeyWeFlow(pid uint32, dataDir string, status func(string)) (string, error) {
	template, ok := keyshared.FindTemplateData(dataDir, 32)
	if !ok || len(template.Ciphertext) == 0 || template.XorKey == nil {
		template, ok = keyshared.FindTemplateData(dataDir, 100)
	}
	if !ok || len(template.Ciphertext) == 0 || template.XorKey == nil {
		return "", nil
	}
	dat2img.V4XorKey = *template.XorKey
	if key, derived := deriveImageKeyByCodeAndWxid(dataDir, status); derived {
		if status != nil {
			status("通过 kvcomm(code+wxid) 推导并验真成功")
		}
		return key, nil
	}
	imageKey, checked, err := scanImageKeyByWeFlow(pid, template.Ciphertext, template.TemplateData)
	if status != nil {
		status(fmt.Sprintf("正在扫描图片密钥... 已检查 %d 个候选字符串", checked))
	}
	if err != nil {
		return "", err
	}
	if imageKey != "" && status != nil {
		status(fmt.Sprintf("通过字符串扫描找到图片密钥! (在检查了 %d 个候选后)", checked))
	}
	return imageKey, nil
}

func scanImageKeyByWeFlow(pid uint32, ciphertext, templateData []byte) (string, int, error) {
	if key, checked, err := scanImageKeyByPIDAndCiphertext(pid, ciphertext); err == nil || key != "" {
		if key != "" && keyshared.VerifyImageKeyStrong([]byte(key), templateData) {
			return key, checked, nil
		}
	}

	candidates, checked, err := scanImageKeyCandidatesByPID(pid)
	if err != nil {
		return "", checked, err
	}
	for _, candidate := range candidates {
		if len(candidate) < 16 {
			continue
		}
		key := candidate[:16]
		if keyshared.VerifyImageKeyHeader([]byte(key), ciphertext) && keyshared.VerifyImageKeyStrong([]byte(key), templateData) {
			return key, checked, nil
		}
	}
	any16, checkedAny16, err := scanImageAny16CandidatesByPID(pid)
	checked += checkedAny16
	if err != nil {
		return "", checked, nil
	}
	for _, key := range any16 {
		if keyshared.VerifyImageKeyHeader([]byte(key), ciphertext) && keyshared.VerifyImageKeyStrong([]byte(key), templateData) {
			return key, checked, nil
		}
	}
	return "", checked, nil
}

func findWeChatPID() (uint32, error) {
	processes, err := process.Processes()
	if err != nil {
		return 0, err
	}
	var maxPID uint32
	for _, candidate := range processes {
		name, err := candidate.Name()
		if err != nil {
			continue
		}
		name = strings.TrimSuffix(strings.ToLower(name), ".exe")
		if name != "weixin" && name != "wechat" {
			continue
		}
		if name == "weixin" {
			if commandLine, err := candidate.Cmdline(); err == nil && strings.Contains(commandLine, "--") {
				continue
			}
		}
		if pid := uint32(candidate.Pid); pid > maxPID {
			maxPID = pid
		}
	}
	if maxPID == 0 {
		return 0, fmt.Errorf("wechat process not found")
	}
	return maxPID, nil
}

func collectWxidCandidates(dataDir string) []string {
	result := make([]string, 0, 8)
	keyshared.AppendAccountIDCandidate(&result, filepath.Base(filepath.Clean(dataDir)))
	if root, ok := accountRootDir(dataDir); ok {
		if entries, err := os.ReadDir(root); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					keyshared.AppendAccountIDCandidate(&result, entry.Name())
				}
			}
		}
	}
	if len(result) == 0 {
		keyshared.AppendAccountIDCandidate(&result, "unknown")
	}
	return result
}

func collectAccountPathCandidates(dataDir string) []string {
	result := make([]string, 0, 8)
	keyshared.AppendUniquePath(&result, dataDir)
	if root, ok := accountRootDir(dataDir); ok {
		if entries, err := os.ReadDir(root); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() || !keyshared.IsReasonableAccountID(entry.Name()) {
					continue
				}
				path := filepath.Join(root, entry.Name())
				if keyshared.IsAccountDir(path) {
					keyshared.AppendUniquePath(&result, path)
				}
			}
		}
	}
	return result
}

func accountRootDir(dataDir string) (string, bool) {
	normalized := strings.ReplaceAll(strings.TrimSpace(strings.TrimRight(dataDir, "\\/")), "\\", "/")
	if normalized == "" {
		return "", false
	}
	lower := strings.ToLower(normalized)
	for _, marker := range []string{"/xwechat_files", "/wechat files"} {
		if index := strings.Index(lower, marker); index >= 0 {
			root := filepath.FromSlash(normalized[:index+len(marker)])
			if stat, err := os.Stat(root); err == nil && stat.IsDir() {
				return root, true
			}
		}
	}
	return "", false
}

func getKvcommCandidates(dataDir string) []string {
	result := make([]string, 0, 16)
	if currentUser, err := user.Current(); err == nil && currentUser.HomeDir != "" {
		keyshared.AppendUniquePath(&result, filepath.Join(currentUser.HomeDir, "AppData", "Roaming", "Tencent", "xwechat_files", "app_data", "net", "kvcomm"))
	}
	if local := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); local != "" {
		keyshared.AppendUniquePath(&result, filepath.Join(local, "Tencent", "xwechat_files", "app_data", "net", "kvcomm"))
		keyshared.AppendUniquePath(&result, filepath.Join(local, "Tencent", "WeChat", "xwechat", "net", "kvcomm"))
	}
	if dataDir != "" {
		normalized := strings.ReplaceAll(strings.TrimRight(dataDir, "\\/"), "\\", "/")
		lower := strings.ToLower(normalized)
		if index := strings.Index(lower, "/xwechat_files"); index >= 0 {
			keyshared.AppendUniquePath(&result, filepath.FromSlash(normalized[:index]+"/app_data/net/kvcomm"))
		}
		if index := strings.Index(lower, "/wechat files"); index >= 0 {
			keyshared.AppendUniquePath(&result, filepath.FromSlash(normalized[:index]+"/app_data/net/kvcomm"))
		}
		for cursor, depth := dataDir, 0; depth < 6; depth++ {
			keyshared.AppendUniquePath(&result, filepath.Join(cursor, "net", "kvcomm"))
			next := filepath.Dir(cursor)
			if next == cursor {
				break
			}
			cursor = next
		}
	}
	return result
}

func deriveImageKeyByCodeAndWxid(dataDir string, status func(string)) (string, bool) {
	return keyshared.DeriveImageKey(
		keyshared.CollectKvcommCodes(getKvcommCandidates(dataDir)),
		collectWxidCandidates(dataDir),
		collectAccountPathCandidates(dataDir),
		status,
	)
}
