package darwin

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/sjzar/chatlog/internal/wechat/model"
	"github.com/sjzar/chatlog/pkg/appver"
)

const (
	ProcessNameWeChat = "WeChat"
	ProcessNameWeixin = "Weixin"
	V4DBFile          = "/db_storage/session/session.db"
)

type Detector struct{}

func NewDetector() *Detector {
	return &Detector{}
}

func (d *Detector) FindProcesses() ([]*model.Process, error) {
	processes, err := process.Processes()
	if err != nil {
		log.Err(err).Msg("获取进程列表失败")
		return nil, err
	}

	var result []*model.Process
	for _, p := range processes {
		name, err := p.Name()
		if err != nil || !isWeChatProcessName(name) {
			continue
		}

		procInfo, err := d.getProcessInfo(p)
		if err != nil {
			log.Err(err).Msgf("获取进程 %d 的信息失败", p.Pid)
			continue
		}
		result = append(result, procInfo)
	}

	return result, nil
}

func (d *Detector) getProcessInfo(p *process.Process) (*model.Process, error) {
	procInfo := &model.Process{
		PID:      uint32(p.Pid),
		Status:   model.StatusOffline,
		Platform: model.PlatformDarwin,
	}

	exePath, err := p.Exe()
	if err != nil {
		return nil, err
	}
	procInfo.ExePath = exePath

	versionInfo, err := appver.New(exePath)
	if err != nil {
		log.Warn().Err(err).Msg("获取版本信息失败，使用默认版本 4")
		procInfo.Version = 4
		procInfo.FullVersion = "4"
	} else {
		procInfo.Version = versionInfo.Version
		procInfo.FullVersion = versionInfo.FullVersion
	}

	if err := initializeProcessInfoWithLsof(p.Pid, procInfo); err != nil {
		if !isBenignLsofErr(err) {
			log.Debug().Err(err).Msg("初始化进程信息失败")
		}
	}
	if procInfo.AccountName == "" {
		procInfo.AccountName = fmt.Sprintf("未登录微信_%d", p.Pid)
	}

	return procInfo, nil
}

func initializeProcessInfoWithLsof(pid int32, info *model.Process) error {
	paths, err := listOpenPathsByLsof(pid)
	if err != nil {
		info.AccountName = fmt.Sprintf("未登录微信_%d", pid)
		return err
	}

	for _, path := range paths {
		normalized := strings.ReplaceAll(filepath.Clean(path), "\\", "/")
		if !strings.HasSuffix(strings.ToLower(normalized), V4DBFile) {
			continue
		}
		dataDir, account, ok := parseDataDirFromSessionDB(normalized)
		if !ok {
			continue
		}
		info.Status = model.StatusOnline
		info.DataDir = dataDir
		info.AccountName = account
		return nil
	}

	info.Status = model.StatusOffline
	info.AccountName = fmt.Sprintf("未登录微信_%d", pid)
	return nil
}

func listOpenPathsByLsof(pid int32) ([]string, error) {
	cmd := exec.Command("lsof", "-n", "-P", "-p", strconv.Itoa(int(pid)), "-F", "n")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			msg := strings.TrimSpace(string(ee.Stderr))
			if msg == "" {
				msg = ee.Error()
			}
			return nil, fmt.Errorf("lsof failed: %s", msg)
		}
		return nil, err
	}

	lines := strings.Split(string(out), "\n")
	paths := make([]string, 0, len(lines))
	for _, line := range lines {
		if len(line) <= 1 || line[0] != 'n' {
			continue
		}
		p := strings.TrimSpace(line[1:])
		if p == "" {
			continue
		}
		paths = append(paths, p)
	}
	return paths, nil
}

func parseDataDirFromSessionDB(sessionPath string) (string, string, bool) {
	n := strings.ReplaceAll(filepath.Clean(sessionPath), "\\", "/")
	parts := strings.Split(n, "/")
	if len(parts) < 4 {
		return "", "", false
	}
	idx := -1
	for i := 0; i < len(parts); i++ {
		if parts[i] == "db_storage" {
			idx = i
			break
		}
	}
	if idx <= 0 {
		return "", "", false
	}
	account := parts[idx-1]
	if account == "" {
		return "", "", false
	}
	dataDir := strings.Join(parts[:idx-1], "/") + "/" + account
	if strings.HasPrefix(n, "/") && !strings.HasPrefix(dataDir, "/") {
		dataDir = "/" + dataDir
	}
	return dataDir, account, true
}

func isWeChatProcessName(name string) bool {
	trimmed := strings.TrimSuffix(strings.TrimSpace(name), ".app")
	return trimmed == ProcessNameWeChat || trimmed == ProcessNameWeixin
}

func isBenignLsofErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such process") || strings.Contains(msg, "lsof failed")
}
