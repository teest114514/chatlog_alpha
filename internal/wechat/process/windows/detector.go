package windows

import (
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/sjzar/chatlog/internal/wechat/model"
	"github.com/sjzar/chatlog/pkg/appver"
)

const (
	V4ProcessName = "Weixin"
	V4DBFile      = `db_storage\session\session.db`

	// noDataDirRecheckInterval 无 DataDir 的主进程缓存过期时间。
	// 覆盖场景：微信已启动但用户尚未登录 → 登录后 DataDir 出现。
	noDataDirRecheckInterval = 30 * time.Second
)

// procCacheEntry 缓存单个主进程的检测结果
type procCacheEntry struct {
	info      *model.Process
	hasData   bool      // DataDir 非空
	checkedAt time.Time // 上次调用 getProcessInfo 的时间
}

// Detector 实现 Windows 平台的进程检测器
type Detector struct {
	mu    sync.Mutex
	cache map[uint32]*procCacheEntry // PID → 缓存（仅主进程）
}

// NewDetector 创建一个新的 Windows 检测器
func NewDetector() *Detector {
	return &Detector{
		cache: make(map[uint32]*procCacheEntry),
	}
}

// FindProcesses 查找所有微信进程并返回它们的信息
func (d *Detector) FindProcesses() ([]*model.Process, error) {
	processes, err := process.Processes()
	if err != nil {
		log.Err(err).Msg("获取进程列表失败")
		return nil, err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	alivePIDs := make(map[uint32]bool)
	var result []*model.Process
	now := time.Now()

	for _, p := range processes {
		name, err := p.Name()
		name = strings.TrimSuffix(name, ".exe")
		if err != nil || name != V4ProcessName {
			continue
		}

		pid := uint32(p.Pid)
		alivePIDs[pid] = true

		// ── 子进程过滤 ──
		// 微信 V4 的 Chromium 子进程 cmdline 含 --type=（wxocr/wxplayer/wxutility 等）。
		// 主进程可能带 --scene= 等参数，但不会有 --type=。
		// 子进程持有大量文件句柄，对其调 p.OpenFiles() 是内存暴涨的根因，必须在此拦截。
		cmdline, err := p.Cmdline()
		if err != nil {
			log.Debug().Err(err).Msgf("获取进程 %d 命令行失败，跳过", p.Pid)
			continue
		}
		if strings.Contains(cmdline, "--type=") {
			continue
		}

		// ── 主进程 PID 缓存 ──
		// 主进程只有1个，getProcessInfo(含 p.OpenFiles)开销可接受，
		// 但仍做缓存以避免每 3 秒重复扫描。
		if entry, ok := d.cache[pid]; ok {
			if entry.hasData || now.Sub(entry.checkedAt) < noDataDirRecheckInterval {
				result = append(result, entry.info)
				continue
			}
			// 无 DataDir 且已超时 → 重新检测（覆盖用户登录场景）
			delete(d.cache, pid)
		}

		// ── 实际检测 ──
		procInfo, err := d.getProcessInfo(p)
		if err != nil {
			log.Err(err).Msgf("获取进程 %d 的信息失败", p.Pid)
			continue
		}

		d.cache[pid] = &procCacheEntry{
			info:      procInfo,
			hasData:   procInfo.DataDir != "",
			checkedAt: now,
		}
		result = append(result, procInfo)
	}

	// 清理已退出进程的缓存
	for pid := range d.cache {
		if !alivePIDs[pid] {
			delete(d.cache, pid)
		}
	}

	return result, nil
}

// getProcessInfo 获取微信进程的详细信息
func (d *Detector) getProcessInfo(p *process.Process) (*model.Process, error) {
	procInfo := &model.Process{
		PID:      uint32(p.Pid),
		Status:   model.StatusOffline,
		Platform: model.PlatformWindows,
	}

	exePath, err := p.Exe()
	if err != nil {
		log.Err(err).Msg("获取可执行文件路径失败")
		return nil, err
	}
	procInfo.ExePath = exePath

	versionInfo, err := appver.New(exePath)
	if err != nil {
		log.Err(err).Msg("获取版本信息失败")
		return nil, err
	}
	procInfo.Version = versionInfo.Version
	procInfo.FullVersion = versionInfo.FullVersion

	if err := initializeProcessInfo(p, procInfo); err != nil {
		log.Err(err).Msg("初始化进程信息失败")
	}

	return procInfo, nil
}
