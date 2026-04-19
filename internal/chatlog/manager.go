package chatlog

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sjzar/chatlog/internal/chatlog/conf"
	"github.com/sjzar/chatlog/internal/chatlog/ctx"
	"github.com/sjzar/chatlog/internal/chatlog/database"
	"github.com/sjzar/chatlog/internal/chatlog/http"
	"github.com/sjzar/chatlog/internal/chatlog/wechat"
	"github.com/sjzar/chatlog/internal/model"
	iwechat "github.com/sjzar/chatlog/internal/wechat"
	"github.com/sjzar/chatlog/pkg/config"
	"github.com/sjzar/chatlog/pkg/util"
	"github.com/sjzar/chatlog/pkg/util/dat2img"
)

// Manager 管理聊天日志应用
type Manager struct {
	ctx *ctx.Context
	sc  *conf.ServerConfig
	scm *config.Manager

	// Services
	db     *database.Service
	http   *http.Service
	wechat *wechat.Service

	// Terminal UI
	app *App
}

func New() *Manager {
	return &Manager{}
}

func (m *Manager) Run(configPath string) error {

	var err error
	m.ctx, err = ctx.New(configPath)
	if err != nil {
		return err
	}

	m.wechat = wechat.NewService(m.ctx)

	m.db = database.NewService(m.ctx)

	m.http = http.NewService(m.ctx, m.db)

	m.ctx.WeChatInstances = m.wechat.GetWeChatInstances()
	if len(m.ctx.WeChatInstances) >= 1 {
		m.ctx.SwitchCurrent(m.ctx.WeChatInstances[0])
	}

	if m.ctx.HTTPEnabled {
		// 启动HTTP服务
		if err := m.StartService(); err != nil {
			m.StopService()
		}
	}
	// 启动终端UI
	m.app = NewApp(m.ctx, m)
	m.app.Run() // 阻塞
	return nil
}

func (m *Manager) Switch(info *iwechat.Account, history string) error {
	if m.ctx.HTTPEnabled {
		if err := m.stopService(); err != nil {
			return err
		}
	}
	if info != nil {
		m.ctx.SwitchCurrent(info)
	} else {
		m.ctx.SwitchHistory(history)
	}

	if m.ctx.HTTPEnabled {
		// 启动HTTP服务
		if err := m.StartService(); err != nil {
			log.Info().Err(err).Msg("启动服务失败")
			m.StopService()
		}
	}
	return nil
}

func (m *Manager) StartService() error {

	// 按依赖顺序启动服务
	if err := m.db.Start(); err != nil {
		return err
	}

	if err := m.http.Start(); err != nil {
		m.db.Stop()
		return err
	}

	// 如果是 4.0 版本，更新下 xorkey
	if m.ctx.Version == 4 {
		dat2img.SetAesKey(m.ctx.ImgKey)
		go dat2img.ScanAndSetXorKey(m.ctx.DataDir)
	}

	// 更新状态
	m.ctx.SetHTTPEnabled(true)

	return nil
}

func (m *Manager) StopService() error {
	if err := m.stopService(); err != nil {
		return err
	}

	// 更新状态
	m.ctx.SetHTTPEnabled(false)

	return nil
}

func (m *Manager) stopService() error {
	// 按依赖的反序停止服务
	var errs []error

	if err := m.http.Stop(); err != nil {
		errs = append(errs, err)
	}

	if err := m.db.Stop(); err != nil {
		errs = append(errs, err)
	}

	// 如果有错误，返回第一个错误
	if len(errs) > 0 {
		return errs[0]
	}

	return nil
}

func (m *Manager) SetHTTPAddr(text string) error {
	var addr string
	if util.IsNumeric(text) {
		addr = fmt.Sprintf("127.0.0.1:%s", text)
	} else if strings.HasPrefix(text, "http://") {
		addr = strings.TrimPrefix(text, "http://")
	} else if strings.HasPrefix(text, "https://") {
		addr = strings.TrimPrefix(text, "https://")
	} else {
		addr = text
	}
	m.ctx.SetHTTPAddr(addr)
	return nil
}

func (m *Manager) GetDataKey() error {
	if m.ctx.Current == nil {
		return fmt.Errorf("未选择任何账号")
	}
	if _, err := m.wechat.GetDataKey(m.ctx.Current); err != nil {
		return err
	}
	m.ctx.Refresh()
	m.ctx.UpdateConfig()
	return nil
}

func (m *Manager) GetImageKey() error {
	if m.ctx.Current == nil {
		return fmt.Errorf("未选择任何账号")
	}
	imgKey, err := m.wechat.GetImageKey(m.ctx.Current)
	if err != nil {
		return err
	}
	if imgKey != "" {
		m.ctx.ImgKey = imgKey
		if m.ctx.Current != nil {
			m.ctx.Current.ImgKey = imgKey
		}
		// Keep runtime decoder in sync immediately (no need to restart HTTP service).
		dat2img.SetAesKey(imgKey)
		if m.ctx.DataDir != "" {
			go dat2img.ScanAndSetXorKey(m.ctx.DataDir)
		}
	}
	m.ctx.Refresh()
	m.ctx.UpdateConfig()
	return nil
}

func (m *Manager) RestartAndGetDataKey(onStatus func(string)) error {
	if m.ctx.Current == nil {
		return fmt.Errorf("未选择任何账号")
	}

	pid := m.ctx.Current.PID
	exePath := m.ctx.Current.ExePath
	platform := m.ctx.Current.Platform

	// 1. Terminate the process
	if onStatus != nil {
		onStatus("正在结束微信进程...")
	}
	log.Info().Msgf("Killing WeChat process with PID %d", pid)
	process, err := os.FindProcess(int(pid))
	if err != nil {
		return fmt.Errorf("could not find process with PID %d: %w", pid, err)
	}
	if err := process.Kill(); err != nil {
		return fmt.Errorf("failed to kill process with PID %d: %w", pid, err)
	}

	// 2. Wait for the process to disappear
	log.Info().Msg("Waiting for WeChat process to terminate...")
	for i := 0; i < 10; i++ { // Wait for max 10 seconds
		instances := m.wechat.GetWeChatInstances()
		found := false
		for _, inst := range instances {
			if inst.PID == pid {
				found = true
				break
			}
		}
		if !found {
			break
		}
		time.Sleep(1 * time.Second)
	}

	// 3. Restart WeChat
	if onStatus != nil {
		onStatus("正在重启微信...")
	}
	log.Info().Msgf("Restarting WeChat from %s", exePath)
	if err := startWeChatProcess(platform, exePath); err != nil {
		return fmt.Errorf("failed to restart WeChat: %w", err)
	}

	// 4. Wait for the new process to appear.
	if onStatus != nil {
		onStatus("正在等待新进程启动...")
	}
	log.Info().Msg("Waiting for new WeChat process to start...")
	var newInstance *iwechat.Account
	for i := 0; i < 30; i++ { // Wait for max 30 seconds
		instances := m.wechat.GetWeChatInstances()
		// Try to find a new instance. A new instance is one with a different PID.
		for _, inst := range instances {
			if inst.PID != pid && inst.ExePath == exePath {
				newInstance = inst
				break
			}
		}
		if newInstance != nil {
			break
		}
		time.Sleep(1 * time.Second)
	}

	if newInstance == nil {
		return fmt.Errorf("failed to find new WeChat process after restart")
	}
	log.Info().Msgf("Found new WeChat process with PID %d", newInstance.PID)

	// 5. Switch to the new instance
	m.ctx.SwitchCurrent(newInstance)
	restartedAt := time.Now()

	// 6. Get the key
	// 增加重试逻辑：微信刚启动后模块/数据目录可能未就绪，需要等待。
	log.Info().Msg("Getting key from new WeChat process...")

	// 使用携带回调的 context。
	// 重启并获取密钥必须强制重扫，避免命中历史 DataKey/all_keys.json 导致“未真正重扫内存”。
	ctx := context.WithValue(context.Background(), "status_callback", onStatus)
	ctx = context.WithValue(ctx, "force_key_refresh", true)
	ctx = context.WithValue(ctx, "force_rescan_memory", true)

	var key, imgKey string
	helperTried := false

	// 初始化截止时间：
	// - macOS: 用户需要完成登录，给更长窗口
	// - 其他平台: 保持较短等待
	waitWindow := 30 * time.Second
	if platform == "darwin" {
		waitWindow = 180 * time.Second
	}
	deadline := time.Now().Add(waitWindow)
	started := time.Now()
	attempt := 0
	readyForScan := false

	for {
		attempt++
		elapsed := int(time.Since(started).Seconds())
		total := int(waitWindow.Seconds())

		// macOS: 每轮重试前重新绑定当前可用微信实例，避免重启后 PID/账户漂移导致持续扫描错误进程。
		if platform == "darwin" {
			if best := pickBestWeChatInstance(m.wechat.GetWeChatInstances(), exePath, platform); best != nil {
				if m.ctx.Current == nil || m.ctx.Current.PID != best.PID {
					m.ctx.SwitchCurrent(best)
					if onStatus != nil {
						onStatus(fmt.Sprintf("已切换到最新微信进程 PID=%d，继续扫描...", best.PID))
					}
				}
			}
		}

		if onStatus != nil {
			if platform == "darwin" {
				if readyForScan {
					onStatus(fmt.Sprintf("微信已启动，正在扫描并验证密钥...（重试 %d 次，已等待 %ds/%ds）", attempt, elapsed, total))
				} else {
					onStatus(fmt.Sprintf("正在等待微信初始化并登录...（重试 %d 次，已等待 %ds/%ds）", attempt, elapsed, total))
				}
			} else {
				onStatus("正在等待微信初始化...")
			}
		}

		// macOS: 登录就绪前不触发扫描，避免“未登录就开始扫 key”导致的噪声重试。
		if platform == "darwin" && !isDarwinLoginReady(m.ctx.Current, restartedAt) {
			if onStatus != nil {
				onStatus(fmt.Sprintf("等待微信登录完成后再启动密钥扫描...（重试 %d 次，已等待 %ds/%ds）", attempt, elapsed, total))
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("获取密钥超时: 微信登录未就绪")
			}
			time.Sleep(1 * time.Second)
			continue
		}
		if platform == "darwin" {
			readyForScan = true
		}

		// 尝试获取密钥
		key, imgKey, err = m.ctx.Current.GetKey(ctx)

		if err == nil {
			break
		}
		if platform == "darwin" && isDarwinScanStageErr(err) {
			readyForScan = true
		}

		// macOS 权限不足时，尝试一次提权 helper。
		if platform == "darwin" && !helperTried && isDarwinPermissionErr(err) {
			helperTried = true
			if onStatus != nil {
				onStatus("正在请求管理员权限以读取微信进程内存...")
			}
			if hk, helperErr := tryDarwinPrivilegedKeyHelper(m.ctx.Current); helperErr == nil && hk != "" {
				key = hk
				imgKey = m.ctx.Current.ImgKey
				err = nil
				break
			}
		}

		err = normalizeKeyAcquireError(err)
		if !isRetryableKeyErr(err) {
			return err
		}
		if platform == "darwin" && onStatus != nil {
			if readyForScan {
				onStatus(fmt.Sprintf("微信已启动，等待聊天窗口触发数据库读取，程序正在自动重试...（重试 %d 次，已等待 %ds/%ds）", attempt, elapsed, total))
			} else {
				onStatus(fmt.Sprintf("等待微信登录并打开聊天窗口触发数据库读取，程序正在自动重试...（重试 %d 次，已等待 %ds/%ds）", attempt, elapsed, total))
			}
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("获取密钥超时: %v", err)
		}

		log.Debug().Err(err).Msg("获取密钥尝试失败，准备重试")

		time.Sleep(1 * time.Second)
	}

	m.ctx.DataKey = key
	m.ctx.ImgKey = imgKey
	if imgKey != "" {
		dat2img.SetAesKey(imgKey)
	}
	if m.ctx.DataDir != "" {
		go dat2img.ScanAndSetXorKey(m.ctx.DataDir)
	}
	m.ctx.Refresh()
	m.ctx.UpdateConfig()

	log.Info().Msg("Successfully got key from new WeChat process.")
	return nil
}

func normalizeKeyAcquireError(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "scan memory failed") || strings.Contains(msg, "task_for_pid") || strings.Contains(msg, "code=-2") {
		return fmt.Errorf(
			"获取密钥失败：macOS 进程内存读取权限不足（task_for_pid）。\n"+
				"请按以下步骤（参考 wx-cli）处理后重试：\n"+
				"1) 对 WeChat 做 ad-hoc 签名（只需一次，升级微信后需重做）:\n"+
				"   codesign --force --deep --sign - /Applications/WeChat.app\n"+
				"2) 重启微信并完成登录:\n"+
				"   killall WeChat && open /Applications/WeChat.app\n"+
				"3) 使用管理员权限启动本程序后再点“重启并获取密钥”:\n"+
				"   sudo -E go run .\n"+
				"若 codesign 报 \"signature in use\"，先执行:\n"+
				"   codesign --remove-signature /Applications/WeChat.app/Contents/Frameworks/vlc_plugins/librtp_mpeg4_plugin.dylib\n"+
				"   codesign --force --deep --sign - /Applications/WeChat.app\n"+
				"原始错误: %w", err)
	}
	return err
}

func isRetryableKeyErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "数据目录未就绪"):
		return true
	case strings.Contains(msg, "wechat process not found"):
		return true
	case strings.Contains(msg, "初始化"):
		return true
	case strings.Contains(msg, "未找到可用的 message_0.db data key"):
		return true
	case strings.Contains(msg, "未找到 all_keys.json"):
		return true
	case strings.Contains(msg, "all_keys.json 为空"):
		return true
	case strings.Contains(msg, "内存扫描未发现候选 key/salt"):
		return true
	case strings.Contains(msg, "扫描到候选 key，但未匹配到任意数据库 salt"):
		return true
	case strings.Contains(msg, "未命中"):
		return true
	default:
		return false
	}
}

func isDarwinPermissionErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "task_for_pid") ||
		strings.Contains(msg, "scan memory failed") ||
		strings.Contains(msg, "code=-2")
}

func isDarwinScanStageErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "内存扫描") ||
		strings.Contains(msg, "all_keys.json") ||
		strings.Contains(msg, "未匹配到任意数据库 salt") ||
		strings.Contains(msg, "未找到可用的 message_0.db")
}

func pickBestWeChatInstance(instances []*iwechat.Account, exePath, platform string) *iwechat.Account {
	var best *iwechat.Account
	for _, inst := range instances {
		if inst == nil {
			continue
		}
		if platform != "" && inst.Platform != platform {
			continue
		}
		if exePath != "" && inst.ExePath != exePath {
			continue
		}
		// 优先有 DataDir 的实例；同等条件下选 PID 更大的（通常是最新进程）
		if best == nil {
			best = inst
			continue
		}
		bestHasData := best.DataDir != ""
		curHasData := inst.DataDir != ""
		if curHasData && !bestHasData {
			best = inst
			continue
		}
		if curHasData == bestHasData && inst.PID > best.PID {
			best = inst
		}
	}
	return best
}

func isDarwinLoginReady(current *iwechat.Account, restartedAt time.Time) bool {
	_ = restartedAt
	if current == nil {
		return false
	}
	// 优先对齐 Windows 的登录判定方式：
	// 通过目标 PID 的 OpenFiles 检测 session.db 是否被进程打开。
	if current.PID != 0 {
		if ok, known := isProcessOpenedSessionDB(current.PID); known {
			return ok
		}
	}
	// 严格模式：未确认打开 session.db 即视为未登录。
	return false
}

// isProcessOpenedSessionDB returns:
//
//	ok    -> whether session.db is opened by target process
//	known -> whether OpenFiles probing is supported and succeeded
func isProcessOpenedSessionDB(pid uint32) (ok bool, known bool) {
	cmd := exec.Command("lsof", "-n", "-P", "-p", strconv.Itoa(int(pid)), "-F", "n")
	out, err := cmd.Output()
	if err != nil {
		return false, false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if len(line) <= 1 || line[0] != 'n' {
			continue
		}
		path := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(line[1:])), "\\", "/")
		if strings.HasSuffix(path, "/db_storage/session/session.db") {
			return true, true
		}
	}
	return false, true
}

func tryDarwinPrivilegedKeyHelper(current *iwechat.Account) (string, error) {
	if current == nil {
		return "", fmt.Errorf("账号为空")
	}
	if current.PID == 0 || current.DataDir == "" {
		return "", fmt.Errorf("微信进程信息不完整，无法提权获取密钥")
	}

	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("获取可执行文件路径失败: %w", err)
	}

	cmd := fmt.Sprintf("%q mac-key-helper --pid %d --data-dir %q", exePath, current.PID, current.DataDir)
	script := fmt.Sprintf("do shell script \"%s\" with administrator privileges", escapeAppleScript(cmd))

	out, err := exec.Command("osascript", "-e", script).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("管理员提权执行失败: %v, 输出: %s", err, strings.TrimSpace(string(out)))
	}

	key := strings.TrimSpace(string(out))
	key = strings.Split(key, "\n")[0]
	if len(key) != 64 {
		return "", fmt.Errorf("管理员提权返回密钥长度异常: %d", len(key))
	}
	if _, err := hex.DecodeString(key); err != nil {
		return "", fmt.Errorf("管理员提权返回无效密钥: %w", err)
	}
	current.Key = strings.ToLower(key)
	return current.Key, nil
}

func escapeAppleScript(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}

func startWeChatProcess(platform, exePath string) error {
	// macOS: 若当前进程为 sudo/root，必须以原登录用户启动微信，
	// 否则微信会落在 /private/var/root/... 导致扫描/解密命中错误账号目录。
	if platform == "darwin" && os.Geteuid() == 0 {
		if sudoUser := strings.TrimSpace(os.Getenv("SUDO_USER")); sudoUser != "" {
			appPath := weChatBundlePath(exePath)
			var cmd *exec.Cmd
			if appPath != "" {
				cmd = exec.Command("sudo", "-u", sudoUser, "open", "-a", appPath)
			} else {
				cmd = exec.Command("sudo", "-u", sudoUser, "open", "-a", "WeChat")
			}
			if err := cmd.Start(); err == nil {
				return nil
			}
			// 兜底：直接以该用户启动二进制
			if exePath != "" {
				if err := exec.Command("sudo", "-u", sudoUser, exePath).Start(); err == nil {
					return nil
				}
			}
		}
	}

	cmd := exec.Command(exePath)
	return cmd.Start()
}

func weChatBundlePath(exePath string) string {
	p := strings.TrimSpace(exePath)
	if p == "" {
		return ""
	}
	n := strings.ReplaceAll(p, "\\", "/")
	idx := strings.Index(strings.ToLower(n), ".app/")
	if idx <= 0 {
		return ""
	}
	return n[:idx+4]
}

func (m *Manager) DecryptDBFiles() error {
	if m.ctx.DataKey == "" {
		if m.ctx.Current == nil {
			return fmt.Errorf("未选择任何账号")
		}
		if err := m.GetDataKey(); err != nil {
			return err
		}
	}
	if m.ctx.WorkDir == "" {
		m.ctx.WorkDir = util.DefaultWorkDir(m.ctx.Account)
	}

	if err := m.wechat.DecryptDBFiles(); err != nil {
		return err
	}
	m.ctx.Refresh()
	m.ctx.UpdateConfig()
	return nil
}

func (m *Manager) StartAutoDecrypt() error {
	if m.ctx.DataKey == "" || m.ctx.DataDir == "" {
		return fmt.Errorf("请先获取密钥")
	}

	// 尝试运行一次解密，验证环境和密钥是否正常
	// 如果解密失败，说明配置或环境有问题，不应开启自动解密
	if err := m.DecryptDBFiles(); err != nil {
		return fmt.Errorf("初始解密失败，无法开启自动解密: %w", err)
	}

	if m.ctx.WorkDir == "" {
		return fmt.Errorf("请先执行解密数据")
	}

	m.wechat.SetAutoDecryptErrorHandler(func(err error) {
		log.Error().Err(err).Msg("自动解密失败，停止服务")
		m.StopAutoDecrypt()

		if m.app != nil {
			m.app.QueueUpdateDraw(func() {
				m.app.showError(fmt.Errorf("自动解密失败，已停止服务: %v", err))
				m.app.updateMenuItemsState()
			})
		}
	})

	if err := m.wechat.StartAutoDecrypt(); err != nil {
		return err
	}

	m.ctx.SetAutoDecrypt(true)
	return nil
}

func (m *Manager) StopAutoDecrypt() error {
	if err := m.wechat.StopAutoDecrypt(); err != nil {
		return err
	}

	m.ctx.SetAutoDecrypt(false)
	return nil
}

func (m *Manager) RefreshSession() error {
	if m.db.GetDB() == nil {
		if err := m.db.Start(); err != nil {
			return err
		}
	}
	resp, err := m.db.GetSessions("", 1, 0)
	if err != nil {
		return err
	}
	if len(resp.Items) == 0 {
		return nil
	}
	m.ctx.LastSession = resp.Items[0].NTime
	return nil
}

func (m *Manager) GetLatestSession() (*model.Session, error) {
	if m.db == nil || m.db.GetDB() == nil {
		return nil, nil
	}
	resp, err := m.db.GetSessions("", 1, 0)
	if err != nil {
		return nil, err
	}
	if len(resp.Items) > 0 {
		return resp.Items[0], nil
	}
	return nil, nil
}

func (m *Manager) CommandKey(configPath string, pid int, force bool, showXorKey bool) (string, error) {

	var err error
	m.ctx, err = ctx.New(configPath)
	if err != nil {
		return "", err
	}

	m.wechat = wechat.NewService(m.ctx)

	m.ctx.WeChatInstances = m.wechat.GetWeChatInstances()
	if len(m.ctx.WeChatInstances) == 0 {
		return "", fmt.Errorf("wechat process not found")
	}

	if len(m.ctx.WeChatInstances) == 1 {
		// 确保当前账户已设置
		if m.ctx.Current == nil {
			m.ctx.SwitchCurrent(m.ctx.WeChatInstances[0])
		}

		key, imgKey := m.ctx.DataKey, m.ctx.ImgKey
		if len(key) == 0 || len(imgKey) == 0 || force {
			key, imgKey, err = m.ctx.WeChatInstances[0].GetKey(context.Background())
			if err != nil {
				return "", err
			}
			m.ctx.Refresh()
			m.ctx.UpdateConfig()
		}

		result := fmt.Sprintf("Data Key: [%s]\nImage Key: [%s]", key, imgKey)
		if m.ctx.Version == 4 && showXorKey {
			if b, err := dat2img.ScanAndSetXorKey(m.ctx.DataDir); err == nil {
				result += fmt.Sprintf("\nXor Key: [0x%X]", b)
			}
		}

		return result, nil
	}
	if pid == 0 {
		str := "Select a process:\n"
		for _, ins := range m.ctx.WeChatInstances {
			str += fmt.Sprintf("PID: %d. %s[Version: %s Data Dir: %s ]\n", ins.PID, ins.Name, ins.FullVersion, ins.DataDir)
		}
		return str, nil
	}
	for _, ins := range m.ctx.WeChatInstances {
		if ins.PID == uint32(pid) {
			// 确保当前账户已设置
			if m.ctx.Current == nil || m.ctx.Current.PID != ins.PID {
				m.ctx.SwitchCurrent(ins)
			}

			key, imgKey := ins.Key, ins.ImgKey
			if len(key) == 0 || len(imgKey) == 0 || force {
				key, imgKey, err = ins.GetKey(context.Background())
				if err != nil {
					return "", err
				}
				m.ctx.Refresh()
				m.ctx.UpdateConfig()
			}
			result := fmt.Sprintf("Data Key: [%s]\nImage Key: [%s]", key, imgKey)
			if m.ctx.Version == 4 && showXorKey {
				if b, err := dat2img.ScanAndSetXorKey(m.ctx.DataDir); err == nil {
					result += fmt.Sprintf("\nXor Key: [0x%X]", b)
				}
			}
			return result, nil
		}
	}
	return "", fmt.Errorf("wechat process not found")
}

func (m *Manager) CommandDecrypt(configPath string, cmdConf map[string]any) error {

	var err error
	m.sc, m.scm, err = conf.LoadServiceConfig(configPath, cmdConf)
	if err != nil {
		return err
	}

	dataDir := m.sc.GetDataDir()
	if len(dataDir) == 0 {
		return fmt.Errorf("dataDir is required")
	}

	dataKey := m.sc.GetDataKey()
	if len(dataKey) == 0 {
		return fmt.Errorf("dataKey is required")
	}

	m.wechat = wechat.NewService(m.sc)

	if err := m.wechat.DecryptDBFiles(); err != nil {
		return err
	}

	return nil
}

func (m *Manager) CommandHTTPServer(configPath string, cmdConf map[string]any) error {

	var err error
	m.sc, m.scm, err = conf.LoadServiceConfig(configPath, cmdConf)
	if err != nil {
		return err
	}

	dataDir := m.sc.GetDataDir()
	workDir := m.sc.GetWorkDir()
	if len(dataDir) == 0 && len(workDir) == 0 {
		return fmt.Errorf("dataDir or workDir is required")
	}

	dataKey := m.sc.GetDataKey()
	if len(dataKey) == 0 {
		return fmt.Errorf("dataKey is required")
	}

	// 如果是 4.0 版本，处理图片密钥
	version := m.sc.GetVersion()
	if version == 4 && len(dataDir) != 0 {
		dat2img.SetAesKey(m.sc.GetImgKey())
		go dat2img.ScanAndSetXorKey(dataDir)
	}

	log.Info().Msgf("server config: %+v", m.sc)

	m.wechat = wechat.NewService(m.sc)

	m.db = database.NewService(m.sc)

	m.http = http.NewService(m.sc, m.db)

	// init db
	go func() {
		// 如果工作目录为空，则解密数据
		if entries, err := os.ReadDir(workDir); err == nil && len(entries) == 0 {
			log.Info().Msgf("work dir is empty, decrypt data.")
			m.db.SetDecrypting()
			if err := m.wechat.DecryptDBFiles(); err != nil {
				log.Info().Msgf("decrypt data failed: %v", err)
				return
			}
			log.Info().Msg("decrypt data success")
		}

		// 按依赖顺序启动服务
		if err := m.db.Start(); err != nil {
			log.Info().Msgf("start db failed, try to decrypt data.")
			m.db.SetDecrypting()
			if err := m.wechat.DecryptDBFiles(); err != nil {
				log.Info().Msgf("decrypt data failed: %v", err)
				return
			}
			log.Info().Msg("decrypt data success")
			if err := m.db.Start(); err != nil {
				log.Info().Msgf("start db failed: %v", err)
				m.db.SetError(err.Error())
				return
			}
		}
	}()

	return m.http.ListenAndServe()
}
