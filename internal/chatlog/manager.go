package chatlog

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
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
	keydarwin "github.com/sjzar/chatlog/internal/wechat/key/darwin"
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

func (m *Manager) GetImageKey(onStatus func(string)) error {
	if m.ctx.Current == nil {
		return fmt.Errorf("未选择任何账号")
	}
	if onStatus != nil {
		onStatus("正在优先尝试本地推导图片密钥")
	}
	imgKey, err := m.wechat.GetImageKeyWithStatus(m.ctx.Current, onStatus)
	if err != nil && runtime.GOOS == "darwin" && errors.Is(err, keydarwin.ErrImageKeyPermission) {
		if onStatus != nil {
			onStatus("普通用户无法读取微信内存，准备请求临时管理员授权")
		}
		dataDir := m.ctx.Current.DataDir
		if dataDir == "" {
			dataDir = m.ctx.DataDir
		}
		imgKey, err = keydarwin.ExtractImageKeyWithAuthorization(
			context.Background(),
			m.ctx.Current.PID,
			dataDir,
			onStatus,
		)
	}
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
	if onStatus != nil {
		onStatus("图片密钥已保存；本次任务未保留管理员权限")
	}
	return nil
}

func (m *Manager) RestartAndGetDataKey(onStatus func(string)) error {
	if m.ctx.Current == nil {
		return fmt.Errorf("未选择任何账号")
	}

	pid := m.ctx.Current.PID
	exePath := m.ctx.Current.ExePath
	platform := m.ctx.Current.Platform
	dataDir := m.ctx.Current.DataDir
	if dataDir == "" {
		dataDir = m.ctx.DataDir
	}

	// macOS：数据库密钥仅通过 Frida Hook CCKeyDerivationPBKDF 提取（已移除内存扫描）。
	if platform == "darwin" {
		if !keydarwin.FridaAvailable() {
			return fmt.Errorf("提取数据库密钥需要 Frida：请先执行 pip3 install frida-tools")
		}
		if onStatus != nil {
			onStatus("[1/6] 检查 Frida 环境")
		}
		log.Info().Msg("RestartAndGetDataKey: Frida-only data key path")

		ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
		defer cancel()

		key, candidates, err := keydarwin.ExtractKeysViaFrida(ctx, dataDir, onStatus)
		if err != nil {
			return fmt.Errorf("Frida 提取密钥失败: %w", err)
		}

		newInstance := pickBestWeChatInstance(m.wechat.GetWeChatInstances(), exePath, platform)
		if newInstance != nil && newInstance.DataDir != "" {
			dataDir = newInstance.DataDir
		}
		// The account data directory is normally known before Frida starts. Do
		// not wait another 120 seconds merely to refresh process metadata.
		if dataDir == "" {
			deadline := time.Now().Add(120 * time.Second)
			for time.Now().Before(deadline) {
				if best := pickBestWeChatInstance(m.wechat.GetWeChatInstances(), exePath, platform); best != nil {
					newInstance = best
					if best.DataDir != "" {
						dataDir = best.DataDir
						break
					}
				}
				if onStatus != nil {
					onStatus("[6/6] 密钥已捕获，等待微信登录并准备数据目录")
				}
				time.Sleep(1 * time.Second)
			}
		} else if onStatus != nil {
			onStatus("[6/6] 已找到账号数据目录，正在保存数据库密钥")
		}
		if newInstance != nil {
			m.ctx.SwitchCurrent(newInstance)
		}
		if dataDir != "" {
			if _, _, applyErr := keydarwin.ApplyCapturedKeysToDataDir(dataDir, candidates, onStatus); applyErr != nil {
				log.Warn().Err(applyErr).Msg("apply frida key to all_keys.json failed")
			}
		}

		m.ctx.DataKey = key
		if m.ctx.Current != nil {
			m.ctx.Current.Key = key
			m.ctx.Current.DataDir = dataDir
		}
		if m.ctx.DataDir == "" && dataDir != "" {
			m.ctx.DataDir = dataDir
		}

		// Keep image-key extraction separate: its task_for_pid memory-scan
		// fallback may require elevated privileges. This data-key action must
		// remain safe to run as the logged-in user.
		if m.ctx.DataDir != "" {
			go dat2img.ScanAndSetXorKey(m.ctx.DataDir)
		}
		m.ctx.Refresh()
		m.ctx.UpdateConfig()
		if onStatus != nil {
			onStatus("Frida 提取密钥成功")
		}
		log.Info().Msg("Successfully got data key via Frida")
		return nil
	}

	// Windows / 其他平台：重启进程后走平台 Extractor。
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

	log.Info().Msg("Waiting for WeChat process to terminate...")
	for i := 0; i < 10; i++ {
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

	if onStatus != nil {
		onStatus("正在重启微信...")
	}
	log.Info().Msgf("Restarting WeChat from %s", exePath)
	if err := startWeChatProcess(platform, exePath); err != nil {
		return fmt.Errorf("failed to restart WeChat: %w", err)
	}

	if onStatus != nil {
		onStatus("正在等待新进程启动...")
	}
	var newInstance *iwechat.Account
	for i := 0; i < 30; i++ {
		instances := m.wechat.GetWeChatInstances()
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
	m.ctx.SwitchCurrent(newInstance)

	ctx := context.WithValue(context.Background(), "status_callback", onStatus)
	ctx = context.WithValue(ctx, "force_key_refresh", true)
	ctx = context.WithValue(ctx, "force_rescan_memory", true)

	var key, imgKey string
	waitWindow := 30 * time.Second
	deadline := time.Now().Add(waitWindow)
	started := time.Now()
	attempt := 0
	for {
		attempt++
		if onStatus != nil {
			elapsed := int(time.Since(started).Seconds())
			onStatus(fmt.Sprintf("正在获取密钥...（重试 %d 次，已等待 %ds/%ds）", attempt, elapsed, int(waitWindow.Seconds())))
		}
		key, imgKey, err = m.ctx.Current.GetKey(ctx)
		if err == nil {
			break
		}
		if !isRetryableKeyErr(err) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("获取密钥超时: %v", err)
		}
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
	case strings.Contains(msg, "未找到 all_keys.json"):
		return true
	case strings.Contains(msg, "all_keys.json 为空"):
		return true
	case strings.Contains(msg, "frida"):
		return true
	case strings.Contains(msg, "未捕获到密钥"):
		return true
	default:
		return false
	}
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
