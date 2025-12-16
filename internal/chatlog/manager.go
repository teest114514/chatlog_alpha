package chatlog

import (
	"context"
	"fmt"
	"os"
	"os/exec"
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
	if m.ctx.AutoDecrypt {
		if err := m.StopAutoDecrypt(); err != nil {
			return err
		}
	}
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
	if _, err := m.wechat.GetImageKey(m.ctx.Current); err != nil {
		return err
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
	cmd := exec.Command(exePath)
	if err := cmd.Start(); err != nil {
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

	// 6. Get the key
	// 增加重试逻辑：微信刚启动时可能DLL未加载完成导致Hook失败，需要等待
	log.Info().Msg("Getting key from new WeChat process...")

	// 使用携带回调的 context
	ctx := context.WithValue(context.Background(), "status_callback", onStatus)

	var key, imgKey string

	// 初始化截止时间 (30秒)
	deadline := time.Now().Add(30 * time.Second)

	for {
		if onStatus != nil {
			onStatus("正在等待微信初始化...")
		}

		// 尝试获取密钥 (会尝试初始化DLL)
		key, imgKey, err = m.ctx.Current.GetKey(ctx)

		// 如果成功，跳出循环
		// 注意：GetKey 成功意味着 Hook 安装成功且已经获取到了密钥
		// 但实际上 DLL 模式下，Extract 会在 Hook 安装成功后阻塞轮询。
		// 所以如果这里返回 nil，说明已经完成了整个流程。
		if err == nil {
			break
		}

		// 如果超时，且包含特定错误，则退出
		if time.Now().After(deadline) {
			return fmt.Errorf("获取密钥超时: %v", err)
		}

		// 检查错误类型，决定是否重试
		// 如果是初始化失败（例如微信模块未加载），则重试
		// 如果是 "wechat process not found" 等临时错误，也重试
		// 如果是 pollKeys 内部的超时（30s），说明 Hook 成功但用户未操作，此时不应该重试，
		// 但 pollKeys 内部超时会返回错误，这里会捕获。
		// 不过 pollKeys 耗时 30s，如果走到这里说明已经等了 30s，外层 deadline 也会触发。
		
		// 只有快速失败（初始化错误）才需要 fast retry
		log.Debug().Err(err).Msg("获取密钥尝试失败，准备重试")
		
		time.Sleep(1 * time.Second)
	}

	m.ctx.DataKey = key
	m.ctx.ImgKey = imgKey
	m.ctx.Refresh()
	m.ctx.UpdateConfig()

	log.Info().Msg("Successfully got key from new WeChat process.")
	return nil
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

	if m.sc.GetAutoDecrypt() {
		if err := m.wechat.StartAutoDecrypt(); err != nil {
			return err
		}
		log.Info().Msg("auto decrypt is enabled")
	}

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

