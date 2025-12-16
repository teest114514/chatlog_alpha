package wechat

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	"github.com/sjzar/chatlog/internal/wechat/key"
	"github.com/sjzar/chatlog/internal/wechat/key/windows"
	"github.com/sjzar/chatlog/internal/wechat/model"
)

// Account 表示一个微信账号
type Account struct {
	Name        string
	Platform    string
	Version     int
	FullVersion string
	DataDir     string
	Key         string
	ImgKey      string
	PID         uint32
	ExePath     string
	Status      string
}

// NewAccount 创建新的账号对象
func NewAccount(proc *model.Process) *Account {
	account := &Account{
		Name:        proc.AccountName,
		Platform:    proc.Platform,
		Version:     proc.Version,
		FullVersion: proc.FullVersion,
		DataDir:     proc.DataDir,
		PID:         proc.PID,
		ExePath:     proc.ExePath,
		Status:      proc.Status,
	}

	// 尝试从配置中加载保存的密钥
	account.loadKeysFromConfig()

	return account
}

// loadKeysFromConfig 从配置中加载保存的密钥
// 注意：这是一个简化实现，实际需要访问全局配置
func (a *Account) loadKeysFromConfig() {
	// 这里应该从配置文件中加载保存的密钥
	// 由于配置系统在另一个包中，这里暂时留空
	// 密钥会在GetKey函数中通过其他方式加载
}

// RefreshStatus 刷新账号的进程状态
func (a *Account) RefreshStatus() error {
	// 查找所有微信进程
	Load()

	// 首先尝试通过名称查找
	process, err := GetProcess(a.Name)
	if err != nil {
		// 如果通过名称找不到，尝试通过PID查找
		if a.PID != 0 {
			// 获取所有进程
			processes, err := GetAllProcesses()
			if err != nil {
				a.Status = model.StatusOffline
				return nil
			}

			// 通过PID查找
			var foundByPID bool
			for _, p := range processes {
				if p.PID == a.PID {
					process = p
					foundByPID = true
					break
				}
			}

			if !foundByPID {
				// 微信可能重启了，原来的PID找不到进程
				// 尝试查找其他微信进程
				if len(processes) > 0 {
					// 选择第一个微信进程（假设只有一个微信实例）
					process = processes[0]

					// 保存旧的PID用于日志
					oldPID := a.PID

					// 重置账号状态为未登录状态
					a.PID = process.PID
					a.ExePath = process.ExePath
					a.Platform = process.Platform
					a.Version = process.Version
					a.FullVersion = process.FullVersion
					a.Status = process.Status
					a.DataDir = process.DataDir

					// 更新临时账户名称（跟随PID变化）
					oldName := a.Name
					a.Name = fmt.Sprintf("未登录微信_%d", process.PID)

					// 如果名称变化，记录日志
					if oldName != a.Name {
						log.Info().Msgf("临时账户名称从 '%s' 更新为 '%s'", oldName, a.Name)
					}

					log.Info().Msgf("微信可能已重启，PID从 %d 变为 %d，账号重置为未登录状态", oldPID, process.PID)
					return nil
				} else {
					// 没有找到任何微信进程 - 微信可能已退出
					a.clearAccountData()
					log.Info().Msg("微信进程未找到，可能已退出，已清除账号数据")
					return nil
				}
			}
		} else {
			// PID为0，尝试查找所有微信进程
			processes, err := GetAllProcesses()
			if err != nil {
				a.Status = model.StatusOffline
				return nil
			}

			if len(processes) > 0 {
				// 找到微信进程，更新账号信息
				process = processes[0]

				// 更新进程信息
				a.PID = process.PID
				a.ExePath = process.ExePath
				a.Platform = process.Platform
				a.Version = process.Version
				a.FullVersion = process.FullVersion
				a.Status = process.Status
				a.DataDir = process.DataDir

				// 更新临时账户名称（跟随PID变化）
				oldName := a.Name
				a.Name = fmt.Sprintf("未登录微信_%d", process.PID)

				// 如果名称变化，记录日志
				if oldName != a.Name {
					log.Info().Msgf("临时账户名称从 '%s' 更新为 '%s'", oldName, a.Name)
				}

				log.Info().Msgf("微信已重新启动，PID: %d，账号重置为未登录状态", process.PID)
				return nil
			} else {
				// 没有找到任何微信进程
				a.Status = model.StatusOffline
				return nil
			}
		}
	}

	// 检查PID是否变化（微信可能重启了）
	if a.PID != 0 && a.PID != process.PID {
		log.Info().Msgf("微信PID变化：从 %d 变为 %d，可能已重启", a.PID, process.PID)
	}

	// 更新进程信息
	a.PID = process.PID
	a.ExePath = process.ExePath
	a.Platform = process.Platform
	a.Version = process.Version
	a.FullVersion = process.FullVersion
	a.Status = process.Status
	a.DataDir = process.DataDir

	// 如果账号名称是临时名称，但进程有真实的账号名称，更新账号名称
	if strings.HasPrefix(a.Name, "未登录微信_") && process.AccountName != "" && !strings.HasPrefix(process.AccountName, "未登录微信_") {
		a.Name = process.AccountName
	} else if strings.HasPrefix(a.Name, "未登录微信_") && (process.AccountName == "" || strings.HasPrefix(process.AccountName, "未登录微信_")) {
		// 账号名称是临时名称，但进程没有真实名称（或也是临时名称）
		// 检查PID是否变化，如果变化则更新临时名称
		oldName := a.Name
		// 从旧名称中提取旧的PID
		oldPIDStr := strings.TrimPrefix(oldName, "未登录微信_")
		var oldPID uint32
		fmt.Sscanf(oldPIDStr, "%d", &oldPID)

		// 如果PID变化，更新临时名称
		if oldPID != process.PID {
			a.Name = fmt.Sprintf("未登录微信_%d", process.PID)
			log.Info().Msgf("临时账户PID变化，名称从 '%s' 更新为 '%s'", oldName, a.Name)
		}
	}

	return nil
}

// clearAccountData 清除账号数据（当微信退出时调用）
func (a *Account) clearAccountData() {
	// 保存旧的名称用于日志
	oldName := a.Name

	// 重置状态
	a.Status = model.StatusOffline

	// 重置PID
	a.PID = 0

	// 重置账号名称为临时名称（如果还有PID的话）
	// 如果没有PID，保持原有名称或设置为空
	if a.PID == 0 {
		// 如果没有PID，无法生成临时名称，保持原有名称
		// 但可以标记为已退出
		log.Info().Msgf("账号 '%s' 的微信已退出，已清除相关数据", oldName)
	}
}

// GetKey 获取账号的密钥
func (a *Account) GetKey(ctx context.Context) (string, string, error) {
	hasDataKey := a.Key != ""
	hasImgKey := a.ImgKey != ""
	isV4 := a.Version == 4

	// 1. 如果已有Data Key
	if hasDataKey {
		// 非V4，或者V4且有图片Key -> 完美，直接返回
		if !isV4 || hasImgKey {
			log.Info().Msgf("使用保存的密钥，账号: %s", a.Name)
			return a.Key, a.ImgKey, nil
		}

		// V4且缺图片Key -> 尝试补全
		// 此时我们不走标准的Extractor (它会走DLL然后等待30秒)，而是直接用原生扫描器
		if isV4 && !hasImgKey && a.Platform == "windows" {
			log.Info().Msgf("账号 %s 已有数据库密钥，正在尝试使用内存扫描补全图片密钥...", a.Name)
			
			// 刷新状态以获取最新的Process对象
			if err := a.RefreshStatus(); err != nil {
				log.Warn().Err(err).Msg("刷新进程状态失败，返回现有密钥")
				return a.Key, a.ImgKey, nil
			}
			process, err := GetProcess(a.Name)
			if err != nil {
				return a.Key, a.ImgKey, nil
			}

			// 图片密钥扫描依赖 DataDir（需要微信登录成功后才会就绪）
			if process.DataDir == "" {
				log.Info().Msg("检测到数据目录未就绪，等待微信登录...")
				for i := 0; i < 30; i++ {
					time.Sleep(1 * time.Second)
					if err := a.RefreshStatus(); err == nil {
						if p, err := GetProcess(a.Name); err == nil && p.DataDir != "" {
							process = p
							a.DataDir = p.DataDir
							log.Info().Msgf("数据目录已就绪: %s", p.DataDir)
							break
						}
					}
				}
			}
			if process.DataDir == "" {
				log.Warn().Msg("数据目录未就绪，无法补全图片密钥（请确保微信已登录）")
				return a.Key, a.ImgKey, nil
			}

			// 准备验证器
			var validator *decrypt.Validator
			if process.DataDir != "" {
				validator, err = decrypt.NewValidator(process.Platform, process.Version, process.DataDir)
				if err != nil {
					log.Warn().Err(err).Msg("创建验证器失败")
				}
			}

			// 直接调用原生V4扫描器
			v4 := windows.NewV4Extractor()
			if validator != nil {
				v4.SetValidate(validator)
			}
			
			_, imgKey, err := v4.Extract(ctx, process)
			if err == nil && imgKey != "" {
				a.ImgKey = imgKey
				log.Info().Msg("成功补全图片密钥")
			} else {
				log.Warn().Msg("补全图片密钥失败，仅返回数据库密钥")
			}
			
			return a.Key, a.ImgKey, nil
		}
	}

	// 2. 如果没有Data Key -> 走标准流程 (DLL)
	// 刷新进程状态
	if err := a.RefreshStatus(); err != nil {
		return "", "", errors.RefreshProcessStatusFailed(err)
	}

	// 注意：不再检查账号状态是否为online
	// 因为DLL提取器支持在未登录状态下工作
	// 用户可以在获取密钥过程中登录微信

	// 创建密钥提取器 - 使用新的接口，传入平台和版本信息
	extractor, err := key.NewExtractor(a.Platform, a.Version)
	if err != nil {
		return "", "", err
	}

	process, err := GetProcess(a.Name)
	if err != nil {
		return "", "", err
	}

	// 对于 Windows V4：
	// - DLL 提取器（InitializeHook/注入）不依赖 DataDir，应在微信进程出现后立即执行；
	// - 只有在非 DLL（纯内存扫描）模式下，才需要等待 DataDir 就绪来提升验证成功率。
	if isV4 && process.DataDir == "" && a.Platform == "windows" {
		if _, ok := extractor.(*windows.DLLExtractor); ok {
			log.Info().Msg("检测到V4版本且数据目录未就绪，将先初始化DLL Hook（无需等待登录），登录后打开聊天窗口即可触发密钥获取")
		} else {
			log.Info().Msg("检测到V4版本且数据目录未就绪（非DLL模式），等待微信登录...")
			for i := 0; i < 30; i++ {
				time.Sleep(1 * time.Second)
				if err := a.RefreshStatus(); err == nil {
					if p, err := GetProcess(a.Name); err == nil && p.DataDir != "" {
						process = p
						a.DataDir = p.DataDir
						log.Info().Msgf("数据目录已就绪: %s", p.DataDir)
						break
					}
				}
			}
		}
	}

	// 只有在DataDir存在时才创建验证器
	// 对于DLL方式，微信可能未登录，DataDir可能为空或路径不存在
	var validator *decrypt.Validator
	if process.DataDir != "" {
		log.Info().Msgf("准备创建验证器，DataDir: %s", process.DataDir)
		validator, err = decrypt.NewValidator(process.Platform, process.Version, process.DataDir)
		if err != nil {
			// 如果创建验证器失败，记录警告但不返回错误
			// 因为DLL方式可以不依赖验证器
			log.Warn().Err(err).Msg("创建验证器失败，将继续尝试获取密钥（DLL方式可能不需要验证器）")
			validator = nil
		}
	}

	if validator != nil {
		extractor.SetValidate(validator)
	}

	// 提取密钥
	// 注意：如果这是V4，且DLL只拿到Data Key，dll_extractor内部的fallback机制会被触发
	// 自动去跑原生扫描来拿Image Key
	dataKey, imgKey, err := extractor.Extract(ctx, process)
	if err != nil {
		return "", "", err
	}

	if dataKey != "" {
		a.Key = dataKey
	}

	if imgKey != "" {
		a.ImgKey = imgKey
	}

	return dataKey, imgKey, nil
}

// GetImageKey 仅尝试获取图片密钥（使用原生扫描器）
func (a *Account) GetImageKey(ctx context.Context) (string, error) {
	// 只有Windows V4支持此功能
	if a.Platform != "windows" || a.Version != 4 {
		return "", fmt.Errorf("只支持Windows微信V4版本获取图片密钥")
	}

	// 刷新进程状态
	if err := a.RefreshStatus(); err != nil {
		return "", errors.RefreshProcessStatusFailed(err)
	}

	process, err := GetProcess(a.Name)
	if err != nil {
		return "", err
	}

	// 等待DataDir就绪
	if process.DataDir == "" {
		log.Info().Msg("检测到数据目录未就绪，等待微信登录...")
		for i := 0; i < 30; i++ {
			time.Sleep(1 * time.Second)
			if err := a.RefreshStatus(); err == nil {
				if p, err := GetProcess(a.Name); err == nil && p.DataDir != "" {
					process = p
					a.DataDir = p.DataDir
					log.Info().Msgf("数据目录已就绪: %s", p.DataDir)
					break
				}
			}
		}
	}

	if process.DataDir == "" {
		return "", fmt.Errorf("数据目录未就绪，无法进行图片密钥扫描，请确保微信已登录")
	}

	// 准备验证器
	validator, err := decrypt.NewValidator(process.Platform, process.Version, process.DataDir)
	if err != nil {
		return "", fmt.Errorf("创建验证器失败(请确保已浏览过图片以生成缓存): %v", err)
	}

	// 直接调用原生V4扫描器
	v4 := windows.NewV4Extractor()
	v4.SetValidate(validator)
	
	log.Info().Msg("正在启动内存扫描以获取图片密钥...")
	_, imgKey, err := v4.Extract(ctx, process)
	if err != nil {
		return "", err
	}
	
	if imgKey != "" {
		a.ImgKey = imgKey
		return imgKey, nil
	}

	return "", fmt.Errorf("未能获取到图片密钥")
}

// DecryptDatabase 解密数据库
func (a *Account) DecryptDatabase(ctx context.Context, dbPath, outputPath string) error {
	// 获取密钥
	hexKey, _, err := a.GetKey(ctx)
	if err != nil {
		return err
	}

	// 创建解密器 - 传入平台信息和版本
	decryptor, err := decrypt.NewDecryptor(a.Platform, a.Version)
	if err != nil {
		return err
	}

	// 创建输出文件
	output, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer output.Close()

	// 解密数据库
	return decryptor.Decrypt(ctx, dbPath, hexKey, output)
}
