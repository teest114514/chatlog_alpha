package windows

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/sjzar/chatlog/internal/wechat/model"
)

// initializeProcessInfo 获取进程的数据目录和账户名
func initializeProcessInfo(p *process.Process, info *model.Process) error {
	files, err := p.OpenFiles()
	if err != nil {
		log.Err(err).Msgf("获取进程 %d 的打开文件失败", p.Pid)
		// 即使获取打开文件失败，也返回进程信息（状态保持为offline）
		// 为未登录的进程生成临时账号名称
		info.AccountName = fmt.Sprintf("未登录微信_%d", p.Pid)
		return nil
	}

	// 仅支持微信 V4：通过 session.db 推导 DataDir 与账号名
	dbPath := V4DBFile

	for _, f := range files {
		if strings.HasSuffix(f.Path, dbPath) {
			filePath := f.Path[4:] // 移除 "\\?\" 前缀
			parts := strings.Split(filePath, string(filepath.Separator))
			if len(parts) < 4 {
				log.Debug().Msg("无效的文件路径: " + filePath)
				continue
			}

			info.Status = model.StatusOnline
			info.DataDir = strings.Join(parts[:len(parts)-3], string(filepath.Separator))
			info.AccountName = parts[len(parts)-4]
			return nil
		}
	}

	// 如果没有找到数据库文件，进程仍然存在，只是未登录
	// 状态保持为 model.StatusOffline（调用方会处理）
	// 为未登录的进程生成临时账号名称
	info.AccountName = fmt.Sprintf("未登录微信_%d", p.Pid)
	return nil
}
