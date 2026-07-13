//go:build darwin

package chatlog

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	keydarwin "github.com/sjzar/chatlog/internal/wechat/key/darwin"
	"github.com/spf13/cobra"
)

var (
	privilegedImageKeyPID     uint32
	privilegedImageKeyDataDir string
)

func init() {
	rootCmd.AddCommand(privilegedImageKeyHelperCmd)
	privilegedImageKeyHelperCmd.Flags().Uint32Var(&privilegedImageKeyPID, "pid", 0, "WeChat PID")
	privilegedImageKeyHelperCmd.Flags().StringVar(&privilegedImageKeyDataDir, "data-dir", "", "WeChat account data directory")
}

var privilegedImageKeyHelperCmd = &cobra.Command{
	Use:    keydarwin.PrivilegedImageKeyHelperCommand,
	Hidden: true,
	Args:   cobra.NoArgs,
	// Override the root logging hook so the short-lived privileged helper does
	// not create root-owned config or log files.
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		_ = cmd
		_ = args
	},
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd
		_ = args
		result := keydarwin.PrivilegedImageKeyResult{}
		switch {
		case os.Geteuid() != 0:
			result.Error = "临时图片密钥辅助进程未获得管理员权限"
		case privilegedImageKeyPID == 0:
			result.Error = "微信进程 PID 无效"
		case privilegedImageKeyDataDir == "":
			result.Error = "微信数据目录为空"
		default:
			key, err := keydarwin.ExtractImageKeyForPID(
				context.Background(),
				privilegedImageKeyPID,
				privilegedImageKeyDataDir,
				nil,
			)
			if err != nil {
				result.Error = err.Error()
			} else if key == "" {
				result.Error = "未找到图片密钥"
			} else {
				result.Key = key
			}
		}
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			fmt.Fprintf(os.Stdout, "{\"error\":%q}\n", err.Error())
		}
	},
}
