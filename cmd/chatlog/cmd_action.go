package chatlog

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	chatlogapp "github.com/sjzar/chatlog/internal/chatlog"
)

type actionEvent struct {
	Type      string      `json:"type"`
	Action    string      `json:"action,omitempty"`
	Stage     string      `json:"stage,omitempty"`
	Message   string      `json:"message,omitempty"`
	ErrorCode string      `json:"error_code,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Timestamp string      `json:"timestamp"`
}

func emitActionEvent(eventType, action, stage, message, errorCode string, data interface{}) {
	payload := actionEvent{
		Type:      eventType,
		Action:    action,
		Stage:     stage,
		Message:   message,
		ErrorCode: errorCode,
		Data:      data,
		Timestamp: time.Now().Format(time.RFC3339),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stdout, "{\"type\":\"error\",\"message\":%q,\"timestamp\":%q}\n", err.Error(), time.Now().Format(time.RFC3339))
		return
	}
	fmt.Fprintln(os.Stdout, string(encoded))
}

var (
	actionPID     int
	actionHistory string

	setHTTPAddr                       string
	setWorkDir                        string
	setDataKey                        string
	setImageKey                       string
	setDataDir                        string
	setWalEnabled                     bool
	setWalEnabledProvided             bool
	setAutoDecompressDebounce         int
	setAutoDecompressDebounceProvided bool
	setLogRetentionDays               int
	setLogRetentionDaysProvided       bool
)

var actionCmd = &cobra.Command{
	Use:   "action",
	Short: "面向前端和脚本的 JSON Lines 动作接口",
}

func init() {
	rootCmd.AddCommand(actionCmd)
	actionCmd.AddCommand(
		actionStatusCmd,
		actionListAccountsCmd,
		actionGetImageKeyCmd,
		actionRestartAndGetKeyCmd,
		actionDecompressCmd,
		actionStartHTTPCmd,
		actionStartAutoDecompressCmd,
		actionSetCmd,
		actionSwitchAccountCmd,
	)
	for _, command := range []*cobra.Command{
		actionStatusCmd,
		actionGetImageKeyCmd,
		actionRestartAndGetKeyCmd,
		actionDecompressCmd,
		actionStartHTTPCmd,
		actionStartAutoDecompressCmd,
		actionSwitchAccountCmd,
	} {
		addTargetFlags(command)
	}
	actionSetCmd.Flags().StringVar(&setHTTPAddr, "http-addr", "", "HTTP 监听地址")
	actionSetCmd.Flags().StringVar(&setWorkDir, "work-dir", "", "工作目录")
	actionSetCmd.Flags().StringVar(&setDataKey, "data-key", "", "数据库密钥")
	actionSetCmd.Flags().StringVar(&setImageKey, "image-key", "", "图片密钥")
	actionSetCmd.Flags().StringVar(&setDataDir, "data-dir", "", "微信数据目录")
	actionSetCmd.Flags().BoolVar(&setWalEnabled, "wal-enabled", false, "WAL 开关值")
	actionSetCmd.Flags().BoolVar(&setWalEnabledProvided, "set-wal-enabled", false, "应用 WAL 开关")
	actionSetCmd.Flags().IntVar(&setAutoDecompressDebounce, "auto-decompress-debounce", 0, "自动解密防抖毫秒数")
	actionSetCmd.Flags().BoolVar(&setAutoDecompressDebounceProvided, "set-auto-decompress-debounce", false, "应用自动解密防抖值")
	actionSetCmd.Flags().IntVar(&setLogRetentionDays, "log-retention-days", 0, "日志保留天数（1-365）")
	actionSetCmd.Flags().BoolVar(&setLogRetentionDaysProvided, "set-log-retention-days", false, "应用日志保留天数")
}

var actionStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "输出当前状态",
	Run: func(cmd *cobra.Command, args []string) {
		manager := initSelectedActionManager("status")
		if manager != nil {
			emitActionEvent("success", "status", "completed", "已输出当前状态", "", manager.Snapshot())
		}
	},
}

var actionListAccountsCmd = &cobra.Command{
	Use:   "list-accounts",
	Short: "列出运行中与历史账号",
	Run: func(cmd *cobra.Command, args []string) {
		manager, err := initActionManager()
		if err != nil {
			emitActionFailure("list-accounts", "init_failed", err)
			return
		}
		emitActionEvent("success", "list-accounts", "completed", "已输出账号列表", "", manager.ListAccounts())
	},
}

var actionGetImageKeyCmd = &cobra.Command{
	Use:   "get-image-key",
	Short: "获取图片解密密钥",
	Run: func(cmd *cobra.Command, args []string) {
		manager := initSelectedActionManager("get-image-key")
		if manager == nil {
			return
		}
		emitActionEvent("action_started", "get-image-key", "starting", "开始获取图片密钥", "", manager.Snapshot())
		err := manager.GetImageKeyWithStatus(actionProgress("get-image-key"))
		if err != nil {
			emitActionFailure("get-image-key", "get_image_key_failed", err)
			return
		}
		emitActionEvent("success", "get-image-key", "completed", "已获取图片密钥", "", manager.Snapshot())
	},
}

var actionRestartAndGetKeyCmd = &cobra.Command{
	Use:   "restart-and-get-key",
	Short: "重启微信并获取数据库密钥",
	Run: func(cmd *cobra.Command, args []string) {
		manager := initSelectedActionManager("restart-and-get-key")
		if manager == nil {
			return
		}
		emitActionEvent("action_started", "restart-and-get-key", "starting", "开始获取数据库密钥", "", manager.Snapshot())
		err := manager.RestartAndGetDataKey(actionProgress("restart-and-get-key"))
		if err != nil {
			emitActionFailure("restart-and-get-key", "restart_and_get_key_failed", err)
			return
		}
		emitActionEvent("success", "restart-and-get-key", "completed", "已获取数据库密钥", "", manager.Snapshot())
	},
}

var actionDecompressCmd = &cobra.Command{
	Use:   "decompress-data",
	Short: "解密聊天数据库",
	Run: func(cmd *cobra.Command, args []string) {
		manager := initSelectedActionManager("decompress-data")
		if manager == nil {
			return
		}
		emitActionEvent("action_started", "decompress-data", "starting", "开始解密数据", "", manager.Snapshot())
		if err := manager.DecryptDBFiles(); err != nil {
			emitActionFailure("decompress-data", "decompress_failed", err)
			return
		}
		emitActionEvent("success", "decompress-data", "completed", "数据解密完成", "", manager.Snapshot())
	},
}

var actionStartHTTPCmd = &cobra.Command{
	Use:   "start-http",
	Short: "启动 HTTP 服务并保持运行",
	Run: func(cmd *cobra.Command, args []string) {
		manager := initSelectedActionManager("start-http")
		if manager == nil {
			return
		}
		emitActionEvent("action_started", "start-http", "starting", "正在启动 HTTP 服务", "", manager.Snapshot())
		if err := manager.StartService(); err != nil {
			emitActionFailure("start-http", "start_http_failed", err)
			return
		}
		emitActionEvent("success", "start-http", "running", "HTTP 服务已启动", "", manager.Snapshot())
		waitForActionSignal(func() {
			if err := manager.StopService(); err != nil {
				log.Error().Err(err).Msg("stop action HTTP service failed")
			}
		})
	},
}

var actionStartAutoDecompressCmd = &cobra.Command{
	Use:   "start-auto-decompress",
	Short: "启动自动解密并保持运行",
	Run: func(cmd *cobra.Command, args []string) {
		manager := initSelectedActionManager("start-auto-decompress")
		if manager == nil {
			return
		}
		emitActionEvent("action_started", "start-auto-decompress", "starting", "正在启动自动解密", "", manager.Snapshot())
		if err := manager.StartAutoDecrypt(); err != nil {
			emitActionFailure("start-auto-decompress", "start_auto_decompress_failed", err)
			return
		}
		emitActionEvent("success", "start-auto-decompress", "running", "自动解密已启动", "", manager.Snapshot())
		waitForActionSignal(func() {
			if err := manager.StopAutoDecrypt(); err != nil {
				log.Error().Err(err).Msg("stop action auto decrypt failed")
			}
		})
	},
}

var actionSetCmd = &cobra.Command{
	Use:   "set",
	Short: "更新运行配置",
	Run: func(cmd *cobra.Command, args []string) {
		manager, err := initActionManager()
		if err != nil {
			emitActionFailure("set", "init_failed", err)
			return
		}
		err = manager.SetConfigValues(
			setHTTPAddr,
			setWorkDir,
			setDataKey,
			setImageKey,
			setDataDir,
			optionalActionBool(setWalEnabledProvided, setWalEnabled),
			optionalActionInt(setAutoDecompressDebounceProvided, setAutoDecompressDebounce),
			optionalActionInt(setLogRetentionDaysProvided, setLogRetentionDays),
		)
		if err != nil {
			emitActionFailure("set", "set_failed", err)
			return
		}
		emitActionEvent("success", "set", "completed", "配置已更新", "", manager.Snapshot())
	},
}

var actionSwitchAccountCmd = &cobra.Command{
	Use:   "switch-account",
	Short: "切换当前账号",
	Run: func(cmd *cobra.Command, args []string) {
		if actionPID == 0 && actionHistory == "" {
			emitActionFailure("switch-account", "invalid_args", fmt.Errorf("必须提供 --pid 或 --history"))
			return
		}
		manager, err := initActionManager()
		if err != nil {
			emitActionFailure("switch-account", "init_failed", err)
			return
		}
		emitActionEvent("action_started", "switch-account", "starting", "开始切换账号", "", nil)
		if err := manager.SwitchToAccount(actionPID, actionHistory); err != nil {
			emitActionFailure("switch-account", "switch_account_failed", err)
			return
		}
		emitActionEvent("success", "switch-account", "completed", "账号切换完成", "", manager.Snapshot())
	},
}

func addTargetFlags(command *cobra.Command) {
	command.Flags().IntVar(&actionPID, "pid", 0, "目标微信 PID")
	command.Flags().StringVar(&actionHistory, "history", "", "历史账号名")
}

func initActionManager() (*chatlogapp.Manager, error) {
	manager := chatlogapp.New()
	if err := manager.InitAction(""); err != nil {
		return nil, err
	}
	return manager, nil
}

func initSelectedActionManager(action string) *chatlogapp.Manager {
	manager, err := initActionManager()
	if err != nil {
		emitActionFailure(action, "init_failed", err)
		return nil
	}
	if err := manager.SelectAccount(actionPID, actionHistory); err != nil {
		emitActionFailure(action, "select_account_failed", err)
		return nil
	}
	return manager
}

func actionProgress(action string) func(string) {
	return func(message string) {
		emitActionEvent("state", action, "progress", message, "", nil)
	}
}

func emitActionFailure(action, code string, err error) {
	emitActionEvent("error", action, code, err.Error(), code, nil)
}

func waitForActionSignal(cleanup func()) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	if cleanup != nil {
		cleanup()
	}
}

func optionalActionBool(enabled, value bool) *bool {
	if !enabled {
		return nil
	}
	result := value
	return &result
}

func optionalActionInt(enabled bool, value int) *int {
	if !enabled {
		return nil
	}
	result := value
	return &result
}
