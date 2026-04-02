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

	"github.com/sjzar/chatlog/internal/chatlog"
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
	b, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stdout, "{\"type\":\"error\",\"message\":\"marshal action event failed: %v\",\"timestamp\":\"%s\"}\n", err, time.Now().Format(time.RFC3339))
		return
	}
	fmt.Fprintln(os.Stdout, string(b))
}

func init() {
	rootCmd.AddCommand(actionCmd)

	actionCmd.AddCommand(actionStatusCmd)
	actionCmd.AddCommand(actionListAccountsCmd)
	actionCmd.AddCommand(actionGetImageKeyCmd)
	actionCmd.AddCommand(actionRestartAndGetKeyCmd)
	actionCmd.AddCommand(actionDecompressCmd)
	actionCmd.AddCommand(actionStartHTTPCmd)
	actionCmd.AddCommand(actionStartAutoDecompressCmd)
	actionCmd.AddCommand(actionSetCmd)
	actionCmd.AddCommand(actionSwitchAccountCmd)

	addTargetFlags(actionStatusCmd)
	addTargetFlags(actionGetImageKeyCmd)
	addTargetFlags(actionRestartAndGetKeyCmd)
	addTargetFlags(actionDecompressCmd)
	addTargetFlags(actionStartHTTPCmd)
	addTargetFlags(actionStartAutoDecompressCmd)
	addTargetFlags(actionSwitchAccountCmd)

	actionSetCmd.Flags().StringVar(&setHTTPAddr, "http-addr", "", "http listen addr")
	actionSetCmd.Flags().StringVar(&setWorkDir, "work-dir", "", "work dir")
	actionSetCmd.Flags().StringVar(&setDataKey, "data-key", "", "data key")
	actionSetCmd.Flags().StringVar(&setImageKey, "image-key", "", "image key")
	actionSetCmd.Flags().StringVar(&setDataDir, "data-dir", "", "data dir")
	actionSetCmd.Flags().BoolVar(&setWalEnabled, "wal-enabled", false, "enable wal")
	actionSetCmd.Flags().BoolVar(&setWalEnabledProvided, "set-wal-enabled", false, "apply wal enabled flag")
	actionSetCmd.Flags().IntVar(&setAutoDecompressDebounce, "auto-decompress-debounce", 0, "auto decompress debounce ms")
	actionSetCmd.Flags().BoolVar(&setAutoDecompressDebounceProvided, "set-auto-decompress-debounce", false, "apply auto decompress debounce")
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
)

var actionCmd = &cobra.Command{
	Use:   "action",
	Short: "前端可调用的动作接口",
}

var actionStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "输出当前状态",
	Run: func(cmd *cobra.Command, args []string) {
		m, err := initActionManager()
		if err != nil {
			emitActionEvent("error", "status", "init_failed", err.Error(), "init_failed", nil)
			return
		}
		if err := m.SelectAccount(actionPID, actionHistory); err != nil {
			emitActionEvent("error", "status", "select_account_failed", err.Error(), "select_account_failed", nil)
			return
		}
		emitActionEvent("success", "status", "completed", "已输出当前状态", "", m.Snapshot())
	},
}

var actionListAccountsCmd = &cobra.Command{
	Use:   "list-accounts",
	Short: "列出运行中与历史账号",
	Run: func(cmd *cobra.Command, args []string) {
		m, err := initActionManager()
		if err != nil {
			emitActionEvent("error", "list-accounts", "init_failed", err.Error(), "init_failed", nil)
			return
		}
		emitActionEvent("success", "list-accounts", "completed", "已输出账号列表", "", m.ListAccounts())
	},
}

var actionGetImageKeyCmd = &cobra.Command{
	Use:   "get-image-key",
	Short: "获取图片解压密钥",
	Run: func(cmd *cobra.Command, args []string) {
		m, err := initActionManager()
		if err != nil {
			emitActionEvent("error", "get-image-key", "init_failed", err.Error(), "init_failed", nil)
			return
		}
		if err := m.SelectAccount(actionPID, actionHistory); err != nil {
			emitActionEvent("error", "get-image-key", "select_account_failed", err.Error(), "select_account_failed", nil)
			return
		}

		emitActionEvent("action_started", "get-image-key", "starting", "开始获取图片解压密钥", "", m.Snapshot())
		err = m.GetImageKeyWithStatus(func(message string) {
			emitActionEvent("state", "get-image-key", "progress", message, "", nil)
		})
		if err != nil {
			emitActionEvent("error", "get-image-key", "failed", err.Error(), "get_image_key_failed", nil)
			return
		}
		emitActionEvent("success", "get-image-key", "completed", "已获取图片解压密钥", "", m.Snapshot())
	},
}

var actionRestartAndGetKeyCmd = &cobra.Command{
	Use:   "restart-and-get-key",
	Short: "重启微信并获取解压密钥",
	Run: func(cmd *cobra.Command, args []string) {
		m, err := initActionManager()
		if err != nil {
			emitActionEvent("error", "restart-and-get-key", "init_failed", err.Error(), "init_failed", nil)
			return
		}
		if err := m.SelectAccount(actionPID, actionHistory); err != nil {
			emitActionEvent("error", "restart-and-get-key", "select_account_failed", err.Error(), "select_account_failed", nil)
			return
		}

		emitActionEvent("action_started", "restart-and-get-key", "starting", "开始重启微信并获取解压密钥", "", m.Snapshot())
		err = m.RestartAndGetDataKey(func(message string) {
			emitActionEvent("state", "restart-and-get-key", "progress", message, "", nil)
		})
		if err != nil {
			emitActionEvent("error", "restart-and-get-key", "failed", err.Error(), "restart_and_get_key_failed", nil)
			return
		}
		emitActionEvent("success", "restart-and-get-key", "completed", "已获取解压密钥", "", m.Snapshot())
	},
}

var actionDecompressCmd = &cobra.Command{
	Use:   "decompress-data",
	Short: "解压聊天数据",
	Run: func(cmd *cobra.Command, args []string) {
		m, err := initActionManager()
		if err != nil {
			emitActionEvent("error", "decompress-data", "init_failed", err.Error(), "init_failed", nil)
			return
		}
		if err := m.SelectAccount(actionPID, actionHistory); err != nil {
			emitActionEvent("error", "decompress-data", "select_account_failed", err.Error(), "select_account_failed", nil)
			return
		}

		emitActionEvent("action_started", "decompress-data", "starting", "开始解压数据", "", m.Snapshot())
		if err := m.DecryptDBFiles(); err != nil {
			emitActionEvent("error", "decompress-data", "failed", err.Error(), "decompress_failed", nil)
			return
		}
		emitActionEvent("success", "decompress-data", "completed", "数据解压完成", "", m.Snapshot())
	},
}

var actionStartHTTPCmd = &cobra.Command{
	Use:   "start-http",
	Short: "启动 HTTP 服务并保持运行",
	Run: func(cmd *cobra.Command, args []string) {
		m, err := initActionManager()
		if err != nil {
			emitActionEvent("error", "start-http", "init_failed", err.Error(), "init_failed", nil)
			return
		}
		if err := m.SelectAccount(actionPID, actionHistory); err != nil {
			emitActionEvent("error", "start-http", "select_account_failed", err.Error(), "select_account_failed", nil)
			return
		}

		emitActionEvent("action_started", "start-http", "starting", "正在启动 HTTP 服务", "", m.Snapshot())
		if err := m.StartService(); err != nil {
			emitActionEvent("error", "start-http", "failed", err.Error(), "start_http_failed", nil)
			return
		}
		emitActionEvent("success", "start-http", "running", "HTTP 服务已启动，进程保持运行中", "", m.Snapshot())

		waitForSignal(func() {
			if err := m.StopService(); err != nil {
				log.Err(err).Msg("stop http service failed")
			}
		})
	},
}

var actionStartAutoDecompressCmd = &cobra.Command{
	Use:   "start-auto-decompress",
	Short: "启动自动解压并保持运行",
	Run: func(cmd *cobra.Command, args []string) {
		m, err := initActionManager()
		if err != nil {
			emitActionEvent("error", "start-auto-decompress", "init_failed", err.Error(), "init_failed", nil)
			return
		}
		if err := m.SelectAccount(actionPID, actionHistory); err != nil {
			emitActionEvent("error", "start-auto-decompress", "select_account_failed", err.Error(), "select_account_failed", nil)
			return
		}

		emitActionEvent("action_started", "start-auto-decompress", "starting", "正在启动自动解压", "", m.Snapshot())
		if err := m.StartAutoDecrypt(); err != nil {
			emitActionEvent("error", "start-auto-decompress", "failed", err.Error(), "start_auto_decompress_failed", nil)
			return
		}
		emitActionEvent("success", "start-auto-decompress", "running", "自动解压已启动，进程保持运行中", "", m.Snapshot())

		waitForSignal(func() {
			if err := m.StopAutoDecrypt(); err != nil {
				log.Err(err).Msg("stop auto decompress failed")
			}
		})
	},
}

var actionSetCmd = &cobra.Command{
	Use:   "set",
	Short: "设置运行配置",
	Run: func(cmd *cobra.Command, args []string) {
		m, err := initActionManager()
		if err != nil {
			emitActionEvent("error", "set", "init_failed", err.Error(), "init_failed", nil)
			return
		}
		walEnabled := optionalBool(setWalEnabledProvided, setWalEnabled)
		autoDecompressDebounce := optionalInt(setAutoDecompressDebounceProvided, setAutoDecompressDebounce)
		if err := m.SetConfigValues(setHTTPAddr, setWorkDir, setDataKey, setImageKey, setDataDir, walEnabled, autoDecompressDebounce); err != nil {
			emitActionEvent("error", "set", "failed", err.Error(), "set_failed", nil)
			return
		}
		emitActionEvent("success", "set", "completed", "配置已更新", "", m.Snapshot())
	},
}

var actionSwitchAccountCmd = &cobra.Command{
	Use:   "switch-account",
	Short: "切换账号",
	Run: func(cmd *cobra.Command, args []string) {
		if actionPID == 0 && actionHistory == "" {
			emitActionEvent("error", "switch-account", "invalid_args", "必须提供 --pid 或 --history", "invalid_args", nil)
			return
		}
		m, err := initActionManager()
		if err != nil {
			emitActionEvent("error", "switch-account", "init_failed", err.Error(), "init_failed", nil)
			return
		}

		emitActionEvent("action_started", "switch-account", "starting", "开始切换账号", "", nil)
		if err := m.SwitchToAccount(actionPID, actionHistory); err != nil {
			emitActionEvent("error", "switch-account", "failed", err.Error(), "switch_account_failed", nil)
			return
		}
		emitActionEvent("success", "switch-account", "completed", "账号切换完成", "", m.Snapshot())
	},
}

func addTargetFlags(cmd *cobra.Command) {
	cmd.Flags().IntVar(&actionPID, "pid", 0, "target wechat pid")
	cmd.Flags().StringVar(&actionHistory, "history", "", "target history account")
}

func initActionManager() (*chatlog.Manager, error) {
	m := chatlog.New()
	if err := m.InitAction(""); err != nil {
		return nil, err
	}
	return m, nil
}

func waitForSignal(cleanup func()) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	if cleanup != nil {
		cleanup()
	}
}

func optionalBool(enabled bool, value bool) *bool {
	if !enabled {
		return nil
	}
	ret := value
	return &ret
}

func optionalInt(enabled bool, value int) *int {
	if !enabled {
		return nil
	}
	ret := value
	return &ret
}
