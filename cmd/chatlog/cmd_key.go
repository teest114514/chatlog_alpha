package chatlog

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sjzar/chatlog/internal/wechat"
	keydarwin "github.com/sjzar/chatlog/internal/wechat/key/darwin"
	"github.com/spf13/cobra"
)

var (
	keyDataDir string
	keyTimeout int
	keyJSON    bool
)

func init() {
	rootCmd.AddCommand(keyCmd)
	keyCmd.Flags().StringVar(&keyDataDir, "data-dir", "", "微信账号数据目录（含 db_storage）；可省略，登录后自动探测")
	keyCmd.Flags().IntVar(&keyTimeout, "timeout", 180, "等待密钥超时秒数")
	keyCmd.Flags().BoolVar(&keyJSON, "json", false, "仅输出密钥十六进制（便于脚本）")
}

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "提取微信数据库密钥（macOS: Frida only）",
	Long: `提取微信 V4 数据库密钥。

macOS 仅支持 Frida Hook CCKeyDerivationPBKDF（已移除内存扫描）：
  1) pip3 install frida-tools
  2) chatlog key
  3) 在自动拉起的微信中登录；捕获后打印 data_key 并写入 all_keys.json
`,
	Run: runKey,
}

func runKey(cmd *cobra.Command, args []string) {
	_ = cmd
	_ = args

	status := func(msg string) {
		if keyJSON {
			return
		}
		fmt.Fprintln(os.Stderr, msg)
	}

	timeout := time.Duration(keyTimeout) * time.Second
	if timeout <= 0 {
		timeout = 180 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if runtime.GOOS != "darwin" {
		// Non-macOS: use process extractor (Windows path).
		if err := wechat.Load(); err != nil {
			log.Fatal().Err(err).Msg("加载微信进程失败")
		}
		accounts := wechat.GetAccounts()
		if len(accounts) == 0 {
			log.Fatal().Msg("未检测到微信进程")
		}
		acc := accounts[0]
		if keyDataDir != "" {
			acc.DataDir = keyDataDir
		}
		ctx = context.WithValue(ctx, "status_callback", status)
		ctx = context.WithValue(ctx, "force_key_refresh", true)
		ctx = context.WithValue(ctx, "force_rescan_memory", true)
		dataKey, imgKey, err := acc.GetKey(ctx)
		if err != nil {
			log.Fatal().Err(err).Msg("提取密钥失败")
		}
		if !keyJSON && imgKey != "" {
			fmt.Fprintf(os.Stderr, "img_key=%s\n", imgKey)
		}
		printKey(dataKey)
		return
	}

	if !keydarwin.FridaAvailable() {
		log.Fatal().Msg("Frida 不可用，请先执行: pip3 install frida-tools")
	}
	status("使用 Frida Hook CCKeyDerivationPBKDF 提取密钥...")
	key, candidates, err := keydarwin.ExtractKeysViaFrida(ctx, keyDataDir, status)
	if err != nil {
		log.Fatal().Err(err).Msg("Frida 提取密钥失败")
	}
	if keyDataDir != "" {
		if _, _, err := keydarwin.ApplyCapturedKeysToDataDir(keyDataDir, candidates, status); err != nil {
			status(fmt.Sprintf("警告: 写入 all_keys.json 失败: %v", err))
		}
	} else if acc := firstAccountWithDataDir(); acc != nil && acc.DataDir != "" {
		if _, _, err := keydarwin.ApplyCapturedKeysToDataDir(acc.DataDir, candidates, status); err != nil {
			status(fmt.Sprintf("警告: 写入 all_keys.json 失败: %v", err))
		} else {
			status("已写入: " + acc.DataDir + "/all_keys.json")
		}
	}
	printKey(key)
}

func printKey(key string) {
	key = strings.ToLower(strings.TrimSpace(key))
	if keyJSON {
		fmt.Println(key)
		return
	}
	fmt.Printf("data_key=%s\n", key)
}

func firstAccountWithDataDir() *wechat.Account {
	_ = wechat.Load()
	accounts := wechat.GetAccounts()
	for _, a := range accounts {
		if a != nil && a.DataDir != "" {
			return a
		}
	}
	if len(accounts) > 0 {
		return accounts[0]
	}
	return nil
}
