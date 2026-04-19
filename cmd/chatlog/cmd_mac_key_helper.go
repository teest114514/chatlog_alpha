package chatlog

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/sjzar/chatlog/internal/wechat/key/darwin"
	"github.com/spf13/cobra"
)

var (
	macKeyHelperPID     uint32
	macKeyHelperDataDir string
)

func init() {
	rootCmd.AddCommand(macKeyHelperCmd)
	macKeyHelperCmd.Flags().Uint32Var(&macKeyHelperPID, "pid", 0, "wechat pid")
	macKeyHelperCmd.Flags().StringVar(&macKeyHelperDataDir, "data-dir", "", "wechat data dir")
}

var macKeyHelperCmd = &cobra.Command{
	Use:    "mac-key-helper",
	Short:  "mac key helper",
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		if macKeyHelperPID == 0 || macKeyHelperDataDir == "" {
			log.Error().Msg("pid and data-dir are required")
			os.Exit(1)
		}

		dataKey, _, err := darwin.InitAllKeysByPID(macKeyHelperPID, macKeyHelperDataDir, nil)
		if err != nil {
			log.Error().Err(err).Msg("extract key failed")
			os.Exit(1)
		}
		fmt.Println(dataKey)
	},
}
