package chatlog

import (
	"io"
	"os"
	"path/filepath"
	"time"

	clog "github.com/sjzar/chatlog/pkg/log"
	"github.com/sjzar/chatlog/pkg/util"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var Debug bool

func initLog(cmd *cobra.Command, args []string) {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	if Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// 日志初始化早于用户配置加载,先用默认保留天数构造轮转器,
	// 待配置加载后由 ctx 通过 clog.SetRetention 回填实际天数。
	logWriter := clog.Init(logFilePath(), clog.DefaultRetentionDays)

	writers := []io.Writer{
		zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339},
		zerolog.ConsoleWriter{Out: logWriter, NoColor: true, TimeFormat: time.RFC3339},
	}

	log.Logger = log.Output(io.MultiWriter(writers...))
}

func initTuiLog(cmd *cobra.Command, args []string) {
	logWriter := clog.Init(logFilePath(), clog.DefaultRetentionDays)

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: logWriter, NoColor: true, TimeFormat: time.RFC3339})
	logrus.SetOutput(logWriter)
}

// logFilePath 返回日志文件路径 <工作目录>/log/chatlog.log,并确保目录存在。
func logFilePath() string {
	logDir := filepath.Join(util.DefaultWorkDir(""), "log")
	_ = util.PrepareDir(logDir)
	return filepath.Join(logDir, "chatlog.log")
}
