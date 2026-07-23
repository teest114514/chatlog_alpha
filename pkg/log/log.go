// Package log 提供带轮转与按天数保留能力的日志文件写入器。
//
// 设计要点:
//   - chatlog 的日志初始化(cmd/chatlog 的 initLog)发生在用户配置加载之前,
//     此时读不到用户配置的保留天数,因此这里先用默认天数构造轮转器,待配置
//     加载完成后再通过 SetRetention 回填天数(lumberjack 的 MaxAge 支持运行期修改)。
//   - 轮转器抽离到底层包,使 cmd/chatlog 与 internal/chatlog/ctx 都能依赖它,
//     避免 ctx -> cmd/chatlog 的循环 import。
package log

import (
	"io"
	"sync"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

// DefaultRetentionDays 是日志文件的默认保留天数。
const DefaultRetentionDays = 7

const (
	// maxSizeMB 单个日志文件大小上限(MB),超过后立即轮转。常规轮转由每日 0 点的
	// Rotate 负责,此值仅作为「单日日志量异常暴涨」时的兜底,防止单文件失控;取较大
	// 值以避免异常场景下文件过度碎片化(正常日志量通常远达不到该上限)。
	maxSizeMB = 500
	// minRetentionDays / maxRetentionDays 为保留天数的合法区间。
	minRetentionDays = 1
	maxRetentionDays = 365
)

var (
	mu      sync.Mutex
	rotator *lumberjack.Logger
	once    sync.Once
)

// Init 初始化并返回日志轮转写入器,可安全重复调用(仅首次生效)。
// retentionDays <= 0 时使用 DefaultRetentionDays。
func Init(filename string, retentionDays int) io.Writer {
	once.Do(func() {
		rotator = &lumberjack.Logger{
			Filename:   filename,
			MaxSize:    maxSizeMB,
			MaxAge:     normalizeRetention(retentionDays),
			MaxBackups: 0, // 不按个数限制,仅按 MaxAge(天)清理
			LocalTime:  true,
			Compress:   true,
		}
		startDailyRotate()
	})
	return rotator
}

// SetRetention 在运行期更新日志保留天数(通常在用户配置加载后调用)。
// 传入非法值(<1)将被忽略,超过上限按上限处理。
func SetRetention(days int) {
	if days < minRetentionDays {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if rotator != nil {
		rotator.MaxAge = normalizeRetention(days)
	}
}

// normalizeRetention 将保留天数归一化到 [minRetentionDays, maxRetentionDays]。
func normalizeRetention(days int) int {
	if days < minRetentionDays {
		return DefaultRetentionDays
	}
	if days > maxRetentionDays {
		return maxRetentionDays
	}
	return days
}

// startDailyRotate 每天 0 点强制轮转一次,配合 MaxAge 实现「每天一个文件、保留 N 天」。
func startDailyRotate() {
	go func() {
		for {
			now := time.Now()
			next := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Add(24 * time.Hour)
			<-time.After(time.Until(next))

			mu.Lock()
			r := rotator
			mu.Unlock()
			if r != nil {
				_ = r.Rotate()
			}
		}
	}()
}
