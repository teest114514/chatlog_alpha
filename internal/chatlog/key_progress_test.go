package chatlog

import (
	"errors"
	"strings"
	"testing"
)

func TestKeyExtractionProgressShowsNumberedStages(t *testing.T) {
	progress := newKeyExtractionProgress()

	text := progress.Update("[3/6] 正在挂载微信进程")
	for _, want := range []string{
		"✓ 1/6 检查 Frida 环境",
		"✓ 2/6 重启并启动微信",
		"→ 3/6 挂载进程并安装 Hook",
		"当前状态：正在挂载微信进程",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("progress output missing %q:\n%s", want, text)
		}
	}

	// A delayed message from an earlier stage must not move progress backwards.
	text = progress.Update("[2/6] 延迟到达的启动状态")
	if !strings.Contains(text, "→ 3/6 挂载进程并安装 Hook") {
		t.Fatalf("progress moved backwards:\n%s", text)
	}
}

func TestKeyExtractionProgressFinish(t *testing.T) {
	progress := newKeyExtractionProgress()
	progress.Update("[5/6] 正在卸载 Hook")

	success := progress.Finish(nil)
	if strings.Count(success, "✓") != keyExtractionStepTotal {
		t.Fatalf("expected every step to be complete:\n%s", success)
	}
	if !strings.Contains(success, "数据库密钥已逐库验证并更新，Frida Hook 已释放") {
		t.Fatalf("missing release confirmation:\n%s", success)
	}
	lateUpdate := progress.Update("迟到的底层状态")
	if lateUpdate != success {
		t.Fatalf("late status replaced the completed view:\n%s", lateUpdate)
	}

	failedProgress := newKeyExtractionProgress()
	failedProgress.Update("[4/6] 等待密钥")
	failed := failedProgress.Finish(errors.New("mock failure"))
	if !strings.Contains(failed, "✗ 4/6") || !strings.Contains(failed, "操作失败：mock failure") {
		t.Fatalf("failure output does not preserve the failed stage:\n%s", failed)
	}
}
