package chatlog

import (
	"fmt"
	"strings"
	"sync"
)

const keyExtractionStepTotal = 6

var keyExtractionStepTitles = [...]string{
	"检查 Frida 环境",
	"重启并启动微信",
	"挂载进程并安装 Hook",
	"短时收集各数据库候选密钥",
	"卸载 Hook 并断开会话",
	"逐库验证密钥并保存映射",
}

type keyExtractionProgress struct {
	mu        sync.Mutex
	current   int
	detail    string
	finished  bool
	finishErr error
}

func newKeyExtractionProgress() *keyExtractionProgress {
	return &keyExtractionProgress{
		current: 1,
		detail:  keyExtractionStepTitles[0],
	}
}

func (p *keyExtractionProgress) Update(message string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		return p.render(p.finishErr == nil, p.finishErr)
	}

	message = strings.TrimSpace(message)
	if step, detail, ok := parseKeyExtractionStep(message); ok {
		// Status callbacks may arrive from different pipe readers. Never let a
		// late message make the visible progress move backwards.
		if step >= p.current {
			p.current = step
			if detail != "" {
				p.detail = detail
			}
		}
	} else if message != "" {
		p.detail = normalizeKeyProgressDetail(message)
	}

	return p.render(false, nil)
}

func (p *keyExtractionProgress) Finish(err error) string {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.finished = true
	p.finishErr = err
	if err == nil {
		p.current = keyExtractionStepTotal
	}
	return p.render(err == nil, err)
}

func (p *keyExtractionProgress) render(done bool, runErr error) string {
	var b strings.Builder
	b.WriteString("重启并获取数据库密钥\n\n")
	for i, title := range keyExtractionStepTitles {
		step := i + 1
		marker := "·"
		switch {
		case done || step < p.current:
			marker = "✓"
		case step == p.current && runErr != nil:
			marker = "✗"
		case step == p.current:
			marker = "→"
		}
		fmt.Fprintf(&b, "%s %d/%d %s\n", marker, step, keyExtractionStepTotal, title)
	}

	switch {
	case runErr != nil:
		fmt.Fprintf(&b, "\n操作失败：%s", normalizeKeyProgressDetail(runErr.Error()))
	case done:
		b.WriteString("\n操作成功：数据库密钥已逐库验证并更新，Frida Hook 已释放。")
	case p.detail != "":
		fmt.Fprintf(&b, "\n当前状态：%s", normalizeKeyProgressDetail(p.detail))
	}
	return strings.TrimSpace(b.String())
}

func parseKeyExtractionStep(message string) (int, string, bool) {
	closing := strings.IndexByte(message, ']')
	if closing <= 0 {
		return 0, "", false
	}

	var step, total int
	if _, err := fmt.Sscanf(message[:closing+1], "[%d/%d]", &step, &total); err != nil {
		return 0, "", false
	}
	if total != keyExtractionStepTotal || step < 1 || step > total {
		return 0, "", false
	}
	return step, normalizeKeyProgressDetail(message[closing+1:]), true
}

func normalizeKeyProgressDetail(message string) string {
	message = strings.Join(strings.Fields(message), " ")
	message = strings.NewReplacer("[", "(", "]", ")").Replace(message)
	runes := []rune(message)
	if len(runes) > 180 {
		message = string(runes[:177]) + "..."
	}
	return message
}
