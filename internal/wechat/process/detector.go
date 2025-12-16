package process

import (
	"github.com/sjzar/chatlog/internal/wechat/model"
	"github.com/sjzar/chatlog/internal/wechat/process/windows"
)

type Detector interface {
	FindProcesses() ([]*model.Process, error)
}

// NewDetector 创建适合当前平台的检测器
func NewDetector(platform string) Detector {
	// 根据平台返回对应的实现
	switch platform {
	case "windows":
		return windows.NewDetector()
	default:
		// 默认返回一个空实现
		return &nullDetector{}
	}
}

// nullDetector 空实现
type nullDetector struct{}

func (d *nullDetector) FindProcesses() ([]*model.Process, error) {
	return nil, nil
}

func (d *nullDetector) GetProcessInfo(pid uint32) (*model.Process, error) {
	return nil, nil
}
