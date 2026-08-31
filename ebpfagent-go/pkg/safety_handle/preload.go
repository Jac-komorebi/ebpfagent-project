// 劫持执行流
package safety_handle

import (
	"context"
	"strings"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/model"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/solution"
)

// 检测对ld.so.preload的写入操作，区分读写
type PreloadDetect struct {
	preloadPath string
}

func NewPreloadDetect() *PreloadDetect {
	return &PreloadDetect{preloadPath: "/etc/ld.so.preload"}
}

func (p *PreloadDetect) Name() string { return "PreloadDetect" }

// 仅对写入ld.so.preload的操作告警。
// openat/read是动态链接器的正常行为（每个进程启动时都访问），不产生告警。
func (p *PreloadDetect) Solve(_ context.Context, e *model.AggregatedEvent) (solution.Severity, string) {
	if !strings.HasSuffix(e.Path, p.preloadPath) && e.Path != p.preloadPath {
		return solution.SevInfo, ""
	}

	sys := e.SyscallName()
	if sys == "write" || sys == "unlinkat" {
		return solution.SevHigh, "对ld.so.preload的写入/删除操作"
	}
	// openat/read 属于正常动态链接器行为
	return solution.SevInfo, ""
}
