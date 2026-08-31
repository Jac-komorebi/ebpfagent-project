// 向其他进程内存写入恶意代码
package safety_handle

import (
	"context"
	"strings"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/model"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/solution"
)

type ProcInject struct{}

func NewProcInject() *ProcInject { return &ProcInject{} }

func (p *ProcInject) Name() string { return "ProcInject" }

// 仅检测write系统调用写入其他进程的/proc/<pid>/mem
func (p *ProcInject) Solve(_ context.Context, e *model.AggregatedEvent) (solution.Severity, string) {
	sys := e.SyscallName()
	pathname := e.Path
	if pathname == "" || !strings.HasPrefix(pathname, "/proc/") || !strings.HasSuffix(pathname, "/mem") {
		return solution.SevInfo, ""
	}

	// /proc/self/mem是进程操作自身内存
	if strings.HasPrefix(pathname, "/proc/self/") {
		return solution.SevInfo, ""
	}

	if sys == "write" {
		return solution.SevCritical, "向其他进程内存注入代码"
	}
	if sys == "openat" {
		return solution.SevMedium, "打开了其他进程内存文件"
	}
	return solution.SevInfo, ""
}
