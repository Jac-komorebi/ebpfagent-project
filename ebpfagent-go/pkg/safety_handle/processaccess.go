// 直接读取其他进程内存
package safety_handle

import (
	"context"
	"strings"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/model"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/solution"
)

type ProcAccess struct{}

func NewProcAccess() *ProcAccess { return &ProcAccess{} }

func (p *ProcAccess) Name() string { return "ProcAccess" }

// 仅检测read系统调用读取其他进程的/proc/<pid>/mem
func (p *ProcAccess) Solve(_ context.Context, e *model.AggregatedEvent) (solution.Severity, string) {
	sys := e.SyscallName()
	pathname := e.Path
	if pathname == "" || !strings.HasPrefix(pathname, "/proc/") || !strings.HasSuffix(pathname, "/mem") {
		return solution.SevInfo, ""
	}

	// /proc/self/mem是进程访问自身内存，属于正常行为
	if strings.HasPrefix(pathname, "/proc/self/") {
		return solution.SevInfo, ""
	}

	if sys == "read" {
		return solution.SevHigh, "读取其他进程内存空间"
	}
	// openat可能只是获取fd未实际读取，降低风险
	if sys == "openat" {
		return solution.SevLow, "打开了其他进程内存文件"
	}
	return solution.SevInfo, ""
}
