// 反恶意进程追踪
package safety_handle

import (
	"context"
	"strings"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/model"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/solution"
)

// 检测非调试器进程使用ptrace附加其他进程
type PtraceDetect struct {
	debuggers []string
}

func NewPtraceDetect(allowlist []string) *PtraceDetect {
	defaults := []string{"gdb", "strace", "ltrace", "gdbserver"}
	return &PtraceDetect{debuggers: append(defaults, allowlist...)}
}

func (p *PtraceDetect) Name() string { return "PtraceDetect" }

// 检测ptrace系统调用，排除已知调试器
func (p *PtraceDetect) Solve(_ context.Context, e *model.AggregatedEvent) (solution.Severity, string) {
	if e.SyscallName() != "ptrace" {
		return solution.SevInfo, ""
	}
	for _, dbg := range p.debuggers {
		if strings.Contains(e.Comm, dbg) {
			return solution.SevInfo, ""
		}
	}
	return solution.SevMedium, "非调试器进程使用ptrace"
}
