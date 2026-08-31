// 特权提升
package safety_handle

import (
	"context"
	"strings"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/model"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/solution"
)

// 此类操作可被利用进行容器逃逸或本地提权
type PrivilegeEsc struct {
	targets []string
}

func NewPrivilegeEsc() *PrivilegeEsc {
	return &PrivilegeEsc{
		targets: []string{
			"/proc/sys/kernel/core_pattern",
			"/proc/sys/kernel/modprobe",
		},
	}
}

func (p *PrivilegeEsc) Name() string { return "PrivilegeEsc" }

// 仅对write/unlinkat触发告警
func (p *PrivilegeEsc) Solve(_ context.Context, e *model.AggregatedEvent) (solution.Severity, string) {
	pathname := e.Path
	if pathname == "" {
		return solution.SevInfo, ""
	}

	hit := false
	for _, t := range p.targets {
		if strings.HasSuffix(pathname, t) || pathname == t {
			hit = true
			break
		}
	}
	if !hit {
		return solution.SevInfo, ""
	}

	sys := e.SyscallName()
	if sys == "write" || sys == "unlinkat" {
		return solution.SevCritical, "对提权敏感路径的写入操作"
	}
	// read/openat 属于正常的参数读取
	return solution.SevInfo, ""
}
