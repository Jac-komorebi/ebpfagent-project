// 系统敏感文件越权访问
package safety_handle

import (
	"context"
	"strings"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/model"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/solution"
)

// 检测对系统敏感文件的访问，区分读写和文件类型
type SensitiveFile struct {
	criticalWorks []string
	infoPaths     []string
}

func NewSensitiveFile() *SensitiveFile {
	return &SensitiveFile{
		criticalWorks: []string{"/etc/shadow", "/etc/gshadow", "/root/.ssh/authorized_keys"},
		infoPaths:     []string{"/etc/passwd", "/etc/ssh/sshd_config"},
	}
}

func (s *SensitiveFile) Name() string { return "SensitiveFile" }

// 区分写入（Critical）和读取（High/Info）。
func (s *SensitiveFile) Solve(_ context.Context, e *model.AggregatedEvent) (solution.Severity, string) {
	// 操作检查
	path := e.Path
	if path == "" {
		return solution.SevInfo, ""
	}
	sys := e.SyscallName()
	isWrite := sys == "write" || sys == "unlinkat"

	for _, cw := range s.criticalWorks {
		if path == cw || strings.HasSuffix(path, cw) {
			if isWrite {
				return solution.SevCritical, "修改高敏感系统文件: " + cw
			}
			return solution.SevHigh, "读取高敏感系统文件: " + cw
		}
	}

	// 信息级别路径
	for _, ip := range s.infoPaths {
		if path == ip || strings.HasSuffix(path, ip) {
			if isWrite {
				return solution.SevCritical, "修改敏感系统文件: " + ip
			}
			if sys == "read" || sys == "openat" {
				return solution.SevInfo, ""
			}
			return solution.SevMedium, "非预期方式访问: " + ip
		}
	}

	return solution.SevInfo, ""
}
