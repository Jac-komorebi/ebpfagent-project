// 非预期的Shell
package safety_handle

import (
	"context"
	"strings"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/model"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/solution"
)

// 检测非预期shell进程的启动
type DealShell struct {
	shellNames        []string
	agentProcessNames []string
	enabled           bool
}

// 创建实例，预置已知shell名称和合法agent进程名
func NewDealShell(allowlist []string) *DealShell {
	shells := []string{"ash", "bash", "csh", "ksh", "sh", "tcsh", "zsh", "dash"}
	defaults := []string{"nginx", "httpd", "httpd-foregroun", "http-nio", "lighttpd", "apache", "apache2"}
	return &DealShell{
		shellNames:        shells,
		agentProcessNames: append(defaults, allowlist...),
		enabled:           true,
	}
}

// 设置是否启用（可关闭以减少噪音）
func (s *DealShell) SetEnabled(enabled bool) { s.enabled = enabled }

func (s *DealShell) Name() string { return "DealShell" }

// 检测execve是否启动了已知shell
func (s *DealShell) Solve(_ context.Context, e *model.AggregatedEvent) (solution.Severity, string) {
	if !s.enabled || e.SyscallName() != "execve" {
		return solution.SevInfo, ""
	}

	path := e.Path
	isShell := false
	for _, name := range s.shellNames {
		if path == name || path == "/bin/"+name || path == "/usr/bin/"+name || strings.HasSuffix(path, "/"+name) {
			isShell = true
			break
		}
	}
	if !isShell {
		return solution.SevInfo, ""
	}

	for _, ag := range s.agentProcessNames {
		if strings.Contains(e.Comm, ag) {
			return solution.SevInfo, ""
		}
	}

	// shell execve本身是弱信号
	return solution.SevLow, "非预期shell进程启动"
}
