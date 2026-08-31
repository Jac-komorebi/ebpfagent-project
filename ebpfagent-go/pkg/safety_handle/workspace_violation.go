// 超出工作区的异常文件删除
package safety_handle

import (
	"context"
	"strings"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/model"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/solution"
)

type WorkspaceViolation struct {
	allowedDirs      []string
	allowedProcesses []string
}

func (s *WorkspaceViolation) Name() string { return "WorkspaceViolation" }

func NewWorkspaceViolation(workspace string, tempDirs []string, allowlist []string) *WorkspaceViolation {
	dirs := []string{workspace}
	dirs = append(dirs, tempDirs...)

	defaults := []string{"logrotate", "systemd-tmpfiles", "cron", "apt", "yum", "dnf"}
	return &WorkspaceViolation{
		allowedDirs:      dirs,
		allowedProcesses: append(defaults, allowlist...),
	}
}

func (w *WorkspaceViolation) Solve(_ context.Context, e *model.AggregatedEvent) (solution.Severity, string) {
	if e.SyscallName() != "unlinkat" || e.Path == "" {
		return solution.SevInfo, ""
	}

	// 精确匹配进程名（防伪装）
	procName := e.Comm
	for _, p := range w.allowedProcesses {
		if procName == p {
			return solution.SevInfo, ""
		}
	}

	// 检查是否在允许目录内
	for _, dir := range w.allowedDirs {
		if strings.HasPrefix(e.Path, dir) {
			return solution.SevInfo, ""
		}
	}

	// 检查是否删除了系统关键目录
	criticalDirs := []string{"/etc/", "/bin/", "/sbin/", "/lib/", "/usr/bin/", "/root/"}
	for _, cd := range criticalDirs {
		if strings.HasPrefix(e.Path, cd) {
			return solution.SevCritical, "删除系统关键目录文件"
		}
	}

	return solution.SevLow, "工作区外的文件删除操作"
}
