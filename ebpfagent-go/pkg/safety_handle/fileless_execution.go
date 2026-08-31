// 无文件恶意行为
package safety_handle

import (
	"context"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/model"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/solution"
)

// 检测execve执行时路径为空的"无文件执行"模式(内存驻留型恶意软件)
type FileExecution struct {
	enabled bool
}

func NewFileExecution() *FileExecution { return &FileExecution{enabled: true} }

// 开关：fexecve/memfd_create在许多现代应用中属合法行为
func (f *FileExecution) SetEnabled(enabled bool) { f.enabled = enabled }

func (f *FileExecution) Name() string { return "FileExecution" }

// 检测execve事件路径为空的无文件执行行为
// 当前聚合事件模型不区分execve/fexecve，按需开启
func (f *FileExecution) Solve(_ context.Context, e *model.AggregatedEvent) (solution.Severity, string) {
	if !f.enabled || e.SyscallName() != "execve" {
		return solution.SevInfo, ""
	}
	if e.Path == "" {
		return solution.SevHigh, "无文件执行：进程执行但未记录文件路径"
	}
	return solution.SevInfo, ""
}
