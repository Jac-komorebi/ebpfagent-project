// 逻辑异常：read/write 操作文件名为空
package safety_handle

import (
	"context"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/model"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/solution"
)

// 检测read/write系统调用时文件名为空的逻辑异常
type EmptyFileIO struct{}

func NewEmptyFileIO() *EmptyFileIO { return &EmptyFileIO{} }

func (e *EmptyFileIO) Name() string { return "EmptyFileIO" }

// 排除pipe/socket/stdio等无路径的正常I/O，仅当connect事件且无IP时报低风险
func (e *EmptyFileIO) Solve(_ context.Context, evt *model.AggregatedEvent) (solution.Severity, string) {
	sys := evt.SyscallName()
	if sys == "read" || sys == "write" {
		if evt.Path == "" && evt.DstIP == "" {
			// 无路径无IP的I/O可能是pipe/socket/stdio，属正常
			return solution.SevInfo, ""
		}
	}
	if sys == "openat" && evt.Path == "" {
		return solution.SevLow, "无文件名的openat操作"
	}
	return solution.SevInfo, ""
}
