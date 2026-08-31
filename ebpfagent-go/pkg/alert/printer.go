package alert

import (
	"context"
	"fmt"
	"log"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/model"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/solution"
)

// 输出结构化日志（供机器消费）和可读的文本块（供运维查看）
type ConsolePrinter struct{}

func NewConsolePrinter() *ConsolePrinter {
	return &ConsolePrinter{}
}

func (p *ConsolePrinter) Print(_ context.Context, e *model.AggregatedEvent, reason string, sev solution.Severity, alertType solution.AlertType) {
	// 结构化日志
	log.Printf("[ALERT][%s][%s] first_time_ns=%d agent=%s pid=%d syscall=%s path=%s reason=%s",
		alertType,
		sev,
		e.FirstTimeNs,
		e.Comm,
		e.PID,
		e.SyscallName(),
		e.Path,
		reason,
	)

	// 可读告警块
	fmt.Println("------------------------------------------------")
	fmt.Printf("告警类型: %s\n", alertType)
	fmt.Printf("严重程度: %s\n", sev)
	fmt.Printf("首次时间: %d ns\n", e.FirstTimeNs)
	fmt.Printf("Agent进程: %s (PID: %d)\n", e.Comm, e.PID)
	fmt.Printf("系统调用: %s\n", e.SyscallName())
	fmt.Printf("累计次数: %d\n", e.Count)
	if e.Path != "" {
		fmt.Printf("操作路径: %s\n", e.Path)
	}
	if e.DstIP != "" {
		fmt.Printf("远端地址: %s:%d\n", e.DstIP, e.DstPort)
	}
	fmt.Printf("异常描述: %s\n", reason)
}
