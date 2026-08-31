// 无意义底层文件读写
package rl_handle

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/model"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/settings"
)

var (
	ErrIOCountExceeded = errors.New("窗口内IO次数超过限制")
	ErrTotalIOExceeded = errors.New("总IO次数超过限制")
)

// 记录单个agent在时间窗口内的I/O操作次数
type IOWindow struct {
	StartTime              time.Time
	IOCounts               int
	TotalIO                int
	AlreadySeriousAlerted  bool
	AlreadyRepeatedAlerted bool
}

// 检测无意义重复文件读写造成的资源浪费
type IOWaste struct {
	mu          sync.Mutex
	windows     map[string]*IOWindow
	windowSize  time.Duration
	maxIOCounts int
	maxTotalIO  int
}

func NewIOWaste(cfg *settings.DetectConfig) *IOWaste {
	dur, _ := time.ParseDuration(cfg.ResourceWindow)
	if dur == 0 {
		dur = 10 * time.Second
	}
	return &IOWaste{
		windows:     make(map[string]*IOWindow),
		windowSize:  dur,
		maxIOCounts: cfg.MaxIOCounts,
		maxTotalIO:  cfg.MaxTotalIO,
	}
}

func (l *IOWaste) Init(_ context.Context) error { return nil }

// 统计read/write且有文件路径的事件，按Count累加
func (l *IOWaste) DealEvent(_ context.Context, e *model.AggregatedEvent) error {
	if e.SyscallName() != "read" && e.SyscallName() != "write" {
		return nil
	}
	if e.Path == "" {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	agentID := e.Comm
	iw, exists := l.windows[agentID]
	now := time.Now()

	if !exists || now.Sub(iw.StartTime) > l.windowSize {
		iw = &IOWindow{StartTime: now}
		l.windows[agentID] = iw
	}

	// 按聚合事件中的次数累加
	iw.IOCounts += int(e.Count)
	iw.TotalIO += int(e.Count)

	// 告警标记，每个条件只告警一次
	if iw.IOCounts >= l.maxIOCounts && !iw.AlreadySeriousAlerted {
		iw.AlreadySeriousAlerted = true
		return fmt.Errorf("%w (%d)", ErrIOCountExceeded, iw.IOCounts)
	}

	if iw.TotalIO >= l.maxTotalIO && !iw.AlreadyRepeatedAlerted {
		iw.AlreadyRepeatedAlerted = true
		return fmt.Errorf("%w (%d)", ErrTotalIOExceeded, iw.TotalIO)
	}

	return nil
}
