// 重复prompt(死循环/计算浪费)
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
	ErrSamePromptExceeded = errors.New("超出相同的prompt次数")
	ErrTotalLoopExceeded  = errors.New("总loop次数超限")
)

// 记录单个agent在时间窗口内的重复执行情况
type LoopWindow struct {
	StartTime              time.Time
	SamePromptCounts       int
	TotalLoop              int
	LastPromptHash         string
	AlreadySeriousAlerted  bool
	AlreadyRepeatedAlerted bool
}

// 检测同一agent的重复prompt
type Waste struct {
	mu                  sync.Mutex
	windows             map[string]*LoopWindow
	windowSize          time.Duration
	maxSamePromptCounts int
	maxTotalLoop        int
}

func NewWaste(cfg *settings.DetectConfig) *Waste {
	dur, _ := time.ParseDuration(cfg.LogicWindow)
	if dur == 0 {
		dur = 10 * time.Second
	}
	return &Waste{
		windows:             make(map[string]*LoopWindow),
		windowSize:          dur,
		maxSamePromptCounts: cfg.MaxSamePrompt,
		maxTotalLoop:        cfg.MaxTotalLoops,
	}
}

func (w *Waste) Init(_ context.Context) error { return nil }

func (w *Waste) DealEvent(_ context.Context, e *model.AggregatedEvent) error {
	// SSL 网络通信不适合用 syscall+path 范式检测重复, connect 网络连接同
	if e.EventType == 3 || e.EventType == 6 {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	agentID := e.Comm
	lw, exists := w.windows[agentID]
	now := time.Now()

	if !exists || now.Sub(lw.StartTime) > w.windowSize {
		lw = &LoopWindow{StartTime: now}
		w.windows[agentID] = lw
	}

	// 用 系统调用+路径 作为prompt的代理哈希
	currentHash := hashEvent(e)

	if lw.LastPromptHash != "" && currentHash == lw.LastPromptHash {
		lw.SamePromptCounts += int(e.Count)
	} else {
		lw.SamePromptCounts = 0
	}
	lw.LastPromptHash = currentHash
	lw.TotalLoop += int(e.Count)

	// 已告警标记，避免重复输出
	if lw.SamePromptCounts >= w.maxSamePromptCounts && !lw.AlreadySeriousAlerted {
		lw.AlreadySeriousAlerted = true
		return fmt.Errorf("%w (%d)", ErrSamePromptExceeded, lw.SamePromptCounts)
	}

	if lw.TotalLoop >= w.maxTotalLoop && !lw.AlreadyRepeatedAlerted {
		lw.AlreadyRepeatedAlerted = true
		return fmt.Errorf("%w (%d)", ErrTotalLoopExceeded, lw.TotalLoop)
	}

	return nil
}

func hashEvent(e *model.AggregatedEvent) string {
	return e.SyscallName() + "|" + e.Path
}
