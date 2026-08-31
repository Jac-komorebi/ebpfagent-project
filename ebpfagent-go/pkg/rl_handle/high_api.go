// 高频api调用
package rl_handle

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/model"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/settings"
)

var ErrHighAPICalls = errors.New("高频API调用")

// 监测每个agent在滑动时间窗口内的系统调用频率，
// 超过阈值则判定为资源异常
type NetWorker struct {
	mu           sync.Mutex
	callCounts   map[string]int // Key：agentID  Value: 调用次数
	startTime    map[string]time.Time
	alreadyAlert map[string]bool
	maxCalls     int
	windowSize   time.Duration
}

func NewNetWorker(cfg *settings.DetectConfig) *NetWorker {
	dur, _ := time.ParseDuration(cfg.ResourceWindow)
	if dur == 0 {
		dur = 10 * time.Second
	}
	return &NetWorker{
		callCounts:   make(map[string]int),
		startTime:    make(map[string]time.Time),
		alreadyAlert: make(map[string]bool),
		maxCalls:     cfg.MaxAPICalls,
		windowSize:   dur,
	}
}

func (nw *NetWorker) Init(_ context.Context) error { return nil }

// 按事件发生次数累加计数，窗口内超阈值则返回错误
func (nw *NetWorker) DealEvent(_ context.Context, e *model.AggregatedEvent) error {
	nw.mu.Lock()
	defer nw.mu.Unlock()

	agentID := e.Comm

	// 窗口过期重置
	if start, ok := nw.startTime[agentID]; !ok || time.Since(start) > nw.windowSize {
		nw.callCounts[agentID] = int(e.Count)
		nw.alreadyAlert[agentID] = false
		nw.startTime[agentID] = time.Now()
		return nil
	}

	// 累加聚合事件中的count
	nw.callCounts[agentID] += int(e.Count)

	// 窗口一直没重置，且累加计数大于max了就是高频调用
	if nw.callCounts[agentID] > nw.maxCalls && !nw.alreadyAlert[agentID] {
		nw.alreadyAlert[agentID] = true
		return ErrHighAPICalls
	}
	return nil
}
