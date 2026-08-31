// 提前终止检测
package rl_handle

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/model"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/solution"
)

var ErrPrematureTerm = errors.New("提前终止: agent 异常静默")

// 跟踪每个agent的最后活跃时间，若超过静默阈值仍未产生新事件则告警
type PrematureTermDetector struct {
	mu            sync.Mutex
	mapper        solution.AgentMapper
	lastSeen      map[string]time.Time // agentKey -> last event time
	silenceThresh time.Duration
	checkInterval time.Duration
	stopCh        chan struct{}
}

func NewPrematureTermDetector(mapper solution.AgentMapper, silenceSec int) *PrematureTermDetector {
	thresh := 30 * time.Second
	if silenceSec > 0 {
		thresh = time.Duration(silenceSec) * time.Second
	}
	return &PrematureTermDetector{
		mapper:        mapper,
		lastSeen:      make(map[string]time.Time),
		silenceThresh: thresh,
		checkInterval: 10 * time.Second,
		stopCh:        make(chan struct{}),
	}
}

func (p *PrematureTermDetector) Init(_ context.Context) error {
	go p.backgroundCheck()
	return nil
}

func (p *PrematureTermDetector) DealEvent(_ context.Context, e *model.AggregatedEvent) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	agentKey := fmt.Sprintf("%s:%d", e.Comm, e.PID)
	p.lastSeen[agentKey] = time.Now()
	return nil
}

// 定期检查是否有agent异常静默，通过日志输出告警
func (p *PrematureTermDetector) backgroundCheck() {
	ticker := time.NewTicker(p.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.mu.Lock()
			now := time.Now()
			var silenced []string
			for agentKey, last := range p.lastSeen {
				if now.Sub(last) > p.silenceThresh {
					silenced = append(silenced, agentKey)
				}
			}
			for _, key := range silenced {
				delete(p.lastSeen, key)
				err := fmt.Errorf("%w: agent=%s 异常静默超过%v, 疑似提前终止", ErrPrematureTerm, key, p.silenceThresh)
				log.Printf("%v", err)
			}
			p.mu.Unlock()
		case <-p.stopCh:
			return
		}
	}
}
