// 目标锚定注入 + 终局断言
package rl_handle

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/model"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/solution"
)

var (
	ErrGoalDeviation = errors.New("行为偏离预期目标")
	ErrTaskViolation = errors.New("输出违反任务规范")
)

// 从隔离层读取agent的预期行为模式，比对实际事件是否偏离
type GoalAnchor struct {
	mu     sync.Mutex
	mapper solution.AgentMapper
	// 存储每个agent的预期行为关键词
	expectedPatterns map[string][]string
	deviationCount   map[string]int
	maxDeviations    int
}

func NewGoalAnchor(mapper solution.AgentMapper, maxDev int) *GoalAnchor {
	if maxDev <= 0 {
		maxDev = 3
	}
	return &GoalAnchor{
		mapper:           mapper,
		expectedPatterns: make(map[string][]string),
		deviationCount:   make(map[string]int),
		maxDeviations:    maxDev,
	}
}

func (g *GoalAnchor) Init(_ context.Context) error { return nil }

// 注入目标锚定（event.Comm即agent 标识），
// 比对事件行为是否偏离隔离层中记录的预期prompt
func (g *GoalAnchor) DealEvent(ctx context.Context, e *model.AggregatedEvent) error {
	repo, err := g.mapper.Get(ctx, e.Comm, e.PID)
	if err != nil || repo == nil {
		return nil // 首次出现，尚无目标可锚定
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	agentKey := fmt.Sprintf("%s:%d", e.Comm, e.PID)

	// 如果这个agent还没有预期模式，用当前行为的指纹作为它的初始基准
	if _, exists := g.expectedPatterns[agentKey]; !exists {
		currentBehavior := extractBehaviorKeywords(e)
		g.expectedPatterns[agentKey] = []string{currentBehavior}
		// 第一次放行
		return nil
	}

	if repo.Prompt != "" && e.EventType == 6 && e.SSLDirection == model.SSLDirResponse {
		// 剔除空白字符后检查响应内容
		if len(strings.TrimSpace(e.SSLData)) == 0 {
			return fmt.Errorf("%w: agent=%s 输出为空，任务执行失败", ErrTaskViolation, e.Comm)
		}
	}

	// 如果agent有已记录的预期模式，比对当前行为
	if patterns, exists := g.expectedPatterns[agentKey]; exists {
		// 提取当前事件的行为特征作为关键词
		currentBehavior := extractBehaviorKeywords(e)
		if !matchesAnyPattern(currentBehavior, patterns) {
			g.deviationCount[agentKey]++
			if g.deviationCount[agentKey] >= g.maxDeviations {
				return fmt.Errorf("%w: agent=%s 当前行为=%s 不在预期模式中",
					ErrGoalDeviation, e.Comm, currentBehavior)
			}
		}
	}
	return nil
}

// 注册agent的预期行为模式
func (g *GoalAnchor) RegisterExpected(agentKey string, patterns []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.expectedPatterns[agentKey] = patterns
}

// 微观操作指纹（prompt）
func extractBehaviorKeywords(e *model.AggregatedEvent) string {
	parts := []string{e.SyscallName()}
	if e.Path != "" {
		parts = append(parts, e.Path)
	}
	if e.DstIP != "" {
		parts = append(parts, e.DstIP)
	}
	return strings.Join(parts, "|")
}

func matchesAnyPattern(behavior string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(behavior, p) {
			return true
		}
	}
	return false
}
