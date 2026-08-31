// 事件处理
package pipeline

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/model"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/solution"
)

const (
	coordTimeout = 5 * time.Second
)

type pipelineResult struct {
	alertType solution.AlertType
	severity  solution.Severity
	reason    string
}

type Pipeline struct {
	mapper        solution.AgentMapper
	solvers       []solution.Solver
	dealers       []solution.Dealwith
	printer       solution.Printer
	minAlertLevel solution.Severity
}

// 隔离存储
func New(mapper solution.AgentMapper, printer solution.Printer,
	solvers []solution.Solver, dealers []solution.Dealwith, minSev solution.Severity) *Pipeline {
	return &Pipeline{
		mapper:        mapper,
		solvers:       solvers,
		dealers:       dealers,
		printer:       printer,
		minAlertLevel: minSev,
	}
}

// 处理聚合事件
func (p *Pipeline) ProcessEvent(ctx context.Context, evt *model.AggregatedEvent) {
	procCtx, cancel := context.WithTimeout(ctx, coordTimeout)
	defer cancel()

	p.processOnce(procCtx, evt)
}

// 单次处理
func (p *Pipeline) processOnce(ctx context.Context, evt *model.AggregatedEvent) {
	// 从 SSL 事件中提取 Prompt 数据注入隔离层
	// SSL_write (direction=0) → Agent 发给大模型的 Prompt
	// SSL_read  (direction=1) → 大模型返回的 Response
	prompt := ""
	if evt.EventType == 6 && evt.SSLDirection == model.SSLDirPrompt {
		prompt = evt.SSLData
	}

	// 隔离存储
	if err := p.mapper.Isolation(ctx, evt.Comm, evt.PID, prompt, 0); err != nil {
		log.Printf("isolation error: %v", err)
	}

	// 目标锚定注入：从隔离层获取agent的原始目标
	repo, _ := p.mapper.Get(ctx, evt.Comm, evt.PID)
	if repo != nil && repo.Prompt != "" {
		log.Printf("目标锚定: agent=%s goal=%s", evt.Comm, truncatePrompt(repo.Prompt, 80))
	}

	// 并行异常检测
	var wg sync.WaitGroup
	errCh := make(chan pipelineResult, len(p.solvers)+len(p.dealers))

	for _, solver := range p.solvers {
		wg.Add(1)
		go func(s solution.Solver) {
			defer wg.Done()
			sev, reason := s.Solve(ctx, evt)
			if reason != "" && sev >= p.minAlertLevel {
				select {
				case errCh <- pipelineResult{alertType: solution.AlertSecurity, severity: sev, reason: reason}:
				case <-ctx.Done():
				}
			}
		}(solver)
	}

	for _, dealer := range p.dealers {
		wg.Add(1)
		go func(d solution.Dealwith) {
			defer wg.Done()
			if err := d.DealEvent(ctx, evt); err != nil {
				select {
				case errCh <- pipelineResult{
					alertType: classifyDealwithError(err),
					severity:  solution.SevMedium,
					reason:    err.Error(),
				}:
				case <-ctx.Done():
				}
			}
		}(dealer)
	}

	wg.Wait()
	close(errCh)

	// 告警输出
	for result := range errCh {
		p.printer.Print(ctx, evt, result.reason, result.severity, result.alertType)
	}
}

func classifyDealwithError(err error) solution.AlertType {
	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "API"), strings.Contains(errStr, "IO"),
		strings.Contains(errStr, "frequency"), strings.Contains(errStr, "资源"):
		return solution.AlertResource
	case strings.Contains(errStr, "prompt"), strings.Contains(errStr, "loop"),
		strings.Contains(errStr, "偏离"), strings.Contains(errStr, "隐瞒"),
		strings.Contains(errStr, "终止"), strings.Contains(errStr, "规范"):
		return solution.AlertLogic
	default:
		return solution.AlertLogic
	}
}

func truncatePrompt(prompt string, maxLen int) string {
	if len(prompt) <= maxLen {
		return prompt
	}
	return prompt[:maxLen] + "..."
}
