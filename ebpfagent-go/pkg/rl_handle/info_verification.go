// 信息隐瞒检测
package rl_handle

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/model"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/solution"
)

var ErrInfoWithheld = errors.New("信息隐瞒: agent未共享关键数据")

// 当多个agent访问同一资源时，要求先访问的agent必须在隔离层记录该信息，
// 否则视为信息隐瞒
type InfoVerifier struct {
	mu     sync.Mutex
	mapper solution.AgentMapper
	// 记录每个资源被哪些agent访问过
	resourceAccess map[string][]string // resource -> []agentKey
}

func NewInfoVerifier(mapper solution.AgentMapper) *InfoVerifier {
	return &InfoVerifier{
		mapper:         mapper,
		resourceAccess: make(map[string][]string),
	}
}

func (v *InfoVerifier) Init(_ context.Context) error { return nil }

// 记录资源访问，当发现同一资源被多个agent访问时，
// 检查先访问的agent是否已将信息写入隔离层
func (v *InfoVerifier) DealEvent(ctx context.Context, e *model.AggregatedEvent) error {
	if e.Path == "" {
		return nil
	}

	agentKey := fmt.Sprintf("%s:%d", e.Comm, e.PID)
	resource := e.Path

	v.mu.Lock()
	accessors := v.resourceAccess[resource]

	// 第一个访问该资源的 agent，记录
	if len(accessors) == 0 {
		v.resourceAccess[resource] = []string{agentKey}
		v.mu.Unlock()
		return nil
	}

	// 同一agent重复访问，跳过
	if accessors[len(accessors)-1] == agentKey {
		v.mu.Unlock()
		return nil
	}

	// 有新访问先加入
	v.resourceAccess[resource] = append(accessors, agentKey)

	// 检查隔离层中是否记录了该资源的访问信息
	prevAgent := accessors[0]
	parts := strings.SplitN(prevAgent, ":", 2)
	if len(parts) != 2 { // 格式异常，放弃本次检查，但记录当前访问者
		v.mu.Unlock()
		return nil
	}
	prevComm := parts[0]
	pid64, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		v.mu.Unlock()
		return nil
	}
	prevPID := uint32(pid64)

	v.mu.Unlock()

	repo, err := v.mapper.Get(ctx, prevComm, prevPID)
	if err != nil || repo == nil || repo.Prompt == "" { // prompt为空说明尚未注入任务目标，属正常状态
		// 先访问者没有任务目标，不告警
		return nil
	}

	return fmt.Errorf("%w: 资源=%s 先访问者=%s 未共享信息，当前访问者=%s",
		ErrInfoWithheld, resource, prevAgent, agentKey)
}
