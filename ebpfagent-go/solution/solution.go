package solution

import (
	"context"
	"time"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/model"
)

// 存储每个agentID, PID组合的状态信息
type AgentRepository struct {
	Prompt         string    `json:"prompt"`
	State          int       `json:"state"`
	LastActiveTime time.Time `json:"last_active_time"`
}

// 隔离业务接口，抽象存储后端
type AgentMapper interface {
	Isolation(ctx context.Context, agentID string, pid uint32, prompt string, state int) error
	Get(ctx context.Context, agentID string, pid uint32) (*AgentRepository, error)
	Delete(ctx context.Context, agentID string, pid uint32) error
	// 关闭，等待后台任务退出
	Shutdown(ctx context.Context) error
}

// 告警严重度
type Severity int

const (
	SevInfo     Severity = iota // 仅记录
	SevLow                      // 低风险
	SevMedium                   // 中风险
	SevHigh                     // 高风险
	SevCritical                 // 严重
)

func (s Severity) String() string {
	switch s {
	case SevInfo:
		return "info"
	case SevLow:
		return "low"
	case SevMedium:
		return "medium"
	case SevHigh:
		return "high"
	case SevCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// 单事件安全异常检测
type Solver interface {
	Name() string
	Solve(ctx context.Context, e *model.AggregatedEvent) (Severity, string)
}

// 多事件资源（逻辑异常检测接口）
type Dealwith interface {
	Init(ctx context.Context) error
	DealEvent(ctx context.Context, e *model.AggregatedEvent) error
}

// 告警类型分类
type AlertType int

const (
	AlertSecurity AlertType = iota // 安全类异常（来自 Solver）
	AlertResource                  // 资源类异常（来自 Dealwith）
	AlertLogic                     // 逻辑类异常（来自 Dealwith）
)

func (a AlertType) String() string {
	switch a {
	case AlertSecurity:
		return "security"
	case AlertResource:
		return "resource"
	case AlertLogic:
		return "logic"
	default:
		return "unknown"
	}
}

// 告警输出与归因定位接口
type Printer interface {
	Print(ctx context.Context, e *model.AggregatedEvent, reason string, sev Severity, alertType AlertType)
}
