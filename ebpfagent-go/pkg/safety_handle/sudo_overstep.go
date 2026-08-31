// sudo规则越权
package safety_handle

import (
	"context"
	"strings"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/model"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/solution"
)

// 攻击者尝试修改sudo规则以获取持久化权限
type SudoOver struct {
	sudoFiles       []string
	sudoDirs        []string
	packageManagers []string
}

func NewSudoOver(allowlist []string) *SudoOver {
	// 内置安全默认值
	defaults := []string{
		"dpkg", "rpm", "apt", "apt-get", "pacman", "yum", "dnf",
		"ansible", "puppet", "chef", "salt", "cfagent",
	}
	// 用户配置追加到默认值之后
	return &SudoOver{
		sudoFiles:       []string{"/etc/sudoers", "/private/etc/sudoers"},
		sudoDirs:        []string{"/etc/sudoers.d/", "/private/etc/sudoers.d/"},
		packageManagers: append(defaults, allowlist...),
	}
}

func (s *SudoOver) Name() string { return "SudoOver" }

// 仅write/unlinkat触发Critical；读取sudoers是sudo/visudo等工具的常见行为
// 包管理器和配置管理工具读取sudoers属于正常运维操作，放行
func (s *SudoOver) Solve(_ context.Context, e *model.AggregatedEvent) (solution.Severity, string) {
	pathname := e.Path
	if pathname == "" {
		return solution.SevInfo, ""
	}

	hit := false
	for _, f := range s.sudoFiles {
		if pathname == f {
			hit = true
			break
		}
	}
	if !hit {
		for _, d := range s.sudoDirs {
			if strings.HasPrefix(pathname, d) {
				hit = true
				break
			}
		}
	}
	if !hit {
		return solution.SevInfo, ""
	}

	sys := e.SyscallName()

	// 包管理器和配置管理工具对sudoers的访问是正常的
	for _, pm := range s.packageManagers {
		if strings.Contains(e.Comm, pm) {
			if sys == "read" || sys == "openat" {
				return solution.SevInfo, ""
			}
		}
	}

	if sys == "write" || sys == "unlinkat" {
		return solution.SevCritical, "对sudo配置文件的写入/删除操作"
	}
	// 非包管理器的读取（sudo命令本身每次执行都会读取）
	if sys == "read" || sys == "openat" {
		return solution.SevLow, "对sudo配置文件的读取操作"
	}
	return solution.SevMedium, "对sudo配置文件的非预期访问"
}
