package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/model"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/pkg/alert"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/pkg/pipeline"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/pkg/rl_handle"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/pkg/safety_handle"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/repo/maprepo"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/settings"
	"github.com/ebpfagent/ebpfagent-project/ebpfagent-go/solution"
)

func main() {
	// 加载配置
	cfg, err := settings.LoadConfig("config/config.yml")
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	log.Printf("Agent ID: %s", cfg.Agent.ID)

	// 解析最低告警等级
	minSev := parseSeverity(cfg.Allow.MinAlertSeverity)

	// 隔离层：默认用内存map（单机部署），未来可切换Redis
	var mapper solution.AgentMapper
	mapper = maprepo.New()

	// Redis 后端（多机部署时取消注释）：
	// redisMapper, err := redisrepo.New(&cfg.Redis)
	// if err != nil {
	// 	log.Fatalf("redis连接失败: %v", err)
	// }
	// mapper = redisMapper

	// 注册单事件安全检测器
	solvers := []solution.Solver{
		safety_handle.NewDealShell(cfg.Allow.ShellProcesses),
		safety_handle.NewFileExecution(),
		safety_handle.NewPtraceDetect(cfg.Allow.Debuggers),
		safety_handle.NewPreloadDetect(),
		safety_handle.NewPrivilegeEsc(),
		safety_handle.NewProcAccess(),
		safety_handle.NewProcInject(),
		safety_handle.NewSudoOver(cfg.Allow.PackageManagers),
		safety_handle.NewSensitiveFile(),
		safety_handle.NewWorkspaceViolation(cfg.Allow.Workspace, cfg.Allow.TempDirs, cfg.Allow.AllowedDeleters),
		safety_handle.NewEmptyFileIO(),
	}

	// 逻辑检测器
	dealers := []solution.Dealwith{
		rl_handle.NewNetWorker(&cfg.Detect),
		rl_handle.NewWaste(&cfg.Detect),
		rl_handle.NewIOWaste(&cfg.Detect),
		rl_handle.NewGoalAnchor(mapper, cfg.Allow.MaxDeviations),
		rl_handle.NewInfoVerifier(mapper),
		rl_handle.NewPrematureTermDetector(mapper, cfg.Allow.SilenceThresholdSec),
	}

	ctx := context.Background()
	for _, d := range dealers {
		if err := d.Init(ctx); err != nil {
			log.Fatalf("初始化检测器失败: %v", err)
		}
	}

	// 告警输出
	printer := alert.NewConsolePrinter()

	// 组装管线
	pipe := pipeline.New(mapper, printer, solvers, dealers, minSev)

	// 从stdin读取Rust侧输出的JSON数组
	eventCh := make(chan *model.AggregatedEvent, 100)

	go func() {
		dec := json.NewDecoder(os.Stdin)
		for {
			var events []model.AggregatedEvent
			if err := dec.Decode(&events); err != nil {
				if err.Error() == "EOF" {
					log.Println("stdin已关闭（EOF），停止读取事件")
				} else {
					log.Printf("JSON解析错误: %v", err)
				}
				close(eventCh)
				return
			}
			for i := range events {
				eventCh <- &events[i]
			}
		}
	}()

	// 退出
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	log.Println("eBPF Agent 已启动，等待 stdin 事件输入...")

	for {
		select {
		case evt, ok := <-eventCh:
			if !ok {
				log.Println("事件源已关闭，退出")
				mapper.Shutdown(context.Background())
				return
			}
			pipe.ProcessEvent(context.Background(), evt)

		case sig := <-sigCh:
			log.Printf("收到信号 %v，优雅退出", sig)
			mapper.Shutdown(context.Background())
			return
		}
	}
}

// 从配置字符串解析严重度阈值
func parseSeverity(s string) solution.Severity {
	switch s {
	case "info":
		return solution.SevInfo
	case "low":
		return solution.SevLow
	case "medium":
		return solution.SevMedium
	case "high":
		return solution.SevHigh
	case "critical":
		return solution.SevCritical
	default:
		return solution.SevLow
	}
}
