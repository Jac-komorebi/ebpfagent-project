package settings

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Redis  RedisConfig  `yaml:"redis"`
	Agent  AgentConfig  `yaml:"agent"`
	Detect DetectConfig `yaml:"detect"`
	Allow  AllowConfig  `yaml:"allow"`
}

// 连接参数
type RedisConfig struct {
	Addr   string `yaml:"addr"`
	Passwd string `yaml:"passwd"`
	DB     int    `yaml:"db"`
}

// 本地agent
type AgentConfig struct {
	ID             string `yaml:"id"`
	CleanupMinutes int    `yaml:"cleanup_minutes"`
}

type DetectConfig struct {
	MaxAPICalls    int    `yaml:"max_api_calls"`
	MaxIOCounts    int    `yaml:"max_io_counts"`
	MaxTotalIO     int    `yaml:"max_total_io"`
	MaxSamePrompt  int    `yaml:"max_same_prompt"`
	MaxTotalLoops  int    `yaml:"max_total_loops"`
	ResourceWindow string `yaml:"resource_window"`
	LogicWindow    string `yaml:"logic_window"`
}

// 白名单配置，减少误报
type AllowConfig struct {
	ShellProcesses      []string `yaml:"shell_processes"`
	Debuggers           []string `yaml:"debuggers"`
	PackageManagers     []string `yaml:"package_managers"`
	Workspace           string   `yaml:"workspace"`
	TempDirs            []string `yaml:"temp_dirs"`
	AllowedDeleters     []string `yaml:"allowed_deleters"`
	MinAlertSeverity    string   `yaml:"min_alert_severity"`
	SilenceThresholdSec int      `yaml:"silence_threshold_sec"`
	MaxDeviations       int      `yaml:"max_deviations"`
}

// 读取并解析YAML配置文件
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置失败: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置失败: %w", err)
	}
	// 默认值
	if cfg.Allow.Workspace == "" {
		cfg.Allow.Workspace = "/home/ebpfagent/workspace"
	}
	if cfg.Allow.MinAlertSeverity == "" {
		cfg.Allow.MinAlertSeverity = "low"
	}
	if cfg.Allow.SilenceThresholdSec == 0 {
		cfg.Allow.SilenceThresholdSec = 30
	}
	if cfg.Allow.MaxDeviations == 0 {
		cfg.Allow.MaxDeviations = 3
	}
	return &cfg, nil
}
