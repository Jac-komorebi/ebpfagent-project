package model

// 事件
type AggregatedEvent struct {
	PID         uint32 `json:"pid"`
	Comm        string `json:"comm"`
	EventType   uint32 `json:"event_type"`
	Count       uint64 `json:"count"`
	FirstTimeNs uint64 `json:"first_time_ns"`
	LastTimeNs  uint64 `json:"last_time_ns"`
	Path        string `json:"path,omitempty"`
	DstIP       string `json:"dst_ip,omitempty"`
	DstPort     uint16 `json:"dst_port,omitempty"`

	// eBPF uprobe 从SSL_write/SSL_read截获的明文
	SSLData      string `json:"ssl_data,omitempty"`
	SSLDirection uint8  `json:"ssl_direction,omitempty"` // 0=Prompt(write), 1=Response(read)
}

// SSL 数据方向常量
const (
	SSLDirPrompt   uint8 = 0 // Agent发给大模型的Prompt
	SSLDirResponse uint8 = 1 // 大模型返回的Response
)

// 将数字事件类型映射到系统调用名称字符串
var eventTypeNames = map[uint32]string{
	1: "execve",
	2: "openat",
	3: "connect",
	4: "unlinkat",
	5: "clone",
	6: "ssl_data",
}

// 返回事件类型的系统调用名称
func (e *AggregatedEvent) SyscallName() string {
	if name, ok := eventTypeNames[e.EventType]; ok {
		return name
	}
	return "unknown"
}
