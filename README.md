# ebpfagent

ebpfagent 是一个基于 eBPF 的 AI Agent 行为安全监测系统。Rust 侧通过内核态 eBPF 程序采集目标进程的关键系统调用和 SSL/TLS 明文数据，用户态 Rust 程序读取 RingBuf、按 1 秒窗口聚合事件，以 JSON 行格式输出。Go 侧接收聚合事件流，从安全异常、资源滥用和逻辑行为三个维度进行多层次的异常检测与告警。

当前代码默认只关注进程名为 `agent` 的目标进程，用于降低无关系统噪声和用户态解析压力。

## 项目组成

- Rust/eBPF 采集与聚合：[`ebpfagent-rust/`](ebpfagent-rust/)
- Go 行为安全检测与告警：[`ebpfagent-go/`](ebpfagent-go/)

下面先介绍 Rust 侧的 eBPF 采集与聚合模块，再介绍 Go 侧的行为安全检测模块。

## Rust 侧：eBPF 采集与聚合

## 功能概览

- 进程启动监控：采集 `execve` 事件。
- 文件访问监控：采集 `openat` 事件。
- 文件删除监控：采集 `unlink` / `unlinkat` 事件。
- 网络连接监控：采集 `connect` 事件，记录 IPv4 目标 IP 和端口。
- 进程/线程派生监控：采集 `clone`、`clone3`、`fork`、`vfork` 类事件。
- SSL/TLS 明文采集：通过 OpenSSL `SSL_write` / `SSL_read` 尝试采集请求和响应明文。
- SSL 数据方向：将 `SSL_write` 标记为写方向，将 `SSL_read` 标记为读方向。
- 用户态聚合输出：Rust collector 从 RingBuf 读取事件，按 1 秒窗口聚合后输出 JSON。
- 事件输出：当前只输出采集结果，不在 collector 内做规则判断。

## 项目结构

```
ebpfagent-rust/
├── Cargo.toml              # Rust workspace 配置
├── rust-toolchain.toml     # nightly + rust-src 工具链配置
├── zhy-ebpf/               # 内核态 eBPF 程序
├── zhy-collector/          # 用户态采集与聚合程序
└── xtask/                  # 构建和运行辅助命令
```

实际入口是 `zhy-ebpf/src/main.rs` 和 `zhy-collector/src/main.rs`。

## 环境要求

- Linux 环境
- Rust nightly
- rust-src 组件
- 支持 eBPF 的 Linux 内核
- sudo 权限
- OpenSSL 动态库 libssl.so

## 构建

构建全部：
```
cargo xtask build
```

仅构建 eBPF：
```
cargo xtask build-ebpf
```

仅构建用户态 collector：
```
cargo xtask build-user
```

## 运行

```
cargo xtask run
```

等价于：
```
sudo -E target/release/zhy-collector target/bpfel-unknown-none/release/zhy-ebpf
```

也可以手动指定 eBPF 对象路径：
```
sudo -E target/release/zhy-collector /path/to/zhy-ebpf
```

## 输出格式

collector 每秒输出一行 JSON 数组。数组中的每个对象表示一个聚合后的事件。

示例：
```json
[
  {
    "pid": 12345,
    "comm": "agent",
    "event_type": 3,
    "count": 2,
    "first_time_ns": 1000000000,
    "last_time_ns": 1000000500,
    "dst_ip": "93.184.216.34",
    "dst_port": 443
  }
]
```

字段说明：

| 字段 | 说明 |
|---|---|
| pid | 进程 ID |
| comm | 进程名 |
| event_type | 事件类型编号 |
| count | 当前 1 秒窗口内聚合次数 |
| first_time_ns | 当前聚合窗口内首次事件时间戳 |
| last_time_ns | 当前聚合窗口内最后一次事件时间戳 |
| path | 文件路径、执行路径或载荷内容 |
| dst_ip | 网络连接目标 IPv4 地址 |
| dst_port | 网络连接目标端口 |
| ssl_data | SSL/TLS 明文数据 |
| ssl_direction | SSL/TLS 数据方向，0 表示写入请求，1 表示读取响应 |

事件类型：

| 编号 | 事件 |
|---|---|
| 1 | execve |
| 2 | openat |
| 3 | connect |
| 4 | unlink / unlinkat |
| 5 | clone / clone3 / fork / vfork |
| 6 | SSL/TLS 明文数据 |

## 实现说明

### 内核态事件采集

eBPF 程序运行在内核态，受 verifier、栈空间和 helper 调用规则限制。内核态只读取必要参数、填充固定长度结构体并写入 RingBuf；事件解释和规则判断放在用户态处理。

### 固定长度事件结构

内核态事件使用 `#[repr(C)]` 和固定长度数组：`comm: [u8; 16]`、`path: [u8; 256]`。这样可以避免动态内存分配，保证 eBPF 程序更容易通过 verifier，同时保持内核态和用户态的二进制结构一致。

### RingBuf + 1 秒聚合

内核态通过 ZHY_EVENTS RingBuf 输出原始事件。用户态 collector 读取事件后批量合并到 HashMap 中，最后每秒统一序列化输出。这种方式可以减少锁竞争，也能避免下游服务直接面对高频原始日志。

### SSL/TLS 明文采集

通过 uprobe 读取 OpenSSL 的 SSL_write 和 SSL_read 缓冲区：SSL_write 读取发送前缓冲区，SSL_read 读取返回后的缓冲区。如果运行环境中没有找到 libssl.so，或者 uprobe 挂载失败，collector 会跳过该能力，基础系统调用监控仍可继续运行。

## 注意事项

- 当前目标进程名硬编码为 `agent`。如需监控其他进程，需要修改 `zhy-ebpf/src/main.rs` 中的 `ZHY_TARGET_COMM`。
- 当前网络连接解析主要处理 IPv4，即 AF_INET。
- eBPF 程序需要 root 权限或等效能力才能加载和附加。
- RingBuf 满时可能丢弃事件，collector 不做重试。
- SSL/TLS 明文采集依赖目标程序使用的 TLS 实现和系统动态库情况，不保证所有程序都能捕获。

---

## Go 侧：行为安全监测

Go 侧接收 Rust 侧 eBPF 探针输出的聚合事件流，从**安全异常**、**资源滥用**和**逻辑行为**三个维度对 AI Agent 进程进行多层次的异常检测与告警。

## 检测能力

### 安全异常检测（单事件，Solver）

| 检测器 | 说明 | 严重度 |
|---|---|---|
| `ShellDetect` | 检测非预期的 shell 进程执行（反弹 shell 等） | Low |
| `FileExecution` | 检测无文件执行（`memfd_create` + `fexecve`） | High |
| `PtraceDetect` | 检测非授权的调试器附加（`PTRACE_ATTACH`） | Medium |
| `PreloadDetect` | 检测 `/etc/ld.so.preload` 的写入/篡改 | High |
| `PrivilegeEsc` | 检测权限提升行为（core_pattern 等敏感路径写入） | Critical |
| `ProcAccess` | 检测非法进程内存访问（`/proc/<pid>/mem`） | High |
| `ProcInject` | 检测进程注入（`/proc/<pid>/mem` 写入） | Critical |
| `SudoOver` | 检测非包管理器外的 `sudo` 越权操作 | Low |
| `SensitiveFile` | 检测敏感文件访问（`/etc/shadow`、SSH key 等） | High |
| `WorkspaceViolation` | 检测工作区外文件操作（路径穿越） | Low |
| `EmptyFileIO` | 检测空文件 I/O（可能是隐蔽写入） | Low |

### 逻辑行为检测（多事件，Dealwith）

| 检测器 | 说明 | 类别 |
|---|---|---|
| `NetWorker` | 检测 API 调用频率异常（网络连接数超阈值） | 资源 |
| `Waste` | 检测重复 prompt/死循环（系统调用模式重复超阈值） | 资源 |
| `IOWaste` | 检测 I/O 操作异常（文件读写次数/总量超阈值） | 资源 |
| `GoalAnchor` | 目标锚定：检测 agent 行为是否偏离预期目标 | 逻辑 |
| `InfoVerifier` | 信息校验：检测 agent 是否隐瞒/伪造信息 | 逻辑 |
| `PrematureTermDetector` | 沉默检测：agent 长时间无响应视为异常终止 | 逻辑 |

## 编译

```bash
go mod tidy
go build -o ebpfagent .
```

## 配置

编辑 `config/config.yml`：

```yaml
agent:
  id: "agent-01"           # 本机 agent 标识
  cleanup_minutes: 15      # 状态清理周期（分钟）

detect:
  max_api_calls: 100       # 最大 API 调用次数
  max_io_counts: 50        # 最大 I/O 操作次数
  max_total_io: 100        # 最大 I/O 总量
  max_same_prompt: 5       # 最大重复 Prompt 次数
  max_total_loops: 100     # 最大循环次数
  resource_window: "10s"   # 资源检测时间窗口
  logic_window: "10s"      # 逻辑检测时间窗口

allow:
  shell_processes: [...]   # 白名单 shell 进程
  debuggers: [...]         # 白名单调试器
  package_managers: [...]  # 白名单包管理器
  workspace: "/home/ebpfagent/workspace"  # 合法工作区路径
  temp_dirs: ["/tmp", "/var/tmp", "/dev/shm"]  # 临时目录
  min_alert_severity: "low"      # 最低告警等级 (info/low/medium/high/critical)
  silence_threshold_sec: 30      # 沉默检测阈值（秒）
  max_deviations: 3              # 最大行为偏离次数
```

## 运行

eBPF Agent 从 stdin 接收 Rust 侧 collector 输出的 JSON 聚合事件流：

```bash
# 配合 eBPF 探针使用
sudo -E target/release/zhy-collector target/bpfel-unknown-none/release/zhy-ebpf | ./ebpfagent

# 或从文件回放
cat events.json | ./ebpfagent
```

## 告警输出

检测到异常时，输出包含两部分：

**结构化日志**（供日志采集系统消费）：

```
[ALERT][security][high] first_time_ns=1719000000000000000 agent=agent-01 pid=12345 syscall=openat path=/etc/shadow reason=访问敏感文件
```

**可读文本块**（供运维人员查看）：

```
------------------------------------------------
告警类型: security
严重程度: high
首次时间: 1719000000000000000 ns
Agent进程: agent-01 (PID: 12345)
系统调用: openat
累计次数: 1
操作路径: /etc/shadow
异常描述: 访问敏感文件
```

## 多机部署

默认使用内存存储（适合单机）。多机部署时切换到 Redis 后端，实现跨节点的 agent 状态共享：

1. 确保 Redis 可访问
2. 在 `config/config.yml` 中配置 Redis 连接：

```yaml
redis:
  addr: "10.0.0.1:6379"
  passwd: "your_password"
  db: 0
```

3. 在 `main.go` 中切换后端（注释掉 `maprepo.New()`，取消注释 Redis 初始化代码）。
