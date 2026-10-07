# my_rust_ebpf

`my_rust_ebpf` 是一个基于 Rust + Aya eBPF 的 Linux 行为监控原型项目。项目通过内核态 eBPF 程序采集目标进程的关键系统调用和 SSL/TLS 明文数据，再由用户态 Rust 程序读取 RingBuf、按 1 秒窗口聚合事件，并以 JSON 行格式输出。

当前代码默认只关注进程名为 `agent` 的目标进程，用于降低无关系统噪声和用户态解析压力。

## 功能概览

- 进程启动监控：采集 `execve` 事件。
- 文件访问监控：采集 `openat` 事件。
- 文件删除监控：采集 `unlink` / `unlinkat` 事件。
- 网络连接监控：采集 `connect` 事件，记录 IPv4 目标 IP 和端口。
- 进程/线程派生监控：采集 `clone`、`clone3`、`fork``vfork` 类事件。
- SSL/TLS 明文采集：通过 OpenSSL `SSL_write` / `SSL_read` 尝试采集请求和响应明文。
- SSL 数据方向：将 `SSL_write` 标记为写方向，将 `SSL_read` 标记为读方向。
- 用户态聚合输出：Rust collector 从 RingBuf 读取事件，按 1 秒窗口聚合后输出 JSON。
- 事件输出：当前只输出采集结果，不在 collector 内做规则判断。

## 项目结构

```text
my_rust_ebpf/
├── Cargo.toml              # Rust workspace 配置
├── rust-toolchain.toml     # nightly + rust-src 工具链配置
├── zhy-ebpf/               # 内核态 eBPF 程序
├── zhy-collector/          # 用户态采集与聚合程序
└── xtask/                  # 构建和运行辅助命令
实际入口是：
zhy-ebpf/src/main.rs
zhy-collector/src/main.rs

环境要求
Linux 环境
Rust nightly
rust-src 组件
支持 eBPF 的 Linux 内核
sudo 权限
OpenSSL 动态库 libssl.so
构建
构建全部：
cargo xtask build
仅构建 eBPF：
cargo xtask build-ebpf
仅构建用户态 collector：
cargo xtask build-user
运行
cargo xtask run
等价于：
sudo -E target/release/zhy-collector target/bpfel-unknown-none/release/zhy-ebpf
也可以手动指定 eBPF 对象路径：
sudo -E target/release/zhy-collector /path/to/zhy-ebpf
输出格式
collector 每秒输出一行 JSON 数组。数组中的每个对象表示一个聚合后的事件。
示例：
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
字段说明：
字段	说明
pid	进程 ID
comm	进程名
event_type	事件类型编号
count	当前 1 秒窗口内聚合次数
first_time_ns	当前聚合窗口内首次事件时间戳
last_time_ns	当前聚合窗口内最后一次事件时间戳
path	文件路径、执行路径或载荷内容
dst_ip	网络连接目标 IPv4 地址
dst_port	网络连接目标端口
ssl_data	SSL/TLS 明文数据
ssl_direction	SSL/TLS 数据方向，0 表示写入请求，1 表示读取响应

事件类型：
编号	事件
1	execve
2	openat
3	connect
4	unlink / unlinkat
5	clone / clone3 / fork / vfork
6	SSL/TLS 明文数据

实现说明
内核态事件采集
eBPF 程序运行在内核态，受 verifier、栈空间和 helper 调用规则限制。内核态只读取必要参数、填充固定长度结构体并写入 RingBuf；事件解释和规则判断放在用户态处理。
固定长度事件结构
内核态事件使用 #[repr(C)] 和固定长度数组：
comm: [u8; 16]
path: [u8; 256]
这样可以避免动态内存分配，保证 eBPF 程序更容易通过 verifier，同时保持内核态和用户态的二进制结构一致。
RingBuf + 1 秒聚合
内核态通过 ZHY_EVENTS RingBuf 输出原始事件。用户态 collector 读取事件后批量合并到 HashMap 中，最后每秒统一序列化输出。
这种方式可以减少锁竞争，也能避免下游服务直接面对高频原始日志。
SSL/TLS 明文采集
通过 uprobe 读取 OpenSSL 的 SSL_write 和 SSL_read 缓冲区：
SSL_write：读取发送前缓冲区。
SSL_read：读取返回后的缓冲区。
如果运行环境中没有找到 libssl.so，或者 uprobe 挂载失败，collector 会跳过该能力，基础系统调用监控仍可继续运行。
注意事项
当前目标进程名硬编码为 agent。
如需监控其他进程，需要修改 zhy-ebpf/src/main.rs 中的 ZHY_TARGET_COMM。
当前网络连接解析主要处理 IPv4，即 AF_INET。
eBPF 程序需要 root 权限或等效能力才能加载和附加。
RingBuf 满时可能丢弃事件，collector 不做重试。
SSL/TLS 明文采集依赖目标程序使用的 TLS 实现和系统动态库情况，不保证所有程序都能捕获。
