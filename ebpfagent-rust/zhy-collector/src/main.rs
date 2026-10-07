use std::{
    borrow::BorrowMut,
    collections::HashMap,
    convert::TryInto,
    hash::{Hash, Hasher},
    mem::{size_of, MaybeUninit},
    net::Ipv4Addr,
    os::fd::AsRawFd,
    path::Path,
    ptr,
    sync::Arc,
};

use anyhow::{anyhow, Context, Result};

use aya::{
    maps::{MapData, RingBuf},
    programs::{TracePoint, UProbe},
    Ebpf,
};
use serde::Serialize;
use tokio::{
    io::unix::AsyncFd,
    sync::Mutex,
    time::{interval, Duration, MissedTickBehavior},
};

const ZHY_EVENT_EXECVE: u32 = 1;
const ZHY_EVENT_OPENAT: u32 = 2;
const ZHY_EVENT_CONNECT: u32 = 3;
const ZHY_EVENT_UNLINKAT: u32 = 4;
const ZHY_EVENT_SSL_DATA: u32 = 6;

const ZHY_SSL_DIR_WRITE: i32 = 0;
const ZHY_SSL_DIR_READ: i32 = 1;

const ZHY_COMM_LEN: usize = 16;
const ZHY_PATH_LEN: usize = 256;
// 必须和 zhy-ebpf::ZHY_Event 保持字段顺序一致
// collector 直接从 RingBuf 原始字节拷贝成这个结构体
// 新增字段时要同时改 eBPF 侧结构体和 Go 侧 JSON 解析
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ZHY_Event {
    pub event_type: u32,
    pub pid: u32,
    pub tgid: u32,
    pub path_len: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; ZHY_COMM_LEN],
    pub path: [u8; ZHY_PATH_LEN],
    pub dirfd: i32,
    pub open_flags: i32,
    pub open_mode: u32,
    pub sock_fd: i32,
    pub sockaddr_family: u16,
    pub dst_port_be: u16,
    pub dst_ip_be: u32,
    pub reserved: u32,
}

#[derive(Clone, Debug, Eq)]
struct ZHY_AggKey {
    pid: u32,
    event_type: u32,
    target: String,
    // connect 使用端口；SSL 事件复用为方向值
    dst_port: u16,
}

impl PartialEq for ZHY_AggKey {
    fn eq(&self, other: &Self) -> bool {
        self.pid == other.pid
            && self.event_type == other.event_type
            && self.target == other.target
            && self.dst_port == other.dst_port
    }
}

impl Hash for ZHY_AggKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pid.hash(state);
        self.event_type.hash(state);
        self.target.hash(state);
        self.dst_port.hash(state);
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AggregatedEvent {
    pub pid: u32,
    pub comm: String,
    pub event_type: u32,
    pub count: u64,
    pub first_time_ns: u64,
    pub last_time_ns: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_ip: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,

    /// 截获的 SSL/TLS 明文负载
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_data: Option<String>,

    /// SSL 数据方向: 0=Write, 1=Read。
    /// Go 侧可以按业务语义再映射为请求/响应
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_direction: Option<u8>,
}

type ZHY_AggMap = HashMap<ZHY_AggKey, AggregatedEvent>;

#[tokio::main]
async fn main() -> Result<()> {
    let default_obj_path = String::from("target/bpfel-unknown-none/release/zhy-ebpf");
    let ebpf_path = std::env::args().nth(1).unwrap_or(default_obj_path);

    let mut bpf = Ebpf::load_file(&ebpf_path)
        .with_context(|| format!("failed to load eBPF object: {ebpf_path}"))?;

    
    // 基础系统调用探针挂载
    // 必需 tracepoint 绑定失败时直接返回错误
    // 可选 tracepoint 失败不影响主流程
    // 必需项覆盖主链路：execve、openat、connect。
    // 这样可以区分“程序无法工作”和“当前内核缺少某个扩展事件”
    zhy_bind_tp(&mut bpf, "zhy_tp_execve", "syscalls", "sys_enter_execve")?;
    zhy_bind_tp(&mut bpf, "zhy_tp_openat", "syscalls", "sys_enter_openat")?;
    zhy_bind_tp(&mut bpf, "zhy_tp_connect", "syscalls", "sys_enter_connect")?;

    // 可选 tracepoint 失败不影响主流程
    // 不同内核版本可能缺少 unlink、clone3 或 vfork 对应 tracepoint
    let _ = zhy_try_bind_tp(&mut bpf, "zhy_tp_unlink", "syscalls", "sys_enter_unlink");
    let _ = zhy_try_bind_tp(&mut bpf, "zhy_tp_unlinkat", "syscalls", "sys_enter_unlinkat");
    let _ = zhy_try_bind_tp(&mut bpf, "zhy_tp_clone", "syscalls", "sys_enter_clone");
    let _ = zhy_try_bind_tp(&mut bpf, "zhy_tp_clone3", "syscalls", "sys_enter_clone3");
    let _ = zhy_try_bind_tp(&mut bpf, "zhy_tp_vfork", "syscalls", "sys_enter_vfork");

    // SSL/TLS uprobe
    // 这部分依赖 libssl 和符号表，失败时仍保留 syscall 事件输出
    let _ = zhy_attach_uprobe_ssl(&mut bpf);
    let _ = zhy_attach_uprobe_gotls(&mut bpf, None);
    let map_obj = bpf
        .take_map("ZHY_EVENTS")
        .ok_or_else(|| anyhow!("ZHY_EVENTS ring buffer map not found"))?;
    let ring_buf = RingBuf::try_from(map_obj)?;
    let mut async_ring = AsyncFd::new(ring_buf)?;
    let zhy_global_ring: Arc<Mutex<ZHY_AggMap>> = Arc::new(Mutex::new(HashMap::new()));
    let mut tick = interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            collect_result = zhy_collect_events(&mut async_ring, &zhy_global_ring) => {
                collect_result?;
            }

            _ = tick.tick() => {
                zhy_flush_aggregated(&zhy_global_ring).await?;
            }
        }
    }
}
// RingBuf 事件收集与窗口聚合
// 先读入本地 Vec，再批量写入聚合 Map，减少持锁时间
// 输出节奏固定为 1 秒，方便下游按批次消费 JSON 行
// stdout 是与 Go 侧对接的边界，不在这里打印额外调试文本
async fn zhy_collect_events<T>(
    async_ring: &mut AsyncFd<RingBuf<T>>,
    zhy_global_ring: &Arc<Mutex<ZHY_AggMap>>,
) -> Result<()>
where
    T: BorrowMut<MapData>,
    RingBuf<T>: AsRawFd,
{
    // staging 避免持有聚合锁时阻塞 RingBuf drain
    let mut zhy_staging_events: Vec<ZHY_Event> = Vec::new();

    {
        let mut guard = async_ring.readable_mut().await?;
        let ring_inner = guard.get_inner_mut();

        loop {
            let item_opt = ring_inner.next();
            let item = match item_opt {
                Some(v) => v,
                None => break,
            };

            if let Some(event) = zhy_extract_event(&item) {
                zhy_staging_events.push(event);
            }
        }

        guard.clear_ready();
    }

    if zhy_staging_events.is_empty() {
        return Ok(());
    }

    let mut locked_map = zhy_global_ring.lock().await;

    for event in zhy_staging_events {
        zhy_merge_event(&mut locked_map, event);
    }

    Ok(())
}
// 序列化前释放锁，避免 JSON 编码阻塞采集侧
// 这里先 clone 一批快照，再清空窗口
async fn zhy_flush_aggregated(zhy_global_ring: &Arc<Mutex<ZHY_AggMap>>) -> Result<()> {
    let mut locked_map = zhy_global_ring.lock().await;

    if locked_map.is_empty() {
        return Ok(());
    }

    let mut zhy_emit_batch: Vec<AggregatedEvent> = Vec::with_capacity(locked_map.len());

    for item in locked_map.values() {
        zhy_emit_batch.push(item.clone());
    }

    locked_map.clear();
    drop(locked_map);
    // 每行是一个 JSON 数组 Go 侧按行读取
    let json_line = serde_json::to_string(&zhy_emit_batch)?;
    println!("{json_line}");

    Ok(())
}

fn zhy_bind_tp(
    bpf: &mut Ebpf,
    program_name: &str,
    category: &str,
    trace_name: &str,
) -> Result<()> {
    let program_obj = bpf
        .program_mut(program_name)
        .ok_or_else(|| anyhow!("program not found: {program_name}"))?;

    let tp: &mut TracePoint = program_obj.try_into()?;

    tp.load()?;
    tp.attach(category, trace_name)?;

    Ok(())
}
fn zhy_try_bind_tp(
    bpf: &mut Ebpf,
    program_name: &str,
    category: &str,
    trace_name: &str,
) -> Result<()> {
    let program_obj = match bpf.program_mut(program_name) {
        Some(v) => v,
        None => return Ok(()),
    };

    let tp: &mut TracePoint = program_obj.try_into()?;

    tp.load()?;

    match tp.attach(category, trace_name) {
        Ok(_) => Ok(()),
        Err(_) => Ok(()),
    }
}

/// 查找系统中 libssl.so 的绝对路径
/// 只做本地候选路径查找，找不到就跳过 SSL hook
fn zhy_find_libssl() -> Option<String> {
    let candidates = [
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/usr/lib/x86_64-linux-gnu/libssl.so",
        "/usr/lib64/libssl.so.3",
        "/usr/lib64/libssl.so.1.1",
        "/usr/lib64/libssl.so",
        "/usr/lib/libssl.so.3",
        "/usr/lib/libssl.so",
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/lib/x86_64-linux-gnu/libssl.so",
    ];
    for p in candidates {
        if Path::new(p).exists() {
            return Some(p.to_string());
        }
    }
    None
}

/// 附加 OpenSSL 的 uprobe/uretprobe
/// - SSL_write: 读取发送前缓冲区
/// - SSL_read: 读取返回后的缓冲区
/// 这些 hook 是可选能力，失败时不影响基础 syscall 事件
fn zhy_attach_uprobe_ssl(bpf: &mut Ebpf) -> Result<()> {
    let libssl = match zhy_find_libssl() {
        Some(p) => {
            eprintln!("[zhy] 找到 libssl: {p}");
            p
        }
        None => {
            eprintln!("[zhy] WARN: 未找到 libssl.so，跳过 SSL uprobe 附加");
            return Ok(());
        }
    };

    // SSL_write uprobe
    // 对应 eBPF 侧 zhy_uprobe_ssl_write
    let ssl_write_prog: &mut UProbe = match bpf.program_mut("zhy_uprobe_ssl_write") {
        Some(p) => p.try_into().context("zhy_uprobe_ssl_write 类型转换失败")?,
        None => {
            eprintln!("[zhy] WARN: eBPF 对象中未找到 zhy_uprobe_ssl_write, 跳过");
            return Ok(());
        }
    };
    ssl_write_prog.load()?;
    ssl_write_prog.attach("SSL_write", libssl.as_str(), aya::programs::uprobe::UProbeScope::AllProcesses)?;
    eprintln!("[zhy] 已附加 uprobe: SSL_write@{libssl}");

    // SSL_read uprobe: 存储缓冲区指针到 PerCpuArray
    // 返回探针需要这个地址读取已写入的数据
    let ssl_read_prog: &mut UProbe = match bpf.program_mut("zhy_uprobe_ssl_read") {
        Some(p) => p.try_into().context("zhy_uprobe_ssl_read 类型转换失败")?,
        None => {
            eprintln!("[zhy] WARN: eBPF 对象中未找到 zhy_uprobe_ssl_read, 跳过");
            return Ok(());
        }
    };
    ssl_read_prog.load()?;
    ssl_read_prog.attach("SSL_read", libssl.as_str(), aya::programs::uprobe::UProbeScope::AllProcesses)?;
    eprintln!("[zhy] 已附加 uprobe: SSL_read@{libssl} (入口, 缓冲区指针存储)");

    // SSL_read uretprobe: 读取 PerCpuArray
    let ssl_read_ret_prog: &mut UProbe = match bpf.program_mut("zhy_uretprobe_ssl_read") {
        Some(p) => p.try_into().context("zhy_uretprobe_ssl_read 类型转换失败")?,
        None => {
            eprintln!("[zhy] WARN: eBPF 对象中未找到 zhy_uretprobe_ssl_read, 跳过");
            return Ok(());
        }
    };
    ssl_read_ret_prog.load()?;
    ssl_read_ret_prog.attach("SSL_read", libssl.as_str(), aya::programs::uprobe::UProbeScope::AllProcesses)?;
    eprintln!("[zhy] 已附加 uretprobe: SSL_read@{libssl}");

    Ok(())
}

/// 尝试附加 Go crypto/tls 的 uprobe（尽力而为, 失败不阻塞）
/// Go 的 crypto/tls.(*Conn).Write 和 Read 符号名因版本和编译方式而异
/// 此处作为一个扩展入口供后续按需实现
#[allow(unused)]
fn zhy_attach_uprobe_gotls(bpf: &mut Ebpf, _agent_binary: Option<&str>) -> Result<()> {
    // Go 1.20+ 寄存器 ABI 下符号名为:
    //   crypto/tls.(*Conn).Write
    //   crypto/tls.(*Conn).Read
    // 但符号解析需要 DWARF/符号表, aya 0.14 的 UProbe 支持 Symbol 模式
    // 如需启用 Go TLS hook, 在此添加对应探针程序并指定 agent 二进制路径即可
    eprintln!("[zhy] Go TLS uprobe hook 未启用 (需要指定 agent 二进制路径)");
    let _ = bpf;
    Ok(())
}

fn zhy_merge_event(map: &mut ZHY_AggMap, event: ZHY_Event) {
    // event.path 在不同事件里含义不同：文件路径、进程路径或 SSL 负载
    let comm_text = zhy_buffer_to_string(&event.comm);

    // path_len 来自 eBPF 侧实际拷贝长度，先截断再转字符串
    let path_len = (event.path_len as usize).min(ZHY_PATH_LEN);
    let path_text = if path_len > 0 {
        let raw_path = &event.path[..path_len];
        let text = zhy_buffer_to_string(raw_path);

        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    } else {
        None
    };

    // eBPF 侧保留网络字节序，collector 输出前转为主机字节序
    let dst_port = if event.event_type == ZHY_EVENT_CONNECT && event.dst_port_be != 0 {
        Some(u16::from_be(event.dst_port_be))
    } else {
        None
    };

    let dst_ip = if event.event_type == ZHY_EVENT_CONNECT && event.dst_ip_be != 0 {
        let ip_host_order = u32::from_be(event.dst_ip_be);
        let ip_text = Ipv4Addr::from(ip_host_order).to_string();
        Some(ip_text)
    } else {
        None
    };

    let mut target = String::new();
    let mut key_port = 0u16;

    // target 是聚合维度，不一定等于输出字段
    if event.event_type == ZHY_EVENT_OPENAT || event.event_type == ZHY_EVENT_UNLINKAT {
        if let Some(v) = &path_text {
            target = v.clone();
        }
    } else if event.event_type == ZHY_EVENT_CONNECT {
        if let Some(v) = &dst_ip {
            target = v.clone();
        }

        if let Some(v) = dst_port {
            key_port = v;
        }
    } else if event.event_type == ZHY_EVENT_EXECVE {
        if let Some(v) = &path_text {
            target = v.clone();
        }
    } else if event.event_type == ZHY_EVENT_SSL_DATA {
        // SSL 事件按 PID 和方向聚合，ssl_data 保留最新内容
        // open_flags 在 SSL 事件中复用为方向标记
        // key_port 也复用方向值，避免读写方向合并到同一条
        let dir_flag = if event.open_flags == ZHY_SSL_DIR_READ { "r" } else { "w" };
        target = dir_flag.to_string();
        key_port = event.open_flags as u16;
    }
    // 复合 Key 避免不同目标在同一窗口内被合并

    let key = ZHY_AggKey {
        pid: event.pid,
        event_type: event.event_type,
        target,
        dst_port: key_port,
    };

    match map.get_mut(&key) {
        Some(agg) => {
            agg.count += 1;
            agg.last_time_ns = event.timestamp_ns;
            // SSL 事件更新最新负载
            // count 仍表示当前窗口内同方向 SSL 事件次数
            if event.event_type == ZHY_EVENT_SSL_DATA {
                agg.ssl_data = path_text;
                agg.ssl_direction = if event.open_flags == ZHY_SSL_DIR_READ {
                    Some(1)
                } else {
                    Some(0)
                };
            }
        }
        None => {
            // SSL 事件写入 ssl_data，非 SSL 事件保留 path
            let (event_path, ssl_data, ssl_direction) =
                if event.event_type == ZHY_EVENT_SSL_DATA {
                    let dir = if event.open_flags == ZHY_SSL_DIR_READ {
                        1
                    } else {
                        0
                    };
                    (None, path_text, Some(dir))
                } else {
                    (path_text, None, None)
                };

            let new_item = AggregatedEvent {
                pid: event.pid,
                comm: comm_text,
                event_type: event.event_type,
                count: 1,
                first_time_ns: event.timestamp_ns,
                last_time_ns: event.timestamp_ns,
                path: event_path,
                dst_ip,
                dst_port,
                ssl_data,
                ssl_direction,
            };

            map.insert(key, new_item);
        }
    }
}

fn zhy_extract_event(raw: &[u8]) -> Option<ZHY_Event> {
    let need_size = size_of::<ZHY_Event>();

    if raw.len() < need_size {
        return None;
    }

    let mut holder = MaybeUninit::<ZHY_Event>::uninit();

    // RingBuf item 是内核侧写入的固定布局字节块
    // 这里不做字段级解析，依赖 #[repr(C)] 的布局约定
    unsafe {
        let src_ptr = raw.as_ptr();
        let dst_ptr = holder.as_mut_ptr() as *mut u8;

        ptr::copy_nonoverlapping(src_ptr, dst_ptr, need_size);

        Some(holder.assume_init())
    }
}
// 内核态原始字节流转换为可读字符串
// 按第一个 NUL 截断，再用 lossy UTF-8 转换
fn zhy_buffer_to_string(raw: &[u8]) -> String {
    let mut end_pos = raw.len();

    for idx in 0..raw.len() {
        if raw[idx] == 0 {
            end_pos = idx;
            break;
        }
    }

    let visible = &raw[..end_pos];
    String::from_utf8_lossy(visible).into_owned()
}
