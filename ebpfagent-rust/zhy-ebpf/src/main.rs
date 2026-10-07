#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint, uprobe, uretprobe},
    maps::{PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};
// Event type 必须和 zhy-collector 保持一致
const ZHY_EVENT_EXECVE: u32 = 1;
const ZHY_EVENT_OPENAT: u32 = 2;
const ZHY_EVENT_CONNECT: u32 = 3;
const ZHY_EVENT_UNLINKAT: u32 = 4;
const ZHY_EVENT_CLONE: u32 = 5;
const ZHY_EVENT_SSL_DATA: u32 = 6;
const ZHY_COMM_LEN: usize = 16;
const ZHY_PATH_LEN: usize = 256;
const ZHY_AF_INET: u16 = 2;
const ZHY_SSL_DIR_WRITE: i32 = 0;
const ZHY_SSL_DIR_READ: i32 = 1;
const ZHY_SSL_MAX_COPY: usize = 240;
// sys_enter_* tracepoint 的 args 偏移，当前按 x86_64 布局读取
const ZHY_ARG0_OFF: usize = 16;
const ZHY_ARG1_OFF: usize = 24;
const ZHY_ARG2_OFF: usize = 32;
const ZHY_ARG3_OFF: usize = 40;
// comm 只有 16 字节，这里匹配 "agent\0" 前 5 个字节
const ZHY_TARGET_COMM: [u8; 5] = *b"agent";
// 结构体布局必须和用户态解析代码保持同步
// 部分字段按 event_type 复用
// - path: 文件路径或 SSL 负载
// - open_flags: 文件 flags 或 SSL 方向
// - open_mode: 文件 mode 或 clone_flags 低 32 位
#[repr(C)]
#[derive(Clone, Copy)]
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

impl ZHY_Event {
    #[inline(always)]
    pub const fn zhy_zeroed(kind: u32) -> Self {
        Self {
            event_type: kind,
            pid: 0,
            tgid: 0,
            path_len: 0,
            timestamp_ns: 0,
            comm: [0; ZHY_COMM_LEN],
            path: [0; ZHY_PATH_LEN],
            dirfd: 0,
            open_flags: 0,
            open_mode: 0,
            sock_fd: 0,
            sockaddr_family: 0,
            dst_port_be: 0,
            dst_ip_be: 0,
            reserved: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZHY_SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}

#[map]
// 事件通过 RingBuf 交给用户态；满时 output 会失败，调用方忽略错误
static ZHY_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct ZHY_SslReadEntry {
    buf: u64,
    tgid: u32,
    _pad: u32,
}
// PerCpuArray 用于在 SSL_read entry/return 之间传递 buf 地址
// OpenSSL 在 return 前才把解密后的数据写入 buf
// return 侧读取后清零，避免复用旧地址
#[map]
static ZHY_SSL_READ_BUF: PerCpuArray<ZHY_SslReadEntry> = PerCpuArray::with_max_entries(1, 0);

#[used]
#[no_mangle]
#[link_section = "license"]
// eBPF 程序需要声明 GPL，部分 helper 依赖该 license
static ZHY_LICENSE: [u8; 4] = *b"GPL\0";

#[tracepoint]
pub fn zhy_tp_execve(ctx: TracePointContext) -> u32 {
    match zhy_handle_exec(ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint]
pub fn zhy_tp_openat(ctx: TracePointContext) -> u32 {
    match zhy_handle_openat(ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint]
pub fn zhy_tp_connect(ctx: TracePointContext) -> u32 {
    match zhy_handle_connect(ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

// execve 探针
// filename 位于 syscall 参数 0
// path_len 由实际拷贝长度填充，用户态据此截断固定数组
// 事件只记录 execve 传入的文件名，不在内核态解析 argv/envp
fn zhy_handle_exec(ctx: TracePointContext) -> Result<u32, i64> {
    let mut event = match zhy_make_base_event(ZHY_EVENT_EXECVE) {
        Some(v) => v,
        None => return Ok(0),
    };

    let filename_raw: u64 = unsafe { ctx.read_at::<u64>(ZHY_ARG0_OFF)? };
    let filename_ptr: *const u8 = filename_raw as *const u8;

    zhy_copy_user_path(filename_ptr, &mut event);

    let _ = ZHY_EVENTS.output(&event, 0);
    Ok(0)
}

// openat 探针
// 保存 dirfd、flags、mode，用户态可还原相对路径语义
// pathname 仍放入 event.path，避免为每类 syscall 定义不同事件结构
// flags/mode 原样透传，权限含义由 Go 或其他上层模块解释
fn zhy_handle_openat(ctx: TracePointContext) -> Result<u32, i64> {
    let mut event = match zhy_make_base_event(ZHY_EVENT_OPENAT) {
        Some(v) => v,
        None => return Ok(0),
    };

    let dirfd_raw: i64 = unsafe { ctx.read_at::<i64>(ZHY_ARG0_OFF)? };
    let pathname_raw: u64 = unsafe { ctx.read_at::<u64>(ZHY_ARG1_OFF)? };
    let flags_raw: i64 = unsafe { ctx.read_at::<i64>(ZHY_ARG2_OFF)? };
    let mode_raw: u64 = unsafe { ctx.read_at::<u64>(ZHY_ARG3_OFF)? };

    event.dirfd = dirfd_raw as i32;
    event.open_flags = flags_raw as i32;
    event.open_mode = mode_raw as u32;

    let pathname_ptr: *const u8 = pathname_raw as *const u8;
    zhy_copy_user_path(pathname_ptr, &mut event);

    let _ = ZHY_EVENTS.output(&event, 0);
    Ok(0)
}
// connect 探针
// sockaddr 来自用户态内存，必须通过 bpf_probe_read_user 读取
// 当前只解析 AF_INET
// dst_port_be 和 dst_ip_be 保持网络字节序，用户态负责转换
// sockaddr 长度不足时直接跳过本次事件
fn zhy_handle_connect(ctx: TracePointContext) -> Result<u32, i64> {
    let mut event = match zhy_make_base_event(ZHY_EVENT_CONNECT) {
        Some(v) => v,
        None => return Ok(0),
    };

    let sock_fd_raw: i64 = unsafe { ctx.read_at::<i64>(ZHY_ARG0_OFF)? };
    let sockaddr_raw: u64 = unsafe { ctx.read_at::<u64>(ZHY_ARG1_OFF)? };
    let addr_len_raw: u64 = unsafe { ctx.read_at::<u64>(ZHY_ARG2_OFF)? };

    event.sock_fd = sock_fd_raw as i32;

    let sockaddr_ptr: *const ZHY_SockAddrIn = sockaddr_raw as *const ZHY_SockAddrIn;
    let min_len: u64 = core::mem::size_of::<ZHY_SockAddrIn>() as u64;

    if sockaddr_ptr.is_null() || addr_len_raw < min_len {
        return Ok(0);
    }

    let sockaddr = match unsafe { bpf_probe_read_user(sockaddr_ptr) } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };

    event.sockaddr_family = sockaddr.sin_family;

    if sockaddr.sin_family != ZHY_AF_INET {
        return Ok(0);
    }

    event.dst_port_be = sockaddr.sin_port;
    event.dst_ip_be = sockaddr.sin_addr;

    let _ = ZHY_EVENTS.output(&event, 0);
    Ok(0)
}

#[inline(always)]
fn zhy_make_base_event(kind: u32) -> Option<ZHY_Event> {
    let current_comm = match bpf_get_current_comm() {
        Ok(v) => v,
        Err(_) => return None,
    };

    if !zhy_is_target_proc(&current_comm) {
        return None;
    }

    let pid_tgid: u64 = bpf_get_current_pid_tgid();
    // pid 是线程 id，tgid 是进程 id；聚合侧主要按 pid 区分事件来源
    let mut event = ZHY_Event::zhy_zeroed(kind);
    event.pid = pid_tgid as u32;
    event.tgid = (pid_tgid >> 32) as u32;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.comm = current_comm;

    Some(event)
}

#[inline(always)]
fn zhy_is_target_proc(comm: &[u8; ZHY_COMM_LEN]) -> bool {
    // 固定字节比较，避免在 eBPF 中分配字符串
    comm[0] == ZHY_TARGET_COMM[0]
        && comm[1] == ZHY_TARGET_COMM[1]
        && comm[2] == ZHY_TARGET_COMM[2]
        && comm[3] == ZHY_TARGET_COMM[3]
        && comm[4] == ZHY_TARGET_COMM[4]
}

#[inline(always)]
fn zhy_copy_user_path(ptr: *const u8, event: &mut ZHY_Event) {
    if ptr.is_null() {
        return;
    }

    // path 固定 256 字节；失败时只置空长度，不输出半截未知数据
    let copied = unsafe { bpf_probe_read_user_str_bytes(ptr, &mut event.path) };

    match copied {
        Ok(slice) => {
            event.path_len = slice.len() as u32;
        }
        Err(_) => {
            event.path_len = 0;
        }
    }
}


#[tracepoint]
pub fn zhy_tp_unlink(ctx: TracePointContext) -> u32 {
    match zhy_handle_unlink(ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint]
pub fn zhy_tp_unlinkat(ctx: TracePointContext) -> u32 {
    match zhy_handle_unlinkat(ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint]
pub fn zhy_tp_clone(ctx: TracePointContext) -> u32 {
    match zhy_clone_inner(ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}
// 进程 / 线程衍生事件
// clone3、fork、vfork 统一按 CLONE 事件上报
// 当前 collector 挂载 clone、clone3、vfork；fork 函数保留给环境支持时使用

#[tracepoint]
pub fn zhy_tp_clone3(ctx: TracePointContext) -> u32 {
    match zhy_fork_like_inner(ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint]
pub fn zhy_tp_fork(ctx: TracePointContext) -> u32 {
    match zhy_fork_like_inner(ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint]
pub fn zhy_tp_vfork(ctx: TracePointContext) -> u32 {
    match zhy_fork_like_inner(ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}
// 文件删除操作（unlink / unlinkat）
// unlinkat 额外携带 dirfd，用户态可结合相对路径解析
// unlink 没有 dirfd，统一按 UNLINKAT 事件类型输出
fn zhy_handle_unlink(ctx: TracePointContext) -> Result<u32, i64> {
    let mut event = match zhy_make_base_event(ZHY_EVENT_UNLINKAT) {
        Some(v) => v,
        None => return Ok(0),
    };

    let pathname_raw: u64 = unsafe { ctx.read_at::<u64>(ZHY_ARG0_OFF)? };
    zhy_copy_user_path(pathname_raw as *const u8, &mut event);

    let _ = ZHY_EVENTS.output(&event, 0);
    Ok(0)
}

fn zhy_handle_unlinkat(ctx: TracePointContext) -> Result<u32, i64> {
    let mut event = match zhy_make_base_event(ZHY_EVENT_UNLINKAT) {
        Some(v) => v,
        None => return Ok(0),
    };

    let dirfd_raw: i64 = unsafe { ctx.read_at::<i64>(ZHY_ARG0_OFF)? };
    let pathname_raw: u64 = unsafe { ctx.read_at::<u64>(ZHY_ARG1_OFF)? };
    let flags_raw: i64 = unsafe { ctx.read_at::<i64>(ZHY_ARG2_OFF)? };

    event.dirfd = dirfd_raw as i32;
    event.open_flags = flags_raw as i32;

    zhy_copy_user_path(pathname_raw as *const u8, &mut event);

    let _ = ZHY_EVENTS.output(&event, 0);
    Ok(0)
}


// 进程/线程创建（clone）
// 只传递 clone_flags，位解析放在用户态
// fork/vfork/clone3 没有统一参数布局时，只记录基础事件

fn zhy_clone_inner(ctx: TracePointContext) -> Result<u32, i64> {
    let mut event = match zhy_make_base_event(ZHY_EVENT_CLONE) {
        Some(v) => v,
        None => return Ok(0)
    };

    let clone_flags_raw: u64 = unsafe { ctx.read_at::<u64>(ZHY_ARG0_OFF)? };
    event.open_mode = clone_flags_raw as u32;

    let _ = ZHY_EVENTS.output(&event, 0);
    Ok(0)
}

fn zhy_fork_like_inner(_ctx: TracePointContext) -> Result<u32, i64> {
    let event = match zhy_make_base_event(ZHY_EVENT_CLONE) {
        Some(v) => v,
        None => return Ok(0),
    };

    let _ = ZHY_EVENTS.output(&event, 0);
    Ok(0)
}
// SSL/TLS uprobe
// SSL_write 入口可以直接读取发送前明文
// SSL_read 需要 entry 保存 buf，return 再按返回长度读取
// SSL 负载复用 event.path；collector 会改写到 ssl_data 字段

#[uprobe]
pub fn zhy_uprobe_ssl_write(ctx: ProbeContext) -> u32 {
    match zhy_ssl_write_inner(ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn zhy_ssl_write_inner(ctx: ProbeContext) -> Result<u32, i64> {
    let mut event = match zhy_make_base_event(ZHY_EVENT_SSL_DATA) {
        Some(v) => v,
        None => return Ok(0),
    };

    // SSL_write(ssl, buf, num) 使用第 1、2 个参数
    let buf_ptr: *const u8 = ctx.arg(1).unwrap_or(core::ptr::null());
    let len: i32 = ctx.arg(2).unwrap_or(0);

    if buf_ptr.is_null() || len <= 0 {
        return Ok(0);
    }

    // 只读取一次 payload，避免重复拷贝同一段用户态内存
    zhy_safe_read_ssl(buf_ptr, len, &mut event);
    event.open_flags = ZHY_SSL_DIR_WRITE;

    let _ = ZHY_EVENTS.output(&event, 0);
    Ok(0)
}

/// SSL_read 入口：保存用户态缓冲区地址
#[uprobe]
pub fn zhy_uprobe_ssl_read(ctx: ProbeContext) -> u32 {
    match zhy_ssl_read_entry_inner(ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn zhy_ssl_read_entry_inner(ctx: ProbeContext) -> Result<u32, i64> {
    let comm = match bpf_get_current_comm() {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };
    if !zhy_is_target_proc(&comm) {
        return Ok(0);
    }

    // SSL_read(ssl, buf, num) 的 buf 在返回后才包含明文
    let buf: Option<u64> = ctx.arg(1);
    let buf_val = match buf {
        Some(v) if v != 0 => v,
        _ => return Ok(0),
    };

    let pid_tgid: u64 = bpf_get_current_pid_tgid();
    let tgid: u32 = (pid_tgid >> 32) as u32;

    if let Some(entry) = ZHY_SSL_READ_BUF.get_ptr_mut(0) {
        unsafe {
            (*entry).buf = buf_val;
            (*entry).tgid = tgid;
        }
    }

    Ok(0)
}

/// SSL_read 返回：读取缓冲区并拷贝返回数据
#[uretprobe]
pub fn zhy_uretprobe_ssl_read(ctx: RetProbeContext) -> u32 {
    match zhy_ssl_read_ret_inner(ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn zhy_ssl_read_ret_inner(ctx: RetProbeContext) -> Result<u32, i64> {
    let mut event = match zhy_make_base_event(ZHY_EVENT_SSL_DATA) {
        Some(v) => v,
        None => return Ok(0),
    };

    let entry = match ZHY_SSL_READ_BUF.get_ptr_mut(0) {
        Some(v) => unsafe { &*v },
        None => return Ok(0),
    };

    let buf_val = entry.buf;
    if buf_val == 0 {
        return Ok(0);
    }

    // 清零，避免下一次 SSL_read 返回时读到旧 buf 地址
    unsafe {
        (*ZHY_SSL_READ_BUF.get_ptr_mut(0).unwrap()).buf = 0;
    }

    let buf_ptr = buf_val as *const u8;

    // ret 是 SSL_read 实际写入 buf 的字节数
    let ret: Option<i32> = ctx.ret();
    let len = match ret {
        Some(n) if n > 0 => n,
        _ => return Ok(0),
    };

    zhy_safe_read_ssl(buf_ptr, len, &mut event);
    event.open_flags = ZHY_SSL_DIR_READ;

    let _ = ZHY_EVENTS.output(&event, 0);
    Ok(0)
}
/// 从用户态缓冲区拷贝 SSL 明文负载到 event.path
/// 最多拷贝 ZHY_SSL_MAX_COPY 字节
/// collector 会把这类 path 解释为 ssl_data
#[inline(always)]
fn zhy_safe_read_ssl(buf: *const u8, len: i32, event: &mut ZHY_Event) {
    let copy_len = (len as usize).min(ZHY_SSL_MAX_COPY);
    // 文本优先走字符串拷贝，失败后按字节回退
    let copied = unsafe { bpf_probe_read_user_str_bytes(buf, &mut event.path[..copy_len]) };
    match copied {
        Ok(slice) => {
            event.path_len = slice.len() as u32;
        }
        Err(_) => {
            let dst = &mut event.path[..copy_len];
            for i in 0..copy_len {
                let byte: Result<u8, _> = unsafe { bpf_probe_read_user(buf.add(i)) };
                match byte {
                    Ok(b) if b != 0 => dst[i] = b,
                    _ => {
                        event.path_len = i as u32;
                        return;
                    }
                }
            }
            event.path_len = copy_len as u32;
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
