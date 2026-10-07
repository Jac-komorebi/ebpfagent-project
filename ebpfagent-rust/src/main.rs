use std::{
    borrow::BorrowMut,
    collections::HashMap,
    convert::TryInto,
    hash::{Hash, Hasher},
    mem::{size_of, MaybeUninit},
    net::Ipv4Addr,
    os::fd::AsRawFd,
    ptr,
    sync::Arc,
};

use anyhow::{anyhow, Context, Result};
use aya::{
    maps::{MapData, RingBuf},
    programs::TracePoint,
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

const ZHY_COMM_LEN: usize = 16;
const ZHY_PATH_LEN: usize = 256;

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
}

type ZHY_AggMap = HashMap<ZHY_AggKey, AggregatedEvent>;

#[tokio::main]
async fn main() -> Result<()> {
    let default_obj_path = String::from("target/bpfel-unknown-none/release/zhy-ebpf");
    let ebpf_path = std::env::args().nth(1).unwrap_or(default_obj_path);

    let mut bpf = Ebpf::load_file(&ebpf_path)
        .with_context(|| format!("failed to load eBPF object: {ebpf_path}"))?;

    zhy_bind_tp(&mut bpf, "zhy_tp_execve", "syscalls", "sys_enter_execve")?;
    zhy_bind_tp(&mut bpf, "zhy_tp_openat", "syscalls", "sys_enter_openat")?;
    zhy_bind_tp(&mut bpf, "zhy_tp_connect", "syscalls", "sys_enter_connect")?;

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

async fn zhy_collect_events<T>(
    async_ring: &mut AsyncFd<RingBuf<T>>,
    zhy_global_ring: &Arc<Mutex<ZHY_AggMap>>,
) -> Result<()>
where
    T: BorrowMut<MapData>,
    RingBuf<T>: AsRawFd,
{
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

fn zhy_merge_event(map: &mut ZHY_AggMap, event: ZHY_Event) {
    let comm_text = zhy_buffer_to_string(&event.comm);

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

    if event.event_type == ZHY_EVENT_OPENAT {
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
    }

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
        }
        None => {
            let new_item = AggregatedEvent {
                pid: event.pid,
                comm: comm_text,
                event_type: event.event_type,
                count: 1,
                first_time_ns: event.timestamp_ns,
                last_time_ns: event.timestamp_ns,
                path: path_text,
                dst_ip,
                dst_port,
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

    unsafe {
        let src_ptr = raw.as_ptr();
        let dst_ptr = holder.as_mut_ptr() as *mut u8;

        ptr::copy_nonoverlapping(src_ptr, dst_ptr, need_size);

        Some(holder.assume_init())
    }
}

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
