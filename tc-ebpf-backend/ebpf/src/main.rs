#![no_std]
#![no_main]

use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::{classifier, map};
use aya_ebpf::maps::{HashMap, LruHashMap};
use aya_ebpf::programs::TcContext;

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const DIRECTION_IN: u8 = 0;
const DIRECTION_OUT: u8 = 1;
const BPF_F_PSEUDO_HDR: u64 = 1 << 4;

// The structs below mirror `src/model.rs` in userspace. They are intentionally
// `repr(C)` because BPF maps are a binary ABI shared across two crates.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuleKey {
    pub protocol: u8,
    pub listen_port: u16,
    pub _pad: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuleValue {
    pub rule_id: u32,
    pub enabled: u8,
    pub _pad: [u8; 3],
    pub target_ip_be: u32,
    pub target_port: u16,
    pub listen_port: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CounterKey {
    pub rule_id: u32,
    pub protocol: u8,
    pub direction: u8,
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CounterValue {
    pub packets: u64,
    pub bytes: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SettingsKey {
    pub key: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SettingsValue {
    pub host_ip_be: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowKey {
    pub client_ip_be: u32,
    pub backend_ip_be: u32,
    pub client_port: u16,
    pub backend_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReverseFlowKey {
    pub backend_ip_be: u32,
    pub backend_port: u16,
    pub nat_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowValue {
    pub rule_id: u32,
    pub listen_port: u16,
    pub client_port: u16,
    pub public_ip_be: u32,
    pub client_ip_be: u32,
    pub last_seen_ns: u64,
}

// Listener table: (protocol, listen_port) -> backend rewrite target.
#[map]
static RULES: HashMap<RuleKey, RuleValue> = HashMap::with_max_entries(4096, 0);

// Per-rule counters read by the userspace status/reconcile path.
#[map]
static COUNTERS: HashMap<CounterKey, CounterValue> = HashMap::with_max_entries(8192, 0);

// Small runtime settings map. SETTINGS[0] stores the host interface IPv4 address.
#[map]
static SETTINGS: HashMap<SettingsKey, SettingsValue> = HashMap::with_max_entries(8, 0);

// Forward and reverse flow maps are separated so reply packets can be looked up
// without reconstructing the full original client tuple from packet data.
#[map]
static FLOWS: LruHashMap<FlowKey, FlowValue> = LruHashMap::with_max_entries(262144, 0);

#[map]
static REVERSE_FLOWS: LruHashMap<ReverseFlowKey, FlowValue> =
    LruHashMap::with_max_entries(262144, 0);

#[classifier]
pub fn xelay_tc_ingress(ctx: TcContext) -> i32 {
    match try_xelay_tc_ingress(ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_xelay_tc_ingress(mut ctx: TcContext) -> Result<i32, ()> {
    // Parse only the minimum Ethernet/IPv4/L4 fields needed for the MVP. All
    // reads go through `ctx.load` so the verifier sees bounds-checked accesses.
    let eth_proto = u16::from_be(load_u16(&ctx, 12)?);
    if eth_proto != ETH_P_IP {
        return Ok(TC_ACT_OK);
    }

    let ip_offset = 14usize;
    let version_ihl = load_u8(&ctx, ip_offset)?;
    if version_ihl >> 4 != 4 {
        return Ok(TC_ACT_OK);
    }
    let ihl = ((version_ihl & 0x0f) as usize) * 4;
    if ihl < 20 {
        return Ok(TC_ACT_OK);
    }

    let protocol = load_u8(&ctx, ip_offset + 9)?;
    if protocol != IPPROTO_TCP && protocol != IPPROTO_UDP {
        return Ok(TC_ACT_OK);
    }

    let total_len = u16::from_be(load_u16(&ctx, ip_offset + 2)?) as u64;
    let src_ip = load_u32(&ctx, ip_offset + 12)?;
    let dst_ip = load_u32(&ctx, ip_offset + 16)?;
    let l4_offset = ip_offset + ihl;
    let src_port = u16::from_be(load_u16(&ctx, l4_offset)?);
    let dst_port = u16::from_be(load_u16(&ctx, l4_offset + 2)?);

    let key = RuleKey {
        protocol,
        listen_port: dst_port,
        _pad: 0,
    };
    if let Some(rule) = unsafe { RULES.get(&key) } {
        if rule.enabled != 0 {
            // Forward path: public listener -> backend. Store enough state for the
            // reply path before rewriting packet headers.
            bump_counter(rule.rule_id, protocol, DIRECTION_IN, total_len);
            let flow = FlowKey {
                client_ip_be: src_ip,
                backend_ip_be: rule.target_ip_be,
                client_port: src_port,
                backend_port: rule.target_port,
                protocol,
                _pad: [0; 3],
            };
            let value = FlowValue {
                rule_id: rule.rule_id,
                listen_port: rule.listen_port,
                client_port: src_port,
                public_ip_be: dst_ip,
                client_ip_be: src_ip,
                last_seen_ns: unsafe { bpf_ktime_get_ns() },
            };
            let _ = unsafe { FLOWS.insert(&flow, &value, 0) };
            let reverse = ReverseFlowKey {
                backend_ip_be: rule.target_ip_be,
                backend_port: rule.target_port,
                nat_port: src_port,
                protocol,
                _pad: [0; 3],
            };
            let _ = unsafe { REVERSE_FLOWS.insert(&reverse, &value, 0) };
            let host_ip = host_ip_be().ok_or(())?;
            rewrite_forward(
                &mut ctx,
                protocol,
                ip_offset,
                l4_offset,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                host_ip,
                rule.target_ip_be,
                rule.target_port,
            )?;
            // After rewriting, let the kernel continue normal routing with the new
            // destination. A later milestone can replace this with explicit FIB or
            // redirect logic if deployments need tighter control.
            return Ok(TC_ACT_OK);
        }
    }

    // Reverse path: backend reply -> original client. The MVP uses the original
    // client source port as the host-side NAT port, so this key is compact but can
    // collide for identical client ports talking to the same backend.
    let reverse = ReverseFlowKey {
        backend_ip_be: src_ip,
        backend_port: src_port,
        nat_port: dst_port,
        protocol,
        _pad: [0; 3],
    };
    if let Some(flow) = unsafe { REVERSE_FLOWS.get(&reverse) } {
        bump_counter(flow.rule_id, protocol, DIRECTION_OUT, total_len);
        rewrite_reverse(
            &mut ctx,
            protocol,
            ip_offset,
            l4_offset,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            flow.public_ip_be,
            flow.client_ip_be,
            flow.client_port,
            flow.listen_port,
        )?;
    }

    Ok(TC_ACT_OK)
}

fn host_ip_be() -> Option<u32> {
    let key = SettingsKey { key: 0 };
    unsafe { SETTINGS.get(&key).map(|value| value.host_ip_be) }
}

#[allow(clippy::too_many_arguments)]
fn rewrite_forward(
    ctx: &mut TcContext,
    protocol: u8,
    ip_offset: usize,
    l4_offset: usize,
    old_src_ip: u32,
    old_dst_ip: u32,
    old_src_port: u16,
    old_dst_port: u16,
    new_src_ip: u32,
    new_dst_ip: u32,
    new_dst_port: u16,
) -> Result<(), ()> {
    // Client-to-backend rewrite:
    //   src client_ip -> host_interface_ip
    //   dst public_listener_ip:listen_port -> backend_ip:target_port
    rewrite_ipv4(ctx, ip_offset, old_src_ip, new_src_ip, true)?;
    rewrite_ipv4(ctx, ip_offset, old_dst_ip, new_dst_ip, false)?;
    if new_dst_port != old_dst_port {
        rewrite_port(ctx, protocol, l4_offset, old_dst_port, new_dst_port, false)?;
    }
    rewrite_l4_addr(ctx, protocol, ip_offset, old_src_ip, new_src_ip)?;
    rewrite_l4_addr(ctx, protocol, ip_offset, old_dst_ip, new_dst_ip)?;
    if new_dst_port != old_dst_port {
        rewrite_l4_port(ctx, protocol, ip_offset, old_dst_port, new_dst_port)?;
    }
    if old_src_port == 0 {
        return Err(());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn rewrite_reverse(
    ctx: &mut TcContext,
    protocol: u8,
    ip_offset: usize,
    l4_offset: usize,
    old_src_ip: u32,
    old_dst_ip: u32,
    old_src_port: u16,
    old_dst_port: u16,
    public_ip: u32,
    client_ip: u32,
    client_port: u16,
    listen_port: u16,
) -> Result<(), ()> {
    // Backend-to-client rewrite:
    //   src backend_ip:target_port -> public_listener_ip:listen_port
    //   dst host_interface_ip:nat_port -> original_client_ip:client_port
    rewrite_ipv4(ctx, ip_offset, old_src_ip, public_ip, true)?;
    rewrite_ipv4(ctx, ip_offset, old_dst_ip, client_ip, false)?;
    if listen_port != old_src_port {
        rewrite_port(ctx, protocol, l4_offset, old_src_port, listen_port, true)?;
    }
    if client_port != old_dst_port {
        rewrite_port(ctx, protocol, l4_offset, old_dst_port, client_port, false)?;
    }
    rewrite_l4_addr(ctx, protocol, ip_offset, old_src_ip, public_ip)?;
    rewrite_l4_addr(ctx, protocol, ip_offset, old_dst_ip, client_ip)?;
    if listen_port != old_src_port {
        rewrite_l4_port(ctx, protocol, ip_offset, old_src_port, listen_port)?;
    }
    if client_port != old_dst_port {
        rewrite_l4_port(ctx, protocol, ip_offset, old_dst_port, client_port)?;
    }
    Ok(())
}

fn rewrite_ipv4(
    ctx: &mut TcContext,
    ip_offset: usize,
    old_ip: u32,
    new_ip: u32,
    source: bool,
) -> Result<(), ()> {
    let field_offset = if source {
        ip_offset + 12
    } else {
        ip_offset + 16
    };
    // Update the IPv4 header checksum before storing the changed address.
    ctx.l3_csum_replace(ip_offset + 10, old_ip as u64, new_ip as u64, 4)
        .map_err(|_| ())?;
    ctx.store(field_offset, &new_ip, 0).map_err(|_| ())
}

fn rewrite_port(
    ctx: &mut TcContext,
    _protocol: u8,
    l4_offset: usize,
    old_port: u16,
    new_port: u16,
    source: bool,
) -> Result<(), ()> {
    let field_offset = if source { l4_offset } else { l4_offset + 2 };
    let new_port_be = new_port.to_be();
    let _ = old_port;
    ctx.store(field_offset, &new_port_be, 0).map_err(|_| ())
}

fn rewrite_l4_addr(
    ctx: &TcContext,
    protocol: u8,
    ip_offset: usize,
    old_ip: u32,
    new_ip: u32,
) -> Result<(), ()> {
    let csum_offset = l4_checksum_offset(protocol, ip_offset)?;
    // IP address changes affect the TCP/UDP pseudo-header checksum.
    ctx.l4_csum_replace(
        csum_offset,
        old_ip as u64,
        new_ip as u64,
        4 | BPF_F_PSEUDO_HDR,
    )
    .map_err(|_| ())
}

fn rewrite_l4_port(
    ctx: &TcContext,
    protocol: u8,
    ip_offset: usize,
    old_port: u16,
    new_port: u16,
) -> Result<(), ()> {
    let csum_offset = l4_checksum_offset(protocol, ip_offset)?;
    // Port changes affect the normal TCP/UDP checksum field.
    ctx.l4_csum_replace(csum_offset, old_port as u64, new_port as u64, 2)
        .map_err(|_| ())
}

fn l4_checksum_offset(protocol: u8, ip_offset: usize) -> Result<usize, ()> {
    let ihl = 20usize;
    match protocol {
        IPPROTO_TCP => Ok(ip_offset + ihl + 16),
        IPPROTO_UDP => Ok(ip_offset + ihl + 6),
        _ => Err(()),
    }
}

fn bump_counter(rule_id: u32, protocol: u8, direction: u8, bytes: u64) {
    let key = CounterKey {
        rule_id,
        protocol,
        direction,
        _pad: [0; 2],
    };
    let value = unsafe { COUNTERS.get(&key).copied() }.unwrap_or(CounterValue {
        packets: 0,
        bytes: 0,
    });
    let next = CounterValue {
        packets: value.packets.saturating_add(1),
        bytes: value.bytes.saturating_add(bytes),
    };
    let _ = unsafe { COUNTERS.insert(&key, &next, 0) };
}

fn load_u8(ctx: &TcContext, offset: usize) -> Result<u8, ()> {
    unsafe { ctx.load(offset).map_err(|_| ()) }
}

fn load_u16(ctx: &TcContext, offset: usize) -> Result<u16, ()> {
    unsafe { ctx.load(offset).map_err(|_| ()) }
}

fn load_u32(ctx: &TcContext, offset: usize) -> Result<u32, ()> {
    unsafe { ctx.load(offset).map_err(|_| ()) }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
