use std::net::Ipv4Addr;

use crate::config::Protocol;

pub const PROGRAM_NAME: &str = "xelay_tc_ingress";
pub const RULES_MAP: &str = "RULES";
pub const COUNTERS_MAP: &str = "COUNTERS";
pub const SETTINGS_MAP: &str = "SETTINGS";

pub const DIRECTION_IN: u8 = 0;
pub const DIRECTION_OUT: u8 = 1;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RuleKey {
    pub protocol: u8,
    pub listen_port: u16,
    pub _pad: u8,
}

impl RuleKey {
    pub fn new(protocol: Protocol, listen_port: u16) -> Self {
        Self {
            protocol: protocol.number(),
            listen_port,
            _pad: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RuleValue {
    pub rule_id: u32,
    pub enabled: u8,
    pub _pad: [u8; 3],
    pub target_ip_be: u32,
    pub target_port: u16,
    pub listen_port: u16,
}

impl RuleValue {
    pub fn new(
        rule_id: u32,
        enabled: bool,
        target_ip: Ipv4Addr,
        target_port: u16,
        listen_port: u16,
    ) -> Self {
        Self {
            rule_id,
            enabled: u8::from(enabled),
            _pad: [0; 3],
            target_ip_be: u32::from_be_bytes(target_ip.octets()),
            target_port,
            listen_port,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CounterKey {
    pub rule_id: u32,
    pub protocol: u8,
    pub direction: u8,
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct CounterValue {
    pub packets: u64,
    pub bytes: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SettingsKey {
    pub key: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SettingsValue {
    pub host_ip_be: u32,
}

pub const SETTINGS_HOST_IPV4: SettingsKey = SettingsKey { key: 0 };

// SAFETY: These types are plain old data shared with eBPF maps.
unsafe impl aya::Pod for RuleKey {}
unsafe impl aya::Pod for RuleValue {}
unsafe impl aya::Pod for CounterKey {}
unsafe impl aya::Pod for CounterValue {}
unsafe impl aya::Pod for SettingsKey {}
unsafe impl aya::Pod for SettingsValue {}
