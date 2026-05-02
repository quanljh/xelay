use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Deserializer};

/// Runtime configuration loaded from JSON and normalized before use.
///
/// This is the user-facing schema for namespace setup, state storage, polling, and
/// all configured forwarding rules.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_namespace")]
    pub namespace: String,
    pub host_interface: String,
    #[serde(default = "default_host_veth_ip")]
    pub host_veth_ip: String,
    #[serde(default = "default_ns_veth_ip")]
    pub ns_veth_ip: String,
    #[serde(default = "default_state_path")]
    pub state_path: PathBuf,
    #[serde(default = "default_poll_interval_secs")]
    pub poll_interval_secs: u64,
    pub rules: Vec<RuleConfig>,
}

/// One TCP/UDP forwarding rule from a public listen port to a backend target.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    pub name: String,
    pub listen_port: u16,
    pub protocols: Vec<Protocol>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub target_host: String,
    #[serde(default)]
    pub target_port: u16,
    pub quota_in: Quota,
    pub quota_out: Quota,
    #[serde(default)]
    pub max_tcp_connections: u32,
    #[serde(default)]
    pub max_udp_flows: u32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

/// Transport protocols supported by the forwarding dataplane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    /// Returns the lowercase nftables/conntrack spelling for this protocol.
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

/// Traffic quota stored internally as bytes.
///
/// JSON may provide either a raw number of bytes or a string like `500GB`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota(pub u64);

impl<'de> Deserialize<'de> for Quota {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum RawQuota {
            Number(u64),
            Text(String),
        }

        match RawQuota::deserialize(deserializer)? {
            RawQuota::Number(value) => Ok(Quota(value)),
            RawQuota::Text(value) => Quota::from_str(&value).map_err(serde::de::Error::custom),
        }
    }
}

impl FromStr for Quota {
    type Err = anyhow::Error;

    /// Parses human-readable quota strings using binary units.
    ///
    /// V1 accepts whole-number values such as `1MB`, `10GB`, `2TB`, `42B`, or raw
    /// bytes like `42`.
    fn from_str(value: &str) -> Result<Self> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            bail!("quota cannot be empty");
        }

        let split_at = trimmed
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(trimmed.len());
        let (digits, suffix) = trimmed.split_at(split_at);

        if digits.is_empty() {
            bail!("quota must start with digits");
        }

        let amount: u64 = digits.parse().context("invalid quota number")?;
        let unit = suffix.trim().to_ascii_uppercase();

        let multiplier = match unit.as_str() {
            "" | "B" => 1,
            "KB" => 1024,
            "MB" => 1024_u64.pow(2),
            "GB" => 1024_u64.pow(3),
            "TB" => 1024_u64.pow(4),
            _ => bail!("unsupported quota suffix `{unit}`"),
        };

        amount
            .checked_mul(multiplier)
            .map(Quota)
            .ok_or_else(|| anyhow::anyhow!("quota overflow"))
    }
}

impl Config {
    /// Loads JSON config from disk, then normalizes and validates it.
    ///
    /// This is the main entrypoint used by the CLI before privileged setup starts.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let mut config: Config = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse config {}", path.display()))?;

        config.normalize_targets()?;
        config.validate()?;
        Ok(config)
    }

    /// Converts legacy `target: "HOST:PORT"` fields into canonical host/port fields.
    fn normalize_targets(&mut self) -> Result<()> {
        for rule in &mut self.rules {
            if let Some(target) = &rule.target {
                if rule.target_host.is_empty() && rule.target_port == 0 {
                    let (host, port) = parse_target(target)?;
                    rule.target_host = host;
                    rule.target_port = port;
                }
            }

            if rule.target_host.trim().is_empty() || rule.target_port == 0 {
                bail!("rule {} target cannot be empty", rule.name);
            }
        }
        Ok(())
    }

    /// Validates cross-field constraints that serde cannot express.
    ///
    /// This prevents ambiguous dataplane rules such as duplicate listen port/protocol
    /// combinations before nftables rules are generated.
    fn validate(&self) -> Result<()> {
        if self.host_interface.trim().is_empty() {
            bail!("host_interface cannot be empty");
        }
        if self.rules.is_empty() {
            bail!("config must contain at least one rule");
        }

        let mut seen = HashSet::new();
        for rule in &self.rules {
            if rule.name.trim().is_empty() {
                bail!("rule name cannot be empty");
            }
            if rule.protocols.is_empty() {
                bail!("rule {} must declare at least one protocol", rule.name);
            }
            for protocol in &rule.protocols {
                let key = (rule.listen_port, *protocol);
                if !seen.insert(key) {
                    bail!(
                        "duplicate listener for port {} protocol {}",
                        rule.listen_port,
                        protocol.as_str()
                    );
                }
            }
        }

        Ok(())
    }

    /// Returns the deterministic host-side veth interface name.
    pub fn host_veth_name(&self) -> String {
        derive_veth_name(&self.namespace, "host")
    }

    /// Returns the deterministic namespace-side veth interface name.
    pub fn ns_veth_name(&self) -> String {
        derive_veth_name(&self.namespace, "ns")
    }

    /// Returns the host-side veth IP without the CIDR prefix length.
    ///
    /// The namespace uses this address as its default gateway.
    pub fn ns_host_ip(&self) -> &str {
        self.host_veth_ip
            .split('/')
            .next()
            .unwrap_or(self.host_veth_ip.as_str())
    }

    /// Returns the namespace-side veth IP without the CIDR prefix length.
    pub fn ns_ip(&self) -> &str {
        self.ns_veth_ip
            .split('/')
            .next()
            .unwrap_or(self.ns_veth_ip.as_str())
    }
}

/// Builds a Linux interface name within the 15-byte limit.
///
/// Non-alphanumeric namespace characters are removed so generated veth names are safe
/// for `ip link` commands.
fn derive_veth_name(namespace: &str, suffix: &str) -> String {
    let mut base = namespace
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>();
    if base.is_empty() {
        base = "fwd".to_string();
    }
    let max_base = 15usize.saturating_sub(suffix.len() + 1);
    base.truncate(max_base);
    format!("{base}-{suffix}")
}

/// Default network namespace that owns the forwarding dataplane.
fn default_namespace() -> String {
    "fwd".to_string()
}

/// Default host-side veth address for the point-to-point namespace link.
fn default_host_veth_ip() -> String {
    "10.200.0.1/30".to_string()
}

/// Default namespace-side veth address for the point-to-point namespace link.
fn default_ns_veth_ip() -> String {
    "10.200.0.2/30".to_string()
}

/// Default path for persisted quota counters and runtime rule state.
fn default_state_path() -> PathBuf {
    PathBuf::from("/var/lib/xelay/state.json")
}

/// Default controller polling interval for counter and conntrack reconciliation.
fn default_poll_interval_secs() -> u64 {
    2
}

/// Rules are enabled unless explicitly disabled in config.
fn default_enabled() -> bool {
    true
}

/// Parses a `HOST:PORT` target string into canonical components.
fn parse_target(value: &str) -> Result<(String, u16)> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("target must be in HOST:PORT format"))?;
    if host.trim().is_empty() {
        bail!("target host cannot be empty");
    }
    let port = port.parse::<u16>().context("invalid target port")?;
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_rule_json() -> String {
        r#"{
            "namespace": "fwd",
            "host_interface": "eth0",
            "rules": [{
                "name": "svc-5000",
                "listen_port": 5000,
                "protocols": ["tcp", "udp"],
                "target_host": "114.111.191.26",
                "target_port": 2616,
                "quota_in": "500GB",
                "quota_out": "500GB",
                "enabled": true
            }]
        }"#
        .to_string()
    }

    #[test]
    fn quota_parses_human_units() {
        assert_eq!(Quota::from_str("500GB").unwrap().0, 500 * 1024_u64.pow(3));
        assert_eq!(Quota::from_str("1024MB").unwrap().0, 1024 * 1024_u64.pow(2));
        assert_eq!(Quota::from_str("42").unwrap().0, 42);
        assert_eq!(Quota::from_str("1tb").unwrap().0, 1024_u64.pow(4));
    }

    #[test]
    fn quota_rejects_invalid_values() {
        assert!(Quota::from_str("").is_err());
        assert!(Quota::from_str("GB").is_err());
        assert!(Quota::from_str("1PB").is_err());
        assert!(Quota::from_str("18446744073709551615TB").is_err());
    }

    #[test]
    fn parse_target_splits_host_and_port() {
        let (host, port) = parse_target("10.0.0.1:8080").unwrap();
        assert_eq!(host, "10.0.0.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn parse_target_rejects_invalid_port() {
        assert!(parse_target("10.0.0.1").is_err());
        assert!(parse_target("10.0.0.1:notaport").is_err());
    }

    #[test]
    fn config_deserializes_target_string() {
        let raw = r#"{
            "namespace": "fwd",
            "host_interface": "eth0",
            "rules": [{
                "name": "svc-5000",
                "listen_port": 5000,
                "protocols": ["tcp"],
                "target": "114.111.191.26:2616",
                "quota_in": "1GB",
                "quota_out": "1GB",
                "enabled": true
            }]
        }"#;

        let mut config: Config = serde_json::from_str(raw).unwrap();
        config.normalize_targets().unwrap();
        config.validate().unwrap();
        let rule = &config.rules[0];
        assert_eq!(rule.target_host, "114.111.191.26");
        assert_eq!(rule.target_port, 2616);
    }

    #[test]
    fn config_validation_rejects_duplicate_port_protocol() {
        let raw = r#"{
            "namespace": "fwd",
            "host_interface": "eth0",
            "rules": [
                {
                    "name": "svc-5000-a",
                    "listen_port": 5000,
                    "protocols": ["tcp"],
                    "target_host": "114.111.191.26",
                    "target_port": 2616,
                    "quota_in": "1GB",
                    "quota_out": "1GB",
                    "enabled": true
                },
                {
                    "name": "svc-5000-b",
                    "listen_port": 5000,
                    "protocols": ["tcp"],
                    "target_host": "114.111.191.27",
                    "target_port": 2617,
                    "quota_in": "1GB",
                    "quota_out": "1GB",
                    "enabled": true
                }
            ]
        }"#;

        let mut config: Config = serde_json::from_str(raw).unwrap();
        config.normalize_targets().unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn derived_names_and_ips_use_defaults() {
        let config: Config = serde_json::from_str(&base_rule_json()).unwrap();
        assert_eq!(config.host_veth_name(), "fwd-host");
        assert_eq!(config.ns_veth_name(), "fwd-ns");
        assert_eq!(config.ns_host_ip(), "10.200.0.1");
        assert_eq!(config.ns_ip(), "10.200.0.2");
    }
}
