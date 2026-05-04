use std::collections::HashSet;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Public/backend Linux interface where the TC ingress classifier is attached.
    pub host_interface: String,
    /// Compiled eBPF object loaded by the userspace controller.
    #[serde(default = "default_bpf_object_path")]
    pub bpf_object_path: PathBuf,
    #[serde(default = "default_state_path")]
    pub state_path: PathBuf,
    #[serde(default)]
    pub log_path: Option<PathBuf>,
    #[serde(default = "default_poll_interval_secs")]
    pub poll_interval_secs: u64,
    pub rules: Vec<RuleConfig>,
}

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
    #[serde(default)]
    pub quota_in: Option<Quota>,
    #[serde(default)]
    pub quota_out: Option<Quota>,
    #[serde(default)]
    pub max_tcp_connections: u32,
    #[serde(default)]
    pub max_udp_flows: u32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }

    pub fn number(self) -> u8 {
        match self {
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
        }
    }
}

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
        let multiplier = match suffix.trim().to_ascii_uppercase().as_str() {
            "" | "B" => 1,
            "KB" => 1024,
            "MB" => 1024_u64.pow(2),
            "GB" => 1024_u64.pow(3),
            "TB" => 1024_u64.pow(4),
            other => bail!("unsupported quota suffix `{other}`"),
        };

        amount
            .checked_mul(multiplier)
            .map(Quota)
            .ok_or_else(|| anyhow::anyhow!("quota overflow"))
    }
}

impl Config {
    /// Load, normalize, and validate the v2 config.
    ///
    /// The schema intentionally remains close to the v1 nftables backend, but the
    /// v2 MVP requires literal IPv4 backend targets so eBPF map values are simple.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let mut config: Self = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse config {}", path.display()))?;
        config.normalize_targets()?;
        config.validate()?;
        Ok(config)
    }

    pub fn requires_monitoring(&self) -> bool {
        // BPF counters live in kernel maps and should be sampled into persisted
        // state regularly, so automatic mode chooses `run` for v2.
        true
    }

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
            rule.target_ipv4().with_context(|| {
                format!(
                    "rule {} target_host must be an IPv4 address in v2 MVP",
                    rule.name
                )
            })?;
            for protocol in &rule.protocols {
                if !seen.insert((rule.listen_port, *protocol)) {
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
}

impl RuleConfig {
    pub fn has_deferred_limits(&self) -> bool {
        self.quota_in.is_some()
            || self.quota_out.is_some()
            || self.max_tcp_connections > 0
            || self.max_udp_flows > 0
    }

    pub fn target_ipv4(&self) -> Result<Ipv4Addr> {
        self.target_host
            .parse()
            .with_context(|| format!("invalid IPv4 target `{}`", self.target_host))
    }
}

fn parse_target(value: &str) -> Result<(String, u16)> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("target must be HOST:PORT"))?;
    if host.trim().is_empty() {
        bail!("target host cannot be empty");
    }
    let port = port.parse().context("invalid target port")?;
    Ok((host.to_string(), port))
}

fn default_bpf_object_path() -> PathBuf {
    PathBuf::from("/usr/lib/xelay/xelay-tc-ebpf.o")
}

fn default_state_path() -> PathBuf {
    PathBuf::from("/var/lib/xelay/tc-ebpf-state.json")
}

fn default_poll_interval_secs() -> u64 {
    2
}

fn default_enabled() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v1_compatible_config_with_bpf_defaults() {
        let raw = r#"{
          "host_interface": "eth0",
          "rules": [{
            "name": "svc",
            "listen_port": 5000,
            "protocols": ["tcp", "udp"],
            "target_host": "114.111.191.26",
            "target_port": 2616,
            "quota_in": "1GB"
          }]
        }"#;

        let mut config: Config = serde_json::from_str(raw).unwrap();
        config.normalize_targets().unwrap();
        config.validate().unwrap();

        assert_eq!(
            config.bpf_object_path,
            PathBuf::from("/usr/lib/xelay/xelay-tc-ebpf.o")
        );
        assert!(config.rules[0].has_deferred_limits());
    }

    #[test]
    fn rejects_non_ipv4_targets_for_mvp() {
        let raw = r#"{
          "host_interface": "eth0",
          "rules": [{
            "name": "svc",
            "listen_port": 5000,
            "protocols": ["tcp"],
            "target_host": "example.com",
            "target_port": 80
          }]
        }"#;

        let mut config: Config = serde_json::from_str(raw).unwrap();
        config.normalize_targets().unwrap();
        assert!(config.validate().is_err());
    }
}
