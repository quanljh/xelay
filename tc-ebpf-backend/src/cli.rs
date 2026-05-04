use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

use crate::reconcile::{CheckReport, RuleStatus, StatusReport};

#[derive(Debug, Parser)]
#[command(name = "xelay-tc-ebpf")]
#[command(about = "TC eBPF Linux port forwarding controller")]
pub struct Cli {
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[arg(long, value_name = "FILE")]
    pub bpf_object: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub enum Commands {
    Apply,
    Run,
    Status,
    Check,
    Clean,
}

pub const LOCAL_CONFIG_PATH: &str = "config.json";
pub const DEFAULT_CONFIG_PATH: &str = "/etc/config/xelay/tc-ebpf-config.json";

pub fn resolve_config_path(config: Option<PathBuf>) -> Result<PathBuf> {
    resolve_config_path_with(config, |path| path.exists())
}

fn resolve_config_path_with<F>(config: Option<PathBuf>, exists: F) -> Result<PathBuf>
where
    F: Fn(&Path) -> bool,
{
    if let Some(path) = config {
        return Ok(path);
    }

    let local = PathBuf::from(LOCAL_CONFIG_PATH);
    if exists(&local) {
        return Ok(local);
    }

    let default = PathBuf::from(DEFAULT_CONFIG_PATH);
    if exists(&default) {
        return Ok(default);
    }

    bail!(
        "no config file provided and none found at {} or {}",
        local.display(),
        default.display()
    )
}

pub fn render_status(report: &StatusReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("backend: {}\n", report.backend));
    out.push_str(&format!("host interface: {}\n", report.host_interface));
    out.push_str(&format!("state file: {}\n\n", report.state_path.display()));

    for rule in &report.rules {
        push_rule_status(&mut out, rule);
        out.push('\n');
    }

    out
}

fn push_rule_status(out: &mut String, rule: &RuleStatus) {
    out.push_str(&format!("{}:\n", rule.name));
    out.push_str(&format!("  state: {}\n", rule.state));
    out.push_str(&format!(
        "  target: {}:{} ({})\n",
        rule.target_host,
        rule.target_port,
        rule.protocols.join(",")
    ));
    out.push_str(&format!("  in: {}\n", human_bytes(rule.in_bytes)));
    out.push_str(&format!("  out: {}\n", human_bytes(rule.out_bytes)));
    if rule.quotas_deferred {
        out.push_str("  quotas: configured, enforcement deferred in TC MVP\n");
    }
    if rule.limits_deferred {
        out.push_str("  limits: configured, enforcement deferred in TC MVP\n");
    }
}

pub fn render_check_report(report: &CheckReport) -> String {
    let mut out = String::new();
    out.push_str("checks:\n");
    for check in &report.checks {
        out.push_str(&format!("  {}: {}\n", check.name, check.result));
    }
    out
}

pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{}{}", bytes, UNITS[unit])
    } else {
        format!("{value:.2}{}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_status_marks_deferred_limits() {
        let report = StatusReport {
            backend: "tc-ebpf".to_string(),
            host_interface: "eth0".to_string(),
            state_path: PathBuf::from("/tmp/state.json"),
            rules: vec![RuleStatus {
                name: "svc".to_string(),
                state: "enabled-limits-deferred".to_string(),
                target_host: "1.2.3.4".to_string(),
                target_port: 80,
                protocols: vec!["tcp".to_string()],
                in_bytes: 1024,
                out_bytes: 2048,
                quotas_deferred: true,
                limits_deferred: true,
            }],
        };

        let rendered = render_status(&report);
        assert!(rendered.contains("backend: tc-ebpf"));
        assert!(rendered.contains("quotas: configured, enforcement deferred"));
        assert!(rendered.contains("limits: configured, enforcement deferred"));
    }
}
