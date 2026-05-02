use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

use crate::reconcile::{CheckReport, RuleStatus, StatusReport};

/// Top-level CLI arguments shared by every subcommand.
#[derive(Debug, Parser)]
#[command(name = "xelay")]
#[command(about = "Namespace-isolated Linux port forwarding controller")]
pub struct Cli {
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Supported operator actions for applying, monitoring, and inspecting the dataplane.
#[derive(Debug, Clone, Copy, Subcommand)]
pub enum Commands {
    Apply,
    Run,
    Status,
    Check,
}

/// Current-directory config fallback used when `--config` is omitted.
pub const LOCAL_CONFIG_PATH: &str = "config.json";

/// System config fallback used when `--config` is omitted and no local config exists.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/config/xelay/config.json";

/// Resolves the config path from CLI input and default lookup paths.
pub fn resolve_config_path(config: Option<PathBuf>) -> Result<PathBuf> {
    resolve_config_path_with(config, |path| path.exists())
}

/// Testable config path resolver with injectable filesystem existence checks.
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

/// Renders the current controller and forwarding-rule status in a human-readable form.
pub fn render_status(report: &StatusReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("namespace: {}\n", report.namespace));
    out.push_str(&format!("state file: {}\n\n", report.state_path.display()));

    for rule in &report.rules {
        push_rule_status(&mut out, rule);
        out.push('\n');
    }

    out
}

/// Appends one forwarding rule's status block to the CLI output.
fn push_rule_status(out: &mut String, rule: &RuleStatus) {
    out.push_str(&format!("{}:\n", rule.name));
    out.push_str(&format!("  state: {}\n", rule.state));
    out.push_str(&format!(
        "  target: {}:{} ({})\n",
        rule.target_host,
        rule.target_port,
        rule.protocols.join(",")
    ));
    out.push_str(&format!(
        "  in: {} / {}\n",
        human_bytes(rule.in_bytes),
        human_quota(rule.in_quota)
    ));
    out.push_str(&format!(
        "  out: {} / {}\n",
        human_bytes(rule.out_bytes),
        human_quota(rule.out_quota)
    ));
    out.push_str(&format!(
        "  tcp: {} / {}\n",
        rule.tcp_connections, rule.max_tcp_connections
    ));
    out.push_str(&format!(
        "  udp: {} / {}\n",
        rule.udp_flows, rule.max_udp_flows
    ));
}

/// Renders dependency and config validation checks for `xelay check`.
pub fn render_check_report(report: &CheckReport) -> String {
    let mut out = String::new();
    out.push_str("checks:\n");
    for check in &report.checks {
        out.push_str(&format!("  {}: {}\n", check.name, check.result));
    }
    out
}

/// Formats bytes with binary units so quota/status output is readable.
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

/// Formats an optional quota limit for status output.
pub fn human_quota(bytes: Option<u64>) -> String {
    bytes
        .map(human_bytes)
        .unwrap_or_else(|| "unlimited".to_string())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::reconcile::{CheckEntry, RuleStatus, StatusReport};

    #[test]
    fn human_bytes_formats_boundaries() {
        assert_eq!(human_bytes(0), "0B");
        assert_eq!(human_bytes(1023), "1023B");
        assert_eq!(human_bytes(1024), "1.00KB");
        assert_eq!(human_bytes(1024 * 1024), "1.00MB");
        assert_eq!(human_bytes(5 * 1024 * 1024 * 1024), "5.00GB");
    }

    #[test]
    fn render_status_includes_rule_details() {
        let report = StatusReport {
            namespace: "fwd".to_string(),
            state_path: PathBuf::from("/tmp/state.json"),
            rules: vec![RuleStatus {
                name: "svc-5000".to_string(),
                state: "enabled".to_string(),
                target_host: "1.2.3.4".to_string(),
                target_port: 2616,
                protocols: vec!["tcp".to_string(), "udp".to_string()],
                in_bytes: 1024,
                in_quota: Some(10 * 1024),
                out_bytes: 2048,
                out_quota: Some(20 * 1024),
                tcp_connections: 10,
                max_tcp_connections: 100,
                udp_flows: 2,
                max_udp_flows: 50,
            }],
        };

        let rendered = render_status(&report);
        assert!(rendered.contains("namespace: fwd"));
        assert!(rendered.contains("svc-5000:"));
        assert!(rendered.contains("target: 1.2.3.4:2616 (tcp,udp)"));
        assert!(rendered.contains("in: 1.00KB / 10.00KB"));
        assert!(rendered.contains("tcp: 10 / 100"));
    }

    #[test]
    fn render_status_formats_unlimited_quotas() {
        let report = StatusReport {
            namespace: "fwd".to_string(),
            state_path: PathBuf::from("/tmp/state.json"),
            rules: vec![RuleStatus {
                name: "svc-5000".to_string(),
                state: "enabled".to_string(),
                target_host: "1.2.3.4".to_string(),
                target_port: 2616,
                protocols: vec!["tcp".to_string()],
                in_bytes: 1024,
                in_quota: None,
                out_bytes: 2048,
                out_quota: None,
                tcp_connections: 0,
                max_tcp_connections: 0,
                udp_flows: 0,
                max_udp_flows: 0,
            }],
        };

        let rendered = render_status(&report);
        assert!(rendered.contains("in: 1.00KB / unlimited"));
        assert!(rendered.contains("out: 2.00KB / unlimited"));
    }

    #[test]
    fn render_check_report_lists_checks() {
        let report = CheckReport {
            checks: vec![
                CheckEntry {
                    name: "ip".to_string(),
                    result: "ok".to_string(),
                },
                CheckEntry {
                    name: "nft".to_string(),
                    result: "missing".to_string(),
                },
            ],
        };

        let rendered = render_check_report(&report);
        assert!(rendered.contains("checks:"));
        assert!(rendered.contains("ip: ok"));
        assert!(rendered.contains("nft: missing"));
    }

    #[test]
    fn resolve_config_path_prefers_explicit_path() {
        let path =
            resolve_config_path_with(Some(PathBuf::from("/tmp/custom.json")), |_| false).unwrap();
        assert_eq!(path, PathBuf::from("/tmp/custom.json"));
    }

    #[test]
    fn resolve_config_path_uses_local_default_first() {
        let path =
            resolve_config_path_with(None, |path| path == Path::new(LOCAL_CONFIG_PATH)).unwrap();
        assert_eq!(path, PathBuf::from(LOCAL_CONFIG_PATH));
    }

    #[test]
    fn resolve_config_path_falls_back_to_system_default() {
        let path =
            resolve_config_path_with(None, |path| path == Path::new(DEFAULT_CONFIG_PATH)).unwrap();
        assert_eq!(path, PathBuf::from(DEFAULT_CONFIG_PATH));
    }

    #[test]
    fn resolve_config_path_errors_when_defaults_are_missing() {
        let error = resolve_config_path_with(None, |_| false)
            .unwrap_err()
            .to_string();
        assert!(error.contains(LOCAL_CONFIG_PATH));
        assert!(error.contains(DEFAULT_CONFIG_PATH));
    }

    #[test]
    fn cli_allows_no_subcommand() {
        let cli = Cli::try_parse_from(["xelay"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn cli_still_accepts_explicit_subcommands() {
        let cli = Cli::try_parse_from(["xelay", "apply"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Apply)));
    }
}
