use clap::{Parser, Subcommand};

use crate::reconcile::{CheckReport, RuleStatus, StatusReport};

/// Top-level CLI arguments shared by every subcommand.
#[derive(Debug, Parser)]
#[command(name = "xelay")]
#[command(about = "Namespace-isolated Linux port forwarding controller")]
pub struct Cli {
    #[arg(short, long, value_name = "FILE")]
    pub config: std::path::PathBuf,

    #[command(subcommand)]
    pub command: Commands,
}

/// Supported operator actions for applying, monitoring, and inspecting the dataplane.
#[derive(Debug, Clone, Copy, Subcommand)]
pub enum Commands {
    Apply,
    Run,
    Status,
    Check,
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
        human_bytes(rule.in_quota)
    ));
    out.push_str(&format!(
        "  out: {} / {}\n",
        human_bytes(rule.out_bytes),
        human_bytes(rule.out_quota)
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
                in_quota: 10 * 1024,
                out_bytes: 2048,
                out_quota: 20 * 1024,
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
}
