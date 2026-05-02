use anyhow::Result;

use crate::command;
use crate::config::{Protocol, RuleConfig};

/// Live flow counts for one forwarding rule.
#[derive(Debug, Default, Clone, Copy)]
pub struct FlowCounts {
    pub tcp_connections: u32,
    pub udp_flows: u32,
}

/// Counts live conntrack entries for a rule inside the forwarding namespace.
///
/// This shells out to `ip netns exec <ns> conntrack -L -n` and then matches the
/// backend target tuple used by the rule.
pub fn count_flows(namespace: &str, rule: &RuleConfig) -> Result<FlowCounts> {
    let output = command::run("ip", ["netns", "exec", namespace, "conntrack", "-L", "-n"])?;

    Ok(count_flows_from_output(&output.stdout, rule))
}

/// Parses conntrack output and counts matching TCP connections and UDP flows.
///
/// Kept pure so rule-matching behavior can be unit tested without root privileges.
fn count_flows_from_output(output: &str, rule: &RuleConfig) -> FlowCounts {
    let mut counts = FlowCounts::default();
    for line in output.lines() {
        if !line.contains(&format!("dport={}", rule.target_port)) {
            continue;
        }
        if !line.contains(&rule.target_host) {
            continue;
        }
        if line.starts_with("tcp") && rule.protocols.contains(&Protocol::Tcp) {
            counts.tcp_connections = counts.tcp_connections.saturating_add(1);
        }
        if line.starts_with("udp") && rule.protocols.contains(&Protocol::Udp) {
            counts.udp_flows = counts.udp_flows.saturating_add(1);
        }
    }

    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Quota, RuleConfig};

    fn sample_rule(protocols: Vec<Protocol>) -> RuleConfig {
        RuleConfig {
            name: "svc-5000".to_string(),
            listen_port: 5000,
            protocols,
            target: None,
            target_host: "114.111.191.26".to_string(),
            target_port: 2616,
            quota_in: Some(Quota(1024)),
            quota_out: Some(Quota(1024)),
            max_tcp_connections: 100,
            max_udp_flows: 100,
            enabled: true,
        }
    }

    #[test]
    fn count_flows_matches_tcp_and_udp_lines() {
        let output = "\
tcp      6 431999 ESTABLISHED src=1.1.1.1 dst=10.0.0.2 sport=50000 dport=2616 src=114.111.191.26 dst=1.1.1.1 sport=2616 dport=50000 [ASSURED]\n\
udp      17 29 src=1.1.1.1 dst=10.0.0.2 sport=50001 dport=2616 src=114.111.191.26 dst=1.1.1.1 sport=2616 dport=50001 [UNREPLIED]\n";
        let counts =
            count_flows_from_output(output, &sample_rule(vec![Protocol::Tcp, Protocol::Udp]));
        assert_eq!(counts.tcp_connections, 1);
        assert_eq!(counts.udp_flows, 1);
    }

    #[test]
    fn count_flows_ignores_non_matching_lines() {
        let output = "\
tcp      6 431999 ESTABLISHED src=1.1.1.1 dst=10.0.0.2 sport=50000 dport=9999 src=114.111.191.26 dst=1.1.1.1 sport=2616 dport=50000 [ASSURED]\n\
udp      17 29 src=1.1.1.1 dst=10.0.0.2 sport=50001 dport=2616 src=114.111.191.99 dst=1.1.1.1 sport=2616 dport=50001 [UNREPLIED]\n";
        let counts =
            count_flows_from_output(output, &sample_rule(vec![Protocol::Tcp, Protocol::Udp]));
        assert_eq!(counts.tcp_connections, 0);
        assert_eq!(counts.udp_flows, 0);
    }
}
