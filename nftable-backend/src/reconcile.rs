use std::thread;
use std::time::Duration;

use anyhow::Result;

use crate::command;
use crate::config::Config;
use crate::conntrack::{self, FlowCounts};
use crate::namespace;
use crate::nft;
use crate::state::{ControllerState, RuleRuntimeState, RuleStateFile};

/// High-level controller that reconciles config, kernel state, and persisted state.
pub struct Reconciler {
    config: Config,
}

impl Reconciler {
    /// Creates a controller for an already-loaded and validated config.
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Performs one reconciliation pass and exits.
    ///
    /// This sets up namespace networking, refreshes counters, updates runtime rule
    /// state, applies nftables, and saves controller state.
    pub fn apply(&mut self) -> Result<()> {
        self.ensure_runtime()
    }

    /// Reconciles forever at the configured polling interval.
    ///
    /// This is the daemon-style mode that enforces quotas and connection limits.
    pub fn run(&mut self) -> Result<()> {
        self.run_with_log(|| Ok(()))
    }

    /// Reconciles forever and invokes `on_pass` after each successful pass.
    pub fn run_with_log<F>(&mut self, mut on_pass: F) -> Result<()>
    where
        F: FnMut() -> Result<()>,
    {
        loop {
            self.ensure_runtime()?;
            on_pass()?;
            thread::sleep(Duration::from_secs(self.config.poll_interval_secs));
        }
    }

    /// Builds a status report from persisted state plus current kernel observations.
    pub fn status(&mut self) -> Result<StatusReport> {
        let mut state = RuleStateFile::load(&self.config.state_path)?.state;
        let samples = nft::read_counters(&self.config).unwrap_or_default();
        nft::merge_counter_samples(&mut state, &self.config, &samples);

        let mut rules = Vec::new();
        for rule in &self.config.rules {
            let counters = state.ensure_rule(&rule.name).counters.clone();
            let flows = conntrack::count_flows(&self.config.namespace, rule).unwrap_or_default();
            let runtime = state.ensure_rule(&rule.name).runtime.clone();
            rules.push(RuleStatus::from_parts(
                rule,
                counters.in_bytes,
                counters.out_bytes,
                flows,
                runtime,
            ));
        }

        Ok(StatusReport {
            namespace: self.config.namespace.clone(),
            state_path: self.config.state_path.clone(),
            rules,
        })
    }

    /// Checks whether required external Linux tools are available.
    pub fn check(&self) -> Result<CheckReport> {
        self.check_with(command::command_exists)
    }

    /// Removes xelay-owned nftables tables and namespace networking.
    pub fn clean(&self) -> Result<()> {
        self.check_clean_requirements()?;
        nft::clean(&self.config)?;
        namespace::clean(&self.config)
    }

    /// Testable variant of `check` with injectable command discovery.
    fn check_with<F>(&self, command_exists: F) -> Result<CheckReport>
    where
        F: Fn(&str) -> bool,
    {
        let required = ["ip", "nft", "conntrack", "sysctl"];
        let mut checks = Vec::new();
        for program in required {
            let result = if command_exists(program) {
                "ok".to_string()
            } else {
                "missing".to_string()
            };
            checks.push(CheckEntry {
                name: program.to_string(),
                result,
            });
        }

        checks.push(CheckEntry {
            name: "config.rules".to_string(),
            result: self.config.rules.len().to_string(),
        });

        Ok(CheckReport { checks })
    }

    /// Runs the core reconciliation sequence used by `apply` and each `run` tick.
    fn ensure_runtime(&mut self) -> Result<()> {
        self.check_requirements()?;
        namespace::ensure(&self.config)?;

        let mut state_file = RuleStateFile::load(&self.config.state_path)?;
        let samples = nft::read_counters(&self.config).unwrap_or_default();
        nft::merge_counter_samples(&mut state_file.state, &self.config, &samples);

        self.refresh_rule_states(&mut state_file.state)?;
        nft::apply(&self.config, &state_file.state)?;
        state_file.save()?;
        Ok(())
    }

    /// Updates each rule's runtime state from counters, config, and live flow counts.
    fn refresh_rule_states(&self, state: &mut ControllerState) -> Result<()> {
        for rule in &self.config.rules {
            let flows =
                conntrack::count_flows(&self.config.namespace, rule).unwrap_or(FlowCounts {
                    tcp_connections: 0,
                    udp_flows: 0,
                });
            let entry = state.ensure_rule(&rule.name);
            entry.runtime = decide_rule_state(
                rule,
                entry.counters.in_bytes,
                entry.counters.out_bytes,
                flows,
            );
        }

        Ok(())
    }

    /// Fails early if the host lacks the external tools this controller shells out to.
    fn check_requirements(&self) -> Result<()> {
        for program in ["ip", "nft", "conntrack", "sysctl"] {
            if !command::command_exists(program) {
                anyhow::bail!("required command `{program}` is missing");
            }
        }
        Ok(())
    }

    /// Fails early if cleanup dependencies are unavailable.
    fn check_clean_requirements(&self) -> Result<()> {
        for program in ["ip", "nft"] {
            if !command::command_exists(program) {
                anyhow::bail!("required command `{program}` is missing");
            }
        }
        Ok(())
    }
}

/// Decides whether a rule should accept new flows, drain TCP, or be disabled.
///
/// Quota limits take precedence over connection limits. UDP limits disable forwarding
/// immediately, while TCP limits keep established traffic drainable.
fn decide_rule_state(
    rule: &crate::config::RuleConfig,
    in_bytes: u64,
    out_bytes: u64,
    flows: FlowCounts,
) -> RuleRuntimeState {
    if !rule.enabled {
        return RuleRuntimeState::disabled_by_config();
    }

    if rule.quota_in.is_some_and(|quota| in_bytes >= quota.0)
        || rule.quota_out.is_some_and(|quota| out_bytes >= quota.0)
    {
        return RuleRuntimeState::quota_blocked();
    }

    if rule.max_udp_flows > 0 && flows.udp_flows >= rule.max_udp_flows {
        return RuleRuntimeState::udp_limit_blocked();
    }

    if rule.max_tcp_connections > 0 && flows.tcp_connections >= rule.max_tcp_connections {
        return RuleRuntimeState::tcp_limit_blocked();
    }

    RuleRuntimeState::enabled()
}

/// Snapshot returned by `status` for all configured rules.
#[derive(Debug)]
pub struct StatusReport {
    pub namespace: String,
    pub state_path: std::path::PathBuf,
    pub rules: Vec<RuleStatus>,
}

/// Operator-facing status for one forwarding rule.
#[derive(Debug)]
pub struct RuleStatus {
    pub name: String,
    pub state: String,
    pub target_host: String,
    pub target_port: u16,
    pub protocols: Vec<String>,
    pub in_bytes: u64,
    pub in_quota: Option<u64>,
    pub out_bytes: u64,
    pub out_quota: Option<u64>,
    pub tcp_connections: u32,
    pub max_tcp_connections: u32,
    pub udp_flows: u32,
    pub max_udp_flows: u32,
}

impl RuleStatus {
    /// Builds a status row by combining static config, counters, flows, and runtime state.
    fn from_parts(
        rule: &crate::config::RuleConfig,
        in_bytes: u64,
        out_bytes: u64,
        flows: FlowCounts,
        runtime: RuleRuntimeState,
    ) -> Self {
        Self {
            name: rule.name.clone(),
            state: runtime.reason,
            target_host: rule.target_host.clone(),
            target_port: rule.target_port,
            protocols: rule
                .protocols
                .iter()
                .map(|p| p.as_str().to_string())
                .collect(),
            in_bytes,
            in_quota: rule.quota_in.map(|quota| quota.0),
            out_bytes,
            out_quota: rule.quota_out.map(|quota| quota.0),
            tcp_connections: flows.tcp_connections,
            max_tcp_connections: rule.max_tcp_connections,
            udp_flows: flows.udp_flows,
            max_udp_flows: rule.max_udp_flows,
        }
    }
}

/// Result of preflight checks performed by `xelay check`.
#[derive(Debug)]
pub struct CheckReport {
    pub checks: Vec<CheckEntry>,
}

/// One named check and its result string.
#[derive(Debug)]
pub struct CheckEntry {
    pub name: String,
    pub result: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Protocol, Quota, RuleConfig};

    fn sample_rule() -> RuleConfig {
        RuleConfig {
            name: "svc".to_string(),
            listen_port: 5000,
            protocols: vec![Protocol::Tcp, Protocol::Udp],
            target: None,
            target_host: "1.2.3.4".to_string(),
            target_port: 80,
            quota_in: Some(Quota(100)),
            quota_out: Some(Quota(100)),
            max_tcp_connections: 10,
            max_udp_flows: 20,
            enabled: true,
        }
    }

    fn sample_config() -> Config {
        Config {
            namespace: "fwd".to_string(),
            host_interface: "eth0".to_string(),
            host_veth_ip: "10.200.0.1/30".to_string(),
            ns_veth_ip: "10.200.0.2/30".to_string(),
            state_path: "/tmp/xelay-state.json".into(),
            log_path: None,
            poll_interval_secs: 2,
            rules: vec![sample_rule()],
        }
    }

    #[test]
    fn decide_rule_state_prefers_disabled_by_config() {
        let mut rule = sample_rule();
        rule.enabled = false;
        let state = decide_rule_state(
            &rule,
            1000,
            1000,
            FlowCounts {
                tcp_connections: 100,
                udp_flows: 100,
            },
        );
        assert_eq!(state.reason, "disabled-by-config");
    }

    #[test]
    fn decide_rule_state_blocks_on_quota() {
        let state = decide_rule_state(&sample_rule(), 100, 0, FlowCounts::default());
        assert_eq!(state.reason, "quota-blocked");
        assert!(state.forwarding_enabled());
        assert!(!state.accepting_new());
    }

    #[test]
    fn decide_rule_state_blocks_udp_limit_before_tcp_limit() {
        let state = decide_rule_state(
            &sample_rule(),
            0,
            0,
            FlowCounts {
                tcp_connections: 10,
                udp_flows: 20,
            },
        );
        assert_eq!(state.reason, "udp-limit-blocked");
        assert!(!state.forwarding_enabled());
    }

    #[test]
    fn decide_rule_state_blocks_tcp_limit_at_boundary() {
        let state = decide_rule_state(
            &sample_rule(),
            0,
            0,
            FlowCounts {
                tcp_connections: 10,
                udp_flows: 0,
            },
        );
        assert_eq!(state.reason, "tcp-limit-blocked");
        assert!(state.forwarding_enabled());
        assert!(!state.accepting_new());
    }

    #[test]
    fn decide_rule_state_enables_when_under_limits() {
        let state = decide_rule_state(
            &sample_rule(),
            99,
            99,
            FlowCounts {
                tcp_connections: 9,
                udp_flows: 19,
            },
        );
        assert_eq!(state.reason, "enabled");
    }

    #[test]
    fn decide_rule_state_ignores_missing_quotas() {
        let mut rule = sample_rule();
        rule.quota_in = None;
        rule.quota_out = None;
        let state = decide_rule_state(&rule, u64::MAX, u64::MAX, FlowCounts::default());
        assert_eq!(state.reason, "enabled");
    }

    #[test]
    fn check_reports_missing_commands() {
        let reconciler = Reconciler::new(sample_config());
        let report = reconciler
            .check_with(|program| program == "ip" || program == "sysctl")
            .unwrap();
        let results: std::collections::HashMap<_, _> = report
            .checks
            .iter()
            .map(|check| (check.name.as_str(), check.result.as_str()))
            .collect();
        assert_eq!(results.get("ip"), Some(&"ok"));
        assert_eq!(results.get("nft"), Some(&"missing"));
        assert_eq!(results.get("config.rules"), Some(&"1"));
    }
}
