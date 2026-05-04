use std::thread;
use std::time::Duration;

use anyhow::Result;
use std::collections::BTreeMap;

use crate::config::{Config, RuleConfig};
use crate::dataplane::{CheckEntry, CounterSample, Dataplane};
use crate::model::{DIRECTION_IN, DIRECTION_OUT};
use crate::state::{ControllerState, RuleRuntimeState, StateFile};

pub struct Reconciler<D> {
    config: Config,
    dataplane: D,
}

impl<D: Dataplane> Reconciler<D> {
    pub fn new(config: Config, dataplane: D) -> Self {
        Self { config, dataplane }
    }

    pub fn apply(&mut self) -> Result<()> {
        self.ensure_runtime()
    }

    pub fn run(&mut self) -> Result<()> {
        self.run_with_log(|| Ok(()))
    }

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

    pub fn status(&mut self) -> Result<StatusReport> {
        let mut state_file = StateFile::load(&self.config.state_path)?;
        let samples = self.dataplane.read_counters().unwrap_or_default();
        merge_counter_samples(&mut state_file.state, &self.config, &samples);

        let rules = self
            .config
            .rules
            .iter()
            .map(|rule| {
                let entry = state_file.state.ensure_rule(&rule.name).clone();
                RuleStatus::from_parts(
                    rule,
                    entry.runtime,
                    entry.counters.in_bytes,
                    entry.counters.out_bytes,
                )
            })
            .collect();

        Ok(StatusReport {
            backend: "tc-ebpf".to_string(),
            host_interface: self.config.host_interface.clone(),
            state_path: self.config.state_path.clone(),
            rules,
        })
    }

    pub fn check(&self) -> Result<CheckReport> {
        Ok(CheckReport {
            checks: self.dataplane.check(&self.config)?,
        })
    }

    pub fn clean(&mut self) -> Result<()> {
        self.dataplane.clean(&self.config)
    }

    fn ensure_runtime(&mut self) -> Result<()> {
        let mut state_file = StateFile::load(&self.config.state_path)?;
        let samples = self.dataplane.read_counters().unwrap_or_default();
        merge_counter_samples(&mut state_file.state, &self.config, &samples);
        refresh_rule_states(&self.config, &mut state_file.state);
        self.dataplane.apply(&self.config, &state_file.state)?;
        state_file.save()?;
        Ok(())
    }
}

pub fn refresh_rule_states(config: &Config, state: &mut ControllerState) {
    for rule in &config.rules {
        let entry = state.ensure_rule(&rule.name);
        entry.runtime = if !rule.enabled {
            RuleRuntimeState::disabled_by_config()
        } else if rule.has_deferred_limits() {
            RuleRuntimeState::enabled_with_deferred_limits()
        } else {
            RuleRuntimeState::enabled()
        };
    }
}

pub fn merge_counter_samples(
    state: &mut ControllerState,
    config: &Config,
    samples: &[CounterSample],
) {
    let mut totals = BTreeMap::<u32, (u64, u64, u64, u64)>::new();
    for sample in samples {
        if !matches!(sample.protocol, 6 | 17) {
            continue;
        }
        let entry = totals.entry(sample.rule_id).or_default();
        match sample.direction {
            DIRECTION_IN => {
                entry.0 = entry.0.saturating_add(sample.packets);
                entry.1 = entry.1.saturating_add(sample.bytes);
            }
            DIRECTION_OUT => {
                entry.2 = entry.2.saturating_add(sample.packets);
                entry.3 = entry.3.saturating_add(sample.bytes);
            }
            _ => {}
        }
    }

    for (rule_id, (in_packets, in_bytes, out_packets, out_bytes)) in totals {
        let Some(rule) = config.rules.get(rule_id as usize) else {
            continue;
        };
        let entry = state.ensure_rule(&rule.name);
        entry.counters.in_packets = in_packets;
        entry.counters.in_bytes = in_bytes;
        entry.counters.out_packets = out_packets;
        entry.counters.out_bytes = out_bytes;
    }
}

#[derive(Debug)]
pub struct CheckReport {
    pub checks: Vec<CheckEntry>,
}

#[derive(Debug)]
pub struct StatusReport {
    pub backend: String,
    pub host_interface: String,
    pub state_path: std::path::PathBuf,
    pub rules: Vec<RuleStatus>,
}

#[derive(Debug)]
pub struct RuleStatus {
    pub name: String,
    pub state: String,
    pub target_host: String,
    pub target_port: u16,
    pub protocols: Vec<String>,
    pub in_bytes: u64,
    pub out_bytes: u64,
    pub quotas_deferred: bool,
    pub limits_deferred: bool,
}

impl RuleStatus {
    fn from_parts(
        rule: &RuleConfig,
        runtime: RuleRuntimeState,
        in_bytes: u64,
        out_bytes: u64,
    ) -> Self {
        Self {
            name: rule.name.clone(),
            state: runtime.reason,
            target_host: rule.target_host.clone(),
            target_port: rule.target_port,
            protocols: rule
                .protocols
                .iter()
                .map(|protocol| protocol.as_str().to_string())
                .collect(),
            in_bytes,
            out_bytes,
            quotas_deferred: rule.quota_in.is_some() || rule.quota_out.is_some(),
            limits_deferred: rule.max_tcp_connections > 0 || rule.max_udp_flows > 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::config::{Config, Protocol, RuleConfig};
    use crate::dataplane::tests::FakeDataplane;

    use super::*;

    fn sample_config() -> Config {
        Config {
            host_interface: "eth0".to_string(),
            bpf_object_path: PathBuf::from("/tmp/xelay.o"),
            state_path: std::env::temp_dir().join("xelay-tc-test-state.json"),
            log_path: None,
            poll_interval_secs: 1,
            rules: vec![RuleConfig {
                name: "svc".to_string(),
                listen_port: 5000,
                protocols: vec![Protocol::Tcp, Protocol::Udp],
                target: None,
                target_host: "114.111.191.26".to_string(),
                target_port: 2616,
                quota_in: None,
                quota_out: None,
                max_tcp_connections: 0,
                max_udp_flows: 0,
                enabled: true,
            }],
        }
    }

    #[test]
    fn apply_reads_counters_then_applies_dataplane() {
        let config = sample_config();
        let path = config.state_path.clone();
        let _ = std::fs::remove_file(&path);
        let mut reconciler = Reconciler::new(config, FakeDataplane::default());

        reconciler.apply().unwrap();

        let calls = reconciler.dataplane.calls.borrow();
        assert_eq!(calls.as_slice(), ["read_counters", "apply"]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn merge_counters_updates_rule_totals_by_rule_id() {
        let config = sample_config();
        let mut state = ControllerState::default();
        merge_counter_samples(
            &mut state,
            &config,
            &[
                CounterSample {
                    rule_id: 0,
                    protocol: 6,
                    direction: DIRECTION_IN,
                    packets: 2,
                    bytes: 100,
                },
                CounterSample {
                    rule_id: 0,
                    protocol: 6,
                    direction: DIRECTION_OUT,
                    packets: 1,
                    bytes: 80,
                },
                CounterSample {
                    rule_id: 0,
                    protocol: 17,
                    direction: DIRECTION_IN,
                    packets: 3,
                    bytes: 25,
                },
            ],
        );

        let entry = &state.rules["svc"];
        assert_eq!(entry.counters.in_bytes, 125);
        assert_eq!(entry.counters.in_packets, 5);
        assert_eq!(entry.counters.out_bytes, 80);
    }
}
