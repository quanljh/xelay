use anyhow::{Context, Result};

use crate::command;
use crate::config::{Config, Protocol, RuleConfig};
use crate::state::{ControllerState, RuleDirectionCounters, RuleRuntimeState};

/// Applies the host and namespace nftables rulesets for the desired config/state.
///
/// The controller owns only `xelay_*` tables. Existing controller tables are deleted
/// first so the rendered ruleset can be applied as a clean snapshot.
pub fn apply(config: &Config, state: &ControllerState) -> Result<()> {
    delete_table("nft", &["delete", "table", "ip", "xelay_hostnat"]);
    delete_table("nft", &["delete", "table", "ip", "xelay_hostfwd"]);
    let host_script = render_host_script(config);
    command::run_input("nft", ["-f", "-"], &host_script)?;

    delete_table_in_namespace(config, &["delete", "table", "inet", "xelay_fwd"]);
    let ns_script = render_namespace_script(config, state);
    let command = format!("ip netns exec {} nft -f -", config.namespace);
    command::run_input("sh", vec!["-c".to_string(), command], &ns_script)?;

    Ok(())
}

/// Removes only nftables tables owned by this controller.
pub fn clean(config: &Config) -> Result<()> {
    clean_with(config, &SystemNftOps)
}

/// Reads named nftables counters from the forwarding namespace.
///
/// Counter values are raw kernel totals; callers merge them with persisted baselines
/// to maintain cumulative quota accounting across controller restarts.
pub fn read_counters(config: &Config) -> Result<Vec<CounterSample>> {
    let output = command::run(
        "ip",
        [
            "netns",
            "exec",
            config.namespace.as_str(),
            "nft",
            "-j",
            "list",
            "table",
            "inet",
            "xelay_fwd",
        ],
    )?;

    parse_counter_json(&output.stdout)
}

/// One named nftables counter sample from the current kernel ruleset.
#[derive(Debug, Clone)]
pub struct CounterSample {
    pub counter_name: String,
    pub bytes: u64,
}

/// Parses `nft -j list table` output and extracts every named counter sample.
fn parse_counter_json(raw: &str) -> Result<Vec<CounterSample>> {
    let value: serde_json::Value =
        serde_json::from_str(raw).context("failed to parse nft JSON output")?;
    let mut samples = Vec::new();
    collect_counters(&value, &mut samples);
    Ok(samples)
}

/// Recursively walks nftables JSON because counters can appear at different depths.
fn collect_counters(value: &serde_json::Value, samples: &mut Vec<CounterSample>) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(counter) = map.get("counter") {
                if let Some(counter_map) = counter.as_object() {
                    let name = counter_map
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    let bytes = counter_map
                        .get("bytes")
                        .and_then(|v| v.as_u64())
                        .unwrap_or_default();
                    if !name.is_empty() {
                        samples.push(CounterSample {
                            counter_name: name.to_string(),
                            bytes,
                        });
                    }
                }
            }
            for value in map.values() {
                collect_counters(value, samples);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_counters(value, samples);
            }
        }
        _ => {}
    }
}

/// Renders the minimal host-side nftables tables.
///
/// The host rules masquerade namespace egress and DNAT public listen ports into the
/// forwarding namespace.
fn render_host_script(config: &Config) -> String {
    let mut script = String::new();
    script.push_str("table ip xelay_hostnat {\n");
    script.push_str(
        " chain postrouting { type nat hook postrouting priority srcnat; policy accept;\n",
    );
    script.push_str(&format!(
        "  oifname \"{}\" ip saddr {} masquerade\n",
        config.host_interface, config.host_veth_ip
    ));
    script.push_str(" }\n}\n");
    script.push_str("table ip xelay_hostfwd {\n");
    script
        .push_str(" chain prerouting { type nat hook prerouting priority dstnat; policy accept;\n");
    for rule in &config.rules {
        for protocol in &rule.protocols {
            if !rule.enabled {
                continue;
            }
            script.push_str(&format!(
                "  {} dport {} dnat to {}:{}\n",
                protocol.as_str(),
                rule.listen_port,
                config.ns_ip(),
                rule.listen_port
            ));
        }
    }
    script.push_str(" }\n}\n");
    script
}

/// Renders the namespace-owned dataplane ruleset.
///
/// This includes DNAT to backends, filter decisions, source NAT, and named counters
/// used for quota accounting.
fn render_namespace_script(config: &Config, state: &ControllerState) -> String {
    let mut script = String::new();
    script.push_str("table inet xelay_fwd {\n");
    for rule in &config.rules {
        for protocol in &rule.protocols {
            script.push_str(&format!(
                " counter {} {{ }}\n",
                counter_name(rule, protocol, "in")
            ));
            script.push_str(&format!(
                " counter {} {{ }}\n",
                counter_name(rule, protocol, "out")
            ));
        }
    }
    script
        .push_str(" chain prerouting { type nat hook prerouting priority dstnat; policy accept;\n");

    for rule in &config.rules {
        let runtime = state.rule_state(&rule.name);
        push_prerouting_rule(&mut script, rule, runtime);
    }
    script.push_str(" }\n");
    script.push_str(" chain forward { type filter hook forward priority filter; policy drop;\n");
    script.push_str("  ct state established,related accept\n");
    for rule in &config.rules {
        if !is_rule_active(rule, state.rule_state(&rule.name)) {
            continue;
        }
        for protocol in &rule.protocols {
            script.push_str(&format!(
                "  ip daddr {} {} dport {} accept\n",
                rule.target_host,
                protocol.as_str(),
                rule.target_port
            ));
        }
    }
    script.push_str(" }\n");
    script.push_str(
        " chain postrouting { type nat hook postrouting priority srcnat; policy accept;\n",
    );
    script.push_str(&format!(
        "  oifname != \"{}\" masquerade\n",
        config.ns_veth_name()
    ));
    for rule in &config.rules {
        if !is_rule_active(rule, state.rule_state(&rule.name)) {
            continue;
        }
        for protocol in &rule.protocols {
            script.push_str(&format!(
                "  ip daddr {} {} sport {} counter name {} accept\n",
                rule.target_host,
                protocol.as_str(),
                rule.target_port,
                counter_name(rule, protocol, "out")
            ));
        }
    }
    script.push_str(" }\n");
    script.push_str("}\n");
    script
}

/// Emits per-rule prerouting behavior based on runtime state.
///
/// Enabled rules DNAT new flows. Blocked rules drop new TCP while established TCP is
/// allowed to drain through conntrack, and drop UDP immediately.
fn push_prerouting_rule(
    script: &mut String,
    rule: &RuleConfig,
    runtime: Option<&RuleRuntimeState>,
) {
    for protocol in &rule.protocols {
        let in_counter = counter_name(rule, protocol, "in");
        let state = runtime.cloned().unwrap_or_else(|| {
            if rule.enabled {
                RuleRuntimeState::enabled()
            } else {
                RuleRuntimeState::disabled_by_config()
            }
        });

        if state.accepting_new() {
            script.push_str(&format!(
                "  ct state new {} dport {} counter name {} dnat ip to {}:{}\n",
                protocol.as_str(),
                rule.listen_port,
                in_counter,
                rule.target_host,
                rule.target_port
            ));
        } else {
            let predicate = match protocol {
                Protocol::Tcp if state.forwarding_enabled() => {
                    format!(
                        "ct state new {} dport {}",
                        protocol.as_str(),
                        rule.listen_port
                    )
                }
                _ => format!("{} dport {}", protocol.as_str(), rule.listen_port),
            };
            script.push_str(&format!(
                "  {} counter name {} drop\n",
                predicate, in_counter
            ));
        }
    }
}

/// Returns whether forward-chain accept rules should remain installed for a rule.
fn is_rule_active(rule: &RuleConfig, runtime: Option<&RuleRuntimeState>) -> bool {
    runtime
        .map(RuleRuntimeState::forwarding_enabled)
        .unwrap_or(rule.enabled)
}

/// Builds the stable nftables counter name for a rule/protocol/direction.
pub fn counter_name(rule: &RuleConfig, protocol: &Protocol, direction: &str) -> String {
    let proto = protocol.as_str();
    format!("{}_{}_{}", sanitize_name(&rule.name), direction, proto)
}

/// Converts arbitrary rule names into nft-safe counter identifiers.
fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// Merges current kernel counter samples into persisted cumulative accounting state.
///
/// Each named counter has a baseline. Only the delta since the last sample is added
/// to the persisted total so restarts do not double count traffic.
pub fn merge_counter_samples(
    state: &mut ControllerState,
    config: &Config,
    samples: &[CounterSample],
) {
    for rule in &config.rules {
        let entry = state.ensure_rule(&rule.name);
        for protocol in &rule.protocols {
            let in_counter = counter_name(rule, protocol, "in");
            let out_counter = counter_name(rule, protocol, "out");
            let in_bytes = samples
                .iter()
                .find(|sample| sample.counter_name == in_counter)
                .map(|sample| sample.bytes)
                .unwrap_or_default();
            let out_bytes = samples
                .iter()
                .find(|sample| sample.counter_name == out_counter)
                .map(|sample| sample.bytes)
                .unwrap_or_default();

            apply_counter_delta(&mut entry.counters, &in_counter, in_bytes, true);
            apply_counter_delta(&mut entry.counters, &out_counter, out_bytes, false);
        }
    }
}

/// Applies one counter's delta to cumulative in/out byte totals.
///
/// If the kernel counter moves backwards, the ruleset was likely recreated; the
/// baseline is reset so the next sample starts a new accounting epoch.
fn apply_counter_delta(
    counters: &mut RuleDirectionCounters,
    counter_name: &str,
    current_bytes: u64,
    is_incoming: bool,
) {
    let baseline = counters
        .baselines
        .entry(counter_name.to_string())
        .or_default();
    if current_bytes < *baseline {
        *baseline = 0;
    }
    let delta = current_bytes.saturating_sub(*baseline);
    *baseline = current_bytes;

    if is_incoming {
        counters.in_bytes = counters.in_bytes.saturating_add(delta);
    } else {
        counters.out_bytes = counters.out_bytes.saturating_add(delta);
    }
}

/// Best-effort deletion of an nftables table before applying a replacement table.
fn delete_table(program: &str, args: &[&str]) {
    let _ = command::run(program, args.iter().copied());
}

/// Best-effort deletion of a namespace-owned nftables table.
fn delete_table_in_namespace(config: &Config, args: &[&str]) {
    let mut command_args = vec!["netns", "exec", config.namespace.as_str(), "nft"];
    command_args.extend(args.iter().copied());
    let _ = command::run("ip", command_args);
}

/// Minimal nft operations needed for cleanup.
trait NftOps {
    fn run(&self, program: &str, args: &[&str]) -> Result<()>;
}

/// Performs best-effort cleanup of xelay-owned nftables tables.
fn clean_with(config: &Config, ops: &dyn NftOps) -> Result<()> {
    ignore_absent(ops.run("nft", &["delete", "table", "ip", "xelay_hostnat"]))?;
    ignore_absent(ops.run("nft", &["delete", "table", "ip", "xelay_hostfwd"]))?;
    ignore_absent(ops.run(
        "ip",
        &[
            "netns",
            "exec",
            config.namespace.as_str(),
            "nft",
            "delete",
            "table",
            "inet",
            "xelay_fwd",
        ],
    ))?;
    Ok(())
}

fn ignore_absent(result: Result<()>) -> Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if is_absent_cleanup_error(&error.to_string()) => Ok(()),
        Err(error) => Err(error),
    }
}

fn is_absent_cleanup_error(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("no such file")
        || message.contains("does not exist")
        || message.contains("cannot open network namespace")
}

struct SystemNftOps;

impl NftOps for SystemNftOps {
    fn run(&self, program: &str, args: &[&str]) -> Result<()> {
        command::run(program, args.iter().copied()).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::config::{Protocol, Quota};
    use crate::state::RuleEntryState;

    #[derive(Default)]
    struct FakeNftOps {
        calls: RefCell<Vec<String>>,
    }

    struct ErrorNftOps {
        message: &'static str,
    }

    impl NftOps for FakeNftOps {
        fn run(&self, program: &str, args: &[&str]) -> Result<()> {
            self.calls
                .borrow_mut()
                .push(format!("{program} {}", args.join(" ")));
            Ok(())
        }
    }

    impl NftOps for ErrorNftOps {
        fn run(&self, _program: &str, _args: &[&str]) -> Result<()> {
            anyhow::bail!("{}", self.message)
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
            rules: vec![RuleConfig {
                name: "svc-5000".to_string(),
                listen_port: 5000,
                protocols: vec![Protocol::Tcp, Protocol::Udp],
                target: None,
                target_host: "114.111.191.26".to_string(),
                target_port: 2616,
                quota_in: Some(Quota(1)),
                quota_out: Some(Quota(1)),
                max_tcp_connections: 10,
                max_udp_flows: 20,
                enabled: true,
            }],
        }
    }

    #[test]
    fn counter_name_sanitizes_rule_name() {
        let config = sample_config();
        assert_eq!(
            counter_name(&config.rules[0], &Protocol::Tcp, "in"),
            "svc_5000_in_tcp"
        );
    }

    #[test]
    fn parse_counter_json_extracts_nested_counters() {
        let raw = r#"{
            "nftables": [{
                "table": {"family": "inet", "name": "xelay_fwd"}
            }, {
                "counter": {"family": "inet", "table": "xelay_fwd", "name": "svc_in_tcp", "packets": 1, "bytes": 100}
            }, {
                "chain": {
                    "family": "inet",
                    "table": "xelay_fwd",
                    "name": "postrouting",
                    "rules": [{
                        "counter": {"name": "svc_out_tcp", "bytes": 250}
                    }]
                }
            }]
        }"#;

        let counters = parse_counter_json(raw).unwrap();
        assert_eq!(counters.len(), 2);
        assert!(counters
            .iter()
            .any(|c| c.counter_name == "svc_in_tcp" && c.bytes == 100));
        assert!(counters
            .iter()
            .any(|c| c.counter_name == "svc_out_tcp" && c.bytes == 250));
    }

    #[test]
    fn render_host_script_contains_port_forwarding() {
        let script = render_host_script(&sample_config());
        assert!(script.contains("table ip xelay_hostnat"));
        assert!(script.contains("oifname \"eth0\" ip saddr 10.200.0.1/30 masquerade"));
        assert!(script.contains("tcp dport 5000 dnat to 10.200.0.2:5000"));
        assert!(script.contains("udp dport 5000 dnat to 10.200.0.2:5000"));
    }

    #[test]
    fn render_namespace_script_for_enabled_rule_contains_dnat_and_accept() {
        let config = sample_config();
        let mut state = ControllerState::default();
        state
            .rules
            .insert("svc-5000".to_string(), RuleEntryState::default());
        let script = render_namespace_script(&config, &state);
        assert!(script.contains("counter svc_5000_in_tcp { }"));
        assert!(script.contains(
            "ct state new tcp dport 5000 counter name svc_5000_in_tcp dnat ip to 114.111.191.26:2616"
        ));
        assert!(script.contains("ip daddr 114.111.191.26 tcp dport 2616 accept"));
        assert!(script.contains(
            "ip daddr 114.111.191.26 tcp sport 2616 counter name svc_5000_out_tcp accept"
        ));
    }

    #[test]
    fn render_namespace_script_for_tcp_drain_blocks_new_only() {
        let config = sample_config();
        let mut state = ControllerState::default();
        let entry = state.ensure_rule("svc-5000");
        entry.runtime = RuleRuntimeState::tcp_limit_blocked();
        let script = render_namespace_script(&config, &state);
        assert!(script.contains("ct state new tcp dport 5000 counter name svc_5000_in_tcp drop"));
        assert!(script.contains("udp dport 5000 counter name svc_5000_in_udp drop"));
    }

    #[test]
    fn clean_deletes_managed_host_and_namespace_tables() {
        let ops = FakeNftOps::default();

        clean_with(&sample_config(), &ops).unwrap();

        let calls = ops.calls.borrow();
        assert!(calls
            .iter()
            .any(|c| c == "nft delete table ip xelay_hostnat"));
        assert!(calls
            .iter()
            .any(|c| c == "nft delete table ip xelay_hostfwd"));
        assert!(calls
            .iter()
            .any(|c| c == "ip netns exec fwd nft delete table inet xelay_fwd"));
    }

    #[test]
    fn clean_ignores_absent_managed_tables() {
        let ops = ErrorNftOps {
            message: "No such file or directory",
        };

        clean_with(&sample_config(), &ops).unwrap();
    }

    #[test]
    fn clean_reports_unexpected_nft_errors() {
        let ops = ErrorNftOps {
            message: "permission denied",
        };

        let error = clean_with(&sample_config(), &ops).unwrap_err().to_string();
        assert!(error.contains("permission denied"));
    }

    #[test]
    fn merge_counter_samples_accumulates_and_handles_resets() {
        let config = sample_config();
        let mut state = ControllerState::default();

        merge_counter_samples(
            &mut state,
            &config,
            &[
                CounterSample {
                    counter_name: "svc_5000_in_tcp".to_string(),
                    bytes: 100,
                },
                CounterSample {
                    counter_name: "svc_5000_out_tcp".to_string(),
                    bytes: 200,
                },
            ],
        );
        let entry = state.ensure_rule("svc-5000");
        assert_eq!(entry.counters.in_bytes, 100);
        assert_eq!(entry.counters.out_bytes, 200);

        merge_counter_samples(
            &mut state,
            &config,
            &[
                CounterSample {
                    counter_name: "svc_5000_in_tcp".to_string(),
                    bytes: 40,
                },
                CounterSample {
                    counter_name: "svc_5000_out_tcp".to_string(),
                    bytes: 50,
                },
            ],
        );
        let entry = state.ensure_rule("svc-5000");
        assert_eq!(entry.counters.in_bytes, 140);
        assert_eq!(entry.counters.out_bytes, 250);
    }
}
