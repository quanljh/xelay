use anyhow::Result;

use crate::command;
use crate::config::Config;

/// Ensures the forwarding namespace, veth pair, routes, and IPv4 forwarding exist.
///
/// This is intentionally idempotent: repeated `apply` or `run` calls should converge
/// the host toward the desired network topology instead of failing on existing links.
pub fn ensure(config: &Config) -> Result<()> {
    ensure_with(config, &SystemNamespaceOps)
}

/// Minimal host operations needed to set up namespace networking.
///
/// The production implementation shells out to Linux tools; tests inject a fake
/// implementation so command sequencing can be verified without touching the host.
trait NamespaceOps {
    fn namespace_exists(&self, namespace: &str) -> Result<bool>;
    fn link_exists(&self, link_name: &str) -> Result<bool>;
    fn link_exists_in_namespace(&self, namespace: &str, link_name: &str) -> Result<bool>;
    fn run(&self, program: &str, args: &[&str]) -> Result<()>;
}

/// Performs namespace reconciliation using the supplied operation backend.
fn ensure_with(config: &Config, ops: &dyn NamespaceOps) -> Result<()> {
    if !ops.namespace_exists(&config.namespace)? {
        ops.run("ip", &["netns", "add", config.namespace.as_str()])?;
    }

    let host_veth = config.host_veth_name();
    let ns_veth = config.ns_veth_name();
    if !ops.link_exists(&host_veth)? {
        ops.run(
            "ip",
            &[
                "link",
                "add",
                host_veth.as_str(),
                "type",
                "veth",
                "peer",
                "name",
                ns_veth.as_str(),
            ],
        )?;
    }

    if !ops.link_exists_in_namespace(&config.namespace, &ns_veth)? {
        ops.run(
            "ip",
            &[
                "link",
                "set",
                ns_veth.as_str(),
                "netns",
                config.namespace.as_str(),
            ],
        )?;
    }

    ops.run(
        "ip",
        &[
            "addr",
            "replace",
            config.host_veth_ip.as_str(),
            "dev",
            host_veth.as_str(),
        ],
    )?;
    ops.run("ip", &["link", "set", host_veth.as_str(), "up"])?;

    ops.run(
        "ip",
        &[
            "netns",
            "exec",
            config.namespace.as_str(),
            "ip",
            "addr",
            "replace",
            config.ns_veth_ip.as_str(),
            "dev",
            ns_veth.as_str(),
        ],
    )?;
    ops.run(
        "ip",
        &[
            "netns",
            "exec",
            config.namespace.as_str(),
            "ip",
            "link",
            "set",
            ns_veth.as_str(),
            "up",
        ],
    )?;
    ops.run(
        "ip",
        &[
            "netns",
            "exec",
            config.namespace.as_str(),
            "ip",
            "link",
            "set",
            "lo",
            "up",
        ],
    )?;
    ops.run(
        "ip",
        &[
            "netns",
            "exec",
            config.namespace.as_str(),
            "ip",
            "route",
            "replace",
            "default",
            "via",
            config.ns_host_ip(),
        ],
    )?;

    ops.run("sysctl", &["-w", "net.ipv4.ip_forward=1"])?;
    ops.run(
        "ip",
        &[
            "netns",
            "exec",
            config.namespace.as_str(),
            "sysctl",
            "-w",
            "net.ipv4.ip_forward=1",
        ],
    )?;

    Ok(())
}

/// Production namespace operation backend backed by `ip` and `sysctl`.
struct SystemNamespaceOps;

impl NamespaceOps for SystemNamespaceOps {
    /// Checks `ip netns list` for the configured namespace name.
    fn namespace_exists(&self, namespace: &str) -> Result<bool> {
        let output = command::run("ip", ["netns", "list"])?;
        Ok(output
            .stdout
            .lines()
            .any(|line| line.split_whitespace().next() == Some(namespace)))
    }

    /// Checks whether a link exists in the host namespace.
    fn link_exists(&self, link_name: &str) -> Result<bool> {
        let output = std::process::Command::new("ip")
            .args(["link", "show", link_name])
            .output()?;
        Ok(output.status.success())
    }

    /// Checks whether a link exists inside the forwarding namespace.
    fn link_exists_in_namespace(&self, namespace: &str, link_name: &str) -> Result<bool> {
        let output = std::process::Command::new("ip")
            .args(["netns", "exec", namespace, "ip", "link", "show", link_name])
            .output()?;
        Ok(output.status.success())
    }

    /// Runs a host command and discards stdout on success.
    fn run(&self, program: &str, args: &[&str]) -> Result<()> {
        command::run(program, args.iter().copied()).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::config::{Config, Protocol, Quota, RuleConfig};

    #[derive(Default)]
    struct FakeNamespaceOps {
        namespace_exists: bool,
        link_exists: bool,
        link_exists_in_namespace: bool,
        calls: RefCell<Vec<String>>,
    }

    impl NamespaceOps for FakeNamespaceOps {
        fn namespace_exists(&self, _namespace: &str) -> Result<bool> {
            Ok(self.namespace_exists)
        }

        fn link_exists(&self, _link_name: &str) -> Result<bool> {
            Ok(self.link_exists)
        }

        fn link_exists_in_namespace(&self, _namespace: &str, _link_name: &str) -> Result<bool> {
            Ok(self.link_exists_in_namespace)
        }

        fn run(&self, program: &str, args: &[&str]) -> Result<()> {
            self.calls
                .borrow_mut()
                .push(format!("{program} {}", args.join(" ")));
            Ok(())
        }
    }

    fn sample_config() -> Config {
        Config {
            namespace: "fwd".to_string(),
            host_interface: "eth0".to_string(),
            host_veth_ip: "10.200.0.1/30".to_string(),
            ns_veth_ip: "10.200.0.2/30".to_string(),
            state_path: "/tmp/xelay-state.json".into(),
            poll_interval_secs: 2,
            rules: vec![RuleConfig {
                name: "svc".to_string(),
                listen_port: 5000,
                protocols: vec![Protocol::Tcp],
                target: None,
                target_host: "1.2.3.4".to_string(),
                target_port: 80,
                quota_in: Quota(1),
                quota_out: Quota(1),
                max_tcp_connections: 1,
                max_udp_flows: 1,
                enabled: true,
            }],
        }
    }

    #[test]
    fn ensure_runs_full_setup_when_missing() {
        let ops = FakeNamespaceOps::default();
        ensure_with(&sample_config(), &ops).unwrap();
        let calls = ops.calls.borrow();
        assert!(calls.iter().any(|c| c.contains("ip netns add fwd")));
        assert!(calls.iter().any(|c| c.contains("ip link add fwd-host type veth peer name fwd-ns")));
        assert!(calls.iter().any(|c| c.contains("sysctl -w net.ipv4.ip_forward=1")));
    }

    #[test]
    fn ensure_skips_create_steps_when_objects_exist() {
        let ops = FakeNamespaceOps {
            namespace_exists: true,
            link_exists: true,
            link_exists_in_namespace: true,
            calls: RefCell::new(Vec::new()),
        };
        ensure_with(&sample_config(), &ops).unwrap();
        let calls = ops.calls.borrow();
        assert!(!calls.iter().any(|c| c.contains("netns add")));
        assert!(!calls.iter().any(|c| c.contains("link add")));
        assert!(!calls.iter().any(|c| c.contains("link set fwd-ns netns")));
        assert!(calls.iter().any(|c| c.contains("addr replace 10.200.0.1/30 dev fwd-host")));
    }
}
