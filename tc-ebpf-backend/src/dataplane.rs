use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use aya::maps::HashMap as AyaHashMap;
use aya::programs::tc::{qdisc_add_clsact, qdisc_detach_program, TcAttachType};
use aya::programs::SchedClassifier;
use aya::Ebpf;

use crate::config::Config;
use crate::interface;
use crate::model::{
    CounterKey, CounterValue, RuleKey, RuleValue, SettingsValue, COUNTERS_MAP, PROGRAM_NAME,
    RULES_MAP, SETTINGS_HOST_IPV4, SETTINGS_MAP,
};
use crate::state::ControllerState;

#[derive(Debug, Clone)]
pub struct CounterSample {
    pub rule_id: u32,
    pub protocol: u8,
    pub direction: u8,
    pub packets: u64,
    pub bytes: u64,
}

pub trait Dataplane {
    fn check(&self, config: &Config) -> Result<Vec<CheckEntry>>;
    fn apply(&mut self, config: &Config, state: &ControllerState) -> Result<()>;
    fn read_counters(&mut self) -> Result<Vec<CounterSample>>;
    fn clean(&mut self, config: &Config) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct CheckEntry {
    pub name: String,
    pub result: String,
}

pub struct AyaDataplane {
    bpf: Option<Ebpf>,
    object_path: PathBuf,
}

impl AyaDataplane {
    pub fn new(object_path: PathBuf) -> Self {
        Self {
            bpf: None,
            object_path,
        }
    }

    fn load(&mut self) -> Result<&mut Ebpf> {
        if self.bpf.is_none() {
            self.bpf = Some(Ebpf::load_file(&self.object_path).with_context(|| {
                format!("failed to load BPF object {}", self.object_path.display())
            })?);
        }
        Ok(self.bpf.as_mut().expect("BPF object loaded above"))
    }
}

impl Dataplane for AyaDataplane {
    fn check(&self, config: &Config) -> Result<Vec<CheckEntry>> {
        let mut checks = Vec::new();
        checks.push(CheckEntry {
            name: "root".to_string(),
            result: if unsafe { libc::geteuid() } == 0 {
                "ok".to_string()
            } else {
                "missing".to_string()
            },
        });
        checks.push(CheckEntry {
            name: format!("interface.{}", config.host_interface),
            result: if interface::interface_exists(&config.host_interface) {
                "ok".to_string()
            } else {
                "missing".to_string()
            },
        });
        checks.push(CheckEntry {
            name: "bpffs".to_string(),
            result: if Path::new("/sys/fs/bpf").exists() {
                "ok".to_string()
            } else {
                "missing".to_string()
            },
        });
        checks.push(CheckEntry {
            name: "bpf_object".to_string(),
            result: if config.bpf_object_path.exists() {
                "ok".to_string()
            } else {
                "missing".to_string()
            },
        });
        checks.push(CheckEntry {
            name: "config.rules".to_string(),
            result: config.rules.len().to_string(),
        });
        Ok(checks)
    }

    fn apply(&mut self, config: &Config, state: &ControllerState) -> Result<()> {
        interface::ensure_root()?;
        let host_ip = interface::interface_ipv4(&config.host_interface)?;
        let bpf = self.load()?;

        qdisc_add_clsact(&config.host_interface).with_context(|| {
            format!("failed to create clsact qdisc on {}", config.host_interface)
        })?;

        {
            let program: &mut SchedClassifier = bpf
                .program_mut(PROGRAM_NAME)
                .context("missing TC classifier program")?
                .try_into()?;
            program.load()?;
            program
                .attach(&config.host_interface, TcAttachType::Ingress)
                .with_context(|| {
                    format!("failed to attach TC program to {}", config.host_interface)
                })?;
        }

        let mut rules: AyaHashMap<_, RuleKey, RuleValue> =
            AyaHashMap::try_from(bpf.map_mut(RULES_MAP).context("missing RULES map")?)?;
        for (rule_id, rule) in config.rules.iter().enumerate() {
            let runtime = state.rules.get(&rule.name).map(|entry| &entry.runtime);
            let enabled = runtime
                .map(|runtime| runtime.accepting_new && runtime.forwarding_enabled)
                .unwrap_or(rule.enabled);
            for protocol in &rule.protocols {
                let key = RuleKey::new(*protocol, rule.listen_port);
                let value = RuleValue::new(
                    rule_id as u32,
                    enabled,
                    rule.target_ipv4()?,
                    rule.target_port,
                    rule.listen_port,
                );
                rules.insert(key, value, 0)?;
            }
        }

        let mut settings: AyaHashMap<_, _, SettingsValue> =
            AyaHashMap::try_from(bpf.map_mut(SETTINGS_MAP).context("missing SETTINGS map")?)?;
        settings.insert(
            SETTINGS_HOST_IPV4,
            SettingsValue {
                host_ip_be: u32::from_be_bytes(host_ip.octets()),
            },
            0,
        )?;

        Ok(())
    }

    fn read_counters(&mut self) -> Result<Vec<CounterSample>> {
        let bpf = self.load()?;
        let counters: AyaHashMap<_, CounterKey, CounterValue> =
            AyaHashMap::try_from(bpf.map(COUNTERS_MAP).context("missing COUNTERS map")?)?;

        let mut samples = Vec::new();
        for item in counters.iter() {
            let (key, value) = item?;
            samples.push(CounterSample {
                rule_id: key.rule_id,
                protocol: key.protocol,
                direction: key.direction,
                packets: value.packets,
                bytes: value.bytes,
            });
        }
        Ok(samples)
    }

    fn clean(&mut self, config: &Config) -> Result<()> {
        let _ = qdisc_detach_program(&config.host_interface, TcAttachType::Ingress, PROGRAM_NAME);
        self.bpf = None;
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use std::cell::RefCell;

    use super::*;

    #[derive(Default)]
    pub struct FakeDataplane {
        pub checks: Vec<CheckEntry>,
        pub samples: Vec<CounterSample>,
        pub calls: RefCell<Vec<String>>,
    }

    impl Dataplane for FakeDataplane {
        fn check(&self, _config: &Config) -> Result<Vec<CheckEntry>> {
            self.calls.borrow_mut().push("check".to_string());
            Ok(self.checks.clone())
        }

        fn apply(&mut self, _config: &Config, _state: &ControllerState) -> Result<()> {
            self.calls.borrow_mut().push("apply".to_string());
            Ok(())
        }

        fn read_counters(&mut self) -> Result<Vec<CounterSample>> {
            self.calls.borrow_mut().push("read_counters".to_string());
            Ok(self.samples.clone())
        }

        fn clean(&mut self, _config: &Config) -> Result<()> {
            self.calls.borrow_mut().push("clean".to_string());
            Ok(())
        }
    }
}
