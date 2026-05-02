use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// On-disk state file containing persisted controller state.
///
/// The path is skipped during serialization because it is runtime metadata, not part
/// of the stored state schema.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleStateFile {
    pub state: ControllerState,
    #[serde(skip)]
    pub path: PathBuf,
}

impl RuleStateFile {
    /// Loads state from disk or creates empty state if the file does not exist.
    ///
    /// The parent directory is created so the caller can immediately save updated
    /// counters after a reconciliation pass.
    pub fn load(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create state directory {}", parent.display()))?;
        }

        if path.exists() {
            let raw = fs::read_to_string(path)
                .with_context(|| format!("failed to read state file {}", path.display()))?;
            let mut file: RuleStateFile =
                serde_json::from_str(&raw).context("failed to parse state file")?;
            file.path = path.to_path_buf();
            Ok(file)
        } else {
            Ok(Self {
                state: ControllerState::default(),
                path: path.to_path_buf(),
            })
        }
    }

    /// Writes the state file as pretty JSON.
    pub fn save(&self) -> Result<()> {
        let serialized = serde_json::to_string_pretty(self)?;
        fs::write(&self.path, serialized)
            .with_context(|| format!("failed to write state file {}", self.path.display()))
    }
}

/// Persisted state for every configured forwarding rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ControllerState {
    pub rules: BTreeMap<String, RuleEntryState>,
}

impl ControllerState {
    /// Returns a mutable rule entry, creating default state when first seen.
    pub fn ensure_rule(&mut self, name: &str) -> &mut RuleEntryState {
        self.rules.entry(name.to_string()).or_default()
    }

    /// Returns the current runtime state for a rule if it has been observed.
    pub fn rule_state(&self, name: &str) -> Option<&RuleRuntimeState> {
        self.rules.get(name).map(|entry| &entry.runtime)
    }
}

/// Persisted counters and runtime decision for one forwarding rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEntryState {
    pub counters: RuleDirectionCounters,
    pub runtime: RuleRuntimeState,
}

impl Default for RuleEntryState {
    /// New rules start enabled with zero accounting state.
    fn default() -> Self {
        Self {
            counters: RuleDirectionCounters::default(),
            runtime: RuleRuntimeState::enabled(),
        }
    }
}

/// Cumulative in/out byte totals plus per-counter kernel baselines.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleDirectionCounters {
    pub in_bytes: u64,
    pub out_bytes: u64,
    pub baselines: BTreeMap<String, u64>,
}

/// Runtime enforcement state used when rendering nftables rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleRuntimeState {
    pub reason: String,
    pub accepting_new: bool,
    pub forwarding_enabled: bool,
}

impl RuleRuntimeState {
    /// Rule is accepting new flows and forwarding existing flows.
    pub fn enabled() -> Self {
        Self {
            reason: "enabled".to_string(),
            accepting_new: true,
            forwarding_enabled: true,
        }
    }

    /// Quota has been reached: block new flows but keep TCP drainable.
    pub fn quota_blocked() -> Self {
        Self {
            reason: "quota-blocked".to_string(),
            accepting_new: false,
            forwarding_enabled: true,
        }
    }

    /// TCP connection cap has been reached: block new TCP but keep established flows.
    pub fn tcp_limit_blocked() -> Self {
        Self {
            reason: "tcp-limit-blocked".to_string(),
            accepting_new: false,
            forwarding_enabled: true,
        }
    }

    /// UDP flow cap has been reached: drop new and existing UDP forwarding.
    pub fn udp_limit_blocked() -> Self {
        Self {
            reason: "udp-limit-blocked".to_string(),
            accepting_new: false,
            forwarding_enabled: false,
        }
    }

    /// Config disabled the rule entirely.
    pub fn disabled_by_config() -> Self {
        Self {
            reason: "disabled-by-config".to_string(),
            accepting_new: false,
            forwarding_enabled: false,
        }
    }

    /// Returns whether prerouting should accept and DNAT new flows.
    pub fn accepting_new(&self) -> bool {
        self.accepting_new
    }

    /// Returns whether forward-chain accept rules should remain installed.
    pub fn forwarding_enabled(&self) -> bool {
        self.forwarding_enabled
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn ensure_rule_creates_and_returns_entry() {
        let mut state = ControllerState::default();
        let entry = state.ensure_rule("svc");
        entry.counters.in_bytes = 42;

        assert_eq!(state.rules["svc"].counters.in_bytes, 42);
        assert_eq!(state.rule_state("svc").unwrap().reason, "enabled");
    }

    #[test]
    fn runtime_state_flags_match_behavior() {
        assert!(RuleRuntimeState::enabled().accepting_new());
        assert!(RuleRuntimeState::enabled().forwarding_enabled());
        assert!(!RuleRuntimeState::quota_blocked().accepting_new());
        assert!(RuleRuntimeState::quota_blocked().forwarding_enabled());
        assert!(!RuleRuntimeState::udp_limit_blocked().forwarding_enabled());
    }

    #[test]
    fn state_file_round_trip_preserves_state() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("xelay-state-{nonce}.json"));

        let mut file = RuleStateFile::load(&path).unwrap();
        let entry = file.state.ensure_rule("svc");
        entry.counters.in_bytes = 12;
        entry.counters.out_bytes = 34;
        entry.runtime = RuleRuntimeState::tcp_limit_blocked();
        file.save().unwrap();

        let loaded = RuleStateFile::load(&path).unwrap();
        let loaded_entry = &loaded.state.rules["svc"];
        assert_eq!(loaded_entry.counters.in_bytes, 12);
        assert_eq!(loaded_entry.counters.out_bytes, 34);
        assert_eq!(loaded_entry.runtime.reason, "tcp-limit-blocked");

        let _ = std::fs::remove_file(path);
    }
}
