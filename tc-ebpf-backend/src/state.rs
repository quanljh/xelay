use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StateFile {
    pub state: ControllerState,
    #[serde(skip)]
    pub path: PathBuf,
}

impl StateFile {
    pub fn load(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create state directory {}", parent.display())
            })?;
        }

        if path.exists() {
            let raw = fs::read_to_string(path)
                .with_context(|| format!("failed to read state file {}", path.display()))?;
            let mut file: Self =
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

    pub fn save(&self) -> Result<()> {
        let serialized = serde_json::to_string_pretty(self)?;
        fs::write(&self.path, serialized)
            .with_context(|| format!("failed to write state file {}", self.path.display()))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ControllerState {
    pub rules: BTreeMap<String, RuleEntryState>,
}

impl ControllerState {
    pub fn ensure_rule(&mut self, name: &str) -> &mut RuleEntryState {
        self.rules.entry(name.to_string()).or_default()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleEntryState {
    pub counters: RuleCounters,
    pub runtime: RuleRuntimeState,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleCounters {
    pub in_bytes: u64,
    pub out_bytes: u64,
    pub in_packets: u64,
    pub out_packets: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleRuntimeState {
    pub reason: String,
    pub accepting_new: bool,
    pub forwarding_enabled: bool,
}

impl Default for RuleRuntimeState {
    fn default() -> Self {
        Self::enabled()
    }
}

impl RuleRuntimeState {
    pub fn enabled() -> Self {
        Self {
            reason: "enabled".to_string(),
            accepting_new: true,
            forwarding_enabled: true,
        }
    }

    pub fn disabled_by_config() -> Self {
        Self {
            reason: "disabled-by-config".to_string(),
            accepting_new: false,
            forwarding_enabled: false,
        }
    }

    pub fn enabled_with_deferred_limits() -> Self {
        Self {
            reason: "enabled-limits-deferred".to_string(),
            accepting_new: true,
            forwarding_enabled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn state_file_round_trip_preserves_counters() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("xelay-tc-state-{nonce}.json"));

        let mut file = StateFile::load(&path).unwrap();
        let entry = file.state.ensure_rule("svc");
        entry.counters.in_bytes = 12;
        entry.counters.out_bytes = 34;
        entry.runtime = RuleRuntimeState::enabled_with_deferred_limits();
        file.save().unwrap();

        let loaded = StateFile::load(&path).unwrap();
        let entry = &loaded.state.rules["svc"];
        assert_eq!(entry.counters.in_bytes, 12);
        assert_eq!(entry.counters.out_bytes, 34);
        assert_eq!(entry.runtime.reason, "enabled-limits-deferred");

        let _ = fs::remove_file(path);
    }
}
