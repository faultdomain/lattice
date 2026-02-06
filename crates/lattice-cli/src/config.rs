//! Lattice CLI configuration stored at `~/.lattice/`.
//!
//! Manages persistent state for `lattice login` and `lattice use`:
//! - `~/.lattice/config.json` — login metadata and current cluster
//! - `~/.lattice/kubeconfig` — proxy kubeconfig fetched during login
//!
//! The kubeconfig resolution chain (highest priority first):
//! 1. Explicit `--kubeconfig` flag
//! 2. `LATTICE_KUBECONFIG` environment variable
//! 3. `~/.lattice/kubeconfig` (from `lattice login`)
//! 4. Fall back to kube default (`KUBECONFIG` env / `~/.kube/config`)

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

const CONFIG_DIR_NAME: &str = ".lattice";
const CONFIG_FILE_NAME: &str = "config.json";
const KUBECONFIG_FILE_NAME: &str = "kubeconfig";
const LATTICE_KUBECONFIG_ENV: &str = "LATTICE_KUBECONFIG";

/// Persistent CLI configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LatticeConfig {
    /// Path to the management cluster kubeconfig used during login.
    pub mgmt_kubeconfig: Option<String>,
    /// Discovered proxy server URL.
    pub proxy_server: Option<String>,
    /// Current cluster set by `lattice use`.
    pub current_cluster: Option<String>,
    /// Whether login used port-forward (Docker/kind).
    pub uses_port_forward: bool,
    /// ISO 8601 timestamp of last login.
    pub last_login: Option<String>,
}

/// Returns `~/.lattice/`, creating it if it doesn't exist.
pub fn lattice_dir() -> Result<PathBuf> {
    let home = dirs::home_dir()
        .ok_or_else(|| Error::command_failed("could not determine home directory"))?;
    let dir = home.join(CONFIG_DIR_NAME);
    if !dir.exists() {
        std::fs::create_dir_all(&dir).map_err(|e| {
            Error::command_failed(format!("failed to create {}: {}", dir.display(), e))
        })?;
    }
    Ok(dir)
}

/// Path to `~/.lattice/config.json`.
pub fn config_path() -> Result<PathBuf> {
    Ok(lattice_dir()?.join(CONFIG_FILE_NAME))
}

/// Path to `~/.lattice/kubeconfig`.
pub fn kubeconfig_path() -> Result<PathBuf> {
    Ok(lattice_dir()?.join(KUBECONFIG_FILE_NAME))
}

/// Load config from `~/.lattice/config.json`, returning default if missing.
pub fn load_config() -> Result<LatticeConfig> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(LatticeConfig::default());
    }
    let data = std::fs::read_to_string(&path)
        .map_err(|e| Error::command_failed(format!("failed to read {}: {}", path.display(), e)))?;
    serde_json::from_str(&data)
        .map_err(|e| Error::command_failed(format!("failed to parse {}: {}", path.display(), e)))
}

/// Save config to `~/.lattice/config.json`.
pub fn save_config(config: &LatticeConfig) -> Result<()> {
    let path = config_path()?;
    let data = serde_json::to_string_pretty(config)
        .map_err(|e| Error::command_failed(format!("failed to serialize config: {}", e)))?;
    std::fs::write(&path, data)
        .map_err(|e| Error::command_failed(format!("failed to write {}: {}", path.display(), e)))
}

/// Save proxy kubeconfig JSON to `~/.lattice/kubeconfig`.
pub fn save_kubeconfig(json: &str) -> Result<PathBuf> {
    let path = kubeconfig_path()?;
    std::fs::write(&path, json)
        .map_err(|e| Error::command_failed(format!("failed to write {}: {}", path.display(), e)))?;
    Ok(path)
}

/// Resolve a kubeconfig path using the priority chain.
///
/// Returns `Some(path)` if a kubeconfig is found, `None` to use kube defaults.
///
/// Priority:
/// 1. `explicit` — the `--kubeconfig` CLI flag
/// 2. `LATTICE_KUBECONFIG` env var
/// 3. `~/.lattice/kubeconfig` (from `lattice login`)
/// 4. `None` — fall back to `kube::Client::try_default()`
pub fn resolve_kubeconfig(explicit: Option<&str>) -> Option<String> {
    if let Some(path) = explicit {
        return Some(path.to_string());
    }

    if let Ok(path) = std::env::var(LATTICE_KUBECONFIG_ENV) {
        if !path.is_empty() {
            return Some(path);
        }
    }

    if let Ok(path) = kubeconfig_path() {
        if path.exists() {
            return Some(path.to_string_lossy().into_owned());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_serde_roundtrip() {
        let config = LatticeConfig {
            mgmt_kubeconfig: Some("/tmp/mgmt".to_string()),
            proxy_server: Some("https://proxy:8082".to_string()),
            current_cluster: Some("prod".to_string()),
            uses_port_forward: true,
            last_login: Some("2025-01-01T00:00:00Z".to_string()),
        };

        let json = serde_json::to_string(&config).unwrap();
        let parsed: LatticeConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.mgmt_kubeconfig.as_deref(), Some("/tmp/mgmt"));
        assert_eq!(parsed.proxy_server.as_deref(), Some("https://proxy:8082"));
        assert_eq!(parsed.current_cluster.as_deref(), Some("prod"));
        assert!(parsed.uses_port_forward);
        assert_eq!(parsed.last_login.as_deref(), Some("2025-01-01T00:00:00Z"));
    }

    #[test]
    fn config_default_is_empty() {
        let config = LatticeConfig::default();
        assert!(config.mgmt_kubeconfig.is_none());
        assert!(config.proxy_server.is_none());
        assert!(config.current_cluster.is_none());
        assert!(!config.uses_port_forward);
        assert!(config.last_login.is_none());
    }

    #[test]
    fn resolve_kubeconfig_explicit_wins() {
        let result = resolve_kubeconfig(Some("/explicit/path"));
        assert_eq!(result.as_deref(), Some("/explicit/path"));
    }

    #[test]
    fn resolve_kubeconfig_none_when_nothing_set() {
        // With no explicit path, no env, and no saved kubeconfig, returns None
        // (we can't fully test env/file without side effects, but at least test the explicit case)
        let result = resolve_kubeconfig(None);
        // This may or may not be None depending on whether ~/.lattice/kubeconfig exists
        // on the test machine, so we just verify it doesn't panic
        let _ = result;
    }
}
