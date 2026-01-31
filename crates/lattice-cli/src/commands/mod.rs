//! CLI commands

use std::fmt::Display;

use lattice_operator::crd::ProviderType;

use crate::{Error, Result};

pub mod install;
pub mod kind_utils;
pub mod uninstall;

/// Build clusterctl init arguments for a given provider type.
///
/// Shared between install and uninstall commands to ensure consistent
/// CAPI provider initialization.
pub fn clusterctl_init_args(provider: ProviderType) -> Vec<String> {
    let infra_arg = match provider {
        ProviderType::Docker => "--infrastructure=docker",
        ProviderType::Proxmox => "--infrastructure=proxmox",
        ProviderType::OpenStack => "--infrastructure=openstack",
        ProviderType::Aws => "--infrastructure=aws",
        ProviderType::Gcp => "--infrastructure=gcp",
        ProviderType::Azure => "--infrastructure=azure",
    };

    let config_path = env!("CLUSTERCTL_CONFIG");

    let mut args = vec![
        "init".to_string(),
        infra_arg.to_string(),
        "--bootstrap=kubeadm,rke2".to_string(),
        "--control-plane=kubeadm,rke2".to_string(),
        format!("--config={}", config_path),
        "--wait-providers".to_string(),
    ];

    if provider == ProviderType::Proxmox {
        args.push("--ipam=in-cluster".to_string());
    }

    args
}

/// Extension trait to convert errors with Display to CLI Error::CommandFailed.
///
/// This reduces boilerplate for the common pattern of `.map_err(|e| Error::command_failed(e.to_string()))`.
pub trait CommandErrorExt<T> {
    /// Convert an error to `Error::CommandFailed` using its Display implementation.
    fn cmd_err(self) -> Result<T>;
}

impl<T, E: Display> CommandErrorExt<T> for std::result::Result<T, E> {
    fn cmd_err(self) -> Result<T> {
        self.map_err(|e| Error::command_failed(e.to_string()))
    }
}

/// Generate a short readable run ID (6 hex chars).
///
/// Used by install/uninstall commands to create unique kind cluster names
/// and temp files for parallel execution.
pub fn generate_run_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u32;
    let pid = std::process::id();
    // Combine timestamp and pid, take 6 hex chars for readability
    format!("{:06x}", (timestamp ^ pid) & 0xFFFFFF)
}
