//! `lattice use` — switch the default cluster context.
//!
//! Reads `~/.lattice/kubeconfig` (saved by `lattice login`), validates the
//! cluster name exists as a context, and sets it as the current context.
//!
//! # Usage
//!
//! ```bash
//! # List available clusters
//! lattice use
//!
//! # Switch to a cluster
//! lattice use prod-backend
//! ```

use clap::Args;

use crate::config;
use crate::{Error, Result};

/// Switch the default cluster for subsequent commands
#[derive(Args, Debug)]
pub struct UseArgs {
    /// Cluster name to switch to (omit to list available clusters)
    pub cluster: Option<String>,
}

/// Run the use command.
pub async fn run(args: UseArgs) -> Result<()> {
    let kc_path = config::kubeconfig_path()?;
    if !kc_path.exists() {
        return Err(Error::command_failed(
            "no saved kubeconfig found. Run `lattice login` first.",
        ));
    }

    let raw = std::fs::read_to_string(&kc_path).map_err(|e| {
        Error::command_failed(format!("failed to read {}: {}", kc_path.display(), e))
    })?;

    let mut kc: kube::config::Kubeconfig = serde_json::from_str(&raw).map_err(|e| {
        Error::command_failed(format!(
            "failed to parse {}: {}. Try `lattice login --refresh`.",
            kc_path.display(),
            e
        ))
    })?;

    let context_names: Vec<String> = kc
        .contexts
        .iter()
        .filter_map(|c| c.name.clone().into())
        .collect();

    if context_names.is_empty() {
        return Err(Error::command_failed(
            "kubeconfig has no contexts. Run `lattice login --refresh`.",
        ));
    }

    let current_context = kc.current_context.as_deref();

    match args.cluster {
        None => {
            // List available clusters
            println!("Available clusters:");
            for name in &context_names {
                let marker = if current_context == Some(name.as_str()) {
                    " *"
                } else {
                    ""
                };
                println!("  {}{}", name, marker);
            }
            println!();
            println!("Use `lattice use <cluster>` to switch.");
        }
        Some(target) => {
            if !context_names.iter().any(|n| n == &target) {
                return Err(Error::command_failed(format!(
                    "cluster '{}' not found. Available: {}",
                    target,
                    context_names.join(", ")
                )));
            }

            // Update current_context in kubeconfig and re-save
            kc.current_context = Some(target.clone());
            let updated = serde_json::to_string_pretty(&kc).map_err(|e| {
                Error::command_failed(format!("failed to serialize kubeconfig: {}", e))
            })?;
            std::fs::write(&kc_path, updated).map_err(|e| {
                Error::command_failed(format!("failed to write {}: {}", kc_path.display(), e))
            })?;

            // Update config.json
            let mut cfg = config::load_config()?;
            cfg.current_cluster = Some(target.clone());
            config::save_config(&cfg)?;

            println!("Switched to cluster '{}'.", target);
        }
    }

    Ok(())
}
