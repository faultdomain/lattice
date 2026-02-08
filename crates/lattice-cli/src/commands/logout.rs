//! Logout command — clear saved credentials and proxy kubeconfig.
//!
//! Removes `~/.lattice/kubeconfig` and `~/.lattice/config.json` so subsequent
//! commands fall back to the default kubeconfig resolution chain.

use clap::Args;
use tracing::info;

use crate::Result;

/// Clear saved credentials and proxy kubeconfig
#[derive(Args, Debug)]
pub struct LogoutArgs {}

pub async fn run(_args: LogoutArgs) -> Result<()> {
    let mut removed = false;

    if let Ok(path) = crate::config::kubeconfig_path() {
        match std::fs::remove_file(&path) {
            Ok(()) => {
                info!("Removed {}", path.display());
                removed = true;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(crate::Error::command_failed(format!(
                    "failed to remove {}: {}",
                    path.display(),
                    e
                )));
            }
        }
    }

    if let Ok(path) = crate::config::config_path() {
        match std::fs::remove_file(&path) {
            Ok(()) => {
                info!("Removed {}", path.display());
                removed = true;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(crate::Error::command_failed(format!(
                    "failed to remove {}: {}",
                    path.display(),
                    e
                )));
            }
        }
    }

    if removed {
        println!("Logged out. Saved credentials have been removed.");
    } else {
        println!("Already logged out (no saved credentials found).");
    }

    Ok(())
}
