//! `lattice login` — authenticate and save a proxy kubeconfig for all future commands.
//!
//! Fetches a multi-context kubeconfig from the Lattice proxy using a bearer token,
//! and saves it to `~/.lattice/`. Subsequent commands automatically use this
//! saved kubeconfig via the resolution chain.
//!
//! # Usage
//!
//! ```bash
//! lattice login --server https://lattice.example.com --token <token>
//! ```

use clap::Args;

use crate::commands::proxy::{extract_cluster_names, fetch_kubeconfig};
use crate::config::{self, LatticeConfig};
use crate::Result;

/// Authenticate with a Lattice cluster and save kubeconfig locally
#[derive(Args, Debug)]
pub struct LoginArgs {
    /// Lattice proxy server URL
    #[arg(long)]
    pub server: String,

    /// Bearer token for authentication
    #[arg(long)]
    pub token: String,

    /// Skip TLS certificate verification (for development)
    #[arg(long, default_value = "false")]
    pub insecure: bool,
}

/// Run the login command.
pub async fn run(args: LoginArgs) -> Result<()> {
    let kubeconfig_json =
        fetch_kubeconfig(&args.server, &args.token, args.insecure, Some("sa"), 10, false).await?;

    let cluster_names = extract_cluster_names(&kubeconfig_json)?;

    let kc_path = config::save_kubeconfig(&kubeconfig_json)?;

    let cfg = LatticeConfig {
        proxy_server: Some(args.server),
        current_cluster: cluster_names.first().cloned(),
        last_login: Some(chrono::Utc::now().to_rfc3339()),
    };
    config::save_config(&cfg)?;

    eprintln!(
        "Logged in successfully. Kubeconfig saved to {}",
        kc_path.display()
    );
    eprintln!();
    eprintln!("Available clusters:");
    for (i, name) in cluster_names.iter().enumerate() {
        let marker = if i == 0 { " *" } else { "" };
        eprintln!("  - {}{}", name, marker);
    }
    eprintln!();
    eprintln!("Use `kubectl config use-context <cluster>` to switch clusters.");

    Ok(())
}
