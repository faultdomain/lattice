//! `lattice login` — authenticate and save a proxy kubeconfig for all future commands.
//!
//! Discovers the Lattice proxy from a management cluster, fetches a multi-context
//! kubeconfig containing all accessible clusters, and saves it to `~/.lattice/`.
//! Subsequent commands (`lattice get`, `lattice backup`, etc.) automatically use
//! this saved kubeconfig via the resolution chain.
//!
//! # Usage
//!
//! ```bash
//! # First-time setup (from a management cluster kubeconfig)
//! lattice login --kubeconfig /path/to/mgmt-kubeconfig
//!
//! # Direct mode (explicit proxy URL + token)
//! lattice login --server https://lattice.example.com --token <token>
//!
//! # Re-fetch clusters using saved config
//! lattice login --refresh
//! ```

use clap::Args;

use crate::commands::proxy::{
    extract_cluster_names, fetch_kubeconfig, resolve_proxy_connection, ProxyConnectionParams,
};
use crate::config::{self, LatticeConfig};
use crate::{Error, Result};

/// Authenticate with a Lattice cluster and save kubeconfig locally
#[derive(Args, Debug)]
pub struct LoginArgs {
    /// Path to a management cluster kubeconfig (for auto-discovery)
    #[arg(long)]
    pub kubeconfig: Option<String>,

    /// Lattice proxy server URL (overrides auto-discovery)
    #[arg(long)]
    pub server: Option<String>,

    /// Bearer token for authentication (overrides auto-generated SA token)
    #[arg(long)]
    pub token: Option<String>,

    /// Namespace of the ServiceAccount
    #[arg(long, default_value = "lattice-system")]
    pub namespace: String,

    /// ServiceAccount name
    #[arg(long, default_value = "default")]
    pub service_account: String,

    /// Re-fetch kubeconfig using previously saved config
    #[arg(long)]
    pub refresh: bool,

    /// Skip TLS certificate verification (for development)
    #[arg(long, default_value = "false")]
    pub insecure: bool,
}

/// Run the login command.
pub async fn run(args: LoginArgs) -> Result<()> {
    let params = build_params(args)?;
    let insecure = params.insecure;
    let uses_port_forward = params.port_forward;
    let mgmt_kubeconfig = params.kubeconfig.clone();
    let proxy_server_override = params.server.clone();

    let (server, token, _port_forward) = resolve_proxy_connection(&params).await?;
    let kubeconfig_json = fetch_kubeconfig(&server, &token, insecure).await?;

    // Extract cluster names for display
    let cluster_names = extract_cluster_names(&kubeconfig_json)?;

    // Save kubeconfig
    let kc_path = config::save_kubeconfig(&kubeconfig_json)?;

    // Save config
    let cfg = LatticeConfig {
        mgmt_kubeconfig,
        proxy_server: Some(proxy_server_override.unwrap_or(server)),
        current_cluster: cluster_names.first().cloned(),
        uses_port_forward,
        last_login: Some(chrono::Utc::now().to_rfc3339()),
    };
    config::save_config(&cfg)?;

    // Print success
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
    eprintln!("Use `lattice use <cluster>` to switch the default cluster.");
    eprintln!("Use `lattice get clusters` to see cluster status.");

    Ok(())
}

/// Build `ProxyConnectionParams` from login args, handling `--refresh`.
fn build_params(args: LoginArgs) -> Result<ProxyConnectionParams> {
    if args.refresh {
        let existing = config::load_config()?;
        let kubeconfig = args.kubeconfig.or(existing.mgmt_kubeconfig);
        let server = args.server.or(existing.proxy_server);

        if kubeconfig.is_none() && server.is_none() {
            return Err(Error::command_failed(
                "no saved login found. Run `lattice login --kubeconfig <path>` first.",
            ));
        }

        return Ok(ProxyConnectionParams {
            kubeconfig,
            server,
            token: args.token,
            namespace: args.namespace,
            service_account: args.service_account,
            port_forward: existing.uses_port_forward,
            insecure: args.insecure,
        });
    }

    // Normal login: require kubeconfig or server+token
    if args.kubeconfig.is_none() && (args.server.is_none() || args.token.is_none()) {
        return Err(Error::validation(
            "--kubeconfig is required (or provide both --server and --token for direct mode)",
        ));
    }

    Ok(ProxyConnectionParams {
        kubeconfig: args.kubeconfig,
        server: args.server,
        token: args.token,
        namespace: args.namespace,
        service_account: args.service_account,
        port_forward: false,
        insecure: args.insecure,
    })
}
