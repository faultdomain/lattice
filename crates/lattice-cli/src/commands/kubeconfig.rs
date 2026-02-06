//! `lattice kubeconfig` - fetch a fresh kubeconfig from the Lattice proxy
//!
//! Connects to a parent cluster, discovers the proxy endpoint from the
//! LatticeCluster CRD, creates a ServiceAccount token, and fetches a
//! multi-context kubeconfig with all accessible clusters.
//!
//! # Usage
//!
//! ```bash
//! # From a management cluster kubeconfig (auto-discovers proxy URL + token)
//! lattice kubeconfig --kubeconfig /path/to/mgmt-kubeconfig
//!
//! # Override proxy URL (e.g., external ingress instead of LB IP)
//! lattice kubeconfig --kubeconfig /path/to/mgmt --server https://lattice.example.com
//!
//! # Direct mode with explicit server + token (no cluster access needed)
//! lattice kubeconfig --server https://lattice.example.com --token <token>
//!
//! # Save to file
//! lattice kubeconfig --kubeconfig /path/to/mgmt -o /tmp/lattice-kubeconfig
//! ```

use clap::Args;
use kube::api::ListParams;
use kube::Api;
use lattice_operator::crd::LatticeCluster;
use tracing::debug;

use crate::{Error, Result};

/// Fetch a kubeconfig from the Lattice proxy's /kubeconfig endpoint
#[derive(Args, Debug)]
pub struct KubeconfigArgs {
    /// Path to a management cluster kubeconfig.
    /// Auto-discovers the proxy URL and creates a ServiceAccount token.
    #[arg(long, env = "KUBECONFIG")]
    pub kubeconfig: Option<String>,

    /// Lattice proxy server URL (overrides auto-discovery from the cluster)
    #[arg(long)]
    pub server: Option<String>,

    /// Bearer token for authentication (overrides auto-generated SA token)
    #[arg(long)]
    pub token: Option<String>,

    /// Namespace of the ServiceAccount (used with --kubeconfig)
    #[arg(long, default_value = "lattice-system")]
    pub namespace: String,

    /// ServiceAccount name (used with --kubeconfig)
    #[arg(long, default_value = "default")]
    pub service_account: String,

    /// Output file path (default: stdout)
    #[arg(short, long)]
    pub output: Option<String>,

    /// Skip TLS certificate verification (for development)
    #[arg(long, default_value = "false")]
    pub insecure: bool,
}

/// Run the kubeconfig command
pub async fn run(args: KubeconfigArgs) -> Result<()> {
    let (server, token) = resolve_server_and_token(&args).await?;
    let kubeconfig_json = fetch_kubeconfig(&server, &token, args.insecure).await?;

    match &args.output {
        Some(path) => {
            std::fs::write(path, &kubeconfig_json).map_err(|e| {
                Error::command_failed(format!("failed to write kubeconfig to {}: {}", path, e))
            })?;
            eprintln!("Kubeconfig written to {}", path);
        }
        None => {
            println!("{}", kubeconfig_json);
        }
    }

    Ok(())
}

/// Resolve the proxy server URL and bearer token.
///
/// Priority:
/// - `--server` overrides auto-discovered proxy URL
/// - `--token` overrides auto-generated SA token
/// - `--kubeconfig` provides both via cluster introspection
async fn resolve_server_and_token(args: &KubeconfigArgs) -> Result<(String, String)> {
    // If both server and token are explicit, no cluster access needed
    if let (Some(server), Some(token)) = (&args.server, &args.token) {
        return Ok((server.clone(), token.clone()));
    }

    // We need a kubeconfig to discover server and/or create a token
    let kubeconfig_path = args.kubeconfig.as_deref().ok_or_else(|| {
        Error::validation(
            "--kubeconfig is required (or provide both --server and --token for direct mode)",
        )
    })?;

    // Auto-discover proxy URL from the cluster if not provided
    let server = match &args.server {
        Some(s) => s.clone(),
        None => {
            debug!("Discovering proxy endpoint from cluster");
            discover_proxy_endpoint(kubeconfig_path).await?
        }
    };

    // Auto-generate SA token if not provided
    let token = match &args.token {
        Some(t) => t.clone(),
        None => {
            debug!(
                "Creating SA token (namespace={}, sa={})",
                args.namespace, args.service_account
            );
            super::create_sa_token(
                kubeconfig_path,
                &args.namespace,
                &args.service_account,
                "1h",
            )?
        }
    };

    Ok((server, token))
}

/// Discover the proxy endpoint from a parent cluster's LatticeCluster CRD.
///
/// Connects to the cluster, finds the self LatticeCluster (the one with
/// `parent_config`), and returns its `proxy_endpoint()`.
async fn discover_proxy_endpoint(kubeconfig_path: &str) -> Result<String> {
    let client = super::kube_client_from_path(kubeconfig_path).await?;

    let api: Api<LatticeCluster> = Api::all(client);
    let clusters = api
        .list(&ListParams::default())
        .await
        .map_err(|e| Error::command_failed(format!("failed to list LatticeCluster CRDs: {}", e)))?
        .items;

    // Find the parent cluster (the one with parent_config)
    let parent = clusters
        .iter()
        .find(|c| c.spec.is_parent())
        .ok_or_else(|| {
            Error::command_failed(
                "no parent cluster found (no LatticeCluster with parent_config). \
                 Use --server to specify the proxy URL manually.",
            )
        })?;

    parent
        .spec
        .parent_config
        .as_ref()
        .and_then(|e| e.proxy_endpoint())
        .ok_or_else(|| {
            Error::command_failed(
                "parent cluster has no proxy endpoint (host not set). \
                 Use --server to specify the proxy URL manually.",
            )
        })
}

/// Fetch kubeconfig JSON from the proxy's /kubeconfig endpoint
async fn fetch_kubeconfig(server: &str, token: &str, insecure: bool) -> Result<String> {
    let client = if insecure {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| Error::command_failed(format!("failed to build HTTP client: {}", e)))?
    } else {
        reqwest::Client::new()
    };

    let url = format!("{}/kubeconfig", server.trim_end_matches('/'));
    debug!("Fetching kubeconfig from {}", url);

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| Error::command_failed(format!("failed to connect to {}: {}", url, e)))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(Error::command_failed(format!(
            "proxy returned {} from {}: {}",
            status, url, body
        )));
    }

    let body = response
        .text()
        .await
        .map_err(|e| Error::command_failed(format!("failed to read response body: {}", e)))?;

    // Validate it's valid JSON before returning
    serde_json::from_str::<serde_json::Value>(&body)
        .map_err(|e| Error::command_failed(format!("proxy returned invalid JSON: {}", e)))?;

    Ok(body)
}
