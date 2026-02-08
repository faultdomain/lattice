//! CLI commands

use std::fmt::Display;
use std::future::Future;
use std::time::{Duration, Instant};

use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Client, Config};
use tracing::{debug, warn};

use crate::{Error, Result};

pub mod get;
pub mod install;
pub mod kind_utils;
pub mod login;
pub mod logout;
pub mod port_forward;
pub mod proxy;
pub mod token;
pub mod uninstall;
pub mod use_cluster;

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

/// Result type for polling check functions.
///
/// - `Ok(Some(value))` - Condition met, return the value
/// - `Ok(None)` - Condition not met yet, keep polling
/// - `Err(e)` - Fatal error, stop polling immediately
pub type PollResult<T> = std::result::Result<Option<T>, String>;

/// Generic timeout-based polling utility.
///
/// Polls a condition function at regular intervals until:
/// - The condition returns `Ok(Some(value))` - returns `Ok(value)`
/// - The timeout is exceeded - returns `Err` with timeout message
/// - The condition returns `Err` - returns that error immediately
///
/// # Arguments
/// * `timeout` - Maximum time to wait for the condition
/// * `interval` - Time between polls
/// * `description` - Human-readable description for error messages
/// * `check_fn` - Async function that returns `PollResult<T>`
///
/// # Example
/// ```ignore
/// let result = wait_with_timeout(
///     Duration::from_secs(60),
///     Duration::from_secs(2),
///     "API server ready",
///     || async {
///         match client.list::<Namespace>().await {
///             Ok(_) => Ok(Some(())),  // Ready
///             Err(e) if is_transient(&e) => Ok(None),  // Keep polling
///             Err(e) => Err(e.to_string()),  // Fatal error
///         }
///     },
/// ).await?;
/// ```
pub async fn wait_with_timeout<T, F, Fut>(
    timeout: Duration,
    interval: Duration,
    description: &str,
    mut check_fn: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = PollResult<T>>,
{
    let start = Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err(Error::command_failed(format!(
                "Timeout waiting for {}",
                description
            )));
        }

        match check_fn().await {
            Ok(Some(value)) => return Ok(value),
            Ok(None) => {
                debug!("Waiting for {}...", description);
                tokio::time::sleep(interval).await;
            }
            Err(e) => {
                return Err(Error::command_failed(format!(
                    "Error waiting for {}: {}",
                    description, e
                )));
            }
        }
    }
}

/// Polls until a resource is deleted (returns 404).
///
/// Similar to `wait_with_timeout` but specifically for waiting on resource deletion.
/// Handles the common pattern of waiting for a Kubernetes resource to be fully removed.
///
/// # Arguments
/// * `timeout` - Maximum time to wait for deletion
/// * `interval` - Time between polls
/// * `description` - Human-readable description for logging
/// * `check_exists` - Async function that returns `Ok(true)` if resource exists,
///   `Ok(false)` if deleted, or `Err` for fatal errors
///
/// # Returns
/// * `Ok(())` - Resource was deleted
/// * `Err` - Timeout or fatal error
pub async fn wait_for_deletion<F, Fut>(
    timeout: Duration,
    interval: Duration,
    description: &str,
    mut check_exists: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::result::Result<bool, String>>,
{
    let start = Instant::now();

    loop {
        if start.elapsed() > timeout {
            warn!(
                "Timeout waiting for {} deletion, proceeding anyway",
                description
            );
            return Ok(());
        }

        match check_exists().await {
            Ok(true) => {
                debug!("{} still exists, waiting...", description);
                tokio::time::sleep(interval).await;
            }
            Ok(false) => {
                debug!("{} deleted", description);
                return Ok(());
            }
            Err(_) => {
                // Treat errors as "deleted" since we can't determine state
                return Ok(());
            }
        }
    }
}

/// Load a [`Kubeconfig`] using the Lattice resolution chain and ensure the proxy is reachable.
///
/// Resolution priority:
/// 1. `explicit` — the `--kubeconfig` CLI flag
/// 2. `LATTICE_KUBECONFIG` env var
/// 3. `~/.lattice/kubeconfig` (from `lattice login`)
/// 4. kube defaults (`KUBECONFIG` env / `~/.kube/config`)
///
/// If the kubeconfig is a proxy kubeconfig with a dead port, a port-forward is
/// auto-started and the server URLs are rewritten. The caller must hold the
/// `PortForward` guard to keep it alive.
pub async fn load_kubeconfig(
    explicit: Option<&str>,
) -> Result<(Kubeconfig, Option<port_forward::PortForward>)> {
    let resolved = crate::config::resolve_kubeconfig(explicit);
    let mut kc = match resolved.as_deref() {
        Some(path) => Kubeconfig::read_from(path).map_err(|e| {
            Error::command_failed(format!("failed to read kubeconfig {}: {}", path, e))
        })?,
        None => Kubeconfig::read()
            .map_err(|e| Error::command_failed(format!("failed to read kubeconfig: {}", e)))?,
    };
    let pf = port_forward::ensure_proxy_reachable(&mut kc).await;
    Ok((kc, pf))
}

/// Build a kube [`Client`] using the Lattice kubeconfig resolution chain.
///
/// If `cluster` is provided, selects that context from the resolved kubeconfig.
///
/// Returns `(Client, Option<PortForward>)`. The caller must hold the `PortForward`
/// guard to keep it alive.
pub async fn resolve_kube_client(
    explicit_kubeconfig: Option<&str>,
    cluster: Option<&str>,
) -> Result<(Client, Option<port_forward::PortForward>)> {
    // No resolved kubeconfig and no cluster context → use kube defaults directly
    if crate::config::resolve_kubeconfig(explicit_kubeconfig).is_none() && cluster.is_none() {
        let client = Client::try_default().await.cmd_err()?;
        return Ok((client, None));
    }

    let (kc, pf) = load_kubeconfig(explicit_kubeconfig).await?;

    let opts = match cluster {
        Some(ctx) => KubeConfigOptions {
            context: Some(ctx.to_string()),
            ..Default::default()
        },
        None => KubeConfigOptions::default(),
    };

    let client = kube_client_from_kubeconfig(kc, &opts).await?;
    Ok((client, pf))
}

/// Build a kube [`Client`] from a kubeconfig file path (default context).
pub async fn kube_client_from_path(path: &str) -> Result<Client> {
    let kubeconfig = Kubeconfig::read_from(path)
        .map_err(|e| Error::command_failed(format!("failed to read kubeconfig {}: {}", path, e)))?;
    kube_client_from_kubeconfig(kubeconfig, &KubeConfigOptions::default()).await
}

/// Build a kube [`Client`] from an already-loaded [`Kubeconfig`] with options.
pub async fn kube_client_from_kubeconfig(
    kubeconfig: Kubeconfig,
    options: &KubeConfigOptions,
) -> Result<Client> {
    let config = Config::from_custom_kubeconfig(kubeconfig, options)
        .await
        .cmd_err()?;
    Client::try_from(config).cmd_err()
}

/// Ensure CAPI providers are installed for the given provider type.
pub async fn ensure_capi_providers(provider: lattice_common::crd::ProviderType) -> Result<()> {
    use lattice_capi::installer::{CapiInstaller, CapiProviderConfig, NativeInstaller};

    let config = CapiProviderConfig::new(provider).cmd_err()?;
    NativeInstaller::new().ensure(&config).await.cmd_err()
}

/// Create a ServiceAccount token using the Kubernetes TokenRequest API.
///
/// Generates a short-lived token for the given ServiceAccount without
/// shelling out to kubectl.
pub async fn create_sa_token_native(
    client: &Client,
    namespace: &str,
    service_account: &str,
    duration_secs: i64,
) -> Result<String> {
    use k8s_openapi::api::authentication::v1::{TokenRequest, TokenRequestSpec};
    use k8s_openapi::api::core::v1::ServiceAccount;
    use kube::Api;

    let sa_api: Api<ServiceAccount> = Api::namespaced(client.clone(), namespace);

    let token_request = TokenRequest {
        metadata: Default::default(),
        spec: TokenRequestSpec {
            audiences: vec![],
            expiration_seconds: Some(duration_secs),
            bound_object_ref: None,
        },
        status: None,
    };

    let result = sa_api
        .create_token_request(service_account, &Default::default(), &token_request)
        .await
        .map_err(|e| Error::command_failed(format!("token request failed: {}", e)))?;

    let token = result
        .status
        .ok_or_else(|| Error::command_failed("token response missing status"))?
        .token;

    if token.is_empty() {
        return Err(Error::command_failed("server returned empty token"));
    }

    Ok(token)
}

/// Parse a human-friendly duration string into seconds.
///
/// Supports `Nh` (hours), `Nm` (minutes), and `Ns` (seconds).
/// Examples: "1h" → 3600, "30m" → 1800, "3600s" → 3600.
pub fn parse_duration(s: &str) -> Result<i64> {
    let s = s.trim();
    if let Some(hours) = s.strip_suffix('h') {
        let n: i64 = hours
            .parse()
            .map_err(|_| Error::validation(format!("invalid duration: {}", s)))?;
        Ok(n * 3600)
    } else if let Some(minutes) = s.strip_suffix('m') {
        let n: i64 = minutes
            .parse()
            .map_err(|_| Error::validation(format!("invalid duration: {}", s)))?;
        Ok(n * 60)
    } else if let Some(secs) = s.strip_suffix('s') {
        secs.parse()
            .map_err(|_| Error::validation(format!("invalid duration: {}", s)))
    } else {
        // Try parsing as raw seconds
        s.parse().map_err(|_| {
            Error::validation(format!(
                "invalid duration '{}', expected e.g. 1h, 30m, 3600s",
                s
            ))
        })
    }
}
