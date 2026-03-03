//! Infrastructure context for E2E and integration tests
//!
//! Provides cluster connection information for tests. Child clusters are accessed
//! through the parent's proxy - the kubeconfig fields contain proxy kubeconfigs.
//!
//! # Environment Variables for Standalone Tests
//!
//! ```bash
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/workload-kubeconfig
//! LATTICE_WORKLOAD2_KUBECONFIG=/path/to/workload2-kubeconfig
//! ```

use std::sync::{Condvar, Mutex};
use std::time::Duration;

#[cfg(feature = "provider-e2e")]
use super::helpers::ProxySession;
use super::providers::InfraProvider;

// =============================================================================
// Test Concurrency Limiter
// =============================================================================

/// Maximum number of integration tests that can run concurrently.
/// Prevents resource exhaustion on single-worker-node clusters.
/// Override with LATTICE_TEST_CONCURRENCY env var (0 = unlimited).
fn max_concurrent_tests() -> usize {
    match std::env::var("LATTICE_TEST_CONCURRENCY") {
        Ok(val) => match val.parse::<usize>() {
            Ok(0) => usize::MAX,
            Ok(n) => n,
            Err(_) => usize::MAX,
        },
        Err(_) => usize::MAX,
    }
}

static SEMAPHORE_COUNTER: Mutex<usize> = Mutex::new(0);
static SEMAPHORE_CONDVAR: Condvar = Condvar::new();

/// RAII permit that limits concurrent test execution.
/// Automatically releases the slot when dropped (even on panic).
pub struct TestPermit(());

impl Drop for TestPermit {
    fn drop(&mut self) {
        let mut count = SEMAPHORE_COUNTER.lock().unwrap();
        *count -= 1;
        SEMAPHORE_CONDVAR.notify_one();
    }
}

/// Block until a test execution slot is available, then return an RAII permit.
pub fn acquire_test_permit() -> TestPermit {
    let mut count = SEMAPHORE_COUNTER.lock().unwrap();
    while *count >= max_concurrent_tests() {
        count = SEMAPHORE_CONDVAR.wait(count).unwrap();
    }
    *count += 1;
    TestPermit(())
}

/// Cluster infrastructure context for tests
///
/// Management cluster is accessed directly. Child clusters (workload, workload2)
/// are accessed through mgmt's proxy.
#[derive(Debug, Clone)]
pub struct InfraContext {
    /// Path to management cluster kubeconfig (direct access)
    pub mgmt_kubeconfig: String,

    /// Path to workload cluster kubeconfig (via mgmt proxy)
    pub workload_kubeconfig: Option<String>,

    /// Path to workload2 cluster kubeconfig (via mgmt proxy, routes through workload)
    pub workload2_kubeconfig: Option<String>,

    /// Infrastructure provider type
    pub provider: InfraProvider,

    /// Mgmt proxy URL (all child access routes through this)
    pub mgmt_proxy_url: Option<String>,
}

impl InfraContext {
    /// Load from environment variables
    pub fn from_env() -> Option<Self> {
        Some(Self {
            mgmt_kubeconfig: std::env::var("LATTICE_MGMT_KUBECONFIG").ok()?,
            workload_kubeconfig: std::env::var("LATTICE_WORKLOAD_KUBECONFIG").ok(),
            workload2_kubeconfig: std::env::var("LATTICE_WORKLOAD2_KUBECONFIG").ok(),
            provider: Self::provider_from_env(),
            mgmt_proxy_url: std::env::var("LATTICE_MGMT_PROXY_URL").ok(),
        })
    }

    /// Create with explicit paths
    pub fn new(
        mgmt_kubeconfig: String,
        workload_kubeconfig: Option<String>,
        workload2_kubeconfig: Option<String>,
        provider: InfraProvider,
    ) -> Self {
        Self {
            mgmt_kubeconfig,
            workload_kubeconfig,
            workload2_kubeconfig,
            provider,
            mgmt_proxy_url: None,
        }
    }

    /// Create with only management cluster
    pub fn mgmt_only(mgmt_kubeconfig: String, provider: InfraProvider) -> Self {
        Self::new(mgmt_kubeconfig, None, None, provider)
    }

    /// Set mgmt proxy URL
    pub fn with_mgmt_proxy_url(mut self, url: String) -> Self {
        self.mgmt_proxy_url = Some(url);
        self
    }

    /// Add workload cluster kubeconfig
    pub fn with_workload(mut self, kubeconfig: String) -> Self {
        self.workload_kubeconfig = Some(kubeconfig);
        self
    }

    /// Add workload2 cluster kubeconfig
    pub fn with_workload2(mut self, kubeconfig: String) -> Self {
        self.workload2_kubeconfig = Some(kubeconfig);
        self
    }

    /// Check if workload kubeconfig is set
    pub fn has_workload(&self) -> bool {
        self.workload_kubeconfig.is_some()
    }

    /// Check if workload2 kubeconfig is set
    pub fn has_workload2(&self) -> bool {
        self.workload2_kubeconfig.is_some()
    }

    /// Get workload kubeconfig or error
    pub fn require_workload(&self) -> Result<&str, String> {
        self.workload_kubeconfig
            .as_deref()
            .ok_or_else(|| "Workload kubeconfig not set".to_string())
    }

    /// Get workload2 kubeconfig or error
    pub fn require_workload2(&self) -> Result<&str, String> {
        self.workload2_kubeconfig
            .as_deref()
            .ok_or_else(|| "Workload2 kubeconfig not set".to_string())
    }

    /// Get all kubeconfigs as (name, path) tuples
    pub fn all_kubeconfigs(&self) -> Vec<(&str, &str)> {
        let mut configs = vec![("mgmt", self.mgmt_kubeconfig.as_str())];
        if let Some(ref kc) = self.workload_kubeconfig {
            configs.push(("workload", kc.as_str()));
        }
        if let Some(ref kc) = self.workload2_kubeconfig {
            configs.push(("workload2", kc.as_str()));
        }
        configs
    }

    fn provider_from_env() -> InfraProvider {
        match std::env::var("LATTICE_PROVIDER")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "aws" => InfraProvider::Aws,
            "proxmox" => InfraProvider::Proxmox,
            "openstack" => InfraProvider::OpenStack,
            _ => InfraProvider::Docker,
        }
    }
}

/// Get a kubeconfig for standalone single-cluster tests.
///
/// Reads `LATTICE_KUBECONFIG` (preferred) or falls back to `LATTICE_WORKLOAD_KUBECONFIG`.
/// Returns `None` if neither is set — callers that also support the two-cluster
/// proxy workflow can fall back to `TestSession::from_env()`.
pub fn standalone_kubeconfig() -> Option<String> {
    std::env::var("LATTICE_KUBECONFIG")
        .ok()
        .or_else(|| std::env::var("LATTICE_WORKLOAD_KUBECONFIG").ok())
}

/// Resolved kubeconfig for standalone tests, potentially backed by a proxy session.
///
/// If `LATTICE_KUBECONFIG` is set, uses it directly (no proxy needed).
/// Otherwise falls back to `TestSession` with proxy + Cedar policy.
/// The session is held to keep the port-forward alive.
///
/// # Example
///
/// ```ignore
/// let resolved = StandaloneKubeconfig::resolve().await.unwrap();
/// run_my_tests(&resolved.kubeconfig).await.unwrap();
/// ```
#[cfg(feature = "provider-e2e")]
pub struct StandaloneKubeconfig {
    /// The resolved kubeconfig path
    pub kubeconfig: String,
    /// Proxy session (kept alive for port-forward). None when using direct access.
    _session: Option<TestSession>,
    /// Concurrency permit — released when this struct is dropped
    _permit: TestPermit,
}

#[cfg(feature = "provider-e2e")]
impl StandaloneKubeconfig {
    /// Resolve kubeconfig for a standalone test.
    ///
    /// Prefers `LATTICE_KUBECONFIG` for direct access. Falls back to
    /// `LATTICE_MGMT_KUBECONFIG` + `LATTICE_WORKLOAD_KUBECONFIG` with proxy + Cedar policy.
    pub async fn resolve() -> Result<Self, String> {
        let permit = acquire_test_permit();

        if let Some(kc) = standalone_kubeconfig() {
            return Ok(Self {
                kubeconfig: kc,
                _session: None,
                _permit: permit,
            });
        }

        let session = TestSession::from_env(
            "Set LATTICE_KUBECONFIG or LATTICE_MGMT_KUBECONFIG + LATTICE_WORKLOAD_KUBECONFIG",
        )
        .await?;
        super::integration::cedar::apply_e2e_default_policy(&session.ctx.mgmt_kubeconfig).await?;
        let kc = session.ctx.require_workload()?.to_string();
        Ok(Self {
            kubeconfig: kc,
            _session: Some(session),
            _permit: permit,
        })
    }
}

/// Initialize E2E test environment (crypto provider + tracing)
pub fn init_e2e_test() {
    lattice_common::fips::install_crypto_provider();

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}

// =============================================================================
// Per-Integration E2E Runner
// =============================================================================

/// Run a per-integration E2E test with standard setup, teardown, timeout, and cleanup.
///
/// Handles the boilerplate shared by all per-integration E2E tests:
/// - `init_e2e_test()` (crypto + tracing)
/// - `setup_mgmt_and_workload()` with default config
/// - Timeout wrapping
/// - `teardown_mgmt_cluster()` on success
/// - `cleanup_bootstrap_cluster()` on failure or timeout
///
/// The `test_fn` closure receives the `InfraContext` (cloned from `SetupResult`)
/// and runs the actual integration test logic.
///
/// # Example
///
/// ```ignore
/// #[tokio::test]
/// async fn test_mesh_e2e() {
///     run_per_integration_e2e("Mesh", Duration::from_secs(2400), |ctx| async move {
///         integration::mesh::run_mesh_tests(ctx.require_workload()?).await
///     }).await;
/// }
/// ```
#[cfg(feature = "provider-e2e")]
pub async fn run_per_integration_e2e<F, Fut>(name: &str, timeout: Duration, test_fn: F)
where
    F: FnOnce(InfraContext) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    use super::helpers::{teardown_mgmt_cluster, MGMT_CLUSTER_NAME};
    use super::integration::setup;
    use tracing::info;

    init_e2e_test();
    info!("Starting E2E test: {}", name);

    let run_inner = async {
        let result = setup::setup_mgmt_and_workload(&setup::SetupConfig::default()).await?;
        let ctx = result.ctx.clone();
        test_fn(ctx).await?;
        teardown_mgmt_cluster(&result.ctx.mgmt_kubeconfig, MGMT_CLUSTER_NAME).await
    };

    match tokio::time::timeout(timeout, run_inner).await {
        Ok(Ok(())) => info!("TEST PASSED: {}", name),
        Ok(Err(e)) => {
            panic!("{} E2E failed (resources left for debugging): {}", name, e);
        }
        Err(_) => {
            panic!(
                "{} E2E timed out after {:?} (resources left for debugging)",
                name, timeout
            );
        }
    }
}

// =============================================================================
// Test Session with Managed Proxy Connections
// =============================================================================

/// A test session that manages proxy connections for the duration of the test.
///
/// When proxy kubeconfigs are used, this struct ensures the required port-forwards
/// are running. The port-forwards are automatically stopped when the session is dropped.
///
/// # Example
///
/// ```ignore
/// let session = TestSession::from_env("Set LATTICE_MGMT_KUBECONFIG")?;
/// // Use session.ctx for test operations
/// // Port-forwards stay alive while session is in scope
/// ```
#[cfg(feature = "provider-e2e")]
pub struct TestSession {
    /// Infrastructure context with kubeconfig paths
    pub ctx: InfraContext,
    /// Proxy session to mgmt cluster (all child access routes through mgmt's proxy)
    mgmt_proxy: Option<ProxySession>,
    /// Concurrency permit — released when this struct is dropped
    _permit: TestPermit,
}

#[cfg(feature = "provider-e2e")]
impl TestSession {
    /// Create a test session from environment variables.
    ///
    /// Starts a port-forward to mgmt's proxy if workload kubeconfig is set.
    /// All child cluster access routes through mgmt's proxy.
    pub async fn from_env(require_msg: &str) -> Result<Self, String> {
        let permit = acquire_test_permit();
        init_e2e_test();
        let mut ctx = InfraContext::from_env().ok_or(require_msg)?;

        // Start port-forward to mgmt proxy if we have child kubeconfigs
        // (all child access routes through mgmt's proxy)
        let mgmt_proxy = if ctx.workload_kubeconfig.is_some() {
            match ProxySession::start(&ctx.mgmt_kubeconfig).await {
                Ok(session) => {
                    ctx.mgmt_proxy_url = Some(session.url.clone());
                    Some(session)
                }
                Err(e) => {
                    tracing::warn!("Failed to start mgmt proxy session: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            ctx,
            mgmt_proxy,
            _permit: permit,
        })
    }

    /// Rebuild operators and restart port-forwards.
    pub async fn rebuild_operators(&mut self, image: &str) -> Result<(), String> {
        use super::helpers::rebuild_and_restart_operators;

        let kubeconfigs = self.ctx.all_kubeconfigs();
        rebuild_and_restart_operators(image, &kubeconfigs).await?;

        self.ensure_proxy_alive().await
    }

    /// Verify mgmt proxy is healthy.
    pub async fn ensure_proxy_alive(&mut self) -> Result<(), String> {
        if let Some(ref mut proxy) = self.mgmt_proxy {
            proxy.ensure_alive().await?;
            self.ctx.mgmt_proxy_url = Some(proxy.url.clone());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_builder() {
        let ctx = InfraContext::mgmt_only("/tmp/mgmt".into(), InfraProvider::Docker)
            .with_workload("/tmp/workload".into())
            .with_workload2("/tmp/workload2".into());

        assert_eq!(ctx.mgmt_kubeconfig, "/tmp/mgmt");
        assert_eq!(ctx.workload_kubeconfig.as_deref(), Some("/tmp/workload"));
        assert_eq!(ctx.workload2_kubeconfig.as_deref(), Some("/tmp/workload2"));
    }

    #[test]
    fn test_require_methods() {
        let ctx = InfraContext::mgmt_only("/tmp/mgmt".into(), InfraProvider::Docker);
        assert!(ctx.require_workload().is_err());

        let ctx = ctx.with_workload("/tmp/workload".into());
        assert_eq!(ctx.require_workload().unwrap(), "/tmp/workload");
    }

    #[test]
    fn test_all_kubeconfigs() {
        let ctx = InfraContext::mgmt_only("/tmp/mgmt".into(), InfraProvider::Docker)
            .with_workload("/tmp/workload".into());

        let configs = ctx.all_kubeconfigs();
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0], ("mgmt", "/tmp/mgmt"));
        assert_eq!(configs[1], ("workload", "/tmp/workload"));
    }
}
