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

#[cfg(feature = "provider-e2e")]
use super::helpers::ProxySession;
use super::providers::InfraProvider;

/// Identifies which cluster level to operate on
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterLevel {
    /// Management cluster (accessed directly)
    Mgmt,
    /// First workload cluster (accessed via mgmt proxy)
    Workload,
    /// Second workload cluster (accessed via workload proxy)
    Workload2,
}

impl ClusterLevel {
    /// Returns a display name for logging
    pub fn display_name(&self) -> &'static str {
        match self {
            ClusterLevel::Mgmt => "management",
            ClusterLevel::Workload => "workload",
            ClusterLevel::Workload2 => "workload2",
        }
    }
}

/// Cluster infrastructure context for tests
///
/// Management cluster is accessed directly. Child clusters (workload, workload2)
/// are accessed through the parent's proxy.
#[derive(Debug, Clone)]
pub struct InfraContext {
    /// Path to management cluster kubeconfig (direct access)
    pub mgmt_kubeconfig: String,

    /// Path to workload cluster kubeconfig (via mgmt proxy)
    pub workload_kubeconfig: Option<String>,

    /// Path to workload2 cluster kubeconfig (via workload proxy)
    pub workload2_kubeconfig: Option<String>,

    /// Infrastructure provider type
    pub provider: InfraProvider,

    /// Mgmt proxy URL (if port-forward is active) - for accessing workload
    pub mgmt_proxy_url: Option<String>,

    /// Workload proxy URL (if port-forward is active) - for accessing workload2
    pub workload_proxy_url: Option<String>,
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
            workload_proxy_url: std::env::var("LATTICE_WORKLOAD_PROXY_URL").ok(),
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
            workload_proxy_url: None,
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

    /// Set workload proxy URL
    pub fn with_workload_proxy_url(mut self, url: String) -> Self {
        self.workload_proxy_url = Some(url);
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

    /// Get kubeconfig for a specific cluster level
    pub fn kubeconfig_for(&self, level: ClusterLevel) -> Result<&str, String> {
        match level {
            ClusterLevel::Mgmt => Ok(&self.mgmt_kubeconfig),
            ClusterLevel::Workload => self.require_workload(),
            ClusterLevel::Workload2 => self.require_workload2(),
        }
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

/// Initialize E2E test environment (crypto provider + tracing)
pub fn init_e2e_test() {
    lattice_common::install_crypto_provider();

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
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
    /// Proxy session to mgmt cluster (keeps port-forward alive for workload access)
    mgmt_proxy: Option<ProxySession>,
    /// Proxy session to workload cluster (keeps port-forward alive for workload2 access)
    workload_proxy: Option<ProxySession>,
}

#[cfg(feature = "provider-e2e")]
impl TestSession {
    /// Create a test session from environment variables.
    ///
    /// This starts any required port-forwards for proxy kubeconfigs.
    /// The port-forwards are kept alive while the session exists.
    pub fn from_env(require_msg: &str) -> Result<Self, String> {
        init_e2e_test();
        let mut ctx = InfraContext::from_env().ok_or(require_msg)?;

        // Start port-forward to mgmt proxy if we have workload kubeconfig
        // (workload is accessed through mgmt's proxy)
        let mgmt_proxy = if ctx.workload_kubeconfig.is_some() {
            match ProxySession::start(&ctx.mgmt_kubeconfig) {
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

        // Start port-forward to workload proxy if we have workload2 kubeconfig
        // AND we have a working mgmt proxy (workload2 is accessed through workload's proxy)
        let workload_proxy = if ctx.workload2_kubeconfig.is_some() && mgmt_proxy.is_some() {
            // We need the workload's direct kubeconfig to start its proxy session
            // For now, try to derive it from the proxy kubeconfig path
            if let Some(ref workload_kc) = ctx.workload_kubeconfig {
                // If this is a proxy kubeconfig, we can't start workload's proxy from it
                // because we'd need the direct kubeconfig. Skip for now.
                if workload_kc.contains("-proxy-") {
                    tracing::info!(
                        "Skipping workload proxy - would need workload's direct kubeconfig"
                    );
                    None
                } else {
                    match ProxySession::start(workload_kc) {
                        Ok(session) => {
                            ctx.workload_proxy_url = Some(session.url.clone());
                            Some(session)
                        }
                        Err(e) => {
                            tracing::warn!("Failed to start workload proxy session: {}", e);
                            None
                        }
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            ctx,
            mgmt_proxy,
            workload_proxy,
        })
    }

    /// Rebuild operators and restart port-forwards.
    ///
    /// This is useful when you need to deploy new code to the operators.
    /// After rebuilding, the port-forwards are automatically restarted
    /// since the operator pods (which include lattice-cell) are replaced.
    pub async fn rebuild_operators(&mut self, image: &str) -> Result<(), String> {
        use super::helpers::rebuild_and_restart_operators;

        let kubeconfigs = self.ctx.all_kubeconfigs();
        rebuild_and_restart_operators(image, &kubeconfigs).await?;

        // Restart port-forwards since the operator pods were replaced
        self.restart_port_forwards()
    }

    /// Verify port-forwards are healthy.
    ///
    /// With ResilientPortForward, the watchdog thread handles automatic restarts,
    /// so this method just verifies health. Useful for diagnostics or after operations
    /// that might temporarily disrupt connectivity.
    pub fn restart_port_forwards(&mut self) -> Result<(), String> {
        if let Some(ref mut proxy) = self.mgmt_proxy {
            proxy.ensure_alive()?;
            self.ctx.mgmt_proxy_url = Some(proxy.url.clone());
        }

        if let Some(ref mut proxy) = self.workload_proxy {
            proxy.ensure_alive()?;
            self.ctx.workload_proxy_url = Some(proxy.url.clone());
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
