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

use super::providers::InfraProvider;

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
}

impl InfraContext {
    /// Load from environment variables
    pub fn from_env() -> Option<Self> {
        Some(Self {
            mgmt_kubeconfig: std::env::var("LATTICE_MGMT_KUBECONFIG").ok()?,
            workload_kubeconfig: std::env::var("LATTICE_WORKLOAD_KUBECONFIG").ok(),
            workload2_kubeconfig: std::env::var("LATTICE_WORKLOAD2_KUBECONFIG").ok(),
            provider: Self::provider_from_env(),
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
        }
    }

    /// Create with only management cluster
    pub fn mgmt_only(mgmt_kubeconfig: String, provider: InfraProvider) -> Self {
        Self::new(mgmt_kubeconfig, None, None, provider)
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

/// Initialize test environment and load config from env
pub fn init_test_env(require_msg: &str) -> InfraContext {
    init_e2e_test();
    InfraContext::from_env().expect(require_msg)
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
