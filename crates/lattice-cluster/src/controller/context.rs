//! Controller context and builder.
//!
//! The `Context` struct holds shared state for the LatticeCluster controller,
//! including Kubernetes clients, CAPI clients, and event publishers.

use std::sync::Arc;

use dashmap::DashMap;
use kube::Client;

#[cfg(test)]
use lattice_common::NoopEventPublisher;

use lattice_capi::client::{CAPIClient, CAPIClientImpl};
use lattice_capi::installer::CapiInstaller;
use lattice_cell::{DefaultManifestGenerator, ParentServers};
use lattice_common::events::EventPublisher;
use lattice_common::KubeEventPublisher;

use super::kube_client::{KubeClient, KubeClientImpl};
use super::FIELD_MANAGER;

/// Shared context for the LatticeCluster controller
///
/// The context is shared across all reconciliation calls and holds
/// resources that are expensive to create (like Kubernetes clients).
///
/// CAPI resources are created in per-cluster namespaces (`capi-{cluster_name}`)
/// to enable clean pivot operations.
///
/// Use [`ContextBuilder`] to construct instances:
///
/// ```text
/// let ctx = Context::builder(client)
///     .parent_servers(servers)
///     .build();
/// ```
pub struct Context {
    /// Kubernetes client for API operations (trait object for testability)
    pub kube: Arc<dyn KubeClient>,
    /// Raw Kubernetes client (for operations that need the concrete type, e.g. secret distribution)
    /// None only in tests using mocks
    pub client: Option<Client>,
    /// CAPI client for applying manifests
    pub capi: Arc<dyn CAPIClient>,
    /// CAPI installer for installing CAPI and providers
    pub capi_installer: Arc<dyn CapiInstaller>,
    /// Cell servers (started at application startup)
    pub parent_servers: Option<Arc<ParentServers<DefaultManifestGenerator>>>,
    /// Name of the cluster this controller is running on (from LATTICE_CLUSTER_NAME env var)
    /// When reconciling this cluster, we skip provisioning since we ARE this cluster
    pub self_cluster_name: Option<String>,
    /// Centralized operator configuration
    pub config: lattice_common::SharedConfig,
    /// Event publisher for emitting Kubernetes Events
    pub events: Arc<dyn EventPublisher>,
    /// Per-cluster error counts for exponential backoff in error_policy.
    ///
    /// Entries are removed on successful reconcile or permanent errors.
    /// `prune_stale_error_counts()` should be called periodically to evict
    /// entries for clusters that no longer exist.
    pub error_counts: DashMap<String, u32>,
}

/// Maximum number of entries before we force a prune (safety valve)
const ERROR_COUNTS_MAX_ENTRIES: usize = 1000;

impl Context {
    /// Remove error_counts entries for clusters that no longer exist.
    ///
    /// Call this periodically (e.g., every reconcile cycle) to prevent
    /// unbounded growth from deleted clusters whose entries were never cleaned up.
    pub fn prune_stale_error_counts(&self, active_clusters: &[String]) {
        if self.error_counts.len() <= ERROR_COUNTS_MAX_ENTRIES {
            return;
        }
        let active_set: std::collections::HashSet<&str> =
            active_clusters.iter().map(|s| s.as_str()).collect();
        self.error_counts
            .retain(|name, _| active_set.contains(name.as_str()));
    }
}

impl Context {
    /// Create a builder for constructing a Context
    pub fn builder(client: Client, config: lattice_common::SharedConfig) -> ContextBuilder {
        ContextBuilder::new(client, config)
    }

    /// Create a context for testing with custom mock clients
    ///
    /// This method is primarily for unit tests where a real Kubernetes
    /// client is not available. For production code, use [`Context::builder`].
    #[cfg(test)]
    pub fn for_testing(
        kube: Arc<dyn KubeClient>,
        capi: Arc<dyn CAPIClient>,
        capi_installer: Arc<dyn CapiInstaller>,
    ) -> Self {
        use lattice_common::config::LatticeConfig;
        use lattice_common::crd::ProviderType;
        Self {
            kube,
            client: None, // Tests use mocks, not real client
            capi,
            capi_installer,
            parent_servers: None,
            self_cluster_name: None,
            config: std::sync::Arc::new(LatticeConfig {
                cluster_name: None,
                provider: ProviderType::Docker,
                provider_ref: "docker".to_string(),
                debug: false,
                image: lattice_common::config::DEFAULT_IMAGE.to_string(),
                monitoring_enabled: false,
                monitoring_ha: false,
                scripts_dir: "/scripts".to_string(),
                oidc_allow_insecure_http: false,
                is_bootstrap_cluster: false,
                grpc_max_message_size: 16 * 1024 * 1024,
            }),
            events: Arc::new(NoopEventPublisher),
            error_counts: DashMap::new(),
        }
    }
}

/// Builder for constructing [`Context`] instances
///
/// # Examples
///
/// Basic context for agent mode:
/// ```text
/// let ctx = Context::builder(client).build();
/// ```
///
/// Full cell context:
/// ```text
/// let ctx = Context::builder(client)
///     .parent_servers(servers)
///     .build();
/// ```
///
/// Testing with mock clients:
/// ```text
/// let ctx = Context::builder(client)
///     .kube_client(mock_kube)
///     .capi_client(mock_capi)
///     .build();
/// ```
pub struct ContextBuilder {
    client: Client,
    config: lattice_common::SharedConfig,
    kube: Option<Arc<dyn KubeClient>>,
    capi: Option<Arc<dyn CAPIClient>>,
    capi_installer: Option<Arc<dyn CapiInstaller>>,
    parent_servers: Option<Arc<ParentServers<DefaultManifestGenerator>>>,
    self_cluster_name: Option<String>,
    events: Option<Arc<dyn EventPublisher>>,
}

impl ContextBuilder {
    /// Create a new builder with the given Kubernetes client and config
    fn new(client: Client, config: lattice_common::SharedConfig) -> Self {
        Self {
            client,
            config,
            kube: None,
            capi: None,
            capi_installer: None,
            parent_servers: None,
            self_cluster_name: None,
            events: None,
        }
    }

    /// Set the cluster name this controller is running on (from LATTICE_CLUSTER_NAME env var)
    pub fn self_cluster_name(mut self, name: impl Into<String>) -> Self {
        self.self_cluster_name = Some(name.into());
        self
    }

    /// Override the Kubernetes client (primarily for testing)
    pub fn kube_client(mut self, kube: Arc<dyn KubeClient>) -> Self {
        self.kube = Some(kube);
        self
    }

    /// Override the CAPI client (primarily for testing)
    pub fn capi_client(mut self, capi: Arc<dyn CAPIClient>) -> Self {
        self.capi = Some(capi);
        self
    }

    /// Override the CAPI installer (primarily for testing)
    pub fn capi_installer(mut self, installer: Arc<dyn CapiInstaller>) -> Self {
        self.capi_installer = Some(installer);
        self
    }

    /// Set cell servers for on-demand startup
    pub fn parent_servers(mut self, servers: Arc<ParentServers<DefaultManifestGenerator>>) -> Self {
        self.parent_servers = Some(servers);
        self
    }

    /// Override the event publisher (primarily for testing)
    pub fn event_publisher(mut self, events: Arc<dyn EventPublisher>) -> Self {
        self.events = Some(events);
        self
    }

    /// Build the Context
    pub fn build(self) -> Context {
        use lattice_capi::installer::NativeInstaller;

        let events = self.events.unwrap_or_else(|| {
            Arc::new(KubeEventPublisher::new(self.client.clone(), FIELD_MANAGER))
        });

        Context {
            kube: self
                .kube
                .unwrap_or_else(|| Arc::new(KubeClientImpl::new(self.client.clone()))),
            client: Some(self.client.clone()),
            capi: self
                .capi
                .unwrap_or_else(|| Arc::new(CAPIClientImpl::new(self.client.clone()))),
            capi_installer: self
                .capi_installer
                .unwrap_or_else(|| Arc::new(NativeInstaller::new())),
            parent_servers: self.parent_servers,
            self_cluster_name: self.self_cluster_name,
            config: self.config,
            events,
            error_counts: DashMap::new(),
        }
    }
}
