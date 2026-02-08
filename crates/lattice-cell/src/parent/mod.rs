//! Parent servers for on-demand gRPC and bootstrap HTTP servers
//!
//! When a cluster has parent configuration (can have children), it runs:
//! - gRPC server: for child agent bidirectional streams
//! - Bootstrap HTTP server: for kubeadm postKubeadmCommands webhook
//! - K8s API proxy: for accessing child cluster APIs through the gRPC stream
//!
//! This module provides `ParentServers` which starts these servers on-demand.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::ByteString;
use kube::api::{Api, PostParams};
use kube::runtime::watcher::{self, Event};
use kube::Client;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::bootstrap::{
    bootstrap_router, BootstrapState, DefaultManifestGenerator, ManifestGenerator,
};
use crate::capi_proxy::{start_capi_proxy, CapiProxyConfig};
use crate::connection::{AgentRegistry, SharedAgentRegistry};
use crate::resources::fetch_distributable_resources;
use crate::server::{AgentServer, SharedSubtreeRegistry};
use crate::subtree_registry::SubtreeRegistry;
use lattice_common::crd::{CedarPolicy, CloudProvider, OIDCProvider, SecretProvider};
use lattice_common::DistributableResources;
use lattice_common::{
    lattice_svc_dns, CA_CERT_KEY, CA_KEY_KEY, CA_SECRET, CA_TRUST_KEY, CELL_SERVICE_NAME,
    LATTICE_SYSTEM_NAMESPACE,
};
use lattice_infra::pki::{CertificateAuthority, CertificateAuthorityBundle};
use lattice_infra::ServerMtlsConfig;
use lattice_proto::{
    cell_command, CellCommand, DistributableResources as ProtoDistributableResources,
    SyncDistributedResourcesCommand,
};

/// Configuration for cell servers
#[derive(Debug, Clone)]
pub struct ParentConfig {
    /// This cluster's name (used for subtree registry)
    pub cluster_name: String,
    /// Address for the bootstrap HTTPS server
    pub bootstrap_addr: SocketAddr,
    /// Address for the gRPC server
    pub grpc_addr: SocketAddr,
    /// Address for the CAPI K8s API proxy server (read-only, pre-pivot)
    pub proxy_addr: SocketAddr,
    /// Address for the authenticated K8s API proxy server (auth + Cedar)
    pub auth_proxy_addr: SocketAddr,
    /// Bootstrap token TTL
    pub token_ttl: Duration,
    /// SANs for server certificates (hostnames/IPs that agents will use to connect)
    pub server_sans: Vec<String>,
    /// Lattice image to deploy on child clusters
    pub image: String,
    /// Registry credentials (optional)
    pub registry_credentials: Option<String>,
}

impl Default for ParentConfig {
    fn default() -> Self {
        Self {
            cluster_name: std::env::var("LATTICE_CLUSTER_NAME")
                .unwrap_or_else(|_| "unknown".to_string()),
            bootstrap_addr: format!("0.0.0.0:{}", lattice_common::DEFAULT_BOOTSTRAP_PORT)
                .parse()
                .expect("hardcoded socket address is valid"),
            grpc_addr: format!("0.0.0.0:{}", lattice_common::DEFAULT_GRPC_PORT)
                .parse()
                .expect("hardcoded socket address is valid"),
            proxy_addr: format!("0.0.0.0:{}", lattice_common::DEFAULT_PROXY_PORT)
                .parse()
                .expect("hardcoded socket address is valid"),
            auth_proxy_addr: format!("0.0.0.0:{}", lattice_common::DEFAULT_AUTH_PROXY_PORT)
                .parse()
                .expect("hardcoded socket address is valid"),
            token_ttl: Duration::from_secs(3600),
            server_sans: vec![
                "localhost".to_string(),
                "host.docker.internal".to_string(),
                "host.containers.internal".to_string(),
                "172.17.0.1".to_string(),
                "127.0.0.1".to_string(),
                // Webhook service DNS name for in-cluster webhook calls
                lattice_svc_dns("lattice-webhook"),
                // Cell service DNS name for proxy access
                lattice_svc_dns(CELL_SERVICE_NAME),
            ],
            image: std::env::var("LATTICE_IMAGE")
                .unwrap_or_else(|_| "ghcr.io/evan-hines-js/lattice:latest".to_string()),
            registry_credentials: load_registry_credentials(),
        }
    }
}

/// Load registry credentials from file specified by REGISTRY_CREDENTIALS_FILE env var.
/// Logs errors instead of silently returning None.
fn load_registry_credentials() -> Option<String> {
    let path = match std::env::var("REGISTRY_CREDENTIALS_FILE") {
        Ok(p) => p,
        Err(_) => return None, // Env var not set is expected, not an error
    };

    match std::fs::read_to_string(&path) {
        Ok(contents) => Some(contents),
        Err(e) => {
            tracing::warn!(
                path = %path,
                error = %e,
                "REGISTRY_CREDENTIALS_FILE is set but file could not be read"
            );
            None
        }
    }
}

/// Cell servers handle - manages the lifecycle of gRPC and bootstrap HTTP servers
///
/// These servers are started on-demand when the controller detects a Pending
/// LatticeCluster CRD, indicating this cluster should provision a child cluster.
pub struct ParentServers<G: ManifestGenerator + Send + Sync + 'static = DefaultManifestGenerator> {
    /// Whether the servers have been started
    running: AtomicBool,
    /// Configuration
    config: ParentConfig,
    /// Certificate Authority bundle for signing and verification (supports rotation)
    ca_bundle: Arc<RwLock<CertificateAuthorityBundle>>,
    /// Kubernetes client for CA persistence
    kube_client: Client,
    /// Bootstrap state for cluster registration
    bootstrap_state: Arc<RwLock<Option<Arc<BootstrapState<G>>>>>,
    /// Agent registry for connected agents
    agent_registry: SharedAgentRegistry,
    /// Subtree registry for tracking cluster hierarchy
    subtree_registry: SharedSubtreeRegistry,
    /// Server handles
    handles: RwLock<Option<ServerHandles>>,
}

struct ServerHandles {
    bootstrap_handle: JoinHandle<()>,
    grpc_handle: JoinHandle<()>,
    secret_sync_handle: JoinHandle<()>,
    proxy_handle: JoinHandle<()>,
}

/// Interval for periodic secret sync (safety net)
const SECRET_SYNC_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes

/// Push distributable resources to all connected agents
async fn push_resources_to_agents(
    registry: &SharedAgentRegistry,
    resources: DistributableResources,
    full_sync: bool,
) {
    let agents = registry.list_clusters();
    if agents.is_empty() {
        debug!("No connected agents to push resources to");
        return;
    }

    let cmd = CellCommand {
        command_id: uuid::Uuid::new_v4().to_string(),
        command: Some(cell_command::Command::SyncResources(
            SyncDistributedResourcesCommand {
                resources: Some(ProtoDistributableResources {
                    cloud_providers: resources.cloud_providers.clone(),
                    secrets_providers: resources.secrets_providers.clone(),
                    secrets: resources.secrets.clone(),
                    cedar_policies: resources.cedar_policies.clone(),
                    oidc_providers: resources.oidc_providers.clone(),
                }),
                full_sync,
            },
        )),
    };

    for agent_name in &agents {
        if let Err(e) = registry.send_command(agent_name, cmd.clone()).await {
            warn!(agent = %agent_name, error = %e, "Failed to push resources to agent");
        } else {
            debug!(
                agent = %agent_name,
                cloud_providers = resources.cloud_providers.len(),
                secrets_providers = resources.secrets_providers.len(),
                cedar_policies = resources.cedar_policies.len(),
                oidc_providers = resources.oidc_providers.len(),
                secrets = resources.secrets.len(),
                "Pushed resources to agent"
            );
        }
    }
}

/// Run the resource sync service
///
/// Watches for changes to CloudProvider, SecretProvider, CedarPolicy, and OIDCProvider CRDs and:
/// 1. Immediately pushes changes to all connected agents (watch-triggered)
/// 2. Periodically does a full sync as a safety net
async fn run_resource_sync(client: Client, registry: SharedAgentRegistry, cluster_name: String) {
    let cp_api: Api<CloudProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let sp_api: Api<SecretProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let cedar_api: Api<CedarPolicy> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let oidc_api: Api<OIDCProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);

    // Create watchers for all distributable CRDs
    // Set a timeout shorter than the client's read_timeout (30s) to ensure the API server
    // closes the watch before the client times out. This prevents "body read timed out" errors.
    let watcher_config = watcher::Config::default().timeout(25);
    let cp_watcher = watcher::watcher(cp_api, watcher_config.clone());
    let sp_watcher = watcher::watcher(sp_api, watcher_config.clone());
    let cedar_watcher = watcher::watcher(cedar_api, watcher_config.clone());
    let oidc_watcher = watcher::watcher(oidc_api, watcher_config);

    let mut cp_watcher = std::pin::pin!(cp_watcher);
    let mut sp_watcher = std::pin::pin!(sp_watcher);
    let mut cedar_watcher = std::pin::pin!(cedar_watcher);
    let mut oidc_watcher = std::pin::pin!(oidc_watcher);

    // Periodic sync timer
    let mut sync_interval = tokio::time::interval(SECRET_SYNC_INTERVAL);
    sync_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    info!("Resource sync service started");

    loop {
        tokio::select! {
            // Watch for CloudProvider changes
            Some(event) = cp_watcher.next() => {
                handle_resource_event(&client, &registry, &cluster_name, event, "CloudProvider").await;
            }
            // Watch for SecretProvider changes
            Some(event) = sp_watcher.next() => {
                handle_resource_event(&client, &registry, &cluster_name, event, "SecretProvider").await;
            }
            // Watch for CedarPolicy changes
            Some(event) = cedar_watcher.next() => {
                handle_resource_event(&client, &registry, &cluster_name, event, "CedarPolicy").await;
            }
            // Watch for OIDCProvider changes
            Some(event) = oidc_watcher.next() => {
                handle_resource_event(&client, &registry, &cluster_name, event, "OIDCProvider").await;
            }
            // Periodic full sync
            _ = sync_interval.tick() => {
                debug!("Running periodic resource sync");
                match fetch_distributable_resources(&client, &cluster_name).await {
                    Ok(resources) if !resources.is_empty() => {
                        push_resources_to_agents(&registry, resources, true).await;
                    }
                    Ok(_) => {}
                    Err(e) => warn!(error = %e, "Failed to fetch resources for periodic sync"),
                }
            }
        }
    }
}

/// Handle a watcher event for distributable resources
async fn handle_resource_event<T>(
    client: &Client,
    registry: &SharedAgentRegistry,
    cluster_name: &str,
    event: Result<Event<T>, watcher::Error>,
    resource_type: &str,
) where
    T: kube::ResourceExt,
{
    match event {
        Ok(Event::Apply(resource)) | Ok(Event::InitApply(resource)) => {
            let name = resource.name_any();
            info!(%resource_type, %name, "Distributable resource changed, pushing to agents");
            match fetch_distributable_resources(client, cluster_name).await {
                Ok(resources) => push_resources_to_agents(registry, resources, false).await,
                Err(e) => warn!(error = %e, "Failed to fetch resources for sync"),
            }
        }
        Ok(Event::Delete(resource)) => {
            let name = resource.name_any();
            info!(%resource_type, %name, "Distributable resource deleted, triggering full sync");
            match fetch_distributable_resources(client, cluster_name).await {
                Ok(resources) => push_resources_to_agents(registry, resources, true).await,
                Err(e) => warn!(error = %e, "Failed to fetch resources for sync"),
            }
        }
        Ok(Event::Init) | Ok(Event::InitDone) => {
            debug!(%resource_type, "Watcher initialized");
        }
        Err(e) => {
            warn!(error = %e, %resource_type, "Watcher error, will retry");
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

/// Error type for cell server operations
#[derive(Debug, thiserror::Error)]
pub enum CellServerError {
    /// Failed to create the Certificate Authority
    #[error("Failed to create CA: {0}")]
    CaCreation(String),
    /// Failed to persist CA to Secret
    #[error("Failed to persist CA: {0}")]
    CaPersistence(String),
    /// Failed to create the manifest generator
    #[error("Failed to create manifest generator: {0}")]
    ManifestGenerator(String),
    /// Failed to generate server certificate
    #[error("Failed to generate server certificate: {0}")]
    CertGeneration(String),
    /// Failed to configure TLS
    #[error("Failed to configure TLS: {0}")]
    TlsConfig(String),
    /// Servers are already running
    #[error("Servers already running")]
    AlreadyRunning,
}

/// Load CA bundle from Secret or create a new one and persist it
///
/// This ensures the CA survives operator restarts. The CA is stored in a Secret
/// named `lattice-ca` in the `lattice-system` namespace.
///
/// The secret format supports CA rotation:
/// - `ca.crt` - PEM bundle of all trusted CA certificates (newest first)
/// - `ca.key` - Private key for the active (newest) CA only
/// - `ca-trust.crt` - (optional) Additional CA certs for verification only (rotated out CAs)
///
/// # Arguments
/// * `client` - Kubernetes client for accessing the Secret
///
/// # Returns
/// The CA bundle, either loaded from the Secret or newly created
pub async fn load_or_create_ca(
    client: &Client,
) -> Result<CertificateAuthorityBundle, CellServerError> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);

    // Try to load existing CA from Secret
    match secrets.get(CA_SECRET).await {
        Ok(secret) => {
            // CA Secret exists, load it
            let data = secret.data.ok_or_else(|| {
                CellServerError::CaPersistence("CA secret exists but has no data".to_string())
            })?;

            let cert_pem = data
                .get(CA_CERT_KEY)
                .ok_or_else(|| {
                    CellServerError::CaPersistence(format!("CA secret missing {}", CA_CERT_KEY))
                })
                .and_then(|b| {
                    String::from_utf8(b.0.clone()).map_err(|e| {
                        CellServerError::CaPersistence(format!(
                            "Invalid {} encoding: {}",
                            CA_CERT_KEY, e
                        ))
                    })
                })?;

            let key_pem = data
                .get(CA_KEY_KEY)
                .ok_or_else(|| {
                    CellServerError::CaPersistence(format!("CA secret missing {}", CA_KEY_KEY))
                })
                .and_then(|b| {
                    String::from_utf8(b.0.clone()).map_err(|e| {
                        CellServerError::CaPersistence(format!(
                            "Invalid {} encoding: {}",
                            CA_KEY_KEY, e
                        ))
                    })
                })?;

            // Load the active CA (has the private key)
            let active_ca = CertificateAuthority::from_pem(&cert_pem, &key_pem)
                .map_err(|e| CellServerError::CaPersistence(format!("Failed to load CA: {}", e)))?;

            let mut cas = vec![active_ca];

            // Load additional trust CAs if present (for rotation transition)
            if let Some(trust_pem) = data.get(CA_TRUST_KEY) {
                if let Ok(trust_str) = String::from_utf8(trust_pem.0.clone()) {
                    // Parse multiple PEM certificates from the trust bundle
                    for pem in pem::parse_many(trust_str.as_bytes())
                        .map_err(|e| {
                            CellServerError::CaPersistence(format!(
                                "Failed to parse trust bundle: {}",
                                e
                            ))
                        })?
                        .iter()
                    {
                        // Create a trust-only CA (we use the active key as placeholder since
                        // we only need the cert for verification). In practice, this CA is
                        // only used for verify_client_cert which only needs the cert.
                        if let Ok(trust_ca) =
                            CertificateAuthority::from_pem(&pem::encode(pem), &key_pem)
                        {
                            cas.push(trust_ca);
                        }
                    }
                }
            }

            let bundle = CertificateAuthorityBundle::from_cas(cas).map_err(|e| {
                CellServerError::CaPersistence(format!("Failed to create CA bundle: {}", e))
            })?;

            let info = bundle.active().cert_info().map_err(|e| {
                CellServerError::CaPersistence(format!("Failed to read CA info: {}", e))
            })?;

            info!(
                ca_count = bundle.len(),
                lifetime_fraction = format!("{:.1}%", info.lifetime_fraction() * 100.0),
                needs_rotation = bundle.needs_rotation().unwrap_or(false),
                "Loaded CA bundle from Secret {}/{}",
                LATTICE_SYSTEM_NAMESPACE,
                CA_SECRET
            );
            Ok(bundle)
        }
        Err(kube::Error::Api(e)) if e.code == 404 => {
            // CA Secret doesn't exist, create a new CA and persist it
            info!("CA Secret not found, creating new CA");

            let ca = CertificateAuthority::new("Lattice CA")
                .map_err(|e| CellServerError::CaCreation(e.to_string()))?;

            // Create Secret with CA cert and key
            let secret = Secret {
                metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                    name: Some(CA_SECRET.to_string()),
                    namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                    ..Default::default()
                },
                type_: Some("Opaque".to_string()),
                data: Some(BTreeMap::from([
                    (
                        CA_CERT_KEY.to_string(),
                        ByteString(ca.ca_cert_pem().as_bytes().to_vec()),
                    ),
                    (
                        CA_KEY_KEY.to_string(),
                        ByteString(ca.ca_key_pem().as_bytes().to_vec()),
                    ),
                ])),
                ..Default::default()
            };

            secrets
                .create(&PostParams::default(), &secret)
                .await
                .map_err(|e| {
                    CellServerError::CaPersistence(format!("Failed to create CA secret: {}", e))
                })?;

            info!(
                "Created and persisted new CA to Secret {}/{}",
                LATTICE_SYSTEM_NAMESPACE, CA_SECRET
            );
            Ok(CertificateAuthorityBundle::new(ca))
        }
        Err(e) => Err(CellServerError::CaPersistence(format!(
            "Failed to get CA secret: {}",
            e
        ))),
    }
}

/// Persist CA bundle to Secret
async fn persist_ca_bundle(
    client: &Client,
    bundle: &CertificateAuthorityBundle,
) -> Result<(), CellServerError> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);

    let active = bundle.active();

    // Build data map
    let mut data = BTreeMap::new();
    data.insert(
        CA_CERT_KEY.to_string(),
        ByteString(active.ca_cert_pem().as_bytes().to_vec()),
    );
    data.insert(
        CA_KEY_KEY.to_string(),
        ByteString(active.ca_key_pem().as_bytes().to_vec()),
    );

    // If there are additional CAs in the bundle, store them in trust bundle
    if bundle.len() > 1 {
        // The trust bundle contains all CA certs for verification
        data.insert(
            CA_TRUST_KEY.to_string(),
            ByteString(bundle.trust_bundle_pem().as_bytes().to_vec()),
        );
    }

    let secret = Secret {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some(CA_SECRET.to_string()),
            namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
            ..Default::default()
        },
        type_: Some("Opaque".to_string()),
        data: Some(data),
        ..Default::default()
    };

    // Use patch to update (or create if missing)
    secrets
        .patch(
            CA_SECRET,
            &kube::api::PatchParams::apply("lattice-operator"),
            &kube::api::Patch::Apply(&secret),
        )
        .await
        .map_err(|e| {
            CellServerError::CaPersistence(format!("Failed to update CA secret: {}", e))
        })?;

    info!("Persisted CA bundle to Secret");
    Ok(())
}

impl<G: ManifestGenerator + Send + Sync + 'static> ParentServers<G> {
    /// Create a new ParentServers instance with persisted CA
    ///
    /// Loads CA from Secret if it exists, otherwise creates and persists a new one.
    /// This ensures the CA survives operator restarts.
    pub async fn new(config: ParentConfig, client: &Client) -> Result<Self, CellServerError> {
        let ca_bundle = Arc::new(RwLock::new(load_or_create_ca(client).await?));
        let subtree_registry = Arc::new(SubtreeRegistry::new(config.cluster_name.clone()));

        Ok(Self {
            running: AtomicBool::new(false),
            config,
            ca_bundle,
            kube_client: client.clone(),
            bootstrap_state: Arc::new(RwLock::new(None)),
            agent_registry: Arc::new(AgentRegistry::new()),
            subtree_registry,
            handles: RwLock::new(None),
        })
    }

    /// Create with an existing CA (for testing)
    #[cfg(test)]
    pub fn with_ca(config: ParentConfig, ca: CertificateAuthority, client: Client) -> Self {
        let subtree_registry = Arc::new(SubtreeRegistry::new(config.cluster_name.clone()));

        Self {
            running: AtomicBool::new(false),
            config,
            ca_bundle: Arc::new(RwLock::new(CertificateAuthorityBundle::new(ca))),
            kube_client: client,
            bootstrap_state: Arc::new(RwLock::new(None)),
            agent_registry: Arc::new(AgentRegistry::new()),
            subtree_registry,
            handles: RwLock::new(None),
        }
    }

    /// Check if the servers are running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get the agent registry
    pub fn agent_registry(&self) -> SharedAgentRegistry {
        self.agent_registry.clone()
    }

    /// Get the subtree registry
    pub fn subtree_registry(&self) -> SharedSubtreeRegistry {
        self.subtree_registry.clone()
    }

    /// Get the CA bundle
    pub fn ca_bundle(&self) -> &Arc<RwLock<CertificateAuthorityBundle>> {
        &self.ca_bundle
    }

    /// Get the CA trust bundle PEM (contains all trusted CA certificates)
    pub async fn ca_trust_bundle_pem(&self) -> String {
        self.ca_bundle.read().await.trust_bundle_pem()
    }

    /// Get the bootstrap state (if servers are running)
    pub async fn bootstrap_state(&self) -> Option<Arc<BootstrapState<G>>> {
        self.bootstrap_state.read().await.clone()
    }

    /// Get the operator image from config
    pub fn image(&self) -> &str {
        &self.config.image
    }

    /// Get registry credentials from config
    pub fn registry_credentials(&self) -> Option<&str> {
        self.config.registry_credentials.as_deref()
    }

    /// Check if CA needs rotation (at 80% TTL)
    pub async fn ca_needs_rotation(&self) -> Result<bool, CellServerError> {
        self.ca_bundle
            .read()
            .await
            .needs_rotation()
            .map_err(|e| CellServerError::CaCreation(format!("Failed to check CA rotation: {}", e)))
    }

    /// Rotate the CA if needed
    ///
    /// Creates a new CA and adds it to the bundle. The new CA becomes the active
    /// signing CA, while old CAs remain trusted for verification during the
    /// transition period.
    ///
    /// Returns Ok(true) if rotation was performed, Ok(false) if not needed.
    pub async fn rotate_ca_if_needed(&self) -> Result<bool, CellServerError> {
        let needs_rotation = self.ca_needs_rotation().await?;
        if !needs_rotation {
            return Ok(false);
        }

        info!("CA needs rotation, generating new CA...");

        {
            let mut bundle = self.ca_bundle.write().await;
            bundle
                .rotate("Lattice CA")
                .map_err(|e| CellServerError::CaCreation(format!("Failed to rotate CA: {}", e)))?;

            // Prune any expired CAs from the bundle
            bundle.prune_expired();

            info!(
                ca_count = bundle.len(),
                "CA rotated successfully, bundle now has {} CA(s)",
                bundle.len()
            );
        }

        // Persist the updated bundle
        let bundle = self.ca_bundle.read().await;
        persist_ca_bundle(&self.kube_client, &bundle).await?;

        Ok(true)
    }

    /// Start the cell servers if not already running
    ///
    /// This is idempotent - calling multiple times is safe.
    /// Returns Ok(true) if servers were started, Ok(false) if already running.
    ///
    /// # Arguments
    ///
    /// * `manifest_generator` - Generator for bootstrap manifests
    /// * `extra_sans` - Additional SANs to include in server certificate (e.g., cell host IP)
    /// * `kube_client` - Kubernetes client for K8s API access
    pub async fn ensure_running(
        &self,
        manifest_generator: G,
        extra_sans: &[String],
        kube_client: Client,
    ) -> Result<bool, CellServerError> {
        // Use compare_exchange to atomically check and set
        if self
            .running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            // Already running
            return Ok(false);
        }

        info!("Starting cell servers...");

        // Get CA bundle for certificate generation
        let ca_bundle = self.ca_bundle.read().await;

        // Create bootstrap state
        // CloudProvider/SecretProvider CRDs and their referenced secrets
        // are automatically synced to child clusters during pivot
        let bootstrap_state = Arc::new(BootstrapState::new(
            manifest_generator,
            self.config.token_ttl,
            self.ca_bundle.clone(),
            self.config.image.clone(),
            self.config.registry_credentials.clone(),
            Some(kube_client.clone()),
        ));

        // Store bootstrap state
        *self.bootstrap_state.write().await = Some(bootstrap_state.clone());

        // Generate server certificates with default SANs + extra SANs (e.g., cell host IP)
        let mut all_sans: Vec<&str> = self.config.server_sans.iter().map(|s| s.as_str()).collect();
        for san in extra_sans {
            all_sans.push(san.as_str());
        }
        let sans = all_sans;
        let (server_cert_pem, server_key_pem) = ca_bundle
            .generate_server_cert(&sans)
            .map_err(|e| CellServerError::CertGeneration(e.to_string()))?;

        info!(sans = ?sans, "Generated server certificate");

        // Clone kube_client for services before it's moved
        let grpc_kube_client = kube_client.clone();
        let sync_client = kube_client.clone();

        // Create bootstrap router
        let app_router = bootstrap_router(bootstrap_state);
        let bootstrap_addr = self.config.bootstrap_addr;

        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
            server_cert_pem.as_bytes().to_vec(),
            server_key_pem.as_bytes().to_vec(),
        )
        .await
        .map_err(|e| CellServerError::TlsConfig(e.to_string()))?;

        info!(addr = %bootstrap_addr, "Starting HTTPS server (bootstrap)");
        let bootstrap_handle = tokio::spawn(async move {
            if let Err(e) = axum_server::bind_rustls(bootstrap_addr, tls_config)
                .serve(app_router.into_make_service())
                .await
            {
                error!(error = %e, "HTTPS server error");
            }
        });

        // Start gRPC server
        let (grpc_cert_pem, grpc_key_pem) = ca_bundle
            .generate_server_cert(&sans)
            .map_err(|e| CellServerError::CertGeneration(e.to_string()))?;

        // Use trust bundle for verification (includes all CAs during rotation)
        let ca_trust_bundle = ca_bundle.trust_bundle_pem();
        let mtls_config =
            ServerMtlsConfig::new(grpc_cert_pem, grpc_key_pem, ca_trust_bundle.clone());

        // Drop the read lock before spawning tasks
        drop(ca_bundle);

        // Set proxy config for kubeconfig patching during unpivot
        // Use auth proxy port so kubeconfigs can be used post-pivot with Cedar authorization
        let proxy_url = format!(
            "https://{}:{}",
            lattice_svc_dns(CELL_SERVICE_NAME),
            self.config.auth_proxy_addr.port()
        );
        self.agent_registry
            .set_proxy_config(crate::connection::KubeconfigProxyConfig {
                url: proxy_url,
                ca_cert_pem: ca_trust_bundle,
            });

        let grpc_addr = self.config.grpc_addr;
        let registry = self.agent_registry.clone();
        let subtree_registry = self.subtree_registry.clone();

        info!(addr = %grpc_addr, "Starting gRPC server");
        let grpc_handle = tokio::spawn(async move {
            if let Err(e) = AgentServer::serve_with_mtls(
                registry,
                subtree_registry,
                grpc_addr,
                mtls_config,
                grpc_kube_client,
            )
            .await
            {
                error!(error = %e, "gRPC server error");
            }
        });

        // Start resource sync service (secrets + configmaps + policies + providers)
        let sync_registry = self.agent_registry.clone();
        let sync_cluster_name = self.config.cluster_name.clone();
        info!("Starting resource sync service");
        let secret_sync_handle = tokio::spawn(async move {
            run_resource_sync(sync_client, sync_registry, sync_cluster_name).await;
        });

        // Start K8s API proxy server
        let proxy_addr = self.config.proxy_addr;
        let proxy_registry = self.agent_registry.clone();
        let ca_bundle_for_proxy = self.ca_bundle.read().await;
        let (proxy_cert_pem, proxy_key_pem) = ca_bundle_for_proxy
            .generate_server_cert(&sans)
            .map_err(|e| CellServerError::CertGeneration(e.to_string()))?;
        drop(ca_bundle_for_proxy);

        info!(addr = %proxy_addr, "Starting CAPI proxy server");
        let proxy_handle = tokio::spawn(async move {
            let config = CapiProxyConfig {
                addr: proxy_addr,
                cert_pem: proxy_cert_pem,
                key_pem: proxy_key_pem,
            };
            if let Err(e) = start_capi_proxy(proxy_registry, config).await {
                error!(error = %e, "CAPI proxy server error");
            }
        });

        // Store handles
        *self.handles.write().await = Some(ServerHandles {
            bootstrap_handle,
            grpc_handle,
            secret_sync_handle,
            proxy_handle,
        });

        info!("Cell servers started successfully");
        Ok(true)
    }

    /// Shutdown the servers
    pub async fn shutdown(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            // Not running
            return;
        }

        info!("Shutting down cell servers...");

        if let Some(handles) = self.handles.write().await.take() {
            handles.bootstrap_handle.abort();
            handles.grpc_handle.abort();
            handles.secret_sync_handle.abort();
            handles.proxy_handle.abort();
        }

        *self.bootstrap_state.write().await = None;

        info!("Cell servers shut down");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::ManifestGenerator;
    use lattice_common::crd::ProviderType;

    /// Mock manifest generator for testing
    struct MockManifestGenerator;

    #[async_trait::async_trait]
    impl ManifestGenerator for MockManifestGenerator {
        async fn generate(
            &self,
            _image: &str,
            _registry_credentials: Option<&str>,
            _cluster_name: Option<&str>,
            _provider: Option<ProviderType>,
        ) -> Vec<String> {
            vec!["mock-manifest".to_string()]
        }
    }

    /// Try to get a Kubernetes client for testing
    /// Returns None if no kubeconfig is available (e.g., in CI without a cluster)
    async fn try_test_client() -> Option<Client> {
        Client::try_default().await.ok()
    }

    async fn test_parent_servers() -> Option<ParentServers<MockManifestGenerator>> {
        // Install crypto provider (ok if already installed)
        lattice_common::install_crypto_provider();

        let client = try_test_client().await?;
        let config = ParentConfig {
            cluster_name: "test-cluster".to_string(),
            bootstrap_addr: "127.0.0.1:0".parse().expect("valid address"),
            grpc_addr: "127.0.0.1:0".parse().expect("valid address"),
            ..Default::default()
        };
        let ca = CertificateAuthority::new("Test CA").expect("CA creation should succeed");
        Some(ParentServers::with_ca(config, ca, client))
    }

    #[test]
    fn test_default_config() {
        let config = ParentConfig::default();
        assert_eq!(
            config.bootstrap_addr,
            format!("0.0.0.0:{}", lattice_common::DEFAULT_BOOTSTRAP_PORT)
                .parse()
                .expect("valid address")
        );
        assert_eq!(
            config.grpc_addr,
            format!("0.0.0.0:{}", lattice_common::DEFAULT_GRPC_PORT)
                .parse()
                .expect("valid address")
        );
        assert_eq!(config.token_ttl, Duration::from_secs(3600));
        assert!(!config.server_sans.is_empty());
    }

    #[tokio::test]
    async fn test_parent_servers_creation() {
        lattice_common::install_crypto_provider();
        let Some(client) = try_test_client().await else {
            return; // Skip if no kubeconfig available
        };
        let config = ParentConfig::default();
        let ca = CertificateAuthority::new("Test CA").expect("CA creation should succeed");
        let servers: ParentServers<MockManifestGenerator> =
            ParentServers::with_ca(config, ca, client);
        assert!(!servers.is_running());
    }

    #[tokio::test]
    async fn test_parent_servers_not_running_initially() {
        let Some(servers) = test_parent_servers().await else {
            return; // Skip if no kubeconfig available
        };
        assert!(!servers.is_running());
    }

    #[tokio::test]
    async fn test_ensure_running_starts_servers() {
        // Install crypto provider before creating kube client (which uses TLS)
        lattice_common::install_crypto_provider();

        let Some(client) = try_test_client().await else {
            // Skip test if no kubeconfig available
            return;
        };

        let Some(servers) = test_parent_servers().await else {
            return; // Skip if no kubeconfig available
        };

        // Start servers
        let result = servers
            .ensure_running(MockManifestGenerator, &[], client.clone())
            .await;
        assert!(result.is_ok());
        assert!(result.expect("ensure_running should succeed")); // Should return true (started)
        assert!(servers.is_running());

        // Second call should return false (already running)
        let result = servers
            .ensure_running(MockManifestGenerator, &[], client)
            .await;
        assert!(result.is_ok());
        assert!(!result.expect("ensure_running should succeed")); // Should return false (was already running)

        // Cleanup
        servers.shutdown().await;
        assert!(!servers.is_running());
    }

    #[tokio::test]
    async fn test_shutdown_idempotent() {
        let Some(servers) = test_parent_servers().await else {
            return; // Skip if no kubeconfig available
        };

        // Shutdown without starting should be safe
        servers.shutdown().await;
        assert!(!servers.is_running());

        // Start and shutdown (only if we have a client)
        if let Some(client) = try_test_client().await {
            servers
                .ensure_running(MockManifestGenerator, &[], client)
                .await
                .expect("ensure_running should succeed");
            servers.shutdown().await;
            assert!(!servers.is_running());

            // Double shutdown should be safe
            servers.shutdown().await;
            assert!(!servers.is_running());
        }
    }

    #[tokio::test]
    async fn test_bootstrap_state_available_after_start() {
        // Install crypto provider before creating kube client (which uses TLS)
        lattice_common::install_crypto_provider();

        let Some(servers) = test_parent_servers().await else {
            return; // Skip if no kubeconfig available
        };

        let Some(client) = try_test_client().await else {
            return; // Skip if no kubeconfig available
        };

        // Before start, bootstrap state should be None
        assert!(servers.bootstrap_state().await.is_none());

        // After start, bootstrap state should be available
        servers
            .ensure_running(MockManifestGenerator, &[], client)
            .await
            .expect("ensure_running should succeed");
        assert!(servers.bootstrap_state().await.is_some());

        // After shutdown, bootstrap state should be None again
        servers.shutdown().await;
        assert!(servers.bootstrap_state().await.is_none());
    }

    #[test]
    fn test_load_registry_credentials_no_env_var() {
        // Ensure env var is not set
        std::env::remove_var("REGISTRY_CREDENTIALS_FILE");
        let result = load_registry_credentials();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_registry_credentials_file_not_found() {
        std::env::set_var("REGISTRY_CREDENTIALS_FILE", "/nonexistent/path/to/file");
        let result = load_registry_credentials();
        assert!(result.is_none());
        std::env::remove_var("REGISTRY_CREDENTIALS_FILE");
    }

    #[test]
    fn test_load_registry_credentials_file_exists() {
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!("test_creds_{}.txt", std::process::id()));
        std::fs::write(&temp_file, "test-credentials").expect("write temp file");

        std::env::set_var("REGISTRY_CREDENTIALS_FILE", temp_file.to_str().unwrap());
        let result = load_registry_credentials();
        assert_eq!(result, Some("test-credentials".to_string()));

        std::env::remove_var("REGISTRY_CREDENTIALS_FILE");
        std::fs::remove_file(&temp_file).ok();
    }
}
