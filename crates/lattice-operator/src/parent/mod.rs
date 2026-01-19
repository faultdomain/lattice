//! Parent servers for on-demand gRPC and bootstrap HTTP servers
//!
//! When a cluster has parent configuration (can have children), it runs:
//! - gRPC server: for child agent bidirectional streams
//! - Bootstrap HTTP server: for kubeadm postKubeadmCommands webhook
//!
//! This module provides `ParentServers` which starts these servers on-demand.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::ByteString;
use kube::api::{Api, PostParams};
use kube::Client;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::agent::connection::{AgentRegistry, SharedAgentRegistry};
use crate::agent::mtls::ServerMtlsConfig;
use crate::agent::server::AgentServer;
use crate::bootstrap::{
    bootstrap_router, BootstrapState, DefaultManifestGenerator, ManifestGenerator,
    CAPMOX_NAMESPACE, CAPMOX_SECRET_NAME,
};
use crate::pki::CertificateAuthority;
use crate::webhook::{webhook_router, WebhookState};

/// Configuration for cell servers
#[derive(Debug, Clone)]
pub struct ParentConfig {
    /// Address for the bootstrap HTTPS server
    pub bootstrap_addr: SocketAddr,
    /// Address for the gRPC server
    pub grpc_addr: SocketAddr,
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
            bootstrap_addr: format!("0.0.0.0:{}", crate::DEFAULT_BOOTSTRAP_PORT)
                .parse()
                .expect("hardcoded socket address is valid"),
            grpc_addr: format!("0.0.0.0:{}", crate::DEFAULT_GRPC_PORT)
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
                "lattice-webhook.lattice-system.svc".to_string(),
            ],
            image: std::env::var("LATTICE_IMAGE")
                .unwrap_or_else(|_| "ghcr.io/evan-hines-js/lattice:latest".to_string()),
            registry_credentials: std::env::var("REGISTRY_CREDENTIALS_FILE")
                .ok()
                .and_then(|path| std::fs::read_to_string(&path).ok()),
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
    /// Certificate Authority for signing agent certificates
    ca: Arc<CertificateAuthority>,
    /// Bootstrap state for cluster registration
    bootstrap_state: Arc<RwLock<Option<Arc<BootstrapState<G>>>>>,
    /// Agent registry for connected agents
    agent_registry: SharedAgentRegistry,
    /// Server handles
    handles: RwLock<Option<ServerHandles>>,
}

struct ServerHandles {
    bootstrap_handle: JoinHandle<()>,
    grpc_handle: JoinHandle<()>,
}

/// Secret name for persisting the CA
const CA_SECRET_NAME: &str = "lattice-ca";
/// Namespace for the CA secret
const CA_SECRET_NAMESPACE: &str = "lattice-system";

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

/// Load CA from Secret or create a new one and persist it
///
/// This ensures the CA survives operator restarts. The CA is stored in a Secret
/// named `lattice-ca` in the `lattice-system` namespace.
///
/// # Arguments
/// * `client` - Kubernetes client for accessing the Secret
///
/// # Returns
/// The CA, either loaded from the Secret or newly created
pub async fn load_or_create_ca(client: &Client) -> Result<CertificateAuthority, CellServerError> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), CA_SECRET_NAMESPACE);

    // Try to load existing CA from Secret
    match secrets.get(CA_SECRET_NAME).await {
        Ok(secret) => {
            // CA Secret exists, load it
            let data = secret.data.ok_or_else(|| {
                CellServerError::CaPersistence("CA secret exists but has no data".to_string())
            })?;

            let cert_pem = data
                .get("ca.crt")
                .ok_or_else(|| {
                    CellServerError::CaPersistence("CA secret missing ca.crt".to_string())
                })
                .and_then(|b| {
                    String::from_utf8(b.0.clone()).map_err(|e| {
                        CellServerError::CaPersistence(format!("Invalid ca.crt encoding: {}", e))
                    })
                })?;

            let key_pem = data
                .get("ca.key")
                .ok_or_else(|| {
                    CellServerError::CaPersistence("CA secret missing ca.key".to_string())
                })
                .and_then(|b| {
                    String::from_utf8(b.0.clone()).map_err(|e| {
                        CellServerError::CaPersistence(format!("Invalid ca.key encoding: {}", e))
                    })
                })?;

            let ca = CertificateAuthority::from_pem(&cert_pem, &key_pem)
                .map_err(|e| CellServerError::CaPersistence(format!("Failed to load CA: {}", e)))?;

            info!(
                "Loaded existing CA from Secret {}/{}",
                CA_SECRET_NAMESPACE, CA_SECRET_NAME
            );
            Ok(ca)
        }
        Err(kube::Error::Api(e)) if e.code == 404 => {
            // CA Secret doesn't exist, create a new CA and persist it
            info!("CA Secret not found, creating new CA");

            let ca = CertificateAuthority::new("Lattice CA")
                .map_err(|e| CellServerError::CaCreation(e.to_string()))?;

            // Create Secret with CA cert and key
            let secret = Secret {
                metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                    name: Some(CA_SECRET_NAME.to_string()),
                    namespace: Some(CA_SECRET_NAMESPACE.to_string()),
                    ..Default::default()
                },
                type_: Some("Opaque".to_string()),
                data: Some(BTreeMap::from([
                    (
                        "ca.crt".to_string(),
                        ByteString(ca.ca_cert_pem().as_bytes().to_vec()),
                    ),
                    (
                        "ca.key".to_string(),
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
                CA_SECRET_NAMESPACE, CA_SECRET_NAME
            );
            Ok(ca)
        }
        Err(e) => Err(CellServerError::CaPersistence(format!(
            "Failed to get CA secret: {}",
            e
        ))),
    }
}

impl<G: ManifestGenerator + Send + Sync + 'static> ParentServers<G> {
    /// Create a new ParentServers instance with persisted CA
    ///
    /// Loads CA from Secret if it exists, otherwise creates and persists a new one.
    /// This ensures the CA survives operator restarts.
    pub async fn new(config: ParentConfig, client: &Client) -> Result<Self, CellServerError> {
        let ca = Arc::new(load_or_create_ca(client).await?);

        Ok(Self {
            running: AtomicBool::new(false),
            config,
            ca,
            bootstrap_state: Arc::new(RwLock::new(None)),
            agent_registry: Arc::new(AgentRegistry::new()),
            handles: RwLock::new(None),
        })
    }

    /// Create with an existing CA (for testing)
    #[cfg(test)]
    pub fn with_ca(config: ParentConfig, ca: Arc<CertificateAuthority>) -> Self {
        Self {
            running: AtomicBool::new(false),
            config,
            ca,
            bootstrap_state: Arc::new(RwLock::new(None)),
            agent_registry: Arc::new(AgentRegistry::new()),
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

    /// Get the CA
    pub fn ca(&self) -> &Arc<CertificateAuthority> {
        &self.ca
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

    /// Get CAPMOX credentials (blocking read of bootstrap state)
    ///
    /// Returns None if servers not running or no credentials available.
    /// Returns owned strings to avoid lifetime issues with the lock.
    pub fn capmox_credentials(&self) -> Option<(String, String, String)> {
        // Use try_read to avoid blocking - if locked, return None
        if let Ok(guard) = self.bootstrap_state.try_read() {
            if let Some(ref state) = *guard {
                return state
                    .capmox_credentials()
                    .map(|(u, t, s)| (u.to_string(), t.to_string(), s.to_string()));
            }
        }
        None
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
    /// * `kube_client` - Kubernetes client for webhook to lookup LatticeServices
    pub async fn ensure_running_with(
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

        // Try to read CAPMOX credentials from Secret (if this cluster has them)
        let capmox_credentials = Self::read_capmox_credentials(&kube_client).await;
        if capmox_credentials.is_some() {
            info!("CAPMOX credentials loaded, will propagate to Proxmox child clusters");
        }

        // Create bootstrap state
        let bootstrap_state = Arc::new(BootstrapState::new(
            manifest_generator,
            self.config.token_ttl,
            self.ca.clone(),
            self.config.image.clone(),
            self.config.registry_credentials.clone(),
            Some(kube_client.clone()),
            capmox_credentials,
        ));

        // Store bootstrap state
        *self.bootstrap_state.write().await = Some(bootstrap_state.clone());

        // Generate server certificates with default SANs + extra SANs (e.g., cell host IP)
        let mut all_sans: Vec<&str> = self.config.server_sans.iter().map(|s| s.as_str()).collect();
        for san in extra_sans {
            all_sans.push(san.as_str());
        }
        let sans = all_sans;
        let (server_cert_pem, server_key_pem) = self
            .ca
            .generate_server_cert(&sans)
            .map_err(|e| CellServerError::CertGeneration(e.to_string()))?;

        info!(sans = ?self.config.server_sans, "Generated server certificate");

        // Clone kube_client for gRPC server before it's moved into WebhookState
        let grpc_kube_client = kube_client.clone();

        // Create routers
        let bootstrap_router = bootstrap_router(bootstrap_state);
        let webhook_state = Arc::new(WebhookState::new(kube_client));
        let webhook_router = webhook_router(webhook_state);

        // Merge bootstrap and webhook routers into a single HTTPS server
        let app_router = bootstrap_router.merge(webhook_router);
        let bootstrap_addr = self.config.bootstrap_addr;

        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
            server_cert_pem.as_bytes().to_vec(),
            server_key_pem.as_bytes().to_vec(),
        )
        .await
        .map_err(|e| CellServerError::TlsConfig(e.to_string()))?;

        info!(addr = %bootstrap_addr, "Starting HTTPS server (bootstrap + webhook)");
        let bootstrap_handle = tokio::spawn(async move {
            if let Err(e) = axum_server::bind_rustls(bootstrap_addr, tls_config)
                .serve(app_router.into_make_service())
                .await
            {
                error!(error = %e, "HTTPS server error");
            }
        });

        // Start gRPC server
        let (grpc_cert_pem, grpc_key_pem) = self
            .ca
            .generate_server_cert(&sans)
            .map_err(|e| CellServerError::CertGeneration(e.to_string()))?;

        let mtls_config = ServerMtlsConfig::new(
            grpc_cert_pem,
            grpc_key_pem,
            self.ca.ca_cert_pem().to_string(),
        );

        let grpc_addr = self.config.grpc_addr;
        let registry = self.agent_registry.clone();

        info!(addr = %grpc_addr, "Starting gRPC server");
        let grpc_handle = tokio::spawn(async move {
            if let Err(e) =
                AgentServer::serve_with_mtls(registry, grpc_addr, mtls_config, grpc_kube_client)
                    .await
            {
                error!(error = %e, "gRPC server error");
            }
        });

        // Store handles
        *self.handles.write().await = Some(ServerHandles {
            bootstrap_handle,
            grpc_handle,
        });

        info!("Cell servers started successfully");
        Ok(true)
    }

    /// Read CAPMOX credentials from the local Secret if it exists
    async fn read_capmox_credentials(client: &Client) -> Option<(String, String, String)> {
        let secrets: Api<Secret> = Api::namespaced(client.clone(), CAPMOX_NAMESPACE);

        match secrets.get(CAPMOX_SECRET_NAME).await {
            Ok(secret) => {
                let data = secret.data.as_ref()?;

                let url = data
                    .get("url")
                    .and_then(|b| String::from_utf8(b.0.clone()).ok())?;
                let token = data
                    .get("token")
                    .and_then(|b| String::from_utf8(b.0.clone()).ok())?;
                let secret_val = data
                    .get("secret")
                    .and_then(|b| String::from_utf8(b.0.clone()).ok())?;

                Some((url, token, secret_val))
            }
            Err(_) => None,
        }
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
        }

        *self.bootstrap_state.write().await = None;

        info!("Cell servers shut down");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::ManifestGenerator;

    /// Mock manifest generator for testing
    struct MockManifestGenerator;

    impl ManifestGenerator for MockManifestGenerator {
        fn generate(
            &self,
            _image: &str,
            _registry_credentials: Option<&str>,
            _cluster_name: Option<&str>,
            _provider: Option<&str>,
            _bootstrap: Option<&str>,
        ) -> Vec<String> {
            vec!["mock-manifest".to_string()]
        }
    }

    fn test_parent_servers() -> ParentServers<MockManifestGenerator> {
        // Install crypto provider (ok if already installed)
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let config = ParentConfig {
            bootstrap_addr: "127.0.0.1:0".parse().unwrap(),
            grpc_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let ca = Arc::new(CertificateAuthority::new("Test CA").unwrap());
        ParentServers::with_ca(config, ca)
    }

    /// Try to get a Kubernetes client for testing
    /// Returns None if no kubeconfig is available (e.g., in CI without a cluster)
    async fn try_test_client() -> Option<Client> {
        Client::try_default().await.ok()
    }

    #[test]
    fn test_default_config() {
        let config = ParentConfig::default();
        assert_eq!(
            config.bootstrap_addr,
            format!("0.0.0.0:{}", crate::DEFAULT_BOOTSTRAP_PORT)
                .parse()
                .unwrap()
        );
        assert_eq!(
            config.grpc_addr,
            format!("0.0.0.0:{}", crate::DEFAULT_GRPC_PORT)
                .parse()
                .unwrap()
        );
        assert_eq!(config.token_ttl, Duration::from_secs(3600));
        assert!(!config.server_sans.is_empty());
    }

    #[test]
    fn test_parent_servers_creation() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let config = ParentConfig::default();
        let ca = Arc::new(CertificateAuthority::new("Test CA").unwrap());
        let servers: ParentServers<MockManifestGenerator> = ParentServers::with_ca(config, ca);
        assert!(!servers.is_running());
    }

    #[test]
    fn test_parent_servers_not_running_initially() {
        let servers = test_parent_servers();
        assert!(!servers.is_running());
    }

    #[tokio::test]
    async fn test_ensure_running_starts_servers() {
        // Install crypto provider before creating kube client (which uses TLS)
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let Some(client) = try_test_client().await else {
            // Skip test if no kubeconfig available
            return;
        };

        let servers = test_parent_servers();

        // Start servers
        let result = servers
            .ensure_running_with(MockManifestGenerator, &[], client.clone())
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should return true (started)
        assert!(servers.is_running());

        // Second call should return false (already running)
        let result = servers
            .ensure_running_with(MockManifestGenerator, &[], client)
            .await;
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should return false (was already running)

        // Cleanup
        servers.shutdown().await;
        assert!(!servers.is_running());
    }

    #[tokio::test]
    async fn test_shutdown_idempotent() {
        let servers = test_parent_servers();

        // Shutdown without starting should be safe
        servers.shutdown().await;
        assert!(!servers.is_running());

        // Start and shutdown (only if we have a client)
        if let Some(client) = try_test_client().await {
            servers
                .ensure_running_with(MockManifestGenerator, &[], client)
                .await
                .unwrap();
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
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let Some(client) = try_test_client().await else {
            // Skip test if no kubeconfig available
            return;
        };

        let servers = test_parent_servers();

        // Before start, bootstrap state should be None
        assert!(servers.bootstrap_state().await.is_none());

        // After start, bootstrap state should be available
        servers
            .ensure_running_with(MockManifestGenerator, &[], client)
            .await
            .unwrap();
        assert!(servers.bootstrap_state().await.is_some());

        // After shutdown, bootstrap state should be None again
        servers.shutdown().await;
        assert!(servers.bootstrap_state().await.is_none());
    }
}
