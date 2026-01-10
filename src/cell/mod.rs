//! Cell servers for on-demand gRPC and bootstrap HTTP servers
//!
//! When a cluster detects a Pending LatticeCluster CRD, it becomes a "cell"
//! and needs to run:
//! - gRPC server: for agent bidirectional streams
//! - Bootstrap HTTP server: for kubeadm postKubeadmCommands webhook
//!
//! This module provides `CellServers` which starts these servers on-demand.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::agent::connection::{AgentRegistry, SharedAgentRegistry};
use crate::agent::mtls::ServerMtlsConfig;
use crate::agent::server::AgentServer;
use crate::bootstrap::{
    bootstrap_router, BootstrapState, DefaultManifestGenerator, ManifestGenerator,
};
use crate::pki::CertificateAuthority;

/// Configuration for cell servers
#[derive(Debug, Clone)]
pub struct CellConfig {
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

impl Default for CellConfig {
    fn default() -> Self {
        Self {
            bootstrap_addr: format!("0.0.0.0:{}", crate::DEFAULT_BOOTSTRAP_PORT).parse().unwrap(),
            grpc_addr: format!("0.0.0.0:{}", crate::DEFAULT_GRPC_PORT).parse().unwrap(),
            token_ttl: Duration::from_secs(3600),
            server_sans: vec![
                "localhost".to_string(),
                "host.docker.internal".to_string(),
                "host.containers.internal".to_string(),
                "172.17.0.1".to_string(),
                "127.0.0.1".to_string(),
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
pub struct CellServers<G: ManifestGenerator + Send + Sync + 'static = DefaultManifestGenerator> {
    /// Whether the servers have been started
    running: AtomicBool,
    /// Configuration
    config: CellConfig,
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

/// Error type for cell server operations
#[derive(Debug, thiserror::Error)]
pub enum CellServerError {
    /// Failed to create the Certificate Authority
    #[error("Failed to create CA: {0}")]
    CaCreation(String),
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

impl CellServers<DefaultManifestGenerator> {
    /// Create a new CellServers instance with default manifest generator
    pub fn new(config: CellConfig) -> Result<Self, CellServerError> {
        let ca = Arc::new(
            CertificateAuthority::new("Lattice CA")
                .map_err(|e| CellServerError::CaCreation(e.to_string()))?,
        );

        Ok(Self {
            running: AtomicBool::new(false),
            config,
            ca,
            bootstrap_state: Arc::new(RwLock::new(None)),
            agent_registry: Arc::new(AgentRegistry::new()),
            handles: RwLock::new(None),
        })
    }
}

impl<G: ManifestGenerator + Send + Sync + 'static> CellServers<G> {
    /// Create with a custom manifest generator
    pub fn with_generator(config: CellConfig, ca: Arc<CertificateAuthority>) -> Self {
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

    /// Start the cell servers if not already running
    ///
    /// This is idempotent - calling multiple times is safe.
    /// Returns Ok(true) if servers were started, Ok(false) if already running.
    ///
    /// # Arguments
    ///
    /// * `manifest_generator` - Generator for bootstrap manifests
    /// * `extra_sans` - Additional SANs to include in server certificate (e.g., cell host IP)
    pub async fn ensure_running_with(
        &self,
        manifest_generator: G,
        extra_sans: &[String],
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

        // Create bootstrap state
        let bootstrap_state = Arc::new(BootstrapState::new(
            manifest_generator,
            self.config.token_ttl,
            self.ca.clone(),
            self.config.image.clone(),
            self.config.registry_credentials.clone(),
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

        // Start bootstrap HTTPS server
        let bootstrap_router = bootstrap_router(bootstrap_state);
        let bootstrap_addr = self.config.bootstrap_addr;

        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
            server_cert_pem.as_bytes().to_vec(),
            server_key_pem.as_bytes().to_vec(),
        )
        .await
        .map_err(|e| CellServerError::TlsConfig(e.to_string()))?;

        info!(addr = %bootstrap_addr, "Starting bootstrap HTTPS server");
        let bootstrap_handle = tokio::spawn(async move {
            if let Err(e) = axum_server::bind_rustls(bootstrap_addr, tls_config)
                .serve(bootstrap_router.into_make_service())
                .await
            {
                error!(error = %e, "Bootstrap server error");
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
            if let Err(e) = AgentServer::serve_with_mtls(registry, grpc_addr, mtls_config).await {
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
        ) -> Vec<String> {
            vec!["mock-manifest".to_string()]
        }
    }

    fn test_cell_servers() -> CellServers<MockManifestGenerator> {
        // Install crypto provider (ok if already installed)
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let config = CellConfig {
            bootstrap_addr: "127.0.0.1:0".parse().unwrap(),
            grpc_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let ca = Arc::new(CertificateAuthority::new("Test CA").unwrap());
        CellServers::with_generator(config, ca)
    }

    #[test]
    fn test_default_config() {
        let config = CellConfig::default();
        assert_eq!(config.bootstrap_addr, format!("0.0.0.0:{}", crate::DEFAULT_BOOTSTRAP_PORT).parse().unwrap());
        assert_eq!(config.grpc_addr, format!("0.0.0.0:{}", crate::DEFAULT_GRPC_PORT).parse().unwrap());
        assert_eq!(config.token_ttl, Duration::from_secs(3600));
        assert!(!config.server_sans.is_empty());
    }

    #[test]
    fn test_cell_servers_creation() {
        let config = CellConfig::default();
        let servers = CellServers::new(config);
        assert!(servers.is_ok());
        let servers = servers.unwrap();
        assert!(!servers.is_running());
    }

    #[test]
    fn test_cell_servers_not_running_initially() {
        let servers = test_cell_servers();
        assert!(!servers.is_running());
    }

    #[tokio::test]
    async fn test_ensure_running_starts_servers() {
        let servers = test_cell_servers();

        // Start servers
        let result = servers.ensure_running_with(MockManifestGenerator, &[]).await;
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should return true (started)
        assert!(servers.is_running());

        // Second call should return false (already running)
        let result = servers.ensure_running_with(MockManifestGenerator, &[]).await;
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should return false (was already running)

        // Cleanup
        servers.shutdown().await;
        assert!(!servers.is_running());
    }

    #[tokio::test]
    async fn test_shutdown_idempotent() {
        let servers = test_cell_servers();

        // Shutdown without starting should be safe
        servers.shutdown().await;
        assert!(!servers.is_running());

        // Start and shutdown
        servers
            .ensure_running_with(MockManifestGenerator, &[])
            .await
            .unwrap();
        servers.shutdown().await;
        assert!(!servers.is_running());

        // Double shutdown should be safe
        servers.shutdown().await;
        assert!(!servers.is_running());
    }

    #[tokio::test]
    async fn test_bootstrap_state_available_after_start() {
        let servers = test_cell_servers();

        // Before start, bootstrap state should be None
        assert!(servers.bootstrap_state().await.is_none());

        // After start, bootstrap state should be available
        servers
            .ensure_running_with(MockManifestGenerator, &[])
            .await
            .unwrap();
        assert!(servers.bootstrap_state().await.is_some());

        // After shutdown, bootstrap state should be None again
        servers.shutdown().await;
        assert!(servers.bootstrap_state().await.is_none());
    }
}
