//! Proxy backend abstraction
//!
//! Defines the `ProxyBackend` trait that decouples the auth proxy from any specific
//! tunnel/registry implementation (e.g., `lattice-cell`). This enables deploying the
//! auth proxy as a standalone service with its own tunnel mechanism.

use std::collections::HashMap;

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use tokio::sync::mpsc;

use lattice_proto::ExecData;

/// Route information for reaching a cluster through the proxy
#[derive(Clone, Debug)]
pub struct ProxyRouteInfo {
    /// Whether this cluster is the current cell itself
    pub is_self: bool,
    /// Agent ID to route through (None if this is self)
    pub agent_id: Option<String>,
    /// Whether the agent is currently connected
    pub connected: bool,
    /// Labels for policy matching
    pub labels: HashMap<String, String>,
}

/// Parameters for a K8s API tunnel request
pub struct K8sTunnelRequest {
    /// HTTP method/verb
    pub method: String,
    /// API path (e.g., /api/v1/pods)
    pub path: String,
    /// Query string
    pub query: String,
    /// Request body
    pub body: Vec<u8>,
    /// Content-Type header
    pub content_type: String,
    /// Accept header
    pub accept: String,
    /// Target cluster name
    pub target_cluster: String,
    /// Source user identity
    pub source_user: String,
    /// Source user groups
    pub source_groups: Vec<String>,
}

/// Parameters for an exec tunnel request
pub struct ExecTunnelRequest {
    /// API path (e.g., /api/v1/namespaces/default/pods/nginx/exec)
    pub path: String,
    /// Query string (command=sh&stdin=true&stdout=true&tty=true)
    pub query: String,
    /// Target cluster name
    pub target_cluster: String,
    /// Source user identity
    pub source_user: String,
    /// Source user groups
    pub source_groups: Vec<String>,
}

/// Errors from proxy backend operations
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// Cluster not found in backend
    #[error("cluster not found: {0}")]
    ClusterNotFound(String),

    /// Agent is disconnected
    #[error("agent disconnected")]
    AgentDisconnected,

    /// Request timed out
    #[error("request timed out")]
    Timeout,

    /// Failed to send request to agent
    #[error("send failed: {0}")]
    SendFailed(String),

    /// Agent returned an error
    #[error("agent error: {0}")]
    AgentError(String),

    /// Failed to build HTTP response
    #[error("response build error: {0}")]
    ResponseBuild(String),

    /// Backend not configured
    #[error("backend not configured")]
    NotConfigured,
}

/// Handle for an active exec session
///
/// Provides methods to send stdin and resize events to the remote process.
#[async_trait]
pub trait ExecSessionHandle: Send + Sync {
    /// Get the unique request ID for this session
    fn request_id(&self) -> &str;

    /// Send stdin data to the remote process
    async fn send_stdin(&self, data: Vec<u8>) -> Result<(), ProxyError>;

    /// Send terminal resize event
    async fn send_resize(&self, width: u32, height: u32) -> Result<(), ProxyError>;

    /// Close stdin (signal EOF)
    async fn close_stdin(&self) -> Result<(), ProxyError>;
}

/// Abstraction over cluster routing and tunneling
///
/// Implementations provide the actual routing (via SubtreeRegistry + AgentRegistry,
/// or any other mechanism) while the auth proxy only depends on this trait.
#[async_trait]
pub trait ProxyBackend: Send + Sync {
    /// Get route info for a cluster
    ///
    /// Returns None if the cluster is not known to this backend.
    async fn get_route(&self, cluster_name: &str) -> Option<ProxyRouteInfo>;

    /// Get all clusters with their labels (for kubeconfig generation and Cedar)
    async fn all_clusters(&self) -> Vec<(String, HashMap<String, String>)>;

    /// Tunnel a K8s API request to a remote cluster
    async fn tunnel_request(
        &self,
        agent_id: &str,
        request: K8sTunnelRequest,
    ) -> Result<Response<Body>, ProxyError>;

    /// Start an exec/attach/portforward session on a remote cluster
    ///
    /// Returns a session handle and a receiver for output data from the agent.
    async fn start_exec_session(
        &self,
        agent_id: &str,
        request: ExecTunnelRequest,
    ) -> Result<(Box<dyn ExecSessionHandle>, mpsc::Receiver<ExecData>), ProxyError>;
}
