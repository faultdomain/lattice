//! Lattice Agent - Child cluster runtime
//!
//! This crate provides the client-side runtime for child/workload clusters:
//!
//! - **Agent Client**: gRPC client connecting to the parent cell
//! - **Pivot Execution**: Importing CAPI manifests, patching kubeconfig
//! - **K8s Request Execution**: Handling K8s API requests from parent
//!
//! # Architecture
//!
//! The agent runs on child clusters and maintains an **outbound** connection
//! to the parent cell. All communication is initiated by the agent.

use std::sync::Arc;
use std::time::Duration;

pub mod client;
pub mod executor;
pub mod pivot;
pub mod subtree;
pub mod watch;

/// Default connection timeout for kube clients (5s is plenty for local API server)
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default read timeout for kube clients
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Trait for forwarding K8s API requests to child clusters.
///
/// When an agent receives a K8s request with a target_cluster that differs
/// from its local cluster name, it uses this forwarder to route the request
/// to the correct child cluster via its own parent_servers.
#[async_trait::async_trait]
pub trait K8sRequestForwarder: Send + Sync {
    /// Forward a K8s request to a target cluster in this agent's subtree.
    ///
    /// Returns the K8s response, or an error response if:
    /// - The cluster is not in this agent's subtree (404)
    /// - The cluster's agent is not connected (502)
    /// - The request times out (504)
    async fn forward(&self, target_cluster: &str, request: KubernetesRequest)
        -> KubernetesResponse;
}

/// Shared forwarder type used by the agent for hierarchical routing.
pub type SharedK8sForwarder = Arc<dyn K8sRequestForwarder>;

/// Build a K8s Status response with the given status code and message.
/// This creates a proper K8s API Status object in the response body.
pub fn build_k8s_status_response(
    request_id: &str,
    status_code: u32,
    message: &str,
) -> KubernetesResponse {
    let reason = match status_code {
        404 => "NotFound",
        502 => "BadGateway",
        504 => "GatewayTimeout",
        _ => "InternalError",
    };

    KubernetesResponse {
        request_id: request_id.to_string(),
        status_code,
        body: format!(
            r#"{{"kind":"Status","apiVersion":"v1","status":"Failure","message":"{}","reason":"{}","code":{}}}"#,
            message, reason, status_code
        ).into_bytes(),
        content_type: "application/json".to_string(),
        error: String::new(),
        streaming: false,
        stream_end: false,
    }
}

/// Build a 404 response for a cluster not found in the subtree.
pub fn build_cluster_not_found_response(
    target_cluster: &str,
    request_id: &str,
) -> KubernetesResponse {
    build_k8s_status_response(
        request_id,
        404,
        &format!("cluster '{}' not found in subtree", target_cluster),
    )
}

/// Create a Kubernetes client with proper timeouts
///
/// Uses in-cluster configuration with explicit timeouts (5s connect, 30s read)
/// instead of kube-rs defaults which may be too long and cause hangs.
pub async fn create_k8s_client() -> Result<kube::Client, kube::Error> {
    let mut config = kube::Config::infer()
        .await
        .map_err(kube::Error::InferConfig)?;
    config.connect_timeout = Some(DEFAULT_CONNECT_TIMEOUT);
    config.read_timeout = Some(DEFAULT_READ_TIMEOUT);
    kube::Client::try_from(config)
}

/// Create a Kubernetes client with logging, returning None on failure.
///
/// Helper for cases where client creation failure should be logged and handled
/// gracefully rather than propagated as an error.
pub async fn create_k8s_client_logged(purpose: &str) -> Option<kube::Client> {
    match create_k8s_client().await {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!(error = %e, "Failed to create K8s client for {}", purpose);
            None
        }
    }
}

/// Macro for getting a K8s client or returning early from a function.
///
/// Use this in async functions that should return early if client creation fails.
/// The purpose string is used in the warning log message.
#[macro_export]
macro_rules! get_client_or_return {
    ($purpose:expr) => {
        match $crate::create_k8s_client().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to create K8s client for {}", $purpose);
                return;
            }
        }
    };
}

pub use client::{AgentClient, AgentClientConfig, AgentCredentials, CertificateError, ClientState};

// Re-export protocol types from lattice_common
pub use executor::{execute_k8s_request, is_watch_request};
pub use lattice_common::{CsrRequest, CsrResponse};
pub use pivot::{
    apply_distributed_resources, patch_kubeconfig_for_self_management, DistributableResources,
    PivotError,
};
pub use subtree::SubtreeSender;
pub use watch::{build_k8s_error_response, execute_watch, WatchRegistry};

// Re-export proto types for convenience
pub use lattice_proto::{
    agent_message, cell_command, AgentMessage, AgentReady, AgentState, BootstrapComplete,
    CellCommand, ClusterDeleting, ClusterHealth, Heartbeat, KubernetesRequest, KubernetesResponse,
    StatusResponse,
};

// Re-export mTLS from infra
pub use lattice_infra::{ClientMtlsConfig, MtlsError, ServerMtlsConfig};
