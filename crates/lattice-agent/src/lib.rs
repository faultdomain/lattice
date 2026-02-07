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

use lattice_proto::{ExecData, ExecRequest, KubernetesRequest, KubernetesResponse};
use tokio_util::sync::CancellationToken;

pub mod client;
pub mod commands;
pub mod config;
pub mod events;
pub mod exec;
pub mod executor;
pub mod health;
pub mod kube_client;
pub mod pivot;
pub mod subtree;
pub mod watch;

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

    /// Forward a watch/follow request to a target cluster with streaming response.
    ///
    /// Returns a receiver that yields multiple KubernetesResponse messages
    /// as watch events arrive. The stream ends when stream_end=true is received.
    async fn forward_watch(
        &self,
        target_cluster: &str,
        request: KubernetesRequest,
    ) -> Result<tokio::sync::mpsc::Receiver<KubernetesResponse>, String>;
}

/// Shared forwarder type used by the agent for hierarchical routing.
pub type SharedK8sForwarder = Arc<dyn K8sRequestForwarder>;

/// Handle for an exec session being forwarded to a child cluster.
///
/// This allows bidirectional communication with the child exec session.
pub struct ForwardedExecSession {
    /// Unique request ID for this session
    pub request_id: String,
    /// Sender for stdin data to the child session
    pub stdin_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Sender for resize events to the child session
    pub resize_tx: tokio::sync::mpsc::Sender<(u16, u16)>,
    /// Receiver for exec data (stdout/stderr) from the child session
    pub data_rx: tokio::sync::mpsc::Receiver<ExecData>,
    /// Cancellation token to signal session termination
    pub cancel_token: CancellationToken,
}

/// Trait for forwarding exec requests to child clusters.
///
/// When an agent receives an exec request with a target_cluster that differs
/// from its local cluster name, it uses this forwarder to start a session
/// on the child cluster via its own parent_servers.
#[async_trait::async_trait]
pub trait ExecRequestForwarder: Send + Sync {
    /// Start an exec session on a target cluster in this agent's subtree.
    ///
    /// Returns a session handle for bidirectional communication, or an error if:
    /// - The cluster is not in this agent's subtree
    /// - The cluster's agent is not connected
    async fn forward_exec(
        &self,
        target_cluster: &str,
        request: ExecRequest,
    ) -> Result<ForwardedExecSession, String>;
}

/// Shared exec forwarder type used by the agent for hierarchical exec routing.
pub type SharedExecForwarder = Arc<dyn ExecRequestForwarder>;

// =============================================================================
// Error Response Builders
// =============================================================================
// There are two types of error responses, used at different layers:
//
// 1. `build_k8s_status_response` - Creates a K8s Status JSON body for HTTP clients.
//    Used when responding to external clients (kubectl) who expect K8s API format.
//    The body contains a proper Status object; the `.error` field is empty.
//
// 2. `build_grpc_error_response` - Sets the `.error` field for gRPC protocol.
//    Used for internal errors within the agent/cell gRPC communication.
//    The receiving cell converts this to TunnelError::AgentError.
// =============================================================================

/// Build a K8s Status response for HTTP clients.
///
/// Creates a proper K8s API Status object in the response body. Use this when
/// the response will be sent directly to an HTTP client (kubectl, controllers).
///
/// The `.error` field is left empty - the error info is in the JSON body.
pub fn build_k8s_status_response(
    request_id: &str,
    status_code: u32,
    message: &str,
) -> KubernetesResponse {
    let reason = match status_code {
        400 => "BadRequest",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "NotFound",
        409 => "Conflict",
        500 => "InternalError",
        502 => "BadGateway",
        503 => "ServiceUnavailable",
        504 => "GatewayTimeout",
        _ => "Unknown",
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

/// Build an error response for the gRPC protocol layer.
///
/// Sets the `.error` field which signals to the receiving cell that the request
/// failed. The cell will convert this to `TunnelError::AgentError`.
///
/// Use this for internal errors during request execution (not for HTTP clients).
pub fn build_grpc_error_response(
    request_id: &str,
    status_code: u32,
    error: &str,
) -> KubernetesResponse {
    KubernetesResponse {
        request_id: request_id.to_string(),
        status_code,
        error: error.to_string(),
        ..Default::default()
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

pub use client::{AgentClient, AgentClientConfig, AgentCredentials, CertificateError, ClientState};
pub use exec::{execute_exec, ExecRegistry};
pub use executor::{execute_k8s_request, is_watch_request};
pub use kube_client::{InClusterClientProvider, KubeClientProvider};
pub use pivot::{apply_distributed_resources, patch_kubeconfig_for_self_management, PivotError};
pub use subtree::SubtreeSender;
pub use watch::{execute_watch, WatchRegistry};

use lattice_common::DistributableResources;

/// Convert proto DistributableResources to domain type.
///
/// This is a standalone function rather than a From impl because of Rust's
/// orphan rules - both types are defined in other crates.
pub fn distributable_resources_from_proto(
    proto: lattice_proto::DistributableResources,
) -> DistributableResources {
    DistributableResources {
        cloud_providers: proto.cloud_providers,
        secrets_providers: proto.secrets_providers,
        secrets: proto.secrets,
        cedar_policies: proto.cedar_policies,
        oidc_providers: proto.oidc_providers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_k8s_status_response_404() {
        let resp = build_k8s_status_response("req-1", 404, "not found");
        assert_eq!(resp.request_id, "req-1");
        assert_eq!(resp.status_code, 404);
        assert!(resp.error.is_empty());
        assert_eq!(resp.content_type, "application/json");
        let body = String::from_utf8_lossy(&resp.body);
        assert!(body.contains("\"kind\":\"Status\""));
        assert!(body.contains("\"reason\":\"NotFound\""));
        assert!(body.contains("\"code\":404"));
    }

    #[test]
    fn test_build_k8s_status_response_all_codes() {
        // Test all mapped status codes have correct reasons
        let cases = [
            (400, "BadRequest"),
            (401, "Unauthorized"),
            (403, "Forbidden"),
            (404, "NotFound"),
            (409, "Conflict"),
            (500, "InternalError"),
            (502, "BadGateway"),
            (503, "ServiceUnavailable"),
            (504, "GatewayTimeout"),
            (418, "Unknown"), // Unmapped code
        ];

        for (code, expected_reason) in cases {
            let resp = build_k8s_status_response("test", code, "msg");
            let body = String::from_utf8_lossy(&resp.body);
            assert!(
                body.contains(&format!("\"reason\":\"{}\"", expected_reason)),
                "Code {} should have reason {}, got body: {}",
                code,
                expected_reason,
                body
            );
        }
    }

    #[test]
    fn test_build_grpc_error_response() {
        let resp = build_grpc_error_response("req-2", 500, "internal error");
        assert_eq!(resp.request_id, "req-2");
        assert_eq!(resp.status_code, 500);
        assert_eq!(resp.error, "internal error");
        assert!(resp.body.is_empty());
        assert!(!resp.streaming);
        assert!(!resp.stream_end);
    }

    #[test]
    fn test_build_cluster_not_found_response() {
        let resp = build_cluster_not_found_response("my-cluster", "req-3");
        assert_eq!(resp.request_id, "req-3");
        assert_eq!(resp.status_code, 404);
        let body = String::from_utf8_lossy(&resp.body);
        assert!(body.contains("my-cluster"));
        assert!(body.contains("not found in subtree"));
    }
}
