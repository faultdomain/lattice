//! K8s request forwarder for hierarchical routing
//!
//! Implements the K8sRequestForwarder trait to enable agents to forward
//! K8s API requests to their child clusters via the gRPC tunnel.

use lattice_agent::{
    build_k8s_status_response, K8sRequestForwarder, KubernetesRequest, KubernetesResponse,
};
use lattice_cell::{
    tunnel_request, K8sRequestParams, SharedAgentRegistry, SharedSubtreeRegistry, TunnelError,
};
use tracing::{debug, warn};

/// Forwarder that routes K8s requests to child clusters via gRPC tunnel.
///
/// Uses the subtree registry to determine which agent connection to route through,
/// then uses the tunnel_request function to forward the request.
pub struct SubtreeForwarder {
    subtree_registry: SharedSubtreeRegistry,
    agent_registry: SharedAgentRegistry,
}

impl SubtreeForwarder {
    /// Create a new SubtreeForwarder with the given registries.
    pub fn new(
        subtree_registry: SharedSubtreeRegistry,
        agent_registry: SharedAgentRegistry,
    ) -> Self {
        Self {
            subtree_registry,
            agent_registry,
        }
    }
}

#[async_trait::async_trait]
impl K8sRequestForwarder for SubtreeForwarder {
    async fn forward(
        &self,
        target_cluster: &str,
        request: KubernetesRequest,
    ) -> KubernetesResponse {
        // Look up the route to the target cluster
        let route_info = match self.subtree_registry.get_route(target_cluster).await {
            Some(info) => info,
            None => {
                warn!(
                    target = %target_cluster,
                    request_id = %request.request_id,
                    "Target cluster not found in subtree"
                );
                return build_k8s_status_response(
                    &request.request_id,
                    404,
                    &format!("cluster '{}' not found in subtree", target_cluster),
                );
            }
        };

        // Get the agent ID to route through
        let agent_id = match route_info.agent_id {
            Some(id) => id,
            None => {
                warn!(
                    target = %target_cluster,
                    request_id = %request.request_id,
                    "Route info missing agent_id"
                );
                return build_k8s_status_response(
                    &request.request_id,
                    502,
                    "internal routing error: missing agent_id",
                );
            }
        };

        // Get the agent connection
        let agent = match self.agent_registry.get(&agent_id) {
            Some(a) => a,
            None => {
                warn!(
                    target = %target_cluster,
                    agent_id = %agent_id,
                    request_id = %request.request_id,
                    "Agent not connected"
                );
                return build_k8s_status_response(
                    &request.request_id,
                    502,
                    &format!("agent '{}' not connected", agent_id),
                );
            }
        };

        let command_tx = agent.command_tx.clone();
        drop(agent);

        debug!(
            target = %target_cluster,
            agent_id = %agent_id,
            request_id = %request.request_id,
            "Forwarding request to child cluster"
        );

        // Forward the request using the tunnel
        // Source identity is preserved from the original request for Cedar checks
        let params = K8sRequestParams {
            method: request.verb.clone(),
            path: request.path.clone(),
            query: request.query.clone(),
            body: request.body.clone(),
            content_type: request.content_type.clone(),
            target_cluster: target_cluster.to_string(),
            source_user: request.source_user.clone(),
            source_groups: request.source_groups.clone(),
        };

        match tunnel_request(&self.agent_registry, target_cluster, command_tx, params).await {
            Ok(response) => {
                // Convert axum Response<Body> to KubernetesResponse
                let status = response.status().as_u16() as u32;
                let content_type = response
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("application/json")
                    .to_string();

                let body = match axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024).await
                {
                    Ok(b) => b.to_vec(),
                    Err(e) => {
                        return build_k8s_status_response(
                            &request.request_id,
                            502,
                            &format!("failed to read response body: {}", e),
                        );
                    }
                };

                KubernetesResponse {
                    request_id: request.request_id,
                    status_code: status,
                    body,
                    content_type,
                    error: String::new(),
                    streaming: false,
                    stream_end: false,
                }
            }
            Err(e) => {
                let (status, msg) = match &e {
                    TunnelError::SendFailed(m) => (502, format!("send failed: {}", m)),
                    TunnelError::ChannelClosed => (502, "agent connection lost".to_string()),
                    TunnelError::Timeout => (504, "request timed out".to_string()),
                    TunnelError::AgentError(m) => (502, format!("agent error: {}", m)),
                    TunnelError::ResponseBuild(m) => (500, format!("response build error: {}", m)),
                };
                build_k8s_status_response(&request.request_id, status, &msg)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_k8s_status_response() {
        let response = build_k8s_status_response("req-1", 404, "cluster not found");
        assert_eq!(response.request_id, "req-1");
        assert_eq!(response.status_code, 404);
        assert!(String::from_utf8_lossy(&response.body).contains("cluster not found"));
    }
}
