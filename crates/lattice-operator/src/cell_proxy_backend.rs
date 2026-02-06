//! Cell-backed implementation of ProxyBackend
//!
//! Wraps `SubtreeRegistry` + `SharedAgentRegistry` from `lattice-cell` to implement
//! the `ProxyBackend` trait defined in `lattice-api`.

use std::collections::HashMap;

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use tokio::sync::mpsc;

use lattice_api::backend::{
    ExecSessionHandle, ExecTunnelRequest, K8sTunnelRequest, ProxyBackend, ProxyError,
    ProxyRouteInfo,
};
use lattice_cell::{
    start_exec_session, tunnel_request_resilient, ExecRequestParams, ExecSession, K8sRequestParams,
    ResilientTunnelConfig, SharedAgentRegistry, SharedSubtreeRegistry, TunnelError,
};
use lattice_proto::ExecData;

/// ProxyBackend implementation backed by lattice-cell registries
pub struct CellProxyBackend {
    subtree: SharedSubtreeRegistry,
    agent_registry: SharedAgentRegistry,
}

impl CellProxyBackend {
    /// Create a new CellProxyBackend
    pub fn new(subtree: SharedSubtreeRegistry, agent_registry: SharedAgentRegistry) -> Self {
        Self {
            subtree,
            agent_registry,
        }
    }
}

#[async_trait]
impl ProxyBackend for CellProxyBackend {
    async fn get_route(&self, cluster_name: &str) -> Option<ProxyRouteInfo> {
        self.subtree
            .get_route(cluster_name)
            .await
            .map(|route| ProxyRouteInfo {
                is_self: route.is_self,
                agent_id: route.agent_id,
                connected: route.connected,
                labels: route.cluster.labels,
            })
    }

    async fn all_clusters(&self) -> Vec<(String, HashMap<String, String>)> {
        self.subtree.all_clusters().await
    }

    async fn tunnel_request(
        &self,
        agent_id: &str,
        request: K8sTunnelRequest,
    ) -> Result<Response<Body>, ProxyError> {
        let params = K8sRequestParams {
            method: request.method,
            path: request.path,
            query: request.query,
            body: request.body,
            content_type: request.content_type,
            accept: request.accept,
            target_cluster: request.target_cluster,
            source_user: request.source_user,
            source_groups: request.source_groups,
        };

        tunnel_request_resilient(
            &self.agent_registry,
            agent_id,
            params,
            &ResilientTunnelConfig::default(),
        )
        .await
        .map_err(tunnel_error_to_proxy_error)
    }

    async fn start_exec_session(
        &self,
        agent_id: &str,
        request: ExecTunnelRequest,
    ) -> Result<(Box<dyn ExecSessionHandle>, mpsc::Receiver<ExecData>), ProxyError> {
        let command_tx = self
            .agent_registry
            .get(agent_id)
            .ok_or(ProxyError::AgentDisconnected)?
            .command_tx
            .clone();

        let params = ExecRequestParams {
            path: request.path,
            query: request.query,
            target_cluster: request.target_cluster,
            source_user: request.source_user,
            source_groups: request.source_groups,
        };

        let (session, data_rx) =
            start_exec_session(&self.agent_registry, agent_id, command_tx, params)
                .await
                .map_err(|e| ProxyError::SendFailed(e.to_string()))?;

        Ok((Box::new(CellExecSession(session)), data_rx))
    }
}

/// Wrapper around `lattice_cell::ExecSession` implementing `ExecSessionHandle`
struct CellExecSession(ExecSession);

#[async_trait]
impl ExecSessionHandle for CellExecSession {
    fn request_id(&self) -> &str {
        &self.0.request_id
    }

    async fn send_stdin(&self, data: Vec<u8>) -> Result<(), ProxyError> {
        self.0
            .send_stdin(data)
            .await
            .map_err(|e| ProxyError::SendFailed(e.to_string()))
    }

    async fn send_resize(&self, width: u32, height: u32) -> Result<(), ProxyError> {
        self.0
            .send_resize(width, height)
            .await
            .map_err(|e| ProxyError::SendFailed(e.to_string()))
    }

    async fn close_stdin(&self) -> Result<(), ProxyError> {
        self.0
            .close_stdin()
            .await
            .map_err(|e| ProxyError::SendFailed(e.to_string()))
    }
}

/// Convert TunnelError to ProxyError
fn tunnel_error_to_proxy_error(e: TunnelError) -> ProxyError {
    match e {
        TunnelError::SendFailed(msg) => ProxyError::SendFailed(msg),
        TunnelError::ChannelClosed => ProxyError::AgentDisconnected,
        TunnelError::UnknownCluster(name) => ProxyError::ClusterNotFound(name),
        TunnelError::Timeout => ProxyError::Timeout,
        TunnelError::AgentError(msg) => ProxyError::AgentError(msg),
        TunnelError::ResponseBuild(msg) => ProxyError::ResponseBuild(msg),
    }
}
