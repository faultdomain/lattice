//! Local move adapter for CLI operations
//!
//! Implements `MoveCommandSender` by calling `AgentMover` directly,
//! without gRPC. Used by `lattice install` and `lattice uninstall`
//! when both kubeconfigs are accessible locally.

use std::path::Path;
use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::info;

use crate::agent::AgentMover;
use crate::cell::{
    BatchAck, CellMover, CellMoverConfig, CompleteAck, MoveBatch, MoveCommandSender,
    MoveCompleteInput, MoveResult,
};
use crate::error::MoveError;

use async_trait::async_trait;
use lattice_common::kube_utils;

/// Move command sender that calls `AgentMover` directly (no gRPC).
///
/// Wraps an `AgentMover` behind a `Mutex` since `apply_batch` requires `&mut self`.
pub struct LocalMoveSender {
    agent: Mutex<AgentMover>,
}

impl LocalMoveSender {
    pub fn new(agent: AgentMover) -> Self {
        Self {
            agent: Mutex::new(agent),
        }
    }
}

#[async_trait]
impl MoveCommandSender for LocalMoveSender {
    async fn send_batch(&self, batch: MoveBatch) -> Result<BatchAck, MoveError> {
        let mut agent = self.agent.lock().await;
        agent.ensure_namespace().await?;
        let (mappings, errors) = agent.apply_batch(&batch.objects).await;

        Ok(BatchAck {
            mappings,
            errors: errors
                .into_iter()
                .map(|e| (e.source_uid, e.message, e.retryable))
                .collect(),
        })
    }

    async fn send_complete(&self, _complete: MoveCompleteInput) -> Result<CompleteAck, MoveError> {
        let agent = self.agent.lock().await;
        agent.unpause_resources().await?;

        Ok(CompleteAck {
            success: true,
            error: String::new(),
            resources_created: agent.resources_created() as i32,
        })
    }
}

/// Move CAPI resources between clusters with both kubeconfigs accessible locally.
///
/// This performs a local CAPI resource move for CLI operations.
/// The full flow is:
/// - Create source and target kube clients
/// - Create `AgentMover` targeting the destination
/// - Wrap it in `LocalMoveSender`
/// - Run `CellMover::execute()` which handles discover, pause, graph, sort, batch, delete
pub async fn local_move(
    source_kubeconfig: &Path,
    target_kubeconfig: &Path,
    namespace: &str,
    cluster_name: &str,
) -> Result<MoveResult, MoveError> {
    let source_client = kube_utils::create_client(Some(source_kubeconfig), None, None)
        .await
        .map_err(|e| MoveError::Discovery(format!("failed to create source client: {}", e)))?;

    let target_client = kube_utils::create_client(Some(target_kubeconfig), None, None)
        .await
        .map_err(|e| MoveError::Discovery(format!("failed to create target client: {}", e)))?;

    let config = CellMoverConfig::new(namespace, namespace, cluster_name);

    let agent = AgentMover::new(target_client, namespace);
    let sender = Arc::new(LocalMoveSender::new(agent));

    let mut mover = CellMover::new(source_client, config, sender);

    info!(
        cluster = %cluster_name,
        namespace = %namespace,
        "Starting local CAPI resource move"
    );

    mover.execute().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_move_sender_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LocalMoveSender>();
    }
}
