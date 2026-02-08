//! gRPC-based implementation of MoveCommandSender
//!
//! Sends move commands to agents via the established gRPC stream and waits for acks.

use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use lattice_move::{
    BatchAck, CompleteAck, MoveBatch, MoveCommandSender, MoveCompleteInput, MoveError,
};
use lattice_proto::{
    cell_command::Command, CellCommand, DistributableResources, MoveComplete, MoveObjectBatch,
};

use crate::SharedAgentRegistry;

/// gRPC-based move command sender
///
/// Sends move commands to agents via the established gRPC bidirectional stream.
/// Uses request_id (command_id) for response correlation.
pub struct GrpcMoveCommandSender {
    registry: SharedAgentRegistry,
    cluster_name: String,
    timeout: Duration,
}

impl GrpcMoveCommandSender {
    /// Create a new sender with default 120s timeout
    pub fn new(registry: SharedAgentRegistry, cluster_name: String) -> Self {
        Self {
            registry,
            cluster_name,
            timeout: Duration::from_secs(120),
        }
    }

    /// Create with custom timeout
    pub fn with_timeout(
        registry: SharedAgentRegistry,
        cluster_name: String,
        timeout: Duration,
    ) -> Self {
        Self {
            registry,
            cluster_name,
            timeout,
        }
    }
}

#[async_trait]
impl MoveCommandSender for GrpcMoveCommandSender {
    async fn send_batch(&self, batch: MoveBatch) -> Result<BatchAck, MoveError> {
        let request_id = uuid::Uuid::new_v4().to_string();

        debug!(
            request_id = %request_id,
            batch_index = batch.batch_index,
            objects = batch.objects.len(),
            "Sending move batch"
        );

        let (tx, rx) = oneshot::channel();
        self.registry.register_pending_batch_ack(&request_id, tx);

        let cmd = CellCommand {
            command_id: request_id.clone(),
            command: Some(Command::MoveBatch(to_proto_batch(&batch))),
        };

        if let Err(e) = self.registry.send_command(&self.cluster_name, cmd).await {
            self.registry.take_pending_batch_ack(&request_id);
            return Err(MoveError::AgentCommunication(e.to_string()));
        }

        let result = tokio::time::timeout(self.timeout, rx).await;
        if result.is_err() {
            self.registry.take_pending_batch_ack(&request_id);
        }
        result
            .map_err(|_| MoveError::Timeout {
                seconds: self.timeout.as_secs(),
            })?
            .map_err(|_| MoveError::AgentCommunication("channel closed".to_string()))
    }

    async fn send_complete(&self, complete: MoveCompleteInput) -> Result<CompleteAck, MoveError> {
        let request_id = uuid::Uuid::new_v4().to_string();

        debug!(request_id = %request_id, "Sending move complete");

        let (tx, rx) = oneshot::channel();
        self.registry.register_pending_complete_ack(&request_id, tx);

        let cmd = CellCommand {
            command_id: request_id.clone(),
            command: Some(Command::MoveComplete(MoveComplete {
                move_id: complete.move_id,
                cluster_name: complete.cluster_name,
                target_namespace: complete.target_namespace,
                resources: Some(DistributableResources {
                    cloud_providers: complete.cloud_providers,
                    secrets_providers: complete.secrets_providers,
                    secrets: complete.secrets,
                    cedar_policies: complete.cedar_policies,
                    oidc_providers: complete.oidc_providers,
                }),
                manifests: complete.manifests,
            })),
        };

        if let Err(e) = self.registry.send_command(&self.cluster_name, cmd).await {
            self.registry.take_pending_complete_ack(&request_id);
            return Err(MoveError::AgentCommunication(e.to_string()));
        }

        let result = tokio::time::timeout(self.timeout, rx).await;
        if result.is_err() {
            self.registry.take_pending_complete_ack(&request_id);
        }
        let ack = result
            .map_err(|_| MoveError::Timeout {
                seconds: self.timeout.as_secs(),
            })?
            .map_err(|_| MoveError::AgentCommunication("channel closed".to_string()))?;

        if ack.success {
            info!(resources_created = ack.resources_created, "Move completed");
        } else {
            warn!(error = %ack.error, "Move failed");
        }

        Ok(ack)
    }
}

fn to_proto_batch(batch: &MoveBatch) -> MoveObjectBatch {
    MoveObjectBatch {
        move_id: batch.move_id.clone(),
        batch_index: batch.batch_index,
        total_batches: batch.total_batches,
        target_namespace: batch.target_namespace.clone(),
        cluster_name: batch.cluster_name.clone(),
        objects: batch.objects.iter().map(Into::into).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentRegistry;
    use lattice_move::{MoveObjectOutput, SourceOwnerRefOutput};
    use std::sync::Arc;

    #[test]
    fn test_to_proto_batch() {
        let batch = MoveBatch {
            move_id: "move-1".to_string(),
            batch_index: 0,
            total_batches: 2,
            target_namespace: "ns".to_string(),
            cluster_name: "cluster".to_string(),
            objects: vec![MoveObjectOutput {
                source_uid: "uid-1".to_string(),
                manifest: b"{}".to_vec(),
                owners: vec![SourceOwnerRefOutput {
                    source_uid: "owner-1".to_string(),
                    api_version: "v1".to_string(),
                    kind: "Cluster".to_string(),
                    name: "c1".to_string(),
                    controller: true,
                    block_owner_deletion: false,
                }],
            }],
        };

        let proto = to_proto_batch(&batch);
        assert_eq!(proto.move_id, "move-1");
        assert_eq!(proto.objects.len(), 1);
        assert_eq!(proto.objects[0].owners.len(), 1);
        assert!(proto.objects[0].owners[0].controller);
    }

    #[test]
    fn test_sender_creation() {
        let registry = Arc::new(AgentRegistry::new());
        let sender = GrpcMoveCommandSender::new(registry, "cluster".to_string());
        assert_eq!(sender.timeout, Duration::from_secs(120));
    }
}
