//! State sync command handler.
//!
//! Responds to RequestStateSync by reading the local LatticeCluster CRD
//! and sending back the full spec + status as JSON.

use kube::Api;
use lattice_common::crd::LatticeCluster;
use lattice_proto::{agent_message::Payload, AgentMessage, StateSyncResponse};
use tracing::{debug, error, warn};

use super::CommandContext;

/// Handle a state sync request from the cell.
///
/// Reads this cluster's LatticeCluster CRD and sends back spec + status JSON.
pub async fn handle(command_id: &str, ctx: &CommandContext) {
    debug!(command_id, "Received state sync request");

    let cluster_name = ctx.cluster_name.clone();
    let message_tx = ctx.message_tx.clone();
    let provider = ctx.kube_provider.clone();

    tokio::spawn(async move {
        let client = match provider.create().await {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "Failed to create K8s client for state sync");
                return;
            }
        };

        let api: Api<LatticeCluster> = Api::all(client);
        let cluster = match api.get(&cluster_name).await {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    cluster = %cluster_name,
                    error = %e,
                    "Failed to get LatticeCluster for state sync"
                );
                return;
            }
        };

        let spec_json = match serde_json::to_vec(&cluster.spec) {
            Ok(j) => j,
            Err(e) => {
                error!(error = %e, "Failed to serialize spec for state sync");
                return;
            }
        };

        let status_json = match cluster.status.as_ref() {
            Some(status) => match serde_json::to_vec(status) {
                Ok(j) => j,
                Err(e) => {
                    error!(error = %e, "Failed to serialize status for state sync");
                    return;
                }
            },
            None => b"{}".to_vec(),
        };

        let msg = AgentMessage {
            cluster_name,
            payload: Some(Payload::StateSyncResponse(StateSyncResponse {
                spec_json,
                status_json,
            })),
        };

        if let Err(e) = message_tx.send(msg).await {
            error!(error = %e, "Failed to send state sync response");
        }
    });
}
