//! Move complete command handler.

use std::sync::Arc;

use lattice_proto::{
    agent_message::Payload, AgentMessage, AgentState, MoveComplete, MoveCompleteAck,
};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::distributable_resources_from_proto;
use crate::kube_client::KubeClientProvider;
use crate::pivot::{apply_distributed_resources, patch_kubeconfig_for_self_management};
use lattice_common::crd::LatticeCluster;

use super::apply_manifests::apply_manifests;
use super::CommandContext;

/// Handle a move complete command from the cell.
pub async fn handle(command_id: &str, complete: &MoveComplete, ctx: &CommandContext) {
    let request_id = command_id.to_string();
    let agent_cluster_name = ctx.cluster_name.clone();
    let message_tx = ctx.message_tx.clone();
    let capi_cluster_name = complete.cluster_name.clone();
    let target_namespace = complete.target_namespace.clone();
    let resources =
        distributable_resources_from_proto(complete.resources.clone().unwrap_or_default());
    let manifests = complete.manifests.clone();

    info!(
        request_id = %request_id,
        cluster = %capi_cluster_name,
        namespace = %target_namespace,
        manifests = manifests.len(),
        cedar_policies = resources.cedar_policies.len(),
        oidc_providers = resources.oidc_providers.len(),
        "Processing move complete"
    );

    let provider = ctx.kube_provider.clone();
    let agent_state = ctx.agent_state.clone();

    tokio::spawn(async move {
        // Check if pivot already completed (handles re-sends after parent crash)
        if check_local_pivot_complete(&capi_cluster_name, provider.as_ref()).await {
            info!(request_id = %request_id, "Pivot already complete, sending immediate ack");
            *agent_state.write().await = AgentState::Ready;
            send_complete_ack(&message_tx, &agent_cluster_name, &request_id, true, "", 0).await;
            return;
        }

        let client = match provider.create().await {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "Failed to create K8s client for move complete");
                send_complete_ack(
                    &message_tx,
                    &agent_cluster_name,
                    &request_id,
                    false,
                    &format!("Failed to create K8s client: {}", e),
                    0,
                )
                .await;
                return;
            }
        };

        // Patch kubeconfig to use kubernetes.default.svc (avoids hairpinning)
        if let Err(e) = patch_kubeconfig_for_self_management(
            &capi_cluster_name,
            &target_namespace,
            provider.as_ref(),
        )
        .await
        {
            warn!(error = %e, "Failed to patch kubeconfig for self-management");
        }

        let mover = lattice_move::AgentMover::new(client.clone(), &target_namespace);

        // Unpause resources
        if let Err(e) = mover.unpause_resources().await {
            warn!(error = ?e, "Failed to unpause resources");
        }

        let resources_created = mover.resources_created() as i32;

        // Apply distributed resources - fail pivot if this fails
        if let Err(e) = apply_distributed_resources(&client, &resources).await {
            error!(error = %e, "Failed to apply distributed resources");
            send_complete_ack(
                &message_tx,
                &agent_cluster_name,
                &request_id,
                false,
                &format!("failed to apply distributed resources: {}", e),
                0,
            )
            .await;
            return;
        }

        // Apply additional manifests (e.g., CiliumNetworkPolicy) - fail pivot if this fails
        if !manifests.is_empty() {
            if let Err(e) = apply_manifests(&client, &manifests).await {
                error!(error = %e, manifests = manifests.len(), "Failed to apply manifests");
                send_complete_ack(
                    &message_tx,
                    &agent_cluster_name,
                    &request_id,
                    false,
                    &format!("failed to apply manifests: {}", e),
                    0,
                )
                .await;
                return;
            }
            info!(manifests = manifests.len(), "Applied post-pivot manifests");
        }

        // Set local pivot_complete AFTER all resources are confirmed in etcd
        if let Err(e) = set_local_pivot_complete(&capi_cluster_name, &provider).await {
            warn!(error = %e, "Failed to set local pivot_complete");
            // Continue anyway - all resources are applied successfully
        }

        // Transition agent state to Ready so heartbeats report correct state
        *agent_state.write().await = AgentState::Ready;
        info!("Agent state transitioned to Ready after successful pivot");

        // Send success ack
        send_complete_ack(
            &message_tx,
            &agent_cluster_name,
            &request_id,
            true,
            "",
            resources_created,
        )
        .await;
    });
}

/// Check if the local LatticeCluster has pivot_complete=true.
pub async fn check_local_pivot_complete(
    cluster_name: &str,
    kube_provider: &dyn KubeClientProvider,
) -> bool {
    let Some(client) = crate::kube_client::create_client_logged(kube_provider, "pivot check").await
    else {
        return false;
    };

    let clusters: kube::Api<LatticeCluster> = kube::Api::all(client);
    match clusters.get(cluster_name).await {
        Ok(cluster) => cluster
            .status
            .as_ref()
            .map(|s| s.pivot_complete)
            .unwrap_or(false),
        Err(e) => {
            warn!(cluster = %cluster_name, error = %e, "Failed to get LatticeCluster");
            false
        }
    }
}

/// Set pivot_complete=true on the local LatticeCluster status.
pub async fn set_local_pivot_complete(
    cluster_name: &str,
    kube_provider: &Arc<dyn KubeClientProvider>,
) -> Result<(), kube::Error> {
    let client = kube_provider.create().await?;
    let clusters: kube::Api<LatticeCluster> = kube::Api::all(client);

    let patch = serde_json::json!({
        "status": {
            "pivotComplete": true
        }
    });
    clusters
        .patch_status(
            cluster_name,
            &kube::api::PatchParams::apply("lattice-agent"),
            &kube::api::Patch::Merge(&patch),
        )
        .await?;

    info!(cluster = %cluster_name, "Set local pivot_complete=true");
    Ok(())
}

/// Send a MoveComplete ack (success or error).
async fn send_complete_ack(
    tx: &mpsc::Sender<AgentMessage>,
    cluster_name: &str,
    request_id: &str,
    success: bool,
    error: &str,
    resources_created: i32,
) {
    let ack = MoveCompleteAck {
        request_id: request_id.to_string(),
        success,
        error: error.to_string(),
        resources_created,
    };
    let msg = AgentMessage {
        cluster_name: cluster_name.to_string(),
        payload: Some(Payload::MoveCompleteAck(ack)),
    };
    if let Err(e) = tx.send(msg).await {
        error!(error = %e, "Failed to send move complete ack");
    }
}
