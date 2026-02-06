//! Cluster health gathering for heartbeat enrichment
//!
//! Collects node health information from the Kubernetes API and converts
//! it into the protobuf ClusterHealth message for inclusion in heartbeats.

use tracing::{debug, warn};

use crate::kube_client::KubeClientProvider;
use lattice_proto::{ClusterHealth, NodeCondition};

/// Gather cluster health from the Kubernetes API.
///
/// Lists nodes and counts ready vs total for control-plane and worker nodes.
/// Returns None if the K8s client cannot be created or nodes cannot be listed.
pub async fn gather_cluster_health(
    kube_provider: &dyn KubeClientProvider,
) -> Option<ClusterHealth> {
    let client = match kube_provider.create().await {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "Failed to create K8s client for health gathering");
            return None;
        }
    };

    let nodes: kube::Api<k8s_openapi::api::core::v1::Node> = kube::Api::all(client);
    let node_list = match nodes.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            warn!(error = %e, "Failed to list nodes for health gathering");
            return None;
        }
    };

    let mut ready_nodes: i32 = 0;
    let mut total_nodes: i32 = 0;
    let mut ready_control_plane: i32 = 0;
    let mut total_control_plane: i32 = 0;
    let mut conditions = Vec::new();

    for node in &node_list.items {
        total_nodes += 1;

        let is_cp = node
            .metadata
            .labels
            .as_ref()
            .map(|l| l.contains_key("node-role.kubernetes.io/control-plane"))
            .unwrap_or(false);

        if is_cp {
            total_control_plane += 1;
        }

        let node_ready = node
            .status
            .as_ref()
            .and_then(|s| s.conditions.as_ref())
            .and_then(|conds| conds.iter().find(|c| c.type_ == "Ready"))
            .map(|c| c.status == "True")
            .unwrap_or(false);

        if node_ready {
            ready_nodes += 1;
            if is_cp {
                ready_control_plane += 1;
            }
        }

        // Collect conditions from each node (deduplicated by type across nodes)
        if let Some(status) = &node.status {
            if let Some(conds) = &status.conditions {
                for cond in conds {
                    // Only include non-healthy conditions (or Ready conditions)
                    let is_notable = cond.type_ == "Ready" || cond.status == "True";
                    if is_notable
                        && !conditions.iter().any(|c: &NodeCondition| {
                            c.r#type == cond.type_ && c.status == cond.status
                        })
                    {
                        conditions.push(NodeCondition {
                            r#type: cond.type_.clone(),
                            status: cond.status.clone(),
                            reason: cond.reason.clone().unwrap_or_default(),
                            message: cond.message.clone().unwrap_or_default(),
                        });
                    }
                }
            }
        }
    }

    debug!(
        ready_nodes,
        total_nodes, ready_control_plane, total_control_plane, "Gathered cluster health"
    );

    Some(ClusterHealth {
        ready_nodes,
        total_nodes,
        ready_control_plane,
        total_control_plane,
        conditions,
    })
}
