//! Cluster health gathering for heartbeat enrichment
//!
//! Collects node health information from the Kubernetes API and converts
//! it into the protobuf ClusterHealth message for inclusion in heartbeats.
//! Includes per-pool resource capacity (CPU, memory, GPU) for scheduling.

use k8s_openapi::api::core::v1::Node;
use lattice_common::resources::{is_control_plane_node, is_node_ready};
use lattice_common::OPERATOR_NAME;
use tracing::{debug, warn};

use crate::kube_client::KubeClientProvider;
use lattice_proto::{ClusterHealth, NodeCondition, PoolResources};

/// Read the operator's own Deployment image from the `lattice-operator` Deployment
/// in `lattice-system`. Returns None if the Deployment can't be read.
pub async fn get_operator_image(kube_provider: &dyn KubeClientProvider) -> Option<String> {
    let client = kube_provider.create().await.ok()?;

    let deploy_api: kube::Api<k8s_openapi::api::apps::v1::Deployment> =
        kube::Api::namespaced(client, lattice_core::LATTICE_SYSTEM_NAMESPACE);

    let deploy = deploy_api.get(OPERATOR_NAME).await.ok()?;
    deploy
        .spec?
        .template
        .spec?
        .containers
        .first()?
        .image
        .clone()
}

/// Gather cluster health from the Kubernetes API.
///
/// Lists nodes and counts ready vs total for control-plane and worker nodes.
/// Also gathers per-pool resource capacity (CPU, memory, GPU) from nodes and pods.
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

    let node_api: kube::Api<Node> = kube::Api::all(client.clone());
    let node_list = match node_api.list(&Default::default()).await {
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

        let is_cp = is_control_plane_node(node);

        if is_cp {
            total_control_plane += 1;
        }

        let node_ready = is_node_ready(node);

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

    // Gather per-pool resource capacity using the shared function
    let pool_summaries = lattice_common::resources::gather_pool_resources(&client).await;
    let pool_resources: Vec<PoolResources> = pool_summaries
        .into_iter()
        .map(|s| PoolResources {
            pool_name: s.pool_name,
            ready_nodes: s.ready_nodes as i32,
            total_nodes: s.total_nodes as i32,
            node_cpu_millis: s.node_cpu_millis,
            node_memory_bytes: s.node_memory_bytes,
            node_gpu_count: s.node_gpu_count as i32,
            gpu_type: s.gpu_type,
            allocated_cpu_millis: s.allocated_cpu_millis,
            allocated_memory_bytes: s.allocated_memory_bytes,
            allocated_gpu_count: s.allocated_gpu_count as i32,
        })
        .collect();

    debug!(
        ready_nodes,
        total_nodes,
        ready_control_plane,
        total_control_plane,
        pool_count = pool_resources.len(),
        "Gathered cluster health"
    );

    Some(ClusterHealth {
        ready_nodes,
        total_nodes,
        ready_control_plane,
        total_control_plane,
        conditions,
        pool_resources,
    })
}
