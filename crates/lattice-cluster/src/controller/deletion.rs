//! Cluster deletion and finalizer handling.
//!
//! This module handles the deletion lifecycle for LatticeCluster resources,
//! including unpivot logic, CAPI infrastructure cleanup, and finalizer management.

use std::time::Duration;

use kube::runtime::controller::Action;
use kube::runtime::events::EventType;
use kube::{Resource, ResourceExt};
use tracing::{debug, info, warn};

use lattice_common::crd::{ClusterPhase, LatticeCluster};
use lattice_common::events::{actions, reasons};
use lattice_common::{capi_namespace, Error, LATTICE_SYSTEM_NAMESPACE, PARENT_CONFIG_SECRET};
use lattice_move::{pause_cluster, unpause_cluster};

use super::context::Context;

/// Finalizer name for LatticeCluster unpivot handling
pub const CLUSTER_FINALIZER: &str = "lattice.dev/unpivot";

/// Check if a cluster has the finalizer
pub(crate) fn has_finalizer(cluster: &LatticeCluster) -> bool {
    cluster
        .metadata
        .finalizers
        .as_ref()
        .is_some_and(|f| f.contains(&CLUSTER_FINALIZER.to_string()))
}

/// Add the unpivot finalizer to a cluster
pub(crate) async fn add_finalizer(cluster: &LatticeCluster, ctx: &Context) -> Result<(), Error> {
    let name = cluster.name_any();
    ctx.kube
        .add_cluster_finalizer(&name, CLUSTER_FINALIZER)
        .await
}

/// Remove the unpivot finalizer from a cluster
async fn remove_finalizer(cluster: &LatticeCluster, ctx: &Context) -> Result<(), Error> {
    let name = cluster.name_any();
    ctx.kube
        .remove_cluster_finalizer(&name, CLUSTER_FINALIZER)
        .await
}

/// Handle cluster deletion with unpivot logic
///
/// For cell clusters (has parent_config): blocks deletion if child clusters exist.
/// This prevents orphaning clusters. Remove finalizer manually for break-glass.
///
/// For self clusters with a parent: unpivot CAPI resources back to parent.
///
/// For root clusters (no parent): just remove the finalizer.
///
/// For non-self clusters (child clusters being deleted from parent):
/// delete CAPI Cluster to trigger infrastructure cleanup.
pub(crate) async fn handle_deletion(
    cluster: &LatticeCluster,
    ctx: &Context,
    is_self: bool,
) -> Result<Action, Error> {
    let name = cluster.name_any();

    // Clean up error_counts entry for this cluster (prevent unbounded growth)
    ctx.error_counts.remove(&name);

    // If no finalizer, nothing to do
    if !has_finalizer(cluster) {
        debug!(cluster = %name, "No finalizer, allowing deletion");
        return Ok(Action::await_change());
    }

    // For non-self clusters (we're the parent), delete CAPI infrastructure
    if !is_self {
        let capi_namespace = capi_namespace(&name);

        // Set phase to Deleting if not already
        let current_phase = cluster.status.as_ref().map(|s| &s.phase);
        if current_phase != Some(&ClusterPhase::Deleting) {
            let status = cluster
                .status
                .clone()
                .unwrap_or_default()
                .phase(ClusterPhase::Deleting);
            ctx.kube.patch_status(&name, &status).await?;
        }

        // Check if CAPI Cluster still exists
        let capi_exists = match ctx.capi.capi_cluster_exists(&name, &capi_namespace).await {
            Ok(exists) => exists,
            Err(e) => {
                // Assume exists on error to avoid premature deletion
                warn!(cluster = %name, error = %e, "Failed to check CAPI cluster existence, assuming exists");
                true
            }
        };

        if capi_exists {
            // Only check stability before the first delete attempt (prevents race
            // with provisioning). Once we've already set the phase to Deleting,
            // skip the check and keep retrying the delete — under CPU overload the
            // stability API call can fail repeatedly, which would block deletion
            // forever if we gate on it every time.
            let already_deleting = current_phase == Some(&ClusterPhase::Deleting);
            if !already_deleting {
                let is_stable = match ctx.capi.is_cluster_stable(&name, &capi_namespace).await {
                    Ok(stable) => stable,
                    Err(e) => {
                        debug!(cluster = %name, error = %e, "Failed to check CAPI stability, assuming unstable");
                        false
                    }
                };

                if !is_stable {
                    info!(cluster = %name, "Waiting for CAPI to stabilize before deletion");
                    let status = cluster
                        .status
                        .clone()
                        .unwrap_or_default()
                        .phase(ClusterPhase::Deleting)
                        .message("Waiting for CAPI to stabilize before cleanup");
                    ctx.kube.patch_status(&name, &status).await?;
                    return Ok(Action::requeue(Duration::from_secs(10)));
                }
            }

            // Delete CAPI Cluster to trigger infrastructure cleanup
            info!(cluster = %name, "Deleting CAPI Cluster to trigger infrastructure cleanup");
            ctx.events
                .publish(
                    &cluster.object_ref(&()),
                    EventType::Normal,
                    reasons::DELETION_STARTED,
                    actions::DELETE,
                    Some("Deleting CAPI cluster".to_string()),
                )
                .await;
            if let Err(e) = ctx.capi.delete_capi_cluster(&name, &capi_namespace).await {
                warn!(cluster = %name, error = %e, "Failed to delete CAPI Cluster");
            }
            // Requeue to wait for deletion
            return Ok(Action::requeue(Duration::from_secs(10)));
        }

        // CAPI Cluster is gone, remove finalizer
        info!(cluster = %name, "Infrastructure cleanup complete, removing finalizer");
        remove_finalizer(cluster, ctx).await?;
        return Ok(Action::await_change());
    }

    // If this cluster is a cell (has parent_config), block deletion if children exist
    if cluster.spec.parent_config.is_some() {
        let child_names: Vec<String> = ctx
            .kube
            .list_clusters()
            .await?
            .into_iter()
            .filter(|c| c.name_any() != name)
            .map(|c| c.name_any())
            .collect();

        if !child_names.is_empty() {
            warn!(cluster = %name, ?child_names, "Cannot delete cell with active children");
            let status = cluster.status.clone().unwrap_or_default().message(format!(
                "Deletion blocked: {} child cluster(s) exist: {}. Delete children first or remove finalizer for break-glass.",
                child_names.len(),
                child_names.join(", ")
            ));
            ctx.kube.patch_status(&name, &status).await?;
            return Ok(Action::requeue(Duration::from_secs(30)));
        }
    }

    // For self clusters, check if we have a parent to unpivot to
    let has_parent = ctx
        .kube
        .get_secret(PARENT_CONFIG_SECRET, LATTICE_SYSTEM_NAMESPACE)
        .await?
        .is_some();

    if !has_parent {
        // Root cluster - no unpivot needed, just remove finalizer
        info!(cluster = %name, "Root cluster deletion - no unpivot needed");
        remove_finalizer(cluster, ctx).await?;
        return Ok(Action::await_change());
    }

    // Pause cluster to freeze CAPI state — eliminates TOCTOU window between
    // stability checks and the agent's unpivot pause
    let capi_namespace = capi_namespace(&name);
    let client = ctx
        .client
        .as_ref()
        .ok_or_else(|| Error::internal("no kube client"))?;
    if let Err(e) = pause_cluster(client, &capi_namespace).await {
        warn!(cluster = %name, error = %e, "Failed to pause for unpivot");
        return Ok(Action::requeue(Duration::from_secs(10)));
    }

    // Wait for cluster to be stable before unpivoting (no scaling in progress)
    // Check 1: CAPI resources are stable (no machines provisioning/deleting)
    let capi_stable = match ctx.capi.is_cluster_stable(&name, &capi_namespace).await {
        Ok(stable) => stable,
        Err(e) => {
            debug!(cluster = %name, error = %e, "Failed to check CAPI stability, assuming unstable");
            false
        }
    };

    if !capi_stable {
        info!(cluster = %name, "Waiting for CAPI to stabilize before unpivoting");
        let _ = unpause_cluster(client, &capi_namespace).await;
        let status = cluster
            .status
            .clone()
            .unwrap_or_default()
            .message("Deletion pending: waiting for CAPI to stabilize");
        ctx.kube.patch_status(&name, &status).await?;
        return Ok(Action::requeue(Duration::from_secs(10)));
    }

    // Check 2: Actual node count matches LatticeCluster spec (prevents TOCTOU with scaling)
    // Query live node counts — status.ready_workers may be stale because handle_ready
    // (which normally refreshes it) is bypassed during deletion.
    let desired_workers: u32 = cluster
        .spec
        .nodes
        .worker_pools
        .values()
        .map(|p| p.replicas)
        .sum();
    let ready_workers = ctx
        .kube
        .get_ready_node_counts()
        .await
        .map(|c| c.ready_workers)
        .unwrap_or(0);

    if ready_workers < desired_workers {
        info!(
            cluster = %name,
            ready = ready_workers,
            desired = desired_workers,
            "Waiting for workers to match spec before unpivoting"
        );
        let _ = unpause_cluster(client, &capi_namespace).await;
        let status = cluster.status.clone().unwrap_or_default().message(format!(
            "Deletion pending: waiting for workers ({}/{})",
            ready_workers, desired_workers
        ));
        ctx.kube.patch_status(&name, &status).await?;
        return Ok(Action::requeue(Duration::from_secs(10)));
    }

    // Self cluster with parent - agent handles unpivot automatically
    // The agent detects deletion_timestamp on connect and starts an unpivot retry loop
    // that keeps sending ClusterDeleting to parent until parent's CAPI deletes us.
    // We just need to:
    // 1. Delete cell service (free up the LoadBalancer IP)
    // 2. Set phase to Unpivoting
    // 3. Wait - finalizer keeps the resource around until CAPI deletes the infrastructure

    let current_phase = cluster
        .status
        .as_ref()
        .map(|s| s.phase)
        .unwrap_or(ClusterPhase::Pending);

    if current_phase != ClusterPhase::Unpivoting {
        info!(cluster = %name, "Starting unpivot - agent will send manifests to parent");
        ctx.events
            .publish(
                &cluster.object_ref(&()),
                EventType::Normal,
                reasons::UNPIVOT_STARTED,
                actions::DELETE,
                Some("Starting unpivot to parent".to_string()),
            )
            .await;

        // Delete the cell LoadBalancer service to free the IP
        ctx.kube.delete_cell_service().await?;

        // Set phase to Unpivoting
        let status = cluster
            .status
            .clone()
            .unwrap_or_default()
            .phase(ClusterPhase::Unpivoting)
            .message("Agent sending CAPI resources to parent");
        ctx.kube.patch_status(&name, &status).await?;
    }

    // Keep waiting - agent is sending manifests, parent will delete us via CAPI
    // Finalizer never explicitly removed; CAPI deletes the entire infrastructure
    debug!(cluster = %name, "Unpivoting - waiting for parent to delete via CAPI");
    Ok(Action::requeue(Duration::from_secs(30)))
}
