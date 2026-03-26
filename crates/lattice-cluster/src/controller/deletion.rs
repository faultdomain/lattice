//! Cluster deletion and finalizer handling.
//!
//! This module handles the deletion lifecycle for LatticeCluster resources,
//! including unpivot logic, CAPI infrastructure cleanup, and finalizer management.
//!
//! Deletion has three paths depending on cluster role:
//!
//! - **Non-self (parent deleting child)**: For pivoted clusters, sends
//!   `DeleteCluster` via gRPC to tell the child to self-delete and unpivot.
//!   For pre-pivot clusters, deletes CAPI directly.
//! - **Self with parent**: Pauses CAPI, waits for stability, sets phase to
//!   Unpivoting. Agent detects deletion and sends CAPI resources to parent.
//! - **Root (no parent)**: Just removes the finalizer.

use std::time::Duration;

use kube::runtime::controller::Action;
use kube::runtime::events::EventType;
use kube::{Resource, ResourceExt};
use tracing::{debug, info, warn};

use lattice_common::crd::{ClusterPhase, LatticeCluster};
use lattice_common::events::{actions, reasons};
use lattice_common::{capi_namespace, Error, LATTICE_SYSTEM_NAMESPACE, PARENT_CONFIG_SECRET};
use lattice_move::{pause_cluster, unpause_cluster};
use lattice_proto::cell_command::Command;
use lattice_proto::{CellCommand, DeleteCluster};

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

/// Handle cluster deletion with unpivot logic.
///
/// Dispatches to the appropriate handler based on whether this is a self
/// cluster (running on itself) or a non-self cluster (child managed by parent).
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

    if is_self {
        handle_self_deletion(cluster, ctx).await
    } else {
        handle_non_self_deletion(cluster, ctx).await
    }
}

/// Handle deletion of a child cluster from the parent side.
///
/// Two paths depending on whether CAPI resources have been pivoted:
///
/// - **Pre-pivot** (`pivot_complete` is false): CAPI resources are still on
///   this (parent) cluster. Delete the CAPI Cluster directly.
/// - **Post-pivot** (`pivot_complete` and not `unpivot_import_complete`):
///   CAPI resources live on the child. Send `DeleteCluster` via gRPC to tell
///   the child to self-delete and unpivot. If the agent is disconnected,
///   requeue and wait for reconnection — we cannot delete CAPI resources we
///   don't have. Once unpivot completes and the cell sets
///   `unpivot_import_complete`, CAPI resources are back on the parent and
///   the direct CAPI delete path takes over.
async fn handle_non_self_deletion(
    cluster: &LatticeCluster,
    ctx: &Context,
) -> Result<Action, Error> {
    let name = cluster.name_any();
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

    // For pivoted clusters where unpivot hasn't completed yet, CAPI resources
    // are on the child — we must tell the child to self-delete via gRPC.
    // Once unpivot_import_complete is set, CAPI resources are back on the
    // parent and we can proceed to direct CAPI delete.
    let status = cluster.status.as_ref();
    let pivot_complete = status.map_or(false, |s| s.pivot_complete);
    let unpivot_import_complete = status.map_or(false, |s| s.unpivot_import_complete);

    if pivot_complete && !unpivot_import_complete {
        return handle_pivoted_child_deletion(cluster, ctx, &name).await;
    }

    // Pre-pivot or post-unpivot: CAPI resources are on this cluster.
    let capi_exists = match ctx.capi.capi_cluster_exists(&name, &capi_namespace).await {
        Ok(exists) => exists,
        Err(e) => {
            warn!(cluster = %name, error = %e, "Failed to check CAPI cluster existence, assuming exists");
            true
        }
    };

    if capi_exists {
        // Only check stability before the first delete attempt. Once Deleting,
        // skip — under CPU overload the stability API can fail repeatedly,
        // which would block deletion forever.
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
        return Ok(Action::requeue(Duration::from_secs(10)));
    }

    // CAPI Cluster is gone — clean up bootstrap state and remove finalizer
    if let Some(ref servers) = ctx.parent_servers {
        if let Some(state) = servers.bootstrap_state().await {
            state.deregister(&name);
        }
    }
    info!(cluster = %name, "Infrastructure cleanup complete, removing finalizer");
    remove_finalizer(cluster, ctx).await?;
    Ok(Action::await_change())
}

/// Send `DeleteCluster` to a pivoted child via gRPC.
///
/// After pivot, CAPI resources live on the child. The only way to delete
/// is to tell the child to self-delete, triggering the unpivot flow that
/// sends CAPI resources back. If the agent is disconnected, we requeue
/// and wait — there is no fallback since we don't have the CAPI resources.
async fn handle_pivoted_child_deletion(
    cluster: &LatticeCluster,
    ctx: &Context,
    name: &str,
) -> Result<Action, Error> {
    if let Some(ref servers) = ctx.parent_servers {
        let registry = servers.agent_registry();
        if registry.is_connected(name) {
            let cmd = CellCommand {
                command_id: uuid::Uuid::new_v4().to_string(),
                command: Some(Command::DeleteCluster(DeleteCluster {
                    cluster_name: name.to_string(),
                })),
            };
            match registry.send_command(name, cmd).await {
                Ok(()) => {
                    info!(cluster = %name, "Sent DeleteCluster to child agent");
                    let status = cluster
                        .status
                        .clone()
                        .unwrap_or_default()
                        .phase(ClusterPhase::Deleting)
                        .message("Waiting for child to unpivot CAPI resources");
                    ctx.kube.patch_status(name, &status).await?;
                    return Ok(Action::requeue(Duration::from_secs(10)));
                }
                Err(e) => {
                    warn!(
                        cluster = %name,
                        error = %e,
                        "Failed to send DeleteCluster, will retry on next reconcile"
                    );
                }
            }
        } else {
            info!(
                cluster = %name,
                "Agent not connected, waiting for reconnection to send DeleteCluster"
            );
        }
    }

    // Requeue — agent will reconnect and we'll retry sending DeleteCluster
    let status = cluster
        .status
        .clone()
        .unwrap_or_default()
        .phase(ClusterPhase::Deleting)
        .message("Waiting for child agent to reconnect for unpivot");
    ctx.kube.patch_status(name, &status).await?;
    Ok(Action::requeue(Duration::from_secs(10)))
}

/// Handle deletion of a self-managed cluster (running on itself).
///
/// For cell clusters with children: blocks deletion until children are deleted.
/// For clusters with a parent: pauses CAPI, waits for stability, sets phase
/// to Unpivoting. The agent detects deletion_timestamp and sends CAPI
/// resources to the parent via the unpivot retry loop.
/// For root clusters: removes finalizer immediately.
async fn handle_self_deletion(
    cluster: &LatticeCluster,
    ctx: &Context,
) -> Result<Action, Error> {
    let name = cluster.name_any();

    // Block deletion if this cell has active children
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

    // Check if we have a parent to unpivot to
    let has_parent = ctx
        .kube
        .get_secret(PARENT_CONFIG_SECRET, LATTICE_SYSTEM_NAMESPACE)
        .await?
        .is_some();

    if !has_parent {
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

    // Wait for CAPI resources to stabilize (no machines provisioning/deleting)
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

    // Verify node counts match spec (prevents TOCTOU with scaling).
    // Query live counts — status.ready_workers may be stale since handle_ready
    // is bypassed during deletion.
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

    // Agent handles unpivot automatically: detects deletion_timestamp and starts
    // sending ClusterDeleting to parent until parent's CAPI deletes us.
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

        let status = cluster
            .status
            .clone()
            .unwrap_or_default()
            .phase(ClusterPhase::Unpivoting)
            .message("Agent sending CAPI resources to parent");
        ctx.kube.patch_status(&name, &status).await?;
    }

    // Finalizer keeps the resource around until CAPI deletes the infrastructure
    debug!(cluster = %name, "Unpivoting - waiting for parent to delete via CAPI");
    Ok(Action::requeue(Duration::from_secs(30)))
}
