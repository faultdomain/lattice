//! Ready phase handler.
//!
//! Reconciles infrastructure and worker pools for self-managing clusters.

use std::collections::BTreeMap;
use std::time::Duration;

use kube::runtime::controller::Action;
use kube::runtime::events::EventType;
use kube::{Resource, ResourceExt};
use tracing::{debug, info, warn};

use lattice_common::crd::{LatticeCluster, LatticeClusterStatus, WorkerPoolStatus};
use lattice_common::events::{actions, reasons};
use lattice_common::{capi_namespace, Error};

use crate::controller::{
    autoscaling_warning, determine_scaling_action, Context, NodeCounts, ScalingAction,
};
use crate::phases::reconcile_infrastructure;

/// Handle a cluster in the Ready phase.
///
/// Ready is for self-managing clusters. This phase:
/// 1. Reconciles infrastructure (Cilium policies, Istio, etc.)
/// 2. Reconciles worker pools (scaling)
/// 3. Updates status with worker pool information
/// 4. Ensures control plane is tainted when workers are ready
pub async fn handle_ready(cluster: &LatticeCluster, ctx: &Context) -> Result<Action, Error> {
    let name = cluster.name_any();

    debug!("cluster is ready, reconciling infrastructure and worker pools");

    // Reconcile infrastructure (Cilium policies, Istio, etc.)
    if let Some(client) = &ctx.client {
        if let Err(e) = reconcile_infrastructure(client, cluster).await {
            warn!(error = %e, "failed to reconcile infrastructure, will retry");
            return Ok(Action::requeue(Duration::from_secs(30)));
        }
    }

    let capi_namespace = capi_namespace(&name);

    // Reconcile worker pools and collect status
    let (total_desired, pool_statuses) =
        reconcile_worker_pools(cluster, ctx, &name, &capi_namespace).await?;

    // Get ready node counts (CP + workers in one API call)
    let counts = ctx.kube.get_ready_node_counts().await.unwrap_or_else(|e| {
        warn!(error = %e, "Failed to get ready node counts, assuming 0");
        NodeCounts {
            ready_control_plane: 0,
            ready_workers: 0,
        }
    });

    // Collect children health from agent registry (parent clusters only)
    let children_health = if let Some(ref parent_servers) = ctx.parent_servers {
        if parent_servers.is_running() {
            parent_servers.agent_registry().collect_children_health()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // Update status with node counts, worker pool information, and children health
    update_node_status(cluster, ctx, &name, pool_statuses, counts, children_health).await;

    debug!(
        desired = total_desired,
        ready_workers = counts.ready_workers,
        ready_cp = counts.ready_control_plane,
        "node status"
    );

    // Ensure control plane is tainted when workers are ready
    if counts.ready_workers >= total_desired {
        ensure_control_plane_tainted(ctx, counts.ready_workers).await;
        Ok(Action::requeue(Duration::from_secs(60)))
    } else {
        // Workers not ready yet, poll faster
        debug!(
            desired = total_desired,
            ready = counts.ready_workers,
            "waiting for workers to be provisioned by CAPI"
        );
        Ok(Action::requeue(Duration::from_secs(10)))
    }
}

/// Reconcile all worker pools and return (total_desired, pool_statuses).
async fn reconcile_worker_pools(
    cluster: &LatticeCluster,
    ctx: &Context,
    name: &str,
    capi_namespace: &str,
) -> Result<(u32, BTreeMap<String, WorkerPoolStatus>), Error> {
    let mut total_desired: u32 = 0;
    let mut pool_statuses = BTreeMap::new();

    for (pool_id, pool_spec) in &cluster.spec.nodes.worker_pools {
        // Get current MachineDeployment replica count
        let current_replicas = ctx
            .capi
            .get_pool_replicas(name, pool_id, capi_namespace)
            .await
            .unwrap_or_else(|e| {
                debug!(pool = %pool_id, error = %e, "Failed to get pool replicas");
                None
            });

        // Determine scaling action
        let action = determine_scaling_action(pool_spec, current_replicas);

        // Log warning if spec.replicas is outside autoscaling bounds
        if let Some(msg) = autoscaling_warning(pool_spec) {
            warn!(pool = %pool_id, "{}", msg);
        }

        total_desired += action.desired_replicas();

        let pool_status = WorkerPoolStatus {
            desired_replicas: action.desired_replicas(),
            current_replicas: current_replicas.unwrap_or(0),
            ready_replicas: 0, // Populated below after we count ready nodes
            autoscaling_enabled: action.is_autoscaling(),
            message: autoscaling_warning(pool_spec),
        };

        pool_statuses.insert(pool_id.clone(), pool_status);

        // Emit event for scaling actions
        if let ScalingAction::Scale { current, target } = &action {
            ctx.events
                .publish(
                    &cluster.object_ref(&()),
                    EventType::Normal,
                    reasons::WORKER_SCALING,
                    actions::SCALE,
                    Some(format!("Scaling pool '{}' {}→{}", pool_id, current, target)),
                )
                .await;
        }

        // Execute scaling action
        if let Err(action) =
            execute_scaling_action(ctx, name, pool_id, capi_namespace, &action).await
        {
            return Ok((total_desired, action));
        }
    }

    Ok((total_desired, pool_statuses))
}

/// Execute a scaling action for a worker pool.
///
/// Returns Ok(()) on success, or Err with the pool_statuses collected so far
/// along with a requeue action.
async fn execute_scaling_action(
    ctx: &Context,
    name: &str,
    pool_id: &str,
    capi_namespace: &str,
    action: &ScalingAction,
) -> Result<(), BTreeMap<String, WorkerPoolStatus>> {
    match action {
        ScalingAction::NoOp { .. } => Ok(()),
        ScalingAction::Scale { current, target } => {
            info!(
                pool = %pool_id,
                current = current,
                desired = target,
                "Scaling pool MachineDeployment to match spec"
            );
            if let Err(e) = ctx
                .capi
                .scale_pool(name, pool_id, capi_namespace, *target)
                .await
            {
                warn!(pool = %pool_id, error = %e, "Failed to scale pool, will retry");
                // Return empty map - caller will handle requeue
                return Err(BTreeMap::new());
            }
            Ok(())
        }
        ScalingAction::WaitForMachineDeployment => {
            warn!(
                pool = %pool_id,
                "MachineDeployment not found for pool, will retry"
            );
            Err(BTreeMap::new())
        }
    }
}

/// Update cluster status with node counts, worker pool information, and children health.
async fn update_node_status(
    cluster: &LatticeCluster,
    ctx: &Context,
    name: &str,
    mut pool_statuses: BTreeMap<String, WorkerPoolStatus>,
    counts: NodeCounts,
    children_health: Vec<lattice_common::crd::ChildClusterHealth>,
) {
    // For single-pool clusters, set ready_replicas on the pool
    if pool_statuses.len() == 1 {
        if let Some(pool_status) = pool_statuses.values_mut().next() {
            pool_status.ready_replicas = counts.ready_workers;
        }
    }

    // Preserve existing status fields (spread operator preserves last_heartbeat, etc.)
    let current_status = cluster.status.clone().unwrap_or_default();
    let updated_status = LatticeClusterStatus {
        worker_pools: pool_statuses,
        ready_workers: Some(counts.ready_workers),
        ready_control_plane: Some(counts.ready_control_plane),
        children_health,
        ..current_status
    };

    if let Err(e) = ctx.kube.patch_status(name, &updated_status).await {
        warn!(error = %e, "Failed to update node status");
    }
}

/// Ensure control plane nodes are tainted when workers are ready.
async fn ensure_control_plane_tainted(ctx: &Context, ready_workers: u32) {
    let tainted = ctx
        .kube
        .are_control_plane_nodes_tainted()
        .await
        .unwrap_or(true);

    if !tainted {
        info!(
            workers = ready_workers,
            "workers ready, re-tainting control plane nodes"
        );

        if let Err(e) = ctx.kube.taint_control_plane_nodes().await {
            warn!(error = %e, "failed to taint control plane nodes, will retry");
        } else {
            info!("control plane nodes tainted successfully");
        }
    }
}
