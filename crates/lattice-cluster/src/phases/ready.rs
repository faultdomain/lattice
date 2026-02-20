//! Ready phase handler.
//!
//! Reconciles infrastructure and worker pools for self-managing clusters.

use std::collections::BTreeMap;
use std::time::Duration;

use kube::runtime::controller::Action;
use kube::runtime::events::EventType;
use kube::{Resource, ResourceExt};
use tracing::{debug, info, warn};

use lattice_capi::provider::format_capi_version;
use lattice_common::crd::{LatticeCluster, LatticeClusterStatus, WorkerPoolStatus};
use lattice_common::events::{actions, reasons};
use lattice_common::{capi_namespace, Error};

use crate::controller::{
    autoscaling_warning, determine_scaling_action, Context, NodeCounts, ScalingAction,
};
use crate::phases::reconcile_infrastructure;

/// Result of version reconciliation.
enum VersionStatus {
    /// All CAPI resources match the desired version.
    UpToDate,
    /// An upgrade is in progress — CP or workers are being rolled.
    UpgradeInProgress,
}

/// Reconcile Kubernetes version between LatticeCluster spec and CAPI resources.
///
/// Uses `status.version` as a crash-safe state machine:
/// - `status.version == desired` → skip entirely (zero CAPI API calls in steady state)
/// - `status.version != desired` → upgrade in progress, read CAPI resources to drive it
/// - `status.version` is only set AFTER all CP + worker versions match
///
/// Upgrade order follows Kubernetes version skew policy:
/// - Control plane first (patch KubeadmControlPlane/RKE2ControlPlane)
/// - Wait for cluster to stabilize (CP nodes finish rolling)
/// - Workers second (patch all MachineDeployments)
async fn reconcile_version(
    cluster: &LatticeCluster,
    ctx: &Context,
    name: &str,
    capi_namespace: &str,
) -> Result<VersionStatus, Error> {
    let bootstrap = &cluster.spec.provider.kubernetes.bootstrap;
    let desired = format_capi_version(&cluster.spec.provider.kubernetes.version, bootstrap);

    // Fast path: status.version matches desired — nothing to do.
    let status_version = cluster.status.as_ref().and_then(|s| s.version.as_deref());
    if status_version == Some(&desired) {
        return Ok(VersionStatus::UpToDate);
    }

    // Upgrade needed or in progress. Read CP version from CAPI.
    let cp_version = ctx
        .capi
        .get_cp_version(name, capi_namespace, bootstrap.clone())
        .await?;

    let Some(current_cp) = cp_version else {
        debug!(cluster = %name, "ControlPlane not found, skipping version reconciliation");
        return Ok(VersionStatus::UpToDate);
    };

    // Stage 1: Patch control plane if needed.
    if current_cp != desired {
        info!(
            cluster = %name,
            current = %current_cp,
            desired = %desired,
            "Control plane version mismatch, patching"
        );
        ctx.capi
            .update_cp_version(name, capi_namespace, bootstrap.clone(), &desired)
            .await?;
        ctx.events
            .publish(
                &cluster.object_ref(&()),
                EventType::Normal,
                reasons::VERSION_UPGRADE_STARTED,
                actions::UPGRADE,
                Some(format!(
                    "Upgrading control plane from {} to {}",
                    current_cp, desired
                )),
            )
            .await;
        return Ok(VersionStatus::UpgradeInProgress);
    }

    // Stage 2: CP matches. Check worker pools.
    let mut pools_to_patch = Vec::new();
    for pool_id in cluster.spec.nodes.worker_pools.keys() {
        let pool_version = ctx
            .capi
            .get_pool_version(name, pool_id, capi_namespace)
            .await?;

        if let Some(ref current_pool) = pool_version {
            if current_pool != &desired {
                pools_to_patch.push((pool_id.clone(), current_pool.clone()));
            }
        }
    }

    if pools_to_patch.is_empty() {
        // All CAPI resources match. Stamp status.version so future reconciles skip entirely.
        let mut updated_status = cluster.status.clone().unwrap_or_default();
        updated_status.version = Some(desired.clone());
        if let Err(e) = ctx.kube.patch_status(name, &updated_status).await {
            warn!(error = %e, "Failed to update status.version");
        }
        return Ok(VersionStatus::UpToDate);
    }

    // Pools need patching — wait for cluster to stabilize first (CP rollout must be done).
    let stable = ctx.capi.is_cluster_stable(name, capi_namespace).await?;
    if !stable {
        debug!(cluster = %name, "Cluster not stable, waiting before patching workers");
        return Ok(VersionStatus::UpgradeInProgress);
    }

    for (pool_id, current_pool) in &pools_to_patch {
        info!(
            cluster = %name,
            pool = %pool_id,
            current = %current_pool,
            desired = %desired,
            "Worker pool version mismatch, patching"
        );
        ctx.capi
            .update_pool_version(name, pool_id, capi_namespace, &desired)
            .await?;
    }

    ctx.events
        .publish(
            &cluster.object_ref(&()),
            EventType::Normal,
            reasons::VERSION_UPGRADE_STARTED,
            actions::UPGRADE,
            Some(format!("Upgrading worker pools to {}", desired)),
        )
        .await;
    Ok(VersionStatus::UpgradeInProgress)
}

/// Handle a cluster in the Ready phase.
///
/// Ready is for self-managing clusters. This phase:
/// 1. Reconciles infrastructure (Cilium policies, Istio, etc.)
/// 2. Reconciles Kubernetes version (CP first, then workers)
/// 3. Reconciles worker pools (scaling)
/// 4. Updates status with worker pool information
/// 5. Requeues with appropriate interval based on worker readiness
pub async fn handle_ready(cluster: &LatticeCluster, ctx: &Context) -> Result<Action, Error> {
    let name = cluster.name_any();

    debug!("cluster is ready, reconciling infrastructure and worker pools");

    // Reconcile infrastructure (Cilium policies, Istio, etc.)
    // Failures are non-blocking — worker pool scaling must proceed even if
    // infrastructure components aren't ready yet (they may need workers to schedule).
    if let Some(client) = &ctx.client {
        if let Err(e) = reconcile_infrastructure(client, cluster).await {
            warn!(error = %e, "failed to reconcile infrastructure, will retry");
        }
    }

    let capi_namespace = capi_namespace(&name);

    // Reconcile Kubernetes version (CP first, then workers).
    // During an upgrade, skip pool scaling — CAPI is already doing a rolling update.
    match reconcile_version(cluster, ctx, &name, &capi_namespace).await {
        Ok(VersionStatus::UpgradeInProgress) => {
            debug!(cluster = %name, "Version upgrade in progress, requeuing");
            return Ok(Action::requeue(Duration::from_secs(10)));
        }
        Err(e) => {
            warn!(error = %e, "Failed to reconcile version, will retry");
        }
        Ok(VersionStatus::UpToDate) => {}
    }

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

    if counts.ready_workers >= total_desired {
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

        // Execute scaling action — on failure, return accumulated pool_statuses
        if !execute_scaling_action(ctx, name, pool_id, capi_namespace, &action).await {
            return Ok((total_desired, pool_statuses));
        }
    }

    Ok((total_desired, pool_statuses))
}

/// Execute a scaling action for a worker pool.
///
/// Returns true on success, false if the action failed and the caller should
/// break out of the loop early (returning accumulated pool_statuses).
async fn execute_scaling_action(
    ctx: &Context,
    name: &str,
    pool_id: &str,
    capi_namespace: &str,
    action: &ScalingAction,
) -> bool {
    match action {
        ScalingAction::NoOp { .. } => true,
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
                return false;
            }
            true
        }
        ScalingAction::WaitForMachineDeployment => {
            warn!(
                pool = %pool_id,
                "MachineDeployment not found for pool, will retry"
            );
            false
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
