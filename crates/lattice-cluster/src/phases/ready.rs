//! Ready phase handler.
//!
//! Reconciles infrastructure and worker pools for self-managing clusters.

use std::collections::BTreeMap;
use std::time::Duration;

use kube::runtime::controller::Action;
use kube::runtime::events::EventType;
use kube::{Resource, ResourceExt};
use tracing::{debug, info, warn};

use lattice_capi::provider::{format_capi_version, pool_resource_suffix};
use lattice_common::crd::{LatticeCluster, LatticeClusterStatus, WorkerPoolStatus};
use lattice_common::events::{actions, reasons};
use lattice_common::{capi_namespace, Error};

use crate::controller::{
    autoscaling_warning, build_gpu_cordon_plan, determine_gpu_action, determine_scaling_action,
    Context, GpuNodeState, NodeCounts, ScalingAction,
};
use crate::phases::{generate_capi_manifests, reconcile_infrastructure};

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

    // Ensure cell LB Service exists when parent_config is present.
    // This is idempotent and handles both steady state and the promotion case
    // (creates the service on the first reconcile after parent_config is added,
    // rather than waiting up to 30s for the background activation watcher to poll).
    if let Some(ref pc) = cluster.spec.parent_config {
        let provider_type = cluster.spec.provider.provider_type();
        if let Err(e) = ctx
            .kube
            .ensure_cell_service(
                pc.bootstrap_port,
                pc.grpc_port,
                pc.proxy_port,
                &provider_type,
            )
            .await
        {
            warn!(error = %e, "failed to ensure cell LB service, will retry");
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
            pool_resources: vec![],
        }
    });

    // Check GPU health annotations on all nodes and cordon/drain as needed
    if let Err(e) = reconcile_gpu_health(cluster, ctx).await {
        warn!(error = %e, "failed to reconcile GPU health, will retry");
    }

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
    update_node_status(cluster, ctx, &name, pool_statuses, &counts, children_health).await;

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
    let mut missing_pools = Vec::new();

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

        // For missing pools, use spec.replicas as desired (WaitForMachineDeployment returns 0)
        if matches!(action, ScalingAction::WaitForMachineDeployment) {
            missing_pools.push(pool_id.clone());
            total_desired += pool_spec.replicas;

            pool_statuses.insert(
                pool_id.clone(),
                WorkerPoolStatus {
                    desired_replicas: pool_spec.replicas,
                    current_replicas: 0,
                    ready_replicas: 0,
                    autoscaling_enabled: action.is_autoscaling(),
                    message: Some(
                        "MachineDeployment not found, creating CAPI resources".to_string(),
                    ),
                },
            );
            continue;
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

    // Create CAPI resources for any pools that don't have MachineDeployments yet
    if !missing_pools.is_empty() {
        if let Err(e) = create_missing_pool_resources(cluster, ctx, &missing_pools).await {
            warn!(
                pools = ?missing_pools,
                error = %e,
                "Failed to create CAPI resources for missing pools, will retry"
            );
        }
    }

    Ok((total_desired, pool_statuses))
}

/// Execute a scaling action for a worker pool.
///
/// Returns true on success, false if the action failed and the caller should
/// break out of the loop early (returning accumulated pool_statuses).
///
/// Note: `WaitForMachineDeployment` is handled before this function is called
/// (missing pools are collected and their CAPI resources created in bulk).
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
            // Should not reach here — handled in reconcile_worker_pools
            warn!(pool = %pool_id, "Unexpected WaitForMachineDeployment in execute_scaling_action");
            false
        }
    }
}

/// Generate and apply CAPI resources for worker pools that don't have MachineDeployments.
///
/// Generates the full set of CAPI manifests for the cluster, then filters to only
/// those belonging to the missing pools (matched by the `-pool-{id}` suffix).
async fn create_missing_pool_resources(
    cluster: &LatticeCluster,
    ctx: &Context,
    missing_pools: &[String],
) -> Result<(), Error> {
    let name = cluster.name_any();
    let capi_ns = capi_namespace(&name);

    info!(
        cluster = %name,
        pools = ?missing_pools,
        "Creating CAPI resources for new worker pools"
    );

    let all_manifests = generate_capi_manifests(cluster, ctx).await?;

    // Filter to manifests belonging to missing pools.
    // Pool resources are named with a `-pool-{pool_id}` suffix.
    let pool_manifests: Vec<_> = all_manifests
        .into_iter()
        .filter(|m| {
            missing_pools
                .iter()
                .any(|pool_id| m.metadata.name.ends_with(&pool_resource_suffix(pool_id)))
        })
        .collect();

    if pool_manifests.is_empty() {
        warn!(
            cluster = %name,
            pools = ?missing_pools,
            "No CAPI manifests matched missing pools"
        );
        return Ok(());
    }

    info!(
        cluster = %name,
        manifests = pool_manifests.len(),
        pools = ?missing_pools,
        "Applying CAPI manifests for new worker pools"
    );

    ctx.capi.apply_manifests(&pool_manifests, &capi_ns).await?;

    ctx.events
        .publish(
            &cluster.object_ref(&()),
            EventType::Normal,
            reasons::PROVISIONING_STARTED,
            actions::PROVISION,
            Some(format!(
                "Created CAPI resources for new worker pools: {}",
                missing_pools.join(", ")
            )),
        )
        .await;

    Ok(())
}

/// Check GPU health annotations on all nodes and take cordon/drain actions.
///
/// Applies a cluster-level cordon budget: if >50% of GPU nodes are already
/// cordoned, new cordons are suppressed. If pending GPU pods exist and we're
/// at the threshold, the lowest-confidence warning node is selectively
/// uncordoned to relieve scheduling pressure.
///
/// Drains only happen when GPUs are confirmed lost (dropped to 0) and the loss
/// has persisted for >60s.
/// Drains only evict pods that request GPU resources (not CPU-only pods).
async fn reconcile_gpu_health(
    cluster: &LatticeCluster,
    ctx: &Context,
) -> Result<(), Error> {
    use lattice_common::resources::GPU_RESOURCE;

    let nodes = ctx.kube.list_nodes().await?;

    // Build per-node GPU state
    let mut gpu_node_states: Vec<GpuNodeState> = Vec::new();

    for node in &nodes {
        let node_name = match node.metadata.name.as_deref() {
            Some(n) => n,
            None => continue,
        };

        let has_gpus = node
            .status
            .as_ref()
            .and_then(|s| s.allocatable.as_ref())
            .and_then(|a| a.get(GPU_RESOURCE))
            .map(|q| lattice_common::resources::parse_quantity_int(Some(q)).unwrap_or(0) > 0)
            .unwrap_or(false);

        if !has_gpus {
            continue;
        }

        let annotations = node.metadata.annotations.as_ref();
        let empty = std::collections::BTreeMap::new();
        let ann = annotations.unwrap_or(&empty);

        let action = determine_gpu_action(
            ann,
            lattice_common::gpu::HEARTBEAT_STALENESS_SECS,
            lattice_common::gpu::GPU_LOSS_DRAIN_DELAY_SECS,
        );
        let anomaly_score = ann
            .get(lattice_common::gpu::ANNOTATION_ANOMALY_SCORE)
            .and_then(|v| v.parse::<f32>().ok())
            .unwrap_or(0.0);
        let is_cordoned = node
            .spec
            .as_ref()
            .and_then(|s| s.unschedulable)
            .unwrap_or(false);

        gpu_node_states.push(GpuNodeState {
            node_name: node_name.to_string(),
            action,
            anomaly_score,
            is_cordoned,
            has_gpu_capacity: has_gpus,
        });
    }

    if gpu_node_states.is_empty() {
        return Ok(());
    }

    // Check for pending pods with GPU requests (priority > 0)
    let has_pending_gpu_pods = ctx.kube.has_pending_gpu_pods().await.unwrap_or(false);

    // Build the cordon plan with threshold enforcement
    let plan = build_gpu_cordon_plan(&gpu_node_states, has_pending_gpu_pods);

    if plan.threshold_hit {
        warn!(
            "GPU cordon threshold hit (>50% of GPU nodes cordoned), suppressing new cordons"
        );
    }

    // Execute uncordons first (relieve pressure before adding more)
    for node_name in &plan.to_uncordon {
        info!(node = %node_name, "selectively uncordoning GPU node (lowest confidence, pending pods)");
        if let Err(e) = ctx.kube.uncordon_node(node_name).await {
            warn!(node = %node_name, error = %e, "failed to uncordon node");
        }
        ctx.events
            .publish(
                &cluster.object_ref(&()),
                EventType::Normal,
                reasons::GPU_HEALTH_WARNING,
                actions::CORDON,
                Some(format!(
                    "Selectively uncordoning GPU node {} (lowest anomaly, pending pods need capacity)",
                    node_name
                )),
            )
            .await;
    }

    // Execute cordons
    for node_name in &plan.to_cordon {
        info!(node = %node_name, "cordoning GPU node (anomaly detected)");
        if let Err(e) = ctx.kube.cordon_node(node_name).await {
            warn!(node = %node_name, error = %e, "failed to cordon node");
        }
        ctx.events
            .publish(
                &cluster.object_ref(&()),
                EventType::Warning,
                reasons::GPU_HEALTH_WARNING,
                actions::CORDON,
                Some(format!(
                    "GPU anomaly detected on node {}, cordoning",
                    node_name
                )),
            )
            .await;
    }

    // Execute drains (cordon + evict GPU pods).
    // Drains only fire for confirmed total GPU loss (allocatable == 0) that has
    // persisted for >60s. The workloads are already broken at this point —
    // draining makes the failure visible and frees pods to reschedule.
    for node_name in &plan.to_drain {
        info!(
            node = %node_name,
            "draining GPU node (all GPUs lost, persisted >60s)"
        );
        if let Err(e) = ctx.kube.cordon_node(node_name).await {
            warn!(node = %node_name, error = %e, "failed to cordon node");
        }
        if let Err(e) = ctx.kube.drain_node(node_name).await {
            warn!(node = %node_name, error = %e, "failed to drain GPU pods");
        }
        ctx.events
            .publish(
                &cluster.object_ref(&()),
                EventType::Warning,
                reasons::GPU_HEALTH_CRITICAL,
                actions::DRAIN,
                Some(format!(
                    "All GPUs lost on node {} (>60s), draining GPU workloads",
                    node_name
                )),
            )
            .await;
    }

    Ok(())
}

/// Update cluster status with node counts, worker pool information, and children health.
async fn update_node_status(
    cluster: &LatticeCluster,
    ctx: &Context,
    name: &str,
    mut pool_statuses: BTreeMap<String, WorkerPoolStatus>,
    counts: &NodeCounts,
    children_health: Vec<lattice_common::crd::ChildClusterHealth>,
) {
    // Distribute ready workers proportionally across pools for parent-side visibility.
    // Agents report accurate per-pool counts in ClusterHealth.pool_resources.
    let total_desired: u32 = pool_statuses.values().map(|p| p.desired_replicas).sum();
    if total_desired > 0 && counts.ready_workers > 0 {
        let mut remaining = counts.ready_workers;
        let pool_count = pool_statuses.len();
        for (i, pool_status) in pool_statuses.values_mut().enumerate() {
            if i == pool_count - 1 {
                // Last pool gets the remainder to avoid rounding errors
                pool_status.ready_replicas = remaining;
            } else {
                let share = (counts.ready_workers as f64 * pool_status.desired_replicas as f64
                    / total_desired as f64)
                    .round() as u32;
                let capped = share.min(remaining);
                pool_status.ready_replicas = capped;
                remaining = remaining.saturating_sub(capped);
            }
        }
    }

    // Preserve existing status fields (spread operator preserves last_heartbeat, etc.)
    let current_status = cluster.status.clone().unwrap_or_default();
    let updated_status = LatticeClusterStatus {
        worker_pools: pool_statuses,
        ready_workers: Some(counts.ready_workers),
        ready_control_plane: Some(counts.ready_control_plane),
        children_health,
        pool_resources: counts.pool_resources.clone(),
        ..current_status
    };

    if let Err(e) = ctx.kube.patch_status(name, &updated_status).await {
        warn!(error = %e, "Failed to update node status");
    }
}
