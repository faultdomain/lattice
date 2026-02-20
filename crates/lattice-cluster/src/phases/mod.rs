//! Phase handlers for the LatticeCluster controller.
//!
//! Each phase of the cluster lifecycle is handled by a dedicated module,
//! making the reconciliation logic testable and maintainable.

mod pending;
mod pivoting;
mod provisioning;
mod ready;

pub use pending::handle_pending;
pub use pivoting::handle_pivoting;
pub use provisioning::handle_provisioning;
pub use ready::handle_ready;

use std::time::Duration;

use kube::runtime::controller::Action;
use kube::runtime::events::EventType;
use kube::{Client, Resource};
use tracing::{debug, info, warn};

use lattice_capi::provider::{create_provider, CAPIManifest};
use lattice_common::crd::{
    ClusterPhase, Condition, ConditionStatus, LatticeCluster, LatticeClusterStatus,
};
use lattice_common::events::{actions, reasons};
use lattice_common::{capi_namespace, Error};

use crate::controller::Context;

/// Try to transition cluster to Ready phase.
///
/// Returns Ok(Action) if transitioned or needs requeue, Err if status update failed.
/// The cluster should not transition to Ready until:
/// 1. Cell servers are running (webhook endpoint is listening)
/// 2. MutatingWebhookConfiguration exists (K8s will route to webhook)
pub async fn try_transition_to_ready(
    cluster: &LatticeCluster,
    ctx: &Context,
    set_pivot_complete: bool,
) -> Result<Action, Error> {
    // Check cell servers are running (only if configured)
    // If parent_servers is None, we're in test mode or special configuration - skip check
    if let Some(ref parent_servers) = ctx.parent_servers {
        if !parent_servers.is_running() {
            debug!("cell servers not running yet, waiting before Ready");
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    }

    // All checks passed, transition to Ready
    info!("transitioning cluster to Ready phase");
    ctx.events
        .publish(
            &cluster.object_ref(&()),
            EventType::Normal,
            reasons::CLUSTER_READY,
            actions::RECONCILE,
            Some("Cluster is ready".to_string()),
        )
        .await;
    update_status(cluster, ctx, ClusterPhase::Ready, None, set_pivot_complete).await?;
    Ok(Action::requeue(Duration::from_secs(60)))
}

/// Update cluster status to the specified phase.
///
/// This consolidates the status update logic for all phases. For Failed phase,
/// pass a custom error message. For other phases, pass None for the message.
pub async fn update_status(
    cluster: &LatticeCluster,
    ctx: &Context,
    phase: ClusterPhase,
    error_message: Option<&str>,
    set_pivot_complete: bool,
) -> Result<(), Error> {
    use kube::ResourceExt;
    let name = cluster.name_any();

    let (condition_type, condition_status, reason, message) = match phase {
        ClusterPhase::Pending => (
            "Pending",
            ConditionStatus::Unknown,
            "AwaitingProvisioning",
            "Cluster is pending provisioning",
        ),
        ClusterPhase::Provisioning => (
            "Provisioning",
            ConditionStatus::True,
            "StartingProvisioning",
            "Provisioning cluster infrastructure",
        ),
        ClusterPhase::Pivoting => (
            "Pivoting",
            ConditionStatus::True,
            "StartingPivot",
            "Pivoting cluster to self-managed",
        ),
        ClusterPhase::Pivoted => (
            "Pivoted",
            ConditionStatus::True,
            "PivotComplete",
            "Child cluster is self-managing",
        ),
        ClusterPhase::Deleting => (
            "Deleting",
            ConditionStatus::True,
            "DeletingCluster",
            "Deleting cluster infrastructure",
        ),
        ClusterPhase::Unpivoting => (
            "Unpivoting",
            ConditionStatus::True,
            "StartingUnpivot",
            "Exporting CAPI resources to parent",
        ),
        ClusterPhase::Ready => (
            "Ready",
            ConditionStatus::True,
            "ClusterReady",
            "Cluster is self-managed and ready",
        ),
        ClusterPhase::Failed => (
            "Ready",
            ConditionStatus::False,
            "ValidationFailed",
            error_message.unwrap_or("Unknown error"),
        ),
    };

    // Idempotency guard: skip update if phase + message already match.
    // This prevents reconcile storms from Condition timestamps.
    // Still patch if set_pivot_complete is requested and not yet set.
    let pivot_already_set = cluster
        .status
        .as_ref()
        .map(|s| s.pivot_complete)
        .unwrap_or(false);
    let needs_pivot_update = set_pivot_complete && !pivot_already_set;

    if !needs_pivot_update {
        if let Some(ref current) = cluster.status {
            if current.phase == phase && current.message.as_deref() == Some(message) {
                debug!("cluster status unchanged, skipping update");
                return Ok(());
            }
        }
    }

    let condition = Condition::new(condition_type, condition_status, reason, message);

    // Preserve existing status fields (worker_pools, ready_workers, etc.)
    let current_status = cluster.status.clone().unwrap_or_default();
    let mut status = LatticeClusterStatus {
        phase,
        message: Some(message.to_string()),
        conditions: vec![condition],
        // Preserve persistent fields
        worker_pools: current_status.worker_pools,
        ready_workers: current_status.ready_workers,
        ready_control_plane: current_status.ready_control_plane,
        endpoint: current_status.endpoint,
        pivot_complete: current_status.pivot_complete,
        bootstrap_complete: current_status.bootstrap_complete,
        unpivot_import_complete: current_status.unpivot_import_complete,
        observed_generation: current_status.observed_generation,
        bootstrap_token: current_status.bootstrap_token,
        children_health: current_status.children_health,
        last_heartbeat: current_status.last_heartbeat,
        version: current_status.version,
    };

    // Set pivot_complete if requested (persists pivot completion across restarts)
    if set_pivot_complete {
        status.pivot_complete = true;
    }

    ctx.kube.patch_status(&name, &status).await?;

    if phase == ClusterPhase::Failed {
        ctx.events
            .publish(
                &cluster.object_ref(&()),
                EventType::Warning,
                reasons::CLUSTER_FAILED,
                actions::RECONCILE,
                Some(message.to_string()),
            )
            .await;
        warn!(message, "updated status to Failed");
    } else {
        info!("updated status to {:?}", phase);
    }

    Ok(())
}

/// Reconcile infrastructure (Cilium policies, Istio policies, etc.)
///
/// This ensures that infrastructure components can't be removed and are always in sync.
/// Uses server-side apply for idempotency.
pub async fn reconcile_infrastructure(
    client: &Client,
    cluster: &LatticeCluster,
) -> Result<(), Error> {
    use lattice_common::ParentConfig;
    use lattice_infra::bootstrap::InfrastructureConfig;

    let mut config = InfrastructureConfig::from(cluster);

    // Read parent config if it exists (indicates we have an upstream parent cell)
    if let Some(parent) = ParentConfig::read(client).await? {
        config.parent_host = Some(parent.endpoint.host);
        config.parent_grpc_port = parent.endpoint.grpc_port;
    }

    // Generate infrastructure manifests
    let manifests = lattice_infra::bootstrap::generate_core(&config)
        .await
        .map_err(|e| Error::internal(format!("failed to generate infrastructure: {}", e)))?;

    debug!(
        cluster = %config.cluster_name,
        parent_host = ?config.parent_host,
        count = manifests.len(),
        "reconciling infrastructure manifests"
    );

    // Apply manifests using server-side apply with skip_missing_crds
    // This handles CRDs that aren't installed yet (e.g., Cilium, Istio)
    let options = lattice_common::ApplyOptions {
        skip_missing_crds: true,
    };
    lattice_common::apply_manifests_with_discovery(client, &manifests, &options)
        .await
        .map_err(|e| Error::internal(format!("failed to apply infrastructure: {}", e)))?;

    Ok(())
}

/// Generate CAPI manifests for a cluster based on its provider type.
pub async fn generate_capi_manifests(
    cluster: &LatticeCluster,
    ctx: &Context,
) -> Result<Vec<CAPIManifest>, Error> {
    use lattice_capi::provider::BootstrapInfo;

    // Each cluster gets its own CAPI namespace for pivot isolation
    let cluster_name = cluster
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| Error::validation("cluster must have a name"))?;
    let capi_ns = capi_namespace(cluster_name);

    // Build bootstrap info - if parent_servers is running, we're a cell provisioning a cluster
    // that needs to connect back to us. Bootstrap clusters skip this since they don't provision children.
    let running_parent_servers = if lattice_common::is_bootstrap_cluster() {
        None
    } else {
        ctx.parent_servers.as_ref().filter(|s| s.is_running())
    };

    let bootstrap = if let Some(parent_servers) = running_parent_servers {
        build_bootstrap_info(cluster, ctx, parent_servers, cluster_name).await?
    } else {
        // No parent_servers - self-provisioning (management cluster bootstrap)
        BootstrapInfo::default()
    };

    let provider = create_provider(cluster.spec.provider.provider_type(), &capi_ns)?;
    provider.generate_capi_manifests(cluster, &bootstrap).await
}

/// Build bootstrap info for cluster registration.
async fn build_bootstrap_info(
    cluster: &LatticeCluster,
    ctx: &Context,
    parent_servers: &lattice_cell::ParentServers<lattice_cell::DefaultManifestGenerator>,
    cluster_name: &str,
) -> Result<lattice_capi::provider::BootstrapInfo, Error> {
    use lattice_capi::provider::BootstrapInfo;

    let self_cluster_name = ctx.self_cluster_name.as_ref().ok_or_else(|| {
        Error::validation("self_cluster_name required when parent_servers is configured")
    })?;
    let self_cluster = ctx
        .kube
        .get_cluster(self_cluster_name)
        .await?
        .ok_or_else(|| Error::bootstrap("self-cluster LatticeCluster not found"))?;
    let endpoints = self_cluster.spec.parent_config.as_ref().ok_or_else(|| {
        Error::validation("self-cluster must have spec.parent_config to provision clusters")
    })?;

    // Get bootstrap state from parent_servers
    let bootstrap_state = parent_servers.bootstrap_state().await.ok_or_else(|| {
        Error::bootstrap("parent_servers running but bootstrap_state not available")
    })?;

    let ca_cert = bootstrap_state.ca_trust_bundle_pem().await;

    // Get the cell host from the LoadBalancer Service
    let cell_host = ctx.kube.get_cell_host().await?.ok_or_else(|| {
        Error::validation(
            "cell Service has no LoadBalancer ingress yet. \
             Wait for the cloud provider or Cilium L2 to assign an address.",
        )
    })?;

    // Build endpoints using the discovered host and configured ports
    let cell_endpoint = format!(
        "{}:{}:{}",
        cell_host, endpoints.bootstrap_port, endpoints.grpc_port
    );
    let bootstrap_endpoint = format!("https://{}:{}", cell_host, endpoints.bootstrap_port);

    // Get or create bootstrap token
    let token = get_or_create_bootstrap_token(
        cluster,
        ctx,
        &bootstrap_state,
        cluster_name,
        &cell_endpoint,
        &ca_cert,
    )
    .await?;

    Ok(BootstrapInfo::new(bootstrap_endpoint, token, ca_cert))
}

/// Get existing bootstrap token or create a new one.
async fn get_or_create_bootstrap_token(
    cluster: &LatticeCluster,
    ctx: &Context,
    bootstrap_state: &lattice_cell::BootstrapState,
    cluster_name: &str,
    cell_endpoint: &str,
    ca_cert: &str,
) -> Result<String, Error> {
    // Get bootstrap token from LatticeCluster status (source of truth)
    if let Some(token) = cluster
        .status
        .as_ref()
        .and_then(|s| s.bootstrap_token.clone())
    {
        debug!(cluster = %cluster_name, "Using existing bootstrap token from LatticeCluster status");
        return Ok(token);
    }

    // No existing token - generate new one and register cluster
    let cluster_manifest =
        serde_json::to_string(&cluster.for_export()).map_err(|e| Error::Serialization {
            message: format!("failed to serialize cluster: {}", e),
            kind: Some("LatticeCluster".to_string()),
        })?;

    let autoscaling_enabled = cluster
        .spec
        .nodes
        .worker_pools
        .values()
        .any(|p| p.is_autoscaling_enabled());

    let registration = lattice_cell::ClusterRegistration {
        cluster_id: cluster_name.to_string(),
        cell_endpoint: cell_endpoint.to_string(),
        ca_certificate: ca_cert.to_string(),
        cluster_manifest,
        networking: cluster.spec.networking.clone(),
        provider: cluster.spec.provider.provider_type(),
        bootstrap: cluster.spec.provider.kubernetes.bootstrap.clone(),
        k8s_version: cluster.spec.provider.kubernetes.version.clone(),
        autoscaling_enabled,
    };
    let new_token = bootstrap_state.register_cluster(registration).await;
    let token_str = new_token.as_str().to_string();

    // Persist the token to LatticeCluster status immediately
    let mut status = cluster.status.clone().unwrap_or_default();
    status.bootstrap_token = Some(token_str.clone());
    ctx.kube.patch_status(cluster_name, &status).await?;
    debug!(cluster = %cluster_name, "Persisted new bootstrap token to LatticeCluster status");

    Ok(token_str)
}
