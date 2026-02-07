//! Pending phase handler.
//!
//! Handles the initial state where prerequisites are checked before provisioning.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;
use kube::runtime::events::EventType;
use kube::{Resource, ResourceExt};
use tracing::{debug, info, warn};

use lattice_agent::{patch_kubeconfig_for_self_management, InClusterClientProvider};
use lattice_capi::installer::CapiProviderConfig;
use lattice_capi::provider::create_provider;
use lattice_common::crd::{ClusterPhase, LatticeCluster};
use lattice_common::events::{actions, reasons};
use lattice_common::retry::{retry_with_backoff, RetryConfig};
use lattice_common::{capi_namespace, Error};

use crate::controller::Context;
use crate::phases::{try_transition_to_ready, update_status};

/// Handle a cluster in the Pending phase.
///
/// This phase checks prerequisites before provisioning:
/// - For self-clusters: wait for CAPI resources from pivot, then transition to Ready
/// - For child clusters: validate provider, install CAPI, generate manifests, transition to Provisioning
pub async fn handle_pending(
    cluster: &LatticeCluster,
    ctx: &Context,
    is_self: bool,
) -> Result<Action, Error> {
    let name = cluster.name_any();

    // Create LoadBalancer Service if this cluster has a cell spec
    // This exposes cell servers for workload clusters to reach bootstrap + gRPC endpoints
    if let Some(ref cell_spec) = cluster.spec.parent_config {
        info!(host = ?cell_spec.host, "ensuring LoadBalancer Service for cell servers");
        ctx.kube
            .ensure_cell_service(
                cell_spec.host.clone(),
                cell_spec.bootstrap_port,
                cell_spec.grpc_port,
            )
            .await?;
        info!("cell LoadBalancer Service created/updated");
    }

    // Self-cluster: we ARE this cluster, skip provisioning
    // Wait for CAPI resources to exist (from pivot) before going Ready
    if is_self {
        return handle_self_cluster(cluster, ctx, &name).await;
    }

    // Child cluster: provision infrastructure
    handle_child_cluster(cluster, ctx, &name).await
}

/// Handle a self-cluster in Pending phase.
///
/// Self-clusters skip provisioning since they already exist. We wait for
/// CAPI resources to exist (from pivot) then patch kubeconfig for self-management.
async fn handle_self_cluster(
    cluster: &LatticeCluster,
    ctx: &Context,
    name: &str,
) -> Result<Action, Error> {
    let capi_namespace = capi_namespace(name);

    // Check if CAPI resources exist (from pivot)
    let bootstrap = cluster.spec.provider.kubernetes.bootstrap.clone();
    let capi_ready = ctx
        .capi
        .is_infrastructure_ready(name, &capi_namespace, bootstrap)
        .await
        .unwrap_or(false);

    if !capi_ready {
        debug!("self-cluster waiting for CAPI resources (pivot not complete yet)");
        return Ok(Action::requeue(Duration::from_secs(10)));
    }

    // CAPI resources exist - patch kubeconfig for self-management
    // CAPI needs to reach itself via kubernetes.default.svc, not external IP
    info!("CAPI resources found, patching kubeconfig for self-management");
    let cluster_name = name.to_string();
    let namespace = capi_namespace.clone();
    let patch_result = retry_with_backoff(
        &RetryConfig::with_max_attempts(10),
        "patch_kubeconfig_for_self_management",
        || {
            let cn = cluster_name.clone();
            let ns = namespace.clone();
            let provider = InClusterClientProvider;
            async move { patch_kubeconfig_for_self_management(&cn, &ns, &provider).await }
        },
    )
    .await;

    if let Err(e) = patch_result {
        warn!(
            error = %e,
            "Failed to patch kubeconfig for self-management after retries"
        );
        return Ok(Action::requeue(Duration::from_secs(10)));
    }

    info!("self-cluster has CAPI resources ready");
    try_transition_to_ready(cluster, ctx, true).await
}

/// Handle a child cluster in Pending phase.
///
/// Child clusters need to have their infrastructure provisioned:
/// 1. Validate CloudProvider exists
/// 2. Copy provider credentials
/// 3. Ensure CAPI is installed
/// 4. Generate and apply CAPI manifests
/// 5. Transition to Provisioning
async fn handle_child_cluster(
    cluster: &LatticeCluster,
    ctx: &Context,
    name: &str,
) -> Result<Action, Error> {
    // Look up the CloudProvider referenced by provider_ref
    let provider_type = cluster.spec.provider.provider_type();
    let cloud_provider = ctx
        .kube
        .get_cloud_provider(&cluster.spec.provider_ref)
        .await?
        .ok_or_else(|| {
            Error::validation(format!(
                "CloudProvider '{}' not found",
                cluster.spec.provider_ref
            ))
        })?;

    // Validate CloudProvider has credentials for non-Docker providers
    if provider_type != lattice_common::crd::ProviderType::Docker
        && cloud_provider.spec.credentials_secret_ref.is_none()
    {
        return Err(Error::validation(format!(
            "CloudProvider '{}' requires credentials_secret_ref for {} provider",
            cluster.spec.provider_ref, provider_type
        )));
    }

    // Copy provider credentials from CloudProvider's secret to provider namespace
    if let (Some(ref client), Some(ref secret_ref)) =
        (&ctx.client, &cloud_provider.spec.credentials_secret_ref)
    {
        lattice_capi::installer::copy_credentials_to_provider_namespace(
            client,
            provider_type,
            secret_ref,
        )
        .await?;
    }

    // Ensure CAPI is installed before provisioning
    info!("ensuring CAPI is installed for provider");
    let capi_config = CapiProviderConfig::new(provider_type)?;
    ctx.capi_installer.ensure(&capi_config).await?;

    // Generate and apply CAPI manifests
    info!("generating CAPI manifests for cluster");
    let capi_namespace = capi_namespace(name);

    // Ensure the namespace exists
    ctx.kube.ensure_namespace(&capi_namespace).await?;

    // Copy provider credentials to cluster namespace in parallel
    let provider = create_provider(cluster.spec.provider.provider_type(), &capi_namespace)?;
    let secrets: Vec<_> = provider.required_secrets(cluster);
    if !secrets.is_empty() {
        let futures: Vec<_> = secrets
            .into_iter()
            .map(|(secret_name, source_namespace)| {
                let kube = Arc::clone(&ctx.kube);
                let target_namespace = capi_namespace.clone();
                async move {
                    kube.copy_secret_to_namespace(
                        &secret_name,
                        &source_namespace,
                        &target_namespace,
                    )
                    .await
                }
            })
            .collect();
        futures::future::try_join_all(futures).await?;
    }

    // Generate CAPI manifests
    let manifests = super::generate_capi_manifests(cluster, ctx).await?;

    // Apply CAPI manifests to the cluster-specific namespace
    info!(count = manifests.len(), namespace = %capi_namespace, "applying CAPI manifests");
    ctx.capi
        .apply_manifests(&manifests, &capi_namespace)
        .await?;

    ctx.events
        .publish(
            &cluster.object_ref(&()),
            EventType::Normal,
            reasons::PROVISIONING_STARTED,
            actions::PROVISION,
            Some(format!("Applied {} CAPI manifests", manifests.len())),
        )
        .await;

    // Transition to Provisioning
    info!("transitioning to Provisioning phase");
    update_status(cluster, ctx, ClusterPhase::Provisioning, None, false).await?;
    Ok(Action::requeue(Duration::from_secs(5)))
}
