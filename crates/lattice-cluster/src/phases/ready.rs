//! Ready phase handler.
//!
//! Reconciles infrastructure and worker pools for self-managing clusters.

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use kube::api::{Api, DynamicObject, GroupVersionKind, ListParams, Patch, PatchParams};
use kube::discovery::ApiResource;
use kube::runtime::controller::Action;
use kube::runtime::events::EventType;
use kube::{Client, Resource, ResourceExt};
use tracing::{debug, info, warn};

use lattice_capi::provider::{format_capi_version, pool_resource_suffix};
use lattice_cert_issuer::builder::{self, MANAGED_BY_LABEL, MANAGED_BY_VALUE};
use lattice_common::crd::{
    CertIssuer, CertIssuerPhase, DNSProvider, LatticeCluster, LatticeClusterStatus,
    WorkerPoolStatus,
};
use lattice_common::events::{actions, reasons};
use lattice_common::{capi_namespace, Error, LATTICE_SYSTEM_NAMESPACE};

use crate::controller::{
    autoscaling_warning, build_gpu_cordon_plan, determine_gpu_action, determine_scaling_action,
    Context, GpuNodeState, NodeCounts, ScalingAction,
};
use crate::phases::{generate_capi_manifests, reconcile_infrastructure};

/// Result of operator image reconciliation.
enum OperatorImageAction {
    /// Deployment image matches spec.latticeImage.
    UpToDate,
    /// Deployment image was patched; K8s will roll pods.
    UpgradeInProgress,
}

/// Reconcile the operator's own Deployment image against `spec.latticeImage`.
///
/// Only runs on the self-cluster (the cluster we're running on). If the Deployment
/// image doesn't match the desired image, patches the Deployment and returns
/// `UpgradeInProgress` so the caller can requeue with a short interval.
async fn reconcile_operator_image(
    cluster: &LatticeCluster,
    ctx: &Context,
    name: &str,
) -> Result<OperatorImageAction, Error> {
    let desired = &cluster.spec.lattice_image;

    let current = ctx
        .kube
        .get_operator_deployment_image()
        .await?
        .ok_or_else(|| {
            Error::internal("lattice-operator Deployment not found in lattice-system")
        })?;

    if current == *desired {
        // Image matches — ensure status reflects it
        let needs_status_update = cluster
            .status
            .as_ref()
            .and_then(|s| s.lattice_image.as_deref())
            != Some(desired);
        if needs_status_update {
            let mut status = cluster.status.clone().unwrap_or_default();
            status.lattice_image = Some(desired.clone());
            if let Err(e) = ctx.kube.patch_status(name, &status).await {
                warn!(error = %e, "Failed to update status.latticeImage");
            }
        }
        return Ok(OperatorImageAction::UpToDate);
    }

    info!(
        cluster = %name,
        current = %current,
        desired = %desired,
        "Operator image mismatch, patching Deployment"
    );
    ctx.kube.patch_operator_deployment_image(desired).await?;

    ctx.events
        .publish(
            &cluster.object_ref(&()),
            EventType::Normal,
            reasons::VERSION_UPGRADE_STARTED,
            actions::UPGRADE,
            Some(format!(
                "Upgrading operator image from {} to {}",
                current, desired
            )),
        )
        .await;

    Ok(OperatorImageAction::UpgradeInProgress)
}

/// Cascade the parent's `spec.latticeImage` to children that don't match.
///
/// For each connected child whose `spec.latticeImage` differs, patches the child's
/// LatticeCluster CRD via the K8s API proxy (for pivoted children).
async fn cascade_upgrade_to_children(cluster: &LatticeCluster, ctx: &Context) {
    if !cluster.spec.cascade_upgrade {
        return;
    }

    let Some(ref parent_servers) = ctx.parent_servers else {
        return;
    };
    if !parent_servers.is_running() {
        return;
    }

    let desired_image = &cluster.spec.lattice_image;
    let desired_k8s_version = &cluster.spec.provider.kubernetes.version;
    let children_health = parent_servers.agent_registry().collect_children_health();

    for child in &children_health {
        // Skip children where both image and K8s version already match
        let image_matches = child.lattice_image.as_deref() == Some(desired_image);
        let version_matches = child
            .kubernetes_version
            .as_deref()
            .is_some_and(|v| k8s_version_matches_spec(v, desired_k8s_version));

        if image_matches && version_matches {
            continue;
        }

        let patch_body = serde_json::json!({
            "spec": {
                "latticeImage": desired_image,
                "provider": {
                    "kubernetes": {
                        "version": desired_k8s_version
                    }
                }
            }
        });
        let body = serde_json::to_vec(&patch_body).unwrap_or_default();

        let path = format!("/apis/lattice.dev/v1alpha1/latticeclusters/{}", child.name);

        let request = lattice_proto::KubernetesRequest {
            request_id: format!("cascade-upgrade-{}", child.name),
            verb: "PATCH".to_string(),
            path,
            query: String::new(),
            body,
            content_type: "application/merge-patch+json".to_string(),
            accept: String::new(),
            timeout_ms: 10_000,
            cancel: false,
            target_path: child.name.clone(),
            source_user: String::new(),
            source_groups: vec![],
            traceparent: String::new(),
            tracestate: String::new(),
        };

        let cmd = lattice_proto::CellCommand {
            command_id: request.request_id.clone(),
            command: Some(lattice_proto::cell_command::Command::KubernetesRequest(
                request,
            )),
        };

        match parent_servers
            .agent_registry()
            .send_command(&child.name, cmd)
            .await
        {
            Ok(()) => {
                info!(
                    child = %child.name,
                    image = %desired_image,
                    k8s_version = %desired_k8s_version,
                    "Cascaded upgrade to child"
                );
            }
            Err(e) => {
                warn!(
                    child = %child.name,
                    error = %e,
                    "Failed to cascade upgrade to child"
                );
            }
        }
    }
}

/// Compare a live K8s version (e.g. "v1.32") against a spec version (e.g. "1.32.0").
///
/// Matches on major.minor only, since the live version from `apiserver_version()`
/// typically omits the patch level.
fn k8s_version_matches_spec(live: &str, spec: &str) -> bool {
    let live_trimmed = live.strip_prefix('v').unwrap_or(live);
    let spec_parts: Vec<&str> = spec.split('.').collect();
    let live_parts: Vec<&str> = live_trimmed.split('.').collect();
    live_parts.first() == spec_parts.first() && live_parts.get(1) == spec_parts.get(1)
}

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

    // Stage 2: CP matches. Check all worker pool versions in one list call.
    let pool_versions = ctx.capi.get_all_pool_versions(name, capi_namespace).await?;

    let mut pools_to_patch = Vec::new();
    for pool_id in cluster.spec.nodes.worker_pools.keys() {
        if let Some(current_pool) = pool_versions.get(pool_id) {
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
/// - Reconciles infrastructure (Cilium policies, Istio, etc.)
/// - Reconciles Kubernetes version (CP first, then workers)
/// - Reconciles worker pools (scaling)
/// - Updates status with worker pool information
/// - Requeues with appropriate interval based on worker readiness
pub async fn handle_ready(cluster: &LatticeCluster, ctx: &Context) -> Result<Action, Error> {
    let name = cluster.name_any();
    let is_self = crate::controller::is_self_cluster(&name, ctx.self_cluster_name.as_deref());

    debug!("cluster is ready, reconciling infrastructure and worker pools");

    // Reconcile operator image (self-cluster only).
    // If an upgrade is in progress, requeue quickly and skip the rest —
    // a new pod will take over after the Deployment rolls.
    if is_self {
        match reconcile_operator_image(cluster, ctx, &name).await {
            Ok(OperatorImageAction::UpgradeInProgress) => {
                return Ok(Action::requeue(Duration::from_secs(10)));
            }
            Ok(OperatorImageAction::UpToDate) => {
                // Cascade to children after self is up-to-date
                cascade_upgrade_to_children(cluster, ctx).await;
            }
            Err(e) => {
                warn!(error = %e, "Failed to reconcile operator image, will retry");
            }
        }
    }

    // Reconcile infrastructure (Cilium policies, Istio, etc.) — self-cluster only.
    // Child clusters manage their own infrastructure after pivot via their own operator.
    // Applying here would overwrite the local istiod config (trust domain, mesh ID)
    // with the child cluster's values, causing waypoint proxy churn.
    if is_self {
        if let Some(client) = &ctx.client {
            if let Err(e) = reconcile_infrastructure(client, cluster).await {
                warn!(error = %e, "failed to reconcile infrastructure, will retry");
            }
            if let Err(e) = reconcile_issuers(client, cluster).await {
                warn!(error = %e, "failed to reconcile issuers, will retry");
            }
            if let Err(e) = reconcile_dns_forwarding(client, cluster).await {
                warn!(error = %e, "failed to reconcile DNS forwarding, will retry");
            }
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

    // Check GPU health annotations on all nodes and cordon as needed.
    // This runs before worker pool reconciliation because it is safety-critical:
    // CAPI errors must not block GPU health responses.
    if let Err(e) = reconcile_gpu_health(cluster, ctx).await {
        warn!(error = %e, "failed to reconcile GPU health, will retry");
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

/// Reconcile cert-manager ClusterIssuers from the cluster's `spec.issuers` map.
///
/// For each issuer entry, fetches the CertIssuer CRD, builds a ClusterIssuer JSON,
/// and applies it via server-side apply. After applying all issuers, removes stale
/// ClusterIssuers that are labeled as managed but no longer referenced in the spec.
async fn reconcile_issuers(client: &Client, cluster: &LatticeCluster) -> Result<(), Error> {
    if cluster.spec.issuers.is_empty() {
        return Ok(());
    }

    let ns = cluster
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());
    let cert_issuer_api: Api<CertIssuer> = Api::namespaced(client.clone(), &ns);
    let dns_provider_api: Api<DNSProvider> = Api::namespaced(client.clone(), &ns);

    let ar = ApiResource::from_gvk(&GroupVersionKind::gvk(
        "cert-manager.io",
        "v1",
        "ClusterIssuer",
    ));
    let cluster_issuer_api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);

    let mut applied_names: HashSet<String> = HashSet::new();

    for (key, cert_issuer_name) in &cluster.spec.issuers {
        let issuer_crd = match cert_issuer_api.get(cert_issuer_name).await {
            Ok(crd) => crd,
            Err(e) => {
                warn!(
                    issuer = %cert_issuer_name,
                    error = %e,
                    "failed to fetch CertIssuer CRD, skipping"
                );
                continue;
            }
        };

        // Only process Ready issuers
        let phase = issuer_crd
            .status
            .as_ref()
            .map(|s| &s.phase)
            .unwrap_or(&CertIssuerPhase::Pending);
        if *phase != CertIssuerPhase::Ready {
            debug!(
                issuer = %cert_issuer_name,
                phase = %phase,
                "CertIssuer not Ready, skipping"
            );
            continue;
        }

        // Fetch DNSProvider if needed for ACME DNS-01
        let dns_provider = if let Some(ref acme) = issuer_crd.spec.acme {
            if let Some(ref dns_ref) = acme.dns_provider_ref {
                match dns_provider_api.get(dns_ref).await {
                    Ok(dp) => Some(dp),
                    Err(e) => {
                        warn!(
                            issuer = %cert_issuer_name,
                            dns_provider = %dns_ref,
                            error = %e,
                            "failed to fetch DNSProvider, skipping issuer"
                        );
                        continue;
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        let issuer_json = match builder::build_cluster_issuer(
            key,
            &issuer_crd.spec,
            dns_provider.as_ref().map(|dp| &dp.spec),
        ) {
            Ok(json) => json,
            Err(e) => {
                warn!(
                    issuer = %cert_issuer_name,
                    key = %key,
                    error = %e,
                    "failed to build ClusterIssuer JSON, skipping"
                );
                continue;
            }
        };

        let issuer_name = format!("lattice-{}", key);
        match cluster_issuer_api
            .patch(
                &issuer_name,
                &PatchParams::apply("lattice-cluster-controller"),
                &Patch::Apply(&issuer_json),
            )
            .await
        {
            Ok(_) => {
                info!(cluster_issuer = %issuer_name, "Applied ClusterIssuer");
                applied_names.insert(issuer_name);
            }
            Err(e) => {
                warn!(
                    cluster_issuer = %issuer_name,
                    error = %e,
                    "failed to apply ClusterIssuer"
                );
            }
        }
    }

    // Clean up stale ClusterIssuers: managed by us but not in current spec
    let expected_names: HashSet<String> = cluster
        .spec
        .issuers
        .keys()
        .map(|k| format!("lattice-{}", k))
        .collect();

    let label_selector = format!("{}={}", MANAGED_BY_LABEL, MANAGED_BY_VALUE);
    let list_params = ListParams::default().labels(&label_selector);

    match cluster_issuer_api.list(&list_params).await {
        Ok(list) => {
            for item in list.items {
                if let Some(name) = item.metadata.name.as_deref() {
                    if !expected_names.contains(name) {
                        info!(cluster_issuer = %name, "Deleting stale ClusterIssuer");
                        if let Err(e) = cluster_issuer_api
                            .delete(name, &Default::default())
                            .await
                        {
                            warn!(
                                cluster_issuer = %name,
                                error = %e,
                                "failed to delete stale ClusterIssuer"
                            );
                        }
                    }
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "failed to list ClusterIssuers for cleanup");
        }
    }

    Ok(())
}

/// Reconcile CoreDNS forwarding for DNS zones defined via DNSProvider CRDs.
///
/// For each DNS provider in the cluster's `spec.dns.providers` map, fetches the
/// DNSProvider CRD and (for PiHole providers) adds a conditional forward block to
/// a `coredns-custom` ConfigMap. CoreDNS's `import` directive picks up custom
/// zone files automatically.
///
/// Cloud providers (Route53, Cloudflare, etc.) don't need CoreDNS forwarding —
/// they're authoritative DNS managed by external-dns, resolved via public DNS.
async fn reconcile_dns_forwarding(
    client: &Client,
    cluster: &LatticeCluster,
) -> Result<(), Error> {
    let dns_config = match &cluster.spec.dns {
        Some(dns) if !dns.providers.is_empty() => dns,
        _ => return Ok(()),
    };

    let ns = cluster
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());
    let dns_api: Api<DNSProvider> = Api::namespaced(client.clone(), &ns);

    // Collect forward blocks for providers that declare a resolver address.
    // Public DNS providers (Route53, Cloudflare, etc.) don't set resolver —
    // their records resolve via the public DNS hierarchy after external-dns creates them.
    let mut custom_blocks = Vec::new();

    for (_key, provider_name) in &dns_config.providers {
        let provider = match dns_api.get(provider_name).await {
            Ok(p) => p,
            Err(e) => {
                warn!(provider = %provider_name, error = %e, "failed to fetch DNSProvider, skipping");
                continue;
            }
        };

        if let Some(ref resolver) = provider.spec.resolver {
            let zone = &provider.spec.zone;
            custom_blocks.push(format!(
                "{zone}:53 {{\n    forward . {resolver}\n    cache 30\n    errors\n}}"
            ));

            debug!(zone = %zone, resolver = %resolver, "adding CoreDNS forward for private zone");
        }
    }

    if custom_blocks.is_empty() {
        return Ok(());
    }

    // Build the coredns-custom ConfigMap with all forward blocks
    let corefile_custom = custom_blocks.join("\n\n");
    let configmap = serde_json::json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": "coredns-custom",
            "namespace": "kube-system",
            "labels": {
                MANAGED_BY_LABEL: MANAGED_BY_VALUE,
            }
        },
        "data": {
            "lattice-dns.server": corefile_custom,
        }
    });

    // Apply via SSA
    let cm_api: Api<k8s_openapi::api::core::v1::ConfigMap> =
        Api::namespaced(client.clone(), "kube-system");
    cm_api
        .patch(
            "coredns-custom",
            &PatchParams::apply("lattice-cluster-controller"),
            &Patch::Apply(&configmap),
        )
        .await
        .map_err(|e| Error::internal(format!("failed to apply coredns-custom ConfigMap: {e}")))?;

    info!(
        zones = custom_blocks.len(),
        "CoreDNS custom forwarding ConfigMap applied"
    );

    Ok(())
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

/// Check GPU health annotations on all nodes and take cordon actions.
///
/// Applies a cluster-level cordon budget: if >50% of GPU nodes are already
/// cordoned, new cordons are suppressed. If pending GPU pods exist and we're
/// at the threshold, the lowest-confidence warning node is selectively
/// uncordoned to relieve scheduling pressure.
///
/// Draining is intentionally not automated — human operators should investigate
/// and decide whether to drain after reviewing GPU metrics.
async fn reconcile_gpu_health(cluster: &LatticeCluster, ctx: &Context) -> Result<(), Error> {
    use lattice_common::resources::GPU_RESOURCE;

    let nodes = ctx.kube.list_nodes().await?;

    // Build per-node GPU state
    let mut gpu_node_states: Vec<GpuNodeState> = Vec::new();

    for node in &nodes {
        let node_name = match node.metadata.name.as_deref() {
            Some(n) => n,
            None => continue,
        };

        let gpu_count = node
            .status
            .as_ref()
            .and_then(|s| s.allocatable.as_ref())
            .and_then(|a| a.get(GPU_RESOURCE))
            .map(|q| {
                match lattice_common::resources::parse_quantity_int(Some(q)) {
                    Ok(v) => v.max(0) as u32,
                    Err(e) => {
                        warn!(node = %node_name, value = ?q, error = %e, "Failed to parse GPU allocatable quantity, skipping node GPU count");
                        0
                    }
                }
            })
            .unwrap_or(0);
        let has_gpu_capacity = gpu_count > 0;

        let annotations = node.metadata.annotations.as_ref();
        let has_gpu_annotations = annotations
            .map(|a| a.contains_key(lattice_common::gpu::ANNOTATION_GPU_HEALTH))
            .unwrap_or(false);

        // Process nodes that either have GPU capacity or GPU health annotations.
        // During total GPU loss, allocatable drops to 0 but annotations remain —
        // the operator must still cordon these nodes.
        if !has_gpu_capacity && !has_gpu_annotations {
            continue;
        }
        let empty = std::collections::BTreeMap::new();
        let ann = annotations.unwrap_or(&empty);

        let action = determine_gpu_action(ann, lattice_common::gpu::HEARTBEAT_STALENESS_SECS);
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
            gpu_count,
        });
    }

    if gpu_node_states.is_empty() {
        return Ok(());
    }

    // Find the largest pending GPU request (0 if none)
    let max_pending_gpu_request = match ctx.kube.max_pending_gpu_request().await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "Failed to query max pending GPU request, defaulting to 0");
            0
        }
    };

    // Build the cordon plan with threshold enforcement
    let plan = build_gpu_cordon_plan(&gpu_node_states, max_pending_gpu_request);

    if plan.threshold_hit {
        warn!("GPU cordon threshold hit (>50% of GPU nodes cordoned), suppressing new cordons");
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

    // Record GPU health metrics
    let cordoned_after = gpu_node_states
        .iter()
        .filter(|s| {
            // Nodes that were already cordoned, plus newly cordoned, minus uncordoned
            let was_cordoned = s.is_cordoned;
            let newly_cordoned = plan.to_cordon.contains(&s.node_name);
            let newly_uncordoned = plan.to_uncordon.contains(&s.node_name);
            (was_cordoned || newly_cordoned) && !newly_uncordoned
        })
        .count() as i64;
    lattice_common::metrics::record_gpu_health(
        gpu_node_states.len() as i64,
        cordoned_after,
        plan.to_cordon.len() as u64,
        plan.to_uncordon.len() as u64,
        plan.threshold_hit,
        max_pending_gpu_request as i64,
    );

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn k8s_version_matches_same_major_minor() {
        assert!(k8s_version_matches_spec("v1.32", "1.32.0"));
        assert!(k8s_version_matches_spec("v1.32", "1.32.3"));
        assert!(k8s_version_matches_spec("1.32", "1.32.0"));
    }

    #[test]
    fn k8s_version_mismatch_different_minor() {
        assert!(!k8s_version_matches_spec("v1.31", "1.32.0"));
        assert!(!k8s_version_matches_spec("v1.33", "1.32.0"));
    }

    #[test]
    fn k8s_version_mismatch_different_major() {
        assert!(!k8s_version_matches_spec("v2.32", "1.32.0"));
    }

    #[test]
    fn k8s_version_matches_with_patch_in_live() {
        assert!(k8s_version_matches_spec("v1.32.1", "1.32.0"));
        assert!(k8s_version_matches_spec("1.32.5", "1.32.0"));
    }

    #[test]
    fn k8s_version_matches_no_patch_in_spec() {
        assert!(k8s_version_matches_spec("v1.32", "1.32"));
    }
}
