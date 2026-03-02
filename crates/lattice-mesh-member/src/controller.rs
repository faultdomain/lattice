//! MeshMember controller — watches `LatticeMeshMember` CRDs and applies mesh policies
//!
//! Generates and applies:
//! - CiliumNetworkPolicy (L4 eBPF)
//! - AuthorizationPolicy (L7 Istio)
//! - PeerAuthentication (per-port mTLS mode)
//! - ServiceEntry (external service registration)
//! - Gateway + Routes (ingress, if configured)
//! - Waypoint Gateway + AuthorizationPolicy (if external deps exist)

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, DynamicObject, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{debug, info, instrument, warn};

use lattice_cedar::{MeshWildcardRequest, PolicyEngine, WildcardDirection};
use lattice_common::crd::{
    AppliedResourceRef, Condition, ConditionStatus, LatticeMeshMember, LatticeMeshMemberStatus,
    MeshMemberPhase, MeshMemberScope, MeshMemberTarget,
};
use lattice_common::graph::{compute_edge_hash, ServiceGraph};
use lattice_common::mesh;
use lattice_common::status_check;
use lattice_common::{CrdKind, CrdRegistry, ReconcileError};

use crate::ingress::{IngressCompiler, WaypointCompiler};
use crate::policy::PolicyCompiler;

// =============================================================================
// Controller context
// =============================================================================

/// Shared context for the MeshMember controller
pub struct MeshMemberContext {
    pub client: Client,
    pub graph: Arc<ServiceGraph>,
    pub cluster_name: String,
    pub registry: Arc<CrdRegistry>,
    pub cedar: Option<Arc<PolicyEngine>>,
}

// =============================================================================
// Field manager
// =============================================================================

const FIELD_MANAGER: &str = "lattice-mesh-member-controller";
const GRAPH_HASH_ANNOTATION: &str = "lattice.dev/graph-hash";

// =============================================================================
// Orphan tracking helpers
// =============================================================================

/// Extract resource refs from compiled policies (AuthorizationPolicy + PeerAuthentication).
///
/// Bilateral-agreement Cilium policies are excluded (always 1 per service, never orphaned).
/// ServiceEntries are excluded (shared per-namespace-per-FQDN, can't safely delete
/// without checking other MeshMembers; orphaned SEs have no security impact since
/// the `allow-fqdn-*` AuthorizationPolicy IS tracked).
pub fn collect_resource_refs(
    policies: &crate::policy::GeneratedPolicies,
) -> HashSet<AppliedResourceRef> {
    let mut refs = HashSet::new();
    let mut track = |kind: CrdKind, name: &str| {
        refs.insert(AppliedResourceRef {
            kind: kind.kind_str().to_string(),
            name: name.to_string(),
        });
    };
    for ap in &policies.authorization_policies {
        track(CrdKind::AuthorizationPolicy, &ap.metadata.name);
    }
    for pa in &policies.peer_authentications {
        track(CrdKind::PeerAuthentication, &pa.metadata.name);
    }
    refs
}

/// Extract resource refs from compiled ingress resources.
///
/// Tracks per-service CNP, auth policy, routes, and certificates for orphan cleanup.
/// The shared Gateway is NOT tracked — its listeners are managed via SSA field managers.
pub fn collect_ingress_refs(
    ingress: &crate::ingress::GeneratedIngress,
) -> HashSet<AppliedResourceRef> {
    let mut refs = HashSet::new();
    let mut track = |kind: CrdKind, name: &str| {
        refs.insert(AppliedResourceRef {
            kind: kind.kind_str().to_string(),
            name: name.to_string(),
        });
    };

    if let Some(ref cnp) = ingress.gateway_policy {
        track(CrdKind::CiliumNetworkPolicy, &cnp.metadata.name);
    }
    if let Some(ref ap) = ingress.gateway_auth_policy {
        track(CrdKind::AuthorizationPolicy, &ap.metadata.name);
    }
    for route in &ingress.http_routes {
        track(CrdKind::HttpRoute, &route.metadata.name);
    }
    for route in &ingress.grpc_routes {
        track(CrdKind::GrpcRoute, &route.metadata.name);
    }
    for route in &ingress.tcp_routes {
        track(CrdKind::TcpRoute, &route.metadata.name);
    }
    for cert in &ingress.certificates {
        track(CrdKind::Certificate, &cert.metadata.name);
    }
    refs
}

/// Read previously applied resource refs from the MeshMember status.
/// Returns an empty set if the status is missing (graceful upgrade).
pub fn read_applied_resources(member: &LatticeMeshMember) -> HashSet<AppliedResourceRef> {
    member
        .status
        .as_ref()
        .map(|s| s.applied_resources.iter().cloned().collect())
        .unwrap_or_default()
}

/// Delete a single resource via the dynamic API, ignoring 404 (already gone).
/// Resolves the CRD from the registry on demand.
async fn delete_if_discovered(
    client: &Client,
    registry: &CrdRegistry,
    namespace: &str,
    name: &str,
    kind: &str,
) -> Result<(), ReconcileError> {
    let crd_kind = match CrdKind::from_kind_str(kind) {
        Some(k) => k,
        None => {
            warn!(kind = %kind, name = %name, "unknown orphan kind, skipping");
            return Ok(());
        }
    };

    let Some(ar) = registry.resolve(crd_kind).await? else {
        debug!(name = %name, kind = %kind, "CRD not discovered, skipping orphan delete");
        return Ok(());
    };

    lattice_common::kube_utils::delete_resource_if_exists(client, namespace, &ar, name, kind)
        .await
        .map_err(|e| ReconcileError::kube(format!("delete orphaned {kind} {name}"), e))?;
    Ok(())
}

/// Delete resources that were previously applied but are no longer in the compiled set.
async fn delete_orphaned_resources(
    client: &Client,
    registry: &CrdRegistry,
    namespace: &str,
    old_refs: &HashSet<AppliedResourceRef>,
    new_refs: &HashSet<AppliedResourceRef>,
) -> Result<(), ReconcileError> {
    let orphans: Vec<&AppliedResourceRef> = old_refs.difference(new_refs).collect();
    if orphans.is_empty() {
        return Ok(());
    }

    info!(count = orphans.len(), "deleting orphaned mesh resources");
    for orphan in orphans {
        delete_if_discovered(client, registry, namespace, &orphan.name, &orphan.kind).await?;
    }
    Ok(())
}

// =============================================================================
// Reconciliation
// =============================================================================

/// Reconcile a LatticeMeshMember resource
#[instrument(skip(member, ctx), fields(mesh_member = %member.name_any()))]
pub async fn reconcile(
    member: Arc<LatticeMeshMember>,
    ctx: Arc<MeshMemberContext>,
) -> Result<Action, ReconcileError> {
    let name = member.name_any();
    let namespace =
        member.metadata.namespace.as_deref().ok_or_else(|| {
            ReconcileError::Validation("LatticeMeshMember missing namespace".into())
        })?;

    // Validate spec
    if let Err(e) = member.spec.validate() {
        let msg = e.to_string();
        warn!(error = %msg, "mesh member validation failed");
        patch_status_with_hash(
            &ctx.client,
            &member,
            status_failed(&msg, member.metadata.generation),
            "",
        )
        .await?;
        return Ok(Action::await_change());
    }

    // Update graph (idempotent — crash recovery)
    ctx.graph.put_mesh_member(namespace, &name, &member.spec);

    // Cedar-gate wildcard inbound/outbound
    if let Some(denied) = check_cedar_wildcards(&name, namespace, &ctx).await {
        warn!(msg = %denied);
        patch_status_with_hash(
            &ctx.client,
            &member,
            status_failed(&denied, member.metadata.generation),
            "",
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(30)));
    }

    // Compute edge hash AFTER graph update to capture current bilateral agreements
    let inbound_edges = ctx.graph.get_active_inbound_edges(namespace, &name);
    let outbound_edges = ctx.graph.get_active_outbound_edges(namespace, &name);
    let cedar_epoch = ctx.cedar.as_ref().map_or(0, |c| c.reload_epoch());
    let graph_hash = compute_edge_hash(&inbound_edges, &outbound_edges, cedar_epoch);

    // Skip reconciliation if spec AND graph state haven't changed
    if is_status_current(&member, &graph_hash) {
        debug!("generation and graph state unchanged, skipping reconcile");
        return Ok(Action::requeue(Duration::from_secs(60)));
    }

    info!("reconciling mesh member");

    let scope = match member.spec.target {
        MeshMemberTarget::Selector(_) => MeshMemberScope::Workload,
        MeshMemberTarget::Namespace(_) => MeshMemberScope::Namespace,
        _ => MeshMemberScope::Workload,
    };

    match do_reconcile(&member, &name, namespace, &ctx).await {
        Ok((true, new_refs)) => {
            let mut status = status_ready(scope, member.metadata.generation);
            status.applied_resources = new_refs.into_iter().collect::<Vec<_>>();
            patch_status_with_hash(&ctx.client, &member, status, &graph_hash).await?;
            Ok(Action::requeue(Duration::from_secs(60)))
        }
        Ok((false, new_refs)) => {
            // ServiceEntries deferred (waypoint not programmed yet) —
            // report Progressing so LatticeService doesn't mark itself Ready.
            let mut status = status_progressing(scope, member.metadata.generation);
            status.applied_resources = new_refs.into_iter().collect::<Vec<_>>();
            patch_status_with_hash(&ctx.client, &member, status, "").await?;
            Ok(Action::requeue(Duration::from_secs(10)))
        }
        Err(e) => {
            let msg = e.to_string();
            warn!(error = %msg, "mesh member reconciliation failed");
            patch_status_with_hash(
                &ctx.client,
                &member,
                status_failed(&msg, member.metadata.generation),
                "",
            )
            .await?;
            Ok(Action::requeue(Duration::from_secs(30)))
        }
    }
}

/// Check Cedar wildcard authorization for allows_all/depends_all.
///
/// Uses the effective service account name (SPIFFE identity) as the Cedar principal,
/// not the LatticeMeshMember resource name.
///
/// Returns `Some(denial_message)` if a wildcard flag is active but denied by policy,
/// or `None` if all checks pass.
async fn check_cedar_wildcards(
    name: &str,
    namespace: &str,
    ctx: &MeshMemberContext,
) -> Option<String> {
    let node = ctx.graph.get_service(namespace, name)?;
    let checks = [
        (node.allows_all, WildcardDirection::Inbound),
        (node.depends_all, WildcardDirection::Outbound),
    ];
    let sa_name = node.sa_name().to_string();
    for (active, direction) in checks {
        if !active {
            continue;
        }
        let allowed = match &ctx.cedar {
            Some(cedar) => {
                let req = MeshWildcardRequest {
                    service_name: sa_name.clone(),
                    namespace: namespace.to_string(),
                    direction,
                };
                cedar.authorize_mesh_wildcard(&req).await.is_allowed()
            }
            None => false, // No Cedar engine = no wildcards (default-deny)
        };
        if !allowed {
            return Some(format!(
                "Cedar policy denied {direction} for {namespace}/{sa_name}; \
                 add a permit policy for Action::\"AllowWildcard\" on Mesh::\"{}\"",
                direction.resource_id(),
            ));
        }
    }
    None
}

/// Inner reconciliation logic. Returns `Ok((waypoint_ready, new_refs))` where
/// `waypoint_ready` is true when fully reconciled (including ServiceEntries),
/// false when partially reconciled (ServiceEntries deferred because waypoint isn't
/// programmed yet). `new_refs` contains the resource refs that were applied (for
/// orphan tracking). Returns `Err` on failure.
async fn do_reconcile(
    member: &LatticeMeshMember,
    name: &str,
    namespace: &str,
    ctx: &MeshMemberContext,
) -> Result<(bool, HashSet<AppliedResourceRef>), ReconcileError> {
    ensure_namespace_ambient(&ctx.client, namespace).await?;

    let policies = PolicyCompiler::new(&ctx.graph, &ctx.cluster_name).compile(name, namespace);

    let ingress = member
        .spec
        .ingress
        .as_ref()
        .map(|ingress_spec| {
            IngressCompiler::compile(name, namespace, ingress_spec, &member.spec.ports)
        })
        .transpose()
        .map_err(|e| ReconcileError::Validation(format!("ingress compilation: {e}")))?;

    let waypoint = if !policies.service_entries.is_empty() {
        Some(WaypointCompiler::compile(namespace))
    } else {
        None
    };

    let registry = &ctx.registry;
    let params = PatchParams::apply(FIELD_MANAGER).force();

    if let Some(ref waypoint_resources) = waypoint {
        apply_waypoint(
            &ctx.client,
            registry,
            namespace,
            &params,
            waypoint_resources,
        )
        .await?;
    }

    let waypoint_ready = if !policies.service_entries.is_empty() {
        is_waypoint_programmed(&ctx.client, registry, namespace).await
    } else {
        true
    };

    if waypoint_ready {
        apply_policies(&ctx.client, registry, namespace, &params, &policies).await?;
    } else {
        info!("waypoint not yet present, deferring ServiceEntry creation");
        let deferred = policies.without_service_entries();
        apply_policies(&ctx.client, registry, namespace, &params, &deferred).await?;
    }

    // Apply ingress resources with per-member field manager
    let ingress_field_manager = format!("{}/{}", FIELD_MANAGER, name);
    let ingress_params = PatchParams::apply(&ingress_field_manager).force();

    if let Some(ref ingress_resources) = ingress {
        apply_ingress(
            &ctx.client,
            registry,
            namespace,
            &ingress_params,
            ingress_resources,
        )
        .await?;
    }

    // Orphan cleanup: merge policy refs + ingress refs, delete stale resources
    let mut new_refs = collect_resource_refs(&policies);
    if let Some(ref ingress_resources) = ingress {
        new_refs.extend(collect_ingress_refs(ingress_resources));
    }
    let old_refs = read_applied_resources(member);
    delete_orphaned_resources(&ctx.client, registry, namespace, &old_refs, &new_refs).await?;

    // When ingress was removed, release this member's Gateway listeners via SSA.
    // Applying empty listeners tells the API server this field manager no longer
    // owns any listener entries, so SSA removes them while preserving other members'.
    let had_ingress_before = old_refs
        .iter()
        .any(|r| r.kind == "HTTPRoute" || r.kind == "GRPCRoute" || r.kind == "TCPRoute");
    if ingress.is_none() && had_ingress_before {
        release_gateway_listeners(&ctx.client, registry, namespace, &ingress_params).await?;
    }

    let total = policies.total_count()
        + ingress.as_ref().map_or(0, |i| i.total_count())
        + waypoint.as_ref().map_or(0, |w| w.total_count());
    info!(resources = total, "applied mesh member resources");

    Ok((waypoint_ready, new_refs))
}

/// Handle mesh member deletion
pub fn cleanup(member: &LatticeMeshMember, ctx: &MeshMemberContext) {
    let name = member.name_any();
    let namespace = match member.metadata.namespace.as_deref() {
        Some(ns) => ns,
        None => {
            warn!(mesh_member = %name, "LatticeMeshMember missing namespace during cleanup");
            return;
        }
    };

    info!(mesh_member = %name, namespace = %namespace, "removing mesh member from graph");
    ctx.graph.delete_service(namespace, &name);
}

// =============================================================================
// Namespace ambient enrollment
// =============================================================================

/// Ensure namespace has `istio.io/dataplane-mode: ambient` label
async fn ensure_namespace_ambient(client: &Client, namespace: &str) -> Result<(), ReconcileError> {
    let labels = std::collections::BTreeMap::from([(
        mesh::DATAPLANE_MODE_LABEL.to_string(),
        mesh::DATAPLANE_MODE_AMBIENT.to_string(),
    )]);
    lattice_common::kube_utils::ensure_namespace(client, namespace, Some(&labels), FIELD_MANAGER)
        .await
        .map_err(|e| ReconcileError::kube("ensure namespace ambient", e))?;

    debug!(namespace = %namespace, "ensured namespace ambient mode");
    Ok(())
}

// =============================================================================
// Waypoint readiness check
// =============================================================================

/// Check if the namespace waypoint Gateway is programmed.
///
/// ServiceEntries with `istio.io/use-waypoint` will fail to bind if applied
/// before the waypoint is fully programmed. Returns `true` only when the
/// Gateway has `Programmed: True` in its status conditions.
async fn is_waypoint_programmed(client: &Client, registry: &CrdRegistry, namespace: &str) -> bool {
    let ar = match registry.resolve(CrdKind::Gateway).await {
        Ok(Some(ar)) => ar,
        Ok(None) => return false,
        Err(e) => {
            warn!(error = %e, "CRD discovery failed checking waypoint status");
            return false;
        }
    };

    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
    let waypoint = mesh::waypoint_name(namespace);

    let gw = match api.get(&waypoint).await {
        Ok(gw) => gw,
        Err(_) => return false,
    };

    // Check status.conditions for Programmed: True
    gw.data
        .get("status")
        .and_then(|s| s.get("conditions"))
        .and_then(|c| c.as_array())
        .map(|conditions| {
            conditions.iter().any(|c| {
                c.get("type").and_then(|t| t.as_str()) == Some("Programmed")
                    && c.get("status").and_then(|s| s.as_str()) == Some("True")
            })
        })
        .unwrap_or(false)
}

// =============================================================================
// SSA apply helpers
// =============================================================================

/// Apply a single resource via server-side apply, resolving the CRD from the registry.
async fn apply_resource(
    client: &Client,
    registry: &CrdRegistry,
    namespace: &str,
    params: &PatchParams,
    resource: &impl serde::Serialize,
    name: &str,
    crd_kind: CrdKind,
) -> Result<(), ReconcileError> {
    let kind = crd_kind.kind_str();
    let ar = registry.resolve(crd_kind).await?.ok_or_else(|| {
        ReconcileError::Internal(format!(
            "{kind} CRD not installed but resource '{name}' needs applying"
        ))
    })?;

    let mut json = serde_json::to_value(resource)
        .map_err(|e| ReconcileError::Internal(format!("serialize {kind}: {e}")))?;

    // Override apiVersion from ApiResource to match what the server serves
    if let Some(obj) = json.as_object_mut() {
        obj.insert(
            "apiVersion".to_string(),
            serde_json::Value::String(ar.api_version.clone()),
        );
    }

    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
    api.patch(name, params, &Patch::Apply(&json))
        .await
        .map_err(|e| ReconcileError::kube(format!("apply {kind} {name}"), e))?;

    debug!(name = %name, kind = %kind, "applied resource");
    Ok(())
}

/// Serialize a batch of CRD-backed resources into (name, kind, json, ApiResource) tuples.
///
/// Resolves the CRD from the registry on demand. Returns immediately if the resource
/// list is empty (no registry call, no warnings). Returns an error if resources need
/// applying but the CRD is not installed.
async fn serialize_crd_batch<T: serde::Serialize>(
    items: &mut Vec<(
        String,
        &'static str,
        serde_json::Value,
        kube::discovery::ApiResource,
    )>,
    resources: &[T],
    registry: &CrdRegistry,
    crd_kind: CrdKind,
    name_fn: impl Fn(&T) -> &str,
) -> Result<(), ReconcileError> {
    if resources.is_empty() {
        return Ok(());
    }

    let kind = crd_kind.kind_str();
    let ar = registry.resolve(crd_kind).await?.ok_or_else(|| {
        ReconcileError::Internal(format!(
            "{kind} CRD not installed but {} resources need applying",
            resources.len()
        ))
    })?;

    for resource in resources {
        let mut json = serde_json::to_value(resource)
            .map_err(|e| ReconcileError::Internal(format!("serialize {kind}: {e}")))?;
        if let Some(obj) = json.as_object_mut() {
            obj.insert(
                "apiVersion".to_string(),
                serde_json::Value::String(ar.api_version.clone()),
            );
        }
        items.push((name_fn(resource).to_string(), kind, json, ar.clone()));
    }

    Ok(())
}

/// Apply all compiled policies in parallel via server-side apply.
///
/// Resolves CRDs from the registry on demand — only CRDs with non-empty resource
/// lists are looked up. Pre-serializes all resources to JSON, then applies them
/// concurrently using `try_join_all`.
async fn apply_policies(
    client: &Client,
    registry: &CrdRegistry,
    namespace: &str,
    params: &PatchParams,
    policies: &crate::policy::GeneratedPolicies,
) -> Result<(), ReconcileError> {
    use futures::future::try_join_all;

    let mut items: Vec<(
        String,
        &'static str,
        serde_json::Value,
        kube::discovery::ApiResource,
    )> = Vec::new();

    serialize_crd_batch(
        &mut items,
        &policies.authorization_policies,
        registry,
        CrdKind::AuthorizationPolicy,
        |ap| &ap.metadata.name,
    )
    .await?;
    serialize_crd_batch(
        &mut items,
        &policies.cilium_policies,
        registry,
        CrdKind::CiliumNetworkPolicy,
        |cnp| &cnp.metadata.name,
    )
    .await?;
    serialize_crd_batch(
        &mut items,
        &policies.service_entries,
        registry,
        CrdKind::ServiceEntry,
        |se| &se.metadata.name,
    )
    .await?;
    serialize_crd_batch(
        &mut items,
        &policies.peer_authentications,
        registry,
        CrdKind::PeerAuthentication,
        |pa| &pa.metadata.name,
    )
    .await?;

    if items.is_empty() {
        return Ok(());
    }

    try_join_all(items.into_iter().map(|(name, kind, json, ar)| {
        let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
        let params = params.clone();
        async move {
            api.patch(&name, &params, &Patch::Apply(&json))
                .await
                .map_err(|e| ReconcileError::kube(format!("apply {kind} {name}"), e))?;
            debug!(name = %name, kind = kind, "applied resource");
            Ok::<(), ReconcileError>(())
        }
    }))
    .await?;

    Ok(())
}

/// Apply compiled ingress resources in parallel via server-side apply.
///
/// The Gateway is applied first (creates the parent reference for routes), then
/// all remaining resources (CNP, auth policy, routes, certs) are applied concurrently.
async fn apply_ingress(
    client: &Client,
    registry: &CrdRegistry,
    namespace: &str,
    params: &PatchParams,
    ingress: &crate::ingress::GeneratedIngress,
) -> Result<(), ReconcileError> {
    use futures::future::try_join_all;

    // Gateway must be applied first (routes reference it as a parentRef)
    if let Some(ref gw) = ingress.gateway {
        apply_resource(
            client,
            registry,
            namespace,
            params,
            gw,
            &gw.metadata.name,
            CrdKind::Gateway,
        )
        .await?;
    }

    // Apply remaining resources concurrently
    let mut items: Vec<(
        String,
        &'static str,
        serde_json::Value,
        kube::discovery::ApiResource,
    )> = Vec::new();

    serialize_crd_batch(
        &mut items,
        &ingress
            .gateway_policy
            .as_ref()
            .into_iter()
            .collect::<Vec<_>>(),
        registry,
        CrdKind::CiliumNetworkPolicy,
        |cnp| &cnp.metadata.name,
    )
    .await?;
    serialize_crd_batch(
        &mut items,
        &ingress
            .gateway_auth_policy
            .as_ref()
            .into_iter()
            .collect::<Vec<_>>(),
        registry,
        CrdKind::AuthorizationPolicy,
        |ap| &ap.metadata.name,
    )
    .await?;
    serialize_crd_batch(
        &mut items,
        &ingress.http_routes,
        registry,
        CrdKind::HttpRoute,
        |r| &r.metadata.name,
    )
    .await?;
    serialize_crd_batch(
        &mut items,
        &ingress.grpc_routes,
        registry,
        CrdKind::GrpcRoute,
        |r| &r.metadata.name,
    )
    .await?;
    serialize_crd_batch(
        &mut items,
        &ingress.tcp_routes,
        registry,
        CrdKind::TcpRoute,
        |r| &r.metadata.name,
    )
    .await?;
    serialize_crd_batch(
        &mut items,
        &ingress.certificates,
        registry,
        CrdKind::Certificate,
        |c| &c.metadata.name,
    )
    .await?;

    if items.is_empty() {
        return Ok(());
    }

    try_join_all(items.into_iter().map(|(name, kind, json, ar)| {
        let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
        let params = params.clone();
        async move {
            api.patch(&name, &params, &Patch::Apply(&json))
                .await
                .map_err(|e| ReconcileError::kube(format!("apply {kind} {name}"), e))?;
            debug!(name = %name, kind = kind, "applied resource");
            Ok::<(), ReconcileError>(())
        }
    }))
    .await?;

    Ok(())
}

/// Release this field manager's Gateway listeners via SSA.
///
/// When a service removes its ingress, its per-member field manager stops applying
/// listeners to the shared Gateway. SSA won't auto-remove the old listeners — they
/// persist until the field manager explicitly releases them. Applying an empty
/// `spec.listeners: []` tells the API server this field manager no longer owns any
/// listeners, so SSA removes them while preserving other members' listeners.
async fn release_gateway_listeners(
    client: &Client,
    registry: &CrdRegistry,
    namespace: &str,
    params: &PatchParams,
) -> Result<(), ReconcileError> {
    let Some(ar) = registry.resolve(CrdKind::Gateway).await? else {
        return Ok(());
    };
    let gateway_name = mesh::ingress_gateway_name(namespace);
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

    // Only release if the Gateway exists (avoid creating an empty one)
    if api.get(&gateway_name).await.is_err() {
        return Ok(());
    }

    let empty_listeners = serde_json::json!({
        "apiVersion": ar.api_version.clone(),
        "kind": ar.kind.clone(),
        "metadata": { "name": gateway_name, "namespace": namespace },
        "spec": {
            "gatewayClassName": mesh::INGRESS_GATEWAY_CLASS,
            "listeners": []
        }
    });

    api.patch(&gateway_name, params, &Patch::Apply(empty_listeners))
        .await
        .map_err(|e| ReconcileError::kube("release gateway listeners", e))?;

    info!("released gateway listeners for removed ingress");
    Ok(())
}

/// Apply compiled waypoint resources
async fn apply_waypoint(
    client: &Client,
    registry: &CrdRegistry,
    namespace: &str,
    params: &PatchParams,
    waypoint: &crate::ingress::GeneratedWaypoint,
) -> Result<(), ReconcileError> {
    if let Some(ref gw) = waypoint.gateway {
        apply_resource(
            client,
            registry,
            namespace,
            params,
            gw,
            &gw.metadata.name,
            CrdKind::Gateway,
        )
        .await?;
    }

    if let Some(ref policy) = waypoint.allow_to_waypoint_policy {
        apply_resource(
            client,
            registry,
            namespace,
            params,
            policy,
            &policy.metadata.name,
            CrdKind::AuthorizationPolicy,
        )
        .await?;
    }

    Ok(())
}

// =============================================================================
// Status helpers
// =============================================================================

/// Skip reconciliation when the spec (generation) AND graph topology (edge hash) are unchanged.
///
/// This prevents reconcile storms from status patches (which bump resourceVersion
/// but not generation) while still reacting to bilateral agreement changes from
/// other members via the graph hash annotation.
fn is_status_current(member: &LatticeMeshMember, current_graph_hash: &str) -> bool {
    let status = match member.status.as_ref() {
        Some(s) if s.phase == MeshMemberPhase::Ready => s,
        _ => return false,
    };

    let generation_matches = matches!(
        (status.observed_generation, member.metadata.generation),
        (Some(observed), Some(current)) if observed == current
    );

    let stored_hash = member
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(GRAPH_HASH_ANNOTATION));

    generation_matches && stored_hash.map(|h| h.as_str()) == Some(current_graph_hash)
}

fn status_progressing(scope: MeshMemberScope, generation: Option<i64>) -> LatticeMeshMemberStatus {
    LatticeMeshMemberStatus {
        phase: MeshMemberPhase::Progressing,
        scope: Some(scope),
        message: Some("Waiting for waypoint to program ServiceEntries".to_string()),
        observed_generation: generation,
        conditions: vec![Condition::new(
            "Ready",
            ConditionStatus::False,
            "WaypointPending",
            "Waiting for waypoint to program ServiceEntries",
        )],
        ..Default::default()
    }
}

fn status_ready(scope: MeshMemberScope, generation: Option<i64>) -> LatticeMeshMemberStatus {
    LatticeMeshMemberStatus {
        phase: MeshMemberPhase::Ready,
        scope: Some(scope),
        message: Some("Policies applied successfully".to_string()),
        observed_generation: generation,
        conditions: vec![Condition::new(
            "Ready",
            ConditionStatus::True,
            "PoliciesApplied",
            "Policies applied successfully",
        )],
        ..Default::default()
    }
}

fn status_failed(message: &str, generation: Option<i64>) -> LatticeMeshMemberStatus {
    LatticeMeshMemberStatus {
        phase: MeshMemberPhase::Failed,
        scope: None,
        message: Some(message.to_string()),
        observed_generation: generation,
        conditions: vec![Condition::new(
            "Ready",
            ConditionStatus::False,
            "ReconcileFailed",
            message,
        )],
        ..Default::default()
    }
}

/// Patch graph hash annotation and status, skipping no-op updates.
///
/// Compares the desired state against the member's current state and only
/// issues API calls when something actually changed. This prevents
/// status-update → watch-event → reconcile tight loops on persistent failures.
///
/// The CRD has a status subresource, so annotation and status must be patched
/// separately. Order matters for crash consistency:
///   - Annotation first (optimization — controls `is_status_current` skip gate)
///   - Status last (user-visible commit point — phase, scope, message, applied resources)
///
/// If we crash between the two, the next reconcile redoes the work (idempotent).
async fn patch_status_with_hash(
    client: &Client,
    member: &LatticeMeshMember,
    new_status: LatticeMeshMemberStatus,
    graph_hash: &str,
) -> Result<(), ReconcileError> {
    let name = member.name_any();
    let namespace = member.metadata.namespace.as_deref().unwrap_or_default();

    let current_hash = member
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(GRAPH_HASH_ANNOTATION))
        .map(|h| h.as_str())
        .unwrap_or_default();

    let status_unchanged = status_check::is_status_unchanged(
        member.status.as_ref(),
        &new_status.phase,
        new_status.message.as_deref(),
        new_status.observed_generation,
    );

    let applied_resources_changed = member
        .status
        .as_ref()
        .map(|s| s.applied_resources != new_status.applied_resources)
        .unwrap_or(!new_status.applied_resources.is_empty());

    let hash_changed = current_hash != graph_hash;

    if !hash_changed && status_unchanged && !applied_resources_changed {
        debug!("status and graph hash unchanged, skipping patch");
        return Ok(());
    }

    let api: Api<LatticeMeshMember> = Api::namespaced(client.clone(), namespace);
    let params = PatchParams::apply(FIELD_MANAGER);

    // Annotation (graph hash only)
    if hash_changed {
        let annotation_patch = serde_json::json!({
            "metadata": { "annotations": { GRAPH_HASH_ANNOTATION: graph_hash } },
        });
        api.patch(&name, &params, &Patch::Merge(&annotation_patch))
            .await
            .map_err(|e| ReconcileError::kube("patch annotation", e))?;
    }

    // Status (phase, scope, message, applied resources)
    if !status_unchanged || applied_resources_changed {
        let status_patch = serde_json::json!({ "status": new_status });
        api.patch_status(&name, &params, &Patch::Merge(&status_patch))
            .await
            .map_err(|e| ReconcileError::kube("patch status", e))?;
    }

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{MeshMemberPort, MeshMemberTarget};
    use lattice_common::graph::ServiceGraph;
    use std::collections::BTreeMap;

    use crate::policy::tests::make_service_spec;

    fn make_test_member(name: &str) -> LatticeMeshMember {
        LatticeMeshMember::new(
            name,
            lattice_common::crd::LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(BTreeMap::new()),
                ports: vec![MeshMemberPort {
                    port: 8080,
                    service_port: None,
                    name: "http".to_string(),
                    peer_auth: lattice_common::crd::PeerAuth::Strict,
                }],
                allowed_callers: vec![],
                dependencies: vec![],
                egress: vec![],
                allow_peer_traffic: false,
                depends_all: false,
                ingress: None,
                service_account: None,
                ambient: true,
            },
        )
    }

    #[test]
    fn collect_resource_refs_extracts_auth_and_peer_auth() {
        let graph = ServiceGraph::new();
        let ns = "test-ns";

        graph.put_service(ns, "api", &make_service_spec(vec![], vec!["gateway"]));
        graph.put_service(ns, "gateway", &make_service_spec(vec!["api"], vec![]));

        let policies =
            crate::policy::PolicyCompiler::new(&graph, "test-cluster").compile("api", ns);

        let refs = collect_resource_refs(&policies);

        assert!(!refs.is_empty());
        assert!(refs
            .iter()
            .all(|r| r.kind == "AuthorizationPolicy" || r.kind == "PeerAuthentication"));
        assert!(!refs.iter().any(|r| r.kind == "CiliumNetworkPolicy"));
    }

    #[test]
    fn collect_resource_refs_empty_for_empty_policies() {
        let refs = collect_resource_refs(&crate::policy::GeneratedPolicies::default());
        assert!(refs.is_empty());
    }

    #[test]
    fn read_applied_resources_returns_empty_on_missing_status() {
        let member = make_test_member("test");
        assert!(read_applied_resources(&member).is_empty());
    }

    #[test]
    fn read_applied_resources_reads_from_status() {
        let refs = vec![
            AppliedResourceRef {
                kind: "AuthorizationPolicy".into(),
                name: "allow-to-api".into(),
            },
            AppliedResourceRef {
                kind: "PeerAuthentication".into(),
                name: "pa-api".into(),
            },
        ];

        let mut member = make_test_member("test");
        member.status = Some(LatticeMeshMemberStatus {
            applied_resources: refs.clone(),
            ..Default::default()
        });

        let result = read_applied_resources(&member);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&refs[0]));
        assert!(result.contains(&refs[1]));
    }
}
