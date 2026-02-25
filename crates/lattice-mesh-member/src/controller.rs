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

use kube::api::{Api, DeleteParams, DynamicObject, Patch, PatchParams};
use kube::discovery::ApiResource;
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, instrument, warn};

use lattice_cedar::{MeshWildcardRequest, PolicyEngine, WildcardDirection};
use lattice_common::crd::{
    Condition, ConditionStatus, LatticeMeshMember, LatticeMeshMemberStatus, MeshMemberPhase,
    MeshMemberScope, MeshMemberTarget,
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
const APPLIED_RESOURCES_ANNOTATION: &str = "lattice.dev/applied-resources";

/// Reference to an applied resource, tracked for orphan cleanup.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ResourceRef {
    pub kind: String,
    pub name: String,
}

// =============================================================================
// Orphan tracking helpers
// =============================================================================

/// Extract resource refs from compiled policies (AuthorizationPolicy + PeerAuthentication).
///
/// Cilium policies are excluded (always 1 per service, never orphaned).
/// ServiceEntries are excluded (shared per-namespace-per-FQDN, can't safely delete
/// without checking other MeshMembers; orphaned SEs have no security impact since
/// the `allow-fqdn-*` AuthorizationPolicy IS tracked).
pub fn collect_resource_refs(policies: &crate::policy::GeneratedPolicies) -> HashSet<ResourceRef> {
    let mut refs = HashSet::new();
    for ap in &policies.authorization_policies {
        refs.insert(ResourceRef {
            kind: "AuthorizationPolicy".to_string(),
            name: ap.metadata.name.clone(),
        });
    }
    for pa in &policies.peer_authentications {
        refs.insert(ResourceRef {
            kind: "PeerAuthentication".to_string(),
            name: pa.metadata.name.clone(),
        });
    }
    refs
}

/// Read previously applied resource refs from the MeshMember annotation.
/// Returns an empty set if the annotation is missing or invalid (graceful upgrade).
pub fn read_applied_resources(member: &LatticeMeshMember) -> HashSet<ResourceRef> {
    member
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(APPLIED_RESOURCES_ANNOTATION))
        .and_then(|json| serde_json::from_str(json).ok())
        .unwrap_or_default()
}

/// Delete a single resource via the dynamic API, ignoring 404 (already gone).
async fn delete_if_discovered(
    client: &Client,
    namespace: &str,
    crd: Option<&ApiResource>,
    name: &str,
    kind: &str,
) -> Result<(), ReconcileError> {
    let Some(ar) = crd else {
        debug!(name = %name, kind = %kind, "CRD not discovered, skipping orphan delete");
        return Ok(());
    };

    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, ar);
    match api.delete(name, &DeleteParams::default()).await {
        Ok(_) => {
            info!(name = %name, kind = %kind, "deleted orphaned resource");
            Ok(())
        }
        Err(kube::Error::Api(ref resp)) if resp.code == 404 => {
            debug!(name = %name, kind = %kind, "orphaned resource already gone");
            Ok(())
        }
        Err(e) => Err(ReconcileError::kube(
            format!("delete orphaned {kind} {name}"),
            e,
        )),
    }
}

/// Delete resources that were previously applied but are no longer in the compiled set.
async fn delete_orphaned_resources(
    client: &Client,
    crds: &ResolvedCrds,
    namespace: &str,
    old_refs: &HashSet<ResourceRef>,
    new_refs: &HashSet<ResourceRef>,
) -> Result<(), ReconcileError> {
    let orphans: Vec<&ResourceRef> = old_refs.difference(new_refs).collect();
    if orphans.is_empty() {
        return Ok(());
    }

    info!(count = orphans.len(), "deleting orphaned mesh resources");
    for orphan in orphans {
        let crd = match orphan.kind.as_str() {
            "AuthorizationPolicy" => crds.authorization_policy.as_ref(),
            "PeerAuthentication" => crds.peer_authentication.as_ref(),
            _ => {
                warn!(kind = %orphan.kind, name = %orphan.name, "unknown orphan kind, skipping");
                continue;
            }
        };
        delete_if_discovered(client, namespace, crd, &orphan.name, &orphan.kind).await?;
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
            None,
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
            None,
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(30)));
    }

    // Compute edge hash AFTER graph update to capture current bilateral agreements
    let inbound_edges = ctx.graph.get_active_inbound_edges(namespace, &name);
    let outbound_edges = ctx.graph.get_active_outbound_edges(namespace, &name);
    let graph_hash = compute_edge_hash(&inbound_edges, &outbound_edges);

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
            patch_status_with_hash(
                &ctx.client,
                &member,
                status_ready(scope, member.metadata.generation),
                &graph_hash,
                Some(&new_refs),
            )
            .await?;
            Ok(Action::requeue(Duration::from_secs(60)))
        }
        Ok((false, new_refs)) => {
            // ServiceEntries deferred (waypoint not programmed yet) —
            // report Progressing so LatticeService doesn't mark itself Ready.
            patch_status_with_hash(
                &ctx.client,
                &member,
                status_progressing(scope, member.metadata.generation),
                "",
                Some(&new_refs),
            )
            .await?;
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
                None,
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
) -> Result<(bool, HashSet<ResourceRef>), ReconcileError> {
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

    let crds = ResolvedCrds::resolve(&ctx.registry).await;
    let params = PatchParams::apply(FIELD_MANAGER).force();

    if let Some(ref waypoint_resources) = waypoint {
        apply_waypoint(&ctx.client, &crds, namespace, &params, waypoint_resources).await?;
    }

    let waypoint_ready = if !policies.service_entries.is_empty() {
        is_waypoint_programmed(&ctx.client, &crds, namespace).await
    } else {
        true
    };

    if waypoint_ready {
        apply_policies(&ctx.client, &crds, namespace, &params, &policies).await?;
    } else {
        info!("waypoint not yet present, deferring ServiceEntry creation");
        let deferred = policies.without_service_entries();
        apply_policies(&ctx.client, &crds, namespace, &params, &deferred).await?;
    }

    // Orphan cleanup: delete resources that were previously applied but are no longer emitted
    let new_refs = collect_resource_refs(&policies);
    let old_refs = read_applied_resources(member);
    delete_orphaned_resources(&ctx.client, &crds, namespace, &old_refs, &new_refs).await?;

    if let Some(ref ingress_resources) = ingress {
        let gateway_field_manager = format!("{}/{}", FIELD_MANAGER, name);
        let gateway_params = PatchParams::apply(&gateway_field_manager).force();
        apply_ingress(
            &ctx.client,
            &crds,
            namespace,
            &params,
            &gateway_params,
            ingress_resources,
        )
        .await?;
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

/// Error policy — requeue after 30s for all errors
pub fn error_policy(
    member: Arc<LatticeMeshMember>,
    error: &ReconcileError,
    _ctx: Arc<MeshMemberContext>,
) -> Action {
    error!(
        ?error,
        mesh_member = %member.name_any(),
        "mesh member reconciliation failed"
    );
    Action::requeue(Duration::from_secs(30))
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
    lattice_common::kube_utils::ensure_namespace_with_labels(
        client,
        namespace,
        &labels,
        FIELD_MANAGER,
    )
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
async fn is_waypoint_programmed(client: &Client, crds: &ResolvedCrds, namespace: &str) -> bool {
    let Some(ref ar) = crds.gateway else {
        return false;
    };

    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, ar);
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
// Resolved CRDs — resolved once per reconcile, shared across apply functions
// =============================================================================

/// All CRD ApiResources needed by the mesh-member apply functions.
///
/// Resolved once in the reconcile loop and passed by reference to avoid
/// duplicate registry lookups across apply_policies/apply_ingress/apply_waypoint.
struct ResolvedCrds {
    authorization_policy: Option<ApiResource>,
    cilium_network_policy: Option<ApiResource>,
    service_entry: Option<ApiResource>,
    peer_authentication: Option<ApiResource>,
    gateway: Option<ApiResource>,
    http_route: Option<ApiResource>,
    grpc_route: Option<ApiResource>,
    tcp_route: Option<ApiResource>,
    certificate: Option<ApiResource>,
}

impl ResolvedCrds {
    async fn resolve(registry: &CrdRegistry) -> Self {
        Self {
            authorization_policy: registry.resolve(CrdKind::AuthorizationPolicy).await,
            cilium_network_policy: registry.resolve(CrdKind::CiliumNetworkPolicy).await,
            service_entry: registry.resolve(CrdKind::ServiceEntry).await,
            peer_authentication: registry.resolve(CrdKind::PeerAuthentication).await,
            gateway: registry.resolve(CrdKind::Gateway).await,
            http_route: registry.resolve(CrdKind::HttpRoute).await,
            grpc_route: registry.resolve(CrdKind::GrpcRoute).await,
            tcp_route: registry.resolve(CrdKind::TcpRoute).await,
            certificate: registry.resolve(CrdKind::Certificate).await,
        }
    }
}

// =============================================================================
// SSA apply helpers
// =============================================================================

/// Apply a single resource via server-side apply, erroring if the CRD is not discovered.
async fn apply_if_discovered(
    client: &Client,
    namespace: &str,
    params: &PatchParams,
    resource: &impl serde::Serialize,
    crd: Option<&ApiResource>,
    name: &str,
    kind: &str,
) -> Result<(), ReconcileError> {
    let ar = crd.ok_or_else(|| {
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

    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, ar);
    api.patch(name, params, &Patch::Apply(&json))
        .await
        .map_err(|e| ReconcileError::kube(format!("apply {kind} {name}"), e))?;

    debug!(name = %name, kind = %kind, "applied resource");
    Ok(())
}

/// Apply all compiled policies in parallel via server-side apply.
///
/// Pre-serializes all resources to JSON, then applies them concurrently
/// using `try_join_all`. Returns an error if any CRD type has compiled
/// resources but its CRD is not discovered on the cluster.
async fn apply_policies(
    client: &Client,
    crds: &ResolvedCrds,
    namespace: &str,
    params: &PatchParams,
    policies: &crate::policy::GeneratedPolicies,
) -> Result<(), ReconcileError> {
    use futures::future::try_join_all;

    let mut items: Vec<(String, &'static str, serde_json::Value, ApiResource)> = Vec::new();

    serialize_crd_batch(
        &mut items,
        &policies.authorization_policies,
        crds.authorization_policy.as_ref(),
        "AuthorizationPolicy",
        |ap| &ap.metadata.name,
    )?;
    serialize_crd_batch(
        &mut items,
        &policies.cilium_policies,
        crds.cilium_network_policy.as_ref(),
        "CiliumNetworkPolicy",
        |cnp| &cnp.metadata.name,
    )?;
    serialize_crd_batch(
        &mut items,
        &policies.service_entries,
        crds.service_entry.as_ref(),
        "ServiceEntry",
        |se| &se.metadata.name,
    )?;
    serialize_crd_batch(
        &mut items,
        &policies.peer_authentications,
        crds.peer_authentication.as_ref(),
        "PeerAuthentication",
        |pa| &pa.metadata.name,
    )?;

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

/// Serialize a batch of CRD-backed resources into (name, kind, json, ApiResource) tuples.
///
/// Returns an error if the CRD is not discovered but resources need applying.
/// Resources are serialized eagerly so the actual API calls can run fully in parallel.
fn serialize_crd_batch<T: serde::Serialize>(
    items: &mut Vec<(String, &'static str, serde_json::Value, ApiResource)>,
    resources: &[T],
    crd: Option<&ApiResource>,
    kind: &'static str,
    name_fn: impl Fn(&T) -> &str,
) -> Result<(), ReconcileError> {
    let Some(ar) = crd else {
        if !resources.is_empty() {
            return Err(ReconcileError::Internal(format!(
                "{kind} CRD not installed but {} resources need applying",
                resources.len()
            )));
        }
        return Ok(());
    };

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

/// Apply compiled ingress resources
///
/// Uses `gateway_params` (per-member field manager) for the shared Gateway
/// and `params` (shared field manager) for routes and certificates.
async fn apply_ingress(
    client: &Client,
    crds: &ResolvedCrds,
    namespace: &str,
    params: &PatchParams,
    gateway_params: &PatchParams,
    ingress: &crate::ingress::GeneratedIngress,
) -> Result<(), ReconcileError> {
    if let Some(ref gw) = ingress.gateway {
        apply_if_discovered(
            client,
            namespace,
            gateway_params,
            gw,
            crds.gateway.as_ref(),
            &gw.metadata.name,
            "Gateway",
        )
        .await?;
    }

    for route in &ingress.http_routes {
        apply_if_discovered(
            client,
            namespace,
            params,
            route,
            crds.http_route.as_ref(),
            &route.metadata.name,
            "HTTPRoute",
        )
        .await?;
    }

    for route in &ingress.grpc_routes {
        apply_if_discovered(
            client,
            namespace,
            params,
            route,
            crds.grpc_route.as_ref(),
            &route.metadata.name,
            "GRPCRoute",
        )
        .await?;
    }

    for route in &ingress.tcp_routes {
        apply_if_discovered(
            client,
            namespace,
            params,
            route,
            crds.tcp_route.as_ref(),
            &route.metadata.name,
            "TCPRoute",
        )
        .await?;
    }

    for cert in &ingress.certificates {
        apply_if_discovered(
            client,
            namespace,
            params,
            cert,
            crds.certificate.as_ref(),
            &cert.metadata.name,
            "Certificate",
        )
        .await?;
    }

    Ok(())
}

/// Apply compiled waypoint resources
async fn apply_waypoint(
    client: &Client,
    crds: &ResolvedCrds,
    namespace: &str,
    params: &PatchParams,
    waypoint: &crate::ingress::GeneratedWaypoint,
) -> Result<(), ReconcileError> {
    if let Some(ref gw) = waypoint.gateway {
        apply_if_discovered(
            client,
            namespace,
            params,
            gw,
            crds.gateway.as_ref(),
            &gw.metadata.name,
            "Gateway",
        )
        .await?;
    }

    if let Some(ref policy) = waypoint.allow_to_waypoint_policy {
        apply_if_discovered(
            client,
            namespace,
            params,
            policy,
            crds.authorization_policy.as_ref(),
            &policy.metadata.name,
            "AuthorizationPolicy",
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
    }
}

/// Patch graph hash annotation, applied-resources annotation, and status,
/// skipping no-op updates.
///
/// Compares the desired state against the member's current state and only
/// issues API calls when something actually changed. This prevents
/// status-update → watch-event → reconcile tight loops on persistent failures.
///
/// The CRD has a status subresource, so annotation and status must be patched
/// separately. Order matters for crash consistency:
///   1. Annotation first (optimization — controls `is_status_current` skip gate)
///   2. Status last (user-visible commit point — phase, scope, message)
///
/// If we crash between the two, the next reconcile redoes the work (idempotent).
async fn patch_status_with_hash(
    client: &Client,
    member: &LatticeMeshMember,
    new_status: LatticeMeshMemberStatus,
    graph_hash: &str,
    applied_resources: Option<&HashSet<ResourceRef>>,
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

    // Check if applied-resources annotation needs updating
    let needs_resource_annotation_update = applied_resources.is_some();

    if current_hash == graph_hash && status_unchanged && !needs_resource_annotation_update {
        debug!("status and graph hash unchanged, skipping patch");
        return Ok(());
    }

    let api: Api<LatticeMeshMember> = Api::namespaced(client.clone(), namespace);
    let params = PatchParams::apply(FIELD_MANAGER);

    // 1. Annotations (graph hash + applied resources)
    let hash_changed = current_hash != graph_hash;
    if hash_changed || needs_resource_annotation_update {
        let mut annotations = serde_json::Map::new();
        if hash_changed {
            annotations.insert(
                GRAPH_HASH_ANNOTATION.to_string(),
                serde_json::Value::String(graph_hash.to_string()),
            );
        }
        if let Some(refs) = applied_resources {
            let json = serde_json::to_string(refs).unwrap_or_else(|_| "[]".to_string());
            annotations.insert(
                APPLIED_RESOURCES_ANNOTATION.to_string(),
                serde_json::Value::String(json),
            );
        }
        let annotation_patch = serde_json::json!({
            "metadata": { "annotations": annotations },
        });
        api.patch(&name, &params, &Patch::Merge(&annotation_patch))
            .await
            .map_err(|e| ReconcileError::kube("patch annotation", e))?;
    }

    // 2. Status (skip if unchanged)
    if !status_unchanged {
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
    use lattice_common::crd::{
        ContainerSpec, DependencyDirection, LatticeServiceSpec, MeshMemberPort, MeshMemberTarget,
        PortSpec, ResourceSpec, ServicePortsSpec, WorkloadSpec,
    };
    use lattice_common::graph::ServiceGraph;
    use std::collections::BTreeMap;

    fn make_test_member(name: &str) -> LatticeMeshMember {
        LatticeMeshMember::new(
            name,
            lattice_common::crd::LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(BTreeMap::new()),
                ports: vec![MeshMemberPort {
                    port: 8080,
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
            },
        )
    }

    fn make_service_spec(deps: Vec<&str>, callers: Vec<&str>) -> LatticeServiceSpec {
        LatticeServiceSpec {
            workload: WorkloadSpec {
                containers: BTreeMap::from([(
                    "main".to_string(),
                    ContainerSpec {
                        image: "test:latest".to_string(),
                        ..Default::default()
                    },
                )]),
                resources: deps
                    .into_iter()
                    .map(|d| {
                        (
                            d.to_string(),
                            ResourceSpec {
                                direction: DependencyDirection::Outbound,
                                ..Default::default()
                            },
                        )
                    })
                    .chain(callers.into_iter().map(|c| {
                        (
                            c.to_string(),
                            ResourceSpec {
                                direction: DependencyDirection::Inbound,
                                ..Default::default()
                            },
                        )
                    }))
                    .collect(),
                service: Some(ServicePortsSpec {
                    ports: BTreeMap::from([(
                        "http".to_string(),
                        PortSpec {
                            port: 8080,
                            target_port: None,
                            protocol: None,
                        },
                    )]),
                }),
            },
            ..Default::default()
        }
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
    fn read_applied_resources_returns_empty_on_missing_annotation() {
        let member = make_test_member("test");
        assert!(read_applied_resources(&member).is_empty());
    }

    #[test]
    fn read_applied_resources_returns_empty_on_invalid_json() {
        let mut member = make_test_member("test");
        member.metadata.annotations = Some(BTreeMap::from([(
            APPLIED_RESOURCES_ANNOTATION.to_string(),
            "not-valid-json".to_string(),
        )]));
        assert!(read_applied_resources(&member).is_empty());
    }

    #[test]
    fn read_applied_resources_deserializes_valid_json() {
        let refs: HashSet<ResourceRef> = [
            ResourceRef {
                kind: "AuthorizationPolicy".into(),
                name: "allow-to-api".into(),
            },
            ResourceRef {
                kind: "PeerAuthentication".into(),
                name: "pa-api".into(),
            },
        ]
        .into_iter()
        .collect();

        let json = serde_json::to_string(&refs).unwrap();
        let mut member = make_test_member("test");
        member.metadata.annotations = Some(BTreeMap::from([(
            APPLIED_RESOURCES_ANNOTATION.to_string(),
            json,
        )]));

        let result = read_applied_resources(&member);
        assert_eq!(result, refs);
    }

    #[test]
    fn resource_ref_roundtrip_serialization() {
        let original = ResourceRef {
            kind: "AuthorizationPolicy".to_string(),
            name: "allow-to-api".to_string(),
        };
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: ResourceRef = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }
}
