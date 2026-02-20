//! MeshMember controller — watches `LatticeMeshMember` CRDs and applies mesh policies
//!
//! Generates and applies:
//! - CiliumNetworkPolicy (L4 eBPF)
//! - AuthorizationPolicy (L7 Istio)
//! - PeerAuthentication (per-port mTLS mode)
//! - ServiceEntry (external service registration)
//! - Gateway + Routes (ingress, if configured)
//! - Waypoint Gateway + AuthorizationPolicy (if external deps exist)

use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, DynamicObject, Patch, PatchParams};
use kube::discovery::ApiResource;
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{debug, error, info, instrument, warn};

use lattice_cedar::{MeshWildcardRequest, PolicyEngine, WildcardDirection};
use lattice_common::crd::{
    Condition, ConditionStatus, LatticeMeshMember, LatticeMeshMemberStatus, MeshMemberPhase,
    MeshMemberScope, MeshMemberTarget,
};
use lattice_common::graph::{ActiveEdge, ServiceGraph};
use lattice_common::kube_utils::{find_discovered_resource, HasApiResource};
use lattice_common::mesh;
use lattice_common::ReconcileError;

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
    pub crds: Arc<MeshMemberDiscoveredCrds>,
    pub cedar: Option<Arc<PolicyEngine>>,
}

/// Discovered CRD API versions for third-party resources applied by this controller.
///
/// Populated at startup via API discovery. Missing CRDs result in `None`
/// and resources of that type are skipped with a warning.
pub struct MeshMemberDiscoveredCrds {
    pub cilium_network_policy: Option<ApiResource>,
    pub authorization_policy: Option<ApiResource>,
    pub service_entry: Option<ApiResource>,
    pub peer_authentication: Option<ApiResource>,
    pub gateway: Option<ApiResource>,
    pub http_route: Option<ApiResource>,
    pub grpc_route: Option<ApiResource>,
    pub tcp_route: Option<ApiResource>,
    pub certificate: Option<ApiResource>,
}

impl MeshMemberDiscoveredCrds {
    /// Discover installed CRD versions from the API server.
    pub async fn discover(client: &Client) -> Self {
        use kube::discovery::Discovery;

        let discovery = match Discovery::new(client.clone()).run().await {
            Ok(d) => d,
            Err(e) => {
                warn!(error = %e, "API discovery failed, falling back to hardcoded CRD versions");
                return Self::hardcoded_defaults();
            }
        };

        Self {
            cilium_network_policy: find_discovered_resource(
                &discovery,
                "cilium.io",
                "CiliumNetworkPolicy",
            ),
            authorization_policy: find_discovered_resource(
                &discovery,
                "security.istio.io",
                "AuthorizationPolicy",
            ),
            service_entry: find_discovered_resource(
                &discovery,
                "networking.istio.io",
                "ServiceEntry",
            ),
            peer_authentication: find_discovered_resource(
                &discovery,
                "security.istio.io",
                "PeerAuthentication",
            ),
            gateway: find_discovered_resource(&discovery, "gateway.networking.k8s.io", "Gateway"),
            http_route: find_discovered_resource(
                &discovery,
                "gateway.networking.k8s.io",
                "HTTPRoute",
            ),
            grpc_route: find_discovered_resource(
                &discovery,
                "gateway.networking.k8s.io",
                "GRPCRoute",
            ),
            tcp_route: find_discovered_resource(
                &discovery,
                "gateway.networking.k8s.io",
                "TCPRoute",
            ),
            certificate: find_discovered_resource(&discovery, "cert-manager.io", "Certificate"),
        }
    }

    /// Fall back to hardcoded defaults (used when discovery fails, and in tests).
    pub fn hardcoded_defaults() -> Self {
        use lattice_common::kube_utils::build_api_resource;
        use lattice_common::network::gateway_api::Gateway as GwApiGateway;
        use lattice_common::network::gateway_api::{Certificate, GrpcRoute, HttpRoute, TcpRoute};
        use lattice_common::policy::cilium::CiliumNetworkPolicy;
        use lattice_common::policy::istio::{AuthorizationPolicy, PeerAuthentication};
        use lattice_common::policy::service_entry::ServiceEntry;

        Self {
            cilium_network_policy: Some(CiliumNetworkPolicy::api_resource()),
            authorization_policy: Some(AuthorizationPolicy::api_resource()),
            service_entry: Some(ServiceEntry::api_resource()),
            peer_authentication: Some(PeerAuthentication::api_resource()),
            gateway: Some(GwApiGateway::api_resource()),
            http_route: Some(HttpRoute::api_resource()),
            grpc_route: Some(GrpcRoute::api_resource()),
            tcp_route: Some(build_api_resource(TcpRoute::API_VERSION, TcpRoute::KIND)),
            certificate: Some(build_api_resource(
                Certificate::API_VERSION,
                Certificate::KIND,
            )),
        }
    }
}

// =============================================================================
// Field manager
// =============================================================================

const FIELD_MANAGER: &str = "lattice-mesh-member-controller";
const GRAPH_HASH_ANNOTATION: &str = "lattice.dev/graph-hash";

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
        warn!(error = %e, "mesh member validation failed");
        patch_status_with_hash(
            &ctx.client,
            &name,
            namespace,
            status_failed(&e, member.metadata.generation),
            "",
        )
        .await?;
        return Ok(Action::await_change());
    }

    // Update graph (idempotent — crash recovery)
    ctx.graph.put_mesh_member(namespace, &name, &member.spec);

    // Cedar-gate wildcard inbound/outbound
    if let Some(node) = ctx.graph.get_service(namespace, &name) {
        let checks = [
            (node.allows_all, WildcardDirection::Inbound),
            (node.depends_all, WildcardDirection::Outbound),
        ];
        for (active, direction) in checks {
            if !active {
                continue;
            }
            let allowed = match &ctx.cedar {
                Some(cedar) => {
                    let req = MeshWildcardRequest {
                        service_name: name.clone(),
                        namespace: namespace.to_string(),
                        direction,
                    };
                    cedar.authorize_mesh_wildcard(&req).await.is_allowed()
                }
                None => false, // No Cedar engine = no wildcards (default-deny)
            };
            if !allowed {
                let msg = format!(
                    "Cedar policy denied {direction} for {namespace}/{name}; \
                     add a permit policy for Action::\"AllowWildcard\" on Mesh::\"{}\"",
                    direction.resource_id(),
                );
                warn!(%msg);
                patch_status_with_hash(
                    &ctx.client,
                    &name,
                    namespace,
                    status_failed(&msg, member.metadata.generation),
                    "",
                )
                .await?;
                return Ok(Action::requeue(Duration::from_secs(30)));
            }
        }
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

    // Ensure namespace has ambient mode label
    ensure_namespace_ambient(&ctx.client, namespace).await?;

    // Compile policies
    let policies = PolicyCompiler::new(&ctx.graph, &ctx.cluster_name).compile(&name, namespace);

    // Compile ingress (if configured)
    let ingress = member
        .spec
        .ingress
        .as_ref()
        .map(|ingress_spec| {
            IngressCompiler::compile(&name, namespace, ingress_spec, &member.spec.ports)
        })
        .transpose()
        .map_err(|e| ReconcileError::Validation(format!("ingress compilation: {e}")))?;

    // Compile waypoint (if service has external dependencies)
    let has_external_deps = outbound_edges.iter().any(|edge| {
        ctx.graph
            .get_service(&edge.callee_namespace, &edge.callee_name)
            .map(|s| s.type_ == lattice_common::graph::ServiceType::External)
            .unwrap_or(false)
    });
    let waypoint = if has_external_deps {
        Some(WaypointCompiler::compile(namespace))
    } else {
        None
    };

    // If a needed CRD wasn't available at startup (e.g. Istio installed in background),
    // re-run discovery to pick it up.
    let crds = if needs_crd_refresh(&ctx.crds, &policies, ingress.as_ref(), waypoint.as_ref()) {
        info!("re-discovering CRDs (needed CRD was missing at startup)");
        Arc::new(MeshMemberDiscoveredCrds::discover(&ctx.client).await)
    } else {
        ctx.crds.clone()
    };

    // Apply all resources
    let params = PatchParams::apply(FIELD_MANAGER).force();

    apply_policies(&ctx.client, &crds, namespace, &params, &policies).await?;

    if let Some(ref ingress_resources) = ingress {
        // Use a per-member field manager for the Gateway so each member owns
        // only its own listeners. The Gateway CRD uses `name` as the list map
        // key on `spec.listeners`, so SSA merges listeners from different
        // field managers correctly.
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

    if let Some(ref waypoint_resources) = waypoint {
        apply_waypoint(&ctx.client, &crds, namespace, &params, waypoint_resources).await?;
    }

    let total = policies.total_count()
        + ingress.as_ref().map_or(0, |i| i.total_count())
        + waypoint.as_ref().map_or(0, |w| w.total_count());

    info!(resources = total, "applied mesh member resources");

    // Update status and graph hash annotation in a single patch
    let scope = match member.spec.target {
        MeshMemberTarget::Selector(_) => MeshMemberScope::Workload,
        MeshMemberTarget::Namespace(_) => MeshMemberScope::Namespace,
    };
    patch_status_with_hash(
        &ctx.client,
        &name,
        namespace,
        status_ready(scope, member.metadata.generation),
        &graph_hash,
    )
    .await?;

    Ok(Action::requeue(Duration::from_secs(60)))
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
    use k8s_openapi::api::core::v1::Namespace;

    let api: Api<Namespace> = Api::all(client.clone());
    let ns = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": namespace,
            "labels": {
                mesh::DATAPLANE_MODE_LABEL: mesh::DATAPLANE_MODE_AMBIENT
            }
        }
    });

    api.patch(
        namespace,
        &PatchParams::apply(FIELD_MANAGER),
        &Patch::Apply(&ns),
    )
    .await
    .map_err(|e| ReconcileError::Kube(format!("ensure namespace ambient: {e}")))?;

    debug!(namespace = %namespace, "ensured namespace ambient mode");
    Ok(())
}

// =============================================================================
// CRD refresh
// =============================================================================

/// Check if any compiled resources need a CRD that wasn't discovered at startup.
///
/// Returns true when re-discovery should be attempted — e.g. Istio or Cilium CRDs
/// were installed in the background after the operator started.
fn needs_crd_refresh(
    crds: &MeshMemberDiscoveredCrds,
    policies: &crate::policy::GeneratedPolicies,
    ingress: Option<&crate::ingress::GeneratedIngress>,
    waypoint: Option<&crate::ingress::GeneratedWaypoint>,
) -> bool {
    (!policies.authorization_policies.is_empty() && crds.authorization_policy.is_none())
        || (!policies.cilium_policies.is_empty() && crds.cilium_network_policy.is_none())
        || (!policies.service_entries.is_empty() && crds.service_entry.is_none())
        || (!policies.peer_authentications.is_empty() && crds.peer_authentication.is_none())
        || ingress.is_some_and(|i| {
            (i.gateway.is_some() && crds.gateway.is_none())
                || (!i.http_routes.is_empty() && crds.http_route.is_none())
                || (!i.grpc_routes.is_empty() && crds.grpc_route.is_none())
                || (!i.tcp_routes.is_empty() && crds.tcp_route.is_none())
                || (!i.certificates.is_empty() && crds.certificate.is_none())
        })
        || waypoint.is_some_and(|w| {
            (w.gateway.is_some() && crds.gateway.is_none())
                || (w.allow_to_waypoint_policy.is_some() && crds.authorization_policy.is_none())
        })
}

// =============================================================================
// SSA apply helpers
// =============================================================================

/// Apply a single resource via server-side apply using DynamicObject
async fn apply_resource(
    client: &Client,
    namespace: &str,
    params: &PatchParams,
    resource: &impl serde::Serialize,
    ar: &ApiResource,
    name: &str,
    kind: &str,
) -> Result<(), ReconcileError> {
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
        .map_err(|e| ReconcileError::Kube(format!("apply {kind} {name}: {e}")))?;

    debug!(name = %name, kind = %kind, "applied resource");
    Ok(())
}

/// Apply a resource if the CRD is discovered, error if not
async fn apply_if_discovered(
    client: &Client,
    namespace: &str,
    params: &PatchParams,
    resource: &impl serde::Serialize,
    crd: Option<&ApiResource>,
    name: &str,
    kind: &str,
) -> Result<(), ReconcileError> {
    match crd {
        Some(ar) => apply_resource(client, namespace, params, resource, ar, name, kind).await,
        None => Err(ReconcileError::Internal(format!(
            "{kind} CRD not installed but resource '{name}' needs applying"
        ))),
    }
}

/// Apply all compiled policies in parallel via server-side apply.
///
/// Pre-serializes all resources to JSON, then applies them concurrently
/// using `try_join_all`. Returns an error if any CRD type has compiled
/// resources but its CRD is not discovered on the cluster.
async fn apply_policies(
    client: &Client,
    crds: &MeshMemberDiscoveredCrds,
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
                .map_err(|e| ReconcileError::Kube(format!("apply {kind} {name}: {e}")))?;
            debug!(name = %name, kind = kind, "applied resource");
            Ok(())
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
    crds: &MeshMemberDiscoveredCrds,
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
    crds: &MeshMemberDiscoveredCrds,
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

/// Compute a stable hash of the active edges for change detection.
///
/// When bilateral agreements change (e.g., a new caller declares a dependency),
/// the edge hash changes even though this member's spec/generation doesn't.
fn compute_edge_hash(inbound: &[ActiveEdge], outbound: &[ActiveEdge]) -> String {
    use std::fmt::Write;

    // Sort edges so the hash is stable regardless of graph iteration order.
    // The graph's edges_in Vec can be reordered by put_node remove+re-insert
    // cycles, which would otherwise cause spurious hash mismatches and tight
    // reconciliation loops.
    let mut sorted_in: Vec<_> = inbound
        .iter()
        .map(|e| (&e.caller_namespace, &e.caller_name))
        .collect();
    sorted_in.sort();

    let mut sorted_out: Vec<_> = outbound
        .iter()
        .map(|e| (&e.callee_namespace, &e.callee_name))
        .collect();
    sorted_out.sort();

    let mut input = String::new();
    for (ns, name) in &sorted_in {
        let _ = write!(input, "in:{ns}/{name}->");
    }
    for (ns, name) in &sorted_out {
        let _ = write!(input, "out:{ns}/{name}->");
    }
    lattice_common::deterministic_hash(&input)
}

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
            "ValidationFailed",
            message,
        )],
    }
}

/// Patch status and graph hash annotation in a single API call.
///
/// Combining both into one merge patch produces exactly one resourceVersion bump,
/// which means one watch event (caught by `is_status_current`) instead of two.
async fn patch_status_with_hash(
    client: &Client,
    name: &str,
    namespace: &str,
    status: LatticeMeshMemberStatus,
    graph_hash: &str,
) -> Result<(), ReconcileError> {
    let api: Api<LatticeMeshMember> = Api::namespaced(client.clone(), namespace);
    let patch = serde_json::json!({
        "metadata": { "annotations": { GRAPH_HASH_ANNOTATION: graph_hash } },
        "status": status,
    });

    api.patch(
        name,
        &PatchParams::apply(FIELD_MANAGER),
        &Patch::Merge(&patch),
    )
    .await
    .map_err(|e| ReconcileError::Kube(format!("patch status: {e}")))?;

    Ok(())
}
