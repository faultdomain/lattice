//! ModelCompiler — orchestrates per-role compilation for LatticeModel
//!
//! For each role:
//! - Compiles workload via `WorkloadCompiler` → pod template + config resources
//! - Compiles Tetragon tracing policies via `lattice_tetragon`
//! - Aggregates mesh members, config, and tracing policies
//!
//! Then builds a Kthena ModelServing from the aggregated pod templates.

use std::collections::BTreeMap;

use lattice_cedar::PolicyEngine;
use lattice_common::crd::{
    derived_name, CallerRef, LatticeMeshMember, LatticeMeshMemberSpec, LatticeModel,
    MeshMemberPort, MeshMemberTarget, PeerAuth, ProviderType,
};
use lattice_common::graph::ServiceGraph;
use lattice_common::policy::tetragon::TracingPolicyNamespaced;
use lattice_common::{KTHENA_AUTOSCALER_SA, KTHENA_NAMESPACE, KTHENA_ROUTER_SA, LABEL_NAME};
use lattice_volcano::routing_compiler::{PD_ROLE_DECODE, PD_ROLE_PREFILL};
use lattice_volcano::{CompiledAutoscaling, CompiledRouting, ModelServing, RoleTemplates};
use lattice_workload::{CompiledConfig, WorkloadCompiler};

use crate::download::{self, CompiledDownload};
use crate::error::ModelError;

/// Compute a stable suffix from the role key set for the ModelServing name.
///
/// Uses `derived_name` (FIPS SHA-256) with an empty prefix, returning an 8-char
/// hex hash. The suffix changes only when roles are added or removed, giving the
/// new ModelServing (and its PodGroup/pods) a different name that doesn't collide
/// with still-Terminating resources from the old role set.
pub(crate) fn role_key_suffix<'a>(role_names: impl Iterator<Item = &'a String>) -> String {
    let mut names: Vec<&str> = role_names.map(|s| s.as_str()).collect();
    names.sort();
    derived_name("", &names)
}

/// Complete compiled output for a LatticeModel
#[derive(Debug)]
pub struct CompiledModel {
    /// Kthena ModelServing resource
    pub model_serving: ModelServing,
    /// Aggregated config resources from all roles (ConfigMaps, Secrets, ESO, PVCs)
    pub config: CompiledConfig,
    /// LatticeMeshMember CRs — one per role that participates in the mesh
    pub mesh_members: Vec<LatticeMeshMember>,
    /// Tetragon TracingPolicyNamespaced resources — per-role runtime enforcement
    pub tracing_policies: Vec<TracingPolicyNamespaced>,
    /// Kthena routing resources (ModelServer + ModelRoutes)
    pub routing: Option<CompiledRouting>,
    /// Kthena autoscaling resources (AutoscalingPolicy + AutoscalingPolicyBinding)
    pub autoscaling: Option<CompiledAutoscaling>,
    /// Model download resources (PVC + Job) when modelSource is configured
    pub download: Option<CompiledDownload>,
    /// Auto-injected topology from kv_connector (for status reporting, never mutates spec)
    pub auto_topology: Option<lattice_common::crd::WorkloadNetworkTopology>,
}

/// Compile a LatticeModel into Kubernetes resources.
///
/// For each role, runs the shared `WorkloadCompiler` pipeline and `lattice_tetragon`
/// policy compiler, then aggregates results into a single `CompiledModel`.
///
/// This function is pure compilation — it does NOT register roles in the service graph.
/// The caller (controller) is responsible for graph registration after successful compilation
/// and cleanup on failure.
pub async fn compile_model(
    model: &LatticeModel,
    graph: &ServiceGraph,
    cluster_name: &str,
    provider_type: ProviderType,
    cedar: &PolicyEngine,
    role_suffix: &str,
) -> Result<CompiledModel, ModelError> {
    let name = model.metadata.name.as_deref().unwrap_or_default();
    let namespace = model
        .metadata
        .namespace
        .as_deref()
        .ok_or(ModelError::MissingNamespace)?;

    if model.spec.roles.is_empty() {
        return Err(ModelError::NoRoles);
    }

    let mut role_templates: BTreeMap<String, RoleTemplates> = BTreeMap::new();
    let mut config = CompiledConfig::default();
    let mut mesh_members = Vec::new();
    let mut tracing_policies = Vec::new();

    for (role_name, role_spec) in &model.spec.roles {
        role_spec
            .validate()
            .map_err(|e| ModelError::RoleValidation {
                role: role_name.clone(),
                message: e.to_string(),
            })?;

        let entry_full_name = format!("{}-{}", name, role_name);

        // Compile entry workload (always present)
        let mut entry_compiler = WorkloadCompiler::new(
            &entry_full_name,
            namespace,
            &role_spec.entry_workload,
            &role_spec.entry_runtime,
            provider_type,
        )
        .with_cedar(cedar)
        .with_cluster_name(cluster_name)
        .with_graph(graph)
        .with_image_pull_secrets(&role_spec.entry_runtime.image_pull_secrets);

        if model.spec.topology.is_some() {
            entry_compiler = entry_compiler.with_topology();
        }

        let entry_compiled =
            entry_compiler
                .compile()
                .await
                .map_err(|e| ModelError::RoleCompilation {
                    role: role_name.clone(),
                    source: e,
                })?;

        let entry_json = lattice_workload::pod_template_to_json(entry_compiled.pod_template)
            .map_err(ModelError::Serialization)?;
        config.merge(entry_compiled.config);

        if let Some(mm) = entry_compiled.mesh_member {
            mesh_members.push(mm);
        }

        let entry_policies = lattice_tetragon::compile_tracing_policies(
            &entry_full_name,
            namespace,
            &role_spec.entry_workload,
            &role_spec.entry_runtime,
            &[],
        );
        tracing_policies.extend(entry_policies);

        // Compile worker workload (if present)
        let worker_json = if let Some(ref worker_workload) = role_spec.worker_workload {
            let worker_runtime = role_spec
                .worker_runtime
                .as_ref()
                .unwrap_or(&role_spec.entry_runtime);
            let worker_name = format!("{}-{}-worker", name, role_name);

            // When worker_runtime falls back to entry_runtime, imagePullSecrets
            // may reference secret resources only declared in entry_workload.
            // Propagate those missing resources so the worker compilation can
            // resolve them (each compilation creates its own K8s Secret via ESO).
            let effective_worker_workload;
            let workload_ref = if role_spec.worker_runtime.is_none() {
                let mut cloned = worker_workload.clone();
                for secret_name in &worker_runtime.image_pull_secrets {
                    if !cloned.resources.contains_key(secret_name) {
                        if let Some(resource) = role_spec.entry_workload.resources.get(secret_name)
                        {
                            cloned
                                .resources
                                .insert(secret_name.clone(), resource.clone());
                        }
                    }
                }
                effective_worker_workload = cloned;
                &effective_worker_workload
            } else {
                worker_workload
            };

            let mut worker_compiler = WorkloadCompiler::new(
                &worker_name,
                namespace,
                workload_ref,
                worker_runtime,
                provider_type,
            )
            .with_cedar(cedar)
            .with_cluster_name(cluster_name)
            .with_graph(graph)
            .with_image_pull_secrets(&worker_runtime.image_pull_secrets);

            if model.spec.topology.is_some() {
                worker_compiler = worker_compiler.with_topology();
            }

            let worker_compiled =
                worker_compiler
                    .compile()
                    .await
                    .map_err(|e| ModelError::RoleCompilation {
                        role: format!("{}-worker", role_name),
                        source: e,
                    })?;

            let worker_template =
                lattice_workload::pod_template_to_json(worker_compiled.pod_template)
                    .map_err(ModelError::Serialization)?;
            config.merge(worker_compiled.config);

            if let Some(mm) = worker_compiled.mesh_member {
                mesh_members.push(mm);
            }

            let worker_policies = lattice_tetragon::compile_tracing_policies(
                &worker_name,
                namespace,
                worker_workload,
                worker_runtime,
                &[],
            );
            tracing_policies.extend(worker_policies);

            Some(worker_template)
        } else {
            None
        };

        role_templates.insert(
            role_name.clone(),
            RoleTemplates {
                entry_template: entry_json,
                worker_template: worker_json,
            },
        );
    }

    // Compile model download (PVC + Job) if modelSource is configured
    let uid = model.metadata.uid.as_deref().unwrap_or_default();
    let download = model
        .spec
        .model_source
        .as_ref()
        .map(|source| download::compile_download(name, namespace, uid, source))
        .transpose()?;

    // When modelSource is set, inject model cache volume + scheduling gate
    // into every role's entry and worker pod templates
    if let Some(ref dl) = download {
        for templates in role_templates.values_mut() {
            download::inject_model_volume(
                &mut templates.entry_template,
                dl.pvc_name(),
                dl.mount_path(),
            );
            download::inject_scheduling_gate(&mut templates.entry_template);

            if let Some(ref mut worker) = templates.worker_template {
                download::inject_model_volume(worker, dl.pvc_name(), dl.mount_path());
                download::inject_scheduling_gate(worker);
            }
        }
    }

    // Build ModelServing from aggregated role templates.
    // The role suffix ensures the resource name changes when the role set changes,
    // avoiding PodGroup name collisions with still-Terminating old resources.
    let compilation = lattice_volcano::compile_model_serving(model, &role_templates, role_suffix);
    let model_serving = compilation.model_serving;
    let auto_topology = compilation.auto_topology;
    let serving_name = &model_serving.metadata.name;

    // Compile routing (ModelServer + ModelRoutes) if configured
    let routing = model.spec.routing.as_ref().map(|routing_spec| {
        lattice_volcano::compile_model_routing(model, routing_spec, serving_name)
    });

    // When routing is configured, ensure mesh policies allow the Kthena router
    // to reach model pods, and enable peer traffic for PD disaggregation.
    if let Some(ref routing_spec) = model.spec.routing {
        ensure_routing_mesh_members(name, &model.spec.roles, routing_spec, &mut mesh_members);
    }

    // Compile autoscaling (AutoscalingPolicy + AutoscalingPolicyBinding) if configured
    let autoscaling = {
        let compiled = lattice_volcano::compile_model_autoscaling(model);
        if compiled.policies.is_empty() {
            None
        } else {
            Some(compiled)
        }
    };

    // When autoscaling is configured, ensure mesh policies allow the Kthena autoscaler
    // to reach model pods for metrics scraping.
    if autoscaling.is_some() {
        ensure_autoscaling_mesh_members(name, &model.spec.roles, &mut mesh_members);
    }

    Ok(CompiledModel {
        model_serving,
        config,
        mesh_members,
        tracing_policies,
        routing,
        autoscaling,
        download,
        auto_topology,
    })
}

/// Ensure mesh members allow inference traffic from the Kthena router.
///
/// For each model role, this function:
/// - Adds the Kthena router as an infrastructure allowed caller (its SPIFFE
///   identity will be used in AuthorizationPolicy since it won't be in the
///   service graph — same pattern as vmagent, KEDA, etc.)
/// - Adds the inference port if not already present
/// - Enables `allow_peer_traffic` only on "prefill" and "decode" roles when PD
///   disaggregation is active. Other roles (e.g. "embedding") are not part of
///   the PD pair and do not need lateral traffic.
///
/// If a role has no existing mesh member (the workload spec had no service
/// ports), a new one is created.
fn ensure_routing_mesh_members(
    model_name: &str,
    roles: &BTreeMap<String, lattice_common::crd::ModelRoleSpec>,
    routing: &lattice_common::crd::ModelRoutingSpec,
    mesh_members: &mut Vec<LatticeMeshMember>,
) {
    let inference_port = routing.port.unwrap_or(8000);
    let router_caller = CallerRef {
        name: KTHENA_ROUTER_SA.to_string(),
        namespace: Some(KTHENA_NAMESPACE.to_string()),
    };
    let has_pd =
        routing.kv_connector.is_some() && lattice_volcano::routing_compiler::has_pd_roles(roles);

    for role_name in roles.keys() {
        // Only PD roles need peer traffic for KV cache transfer
        let needs_peer_traffic =
            has_pd && (role_name == PD_ROLE_PREFILL || role_name == PD_ROLE_DECODE);

        let entry_name = format!("{}-{}", model_name, role_name);
        ensure_infra_caller_on_mesh_member(
            mesh_members,
            &entry_name,
            &router_caller,
            Some((inference_port, "inference")),
            needs_peer_traffic,
        );

        // Also handle worker mesh members if they exist
        let worker_name = format!("{}-{}-worker", model_name, role_name);
        augment_existing_mesh_member(
            mesh_members,
            &worker_name,
            &router_caller,
            Some((inference_port, "inference")),
            needs_peer_traffic,
        );
    }
}

/// Ensure mesh members allow metrics scraping from the Kthena autoscaler.
///
/// For each model role that has autoscaling configured, this function:
/// - Adds the Kthena autoscaler as an infrastructure allowed caller
/// - Adds the metrics port discovered from `entry_workload.service.ports["metrics"]`
///   if present and not already on the mesh member
///
/// If a role has no existing mesh member, a new one is created.
fn ensure_autoscaling_mesh_members(
    model_name: &str,
    roles: &BTreeMap<String, lattice_common::crd::ModelRoleSpec>,
    mesh_members: &mut Vec<LatticeMeshMember>,
) {
    let autoscaler_caller = CallerRef {
        name: KTHENA_AUTOSCALER_SA.to_string(),
        namespace: Some(KTHENA_NAMESPACE.to_string()),
    };

    for (role_name, role_spec) in roles {
        if role_spec.autoscaling.is_none() {
            continue;
        }

        let metrics_port = role_spec
            .entry_workload
            .service
            .as_ref()
            .and_then(|svc| svc.ports.get("metrics"))
            .map(|ps| ps.port);

        let entry_name = format!("{}-{}", model_name, role_name);

        let metrics = metrics_port.map(|p| (p, "metrics"));
        ensure_infra_caller_on_mesh_member(
            mesh_members,
            &entry_name,
            &autoscaler_caller,
            metrics,
            false,
        );

        // Also handle worker mesh members if they exist
        let worker_name = format!("{}-{}-worker", model_name, role_name);
        augment_existing_mesh_member(
            mesh_members,
            &worker_name,
            &autoscaler_caller,
            metrics,
            false,
        );
    }
}

/// Add an infrastructure caller (and optionally a port) to a mesh member, creating it if absent.
fn ensure_infra_caller_on_mesh_member(
    mesh_members: &mut Vec<LatticeMeshMember>,
    name: &str,
    caller: &CallerRef,
    port: Option<(u16, &str)>,
    allow_peer_traffic: bool,
) {
    if let Some(mm) = mesh_members
        .iter_mut()
        .find(|mm| mm.metadata.name.as_deref() == Some(name))
    {
        add_caller_and_port(mm, caller, port, allow_peer_traffic);
    } else {
        // No existing mesh member — create one
        let ports = match port {
            Some((p, name)) => vec![MeshMemberPort {
                port: p,
                service_port: None,
                name: name.to_string(),
                peer_auth: PeerAuth::Strict,
            }],
            None => Vec::new(),
        };

        let mm = LatticeMeshMember::new(
            name,
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(
                    [(LABEL_NAME.to_string(), name.to_string())]
                        .into_iter()
                        .collect(),
                ),
                ports,
                allowed_callers: vec![caller.clone()],
                dependencies: vec![],
                egress: vec![],
                allow_peer_traffic,
                depends_all: false,
                ingress: None,
                service_account: None,
            },
        );
        mesh_members.push(mm);
    }
}

/// Augment an existing mesh member with a caller and port. Does nothing if the member doesn't exist.
///
/// Workers may not have a mesh member if they have no service ports. This is expected —
/// workers typically don't receive direct inference traffic and are only reached by their
/// entry pod via intra-group communication.
fn augment_existing_mesh_member(
    mesh_members: &mut [LatticeMeshMember],
    name: &str,
    caller: &CallerRef,
    port: Option<(u16, &str)>,
    allow_peer_traffic: bool,
) {
    if let Some(mm) = mesh_members
        .iter_mut()
        .find(|mm| mm.metadata.name.as_deref() == Some(name))
    {
        add_caller_and_port(mm, caller, port, allow_peer_traffic);
    }
}

/// Shared logic: add a caller + optional port to a mesh member, deduplicating both.
fn add_caller_and_port(
    mm: &mut LatticeMeshMember,
    caller: &CallerRef,
    port: Option<(u16, &str)>,
    allow_peer_traffic: bool,
) {
    if !mm.spec.allowed_callers.contains(caller) {
        mm.spec.allowed_callers.push(caller.clone());
        mm.spec
            .allowed_callers
            .sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
    }

    if let Some((p, name)) = port {
        if !mm.spec.ports.iter().any(|existing| existing.port == p) {
            mm.spec.ports.push(MeshMemberPort {
                port: p,
                service_port: None,
                name: name.to_string(),
                peer_auth: PeerAuth::Strict,
            });
        }
    }

    if allow_peer_traffic {
        mm.spec.allow_peer_traffic = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use lattice_common::crd::{
        AutoscalingMetric, ContainerSpec, InferenceEngine, KvConnector, KvConnectorType,
        LatticeModelSpec, ModelAutoscalingSpec, ModelRoleSpec, ModelRouteRule, ModelRouteSpec,
        ModelRoutingSpec, ModelSourceSpec, PortSpec, ResourceSpec, ResourceType, RuntimeSpec,
        ServicePortsSpec, TargetModel, WorkloadSpec,
    };

    fn make_model(roles: BTreeMap<String, ModelRoleSpec>) -> LatticeModel {
        let spec = LatticeModelSpec {
            roles,
            ..Default::default()
        };
        let mut model = LatticeModel::new("test-model", spec);
        model.metadata.namespace = Some("default".to_string());
        model.metadata.uid = Some("uid-456".to_string());
        model
    }

    fn make_role(image: &str, replicas: u32) -> ModelRoleSpec {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: image.to_string(),
                ..Default::default()
            },
        );
        ModelRoleSpec {
            replicas,
            entry_workload: WorkloadSpec {
                containers,
                ..Default::default()
            },
            entry_runtime: RuntimeSpec::default(),
            worker_replicas: None,
            worker_workload: None,
            worker_runtime: None,
            autoscaling: None,
        }
    }

    fn permit_all_cedar() -> PolicyEngine {
        PolicyEngine::with_policies("permit(principal, action, resource);").unwrap()
    }

    fn basic_routing() -> ModelRoutingSpec {
        ModelRoutingSpec {
            inference_engine: InferenceEngine::VLlm,
            model: "test-org/test-model".to_string(),
            port: None,
            protocol: None,
            traffic_policy: None,
            kv_connector: None,
            routes: BTreeMap::from([(
                "default".to_string(),
                ModelRouteSpec {
                    model_name: None,
                    lora_adapters: None,
                    rules: vec![ModelRouteRule {
                        name: "default".to_string(),
                        model_match: None,
                        target_models: vec![TargetModel {
                            model_server_name: None,
                            weight: Some(100),
                        }],
                    }],
                    rate_limit: None,
                    parent_refs: None,
                },
            )]),
        }
    }

    #[tokio::test]
    async fn compile_single_role_model() {
        let mut roles = BTreeMap::new();
        roles.insert("decode".to_string(), make_role("decoder:latest", 2));

        let model = make_model(roles);
        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_model(
            &model,
            &graph,
            "test-cluster",
            ProviderType::Docker,
            &cedar,
            "test",
        )
        .await
        .unwrap();

        assert_eq!(compiled.model_serving.spec.template.roles.len(), 1);
        assert_eq!(compiled.model_serving.spec.template.roles[0].name, "decode");
        assert_eq!(compiled.model_serving.spec.template.roles[0].replicas, 2);
        assert!(compiled.tracing_policies.is_empty());
        assert!(compiled.routing.is_none());
    }

    #[tokio::test]
    async fn compile_multi_role_model() {
        let mut roles = BTreeMap::new();
        roles.insert("prefill".to_string(), make_role("prefill:latest", 1));
        roles.insert("decode".to_string(), make_role("decode:latest", 4));

        let model = make_model(roles);
        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_model(
            &model,
            &graph,
            "test-cluster",
            ProviderType::Docker,
            &cedar,
            "test",
        )
        .await
        .unwrap();

        assert_eq!(compiled.model_serving.spec.template.roles.len(), 2);
        assert!(compiled.routing.is_none());
    }

    #[tokio::test]
    async fn empty_roles_returns_error() {
        let model = make_model(BTreeMap::new());
        let graph = ServiceGraph::new();
        let cedar = PolicyEngine::new();

        let result = compile_model(
            &model,
            &graph,
            "test-cluster",
            ProviderType::Docker,
            &cedar,
            "test",
        )
        .await;
        assert!(matches!(result, Err(ModelError::NoRoles)));
    }

    #[tokio::test]
    async fn missing_namespace_returns_error() {
        let mut roles = BTreeMap::new();
        roles.insert("decode".to_string(), make_role("decoder:latest", 1));
        let spec = LatticeModelSpec {
            roles,
            ..Default::default()
        };
        let model = LatticeModel::new("test-model", spec);
        // No namespace set

        let graph = ServiceGraph::new();
        let cedar = PolicyEngine::new();

        let result = compile_model(
            &model,
            &graph,
            "test-cluster",
            ProviderType::Docker,
            &cedar,
            "test",
        )
        .await;
        assert!(matches!(result, Err(ModelError::MissingNamespace)));
    }

    #[tokio::test]
    async fn routing_compiles_model_server_and_routes() {
        let mut roles = BTreeMap::new();
        roles.insert("decode".to_string(), make_role("decoder:latest", 2));

        let spec = LatticeModelSpec {
            roles,
            routing: Some(basic_routing()),
            ..Default::default()
        };
        let mut model = LatticeModel::new("test-model", spec);
        model.metadata.namespace = Some("default".to_string());
        model.metadata.uid = Some("uid-456".to_string());

        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_model(
            &model,
            &graph,
            "test-cluster",
            ProviderType::Docker,
            &cedar,
            "test",
        )
        .await
        .unwrap();

        let routing = compiled.routing.as_ref().expect("routing should be Some");
        assert_eq!(routing.model_server.metadata.name, "test-model");
        assert_eq!(routing.model_routes.len(), 1);
        assert_eq!(routing.model_routes[0].metadata.name, "test-model-default");
    }

    #[tokio::test]
    async fn routing_creates_mesh_member_for_kthena_router() {
        let mut roles = BTreeMap::new();
        roles.insert("decode".to_string(), make_role("decoder:latest", 2));

        let spec = LatticeModelSpec {
            roles,
            routing: Some(basic_routing()),
            ..Default::default()
        };
        let mut model = LatticeModel::new("test-model", spec);
        model.metadata.namespace = Some("default".to_string());
        model.metadata.uid = Some("uid-456".to_string());

        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_model(
            &model,
            &graph,
            "test-cluster",
            ProviderType::Docker,
            &cedar,
            "test",
        )
        .await
        .unwrap();

        // Mesh member created for the decode role with router as allowed caller
        let mm = compiled
            .mesh_members
            .iter()
            .find(|mm| mm.metadata.name.as_deref() == Some("test-model-decode"))
            .expect("mesh member for decode role should exist");

        let has_router_caller = mm.spec.allowed_callers.iter().any(|c| {
            c.name == KTHENA_ROUTER_SA && c.namespace.as_deref() == Some(KTHENA_NAMESPACE)
        });
        assert!(
            has_router_caller,
            "Kthena router should be an allowed caller"
        );

        let has_inference_port = mm.spec.ports.iter().any(|p| p.port == 8000);
        assert!(has_inference_port, "inference port 8000 should be present");
    }

    #[tokio::test]
    async fn pd_disaggregation_enables_peer_traffic() {
        let mut roles = BTreeMap::new();
        roles.insert("prefill".to_string(), make_role("prefill:latest", 1));
        roles.insert("decode".to_string(), make_role("decode:latest", 4));

        let mut routing = basic_routing();
        routing.kv_connector = Some(KvConnector {
            type_: KvConnectorType::Nixl,
        });

        let spec = LatticeModelSpec {
            roles,
            routing: Some(routing),
            ..Default::default()
        };
        let mut model = LatticeModel::new("test-model", spec);
        model.metadata.namespace = Some("default".to_string());
        model.metadata.uid = Some("uid-456".to_string());

        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_model(
            &model,
            &graph,
            "test-cluster",
            ProviderType::Docker,
            &cedar,
            "test",
        )
        .await
        .unwrap();

        // Both roles should have allow_peer_traffic=true for KV cache transfer
        for role_name in &["prefill", "decode"] {
            let mm_name = format!("test-model-{}", role_name);
            let mm = compiled
                .mesh_members
                .iter()
                .find(|mm| mm.metadata.name.as_deref() == Some(&mm_name))
                .unwrap_or_else(|| panic!("mesh member for {} should exist", role_name));
            assert!(
                mm.spec.allow_peer_traffic,
                "{} should have allow_peer_traffic=true for PD disaggregation",
                role_name
            );
        }
    }

    #[tokio::test]
    async fn pd_peer_traffic_scoped_to_pd_roles_only() {
        let mut roles = BTreeMap::new();
        roles.insert("prefill".to_string(), make_role("prefill:latest", 1));
        roles.insert("decode".to_string(), make_role("decode:latest", 4));
        roles.insert("embedding".to_string(), make_role("embed:latest", 1));

        let mut routing = basic_routing();
        routing.kv_connector = Some(KvConnector {
            type_: KvConnectorType::Nixl,
        });

        let spec = LatticeModelSpec {
            roles,
            routing: Some(routing),
            ..Default::default()
        };
        let mut model = LatticeModel::new("test-model", spec);
        model.metadata.namespace = Some("default".to_string());
        model.metadata.uid = Some("uid-456".to_string());

        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_model(
            &model,
            &graph,
            "test-cluster",
            ProviderType::Docker,
            &cedar,
            "test",
        )
        .await
        .unwrap();

        // PD roles should have peer traffic
        for role_name in &["prefill", "decode"] {
            let mm_name = format!("test-model-{}", role_name);
            let mm = compiled
                .mesh_members
                .iter()
                .find(|mm| mm.metadata.name.as_deref() == Some(&mm_name))
                .unwrap_or_else(|| panic!("mesh member for {} should exist", role_name));
            assert!(
                mm.spec.allow_peer_traffic,
                "{} should have allow_peer_traffic=true",
                role_name
            );
        }

        // Non-PD role should NOT have peer traffic
        let embed_mm = compiled
            .mesh_members
            .iter()
            .find(|mm| mm.metadata.name.as_deref() == Some("test-model-embedding"))
            .expect("mesh member for embedding should exist");
        assert!(
            !embed_mm.spec.allow_peer_traffic,
            "embedding role should NOT have allow_peer_traffic"
        );
    }

    #[tokio::test]
    async fn no_routing_means_no_routing_output() {
        let mut roles = BTreeMap::new();
        roles.insert("decode".to_string(), make_role("decoder:latest", 2));

        let model = make_model(roles);
        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_model(
            &model,
            &graph,
            "test-cluster",
            ProviderType::Docker,
            &cedar,
            "test",
        )
        .await
        .unwrap();

        assert!(compiled.routing.is_none());
    }

    #[tokio::test]
    async fn model_source_produces_download() {
        let mut roles = BTreeMap::new();
        roles.insert("decode".to_string(), make_role("decoder:latest", 2));

        let spec = LatticeModelSpec {
            roles,
            model_source: Some(ModelSourceSpec {
                uri: "hf://Qwen/Qwen3-8B".to_string(),
                cache_size: "50Gi".to_string(),
                storage_class: None,
                mount_path: None,
                token_secret: None,
                downloader_image: None,
                access_mode: None,
                security: None,
                resources: BTreeMap::new(),
                image_pull_secrets: Vec::new(),
            }),
            ..Default::default()
        };
        let mut model = LatticeModel::new("test-model", spec);
        model.metadata.namespace = Some("default".to_string());
        model.metadata.uid = Some("uid-456".to_string());

        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_model(
            &model,
            &graph,
            "test-cluster",
            ProviderType::Docker,
            &cedar,
            "test",
        )
        .await
        .unwrap();

        let download = compiled.download.as_ref().expect("download should be Some");
        assert_eq!(download.pvc_name(), "vol-test-model-model-cache");
        assert_eq!(download.mount_path(), "/models");

        // Verify scheduling gate + volume injected into pod templates
        let role = &compiled.model_serving.spec.template.roles[0];
        let gates = role.entry_template["spec"]["schedulingGates"]
            .as_array()
            .expect("schedulingGates should be set");
        assert!(
            gates
                .iter()
                .any(|g| g["name"] == "lattice.dev/model-download"),
            "model-download scheduling gate should be present"
        );

        let volumes = role.entry_template["spec"]["volumes"]
            .as_array()
            .expect("volumes should be set");
        assert!(
            volumes.iter().any(|v| v["name"] == "model-cache"),
            "model-cache volume should be present"
        );
    }

    #[tokio::test]
    async fn no_model_source_means_no_download() {
        let mut roles = BTreeMap::new();
        roles.insert("decode".to_string(), make_role("decoder:latest", 2));

        let model = make_model(roles);
        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_model(
            &model,
            &graph,
            "test-cluster",
            ProviderType::Docker,
            &cedar,
            "test",
        )
        .await
        .unwrap();

        assert!(compiled.download.is_none());

        // Verify no scheduling gate on pod templates
        let role = &compiled.model_serving.spec.template.roles[0];
        let gates = role.entry_template["spec"]["schedulingGates"].as_array();
        assert!(
            gates.is_none_or(|g| g.is_empty()),
            "no scheduling gates when model_source is None"
        );
    }

    #[tokio::test]
    async fn autoscaling_adds_autoscaler_mesh_member() {
        let mut decode = make_role("decoder:latest", 2);
        // Add a "metrics" port to the entry workload service so the compiler discovers it
        let mut ports = BTreeMap::new();
        ports.insert(
            "metrics".to_string(),
            PortSpec {
                port: 9090,
                target_port: None,
                protocol: None,
            },
        );
        decode.entry_workload.service = Some(ServicePortsSpec { ports });
        decode.autoscaling = Some(ModelAutoscalingSpec {
            max: 8,
            metrics: vec![AutoscalingMetric {
                metric: "gpu_kv_cache_usage".to_string(),
                target: 0.8,
            }],
            tolerance_percent: None,
            behavior: None,
        });

        let mut roles = BTreeMap::new();
        roles.insert("decode".to_string(), decode);

        let spec = LatticeModelSpec {
            roles,
            routing: Some(basic_routing()),
            ..Default::default()
        };
        let mut model = LatticeModel::new("test-model", spec);
        model.metadata.namespace = Some("default".to_string());
        model.metadata.uid = Some("uid-456".to_string());

        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_model(
            &model,
            &graph,
            "test-cluster",
            ProviderType::Docker,
            &cedar,
            "test",
        )
        .await
        .unwrap();

        // Autoscaling resources should be compiled
        assert!(compiled.autoscaling.is_some());

        // Mesh member should have both router AND autoscaler as allowed callers
        let mm = compiled
            .mesh_members
            .iter()
            .find(|mm| mm.metadata.name.as_deref() == Some("test-model-decode"))
            .expect("mesh member for decode role should exist");

        let has_autoscaler = mm.spec.allowed_callers.iter().any(|c| {
            c.name == KTHENA_AUTOSCALER_SA && c.namespace.as_deref() == Some(KTHENA_NAMESPACE)
        });
        assert!(
            has_autoscaler,
            "Kthena autoscaler should be an allowed caller"
        );

        let has_router = mm.spec.allowed_callers.iter().any(|c| {
            c.name == KTHENA_ROUTER_SA && c.namespace.as_deref() == Some(KTHENA_NAMESPACE)
        });
        assert!(
            has_router,
            "Kthena router should still be an allowed caller"
        );

        // Metrics port from metricEndpoint should be present
        let has_metrics_port = mm
            .spec
            .ports
            .iter()
            .any(|p| p.port == 9090 && p.name == "metrics");
        assert!(
            has_metrics_port,
            "metrics port 9090 from metricEndpoint should be present"
        );
    }

    #[tokio::test]
    async fn worker_inherits_image_pull_secrets_from_entry_runtime() {
        // When worker_runtime is None, the worker uses entry_runtime. If
        // entry_runtime has imagePullSecrets referencing resources only in
        // entry_workload, the compiler should propagate those resources to
        // the worker workload so compilation succeeds.
        let mut secret_params = BTreeMap::new();
        secret_params.insert("provider".to_string(), serde_json::json!("lattice-local"));

        let mut entry_resources = BTreeMap::new();
        entry_resources.insert(
            "ghcr-creds".to_string(),
            ResourceSpec {
                type_: ResourceType::Secret,
                id: Some("registry-creds".to_string()),
                params: Some(secret_params),
                ..Default::default()
            },
        );

        let mut entry_containers = BTreeMap::new();
        entry_containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "ghcr.io/org/decode:latest".to_string(),
                ..Default::default()
            },
        );

        let mut worker_containers = BTreeMap::new();
        worker_containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "ghcr.io/org/decode-worker:latest".to_string(),
                ..Default::default()
            },
        );

        let role = ModelRoleSpec {
            replicas: 1,
            entry_workload: WorkloadSpec {
                containers: entry_containers,
                resources: entry_resources,
                ..Default::default()
            },
            entry_runtime: RuntimeSpec {
                image_pull_secrets: vec!["ghcr-creds".to_string()],
                ..Default::default()
            },
            worker_replicas: Some(2),
            worker_workload: Some(WorkloadSpec {
                containers: worker_containers,
                // No resources — ghcr-creds only declared in entry
                ..Default::default()
            }),
            worker_runtime: None, // Falls back to entry_runtime
            autoscaling: None,
        };

        let mut roles = BTreeMap::new();
        roles.insert("decode".to_string(), role);

        let model = make_model(roles);
        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        // This should succeed — the compiler propagates ghcr-creds to the worker workload
        let compiled = compile_model(
            &model,
            &graph,
            "test-cluster",
            ProviderType::Docker,
            &cedar,
            "test",
        )
        .await
        .expect("worker should compile with entry runtime's imagePullSecrets");

        assert_eq!(compiled.model_serving.spec.template.roles.len(), 1);
    }

    #[tokio::test]
    async fn no_autoscaling_means_no_autoscaler_in_mesh() {
        let mut roles = BTreeMap::new();
        roles.insert("decode".to_string(), make_role("decoder:latest", 2));

        let spec = LatticeModelSpec {
            roles,
            routing: Some(basic_routing()),
            ..Default::default()
        };
        let mut model = LatticeModel::new("test-model", spec);
        model.metadata.namespace = Some("default".to_string());
        model.metadata.uid = Some("uid-456".to_string());

        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_model(
            &model,
            &graph,
            "test-cluster",
            ProviderType::Docker,
            &cedar,
            "test",
        )
        .await
        .unwrap();

        assert!(compiled.autoscaling.is_none());

        let mm = compiled
            .mesh_members
            .iter()
            .find(|mm| mm.metadata.name.as_deref() == Some("test-model-decode"))
            .expect("mesh member should exist from routing");

        let has_autoscaler = mm.spec.allowed_callers.iter().any(|c| {
            c.name == KTHENA_AUTOSCALER_SA && c.namespace.as_deref() == Some(KTHENA_NAMESPACE)
        });
        assert!(
            !has_autoscaler,
            "Kthena autoscaler should NOT be present when no autoscaling configured"
        );
    }

    #[test]
    fn role_key_suffix_deterministic() {
        let roles = vec!["decode".to_string(), "prefill".to_string()];
        let a = role_key_suffix(roles.iter());
        let b = role_key_suffix(roles.iter());
        assert_eq!(a, b);
    }

    #[test]
    fn role_key_suffix_order_independent() {
        let fwd = vec!["decode".to_string(), "prefill".to_string()];
        let rev = vec!["prefill".to_string(), "decode".to_string()];
        assert_eq!(role_key_suffix(fwd.iter()), role_key_suffix(rev.iter()));
    }

    #[test]
    fn role_key_suffix_different_roles_differ() {
        let a = vec!["decode".to_string()];
        let b = vec!["decode".to_string(), "prefill".to_string()];
        assert_ne!(role_key_suffix(a.iter()), role_key_suffix(b.iter()));
    }
}
