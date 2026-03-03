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
    derived_name, CallerRef, LatticeMeshMember, LatticeModel, MeshMemberPort, PeerAuth, PortSpec,
    ProviderType,
};
use lattice_common::graph::ServiceGraph;
use lattice_common::policy::tetragon::TracingPolicyNamespaced;
use lattice_common::{KTHENA_AUTOSCALER_SA, KTHENA_NAMESPACE, KTHENA_ROUTER_SA, LABEL_MODEL};
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
    /// Peer-discovery K8s Services for P/D roles (stable DNS for nixl KV cache transfer)
    pub peer_services: Vec<serde_json::Value>,
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
    let name = model
        .metadata
        .name
        .as_deref()
        .ok_or(ModelError::MissingName)?;
    let namespace = model
        .metadata
        .namespace
        .as_deref()
        .ok_or(ModelError::MissingNamespace)?;

    if model.spec.roles.is_empty() {
        return Err(ModelError::NoRoles);
    }

    // Apply defaults to each role via strategic merge patch (compile-time only)
    let mut roles = model.spec.merged_roles();

    // When routing is configured with a port, inject it as "inference" into each
    // role's entry workload. Roles like prefill may declare no service.ports,
    // causing WorkloadCompiler to skip mesh member creation. The inference port
    // ensures every role gets a mesh member and participates in the service graph.
    if let Some(ref routing) = model.spec.routing {
        if let Some(inference_port) = routing.port {
            for role_spec in roles.values_mut() {
                let svc = role_spec
                    .entry_workload
                    .service
                    .get_or_insert_with(Default::default);
                svc.ports
                    .entry("inference".to_string())
                    .or_insert(PortSpec {
                        port: inference_port,
                        target_port: None,
                        protocol: None,
                    });
            }
        }
    }

    let mut role_templates: BTreeMap<String, RoleTemplates> = BTreeMap::new();
    let mut config = CompiledConfig::default();
    let mut mesh_members = Vec::new();
    let mut tracing_policies = Vec::new();

    for (role_name, role_spec) in &roles {
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
    let uid = model
        .metadata
        .uid
        .as_deref()
        .ok_or(ModelError::MissingUid)?;
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

    // Inject model group label and ambient mesh opt-out into all pod templates
    let model_labels: &[(&str, &str)] = &[(LABEL_MODEL, name), ("istio.io/dataplane-mode", "none")];
    for templates in role_templates.values_mut() {
        lattice_workload::inject_pod_labels(&mut templates.entry_template, model_labels);
        if let Some(ref mut worker) = templates.worker_template {
            lattice_workload::inject_pod_labels(worker, model_labels);
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

    // Compile autoscaling (AutoscalingPolicy + AutoscalingPolicyBinding) if configured
    let autoscaling = {
        let compiled = lattice_volcano::compile_model_autoscaling(model);
        if compiled.policies.is_empty() {
            None
        } else {
            Some(compiled)
        }
    };

    // When routing or autoscaling is configured, ensure mesh policies allow
    // the Kthena router/autoscaler to reach model pods.
    augment_kthena_callers(
        name,
        &roles,
        model.spec.routing.as_ref(),
        autoscaling.is_some(),
        &mut mesh_members,
    )?;

    // Create peer-discovery Services for P/D roles when kv_connector disaggregation
    // is active. These provide stable DNS names (e.g., llm-serving-prefill) for
    // nixl KV cache transfer between prefill and decode pods.
    let peer_services = {
        let has_pd = model
            .spec
            .routing
            .as_ref()
            .map(|r| {
                r.kv_connector.is_some() && lattice_volcano::routing_compiler::has_pd_roles(&roles)
            })
            .unwrap_or(false);

        if has_pd {
            let routing_spec = model.spec.routing.as_ref().unwrap();
            let inference_port = routing_spec.port.ok_or(ModelError::MissingInferencePort)?;
            let side_channel_port = routing_spec
                .kv_connector
                .as_ref()
                .and_then(|kv| kv.port)
                .unwrap_or(lattice_common::crd::DEFAULT_KV_SIDE_CHANNEL_PORT);

            [PD_ROLE_PREFILL, PD_ROLE_DECODE]
                .iter()
                .map(|role| {
                    compile_peer_service(name, role, namespace, inference_port, side_channel_port)
                })
                .collect()
        } else {
            Vec::new()
        }
    };

    // Model serving: opt out of ambient mesh. All model pods share the
    // `lattice.dev/model` group label for Cilium L4 peer traffic rules.
    // Kthena callers (router, autoscaler) are handled by bilateral agreement
    // via compile_direct_cilium_policy label-based ingress.
    for mm in &mut mesh_members {
        mm.spec.ambient = false;
        mm.spec.target = lattice_common::crd::MeshMemberTarget::Selector(
            [(LABEL_MODEL.to_string(), name.to_string())]
                .into_iter()
                .collect(),
        );
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
        peer_services,
    })
}

/// Compile a peer-discovery ClusterIP Service for a P/D role.
///
/// Creates a Service with a predictable name (`{model_name}-{role_name}`) that
/// pods can use for DNS-based peer discovery during nixl KV cache transfer.
/// The selector uses `LABEL_NAME` to match pods labeled by `PodTemplateCompiler`.
/// Exposes both the inference port and the KV cache side-channel port.
fn compile_peer_service(
    model_name: &str,
    role_name: &str,
    namespace: &str,
    inference_port: u16,
    side_channel_port: u16,
) -> serde_json::Value {
    let service_name = format!("{}-{}", model_name, role_name);
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": service_name,
            "namespace": namespace
        },
        "spec": {
            "selector": {
                lattice_common::LABEL_NAME: service_name
            },
            "ports": [
                {
                    "name": "inference",
                    "port": inference_port,
                    "targetPort": inference_port,
                    "protocol": "TCP"
                },
                {
                    "name": "kv-side-channel",
                    "port": side_channel_port,
                    "targetPort": side_channel_port,
                    "protocol": "TCP"
                }
            ]
        }
    })
}

/// Augment mesh members with Kthena callers for routing and autoscaling.
///
/// For each model role, adds callers and ports to existing mesh members:
/// - Kthena router + inference port (when routing is configured)
/// - Kthena autoscaler + metrics port (when autoscaling is active)
/// - `allow_peer_traffic` on "prefill"/"decode" roles for PD disaggregation
///
/// These callers form bilateral agreements with the kthena-router and
/// kthena-autoscaler MeshMembers deployed in kthena-system (which use
/// `depends_all: true`).
///
/// Mesh members must already exist (created by WorkloadCompiler after graph
/// registration). Workers without mesh members are silently skipped — they
/// don't receive direct inference traffic.
fn augment_kthena_callers(
    model_name: &str,
    roles: &BTreeMap<String, lattice_common::crd::ModelRoleSpec>,
    routing: Option<&lattice_common::crd::ModelRoutingSpec>,
    has_autoscaling: bool,
    mesh_members: &mut [LatticeMeshMember],
) -> Result<(), ModelError> {
    let router_caller = routing.map(|_| CallerRef {
        name: KTHENA_ROUTER_SA.to_string(),
        namespace: Some(KTHENA_NAMESPACE.to_string()),
    });

    let inference_port = routing
        .map(|r| r.port.ok_or(ModelError::MissingInferencePort))
        .transpose()?;

    let has_pd = routing
        .map(|r| r.kv_connector.is_some() && lattice_volcano::routing_compiler::has_pd_roles(roles))
        .unwrap_or(false);

    let autoscaler_caller = if has_autoscaling {
        Some(CallerRef {
            name: KTHENA_AUTOSCALER_SA.to_string(),
            namespace: Some(KTHENA_NAMESPACE.to_string()),
        })
    } else {
        None
    };

    for (role_name, role_spec) in roles {
        let entry_name = format!("{}-{}", model_name, role_name);
        let worker_name = format!("{}-{}-worker", model_name, role_name);

        let needs_peer_traffic =
            has_pd && (role_name == PD_ROLE_PREFILL || role_name == PD_ROLE_DECODE);

        if let (Some(caller), Some(port)) = (&router_caller, inference_port) {
            augment_mesh_member(
                mesh_members,
                &entry_name,
                caller,
                Some((port, "inference")),
                needs_peer_traffic,
            );
            augment_mesh_member(
                mesh_members,
                &worker_name,
                caller,
                Some((port, "inference")),
                needs_peer_traffic,
            );
        }

        if let Some(ref caller) = autoscaler_caller {
            if role_spec.autoscaling.is_some() {
                let metrics_port = role_spec
                    .entry_workload
                    .service
                    .as_ref()
                    .and_then(|svc| svc.ports.get("metrics"))
                    .map(|ps| (ps.port, "metrics"));

                augment_mesh_member(mesh_members, &entry_name, caller, metrics_port, false);
                augment_mesh_member(mesh_members, &worker_name, caller, metrics_port, false);
            }
        }
    }

    Ok(())
}

/// Add a caller and optional port to an existing mesh member.
///
/// Does nothing if the member doesn't exist — workers may lack mesh members
/// when they have no service ports.
fn augment_mesh_member(
    mesh_members: &mut [LatticeMeshMember],
    name: &str,
    caller: &CallerRef,
    port: Option<(u16, &str)>,
    allow_peer_traffic: bool,
) {
    let Some(mm) = mesh_members
        .iter_mut()
        .find(|mm| mm.metadata.name.as_deref() == Some(name))
    else {
        return;
    };

    if !mm.spec.allowed_callers.contains(caller) {
        mm.spec.allowed_callers.push(caller.clone());
        mm.spec
            .allowed_callers
            .sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
    }

    if let Some((p, port_name)) = port {
        if !mm.spec.ports.iter().any(|existing| existing.port == p) {
            mm.spec.ports.push(MeshMemberPort {
                port: p,
                service_port: None,
                name: port_name.to_string(),
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
        ModelRoutingSpec, ModelSourceSpec, PortSpec, ResourceParams, ResourceSpec, ResourceType,
        RuntimeSpec, SecretParams, ServicePortsSpec, TargetModel, WorkloadSpec,
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
        let mut ports = BTreeMap::new();
        ports.insert(
            "inference".to_string(),
            PortSpec {
                port: 8000,
                target_port: None,
                protocol: None,
            },
        );
        ModelRoleSpec {
            replicas: Some(replicas),
            entry_workload: WorkloadSpec {
                containers,
                service: Some(ServicePortsSpec { ports }),
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

    /// Register model roles in the service graph, matching what the controller
    /// does before calling `compile_model`. This ensures WorkloadCompiler creates
    /// mesh members for entry workloads.
    fn register_model_roles(model: &LatticeModel, graph: &ServiceGraph) {
        let name = model.metadata.name.as_deref().unwrap();
        let namespace = model.metadata.namespace.as_deref().unwrap();
        for (role_name, role_spec) in &model.spec.roles {
            graph.put_workload(
                namespace,
                &format!("{}-{}", name, role_name),
                &role_spec.entry_workload,
            );
        }
    }

    fn basic_routing() -> ModelRoutingSpec {
        ModelRoutingSpec {
            inference_engine: InferenceEngine::VLlm,
            model: "test-org/test-model".to_string(),
            port: Some(8000),
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
        register_model_roles(&model, &graph);
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
            port: None,
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
        register_model_roles(&model, &graph);
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
            port: None,
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
        register_model_roles(&model, &graph);
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
        register_model_roles(&model, &graph);
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
        let mut entry_resources = BTreeMap::new();
        entry_resources.insert(
            "ghcr-creds".to_string(),
            ResourceSpec {
                type_: ResourceType::Secret,
                id: Some("registry-creds".to_string()),
                params: ResourceParams::Secret(SecretParams {
                    provider: "lattice-local".to_string(),
                    ..Default::default()
                }),
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
            replicas: Some(1),
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
        register_model_roles(&model, &graph);
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
        let roles = ["decode".to_string(), "prefill".to_string()];
        let a = role_key_suffix(roles.iter());
        let b = role_key_suffix(roles.iter());
        assert_eq!(a, b);
    }

    #[test]
    fn role_key_suffix_order_independent() {
        let fwd = ["decode".to_string(), "prefill".to_string()];
        let rev = ["prefill".to_string(), "decode".to_string()];
        assert_eq!(role_key_suffix(fwd.iter()), role_key_suffix(rev.iter()));
    }

    #[test]
    fn role_key_suffix_different_roles_differ() {
        let a = ["decode".to_string()];
        let b = ["decode".to_string(), "prefill".to_string()];
        assert_ne!(role_key_suffix(a.iter()), role_key_suffix(b.iter()));
    }

    #[tokio::test]
    async fn missing_name_returns_error() {
        let mut roles = BTreeMap::new();
        roles.insert("decode".to_string(), make_role("decoder:latest", 1));
        let spec = LatticeModelSpec {
            roles,
            ..Default::default()
        };
        // Create model with no name
        let mut model = LatticeModel::new("", spec);
        model.metadata.name = None;
        model.metadata.namespace = Some("default".to_string());

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
        assert!(matches!(result, Err(ModelError::MissingName)));
    }

    #[tokio::test]
    async fn missing_uid_returns_error() {
        let mut roles = BTreeMap::new();
        roles.insert("decode".to_string(), make_role("decoder:latest", 1));
        let spec = LatticeModelSpec {
            roles,
            model_source: Some(ModelSourceSpec {
                uri: "hf://test/model".to_string(),
                cache_size: "10Gi".to_string(),
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
        model.metadata.uid = None;

        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let result = compile_model(
            &model,
            &graph,
            "test-cluster",
            ProviderType::Docker,
            &cedar,
            "test",
        )
        .await;
        assert!(matches!(result, Err(ModelError::MissingUid)));
    }

    #[tokio::test]
    async fn routing_without_port_returns_error() {
        let mut roles = BTreeMap::new();
        roles.insert("decode".to_string(), make_role("decoder:latest", 2));

        let mut routing = basic_routing();
        routing.port = None;

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

        let result = compile_model(
            &model,
            &graph,
            "test-cluster",
            ProviderType::Docker,
            &cedar,
            "test",
        )
        .await;
        assert!(matches!(result, Err(ModelError::MissingInferencePort)));
    }

    #[tokio::test]
    async fn peer_services_created_for_pd_roles() {
        let mut roles = BTreeMap::new();
        roles.insert("prefill".to_string(), make_role("prefill:latest", 1));
        roles.insert("decode".to_string(), make_role("decode:latest", 4));

        let mut routing = basic_routing();
        routing.kv_connector = Some(KvConnector {
            type_: KvConnectorType::Nixl,
            port: None,
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
        register_model_roles(&model, &graph);
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

        assert_eq!(
            compiled.peer_services.len(),
            2,
            "should create one peer service per P/D role"
        );

        for (role, expected_name) in [
            ("prefill", "test-model-prefill"),
            ("decode", "test-model-decode"),
        ] {
            let svc = compiled
                .peer_services
                .iter()
                .find(|s| s["metadata"]["name"].as_str() == Some(expected_name))
                .unwrap_or_else(|| panic!("peer service for {} should exist", role));

            assert_eq!(
                svc["metadata"]["namespace"].as_str(),
                Some("default"),
                "{} service should be in the model namespace",
                role
            );

            let selector = &svc["spec"]["selector"];
            assert_eq!(
                selector[lattice_common::LABEL_NAME].as_str(),
                Some(expected_name),
                "{} selector should match LABEL_NAME",
                role
            );

            let ports = svc["spec"]["ports"].as_array().expect("ports should exist");
            assert_eq!(
                ports.len(),
                2,
                "should have inference + kv-side-channel ports"
            );
            assert_eq!(ports[0]["name"], "inference");
            assert_eq!(ports[0]["port"], 8000);
            assert_eq!(ports[0]["targetPort"], 8000);
            assert_eq!(ports[1]["name"], "kv-side-channel");
            assert_eq!(ports[1]["port"], 5557);
            assert_eq!(ports[1]["targetPort"], 5557);
        }
    }

    #[tokio::test]
    async fn peer_services_use_explicit_side_channel_port() {
        let mut roles = BTreeMap::new();
        roles.insert("prefill".to_string(), make_role("prefill:latest", 1));
        roles.insert("decode".to_string(), make_role("decode:latest", 4));

        let mut routing = basic_routing();
        routing.kv_connector = Some(KvConnector {
            type_: KvConnectorType::Nixl,
            port: Some(6000),
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
        register_model_roles(&model, &graph);
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

        for svc in &compiled.peer_services {
            let ports = svc["spec"]["ports"].as_array().expect("ports should exist");
            assert_eq!(ports.len(), 2);
            assert_eq!(ports[1]["name"], "kv-side-channel");
            assert_eq!(ports[1]["port"], 6000);
            assert_eq!(ports[1]["targetPort"], 6000);
        }
    }

    #[tokio::test]
    async fn no_peer_services_without_kv_connector() {
        let mut roles = BTreeMap::new();
        roles.insert("prefill".to_string(), make_role("prefill:latest", 1));
        roles.insert("decode".to_string(), make_role("decode:latest", 4));

        // Routing without kv_connector
        let spec = LatticeModelSpec {
            roles,
            routing: Some(basic_routing()),
            ..Default::default()
        };
        let mut model = LatticeModel::new("test-model", spec);
        model.metadata.namespace = Some("default".to_string());
        model.metadata.uid = Some("uid-456".to_string());

        let graph = ServiceGraph::new();
        register_model_roles(&model, &graph);
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

        assert!(
            compiled.peer_services.is_empty(),
            "no peer services without kv_connector"
        );
    }

    #[tokio::test]
    async fn prefill_role_without_ports_gets_mesh_member_via_routing_port() {
        // A prefill role with no service.ports should still get a mesh member
        // when routing.port is configured, because the inference port is injected.
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "prefill:latest".to_string(),
                ..Default::default()
            },
        );
        let prefill = ModelRoleSpec {
            replicas: Some(1),
            entry_workload: WorkloadSpec {
                containers,
                // No service ports declared
                ..Default::default()
            },
            entry_runtime: RuntimeSpec::default(),
            worker_replicas: None,
            worker_workload: None,
            worker_runtime: None,
            autoscaling: None,
        };

        let mut roles = BTreeMap::new();
        roles.insert("prefill".to_string(), prefill);
        roles.insert("decode".to_string(), make_role("decode:latest", 4));

        let spec = LatticeModelSpec {
            roles,
            routing: Some(basic_routing()),
            ..Default::default()
        };
        let mut model = LatticeModel::new("test-model", spec);
        model.metadata.namespace = Some("default".to_string());
        model.metadata.uid = Some("uid-456".to_string());

        let graph = ServiceGraph::new();
        register_model_roles(&model, &graph);
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

        // Prefill role should have a mesh member with inference port injected
        let prefill_mm = compiled
            .mesh_members
            .iter()
            .find(|mm| mm.metadata.name.as_deref() == Some("test-model-prefill"))
            .expect("prefill role should have a mesh member when routing.port is set");

        let has_inference_port = prefill_mm
            .spec
            .ports
            .iter()
            .any(|p| p.port == 8000 && p.name == "inference");
        assert!(
            has_inference_port,
            "prefill mesh member should have the inference port"
        );

        // Router should be an allowed caller
        let has_router = prefill_mm.spec.allowed_callers.iter().any(|c| {
            c.name == KTHENA_ROUTER_SA && c.namespace.as_deref() == Some(KTHENA_NAMESPACE)
        });
        assert!(
            has_router,
            "kthena-router should be an allowed caller on prefill"
        );
    }
}
