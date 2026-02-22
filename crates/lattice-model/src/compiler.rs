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
    CallerRef, LatticeMeshMember, LatticeMeshMemberSpec, LatticeModel, MeshMemberPort,
    MeshMemberTarget, PeerAuth, ProviderType,
};
use lattice_common::graph::ServiceGraph;
use lattice_common::policy::tetragon::TracingPolicyNamespaced;
use lattice_common::{KTHENA_AUTOSCALER_SA, KTHENA_NAMESPACE, KTHENA_ROUTER_SA, LABEL_NAME};
use lattice_volcano::{CompiledAutoscaling, CompiledRouting, ModelServing, RoleTemplates};
use lattice_workload::{CompiledConfig, WorkloadCompiler};

use crate::download::{self, CompiledDownload};
use crate::error::ModelError;

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
        role_spec.validate().map_err(|e| ModelError::RoleValidation {
            role: role_name.clone(),
            message: e.to_string(),
        })?;

        let entry_full_name = format!("{}-{}", name, role_name);

        // Compile entry workload (always present)
        let entry_compiled = WorkloadCompiler::new(
            &entry_full_name,
            namespace,
            &role_spec.entry_workload,
            &role_spec.entry_runtime,
            provider_type,
        )
        .with_cedar(cedar)
        .with_cluster_name(cluster_name)
        .with_graph(graph)
        .with_image_pull_secrets(&role_spec.entry_runtime.image_pull_secrets)
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

            let worker_compiled = WorkloadCompiler::new(
                &worker_name,
                namespace,
                worker_workload,
                worker_runtime,
                provider_type,
            )
            .with_cedar(cedar)
            .with_cluster_name(cluster_name)
            .with_graph(graph)
            .with_image_pull_secrets(&worker_runtime.image_pull_secrets)
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
                &dl.pvc_name,
                &dl.mount_path,
            );
            download::inject_scheduling_gate(&mut templates.entry_template);

            if let Some(ref mut worker) = templates.worker_template {
                download::inject_model_volume(worker, &dl.pvc_name, &dl.mount_path);
                download::inject_scheduling_gate(worker);
            }
        }
    }

    // Build ModelServing from aggregated role templates
    let model_serving = lattice_volcano::compile_model_serving(model, &role_templates);

    // Compile routing (ModelServer + ModelRoutes) if configured
    let routing = model
        .spec
        .routing
        .as_ref()
        .map(|routing_spec| lattice_volcano::compile_model_routing(model, routing_spec));

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
    })
}

/// Ensure mesh members allow inference traffic from the Kthena router.
///
/// For each model role, this function:
/// - Adds the Kthena router as an infrastructure allowed caller (its SPIFFE
///   identity will be used in AuthorizationPolicy since it won't be in the
///   service graph — same pattern as vmagent, KEDA, etc.)
/// - Adds the inference port if not already present
/// - Enables `allow_peer_traffic` when PD disaggregation is active (prefill
///   and decode roles need to exchange KV cache data)
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
    let has_pd = routing.kv_connector.is_some()
        && lattice_volcano::routing_compiler::has_pd_roles(roles);

    for role_name in roles.keys() {
        let entry_name = format!("{}-{}", model_name, role_name);

        if let Some(mm) = mesh_members
            .iter_mut()
            .find(|mm| mm.metadata.name.as_deref() == Some(entry_name.as_str()))
        {
            // Add router as allowed caller if not present
            if !mm.spec.allowed_callers.contains(&router_caller) {
                mm.spec.allowed_callers.push(router_caller.clone());
                mm.spec
                    .allowed_callers
                    .sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
            }

            // Add inference port if not present
            if !mm.spec.ports.iter().any(|p| p.port == inference_port) {
                mm.spec.ports.push(MeshMemberPort {
                    port: inference_port,
                    name: "inference".to_string(),
                    peer_auth: PeerAuth::Strict,
                });
            }

            // Enable peer traffic for PD disaggregation
            if has_pd {
                mm.spec.allow_peer_traffic = true;
            }
        } else {
            // No existing mesh member — create one for routing
            let mm = LatticeMeshMember::new(
                &entry_name,
                LatticeMeshMemberSpec {
                    target: MeshMemberTarget::Selector(
                        [(LABEL_NAME.to_string(), entry_name.clone())]
                            .into_iter()
                            .collect(),
                    ),
                    ports: vec![MeshMemberPort {
                        port: inference_port,
                        name: "inference".to_string(),
                        peer_auth: PeerAuth::Strict,
                    }],
                    allowed_callers: vec![router_caller.clone()],
                    dependencies: vec![],
                    egress: vec![],
                    allow_peer_traffic: has_pd,
                    depends_all: false,
                    ingress: None,
                    service_account: None,
                },
            );
            mesh_members.push(mm);
        }

        // Also handle worker mesh members if they exist
        let worker_name = format!("{}-{}-worker", model_name, role_name);
        if let Some(wmm) = mesh_members
            .iter_mut()
            .find(|mm| mm.metadata.name.as_deref() == Some(worker_name.as_str()))
        {
            if !wmm.spec.allowed_callers.contains(&router_caller) {
                wmm.spec.allowed_callers.push(router_caller.clone());
                wmm.spec
                    .allowed_callers
                    .sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
            }
            if !wmm.spec.ports.iter().any(|p| p.port == inference_port) {
                wmm.spec.ports.push(MeshMemberPort {
                    port: inference_port,
                    name: "inference".to_string(),
                    peer_auth: PeerAuth::Strict,
                });
            }
            if has_pd {
                wmm.spec.allow_peer_traffic = true;
            }
        }
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

        if let Some(mm) = mesh_members
            .iter_mut()
            .find(|mm| mm.metadata.name.as_deref() == Some(entry_name.as_str()))
        {
            // Add autoscaler as allowed caller if not present
            if !mm.spec.allowed_callers.contains(&autoscaler_caller) {
                mm.spec.allowed_callers.push(autoscaler_caller.clone());
                mm.spec
                    .allowed_callers
                    .sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
            }

            // Add metrics port if configured and not already present
            if let Some(port) = metrics_port {
                if !mm.spec.ports.iter().any(|p| p.port == port) {
                    mm.spec.ports.push(MeshMemberPort {
                        port,
                        name: "metrics".to_string(),
                        peer_auth: PeerAuth::Strict,
                    });
                }
            }
        } else {
            // No existing mesh member — create one for autoscaler metrics scraping
            let mut ports = Vec::new();
            if let Some(port) = metrics_port {
                ports.push(MeshMemberPort {
                    port,
                    name: "metrics".to_string(),
                    peer_auth: PeerAuth::Strict,
                });
            }

            let mm = LatticeMeshMember::new(
                &entry_name,
                LatticeMeshMemberSpec {
                    target: MeshMemberTarget::Selector(
                        [(LABEL_NAME.to_string(), entry_name.clone())]
                            .into_iter()
                            .collect(),
                    ),
                    ports,
                    allowed_callers: vec![autoscaler_caller.clone()],
                    dependencies: vec![],
                    egress: vec![],
                    allow_peer_traffic: false,
                    depends_all: false,
                    ingress: None,
                    service_account: None,
                },
            );
            mesh_members.push(mm);
        }

        // Also handle worker mesh members if they exist
        let worker_name = format!("{}-{}-worker", model_name, role_name);
        if let Some(wmm) = mesh_members
            .iter_mut()
            .find(|mm| mm.metadata.name.as_deref() == Some(worker_name.as_str()))
        {
            if !wmm.spec.allowed_callers.contains(&autoscaler_caller) {
                wmm.spec.allowed_callers.push(autoscaler_caller.clone());
                wmm.spec
                    .allowed_callers
                    .sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
            }
            if let Some(port) = metrics_port {
                if !wmm.spec.ports.iter().any(|p| p.port == port) {
                    wmm.spec.ports.push(MeshMemberPort {
                        port,
                        name: "metrics".to_string(),
                        peer_auth: PeerAuth::Strict,
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use lattice_common::crd::{
        AutoscalingMetric, ContainerSpec, InferenceEngine, KvConnector, LatticeModelSpec,
        ModelAutoscalingSpec, ModelRoleSpec, ModelRouteRule, ModelRouteSpec, ModelRoutingSpec,
        ModelSourceSpec, PortSpec, RuntimeSpec, ServicePortsSpec, TargetModel, WorkloadSpec,
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

        let compiled = compile_model(&model, &graph, "test-cluster", ProviderType::Docker, &cedar)
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

        let compiled = compile_model(&model, &graph, "test-cluster", ProviderType::Docker, &cedar)
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

        let result =
            compile_model(&model, &graph, "test-cluster", ProviderType::Docker, &cedar).await;
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

        let result =
            compile_model(&model, &graph, "test-cluster", ProviderType::Docker, &cedar).await;
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

        let compiled = compile_model(&model, &graph, "test-cluster", ProviderType::Docker, &cedar)
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

        let compiled = compile_model(&model, &graph, "test-cluster", ProviderType::Docker, &cedar)
            .await
            .unwrap();

        // Mesh member created for the decode role with router as allowed caller
        let mm = compiled
            .mesh_members
            .iter()
            .find(|mm| mm.metadata.name.as_deref() == Some("test-model-decode"))
            .expect("mesh member for decode role should exist");

        let has_router_caller = mm
            .spec
            .allowed_callers
            .iter()
            .any(|c| c.name == KTHENA_ROUTER_SA && c.namespace.as_deref() == Some(KTHENA_NAMESPACE));
        assert!(has_router_caller, "Kthena router should be an allowed caller");

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
            type_: "nixl".to_string(),
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

        let compiled = compile_model(&model, &graph, "test-cluster", ProviderType::Docker, &cedar)
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
    async fn no_routing_means_no_routing_output() {
        let mut roles = BTreeMap::new();
        roles.insert("decode".to_string(), make_role("decoder:latest", 2));

        let model = make_model(roles);
        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_model(&model, &graph, "test-cluster", ProviderType::Docker, &cedar)
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
            }),
            ..Default::default()
        };
        let mut model = LatticeModel::new("test-model", spec);
        model.metadata.namespace = Some("default".to_string());
        model.metadata.uid = Some("uid-456".to_string());

        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_model(&model, &graph, "test-cluster", ProviderType::Docker, &cedar)
            .await
            .unwrap();

        let download = compiled.download.as_ref().expect("download should be Some");
        assert_eq!(download.pvc_name, "vol-test-model-model-cache");
        assert_eq!(download.mount_path, "/models");

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
            volumes
                .iter()
                .any(|v| v["name"] == "model-cache"),
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

        let compiled = compile_model(&model, &graph, "test-cluster", ProviderType::Docker, &cedar)
            .await
            .unwrap();

        assert!(compiled.download.is_none());

        // Verify no scheduling gate on pod templates
        let role = &compiled.model_serving.spec.template.roles[0];
        let gates = role.entry_template["spec"]["schedulingGates"].as_array();
        assert!(
            gates.map_or(true, |g| g.is_empty()),
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

        let compiled = compile_model(&model, &graph, "test-cluster", ProviderType::Docker, &cedar)
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
        assert!(has_router, "Kthena router should still be an allowed caller");

        // Metrics port from metricEndpoint should be present
        let has_metrics_port = mm.spec.ports.iter().any(|p| p.port == 9090 && p.name == "metrics");
        assert!(
            has_metrics_port,
            "metrics port 9090 from metricEndpoint should be present"
        );
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

        let compiled = compile_model(&model, &graph, "test-cluster", ProviderType::Docker, &cedar)
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
}
