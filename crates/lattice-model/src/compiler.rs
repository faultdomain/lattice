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
    derived_name, EgressRule, EgressTarget, LatticeMeshMember, LatticeModel, MeshMemberPort,
    ModelRoutingSpec, ModelSourceSpec, PeerAuth, PortSpec, ProviderType, ServiceRef,
};
use lattice_common::graph::ServiceGraph;
use lattice_common::policy::tetragon::TracingPolicyNamespaced;
use lattice_common::{KTHENA_AUTOSCALER_SA, KTHENA_NAMESPACE, KTHENA_ROUTER_SA, LABEL_MODEL};
use lattice_volcano::routing_compiler::{PD_ROLE_DECODE, PD_ROLE_PREFILL};
use lattice_volcano::{CompiledAutoscaling, CompiledRouting, ModelServing, RoleTemplates};
use lattice_workload::{CompiledConfig, WorkloadCompiler};

use crate::error::ModelError;

const DEFAULT_DOWNLOADER_IMAGE: &str = "ghcr.io/volcano-sh/downloader:latest";
const DEFAULT_MOUNT_PATH: &str = "/models";
const VOLUME_NAME: &str = "model-cache";
const INIT_CONTAINER_NAME: &str = "model-downloader";
const SCRATCH_VOLUME_NAME: &str = "model-downloader-scratch";
const DSHM_VOLUME_NAME: &str = "dshm";

fn entry_workload_name(model_name: &str, role_name: &str) -> String {
    format!("{}-{}", model_name, role_name)
}

fn worker_workload_name(model_name: &str, role_name: &str) -> String {
    format!("{}-{}-worker", model_name, role_name)
}

fn kthena_caller(service_account: &str) -> ServiceRef {
    ServiceRef::new(KTHENA_NAMESPACE, service_account)
}

/// Compute infrastructure callers for model roles (kthena-router, kthena-autoscaler).
/// Same callers that `augment_kthena_callers` adds to compiled MeshMembers.
pub fn model_callers(routing: Option<&ModelRoutingSpec>, has_autoscaling: bool) -> Vec<ServiceRef> {
    let mut callers = Vec::new();
    if routing.is_some() {
        callers.push(kthena_caller(KTHENA_ROUTER_SA));
    }
    if has_autoscaling {
        callers.push(kthena_caller(KTHENA_AUTOSCALER_SA));
    }
    callers
}

/// Check whether routing uses P/D disaggregation (kv_connector with prefill/decode roles).
fn has_pd_disaggregation(
    routing: Option<&lattice_common::crd::ModelRoutingSpec>,
    roles: &BTreeMap<String, lattice_common::crd::ModelRoleSpec>,
) -> bool {
    routing
        .map(|r| r.kv_connector.is_some() && lattice_volcano::routing_compiler::has_pd_roles(roles))
        .unwrap_or(false)
}

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
    /// Auto-injected topology from kv_connector (for status reporting, never mutates spec)
    pub auto_topology: Option<lattice_common::crd::WorkloadNetworkTopology>,
    /// Peer-discovery K8s Services for P/D roles (stable DNS for nixl KV cache transfer)
    pub peer_services: Vec<serde_json::Value>,
}

/// Compile a LatticeModel into Kubernetes resources.
///
/// Orchestrates: role preparation, per-role workload compilation, download
/// injection, ModelServing assembly, routing/autoscaling, and mesh finalization.
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

    let roles = prepare_roles(model)?;

    let ctx = CompilationCtx {
        namespace,
        provider_type,
        cedar,
        cluster_name,
        graph,
        has_topology: model.spec.topology.is_some(),
    };

    let mut compiled = compile_roles(name, &roles, &ctx).await?;

    inject_model_download(
        model.spec.model_source.as_ref(),
        &mut compiled.role_templates,
    );

    inject_model_labels(name, &mut compiled.role_templates);

    let assembled = assemble_serving(model, &compiled.role_templates, role_suffix)?;

    let peer_services =
        compile_peer_services(name, namespace, &roles, model.spec.routing.as_ref())?;

    finalize_mesh(
        name,
        &roles,
        model.spec.routing.as_ref(),
        assembled.autoscaling.is_some(),
        model.spec.model_source.as_ref(),
        &mut compiled.mesh_members,
    )?;

    Ok(CompiledModel {
        model_serving: assembled.model_serving,
        config: compiled.config,
        mesh_members: compiled.mesh_members,
        tracing_policies: compiled.tracing_policies,
        routing: assembled.routing,
        autoscaling: assembled.autoscaling,
        auto_topology: assembled.auto_topology,
        peer_services,
    })
}

/// Validate model spec and prepare roles with merged defaults and routing ports.
fn prepare_roles(
    model: &LatticeModel,
) -> Result<BTreeMap<String, lattice_common::crd::ModelRoleSpec>, ModelError> {
    if model.spec.roles.is_empty() {
        return Err(ModelError::NoRoles);
    }

    let mut roles = model.spec.merged_roles();

    // Inject routing inference port into each role so WorkloadCompiler creates
    // mesh members even for roles that don't declare service.ports.
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

    Ok(roles)
}

/// Shared context for compiling workloads within a model.
struct CompilationCtx<'a> {
    namespace: &'a str,
    provider_type: ProviderType,
    cedar: &'a PolicyEngine,
    cluster_name: &'a str,
    graph: &'a ServiceGraph,
    has_topology: bool,
}

/// Compile a single workload (entry or worker) through the WorkloadCompiler pipeline.
///
/// Returns the pod template JSON, compiled config, optional mesh member, and tracing policies.
async fn compile_workload(
    ctx: &CompilationCtx<'_>,
    workload_name: &str,
    workload: &lattice_common::crd::WorkloadSpec,
    runtime: &lattice_common::crd::RuntimeSpec,
    role_label: &str,
) -> Result<
    (
        serde_json::Value,
        CompiledConfig,
        Option<LatticeMeshMember>,
        Vec<TracingPolicyNamespaced>,
    ),
    ModelError,
> {
    let mut compiler = WorkloadCompiler::new(
        workload_name,
        ctx.namespace,
        workload,
        runtime,
        ctx.provider_type,
        ctx.cedar,
    )
    .with_cluster_name(ctx.cluster_name)
    .with_graph(ctx.graph)
    .with_image_pull_secrets(&runtime.image_pull_secrets);

    if ctx.has_topology {
        compiler = compiler.with_topology();
    }

    let compiled = compiler
        .compile()
        .await
        .map_err(|e| ModelError::RoleCompilation {
            role: role_label.to_string(),
            source: e,
        })?;

    let template = lattice_workload::pod_template_to_json(compiled.pod_template)
        .map_err(ModelError::Serialization)?;

    let policies = lattice_tetragon::compile_tracing_policies(
        workload_name,
        ctx.namespace,
        workload,
        runtime,
        &[],
    );

    Ok((template, compiled.config, compiled.mesh_member, policies))
}

/// When worker_runtime falls back to entry_runtime, imagePullSecrets may
/// reference secret resources only declared in entry_workload. Returns a
/// modified clone with those resources propagated, or None if no changes needed.
fn prepare_worker_workload(
    worker_workload: &lattice_common::crd::WorkloadSpec,
    entry_workload: &lattice_common::crd::WorkloadSpec,
    worker_runtime: &lattice_common::crd::RuntimeSpec,
    has_explicit_worker_runtime: bool,
) -> Option<lattice_common::crd::WorkloadSpec> {
    if has_explicit_worker_runtime {
        return None;
    }
    let mut cloned = worker_workload.clone();
    for secret_name in &worker_runtime.image_pull_secrets {
        if !cloned.resources.contains_key(secret_name) {
            if let Some(resource) = entry_workload.resources.get(secret_name) {
                cloned
                    .resources
                    .insert(secret_name.clone(), resource.clone());
            }
        }
    }
    Some(cloned)
}

/// Aggregated output from compiling all roles.
struct CompiledRoles {
    role_templates: BTreeMap<String, RoleTemplates>,
    config: CompiledConfig,
    mesh_members: Vec<LatticeMeshMember>,
    tracing_policies: Vec<TracingPolicyNamespaced>,
}

/// Compile all roles (entry + optional worker workloads).
async fn compile_roles(
    name: &str,
    roles: &BTreeMap<String, lattice_common::crd::ModelRoleSpec>,
    ctx: &CompilationCtx<'_>,
) -> Result<CompiledRoles, ModelError> {
    let mut result = CompiledRoles {
        role_templates: BTreeMap::new(),
        config: CompiledConfig::default(),
        mesh_members: Vec::new(),
        tracing_policies: Vec::new(),
    };

    for (role_name, role_spec) in roles {
        role_spec
            .validate()
            .map_err(|e| ModelError::RoleValidation {
                role: role_name.clone(),
                message: e.to_string(),
            })?;

        let (entry_json, entry_config, entry_mm, entry_policies) = compile_workload(
            ctx,
            &entry_workload_name(name, role_name),
            &role_spec.entry_workload,
            &role_spec.entry_runtime,
            role_name,
        )
        .await?;

        result.config.merge(entry_config);
        result.mesh_members.extend(entry_mm);
        result.tracing_policies.extend(entry_policies);

        let worker_json = match role_spec.worker_workload {
            Some(ref worker_workload) => {
                let worker_runtime = role_spec
                    .worker_runtime
                    .as_ref()
                    .unwrap_or(&role_spec.entry_runtime);

                let effective = prepare_worker_workload(
                    worker_workload,
                    &role_spec.entry_workload,
                    worker_runtime,
                    role_spec.worker_runtime.is_some(),
                );
                let workload_ref = effective.as_ref().unwrap_or(worker_workload);

                let (template, config, mm, policies) = compile_workload(
                    ctx,
                    &worker_workload_name(name, role_name),
                    workload_ref,
                    worker_runtime,
                    &format!("{}-worker", role_name),
                )
                .await?;

                result.config.merge(config);
                result.mesh_members.extend(mm);
                result.tracing_policies.extend(policies);

                Some(template)
            }
            None => None,
        };

        result.role_templates.insert(
            role_name.clone(),
            RoleTemplates {
                entry_template: entry_json,
                worker_template: worker_json,
            },
        );
    }

    Ok(result)
}

/// Inject a downloader init container and cache volume into all role pod templates.
///
/// When `model_source` is set, each pod template gets:
/// - A cache volume (emptyDir, PVC, or hostPath based on `cache_uri`)
/// - A read-only volumeMount on all existing containers
/// - A downloader init container that downloads the model before serving starts
///
/// On model spec change, the init container args change → Kthena rolling update →
/// new pods download the new model → old pods serve until new pods are ready.
fn inject_model_download(
    source: Option<&ModelSourceSpec>,
    role_templates: &mut BTreeMap<String, RoleTemplates>,
) {
    let Some(source) = source else {
        return;
    };

    let mount_path = source.mount_path.as_deref().unwrap_or(DEFAULT_MOUNT_PATH);

    // Deterministic, collision-free download subdirectory
    let uri_hash = derived_name("", &[&source.uri]);
    let download_dir = format!("{}/{}", mount_path, uri_hash);

    let cache_volume = build_cache_volume(source);
    let init_container = build_init_container(source, &download_dir);

    let read_only_mount = serde_json::json!({
        "name": VOLUME_NAME,
        "mountPath": mount_path,
        "readOnly": true
    });

    let is_hf = source.uri.starts_with("hf://");

    for templates in role_templates.values_mut() {
        inject_into_template(
            &mut templates.entry_template,
            &cache_volume,
            &init_container,
            &read_only_mount,
            is_hf,
        );
        if let Some(ref mut worker) = templates.worker_template {
            inject_into_template(
                worker,
                &cache_volume,
                &init_container,
                &read_only_mount,
                is_hf,
            );
        }
    }
}

/// Inject cache volume, init container, dshm volume, and read-only mounts into a single pod template.
///
/// When `is_hf` is true, also injects `HF_HUB_OFFLINE=1` on serving containers
/// (not the init container) to prevent the HuggingFace client from making
/// network calls at runtime.
fn inject_into_template(
    template: &mut serde_json::Value,
    cache_volume: &serde_json::Value,
    init_container: &serde_json::Value,
    read_only_mount: &serde_json::Value,
    is_hf: bool,
) {
    let spec = &mut template["spec"];

    json_array_push(spec, "volumes", cache_volume.clone());
    json_array_push(
        spec,
        "volumes",
        serde_json::json!({"name": SCRATCH_VOLUME_NAME, "emptyDir": {}}),
    );
    // /dev/shm memory volume for NCCL multi-GPU communication
    json_array_push(
        spec,
        "volumes",
        serde_json::json!({"name": DSHM_VOLUME_NAME, "emptyDir": {"medium": "Memory"}}),
    );
    json_array_push(spec, "initContainers", init_container.clone());

    // Add read-only mount, dshm mount, and (for HF models) HF_HUB_OFFLINE=1 to all serving containers
    if let Some(containers) = spec.get_mut("containers").and_then(|v| v.as_array_mut()) {
        for container in containers {
            json_array_push(container, "volumeMounts", read_only_mount.clone());
            json_array_push(
                container,
                "volumeMounts",
                serde_json::json!({"name": DSHM_VOLUME_NAME, "mountPath": "/dev/shm"}),
            );
            if is_hf {
                json_array_push(
                    container,
                    "env",
                    serde_json::json!({"name": "HF_HUB_OFFLINE", "value": "1"}),
                );
            }
        }
    }
}

/// Build the cache volume JSON based on `cache_uri`.
fn build_cache_volume(source: &ModelSourceSpec) -> serde_json::Value {
    match source.cache_uri.as_deref() {
        Some(uri) if uri.starts_with("pvc://") => {
            let claim_name = &uri["pvc://".len()..];
            serde_json::json!({
                "name": VOLUME_NAME,
                "persistentVolumeClaim": {
                    "claimName": claim_name
                }
            })
        }
        Some(uri) if uri.starts_with("hostpath://") => {
            let path = &uri["hostpath://".len()..];
            serde_json::json!({
                "name": VOLUME_NAME,
                "hostPath": {
                    "path": path,
                    "type": "DirectoryOrCreate"
                }
            })
        }
        _ => {
            // emptyDir with optional sizeLimit
            let mut empty_dir = serde_json::json!({});
            if let Some(ref size) = source.cache_size {
                empty_dir["sizeLimit"] = serde_json::json!(size);
            }
            serde_json::json!({
                "name": VOLUME_NAME,
                "emptyDir": empty_dir
            })
        }
    }
}

/// Build the downloader init container JSON.
fn build_init_container(source: &ModelSourceSpec, download_dir: &str) -> serde_json::Value {
    let image = source
        .downloader_image
        .as_deref()
        .unwrap_or(DEFAULT_DOWNLOADER_IMAGE);

    let mount_path = source.mount_path.as_deref().unwrap_or(DEFAULT_MOUNT_PATH);

    let mut init = serde_json::json!({
        "name": INIT_CONTAINER_NAME,
        "image": image,
        "args": ["--source", &source.uri, "--output-dir", download_dir],
        "env": [{"name": "HOME", "value": "/home/downloader"}],
        "volumeMounts": [
            {
                "name": VOLUME_NAME,
                "mountPath": mount_path
            },
            {
                "name": SCRATCH_VOLUME_NAME,
                "mountPath": "/home/downloader"
            }
        ],
        "securityContext": {
            "runAsUser": 65534,
            "runAsNonRoot": true,
            "allowPrivilegeEscalation": false
        }
    });

    if let Some(ref token_secret) = source.token_secret {
        init["envFrom"] = serde_json::json!([{
            "secretRef": {
                "name": token_secret.name
            }
        }]);
    }

    init
}

/// Push a value onto a JSON array field, creating the array if absent.
///
/// Uses `get_mut` internally so it never inserts null keys — mutable indexing
/// on `serde_json::Value` silently inserts `Null` for missing keys, which
/// Kubernetes rejects on array-typed fields.
fn json_array_push(object: &mut serde_json::Value, key: &str, value: serde_json::Value) {
    if let Some(obj) = object.as_object_mut() {
        match obj.get_mut(key).and_then(|v| v.as_array_mut()) {
            Some(arr) => arr.push(value),
            None => {
                obj.insert(key.to_string(), serde_json::json!([value]));
            }
        }
    }
}

/// Inject model group label and ambient mesh opt-out into all pod templates.
fn inject_model_labels(name: &str, role_templates: &mut BTreeMap<String, RoleTemplates>) {
    let model_labels: &[(&str, &str)] = &[(LABEL_MODEL, name), ("istio.io/dataplane-mode", "none")];
    for templates in role_templates.values_mut() {
        lattice_workload::inject_pod_labels(&mut templates.entry_template, model_labels);
        if let Some(ref mut worker) = templates.worker_template {
            lattice_workload::inject_pod_labels(worker, model_labels);
        }
    }
}

/// Output from assembling ModelServing, routing, and autoscaling.
struct AssembledServing {
    model_serving: ModelServing,
    auto_topology: Option<lattice_common::crd::WorkloadNetworkTopology>,
    routing: Option<CompiledRouting>,
    autoscaling: Option<CompiledAutoscaling>,
}

/// Build ModelServing, routing, and autoscaling from compiled role templates.
fn assemble_serving(
    model: &LatticeModel,
    role_templates: &BTreeMap<String, RoleTemplates>,
    role_suffix: &str,
) -> Result<AssembledServing, ModelError> {
    let compilation = lattice_volcano::compile_model_serving(model, role_templates, role_suffix);
    let serving_name = &compilation.model_serving.metadata.name;

    let routing = model.spec.routing.as_ref().map(|routing_spec| {
        lattice_volcano::compile_model_routing(model, routing_spec, serving_name)
    });

    let autoscaling = {
        let compiled = lattice_volcano::compile_model_autoscaling(model);
        if compiled.policies.is_empty() {
            None
        } else {
            Some(compiled)
        }
    };

    Ok(AssembledServing {
        model_serving: compilation.model_serving,
        auto_topology: compilation.auto_topology,
        routing,
        autoscaling,
    })
}

/// Compile peer-discovery Services for P/D roles when kv_connector is active.
fn compile_peer_services(
    name: &str,
    namespace: &str,
    roles: &BTreeMap<String, lattice_common::crd::ModelRoleSpec>,
    routing: Option<&lattice_common::crd::ModelRoutingSpec>,
) -> Result<Vec<serde_json::Value>, ModelError> {
    if !has_pd_disaggregation(routing, roles) {
        return Ok(Vec::new());
    }

    let routing_spec = routing.expect("routing checked by has_pd_disaggregation");
    let inference_port = routing_spec.port.ok_or(ModelError::MissingInferencePort)?;
    let side_channel_port = routing_spec
        .kv_connector
        .as_ref()
        .and_then(|kv| kv.port)
        .unwrap_or(lattice_common::crd::DEFAULT_KV_SIDE_CHANNEL_PORT);

    Ok([PD_ROLE_PREFILL, PD_ROLE_DECODE]
        .iter()
        .map(|role| compile_peer_service(name, role, namespace, inference_port, side_channel_port))
        .collect())
}

/// Finalize mesh members: augment Kthena callers, opt out of ambient, set group selector,
/// and inject model download egress rules when a model source is configured.
fn finalize_mesh(
    name: &str,
    roles: &BTreeMap<String, lattice_common::crd::ModelRoleSpec>,
    routing: Option<&lattice_common::crd::ModelRoutingSpec>,
    has_autoscaling: bool,
    model_source: Option<&ModelSourceSpec>,
    mesh_members: &mut [LatticeMeshMember],
) -> Result<(), ModelError> {
    augment_kthena_callers(name, roles, routing, has_autoscaling, mesh_members)?;

    for mm in mesh_members.iter_mut() {
        mm.spec.ambient = false;
        mm.spec.target = lattice_common::crd::MeshMemberTarget::Selector(
            [(LABEL_MODEL.to_string(), name.to_string())]
                .into_iter()
                .collect(),
        );

        if let Some(source) = model_source {
            for fqdn in download_egress_fqdns(source) {
                mm.spec.egress.push(EgressRule {
                    target: EgressTarget::Fqdn(fqdn),
                    ports: vec![443],
                });
            }
        }
    }

    Ok(())
}

/// Return the FQDN(s) that the downloader init container needs to reach.
///
/// Derives defaults from the URI scheme, then merges any user-specified egress FQDNs:
/// - `hf://` → huggingface.co, cdn-lfs-us-1.hf.co, cdn-lfs.hf.co
/// - `s3://` → *.amazonaws.com
/// - `gs://` → storage.googleapis.com
fn download_egress_fqdns(source: &ModelSourceSpec) -> Vec<String> {
    if !source.egress.is_empty() {
        return source.egress.clone();
    }

    if source.uri.starts_with("hf://") {
        vec![
            "huggingface.co".to_string(),
            "cdn-lfs-us-1.hf.co".to_string(),
            "cdn-lfs.hf.co".to_string(),
            "cas-server.xethub.hf.co".to_string(),
            "transfer.xethub.hf.co".to_string(),
        ]
    } else if source.uri.starts_with("s3://") {
        vec!["*.amazonaws.com".to_string()]
    } else if source.uri.starts_with("gs://") {
        vec!["storage.googleapis.com".to_string()]
    } else {
        vec![]
    }
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
    let router_caller = routing.map(|_| kthena_caller(KTHENA_ROUTER_SA));

    let inference_port = routing
        .map(|r| r.port.ok_or(ModelError::MissingInferencePort))
        .transpose()?;

    let has_pd = has_pd_disaggregation(routing, roles);

    let autoscaler_caller = has_autoscaling.then(|| kthena_caller(KTHENA_AUTOSCALER_SA));

    for (role_name, role_spec) in roles {
        let entry_name = entry_workload_name(model_name, role_name);
        let worker_name = worker_workload_name(model_name, role_name);

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
    caller: &ServiceRef,
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
                &[],
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
    async fn model_source_injects_init_container() {
        let mut roles = BTreeMap::new();
        roles.insert("decode".to_string(), make_role("decoder:latest", 2));

        let spec = LatticeModelSpec {
            roles,
            model_source: Some(ModelSourceSpec {
                uri: "hf://Qwen/Qwen3-8B".to_string(),
                cache_uri: None,
                cache_size: Some("50Gi".to_string()),
                mount_path: None,
                token_secret: None,
                downloader_image: None,
                egress: vec![],
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

        // Verify init container + volume injected into pod templates
        let role = &compiled.model_serving.spec.template.roles[0];

        let init_containers = role.entry_template["spec"]["initContainers"]
            .as_array()
            .expect("initContainers should be set");
        assert!(
            init_containers
                .iter()
                .any(|c| c["name"] == "model-downloader"),
            "model-downloader init container should be present"
        );

        let volumes = role.entry_template["spec"]["volumes"]
            .as_array()
            .expect("volumes should be set");
        assert!(
            volumes.iter().any(|v| v["name"] == "model-cache"),
            "model-cache volume should be present"
        );

        // Verify read-only mount on existing containers
        let containers = role.entry_template["spec"]["containers"]
            .as_array()
            .expect("containers should be set");
        for c in containers {
            let mounts = c["volumeMounts"]
                .as_array()
                .expect("volumeMounts should exist");
            assert!(
                mounts
                    .iter()
                    .any(|m| m["name"] == "model-cache" && m["readOnly"] == true),
                "container should have read-only model-cache mount"
            );
            // /dev/shm mount for NCCL multi-GPU communication
            assert!(
                mounts
                    .iter()
                    .any(|m| m["name"] == "dshm" && m["mountPath"] == "/dev/shm"),
                "container should have /dev/shm mount"
            );
            // HF_HUB_OFFLINE=1 for HuggingFace models
            let env = c["env"].as_array().expect("env should exist");
            assert!(
                env.iter()
                    .any(|e| e["name"] == "HF_HUB_OFFLINE" && e["value"] == "1"),
                "container should have HF_HUB_OFFLINE=1"
            );
        }

        // Verify dshm volume exists
        assert!(
            volumes
                .iter()
                .any(|v| v["name"] == "dshm" && v["emptyDir"]["medium"] == "Memory"),
            "dshm memory volume should be present"
        );
    }

    #[tokio::test]
    async fn no_model_source_means_no_init_container() {
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

        // Verify no init container on pod templates
        let role = &compiled.model_serving.spec.template.roles[0];
        let init_containers = role.entry_template["spec"]
            .as_object()
            .and_then(|o| o.get("initContainers"))
            .and_then(|v| v.as_array());
        assert!(
            init_containers.is_none_or(|c| c.is_empty()),
            "no init containers when model_source is None"
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
