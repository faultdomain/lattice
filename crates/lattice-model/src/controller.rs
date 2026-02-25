//! LatticeModel controller implementation
//!
//! Reconciles LatticeModel resources through a state machine:
//! Pending → Loading → Serving | Failed
//!
//! Resources are applied in layers to prevent race conditions:
//! - Layer 0: Model download PVC + Job (only when modelSource is configured)
//! - Layer 1: ConfigMaps, Secrets, ExternalSecrets, PVCs, MeshMembers, TracingPolicies
//! - Layer 2: ModelServing (only after mesh/security is ready)
//! - Layer 3: Routing — ModelServer + ModelRoutes
//! - Layer 4a: Autoscaling — AutoscalingPolicy (must exist before bindings)
//! - Layer 4b: Autoscaling — AutoscalingPolicyBinding (references policies)
//!
//! When `modelSource` is set, pods are created with a `lattice.dev/model-download`
//! scheduling gate that keeps them `SchedulingGated` (zero resource usage, no GPU
//! allocation) until the download Job completes. The Loading phase checks Job status
//! and removes the gate on success.

use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, DynamicObject, Patch, PatchParams};
use kube::discovery::ApiResource;
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{error, info, warn};

use lattice_cedar::PolicyEngine;
use lattice_common::crd::{
    JobPhase, LatticeJob, LatticeModel, LatticeModelStatus, ModelCondition, ModelServingPhase,
    ProviderType,
};
use lattice_common::graph::ServiceGraph;
use lattice_common::kube_utils::ApplyBatch;
use lattice_common::status_check;
use lattice_common::{CrdKind, CrdRegistry};

use crate::compiler::{compile_model, CompiledModel};
use crate::download::{CompiledDownload, SCHEDULING_GATE_MODEL_DOWNLOAD};
use crate::error::ModelError;

const FIELD_MANAGER: &str = "lattice-model-controller";

/// Requeue interval while loading, downloading, or recompiling after spec change
const REQUEUE_LOADING: Duration = Duration::from_secs(15);
/// Requeue interval during steady-state serving (health monitoring)
const REQUEUE_SERVING: Duration = Duration::from_secs(60);
/// Requeue interval for fast retry after spec change in Failed state
const REQUEUE_RETRY: Duration = Duration::from_secs(5);
/// Requeue interval after a reconciliation error
const REQUEUE_ERROR: Duration = Duration::from_secs(30);

/// Shared context for the LatticeModel controller
pub struct ModelContext {
    pub client: Client,
    pub graph: Arc<ServiceGraph>,
    pub cluster_name: String,
    pub provider_type: ProviderType,
    pub cedar: Arc<PolicyEngine>,
    pub registry: Arc<CrdRegistry>,
}

impl ModelContext {
    pub fn new(
        client: Client,
        graph: Arc<ServiceGraph>,
        cluster_name: String,
        provider_type: ProviderType,
        cedar: Arc<PolicyEngine>,
        registry: Arc<CrdRegistry>,
    ) -> Self {
        Self {
            client,
            graph,
            cluster_name,
            provider_type,
            cedar,
            registry,
        }
    }
}

/// Reconcile a LatticeModel resource
pub async fn reconcile(
    model: Arc<LatticeModel>,
    ctx: Arc<ModelContext>,
) -> Result<Action, ModelError> {
    let name = model.name_any();
    let namespace = model
        .metadata
        .namespace
        .as_deref()
        .ok_or(ModelError::MissingNamespace)?;

    // Validate the model spec (all roles)
    model.spec.validate()?;

    let generation = model.metadata.generation.unwrap_or(0);
    let phase = model
        .status
        .as_ref()
        .map(|s| s.phase.clone())
        .unwrap_or(ModelServingPhase::Pending);

    match phase {
        ModelServingPhase::Pending => {
            let compiled = compile_model(
                &model,
                &ctx.graph,
                &ctx.cluster_name,
                ctx.provider_type,
                &ctx.cedar,
            )
            .await;

            let compiled = match compiled {
                Ok(c) => c,
                Err(e) => {
                    cleanup_graph(&model, &ctx.graph, namespace);
                    let msg = format!("Failed to compile: {}", e);
                    let _ = update_status(
                        &ctx.client,
                        &model,
                        namespace,
                        ModelServingPhase::Failed,
                        Some(&msg),
                        Some(generation),
                        None,
                    )
                    .await;
                    return Err(e);
                }
            };

            register_graph(&model, &ctx.graph, namespace);

            if let Err(e) = apply_compiled_model(&ctx.client, namespace, &compiled, &ctx).await {
                cleanup_graph(&model, &ctx.graph, namespace);
                let msg = format!("Apply failed (will retry): {}", e);
                // Stay in Pending — apply errors are transient (webhook not ready,
                // API server hiccup). error_policy requeues after REQUEUE_ERROR.
                // Changing phase would trigger a watch event → immediate reconcile
                // → tight Pending↔Failed flapping loop.
                let _ = update_status(
                    &ctx.client,
                    &model,
                    namespace,
                    ModelServingPhase::Pending,
                    Some(&msg),
                    None,
                    None,
                )
                .await;
                return Err(e);
            }
            update_status(
                &ctx.client,
                &model,
                namespace,
                ModelServingPhase::Loading,
                Some("Resources applied, waiting for model serving readiness"),
                Some(generation),
                None,
            )
            .await?;
            Ok(Action::requeue(REQUEUE_LOADING))
        }
        ModelServingPhase::Loading => {
            // When modelSource is configured, check download Job before ModelServing
            if model.spec.model_source.is_some() {
                let job_name = format!("{}-download", name);
                match check_download_job_status(&ctx.client, &job_name, namespace).await {
                    Some(DownloadState::Succeeded) => {
                        info!(model = %name, "model download job completed");
                        remove_scheduling_gates(&ctx.client, &name, namespace).await?;
                    }
                    Some(DownloadState::Failed { permanent }) => {
                        if permanent {
                            // VCJob ran and failed — permanent download failure
                            error!(model = %name, "model download job permanently failed");
                            cleanup_graph(&model, &ctx.graph, namespace);
                            update_status(
                                &ctx.client,
                                &model,
                                namespace,
                                ModelServingPhase::Failed,
                                Some("Model download failed"),
                                Some(generation),
                                None,
                            )
                            .await?;
                            return Ok(Action::await_change());
                        }
                        // LatticeJob is retrying (transient failure) — keep polling
                        info!(model = %name, "model download job retrying, waiting");
                        return Ok(Action::requeue(REQUEUE_LOADING));
                    }
                    Some(DownloadState::Running) => {
                        info!(model = %name, "model download in progress");
                        return Ok(Action::requeue(REQUEUE_LOADING));
                    }
                    None => {
                        warn!(model = %name, "download job not found, requeuing");
                        return Ok(Action::requeue(REQUEUE_LOADING));
                    }
                }
            }

            let (state, conditions) =
                check_model_serving_status(&ctx.client, &name, namespace, &ctx.registry).await;

            match state {
                ModelServingState::Available => {
                    info!(model = %name, "model serving is available");
                    update_status(
                        &ctx.client,
                        &model,
                        namespace,
                        ModelServingPhase::Serving,
                        Some("Model is serving inference requests"),
                        Some(generation),
                        conditions,
                    )
                    .await?;
                    Ok(Action::requeue(REQUEUE_SERVING))
                }
                ModelServingState::Failed => {
                    error!(model = %name, "model serving failed");
                    cleanup_graph(&model, &ctx.graph, namespace);
                    update_status(
                        &ctx.client,
                        &model,
                        namespace,
                        ModelServingPhase::Failed,
                        Some("ModelServing failed"),
                        Some(generation),
                        conditions,
                    )
                    .await?;
                    Ok(Action::await_change())
                }
                ModelServingState::Progressing => Ok(Action::requeue(REQUEUE_LOADING)),
            }
        }
        ModelServingPhase::Serving => {
            let observed = model.status.as_ref().and_then(|s| s.observed_generation);
            if observed != Some(generation) {
                // Spec changed — re-compile and re-apply
                info!(model = %name, observed = ?observed, current = generation, "spec changed, re-applying");
                let compiled = compile_model(
                    &model,
                    &ctx.graph,
                    &ctx.cluster_name,
                    ctx.provider_type,
                    &ctx.cedar,
                )
                .await?;
                register_graph(&model, &ctx.graph, namespace);
                apply_compiled_model(&ctx.client, namespace, &compiled, &ctx).await?;
                let conditions =
                    read_model_serving_conditions(&ctx.client, &name, namespace, &ctx.registry)
                        .await;
                update_status(
                    &ctx.client,
                    &model,
                    namespace,
                    ModelServingPhase::Serving,
                    Some("Model updated and serving"),
                    Some(generation),
                    conditions,
                )
                .await?;
                return Ok(Action::requeue(REQUEUE_LOADING));
            }

            // No spec change — monitor health via ModelServing conditions
            let message = "Model is serving inference requests";
            if status_check::is_status_unchanged(
                model.status.as_ref(),
                &ModelServingPhase::Serving,
                Some(message),
                Some(generation),
            ) {
                return Ok(Action::requeue(REQUEUE_SERVING));
            }
            let conditions =
                read_model_serving_conditions(&ctx.client, &name, namespace, &ctx.registry).await;
            update_status(
                &ctx.client,
                &model,
                namespace,
                ModelServingPhase::Serving,
                Some(message),
                Some(generation),
                conditions,
            )
            .await?;
            Ok(Action::requeue(REQUEUE_SERVING))
        }
        ModelServingPhase::Failed => {
            // Failed is only reached for permanent errors (compile failure,
            // ModelServing failure, permanent download failure). All set
            // observed_generation. Retry only if the user changed the spec.
            let observed = model.status.as_ref().and_then(|s| s.observed_generation);
            if observed != Some(generation) {
                info!(model = %name, observed = ?observed, current = generation, "spec changed while Failed, retrying");
                update_status(
                    &ctx.client,
                    &model,
                    namespace,
                    ModelServingPhase::Pending,
                    Some("Retrying after spec change"),
                    None,
                    None,
                )
                .await?;
                return Ok(Action::requeue(REQUEUE_RETRY));
            }
            Ok(Action::await_change())
        }
        _ => Ok(Action::await_change()),
    }
}

/// Register all model roles in the service graph for bilateral agreements
fn register_graph(model: &LatticeModel, graph: &ServiceGraph, namespace: &str) {
    let name = model.metadata.name.as_deref().unwrap_or_default();
    for (role_name, role_spec) in &model.spec.roles {
        graph.put_workload(
            namespace,
            &format!("{}-{}", name, role_name),
            &role_spec.entry_workload,
        );
    }
}

/// Remove model roles from the service graph on failure
fn cleanup_graph(model: &LatticeModel, graph: &ServiceGraph, namespace: &str) {
    let name = model.metadata.name.as_deref().unwrap_or_default();
    for role_name in model.spec.roles.keys() {
        graph.delete_service(namespace, &format!("{}-{}", name, role_name));
    }
}

/// Error policy for LatticeModel reconciliation
pub fn error_policy(
    model: Arc<LatticeModel>,
    error: &ModelError,
    _ctx: Arc<ModelContext>,
) -> Action {
    error!(
        ?error,
        model = %model.name_any(),
        "model reconciliation failed"
    );
    Action::requeue(REQUEUE_ERROR)
}

/// Apply compiled model resources in layers using ApplyBatch
async fn apply_compiled_model(
    client: &Client,
    namespace: &str,
    compiled: &CompiledModel,
    ctx: &ModelContext,
) -> Result<(), ModelError> {
    let params = PatchParams::apply(FIELD_MANAGER).force();

    lattice_common::kube_utils::ensure_namespace_ssa(client, namespace, FIELD_MANAGER).await?;

    let ms_api = ctx
        .registry
        .resolve(CrdKind::ModelServing)
        .await
        .ok_or(ModelError::KthenaCrdMissing)?;

    apply_layers(client, namespace, compiled, &ctx.registry, &ms_api, &params).await
}

async fn apply_layers(
    client: &Client,
    namespace: &str,
    compiled: &CompiledModel,
    registry: &CrdRegistry,
    ms_api: &ApiResource,
    params: &PatchParams,
) -> Result<(), ModelError> {
    // Layer 0: Model download (PVC + Job + MeshMember + SA) — only when modelSource is configured
    if let Some(ref download) = compiled.download {
        apply_download_resources(client, namespace, download, params).await?;
    }

    // Layer 1: Infrastructure (config, mesh, security, service accounts)
    let cm_ar = ApiResource::erase::<k8s_openapi::api::core::v1::ConfigMap>(&());
    let secret_ar = ApiResource::erase::<k8s_openapi::api::core::v1::Secret>(&());
    let pvc_ar = ApiResource::erase::<k8s_openapi::api::core::v1::PersistentVolumeClaim>(&());
    let sa_ar = ApiResource::erase::<k8s_openapi::api::core::v1::ServiceAccount>(&());

    let mut layer1 = ApplyBatch::new(client.clone(), namespace, params);

    // Create a ServiceAccount for each role (entry + worker templates)
    for role in &compiled.model_serving.spec.template.roles {
        if let Some(sa_name) = role.entry_template["spec"]["serviceAccountName"].as_str() {
            let sa = lattice_common::kube_utils::compile_service_account(sa_name, namespace);
            layer1.push("ServiceAccount", sa_name, &sa, &sa_ar)?;
        }
        if let Some(ref wt) = role.worker_template {
            if let Some(sa_name) = wt["spec"]["serviceAccountName"].as_str() {
                let sa = lattice_common::kube_utils::compile_service_account(sa_name, namespace);
                layer1.push("ServiceAccount", sa_name, &sa, &sa_ar)?;
            }
        }
    }

    for cm in &compiled.config.env_config_maps {
        layer1.push("ConfigMap", &cm.metadata.name, cm, &cm_ar)?;
    }
    for cm in &compiled.config.files_config_maps {
        layer1.push("ConfigMap", &cm.metadata.name, cm, &cm_ar)?;
    }
    for secret in &compiled.config.env_secrets {
        layer1.push("Secret", &secret.metadata.name, secret, &secret_ar)?;
    }
    for secret in &compiled.config.files_secrets {
        layer1.push("Secret", &secret.metadata.name, secret, &secret_ar)?;
    }
    let es_ar = registry.resolve(CrdKind::ExternalSecret).await;
    layer1.push_crd(
        "ExternalSecret",
        es_ar.as_ref(),
        &compiled.config.external_secrets,
        |es| &es.metadata.name,
    )?;
    for pvc in &compiled.config.pvcs {
        layer1.push("PersistentVolumeClaim", &pvc.metadata.name, pvc, &pvc_ar)?;
    }
    let mm_ar = registry.resolve(CrdKind::MeshMember).await;
    layer1.push_crd(
        "LatticeMeshMember",
        mm_ar.as_ref(),
        &compiled.mesh_members,
        |mm| mm.metadata.name.as_deref().unwrap_or("unknown"),
    )?;
    let tp_ar = registry.resolve(CrdKind::TracingPolicyNamespaced).await;
    layer1.push_crd(
        "TracingPolicyNamespaced",
        tp_ar.as_ref(),
        &compiled.tracing_policies,
        |tp| &tp.metadata.name,
    )?;

    layer1.run("layer-1-infrastructure").await?;

    // Layer 2: ModelServing (after mesh/security is ready)
    let mut layer2 = ApplyBatch::new(client.clone(), namespace, params);
    layer2.push(
        "ModelServing",
        &compiled.model_serving.metadata.name,
        &compiled.model_serving,
        ms_api,
    )?;
    layer2.run("layer-2-model-serving").await?;

    // Layer 3: Routing — ModelServer + ModelRoutes (after ModelServing pods are labeled)
    if let Some(ref routing) = compiled.routing {
        let mut layer3 = ApplyBatch::new(client.clone(), namespace, params);

        if let Some(ref ms_server_ar) = registry.resolve(CrdKind::KthenaModelServer).await {
            layer3.push(
                "ModelServer",
                &routing.model_server.metadata.name,
                &routing.model_server,
                ms_server_ar,
            )?;
        }

        if let Some(ref mr_ar) = registry.resolve(CrdKind::KthenaModelRoute).await {
            for route in &routing.model_routes {
                layer3.push("ModelRoute", &route.metadata.name, route, mr_ar)?;
            }
        }

        layer3.run("layer-3-routing").await?;
    }

    // Layer 4: Autoscaling — policies first, then bindings.
    // The Volcano admission webhook validates that the referenced AutoscalingPolicy
    // exists when an AutoscalingPolicyBinding is created, so policies must be
    // applied before bindings.
    if let Some(ref autoscaling) = compiled.autoscaling {
        if let Some(ref ap_ar) = registry.resolve(CrdKind::AutoscalingPolicy).await {
            let mut layer4a = ApplyBatch::new(client.clone(), namespace, params);
            for policy in &autoscaling.policies {
                layer4a.push("AutoscalingPolicy", &policy.metadata.name, policy, ap_ar)?;
            }
            layer4a.run("layer-4a-autoscaling-policies").await?;
        }

        if let Some(ref apb_ar) = registry.resolve(CrdKind::AutoscalingPolicyBinding).await {
            let mut layer4b = ApplyBatch::new(client.clone(), namespace, params);
            for binding in &autoscaling.bindings {
                layer4b.push(
                    "AutoscalingPolicyBinding",
                    &binding.metadata.name,
                    binding,
                    apb_ar,
                )?;
            }
            layer4b.run("layer-4b-autoscaling-bindings").await?;
        }
    }

    info!(
        namespace = %namespace,
        model_serving = %compiled.model_serving.metadata.name,
        mesh_members = compiled.mesh_members.len(),
        tracing_policies = compiled.tracing_policies.len(),
        has_routing = compiled.routing.is_some(),
        has_autoscaling = compiled.autoscaling.is_some(),
        has_download = compiled.download.is_some(),
        "applied compiled model resources"
    );

    Ok(())
}

enum ModelServingState {
    Available,
    Failed,
    Progressing,
}

/// Read conditions from a ModelServing resource and convert to ModelCondition structs.
async fn read_model_serving_conditions(
    client: &Client,
    name: &str,
    namespace: &str,
    registry: &CrdRegistry,
) -> Option<Vec<ModelCondition>> {
    let ms_api = registry.resolve(CrdKind::ModelServing).await?;
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ms_api);

    match api.get(name).await {
        Ok(obj) => {
            let raw_conditions = obj
                .data
                .get("status")
                .and_then(|s| s.get("conditions"))
                .and_then(|c| c.as_array())?;

            let conditions: Vec<ModelCondition> = raw_conditions
                .iter()
                .filter_map(|c| {
                    Some(ModelCondition {
                        type_: c.get("type")?.as_str()?.to_string(),
                        status: c.get("status")?.as_str()?.to_string(),
                        reason: c
                            .get("reason")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        message: c
                            .get("message")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        last_transition_time: c
                            .get("lastTransitionTime")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                    })
                })
                .collect();

            if conditions.is_empty() {
                None
            } else {
                Some(conditions)
            }
        }
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            warn!(model = %name, "ModelServing not found");
            None
        }
        Err(e) => {
            warn!(model = %name, error = %e, "failed to read ModelServing conditions");
            None
        }
    }
}

/// Derive the high-level ModelServing state from its conditions.
fn derive_model_serving_state(conditions: Option<&[ModelCondition]>) -> ModelServingState {
    if let Some(conditions) = conditions {
        for cond in conditions {
            match (cond.type_.as_str(), cond.status.as_str()) {
                ("Available", "True") => return ModelServingState::Available,
                ("Failed", "True") => return ModelServingState::Failed,
                _ => {}
            }
        }
    }
    ModelServingState::Progressing
}

async fn check_model_serving_status(
    client: &Client,
    name: &str,
    namespace: &str,
    registry: &CrdRegistry,
) -> (ModelServingState, Option<Vec<ModelCondition>>) {
    let conditions = read_model_serving_conditions(client, name, namespace, registry).await;
    let state = derive_model_serving_state(conditions.as_deref());
    (state, conditions)
}

/// Apply model download resources (PVC + ServiceAccount + LatticeJob) as Layer 0.
///
/// The PVC is owned by the LatticeModel (for GC cascading). The LatticeJob
/// references the PVC as a volume. The LatticeJob controller handles mesh
/// member generation (entity egress) through the normal compilation pipeline.
async fn apply_download_resources(
    client: &Client,
    namespace: &str,
    download: &CompiledDownload,
    params: &PatchParams,
) -> Result<(), ModelError> {
    let pvc_ar = ApiResource::erase::<k8s_openapi::api::core::v1::PersistentVolumeClaim>(&());
    let sa_ar = ApiResource::erase::<k8s_openapi::api::core::v1::ServiceAccount>(&());

    // Layer 0a: PVC + ServiceAccount (must exist before LatticeJob references them)
    let mut layer0a = ApplyBatch::new(client.clone(), namespace, params);

    layer0a.push(
        "ServiceAccount",
        download.job_name(),
        &download.service_account,
        &sa_ar,
    )?;

    layer0a.push(
        "PersistentVolumeClaim",
        download.pvc_name(),
        &download.pvc,
        &pvc_ar,
    )?;

    layer0a.run("layer-0a-download-infra").await?;

    // Layer 0b: LatticeJob (after PVC exists so the volume reference resolves)
    let lj_api: Api<LatticeJob> = Api::namespaced(client.clone(), namespace);
    lj_api
        .patch(download.job_name(), params, &Patch::Apply(&download.job))
        .await?;

    info!(
        pvc = %download.pvc_name(),
        job = %download.job_name(),
        mount_path = %download.mount_path(),
        "applied model download resources (Layer 0)"
    );

    Ok(())
}

enum DownloadState {
    Succeeded,
    /// Download job failed. `permanent` is true when the underlying VCJob
    /// actually ran and failed (observed_generation set), false when the
    /// failure was transient (webhook not ready, etc.) and the LatticeJob
    /// controller will retry automatically.
    Failed {
        permanent: bool,
    },
    Running,
}

/// Check the status of a model download LatticeJob
async fn check_download_job_status(
    client: &Client,
    name: &str,
    namespace: &str,
) -> Option<DownloadState> {
    let jobs: Api<LatticeJob> = Api::namespaced(client.clone(), namespace);

    match jobs.get(name).await {
        Ok(job) => {
            let status = job.status.as_ref()?;
            match &status.phase {
                JobPhase::Succeeded => Some(DownloadState::Succeeded),
                JobPhase::Failed => {
                    // Permanent if observed_generation is set (VCJob ran and failed).
                    // Transient if None (apply error, webhook not ready — LatticeJob retries).
                    let permanent = status.observed_generation.is_some();
                    Some(DownloadState::Failed { permanent })
                }
                JobPhase::Pending | JobPhase::Running | _ => Some(DownloadState::Running),
            }
        }
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            warn!(job = %name, "download LatticeJob not found");
            None
        }
        Err(e) => {
            warn!(job = %name, error = %e, "failed to check download LatticeJob status");
            None
        }
    }
}

/// Remove the model-download scheduling gate from all ModelServing pods.
///
/// Lists pods by the `modelserving.volcano.sh/name` label and patches each
/// one that has the `lattice.dev/model-download` gate to remove it, allowing
/// the kube-scheduler to schedule them.
async fn remove_scheduling_gates(
    client: &Client,
    model_name: &str,
    namespace: &str,
) -> Result<(), ModelError> {
    use kube::api::ListParams;

    let pods: Api<k8s_openapi::api::core::v1::Pod> = Api::namespaced(client.clone(), namespace);
    let lp = ListParams::default().labels(&format!("modelserving.volcano.sh/name={}", model_name));

    let pod_list = pods.list(&lp).await?;
    let mut removed = 0u32;

    for pod in &pod_list {
        let pod_name = pod.metadata.name.as_deref().unwrap_or_default();
        let has_gate = pod
            .spec
            .as_ref()
            .and_then(|s| s.scheduling_gates.as_ref())
            .is_some_and(|gates| {
                gates
                    .iter()
                    .any(|g| g.name == SCHEDULING_GATE_MODEL_DOWNLOAD)
            });

        if has_gate {
            // Remove the scheduling gate via JSON merge patch
            let new_gates: Vec<&k8s_openapi::api::core::v1::PodSchedulingGate> = pod
                .spec
                .as_ref()
                .and_then(|s| s.scheduling_gates.as_ref())
                .map(|gates| {
                    gates
                        .iter()
                        .filter(|g| g.name != SCHEDULING_GATE_MODEL_DOWNLOAD)
                        .collect()
                })
                .unwrap_or_default();

            let patch = if new_gates.is_empty() {
                serde_json::json!({ "spec": { "schedulingGates": null } })
            } else {
                serde_json::json!({ "spec": { "schedulingGates": new_gates } })
            };

            match pods
                .patch(pod_name, &PatchParams::default(), &Patch::Merge(&patch))
                .await
            {
                Ok(_) => {
                    removed += 1;
                    info!(pod = %pod_name, "removed model-download scheduling gate");
                }
                Err(e) => {
                    warn!(pod = %pod_name, error = %e, "failed to remove scheduling gate");
                }
            }
        }
    }

    if removed > 0 {
        info!(model = %model_name, count = removed, "removed scheduling gates from pods");
    }

    Ok(())
}

async fn update_status(
    client: &Client,
    model: &LatticeModel,
    namespace: &str,
    phase: ModelServingPhase,
    message: Option<&str>,
    observed_generation: Option<i64>,
    conditions: Option<Vec<ModelCondition>>,
) -> Result<(), ModelError> {
    // Skip redundant writes when not updating conditions.
    // Condition updates (from ModelServing health checks) always write through.
    if conditions.is_none()
        && status_check::is_status_unchanged(
            model.status.as_ref(),
            &phase,
            message,
            observed_generation,
        )
    {
        return Ok(());
    }

    let name = model.name_any();
    let status = LatticeModelStatus {
        phase,
        message: message.map(|m| m.to_string()),
        observed_generation,
        conditions,
    };
    lattice_common::kube_utils::patch_resource_status::<LatticeModel>(
        client,
        &name,
        namespace,
        &status,
        FIELD_MANAGER,
    )
    .await?;
    Ok(())
}
