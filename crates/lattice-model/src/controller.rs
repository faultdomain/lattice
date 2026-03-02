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

use kube::api::{Api, DeleteParams, DynamicObject, Patch, PatchParams};
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
use lattice_common::{CrdKind, CrdRegistry, Retryable};

use crate::compiler::{compile_model, role_key_suffix, CompiledModel};
use crate::download::{CompiledDownload, SCHEDULING_GATE_MODEL_DOWNLOAD};
use crate::error::ModelError;

const FIELD_MANAGER: &str = "lattice-model-controller";

/// Requeue interval while loading, downloading, or recompiling after spec change
const REQUEUE_LOADING: Duration = Duration::from_secs(15);
/// Requeue interval during steady-state serving (health monitoring)
const REQUEUE_SERVING: Duration = Duration::from_secs(60);
/// Requeue interval for fast retry after spec change in Failed state
const REQUEUE_RETRY: Duration = Duration::from_secs(5);
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

    // Snapshot role keys BEFORE refreshing the graph. register_graph
    // overwrites the graph with the NEW spec's roles, so capturing
    // after would lose the diff needed to detect removed roles.
    let pre_register_role_keys = current_graph_role_keys(&ctx.graph, &name, namespace);

    // Always ensure roles are in the graph (crash recovery).
    // After a controller restart the in-memory graph is empty, so
    // current_graph_role_keys() would return nothing and removed roles
    // would go undetected during spec-change cleanup.
    register_graph(&model, &ctx.graph, namespace);

    let generation = model.metadata.generation.unwrap_or(0);
    let suffix = role_key_suffix(model.spec.roles.keys());
    let serving_name = format!("{}-{}", name, suffix);
    let phase = model
        .status
        .as_ref()
        .map(|s| s.phase.clone())
        .unwrap_or(ModelServingPhase::Pending);

    // Kthena may create new pods (scale-up, worker addition) after the initial
    // gate removal in Loading. Run gate removal on every reconcile past Pending
    // when the download job has completed, so late-arriving pods get ungated.
    if model.spec.model_source.is_some() && phase != ModelServingPhase::Pending {
        let job_name = format!("{}-download", name);
        if matches!(
            check_download_job_status(&ctx.client, &job_name, namespace).await,
            Some(DownloadState::Succeeded)
        ) {
            remove_scheduling_gates(&ctx.client, &serving_name, namespace).await?;
        }
    }

    match phase {
        ModelServingPhase::Pending => {
            let compiled = compile_model(
                &model,
                &ctx.graph,
                &ctx.cluster_name,
                ctx.provider_type,
                &ctx.cedar,
                &suffix,
            )
            .await;

            let compiled = match compiled {
                Ok(c) => c,
                Err(e) => {
                    if e.is_retryable() {
                        // Transient — stay in Pending so error_policy retries
                        let msg = format!("Compile failed (will retry): {}", e);
                        let _ = StatusUpdate::new(ModelServingPhase::Pending)
                            .message(&msg)
                            .apply(&ctx.client, &model, namespace)
                            .await;
                    } else {
                        // Permanent — go to Failed
                        cleanup_graph(&model, &ctx.graph, namespace);
                        let msg = format!("Failed to compile: {}", e);
                        let _ = StatusUpdate::new(ModelServingPhase::Failed)
                            .message(&msg)
                            .observed_generation(generation)
                            .apply(&ctx.client, &model, namespace)
                            .await;
                    }
                    return Err(e);
                }
            };

            register_graph(&model, &ctx.graph, namespace);

            if let Err(e) = apply_compiled_model(&ctx.client, namespace, &compiled, &ctx).await {
                cleanup_graph(&model, &ctx.graph, namespace);
                let msg = format!("Apply failed (will retry): {}", e);
                // Stay in Pending — apply errors are transient (webhook not ready,
                // API server hiccup). error_policy requeues after 30s.
                let _ = StatusUpdate::new(ModelServingPhase::Pending)
                    .message(&msg)
                    .apply(&ctx.client, &model, namespace)
                    .await;
                return Err(e);
            }
            StatusUpdate::new(ModelServingPhase::Loading)
                .message("Resources applied, waiting for model serving readiness")
                .observed_generation(generation)
                .auto_topology(compiled.auto_topology)
                .apply(&ctx.client, &model, namespace)
                .await?;
            Ok(Action::requeue(REQUEUE_LOADING))
        }
        ModelServingPhase::Loading => {
            // Check if the spec changed since we compiled in Pending. If so,
            // go back to Pending to recompile with the new spec. Without this
            // check, Loading→Serving would stamp the new generation despite
            // running resources compiled from the old spec.
            if spec_changed_since_compilation(model.status.as_ref(), generation) {
                info!(model = %name, "spec changed during Loading, recompiling");
                StatusUpdate::new(ModelServingPhase::Pending)
                    .message("Spec changed, recompiling")
                    .apply(&ctx.client, &model, namespace)
                    .await?;
                return Ok(Action::requeue(REQUEUE_RETRY));
            }

            // When modelSource is configured, check download Job before ModelServing.
            // Gate removal already happened above (pre-phase); here we only gate on
            // the download status to block ModelServing readiness checks.
            if model.spec.model_source.is_some() {
                let job_name = format!("{}-download", name);
                match check_download_job_status(&ctx.client, &job_name, namespace).await {
                    Some(DownloadState::Succeeded) => {
                        info!(model = %name, "model download job completed");
                    }
                    Some(DownloadState::Failed { permanent }) => {
                        if permanent {
                            // VCJob ran and failed — permanent download failure
                            error!(model = %name, "model download job permanently failed");
                            cleanup_graph(&model, &ctx.graph, namespace);
                            StatusUpdate::new(ModelServingPhase::Failed)
                                .message("Model download failed")
                                .observed_generation(generation)
                                .apply(&ctx.client, &model, namespace)
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
                check_model_serving_status(&ctx.client, &serving_name, namespace, &ctx.registry)
                    .await;

            match state {
                ModelServingState::Available => {
                    info!(model = %name, "model serving is available");
                    let mut s = StatusUpdate::new(ModelServingPhase::Serving)
                        .message("Model is serving inference requests")
                        .observed_generation(generation);
                    if let Some(c) = conditions {
                        s = s.conditions(c);
                    }
                    s.apply(&ctx.client, &model, namespace).await?;
                    Ok(Action::requeue(REQUEUE_SERVING))
                }
                ModelServingState::Failed => {
                    error!(model = %name, "model serving failed");
                    cleanup_graph(&model, &ctx.graph, namespace);
                    let mut s = StatusUpdate::new(ModelServingPhase::Failed)
                        .message("ModelServing failed")
                        .observed_generation(generation);
                    if let Some(c) = conditions {
                        s = s.conditions(c);
                    }
                    s.apply(&ctx.client, &model, namespace).await?;
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

                // Use the pre-register snapshot captured before register_graph
                // overwrote the graph with the new spec's roles.
                let old_role_keys = pre_register_role_keys.clone();
                let new_role_keys = spec_role_keys(&name, &model.spec.roles);

                let compiled = match compile_model(
                    &model,
                    &ctx.graph,
                    &ctx.cluster_name,
                    ctx.provider_type,
                    &ctx.cedar,
                    &suffix,
                )
                .await
                {
                    Ok(c) => c,
                    Err(e) => {
                        if e.is_retryable() {
                            // Transient — stay in Serving, let error_policy retry
                            let msg = format!("Recompile failed (will retry): {}", e);
                            let mut s = StatusUpdate::new(ModelServingPhase::Serving).message(&msg);
                            if let Some(gen) = observed {
                                s = s.observed_generation(gen);
                            }
                            let _ = s.apply(&ctx.client, &model, namespace).await;
                        } else {
                            // Permanent — go to Failed
                            cleanup_graph(&model, &ctx.graph, namespace);
                            let msg = format!("Failed to recompile after spec change: {}", e);
                            let _ = StatusUpdate::new(ModelServingPhase::Failed)
                                .message(&msg)
                                .observed_generation(generation)
                                .apply(&ctx.client, &model, namespace)
                                .await;
                        }
                        return Err(e);
                    }
                };
                register_graph(&model, &ctx.graph, namespace);

                // Clean up graph nodes and K8s resources for removed roles
                cleanup_removed_roles(
                    &ctx.client,
                    &ctx.graph,
                    &ctx.registry,
                    &name,
                    namespace,
                    &old_role_keys,
                    &new_role_keys,
                )
                .await;

                // When roles are added or removed, the gang policy's
                // minRoleReplicas key set changes. Volcano marks that field
                // immutable, so an SSA update would 422. Delete the old
                // ModelServing and requeue — the old PodGroup and pods need
                // time to be garbage-collected. Applying immediately would
                // SSA-patch the Terminating resource or create a PodGroup
                // name collision, leaving decode pods stuck in Pending.
                //
                // On the next reconcile, register_graph (above) has already
                // updated the graph so old_role_keys == new_role_keys, the
                // delete is skipped, and apply_compiled_model creates a
                // clean new ModelServing.
                if old_role_keys != new_role_keys {
                    delete_model_serving(&ctx.client, &ctx.registry, &name, namespace).await?;
                    info!(model = %name, "deleted ModelServing for role change, requeuing for clean recreate");
                    return Ok(Action::requeue(REQUEUE_LOADING));
                }

                if let Err(e) = apply_compiled_model(&ctx.client, namespace, &compiled, &ctx).await
                {
                    // Apply errors are transient — stay in Serving, let
                    // error_policy retry. Keep the old observed_generation so
                    // the next reconcile re-enters this recompile path.
                    let msg = format!("Apply failed after spec change (will retry): {}", e);
                    let mut s = StatusUpdate::new(ModelServingPhase::Serving).message(&msg);
                    if let Some(gen) = observed {
                        s = s.observed_generation(gen);
                    }
                    let _ = s.apply(&ctx.client, &model, namespace).await;
                    return Err(e);
                }
                // Transition to Loading so the next reconcile checks the
                // download job and removes scheduling gates on new pods.
                // Staying in Serving would skip gate removal (only in Loading).
                StatusUpdate::new(ModelServingPhase::Loading)
                    .message("Spec changed, reloading")
                    .observed_generation(generation)
                    .auto_topology(compiled.auto_topology)
                    .apply(&ctx.client, &model, namespace)
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
                read_model_serving_conditions(&ctx.client, &serving_name, namespace, &ctx.registry)
                    .await;
            let mut s = StatusUpdate::new(ModelServingPhase::Serving)
                .message(message)
                .observed_generation(generation);
            if let Some(c) = conditions {
                s = s.conditions(c);
            }
            s.apply(&ctx.client, &model, namespace).await?;
            Ok(Action::requeue(REQUEUE_SERVING))
        }
        ModelServingPhase::Failed => {
            // Periodically retry Failed models. If the spec changed, go back
            // to Pending for a full recompile. Otherwise just requeue — the
            // error may have been transient (CRD not installed yet, API blip).
            let observed = model.status.as_ref().and_then(|s| s.observed_generation);
            if observed != Some(generation) {
                info!(model = %name, observed = ?observed, current = generation, "spec changed while Failed, retrying");
                StatusUpdate::new(ModelServingPhase::Pending)
                    .message("Retrying after spec change")
                    .apply(&ctx.client, &model, namespace)
                    .await?;
                return Ok(Action::requeue(REQUEUE_RETRY));
            }
            Ok(Action::requeue(Duration::from_secs(30)))
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

/// Compute the set of role graph keys (e.g. "llm-serving-prefill") from the spec.
fn spec_role_keys(
    model_name: &str,
    roles: &std::collections::BTreeMap<String, lattice_common::crd::ModelRoleSpec>,
) -> std::collections::BTreeSet<String> {
    roles
        .keys()
        .map(|r| format!("{}-{}", model_name, r))
        .collect()
}

/// Compute the set of role graph keys currently in the graph for a model.
///
/// Enumerates all services in the namespace and filters by the model name prefix.
/// This captures roles that were registered in a previous reconcile but may have
/// been removed from the spec.
fn current_graph_role_keys(
    graph: &ServiceGraph,
    model_name: &str,
    namespace: &str,
) -> std::collections::BTreeSet<String> {
    let prefix = format!("{}-", model_name);
    graph
        .list_services(namespace)
        .into_iter()
        .filter(|node| node.name.starts_with(&prefix))
        .map(|node| node.name)
        .collect()
}

/// Clean up graph nodes and K8s resources for roles that were removed from the spec.
///
/// When a model spec changes from e.g. {prefill, decode} to {decode}, the old
/// "prefill" graph node persists (affecting bilateral agreements) and the old
/// LatticeMeshMember resource persists (keeping stale policies).
async fn cleanup_removed_roles(
    client: &Client,
    graph: &ServiceGraph,
    registry: &CrdRegistry,
    model_name: &str,
    namespace: &str,
    old_role_names: &std::collections::BTreeSet<String>,
    new_role_names: &std::collections::BTreeSet<String>,
) {
    let removed: Vec<&String> = old_role_names.difference(new_role_names).collect();
    if removed.is_empty() {
        return;
    }

    info!(model = %model_name, removed = ?removed, "cleaning up removed role resources");

    for role_key in &removed {
        // Remove from service graph
        graph.delete_service(namespace, role_key);

        // Delete orphaned LatticeMeshMember
        match registry.resolve(CrdKind::MeshMember).await {
            Ok(Some(mm_ar)) => {
                if let Err(e) = lattice_common::kube_utils::delete_resource_if_exists(
                    client,
                    namespace,
                    &mm_ar,
                    role_key,
                    "LatticeMeshMember",
                )
                .await
                {
                    warn!(name = %role_key, error = %e, "failed to delete orphaned MeshMember");
                }
            }
            Ok(None) => {}
            Err(e) => {
                warn!(name = %role_key, error = %e, "CRD discovery failed during orphan cleanup");
            }
        }

        // Delete orphaned peer-discovery Service
        let svc_ar = ApiResource::erase::<k8s_openapi::api::core::v1::Service>(&());
        if let Err(e) = lattice_common::kube_utils::delete_resource_if_exists(
            client, namespace, &svc_ar, role_key, "Service",
        )
        .await
        {
            warn!(name = %role_key, error = %e, "failed to delete orphaned peer Service");
        }
    }
}

/// Delete all ModelServing resources owned by a LatticeModel.
///
/// Uses label-based listing (`app.kubernetes.io/name`) to find ModelServings
/// regardless of their role-suffix. This handles the case where the role set
/// changes and the new ModelServing has a different name suffix.
///
/// Volcano marks `gangPolicy.minRoleReplicas` as immutable. When the role set
/// changes (roles added or removed), an SSA update would get a 422. Deleting
/// first lets the re-apply create a fresh resource with the new suffix.
async fn delete_model_serving(
    client: &Client,
    registry: &CrdRegistry,
    model_name: &str,
    namespace: &str,
) -> Result<(), ModelError> {
    let Some(ms_ar) = registry.resolve(CrdKind::ModelServing).await? else {
        return Ok(());
    };
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ms_ar);
    let lp =
        kube::api::ListParams::default().labels(&format!("app.kubernetes.io/name={model_name}"));
    let list = api.list(&lp).await?;
    for ms in list.items {
        let ms_name = ms.name_any();
        match api.delete(&ms_name, &DeleteParams::default()).await {
            Ok(_) => {
                info!(model = %model_name, serving = %ms_name, "deleted ModelServing")
            }
            Err(kube::Error::Api(ref resp)) if resp.code == 404 => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Apply compiled model resources in layers using ApplyBatch
async fn apply_compiled_model(
    client: &Client,
    namespace: &str,
    compiled: &CompiledModel,
    ctx: &ModelContext,
) -> Result<(), ModelError> {
    let params = PatchParams::apply(FIELD_MANAGER).force();

    lattice_common::kube_utils::ensure_namespace(client, namespace, None, FIELD_MANAGER).await?;

    let ms_api = ctx
        .registry
        .resolve(CrdKind::ModelServing)
        .await?
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
    let es_ar = registry.resolve(CrdKind::ExternalSecret).await?;
    layer1.push_crd(
        "ExternalSecret",
        es_ar.as_ref(),
        &compiled.config.external_secrets,
        |es| &es.metadata.name,
    )?;
    for pvc in &compiled.config.pvcs {
        layer1.push("PersistentVolumeClaim", &pvc.metadata.name, pvc, &pvc_ar)?;
    }
    let mm_ar = registry.resolve(CrdKind::MeshMember).await?;
    layer1.push_crd(
        "LatticeMeshMember",
        mm_ar.as_ref(),
        &compiled.mesh_members,
        |mm| mm.metadata.name.as_deref().unwrap_or("unknown"),
    )?;
    let tp_ar = registry.resolve(CrdKind::TracingPolicyNamespaced).await?;
    layer1.push_crd(
        "TracingPolicyNamespaced",
        tp_ar.as_ref(),
        &compiled.tracing_policies,
        |tp| &tp.metadata.name,
    )?;
    let svc_ar = ApiResource::erase::<k8s_openapi::api::core::v1::Service>(&());
    for svc in &compiled.peer_services {
        let svc_name = svc["metadata"]["name"]
            .as_str()
            .unwrap_or("unknown-peer-svc");
        layer1.push("Service", svc_name, svc, &svc_ar)?;
    }

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

        if let Some(ref ms_server_ar) = registry.resolve(CrdKind::KthenaModelServer).await? {
            layer3.push(
                "ModelServer",
                &routing.model_server.metadata.name,
                &routing.model_server,
                ms_server_ar,
            )?;
        }

        if let Some(ref mr_ar) = registry.resolve(CrdKind::KthenaModelRoute).await? {
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
        if let Some(ref ap_ar) = registry.resolve(CrdKind::AutoscalingPolicy).await? {
            let mut layer4a = ApplyBatch::new(client.clone(), namespace, params);
            for policy in &autoscaling.policies {
                layer4a.push("AutoscalingPolicy", &policy.metadata.name, policy, ap_ar)?;
            }
            layer4a.run("layer-4a-autoscaling-policies").await?;
        }

        if let Some(ref apb_ar) = registry.resolve(CrdKind::AutoscalingPolicyBinding).await? {
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
    let ms_api = match registry.resolve(CrdKind::ModelServing).await {
        Ok(Some(ar)) => ar,
        Ok(None) => return None,
        Err(e) => {
            warn!(error = %e, "CRD discovery failed reading ModelServing conditions");
            return None;
        }
    };
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
    let sa_ar = ApiResource::erase::<k8s_openapi::api::core::v1::ServiceAccount>(&());

    // Layer 0a: ServiceAccount (must exist before LatticeJob pod references it)
    let mut layer0a = ApplyBatch::new(client.clone(), namespace, params);

    layer0a.push(
        "ServiceAccount",
        download.job_name(),
        &download.service_account,
        &sa_ar,
    )?;

    layer0a.run("layer-0a-download-infra").await?;

    // Layer 0b: LatticeJob (the job compiler's VolumeCompiler creates the PVC
    // with ownerReferences forwarded from the LatticeJob metadata)
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
///
/// `serving_name` must be the ModelServing resource name (model name + role suffix),
/// since Kthena labels pods with `modelserving.volcano.sh/name={ModelServing.metadata.name}`.
async fn remove_scheduling_gates(
    client: &Client,
    serving_name: &str,
    namespace: &str,
) -> Result<(), ModelError> {
    use kube::api::ListParams;

    let pods: Api<k8s_openapi::api::core::v1::Pod> = Api::namespaced(client.clone(), namespace);
    let lp =
        ListParams::default().labels(&format!("modelserving.volcano.sh/name={}", serving_name));

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
        info!(serving = %serving_name, count = removed, "removed scheduling gates from pods");
    }

    Ok(())
}

/// Check if the spec changed since the last compilation.
///
/// Returns `true` if `observed_generation` (set when resources were last compiled)
/// doesn't match the current `metadata.generation`. This means the user has updated
/// the spec and the controller needs to re-compile.
fn spec_changed_since_compilation(status: Option<&LatticeModelStatus>, generation: i64) -> bool {
    let observed = status.and_then(|s| s.observed_generation);
    observed != Some(generation)
}

/// Status update builder — avoids long parameter lists and makes optional fields explicit.
struct StatusUpdate<'a> {
    phase: ModelServingPhase,
    message: Option<&'a str>,
    observed_generation: Option<i64>,
    conditions: Option<Vec<ModelCondition>>,
    auto_topology: Option<lattice_common::crd::WorkloadNetworkTopology>,
}

impl<'a> StatusUpdate<'a> {
    fn new(phase: ModelServingPhase) -> Self {
        Self {
            phase,
            message: None,
            observed_generation: None,
            conditions: None,
            auto_topology: None,
        }
    }

    fn message(mut self, msg: &'a str) -> Self {
        self.message = Some(msg);
        self
    }

    fn observed_generation(mut self, gen: i64) -> Self {
        self.observed_generation = Some(gen);
        self
    }

    fn conditions(mut self, conditions: Vec<ModelCondition>) -> Self {
        self.conditions = Some(conditions);
        self
    }

    fn auto_topology(mut self, topo: Option<lattice_common::crd::WorkloadNetworkTopology>) -> Self {
        self.auto_topology = topo;
        self
    }

    async fn apply(
        self,
        client: &Client,
        model: &LatticeModel,
        namespace: &str,
    ) -> Result<(), ModelError> {
        // Skip redundant writes when not updating conditions or auto_topology.
        // Condition updates (from ModelServing health checks) always write through.
        if self.conditions.is_none()
            && self.auto_topology.is_none()
            && status_check::is_status_unchanged(
                model.status.as_ref(),
                &self.phase,
                self.message,
                self.observed_generation,
            )
        {
            return Ok(());
        }

        let name = model.name_any();
        // Preserve auto_topology from existing status unless explicitly overridden
        let auto_topology = self
            .auto_topology
            .or_else(|| model.status.as_ref().and_then(|s| s.auto_topology.clone()));
        let status = LatticeModelStatus {
            phase: self.phase,
            message: self.message.map(|m| m.to_string()),
            observed_generation: self.observed_generation,
            conditions: self.conditions,
            auto_topology,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_status(
        phase: ModelServingPhase,
        observed_generation: Option<i64>,
    ) -> LatticeModelStatus {
        LatticeModelStatus {
            phase,
            message: None,
            observed_generation,
            conditions: None,
            auto_topology: None,
        }
    }

    #[test]
    fn spec_unchanged_when_generation_matches() {
        let status = make_status(ModelServingPhase::Loading, Some(1));
        assert!(!spec_changed_since_compilation(Some(&status), 1));
    }

    #[test]
    fn spec_changed_when_generation_advances() {
        let status = make_status(ModelServingPhase::Loading, Some(1));
        assert!(spec_changed_since_compilation(Some(&status), 2));
    }

    #[test]
    fn spec_changed_when_no_observed_generation() {
        let status = make_status(ModelServingPhase::Loading, None);
        assert!(spec_changed_since_compilation(Some(&status), 1));
    }

    /// The Loading phase must detect spec changes. When the user updates a model
    /// spec while it's Loading, the old compiled resources are still running.
    /// If Loading doesn't detect the generation mismatch and transitions to
    /// Serving, it stamps the new generation on the status — making Serving think
    /// it's up-to-date when it's actually running stale config.
    #[test]
    fn loading_must_detect_spec_change() {
        // Simulates: Pending compiled at gen=1, entered Loading with observed_gen=1.
        // User updates spec → metadata.generation becomes 2.
        let status = make_status(ModelServingPhase::Loading, Some(1));
        let current_generation = 2;

        assert!(
            spec_changed_since_compilation(Some(&status), current_generation),
            "Loading phase must detect spec changes to prevent running stale config"
        );
    }

    #[test]
    fn derive_available_state() {
        let conditions = vec![ModelCondition {
            type_: "Available".to_string(),
            status: "True".to_string(),
            reason: None,
            message: None,
            last_transition_time: None,
        }];
        assert!(matches!(
            derive_model_serving_state(Some(&conditions)),
            ModelServingState::Available
        ));
    }

    #[test]
    fn derive_failed_state() {
        let conditions = vec![ModelCondition {
            type_: "Failed".to_string(),
            status: "True".to_string(),
            reason: None,
            message: None,
            last_transition_time: None,
        }];
        assert!(matches!(
            derive_model_serving_state(Some(&conditions)),
            ModelServingState::Failed
        ));
    }

    #[test]
    fn derive_progressing_with_no_conditions() {
        assert!(matches!(
            derive_model_serving_state(None),
            ModelServingState::Progressing
        ));
    }

    // =========================================================================
    // Role Graph Key Tests
    // =========================================================================

    fn make_minimal_workload() -> lattice_common::crd::workload::spec::WorkloadSpec {
        use std::collections::BTreeMap;
        lattice_common::crd::workload::spec::WorkloadSpec {
            containers: BTreeMap::from([(
                "main".to_string(),
                lattice_common::crd::ContainerSpec {
                    image: "test:latest".to_string(),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        }
    }

    fn make_role() -> lattice_common::crd::ModelRoleSpec {
        lattice_common::crd::ModelRoleSpec {
            entry_workload: make_minimal_workload(),
            ..Default::default()
        }
    }

    #[test]
    fn spec_role_keys_computes_correct_keys() {
        use std::collections::BTreeMap;

        let roles = BTreeMap::from([
            ("prefill".to_string(), make_role()),
            ("decode".to_string(), make_role()),
        ]);

        let keys = spec_role_keys("llm-serving", &roles);
        assert_eq!(keys.len(), 2);
        assert!(keys.contains("llm-serving-prefill"));
        assert!(keys.contains("llm-serving-decode"));
    }

    #[test]
    fn current_graph_role_keys_finds_matching_entries() {
        let graph = ServiceGraph::new();

        // Register two roles for model "llm-serving"
        graph.put_workload("ns", "llm-serving-prefill", &make_minimal_workload());
        graph.put_workload("ns", "llm-serving-decode", &make_minimal_workload());

        // Register an unrelated service
        graph.put_workload("ns", "other-service", &make_minimal_workload());

        let keys = current_graph_role_keys(&graph, "llm-serving", "ns");
        assert_eq!(keys.len(), 2);
        assert!(keys.contains("llm-serving-prefill"));
        assert!(keys.contains("llm-serving-decode"));
        assert!(!keys.contains("other-service"));
    }

    /// When a model spec changes from {prefill, decode} to {decode}, the old
    /// "prefill" graph node must be identified for cleanup. This test verifies
    /// that spec_role_keys + current_graph_role_keys correctly identify removed roles.
    #[test]
    fn removed_role_detected_via_set_difference() {
        use std::collections::BTreeMap;

        let graph = ServiceGraph::new();

        // Old spec had both roles
        graph.put_workload("ns", "llm-decode", &make_minimal_workload());
        graph.put_workload("ns", "llm-prefill", &make_minimal_workload());

        let old_keys = current_graph_role_keys(&graph, "llm", "ns");

        // New spec only has "decode"
        let new_roles = BTreeMap::from([("decode".to_string(), make_role())]);
        let new_keys = spec_role_keys("llm", &new_roles);

        let removed: Vec<&String> = old_keys.difference(&new_keys).collect();
        assert_eq!(removed.len(), 1);
        assert_eq!(*removed[0], "llm-prefill");
    }

    /// Verify that register_graph + cleanup correctly handles role addition.
    /// Adding a role should NOT trigger cleanup of existing roles.
    #[test]
    fn adding_role_does_not_remove_existing() {
        use std::collections::BTreeMap;

        let graph = ServiceGraph::new();

        // Old spec had one role
        graph.put_workload("ns", "llm-decode", &make_minimal_workload());
        let old_keys = current_graph_role_keys(&graph, "llm", "ns");

        // New spec adds a role
        let new_roles = BTreeMap::from([
            ("decode".to_string(), make_role()),
            ("prefill".to_string(), make_role()),
        ]);
        let new_keys = spec_role_keys("llm", &new_roles);

        let removed: Vec<&String> = old_keys.difference(&new_keys).collect();
        assert!(
            removed.is_empty(),
            "adding a role should not identify any removals"
        );
    }
}
