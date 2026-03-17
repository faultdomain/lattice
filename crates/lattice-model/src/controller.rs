//! LatticeModel controller implementation
//!
//! Reconciles LatticeModel resources through a state machine:
//! Pending → Loading → Serving | Failed
//!
//! Resources are applied in layers to prevent race conditions:
//! - Layer 1: ConfigMaps, Secrets, ExternalSecrets, PVCs, MeshMembers, TracingPolicies
//! - Layer 2: ModelServing (only after mesh/security is ready)
//! - Layer 3: Routing — ModelServer + ModelRoutes
//! - Layer 4a: Autoscaling — AutoscalingPolicy (must exist before bindings)
//! - Layer 4b: Autoscaling — AutoscalingPolicyBinding (references policies)
//!
//! When `modelSource` is set, a downloader init container is injected into each
//! pod template. The init container downloads model artifacts before the main
//! serving container starts. On model spec change, the init container args change →
//! Kthena rolling update → zero downtime model updates.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use kube::api::{Api, DeleteParams, DynamicObject, PatchParams};
use kube::discovery::ApiResource;
use kube::runtime::controller::Action;
use kube::{Client, Resource, ResourceExt};
use tracing::{error, info, warn};

#[cfg(test)]
use mockall::automock;

use kube::runtime::events::EventType;
use lattice_cedar::PolicyEngine;
use lattice_common::crd::{
    CostEstimate, LatticeModel, LatticeModelStatus, MetricsScraper, MetricsSnapshot,
    ModelCondition, ModelServingPhase, ProviderType,
};
use lattice_common::events::{actions, reasons, EventPublisher};
use lattice_common::graph::ServiceGraph;
use lattice_common::kube_utils::ApplyBatch;
use lattice_common::{CrdKind, CrdRegistry, Retryable};
use lattice_cost::CostProvider;

use crate::compiler::{compile_model, role_key_suffix, CompiledModel};
use crate::error::ModelError;

const FIELD_MANAGER: &str = "lattice-model-controller";

/// Requeue interval while loading, downloading, or recompiling after spec change
const REQUEUE_LOADING: Duration = Duration::from_secs(15);
/// Requeue interval during steady-state serving (health monitoring)
const REQUEUE_SERVING: Duration = Duration::from_secs(60);
/// Requeue interval for fast retry after spec change in Failed state
const REQUEUE_RETRY: Duration = Duration::from_secs(5);
// =============================================================================
// Trait for dependency injection and testability
// =============================================================================

/// Trait abstracting Kubernetes client operations for LatticeModel
#[cfg_attr(test, automock)]
#[async_trait]
pub trait ModelKubeClient: Send + Sync {
    /// Patch the status of a LatticeModel
    async fn patch_model_status(
        &self,
        name: &str,
        namespace: &str,
        status: &LatticeModelStatus,
    ) -> Result<(), ModelError>;

    /// Apply compiled model resources in layers
    async fn apply_compiled_model(
        &self,
        name: &str,
        namespace: &str,
        compiled: &CompiledModel,
    ) -> Result<(), ModelError>;

    /// Check ModelServing status and return derived state + conditions
    async fn check_model_serving_status(
        &self,
        serving_name: &str,
        namespace: &str,
    ) -> (ModelServingState, Option<Vec<ModelCondition>>);

    /// Read conditions from a ModelServing resource
    async fn read_model_serving_conditions(
        &self,
        serving_name: &str,
        namespace: &str,
    ) -> Option<Vec<ModelCondition>>;

    /// Delete all ModelServing resources owned by a model
    async fn delete_model_serving(
        &self,
        model_name: &str,
        namespace: &str,
    ) -> Result<(), ModelError>;

    /// Clean up K8s resources and graph nodes for roles removed from the spec
    async fn cleanup_removed_roles(
        &self,
        model_name: &str,
        namespace: &str,
        old_keys: &BTreeSet<String>,
        new_keys: &BTreeSet<String>,
        graph: &ServiceGraph,
    );
}

/// Real Kubernetes client implementation
pub struct ModelKubeClientImpl {
    client: Client,
    registry: Arc<CrdRegistry>,
}

impl ModelKubeClientImpl {
    /// Create a new ModelKubeClientImpl wrapping the given client and CRD registry
    pub fn new(client: Client, registry: Arc<CrdRegistry>) -> Self {
        Self { client, registry }
    }
}

#[async_trait]
impl ModelKubeClient for ModelKubeClientImpl {
    async fn patch_model_status(
        &self,
        name: &str,
        namespace: &str,
        status: &LatticeModelStatus,
    ) -> Result<(), ModelError> {
        lattice_common::kube_utils::patch_resource_status::<LatticeModel>(
            &self.client,
            name,
            namespace,
            status,
            FIELD_MANAGER,
        )
        .await?;
        Ok(())
    }

    async fn apply_compiled_model(
        &self,
        _name: &str,
        namespace: &str,
        compiled: &CompiledModel,
    ) -> Result<(), ModelError> {
        let params = PatchParams::apply(FIELD_MANAGER).force();

        lattice_common::kube_utils::ensure_namespace(&self.client, namespace, None, FIELD_MANAGER)
            .await?;

        let ms_api = self
            .registry
            .resolve(CrdKind::ModelServing)
            .await?
            .ok_or(ModelError::KthenaCrdMissing)?;

        apply_layers(
            &self.client,
            namespace,
            compiled,
            &self.registry,
            &ms_api,
            &params,
        )
        .await
    }

    async fn check_model_serving_status(
        &self,
        serving_name: &str,
        namespace: &str,
    ) -> (ModelServingState, Option<Vec<ModelCondition>>) {
        let conditions = self
            .read_model_serving_conditions(serving_name, namespace)
            .await;
        let state = derive_model_serving_state(conditions.as_deref());
        (state, conditions)
    }

    async fn read_model_serving_conditions(
        &self,
        name: &str,
        namespace: &str,
    ) -> Option<Vec<ModelCondition>> {
        read_model_serving_conditions_impl(&self.client, name, namespace, &self.registry).await
    }

    async fn delete_model_serving(
        &self,
        model_name: &str,
        namespace: &str,
    ) -> Result<(), ModelError> {
        delete_model_serving_impl(&self.client, &self.registry, model_name, namespace).await
    }

    async fn cleanup_removed_roles(
        &self,
        model_name: &str,
        namespace: &str,
        old_keys: &BTreeSet<String>,
        new_keys: &BTreeSet<String>,
        graph: &ServiceGraph,
    ) {
        let removed: Vec<&String> = old_keys.difference(new_keys).collect();
        for role_key in &removed {
            graph.delete_service(namespace, role_key);
        }
        cleanup_removed_roles_impl(
            &self.client,
            &self.registry,
            model_name,
            namespace,
            old_keys,
            new_keys,
        )
        .await;
    }
}

/// Shared context for the LatticeModel controller
pub struct ModelContext {
    pub kube: Arc<dyn ModelKubeClient>,
    pub graph: Arc<ServiceGraph>,
    pub cluster_name: String,
    pub provider_type: ProviderType,
    pub cedar: Arc<PolicyEngine>,
    pub events: Arc<dyn EventPublisher>,
    pub metrics_scraper: Arc<dyn MetricsScraper>,
    /// Cost provider for estimating workload costs (None = cost estimation disabled)
    pub cost_provider: Option<Arc<dyn CostProvider>>,
}

impl ModelContext {
    /// Create a new ModelContext with the given dependencies
    pub fn new(
        kube: Arc<dyn ModelKubeClient>,
        graph: Arc<ServiceGraph>,
        cluster_name: String,
        provider_type: ProviderType,
        cedar: Arc<PolicyEngine>,
        events: Arc<dyn EventPublisher>,
        metrics_scraper: Arc<dyn MetricsScraper>,
    ) -> Self {
        Self {
            kube,
            graph,
            cluster_name,
            provider_type,
            cedar,
            events,
            metrics_scraper,
            cost_provider: None,
        }
    }

    /// Create a context for testing with mock clients.
    ///
    /// Uses a permit-all Cedar PolicyEngine so compilation doesn't fail on
    /// security overrides in unit tests.
    #[cfg(test)]
    pub fn for_testing(kube: Arc<dyn ModelKubeClient>) -> Self {
        Self {
            kube,
            graph: Arc::new(ServiceGraph::new()),
            cluster_name: "test-cluster".to_string(),
            provider_type: ProviderType::Docker,
            cedar: Arc::new(
                PolicyEngine::with_policies("permit(principal, action, resource);")
                    .expect("permit-all policy should parse"),
            ),
            events: Arc::new(lattice_common::NoopEventPublisher),
            metrics_scraper: Arc::new(lattice_common::crd::NoopMetricsScraper),
            cost_provider: None,
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

    // Compute cost once per reconcile — always fresh, no stale preservation.
    let model_spec = &model.spec;
    let cost = lattice_cost::try_estimate(&ctx.cost_provider, |rates, ts| {
        lattice_cost::estimate_model_cost(model_spec, rates, ts)
    })
    .await;

    // Read previously applied role keys from persisted status (no TOCTOU).
    // On first reconcile applied_roles is None — fall back to spec keys
    // (no cleanup needed on first apply).
    let pre_applied_roles: std::collections::BTreeSet<String> = model
        .status
        .as_ref()
        .and_then(|s| s.applied_roles.as_ref())
        .map(|roles| roles.iter().cloned().collect())
        .unwrap_or_else(|| spec_role_keys(&name, &model.spec.roles));

    // Always ensure roles are in the graph (crash recovery).
    register_graph(&model, &ctx.graph, namespace);

    let generation = model.metadata.generation.unwrap_or(0);
    let suffix = role_key_suffix(model.spec.roles.keys());
    let serving_name = format!("{}-{}", name, suffix);
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
                &suffix,
            )
            .await;

            let compiled = match compiled {
                Ok(c) => c,
                Err(e) => {
                    if e.is_retryable() {
                        let msg = format!("Compile failed (will retry): {}", e);
                        let _ = StatusUpdate::new(ModelServingPhase::Pending, &cost)
                            .message(&msg)
                            .apply(ctx.kube.as_ref(), &model, namespace)
                            .await;
                    } else {
                        cleanup_graph(&model, &ctx.graph, namespace);
                        let msg = format!("Failed to compile: {}", e);
                        ctx.events
                            .publish(
                                &model.object_ref(&()),
                                EventType::Warning,
                                reasons::MODEL_FAILED,
                                actions::COMPILE,
                                Some(msg.clone()),
                            )
                            .await;
                        let _ = StatusUpdate::new(ModelServingPhase::Failed, &cost)
                            .message(&msg)
                            .observed_generation(generation)
                            .apply(ctx.kube.as_ref(), &model, namespace)
                            .await;
                    }
                    return Err(e);
                }
            };

            register_graph(&model, &ctx.graph, namespace);

            if let Err(e) = ctx
                .kube
                .apply_compiled_model(&name, namespace, &compiled)
                .await
            {
                let msg = format!("Apply failed (will retry): {}", e);
                // Stay in Pending — apply errors are transient (webhook not ready,
                // API server hiccup). error_policy requeues after 30s.
                // Don't cleanup the graph: the roles are valid (compilation succeeded),
                // and register_graph will re-register them on the next reconcile anyway.
                let _ = StatusUpdate::new(ModelServingPhase::Pending, &cost)
                    .message(&msg)
                    .apply(ctx.kube.as_ref(), &model, namespace)
                    .await;
                return Err(e);
            }
            ctx.events
                .publish(
                    &model.object_ref(&()),
                    EventType::Normal,
                    reasons::MODEL_LOADING,
                    actions::RECONCILE,
                    Some("Resources applied, waiting for model serving readiness".to_string()),
                )
                .await;
            let role_keys: Vec<String> = spec_role_keys(&name, &model.spec.roles)
                .into_iter()
                .collect();
            StatusUpdate::new(ModelServingPhase::Loading, &cost)
                .message("Resources applied, waiting for model serving readiness")
                .observed_generation(generation)
                .auto_topology(compiled.auto_topology)
                .applied_roles(role_keys)
                .apply(ctx.kube.as_ref(), &model, namespace)
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
                StatusUpdate::new(ModelServingPhase::Pending, &cost)
                    .message("Spec changed, recompiling")
                    .apply(ctx.kube.as_ref(), &model, namespace)
                    .await?;
                return Ok(Action::requeue(REQUEUE_RETRY));
            }

            // No download job gating — init containers naturally block pod startup
            // until model download completes.

            let (state, conditions) = ctx
                .kube
                .check_model_serving_status(&serving_name, namespace)
                .await;

            match state {
                ModelServingState::Available => {
                    info!(model = %name, "model serving is available");
                    ctx.events
                        .publish(
                            &model.object_ref(&()),
                            EventType::Normal,
                            reasons::MODEL_SERVING,
                            actions::RECONCILE,
                            Some("Model is serving inference requests".to_string()),
                        )
                        .await;
                    let mut s = StatusUpdate::new(ModelServingPhase::Serving, &cost)
                        .message("Model is serving inference requests")
                        .observed_generation(generation);
                    if let Some(c) = conditions {
                        s = s.conditions(c);
                    }
                    s.apply(ctx.kube.as_ref(), &model, namespace).await?;
                    Ok(Action::requeue(REQUEUE_SERVING))
                }
                ModelServingState::Failed => {
                    error!(model = %name, "model serving failed");
                    ctx.events
                        .publish(
                            &model.object_ref(&()),
                            EventType::Warning,
                            reasons::MODEL_FAILED,
                            actions::RECONCILE,
                            Some("ModelServing failed".to_string()),
                        )
                        .await;
                    cleanup_graph(&model, &ctx.graph, namespace);
                    let mut s = StatusUpdate::new(ModelServingPhase::Failed, &cost)
                        .message("ModelServing failed")
                        .observed_generation(generation);
                    if let Some(c) = conditions {
                        s = s.conditions(c);
                    }
                    s.apply(ctx.kube.as_ref(), &model, namespace).await?;
                    // Always requeue as a safety net — watch events can be missed during pod restarts.
                    Ok(Action::requeue(Duration::from_secs(
                        lattice_common::REQUEUE_SUCCESS_SECS,
                    )))
                }
                ModelServingState::Progressing => Ok(Action::requeue(REQUEUE_LOADING)),
            }
        }
        ModelServingPhase::Serving => {
            let observed = model.status.as_ref().and_then(|s| s.observed_generation);
            if observed != Some(generation) {
                // Spec changed — re-compile and re-apply
                info!(model = %name, observed = ?observed, current = generation, "spec changed, re-applying");
                ctx.events
                    .publish(
                        &model.object_ref(&()),
                        EventType::Normal,
                        reasons::MODEL_SPEC_CHANGED,
                        actions::RECONCILE,
                        Some("Spec changed, recompiling".to_string()),
                    )
                    .await;

                let old_role_keys = pre_applied_roles.clone();
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
                            let mut s =
                                StatusUpdate::new(ModelServingPhase::Serving, &cost).message(&msg);
                            if let Some(gen) = observed {
                                s = s.observed_generation(gen);
                            }
                            let _ = s.apply(ctx.kube.as_ref(), &model, namespace).await;
                        } else {
                            // Permanent — go to Failed
                            cleanup_graph(&model, &ctx.graph, namespace);
                            let msg = format!("Failed to recompile after spec change: {}", e);
                            let _ = StatusUpdate::new(ModelServingPhase::Failed, &cost)
                                .message(&msg)
                                .observed_generation(generation)
                                .apply(ctx.kube.as_ref(), &model, namespace)
                                .await;
                        }
                        return Err(e);
                    }
                };
                register_graph(&model, &ctx.graph, namespace);

                // Clean up K8s resources and graph nodes for removed roles
                ctx.kube
                    .cleanup_removed_roles(
                        &name,
                        namespace,
                        &old_role_keys,
                        &new_role_keys,
                        &ctx.graph,
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
                // The status update below persists the new applied_roles so
                // the next reconcile sees old == new, skips the delete, and
                // falls through to apply_compiled_model for a clean recreate.
                if old_role_keys != new_role_keys {
                    ctx.kube.delete_model_serving(&name, namespace).await?;
                    // Persist the new role keys so the next reconcile sees
                    // old == new and falls through to apply. Keep the OLD
                    // observed_generation so spec_changed_since_compilation
                    // still triggers the recompile path.
                    let role_keys: Vec<String> = new_role_keys.into_iter().collect();
                    let mut s = StatusUpdate::new(ModelServingPhase::Serving, &cost)
                        .applied_roles(role_keys);
                    if let Some(gen) = observed {
                        s = s.observed_generation(gen);
                    }
                    let _ = s.apply(ctx.kube.as_ref(), &model, namespace).await;
                    info!(model = %name, "deleted ModelServing for role change, requeuing for clean recreate");
                    return Ok(Action::requeue(REQUEUE_LOADING));
                }

                if let Err(e) = ctx
                    .kube
                    .apply_compiled_model(&name, namespace, &compiled)
                    .await
                {
                    // Apply errors are transient — stay in Serving, let
                    // error_policy retry. Keep the old observed_generation so
                    // the next reconcile re-enters this recompile path.
                    let msg = format!("Apply failed after spec change (will retry): {}", e);
                    let mut s = StatusUpdate::new(ModelServingPhase::Serving, &cost).message(&msg);
                    if let Some(gen) = observed {
                        s = s.observed_generation(gen);
                    }
                    let _ = s.apply(ctx.kube.as_ref(), &model, namespace).await;
                    return Err(e);
                }
                // Transition to Loading so the next reconcile checks
                // ModelServing readiness after the rolling update.
                let role_keys: Vec<String> = new_role_keys.into_iter().collect();
                StatusUpdate::new(ModelServingPhase::Loading, &cost)
                    .message("Spec changed, reloading")
                    .observed_generation(generation)
                    .auto_topology(compiled.auto_topology)
                    .applied_roles(role_keys)
                    .apply(ctx.kube.as_ref(), &model, namespace)
                    .await?;
                return Ok(Action::requeue(REQUEUE_LOADING));
            }

            // No spec change — monitor health and scrape metrics
            let message = "Model is serving inference requests";
            let conditions = ctx
                .kube
                .read_model_serving_conditions(&serving_name, namespace)
                .await;

            let existing_metrics = model.status.as_ref().and_then(|s| s.metrics.as_ref());
            let metrics = lattice_common::crd::scrape_metrics(
                ctx.metrics_scraper.as_ref(),
                model.spec.observability.as_ref(),
                namespace,
                &name,
                existing_metrics,
            )
            .await;

            let mut s = StatusUpdate::new(ModelServingPhase::Serving, &cost)
                .message(message)
                .observed_generation(generation)
                .metrics(metrics);
            if let Some(c) = conditions {
                s = s.conditions(c);
            }
            s.apply(ctx.kube.as_ref(), &model, namespace).await?;
            Ok(Action::requeue(REQUEUE_SERVING))
        }
        ModelServingPhase::Failed => {
            // Periodically retry Failed models. If the spec changed, go back
            // to Pending for a full recompile. Otherwise just requeue — the
            // error may have been transient (CRD not installed yet, API blip).
            let observed = model.status.as_ref().and_then(|s| s.observed_generation);
            if observed != Some(generation) {
                info!(model = %name, observed = ?observed, current = generation, "spec changed while Failed, retrying");
                StatusUpdate::new(ModelServingPhase::Pending, &cost)
                    .message("Retrying after spec change")
                    .apply(ctx.kube.as_ref(), &model, namespace)
                    .await?;
                return Ok(Action::requeue(REQUEUE_RETRY));
            }
            Ok(Action::requeue(Duration::from_secs(30)))
        }
        // Safety net requeue for any unmatched phase — watch events can be missed during pod restarts.
        _ => Ok(Action::requeue(Duration::from_secs(
            lattice_common::REQUEUE_SUCCESS_SECS,
        ))),
    }
}

/// Register all model roles in the service graph for bilateral agreements
fn register_graph(model: &LatticeModel, graph: &ServiceGraph, namespace: &str) {
    let name = model.metadata.name.as_deref().unwrap_or_default();
    let has_autoscaling = model.spec.roles.values().any(|r| r.autoscaling.is_some());
    let callers = crate::compiler::model_callers(model.spec.routing.as_ref(), has_autoscaling);
    for (role_name, role_spec) in &model.spec.roles {
        graph.put_workload(
            namespace,
            &format!("{}-{}", name, role_name),
            &role_spec.entry_workload,
            &callers,
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

/// Clean up K8s resources for roles that were removed from the spec.
async fn cleanup_removed_roles_impl(
    client: &Client,
    registry: &CrdRegistry,
    model_name: &str,
    namespace: &str,
    old_role_names: &BTreeSet<String>,
    new_role_names: &BTreeSet<String>,
) {
    let removed: Vec<&String> = old_role_names.difference(new_role_names).collect();
    if removed.is_empty() {
        return;
    }

    info!(model = %model_name, removed = ?removed, "cleaning up removed role resources");

    for role_key in &removed {
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
async fn delete_model_serving_impl(
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

async fn apply_layers(
    client: &Client,
    namespace: &str,
    compiled: &CompiledModel,
    registry: &CrdRegistry,
    ms_api: &ApiResource,
    params: &PatchParams,
) -> Result<(), ModelError> {
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
        "applied compiled model resources"
    );

    Ok(())
}

/// High-level state derived from ModelServing conditions
pub enum ModelServingState {
    /// ModelServing is available and serving requests
    Available,
    /// ModelServing has failed
    Failed,
    /// ModelServing is still progressing
    Progressing,
}

/// Read conditions from a ModelServing resource and convert to ModelCondition structs.
async fn read_model_serving_conditions_impl(
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
    applied_roles: Option<Vec<String>>,
    cost: Option<CostEstimate>,
    metrics: Option<MetricsSnapshot>,
}

impl<'a> StatusUpdate<'a> {
    fn new(phase: ModelServingPhase, cost: &Option<CostEstimate>) -> Self {
        Self {
            phase,
            message: None,
            observed_generation: None,
            conditions: None,
            auto_topology: None,
            applied_roles: None,
            cost: cost.clone(),
            metrics: None,
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

    fn applied_roles(mut self, roles: Vec<String>) -> Self {
        self.applied_roles = Some(roles);
        self
    }

    fn metrics(mut self, snapshot: Option<MetricsSnapshot>) -> Self {
        self.metrics = snapshot;
        self
    }

    async fn apply(
        self,
        kube: &dyn ModelKubeClient,
        model: &LatticeModel,
        namespace: &str,
    ) -> Result<(), ModelError> {
        let name = model.name_any();
        // Preserve fields from existing status unless explicitly overridden
        let auto_topology = self
            .auto_topology
            .or_else(|| model.status.as_ref().and_then(|s| s.auto_topology.clone()));
        let applied_roles = self
            .applied_roles
            .or_else(|| model.status.as_ref().and_then(|s| s.applied_roles.clone()));
        let cost = self.cost;
        let metrics = self
            .metrics
            .or_else(|| model.status.as_ref().and_then(|s| s.metrics.clone()));
        let status = LatticeModelStatus {
            phase: self.phase,
            message: self.message.map(|m| m.to_string()),
            observed_generation: self.observed_generation,
            conditions: self.conditions,
            auto_topology,
            applied_roles,
            cost,
            metrics,
        };
        if model.status.as_ref() == Some(&status) {
            return Ok(());
        }
        kube.patch_model_status(&name, namespace, &status).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use std::collections::BTreeMap;

    // =========================================================================
    // Test Fixtures
    // =========================================================================

    fn make_minimal_model(name: &str) -> LatticeModel {
        LatticeModel {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("test-ns".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: lattice_common::crd::LatticeModelSpec {
                roles: BTreeMap::from([("serving".to_string(), make_role())]),
                ..Default::default()
            },
            status: None,
        }
    }

    // =========================================================================
    // Reconcile Story Tests
    // =========================================================================

    /// Pending model compiles, applies, and transitions to Loading
    #[tokio::test]
    async fn pending_transitions_to_loading() {
        let model = Arc::new(make_minimal_model("my-model"));

        let mut mock = MockModelKubeClient::new();
        mock.expect_patch_model_status().returning(|_, _, _| Ok(()));
        mock.expect_apply_compiled_model()
            .returning(|_, _, _| Ok(()));

        let ctx = Arc::new(ModelContext::for_testing(Arc::new(mock)));

        let action = reconcile(model, ctx)
            .await
            .expect("reconcile should succeed");
        assert_eq!(action, Action::requeue(REQUEUE_LOADING));
    }

    /// Loading with Available ModelServing transitions to Serving
    #[tokio::test]
    async fn loading_transitions_to_serving_when_available() {
        let mut model = make_minimal_model("my-model");
        model.status = Some(LatticeModelStatus {
            phase: ModelServingPhase::Loading,
            observed_generation: Some(1),
            applied_roles: Some(vec!["my-model-serving".to_string()]),
            ..Default::default()
        });
        let model = Arc::new(model);

        let mut mock = MockModelKubeClient::new();
        mock.expect_check_model_serving_status()
            .returning(|_, _| (ModelServingState::Available, None));
        mock.expect_patch_model_status().returning(|_, _, _| Ok(()));

        let ctx = Arc::new(ModelContext::for_testing(Arc::new(mock)));

        let action = reconcile(model, ctx)
            .await
            .expect("reconcile should succeed");
        assert_eq!(action, Action::requeue(REQUEUE_SERVING));
    }

    /// Loading with Failed ModelServing transitions to Failed
    #[tokio::test]
    async fn loading_transitions_to_failed_when_model_serving_fails() {
        let mut model = make_minimal_model("my-model");
        model.status = Some(LatticeModelStatus {
            phase: ModelServingPhase::Loading,
            observed_generation: Some(1),
            applied_roles: Some(vec!["my-model-serving".to_string()]),
            ..Default::default()
        });
        let model = Arc::new(model);

        let mut mock = MockModelKubeClient::new();
        mock.expect_check_model_serving_status()
            .returning(|_, _| (ModelServingState::Failed, None));
        mock.expect_patch_model_status().returning(|_, _, _| Ok(()));

        let ctx = Arc::new(ModelContext::for_testing(Arc::new(mock)));

        let action = reconcile(model, ctx)
            .await
            .expect("reconcile should succeed");
        assert_eq!(
            action,
            Action::requeue(Duration::from_secs(lattice_common::REQUEUE_SUCCESS_SECS))
        );
    }

    /// Serving with no spec change requeues for health monitoring
    #[tokio::test]
    async fn serving_steady_state_requeues() {
        let mut model = make_minimal_model("my-model");
        model.status = Some(LatticeModelStatus {
            phase: ModelServingPhase::Serving,
            observed_generation: Some(1),
            applied_roles: Some(vec!["my-model-serving".to_string()]),
            ..Default::default()
        });
        let model = Arc::new(model);

        let mut mock = MockModelKubeClient::new();
        mock.expect_read_model_serving_conditions()
            .returning(|_, _| None);
        mock.expect_patch_model_status().returning(|_, _, _| Ok(()));

        let ctx = Arc::new(ModelContext::for_testing(Arc::new(mock)));

        let action = reconcile(model, ctx)
            .await
            .expect("reconcile should succeed");
        assert_eq!(action, Action::requeue(REQUEUE_SERVING));
    }

    /// Serving with spec change triggers recompile → Loading
    #[tokio::test]
    async fn serving_spec_change_triggers_recompile() {
        let mut model = make_minimal_model("my-model");
        model.metadata.generation = Some(2);
        model.status = Some(LatticeModelStatus {
            phase: ModelServingPhase::Serving,
            observed_generation: Some(1),
            applied_roles: Some(vec!["my-model-serving".to_string()]),
            ..Default::default()
        });
        let model = Arc::new(model);

        let mut mock = MockModelKubeClient::new();
        mock.expect_apply_compiled_model()
            .returning(|_, _, _| Ok(()));
        mock.expect_cleanup_removed_roles()
            .returning(|_, _, _, _, _| ());
        mock.expect_patch_model_status().returning(|_, _, _| Ok(()));

        let ctx = Arc::new(ModelContext::for_testing(Arc::new(mock)));

        let action = reconcile(model, ctx)
            .await
            .expect("reconcile should succeed");
        assert_eq!(action, Action::requeue(REQUEUE_LOADING));
    }

    /// Failed with spec change goes back to Pending for retry
    #[tokio::test]
    async fn failed_spec_change_retries() {
        let mut model = make_minimal_model("my-model");
        model.metadata.generation = Some(2);
        model.status = Some(LatticeModelStatus {
            phase: ModelServingPhase::Failed,
            observed_generation: Some(1),
            ..Default::default()
        });
        let model = Arc::new(model);

        let mut mock = MockModelKubeClient::new();
        mock.expect_patch_model_status().returning(|_, _, _| Ok(()));

        let ctx = Arc::new(ModelContext::for_testing(Arc::new(mock)));

        let action = reconcile(model, ctx)
            .await
            .expect("reconcile should succeed");
        assert_eq!(action, Action::requeue(REQUEUE_RETRY));
    }

    // =========================================================================
    // Status helper tests
    // =========================================================================

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
            applied_roles: None,
            cost: None,
            metrics: None,
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

    /// When a model spec changes from {prefill, decode} to {decode}, the old
    /// "prefill" role must be identified for cleanup via status-persisted applied_roles.
    #[test]
    fn removed_role_detected_via_status_diff() {
        use std::collections::BTreeMap;

        // Simulate status.applied_roles from previous reconcile
        let old_keys: std::collections::BTreeSet<String> = ["llm-decode", "llm-prefill"]
            .into_iter()
            .map(String::from)
            .collect();

        // New spec only has "decode"
        let new_roles = BTreeMap::from([("decode".to_string(), make_role())]);
        let new_keys = spec_role_keys("llm", &new_roles);

        let removed: Vec<&String> = old_keys.difference(&new_keys).collect();
        assert_eq!(removed.len(), 1);
        assert_eq!(*removed[0], "llm-prefill");
    }

    /// Adding a role should NOT trigger cleanup of existing roles.
    #[test]
    fn adding_role_does_not_remove_existing() {
        use std::collections::BTreeMap;

        // Simulate status.applied_roles from previous reconcile
        let old_keys: std::collections::BTreeSet<String> =
            ["llm-decode"].into_iter().map(String::from).collect();

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

    /// On first reconcile (no status), applied_roles falls back to spec_role_keys,
    /// so no cleanup is triggered.
    #[test]
    fn first_reconcile_no_status_skips_cleanup() {
        use std::collections::BTreeMap;

        let roles = BTreeMap::from([
            ("decode".to_string(), make_role()),
            ("prefill".to_string(), make_role()),
        ]);

        // Simulate: status.applied_roles is None → fall back to spec_role_keys
        let old_keys = spec_role_keys("llm", &roles);
        let new_keys = spec_role_keys("llm", &roles);

        let removed: Vec<&String> = old_keys.difference(&new_keys).collect();
        assert!(
            removed.is_empty(),
            "first reconcile should not trigger cleanup"
        );
    }
}
