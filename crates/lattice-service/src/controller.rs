//! LatticeService controller implementation
//!
//! This module implements the reconciliation logic for LatticeService resources.
//! It follows the Kubernetes controller pattern: observe current state, determine
//! desired state, calculate diff, and apply changes.
//!
//! The controller maintains a ServiceGraph for tracking service dependencies
//! and allowed callers for network policy generation.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use kube::api::{Api, Patch, PatchParams};
use kube::discovery::ApiResource;
use kube::runtime::controller::Action;
use kube::runtime::events::EventType;
use kube::{Client, Resource, ResourceExt};
use tracing::{debug, error, info, instrument, warn};

#[cfg(test)]
use mockall::automock;

use lattice_common::kube_utils::ApplyBatch;
use lattice_common::status_check;
use lattice_common::{CrdKind, CrdRegistry};

use lattice_cedar::PolicyEngine;
use lattice_common::events::{actions, reasons, EventPublisher};
#[cfg(test)]
use lattice_common::NoopEventPublisher;
use lattice_cost::CostProvider;

use crate::compiler::{ApplyLayer, CompiledService, CompilerPhase, ServiceCompiler};
use crate::crd::{
    ClusterConfig, Condition, ConditionStatus, CostEstimate, LatticeService, LatticeServiceSpec,
    LatticeServiceStatus, MetricsScraper, MetricsSnapshot, MonitoringConfig, ProviderType,
    ServicePhase,
};
use crate::graph::ServiceGraph;
use crate::Error;

const FIELD_MANAGER: &str = "lattice-service-controller";

/// Timeout waiting for ESO to sync imagePullSecret K8s Secrets.
const IMAGE_PULL_SECRET_TIMEOUT: Duration = Duration::from_secs(120);
/// Polling interval while waiting for imagePullSecrets.
const IMAGE_PULL_SECRET_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Requeue interval when service is in Pending phase.
const REQUEUE_PENDING: Duration = Duration::from_secs(5);
/// Requeue interval when service is Ready (periodic drift check).
const REQUEUE_READY: Duration = Duration::from_secs(60);

// =============================================================================
// Traits for dependency injection and testability
// =============================================================================

/// Trait abstracting Kubernetes client operations for LatticeService
///
/// This trait allows mocking the Kubernetes client in tests while using
/// the real client in production.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait ServiceKubeClient: Send + Sync {
    /// Patch the status of a LatticeService
    async fn patch_service_status(
        &self,
        name: &str,
        namespace: &str,
        status: &LatticeServiceStatus,
    ) -> Result<(), Error>;

    /// Get a LatticeService by name and namespace
    async fn get_service(
        &self,
        name: &str,
        namespace: &str,
    ) -> Result<Option<LatticeService>, Error>;

    /// List all LatticeServices across all namespaces
    async fn list_services(&self) -> Result<Vec<LatticeService>, Error>;

    /// Apply compiled workloads and policies to the cluster
    async fn apply_compiled_service(
        &self,
        service_name: &str,
        namespace: &str,
        compiled: &CompiledService,
    ) -> Result<(), Error>;

    /// Patch an annotation on a LatticeService
    async fn patch_service_annotation(
        &self,
        name: &str,
        namespace: &str,
        key: &str,
        value: &str,
    ) -> Result<(), Error>;

    /// Check if a LatticeMeshMember is Ready (policies fully applied, including ServiceEntries)
    async fn is_mesh_member_ready(&self, name: &str, namespace: &str) -> Result<bool, Error>;

    /// Delete ExternalSecrets owned by a service when Cedar policy revokes access.
    ///
    /// When a Cedar policy change denies a previously-allowed secret, compilation fails
    /// but the ExternalSecret remains in the cluster, continuing to sync the revoked secret.
    /// This method deletes all ExternalSecrets labeled with the service name to enforce
    /// the revocation immediately.
    async fn delete_revoked_external_secrets(
        &self,
        service_name: &str,
        namespace: &str,
    ) -> Result<(), Error>;

    /// Delete resources that were previously applied but are no longer in the compiled output.
    ///
    /// When a spec change causes compilation to produce fewer resources (e.g., removing
    /// `autoscaling` makes `scaled_object: None`), the apply step only upserts and won't
    /// delete the old resource. This method handles that cleanup by checking each optional
    /// resource type and deleting by name if it's no longer in the compiled output.
    async fn cleanup_orphaned_resources(
        &self,
        service_name: &str,
        namespace: &str,
        compiled: &CompiledService,
    ) -> Result<(), Error>;
}

/// Real Kubernetes client implementation
pub struct ServiceKubeClientImpl {
    client: Client,
    registry: Arc<CrdRegistry>,
}

impl ServiceKubeClientImpl {
    /// Create a new ServiceKubeClientImpl wrapping the given client and CRD registry
    pub fn new(client: Client, registry: Arc<CrdRegistry>) -> Self {
        Self { client, registry }
    }
}

#[async_trait]
impl ServiceKubeClient for ServiceKubeClientImpl {
    async fn patch_service_status(
        &self,
        name: &str,
        namespace: &str,
        status: &LatticeServiceStatus,
    ) -> Result<(), Error> {
        lattice_common::kube_utils::patch_resource_status::<LatticeService>(
            &self.client,
            name,
            namespace,
            status,
            FIELD_MANAGER,
        )
        .await?;
        Ok(())
    }

    async fn get_service(
        &self,
        name: &str,
        namespace: &str,
    ) -> Result<Option<LatticeService>, Error> {
        let api: Api<LatticeService> = Api::namespaced(self.client.clone(), namespace);
        match api.get(name).await {
            Ok(svc) => Ok(Some(svc)),
            Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn list_services(&self) -> Result<Vec<LatticeService>, Error> {
        let api: Api<LatticeService> = Api::all(self.client.clone());
        let list = api.list(&Default::default()).await?;
        Ok(list.items)
    }

    async fn apply_compiled_service(
        &self,
        service_name: &str,
        namespace: &str,
        compiled: &CompiledService,
    ) -> Result<(), Error> {
        use k8s_openapi::api::apps::v1::Deployment as K8sDeployment;
        use k8s_openapi::api::core::v1::{
            ConfigMap as K8sCm, PersistentVolumeClaim as K8sPvc, Secret as K8sSecret,
            Service as K8sService, ServiceAccount as K8sSA,
        };

        lattice_common::kube_utils::ensure_namespace(&self.client, namespace, None, FIELD_MANAGER)
            .await?;

        let params = PatchParams::apply(FIELD_MANAGER).force();

        // ApiResources for native K8s types (used by push via DynamicObject)
        let ar_sa = ApiResource::erase::<K8sSA>(&());
        let ar_pvc = ApiResource::erase::<K8sPvc>(&());
        let ar_cm = ApiResource::erase::<K8sCm>(&());
        let ar_secret = ApiResource::erase::<K8sSecret>(&());
        let ar_svc = ApiResource::erase::<K8sService>(&());
        let ar_deploy = ApiResource::erase::<K8sDeployment>(&());
        let ar_pdb =
            lattice_common::kube_utils::build_api_resource("policy/v1", "PodDisruptionBudget");

        // ── Layer 1: Infrastructure ──
        // Everything except the Deployment and ScaledObject. ExternalSecrets
        // trigger ESO to sync K8s Secrets that the Deployment may reference
        // via imagePullSecrets, so they must be applied first.
        let mut layer1 = ApplyBatch::new(self.client.clone(), namespace, &params);

        // Workload infrastructure
        if let Some(sa) = &compiled.workloads.service_account {
            layer1.push("ServiceAccount", &sa.metadata.name, sa, &ar_sa)?;
        }
        for pvc in &compiled.workloads.config.pvcs {
            layer1.push("PersistentVolumeClaim", &pvc.metadata.name, pvc, &ar_pvc)?;
        }
        for cm in &compiled.workloads.config.env_config_maps {
            layer1.push("ConfigMap", &cm.metadata.name, cm, &ar_cm)?;
        }
        for secret in &compiled.workloads.config.env_secrets {
            layer1.push("Secret", &secret.metadata.name, secret, &ar_secret)?;
        }
        for cm in &compiled.workloads.config.files_config_maps {
            layer1.push("ConfigMap", &cm.metadata.name, cm, &ar_cm)?;
        }
        for secret in &compiled.workloads.config.files_secrets {
            layer1.push("Secret", &secret.metadata.name, secret, &ar_secret)?;
        }
        if let Some(svc) = &compiled.workloads.service {
            layer1.push("Service", &svc.metadata.name, svc, &ar_svc)?;
        }
        if let Some(pdb) = &compiled.workloads.pdb {
            layer1.push("PodDisruptionBudget", &pdb.metadata.name, pdb, &ar_pdb)?;
        }

        // Volcano PodGroup for topology-aware scheduling (must exist before Deployment
        // so Volcano can associate pods with the group)
        let pg_ar = self.registry.resolve(CrdKind::PodGroup).await?;
        layer1.push_optional_crd(
            "PodGroup",
            pg_ar.as_ref(),
            compiled.workloads.pod_group.as_ref(),
            |pg| &pg.metadata.name,
        )?;

        // ExternalSecrets (ESO syncs secrets from Vault)
        let es_ar = self.registry.resolve(CrdKind::ExternalSecret).await?;
        layer1.push_crd(
            "ExternalSecret",
            es_ar.as_ref(),
            &compiled.workloads.config.external_secrets,
            |es| &es.metadata.name,
        )?;

        // LatticeMeshMember CR — the MeshMember controller generates all mesh policies
        let mm_ar = self.registry.resolve(CrdKind::MeshMember).await?;
        layer1.push_optional_crd(
            "LatticeMeshMember",
            mm_ar.as_ref(),
            compiled.mesh_member.as_ref(),
            |mm| mm.metadata.name.as_deref().unwrap_or("unknown"),
        )?;

        // Tetragon TracingPolicyNamespaced (runtime enforcement)
        let tp_ar = self
            .registry
            .resolve(CrdKind::TracingPolicyNamespaced)
            .await?;
        layer1.push_crd(
            "TracingPolicyNamespaced",
            tp_ar.as_ref(),
            &compiled.tracing_policies,
            |tp| &tp.metadata.name,
        )?;

        // Extension resources — infrastructure layer
        for ext in &compiled.extensions {
            if ext.layer == ApplyLayer::Infrastructure {
                layer1.push_dynamic(ext)?;
            }
        }

        let layer1_count = layer1.run("infrastructure").await?;

        // ── Wait: imagePullSecrets must exist before the Deployment ──
        // ESO syncs K8s Secrets from the ExternalSecrets applied above.
        // On subsequent reconciles the secrets already exist so this is instant.
        self.wait_for_image_pull_secrets(namespace, &compiled.workloads.deployment)
            .await?;

        // ── Layer 2: Deployment + workload extensions ──
        let mut layer2 = ApplyBatch::new(self.client.clone(), namespace, &params);
        if let Some(deployment) = &compiled.workloads.deployment {
            layer2.push(
                "Deployment",
                &deployment.metadata.name,
                deployment,
                &ar_deploy,
            )?;
        }
        for ext in &compiled.extensions {
            if ext.layer == ApplyLayer::Workload {
                layer2.push_dynamic(ext)?;
            }
        }
        let layer2_count = layer2.run("deployment").await?;

        // ── Layer 3: ScaledObject (KEDA) ──
        // Must be applied after the Deployment because KEDA's admission webhook
        // validates that the scaleTargetRef target exists.
        let mut layer3 = ApplyBatch::new(self.client.clone(), namespace, &params);
        let so_ar = self.registry.resolve(CrdKind::ScaledObject).await?;
        layer3.push_optional_crd(
            "ScaledObject",
            so_ar.as_ref(),
            compiled.workloads.scaled_object.as_ref(),
            |so| &so.metadata.name,
        )?;
        let layer3_count = layer3.run("autoscaling").await?;

        info!(
            service = %service_name,
            namespace = %namespace,
            resources = layer1_count + layer2_count + layer3_count,
            "applied compiled resources"
        );
        Ok(())
    }

    async fn patch_service_annotation(
        &self,
        name: &str,
        namespace: &str,
        key: &str,
        value: &str,
    ) -> Result<(), Error> {
        let api: Api<LatticeService> = Api::namespaced(self.client.clone(), namespace);
        let patch = serde_json::json!({
            "metadata": { "annotations": { key: value } }
        });
        api.patch(
            name,
            &PatchParams::apply(FIELD_MANAGER),
            &Patch::Merge(&patch),
        )
        .await?;
        Ok(())
    }

    async fn delete_revoked_external_secrets(
        &self,
        service_name: &str,
        namespace: &str,
    ) -> Result<(), Error> {
        use lattice_common::crd_registry::CrdKind;

        let Some(ar) = self.registry.resolve(CrdKind::ExternalSecret).await? else {
            return Ok(());
        };

        let api: Api<kube::api::DynamicObject> =
            Api::namespaced_with(self.client.clone(), namespace, &ar);

        let label_selector = format!("{}={}", lattice_common::LABEL_SERVICE_OWNER, service_name);
        let lp = kube::api::ListParams::default().labels(&label_selector);

        let list = api.list(&lp).await.map_err(|e| {
            Error::internal_with_context(
                "delete_revoked_external_secrets",
                format!("list ExternalSecrets for {}: {}", service_name, e),
            )
        })?;

        for es in &list.items {
            if let Some(name) = &es.metadata.name {
                tracing::info!(
                    service = %service_name,
                    external_secret = %name,
                    "Deleting revoked ExternalSecret"
                );
                let dp = kube::api::DeleteParams::default();
                let _ = api.delete(name, &dp).await;
            }
        }

        Ok(())
    }

    async fn is_mesh_member_ready(&self, name: &str, namespace: &str) -> Result<bool, Error> {
        use lattice_common::crd::{LatticeMeshMember, MeshMemberPhase};
        let api: Api<LatticeMeshMember> = Api::namespaced(self.client.clone(), namespace);
        match api.get_opt(name).await? {
            Some(mm) => Ok(mm
                .status
                .as_ref()
                .map(|s| s.phase == MeshMemberPhase::Ready)
                .unwrap_or(false)),
            None => Ok(false),
        }
    }

    async fn cleanup_orphaned_resources(
        &self,
        service_name: &str,
        namespace: &str,
        compiled: &CompiledService,
    ) -> Result<(), Error> {
        use lattice_common::kube_utils::delete_resource_if_exists;

        let cleanup_err = |kind: &str, e: kube::Error| {
            Error::internal_with_context(
                "cleanup_orphaned_resources",
                format!("delete orphaned {kind} {service_name}: {e}"),
            )
        };

        // ScaledObject: if compilation no longer produces one, delete the old one.
        // Without this, KEDA keeps auto-scaling with stale configuration.
        if compiled.workloads.scaled_object.is_none() {
            if let Some(ar) = self.registry.resolve(CrdKind::ScaledObject).await? {
                delete_resource_if_exists(
                    &self.client,
                    namespace,
                    &ar,
                    service_name,
                    "ScaledObject",
                )
                .await
                .map_err(|e| cleanup_err("ScaledObject", e))?;
            }
        }

        // PodDisruptionBudget: if compilation no longer produces one, delete the old one.
        if compiled.workloads.pdb.is_none() {
            let ar =
                lattice_common::kube_utils::build_api_resource("policy/v1", "PodDisruptionBudget");
            delete_resource_if_exists(
                &self.client,
                namespace,
                &ar,
                service_name,
                "PodDisruptionBudget",
            )
            .await
            .map_err(|e| cleanup_err("PodDisruptionBudget", e))?;
        }

        // PodGroup: if compilation no longer produces one (topology removed), delete the old one.
        if compiled.workloads.pod_group.is_none() {
            if let Some(ar) = self.registry.resolve(CrdKind::PodGroup).await? {
                delete_resource_if_exists(&self.client, namespace, &ar, service_name, "PodGroup")
                    .await
                    .map_err(|e| cleanup_err("PodGroup", e))?;
            }
        }

        // LatticeMeshMember: if compilation no longer produces one, delete the old one.
        if compiled.mesh_member.is_none() {
            if let Some(ar) = self.registry.resolve(CrdKind::MeshMember).await? {
                delete_resource_if_exists(
                    &self.client,
                    namespace,
                    &ar,
                    service_name,
                    "LatticeMeshMember",
                )
                .await
                .map_err(|e| cleanup_err("LatticeMeshMember", e))?;
            }
        }

        Ok(())
    }
}

/// Extension trait for `ApplyBatch` to support service-specific `DynamicResource`.
trait ApplyBatchExt {
    fn push_dynamic(&mut self, ext: &crate::compiler::DynamicResource) -> Result<(), Error>;
}

impl ApplyBatchExt for ApplyBatch<'_> {
    fn push_dynamic(&mut self, ext: &crate::compiler::DynamicResource) -> Result<(), Error> {
        self.push_json(&ext.kind, &ext.name, ext.json.clone(), &ext.api_resource)
    }
}

impl ServiceKubeClientImpl {
    /// Wait for imagePullSecrets K8s Secrets to exist before applying the Deployment.
    ///
    /// ESO creates K8s Secrets from the ExternalSecrets applied in Layer 1. If the
    /// Deployment references those secrets via `imagePullSecrets` and they don't exist
    /// yet, kubelet enters `ImagePullBackOff` with exponential backoff (up to 5 min).
    /// Polling here is cheap: on subsequent reconciles the secrets already exist so
    /// `get_opt` returns immediately.
    async fn wait_for_image_pull_secrets(
        &self,
        namespace: &str,
        deployment: &Option<crate::workload::Deployment>,
    ) -> Result<(), Error> {
        use k8s_openapi::api::core::v1::Secret as K8sSecret;

        let deployment = match deployment {
            Some(d) => d,
            None => return Ok(()),
        };

        let secret_names: Vec<&str> = deployment
            .spec
            .template
            .spec
            .image_pull_secrets
            .iter()
            .map(|r| r.name.as_str())
            .collect();

        if secret_names.is_empty() {
            return Ok(());
        }

        let api: Api<K8sSecret> = Api::namespaced(self.client.clone(), namespace);
        let timeout = IMAGE_PULL_SECRET_TIMEOUT;
        let poll_interval = IMAGE_PULL_SECRET_POLL_INTERVAL;

        let start = std::time::Instant::now();
        let mut remaining: std::collections::HashSet<&str> = secret_names.iter().copied().collect();

        while !remaining.is_empty() {
            if start.elapsed() >= timeout {
                let missing: Vec<_> = remaining.into_iter().collect();
                return Err(Error::internal_with_context(
                    "wait_for_image_pull_secrets",
                    format!(
                        "timed out waiting for imagePullSecrets {:?} in namespace '{}'",
                        missing, namespace
                    ),
                ));
            }

            // Check all remaining secrets in one pass
            let mut still_missing = Vec::new();
            for secret_name in &remaining {
                match api.get_opt(secret_name).await? {
                    Some(_) => {
                        debug!(secret = %secret_name, "imagePullSecret exists");
                    }
                    None => {
                        still_missing.push(*secret_name);
                    }
                }
            }

            if still_missing.is_empty() {
                break;
            }

            debug!(
                missing = ?still_missing,
                elapsed = ?start.elapsed(),
                "waiting for imagePullSecrets to be synced by ESO"
            );
            remaining = still_missing.into_iter().collect();
            tokio::time::sleep(poll_interval).await;
        }

        info!(
            count = secret_names.len(),
            namespace = %namespace,
            "all imagePullSecrets available"
        );
        Ok(())
    }
}

// =============================================================================
// Controller context
// =============================================================================

/// Controller context containing shared state and clients
///
/// The context is shared across all reconciliation calls and holds
/// resources that are expensive to create (like Kubernetes clients)
/// and shared state (like the ServiceGraph).
pub struct ServiceContext {
    /// Kubernetes client for API operations
    pub kube: Arc<dyn ServiceKubeClient>,
    /// Service dependency graph (shared across all reconciliations)
    pub graph: Arc<ServiceGraph>,
    /// Cluster name used in trust domain (lattice.{cluster}.local)
    pub cluster_name: String,
    /// Provider type for topology-aware scheduling (zone for cloud, hostname for on-prem)
    pub provider_type: ProviderType,
    /// Cedar policy engine for secret access authorization
    pub cedar: Arc<PolicyEngine>,
    /// Event publisher for emitting Kubernetes Events
    pub events: Arc<dyn EventPublisher>,
    /// Monitoring configuration for this cluster (VictoriaMetrics mode)
    pub monitoring: MonitoringConfig,
    /// Extension phases that run after core compilation
    pub extension_phases: Vec<Arc<dyn CompilerPhase>>,
    /// Metrics scraper for querying VictoriaMetrics
    pub metrics_scraper: Arc<dyn MetricsScraper>,
    /// Cost provider for estimating workload costs (None = cost estimation disabled)
    pub cost_provider: Option<Arc<dyn CostProvider>>,
}

impl ServiceContext {
    /// Create a new ServiceContext with the given dependencies
    pub fn new(
        kube: Arc<dyn ServiceKubeClient>,
        graph: Arc<ServiceGraph>,
        cluster: ClusterConfig,
        cedar: Arc<PolicyEngine>,
        events: Arc<dyn EventPublisher>,
        metrics_scraper: Arc<dyn MetricsScraper>,
    ) -> Self {
        Self {
            kube,
            graph,
            cluster_name: cluster.cluster_name,
            provider_type: cluster.provider_type,
            cedar,
            events,
            monitoring: cluster.monitoring,
            extension_phases: Vec::new(),
            metrics_scraper,
            cost_provider: None,
        }
    }

    /// Create a context for testing with mock clients
    ///
    /// Uses a default-deny PolicyEngine. To test with policies, construct
    /// `ServiceContext` directly with a configured `PolicyEngine`.
    #[cfg(test)]
    pub fn for_testing(kube: Arc<dyn ServiceKubeClient>) -> Self {
        Self {
            kube,
            graph: Arc::new(ServiceGraph::new()),
            cluster_name: "test-cluster".to_string(),
            provider_type: ProviderType::Docker,
            cedar: Arc::new(PolicyEngine::new()),
            events: Arc::new(NoopEventPublisher),
            monitoring: MonitoringConfig::default(),
            extension_phases: Vec::new(),
            metrics_scraper: Arc::new(lattice_common::crd::NoopMetricsScraper),
            cost_provider: None,
        }
    }
}

// =============================================================================
// LatticeService reconciliation
// =============================================================================

/// Annotation key for the inputs hash used by the reconcile guard.
const INPUTS_HASH_ANNOTATION: &str = "lattice.dev/inputs-hash";

/// Check if reconciliation can be skipped because nothing has changed.
///
/// Returns true when the service is Ready or Failed AND:
/// - observed_generation matches metadata.generation (spec unchanged)
/// - stored inputs hash matches the current graph + policy state
///
/// For Failed services, this prevents a tight reconcile loop: if the
/// spec and inputs haven't changed, the same compilation error will
/// recur. The 30-second requeue timer handles retries for transient
/// errors without needing to re-enter the compile path on every
/// watch event.
fn is_reconcile_current(service: &LatticeService, current_inputs_hash: &str) -> bool {
    let status = match service.status.as_ref() {
        Some(s) if s.phase == ServicePhase::Ready || s.phase == ServicePhase::Failed => s,
        _ => return false,
    };

    let generation_matches = matches!(
        (status.observed_generation, service.metadata.generation),
        (Some(observed), Some(current)) if observed == current
    );

    let stored_hash = service
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(INPUTS_HASH_ANNOTATION));

    generation_matches && stored_hash.map(|h| h.as_str()) == Some(current_inputs_hash)
}

/// Reconcile a LatticeService resource
///
/// This function is called whenever a LatticeService is created, updated, or deleted.
/// It maintains the service graph and updates the service status.
///
/// # Arguments
///
/// * `service` - The LatticeService to reconcile
/// * `ctx` - Shared controller context
///
/// # Returns
///
/// An `Action` indicating when to requeue, or an `Error` if reconciliation failed.
#[instrument(skip(service, ctx), fields(service = %service.name_any()))]
pub async fn reconcile(
    service: Arc<LatticeService>,
    ctx: Arc<ServiceContext>,
) -> Result<Action, Error> {
    let name = service.name_any();
    info!("reconciling service");

    // Validate the full service spec (workload, runtime, autoscaling, backup)
    if let Err(e) = service.spec.validate() {
        warn!(error = %e, "service validation failed");
        ServiceStatusUpdate::failed(&e.to_string(), service.metadata.generation)
            .apply(ctx.kube.as_ref(), &service)
            .await?;
        // Validation errors require spec changes, but always requeue as a
        // safety net — watch events can be missed during pod restarts.
        return Ok(Action::requeue(Duration::from_secs(
            lattice_common::REQUEUE_SUCCESS_SECS,
        )));
    }

    // Get current status, defaulting to Pending if not set
    let current_phase = service
        .status
        .as_ref()
        .map(|s| s.phase)
        .unwrap_or(ServicePhase::Pending);

    debug!(?current_phase, "current service phase");

    // Get namespace from metadata (LatticeService is namespace-scoped)
    let namespace = match service.metadata.namespace.as_deref() {
        Some(ns) => ns,
        None => {
            error!("LatticeService is missing namespace - this is a cluster-scoped resource that needs migration");
            ServiceStatusUpdate::failed("Resource missing namespace", service.metadata.generation)
                .apply(ctx.kube.as_ref(), &service)
                .await?;
            return Ok(Action::requeue(Duration::from_secs(
                lattice_common::REQUEUE_SUCCESS_SECS,
            )));
        }
    };

    // Always ensure this service is in the graph (crash recovery)
    // This is idempotent - put_service handles updates correctly
    ctx.graph.put_service(namespace, &name, &service.spec);

    // Pending → transition to Compiling and requeue immediately
    if current_phase == ServicePhase::Pending {
        ServiceStatusUpdate::compiling()
            .apply(ctx.kube.as_ref(), &service)
            .await?;
        return Ok(Action::requeue(REQUEUE_PENDING));
    }

    // All other phases share the same compile path with an inputs-hash guard.
    let active_in = ctx.graph.get_active_inbound_edges(namespace, &name);
    let active_out = ctx.graph.get_active_outbound_edges(namespace, &name);
    let inputs_hash =
        lattice_common::graph::compute_edge_hash(&active_in, &active_out, ctx.cedar.reload_epoch());

    // Skip reconcile when spec and external inputs are unchanged (Ready only).
    // Compiling and Failed services always re-enter the compile path.
    // Metrics are still scraped on every cycle so values populate even when
    // VictoriaMetrics hasn't ingested data at the initial Ready transition.
    if is_reconcile_current(&service, &inputs_hash) {
        debug!("generation and inputs unchanged, skipping reconcile");
        scrape_and_patch_metrics(&service, &ctx).await;
        return Ok(Action::requeue(REQUEUE_READY));
    }

    let missing_deps = check_missing_dependencies(&service.spec, &ctx.graph, namespace);
    if !missing_deps.is_empty() {
        // Log but don't block compilation. The graph already handles Unknown stubs
        // correctly — they don't form bilateral agreements. Blocking here would
        // prevent the service from updating its policies/mesh when a dependency is
        // deleted, causing a liveness hazard.
        warn!(
            ?missing_deps,
            "some dependencies not yet in graph, compiling anyway"
        );
    }

    compile_and_apply(&service, &name, namespace, &ctx, &inputs_hash).await
}

/// Check which dependencies are missing from the graph
fn check_missing_dependencies(
    spec: &LatticeServiceSpec,
    graph: &ServiceGraph,
    namespace: &str,
) -> Vec<String> {
    spec.workload
        .internal_dependencies(namespace)
        .into_iter()
        .filter(|dep| {
            // Check if dependency exists (not Unknown type)
            let dep_ns = dep.resolve_namespace(namespace);
            graph
                .get_service(dep_ns, &dep.name)
                .map(|node| node.type_.is_unknown())
                .unwrap_or(true)
        })
        .map(|dep| {
            // Format as "namespace/name" for cross-namespace deps, just "name" for same namespace
            let dep_ns = dep.resolve_namespace(namespace);
            if dep_ns == namespace {
                dep.name
            } else {
                format!("{}/{}", dep_ns, dep.name)
            }
        })
        .collect()
}

/// Compile a service, apply resources, update status, and record the inputs hash.
///
/// The inputs hash is stored as an annotation so the reconcile guard can
/// suppress retries when nothing has changed (same spec + same graph state =
/// same compilation outcome). The hash is stored on both success and failure
/// so the guard works in all phases.
async fn compile_and_apply(
    service: &LatticeService,
    name: &str,
    namespace: &str,
    ctx: &ServiceContext,
    inputs_hash: &str,
) -> Result<Action, Error> {
    let compiler = ServiceCompiler::new(
        &ctx.graph,
        &ctx.cluster_name,
        ctx.provider_type,
        &ctx.cedar,
        ctx.monitoring.clone(),
    )
    .with_phases(&ctx.extension_phases);
    let compiled = match compiler.compile(service).await {
        Ok(compiled) => compiled,
        Err(e) => {
            let event_reason = if e.is_policy_denied() {
                match &e {
                    lattice_workload::CompilationError::SecurityOverrideDenied { .. } => {
                        reasons::SECURITY_OVERRIDE_DENIED
                    }
                    lattice_workload::CompilationError::VolumeAccessDenied { .. } => {
                        reasons::VOLUME_ACCESS_DENIED
                    }
                    _ => reasons::SECRET_ACCESS_DENIED,
                }
            } else {
                reasons::COMPILATION_FAILED
            };

            // When a Cedar policy revokes secret access, delete ExternalSecrets
            // that were previously applied. Without this, ESO continues syncing
            // the revoked secret from the external store.
            if e.is_policy_denied() {
                if let Err(cleanup_err) = ctx
                    .kube
                    .delete_revoked_external_secrets(name, namespace)
                    .await
                {
                    warn!(error = %cleanup_err, "failed to delete revoked ExternalSecrets (non-fatal)");
                }
            }

            transition_to_failed(service, ctx, &e.to_string(), event_reason).await?;
            record_inputs_hash(ctx, name, namespace, inputs_hash).await;
            return Ok(Action::requeue(Duration::from_secs(30)));
        }
    };

    let has_mesh_member = compiled.mesh_member.is_some();

    debug!(
        resources = compiled.resource_count(),
        "applying compiled resources"
    );
    if let Err(e) = ctx
        .kube
        .apply_compiled_service(name, namespace, &compiled)
        .await
    {
        transition_to_failed(service, ctx, &e.to_string(), reasons::COMPILATION_FAILED).await?;
        // Don't record the inputs hash for apply failures — these are often
        // transient (broken webhook, API server blip, network timeout) and
        // should retry on the next requeue even if inputs are unchanged.
        return Ok(Action::requeue(Duration::from_secs(30)));
    }

    // Clean up resources that were previously applied but are no longer needed.
    // This handles the case where a spec update removes optional features
    // (e.g., removing autoscaling should delete the ScaledObject).
    if let Err(e) = ctx
        .kube
        .cleanup_orphaned_resources(name, namespace, &compiled)
        .await
    {
        // Orphan cleanup failures are non-fatal — the service is functional,
        // just has stale resources. Log and continue.
        warn!(error = %e, "orphan cleanup failed (non-fatal)");
    }

    // Don't mark Ready until the MeshMember controller has fully reconciled
    if has_mesh_member && !ctx.kube.is_mesh_member_ready(name, namespace).await? {
        debug!("mesh member not yet ready, staying in Compiling");
        // Only write status if not already Compiling — avoids watch-event loop
        let already_compiling = service
            .status
            .as_ref()
            .map(|s| s.phase == ServicePhase::Compiling)
            .unwrap_or(false);
        if !already_compiling {
            ServiceStatusUpdate::compiling()
                .apply(ctx.kube.as_ref(), service)
                .await?;
        }
        return Ok(Action::requeue(REQUEUE_PENDING));
    }

    let spec = &service.spec;
    let cost = lattice_cost::try_estimate(&ctx.cost_provider, |rates, ts| {
        lattice_cost::estimate_service_cost(spec, rates, ts)
    })
    .await;

    let existing_metrics = service.status.as_ref().and_then(|s| s.metrics.as_ref());
    let metrics = lattice_common::crd::scrape_metrics(
        ctx.metrics_scraper.as_ref(),
        spec.observability.as_ref(),
        namespace,
        name,
        existing_metrics,
    )
    .await;

    ServiceStatusUpdate::ready(service.metadata.generation)
        .with_cost(cost)
        .with_metrics(metrics)
        .apply(ctx.kube.as_ref(), service)
        .await?;
    record_inputs_hash(ctx, name, namespace, inputs_hash).await;
    Ok(Action::requeue(REQUEUE_READY))
}

/// Transition a service to Failed, skipping both the status write and the
/// K8s event when the status is already identical. Skipping the write
/// prevents a tight reconcile loop (status patch → watch event → reconcile).
async fn transition_to_failed(
    service: &LatticeService,
    ctx: &ServiceContext,
    message: &str,
    event_reason: &str,
) -> Result<(), Error> {
    if status_check::is_status_unchanged(
        service.status.as_ref(),
        &ServicePhase::Failed,
        Some(message),
        service.metadata.generation,
    ) {
        debug!(error = %message, "failure unchanged, skipping status write");
        return Ok(());
    }

    ctx.events
        .publish(
            &service.object_ref(&()),
            EventType::Warning,
            event_reason,
            actions::COMPILE,
            Some(message.to_string()),
        )
        .await;
    warn!(error = %message, "service failed");
    ServiceStatusUpdate::failed(message, service.metadata.generation)
        .apply(ctx.kube.as_ref(), service)
        .await?;
    Ok(())
}

/// Best-effort metrics scrape on steady-state requeues.
///
/// Called when the reconcile guard skips the full compile path so that
/// metrics still populate even when VictoriaMetrics hadn't ingested data
/// at the initial Ready transition.
async fn scrape_and_patch_metrics(service: &LatticeService, ctx: &ServiceContext) {
    let name = service.name_any();
    let namespace = match service.namespace() {
        Some(ns) => ns,
        None => return,
    };

    let existing = service.status.as_ref().and_then(|s| s.metrics.as_ref());
    let metrics = lattice_common::crd::scrape_metrics(
        ctx.metrics_scraper.as_ref(),
        service.spec.observability.as_ref(),
        &namespace,
        &name,
        existing,
    )
    .await;

    // scrape_metrics returns existing unchanged or None when nothing to do.
    if metrics.as_ref() == existing {
        return;
    }

    let mut status = service.status.clone().unwrap_or_default();
    status.metrics = metrics;
    if let Err(e) = ctx
        .kube
        .patch_service_status(&name, &namespace, &status)
        .await
    {
        warn!(error = %e, "failed to patch metrics on steady-state requeue");
    }
}

/// Best-effort store of the inputs hash annotation.
async fn record_inputs_hash(ctx: &ServiceContext, name: &str, namespace: &str, hash: &str) {
    if let Err(e) = ctx
        .kube
        .patch_service_annotation(name, namespace, INPUTS_HASH_ANNOTATION, hash)
        .await
    {
        warn!(error = %e, "failed to patch inputs hash annotation");
    }
}

// =============================================================================
// Service cleanup on delete
// =============================================================================

/// Handle service deletion by removing from the graph
///
/// Called when a LatticeService is deleted. Removes the service from the graph
/// and cleans up edges.
pub fn cleanup_service(service: &LatticeService, ctx: &ServiceContext) {
    let name = service.name_any();
    let namespace = match service.metadata.namespace.as_deref() {
        Some(ns) => ns,
        None => {
            warn!(service = %name, "LatticeService missing namespace during cleanup, skipping");
            return;
        }
    };

    info!(service = %name, namespace = %namespace, "removing service from graph");
    ctx.graph.delete_service(namespace, &name);
}

// =============================================================================
// Status update helpers
// =============================================================================

/// Status update builder — matches Model/Job pattern.
struct ServiceStatusUpdate<'a> {
    phase: ServicePhase,
    message: &'a str,
    condition_type: &'a str,
    condition_status: ConditionStatus,
    reason: &'a str,
    observed_generation: Option<i64>,
    cost: Option<CostEstimate>,
    metrics: Option<MetricsSnapshot>,
}

impl<'a> ServiceStatusUpdate<'a> {
    fn new(phase: ServicePhase) -> Self {
        Self {
            phase,
            message: "",
            condition_type: "",
            condition_status: ConditionStatus::Unknown,
            reason: "",
            observed_generation: None,
            cost: None,
            metrics: None,
        }
    }

    fn message(mut self, msg: &'a str) -> Self {
        self.message = msg;
        self
    }

    fn condition(mut self, type_: &'a str, status: ConditionStatus, reason: &'a str) -> Self {
        self.condition_type = type_;
        self.condition_status = status;
        self.reason = reason;
        self
    }

    fn observed_generation(mut self, gen: Option<i64>) -> Self {
        self.observed_generation = gen;
        self
    }

    fn with_cost(mut self, cost: Option<CostEstimate>) -> Self {
        self.cost = cost;
        self
    }

    fn with_metrics(mut self, metrics: Option<MetricsSnapshot>) -> Self {
        self.metrics = metrics;
        self
    }

    /// Convenience: Compiling phase
    fn compiling() -> Self {
        Self::new(ServicePhase::Compiling)
            .message("Compiling service dependencies")
            .condition("Compiling", ConditionStatus::True, "DependencyCheck")
    }

    /// Convenience: Ready phase
    fn ready(generation: Option<i64>) -> Self {
        Self::new(ServicePhase::Ready)
            .message("Service is operational")
            .condition("Ready", ConditionStatus::True, "ServiceReady")
            .observed_generation(generation)
    }

    /// Convenience: Failed phase
    fn failed(message: &'a str, generation: Option<i64>) -> Self {
        Self::new(ServicePhase::Failed)
            .message(message)
            .condition("Ready", ConditionStatus::False, "ValidationFailed")
            .observed_generation(generation)
    }

    async fn apply(
        self,
        kube: &dyn ServiceKubeClient,
        service: &LatticeService,
    ) -> Result<(), Error> {
        let status = LatticeServiceStatus::with_phase(self.phase)
            .message(self.message)
            .condition(Condition::new(
                self.condition_type,
                self.condition_status,
                self.reason,
                self.message,
            ))
            .observed_generation(self.observed_generation)
            .cost(self.cost)
            .metrics(self.metrics);

        if service.status.as_ref() == Some(&status) {
            return Ok(());
        }

        let name = service.name_any();
        let namespace = lattice_common::kube_utils::effective_namespace(service);
        kube.patch_service_status(&name, &namespace, &status).await
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{ContainerSpec, DependencyDirection, ResourceSpec, WorkloadSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use std::collections::BTreeMap;

    // =========================================================================
    // Test Fixtures
    // =========================================================================

    fn simple_container() -> ContainerSpec {
        ContainerSpec {
            image: "nginx:latest".to_string(),
            command: Some(vec!["/usr/sbin/nginx".to_string()]),
            resources: Some(lattice_common::crd::ResourceRequirements {
                limits: Some(lattice_common::crd::ResourceQuantity {
                    memory: Some("256Mi".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn sample_service_spec() -> LatticeServiceSpec {
        let mut containers = BTreeMap::new();
        containers.insert("main".to_string(), simple_container());

        LatticeServiceSpec {
            workload: WorkloadSpec {
                containers,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn sample_service(name: &str) -> LatticeService {
        LatticeService {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("test".to_string()),
                uid: Some("test-uid-12345".to_string()),
                ..Default::default()
            },
            spec: sample_service_spec(),
            status: None,
        }
    }

    fn service_with_deps(name: &str, deps: Vec<&str>) -> LatticeService {
        let mut spec = sample_service_spec();
        for dep in deps {
            spec.workload.resources.insert(
                dep.to_string(),
                ResourceSpec {
                    direction: DependencyDirection::Outbound,
                    ..Default::default()
                },
            );
        }

        LatticeService {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("test".to_string()),
                uid: Some("test-uid-12345".to_string()),
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    fn service_with_callers(name: &str, callers: Vec<&str>) -> LatticeService {
        let mut spec = sample_service_spec();
        for caller in callers {
            spec.workload.resources.insert(
                caller.to_string(),
                ResourceSpec {
                    direction: DependencyDirection::Inbound,
                    ..Default::default()
                },
            );
        }

        LatticeService {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("test".to_string()),
                uid: Some("test-uid-12345".to_string()),
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    // =========================================================================
    // Mock Setup
    // =========================================================================

    fn mock_kube() -> MockServiceKubeClient {
        let mut mock = MockServiceKubeClient::new();
        mock.expect_patch_service_status()
            .returning(|_, _, _| Ok(()));
        mock.expect_get_service().returning(|_, _| Ok(None));
        mock.expect_list_services().returning(|| Ok(vec![]));
        mock.expect_apply_compiled_service()
            .returning(|_, _, _| Ok(()));
        mock.expect_patch_service_annotation()
            .returning(|_, _, _, _| Ok(()));
        mock.expect_is_mesh_member_ready()
            .returning(|_, _| Ok(true));
        mock.expect_delete_revoked_external_secrets()
            .returning(|_, _| Ok(()));
        mock
    }

    // =========================================================================
    // Reconciliation Story Tests
    // =========================================================================

    /// Story: New service transitions from Pending to Compiling
    #[tokio::test]
    async fn new_service_transitions_to_compiling() {
        let service = Arc::new(sample_service("my-service"));
        let mock_kube = mock_kube();
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        let action = reconcile(service, ctx.clone())
            .await
            .expect("reconcile should succeed");

        // Should requeue quickly to check dependencies
        assert_eq!(action, Action::requeue(REQUEUE_PENDING));

        // Service should be in the graph
        let node = ctx.graph.get_service("test", "my-service");
        assert!(node.is_some());
    }

    /// Story: Service with missing dependencies still compiles (doesn't block)
    #[tokio::test]
    async fn service_compiles_with_missing_dependencies() {
        let mut service = service_with_deps("frontend", vec!["backend"]);
        service.status = Some(LatticeServiceStatus::with_phase(ServicePhase::Compiling));
        let service = Arc::new(service);

        let mut mock_kube = mock_kube();
        mock_kube
            .expect_cleanup_orphaned_resources()
            .returning(|_, _, _| Ok(()));
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        // Put the service in the graph first (but NOT its dependency "backend")
        ctx.graph.put_service("test", "frontend", &service.spec);

        let action = reconcile(service, ctx)
            .await
            .expect("reconcile should succeed");

        // Should proceed to compile (Ready), not block waiting for deps
        assert_eq!(action, Action::requeue(REQUEUE_READY));
    }

    /// Story: Service becomes ready when dependencies exist
    #[tokio::test]
    async fn service_becomes_ready_with_deps() {
        let mut service = service_with_deps("frontend", vec!["backend"]);
        service.status = Some(LatticeServiceStatus::with_phase(ServicePhase::Compiling));
        let service = Arc::new(service);

        let mut mock_kube = mock_kube();
        mock_kube
            .expect_cleanup_orphaned_resources()
            .returning(|_, _, _| Ok(()));
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        // Add both services to graph
        ctx.graph.put_service("test", "frontend", &service.spec);
        ctx.graph
            .put_service("test", "backend", &sample_service_spec());

        let action = reconcile(service, ctx)
            .await
            .expect("reconcile should succeed");

        // Should transition to Ready and requeue periodically
        assert_eq!(action, Action::requeue(REQUEUE_READY));
    }

    /// Story: Service in Ready state stays ready
    #[tokio::test]
    async fn ready_service_stays_ready() {
        let mut service = sample_service("my-service");
        service.status = Some(LatticeServiceStatus::with_phase(ServicePhase::Ready));
        let service = Arc::new(service);

        let mut mock_kube = mock_kube();
        mock_kube
            .expect_cleanup_orphaned_resources()
            .returning(|_, _, _| Ok(()));
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        ctx.graph.put_service("test", "my-service", &service.spec);

        let action = reconcile(service, ctx)
            .await
            .expect("reconcile should succeed");

        // Should requeue for periodic drift check
        assert_eq!(action, Action::requeue(REQUEUE_READY));
    }

    /// Story: Invalid service transitions to Failed
    #[tokio::test]
    async fn invalid_service_fails() {
        let mut service = sample_service("bad-service");
        // Make it invalid by removing containers
        service.spec.workload.containers.clear();
        let service = Arc::new(service);

        let mock_kube = mock_kube();
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        let action = reconcile(service, ctx)
            .await
            .expect("reconcile should succeed");

        // Should requeue with long backoff (safety net for missed watch events)
        assert_eq!(
            action,
            Action::requeue(Duration::from_secs(lattice_common::REQUEUE_SUCCESS_SECS))
        );
    }

    // =========================================================================
    // Graph Integration Tests
    // =========================================================================

    /// Story: Graph tracks active edges with bilateral agreements
    #[tokio::test]
    async fn graph_tracks_bilateral_agreements() {
        let mock_kube = mock_kube();
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        // Frontend depends on backend
        let frontend = service_with_deps("frontend", vec!["backend"]);
        ctx.graph.put_service("test", "frontend", &frontend.spec);

        // Backend allows frontend
        let backend = service_with_callers("backend", vec!["frontend"]);
        ctx.graph.put_service("test", "backend", &backend.spec);

        // Should have active edge from frontend to backend
        let active = ctx.graph.get_active_outbound_edges("test", "frontend");
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].callee_name, "backend");
    }

    /// Story: Graph handles service deletion
    #[tokio::test]
    async fn graph_handles_deletion() {
        let mock_kube = mock_kube();
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        // Add a service
        ctx.graph
            .put_service("test", "my-service", &sample_service_spec());
        assert!(ctx.graph.get_service("test", "my-service").is_some());

        // Create and cleanup
        let service = sample_service("my-service");
        cleanup_service(&service, &ctx);

        // Should be removed
        assert!(ctx.graph.get_service("test", "my-service").is_none());
    }

    // =========================================================================
    // Missing Dependency Detection Tests
    // =========================================================================

    /// Story: Detect missing internal dependencies
    #[test]
    fn detect_missing_dependencies() {
        let graph = ServiceGraph::new();
        let spec = service_with_deps("frontend", vec!["backend", "cache"]).spec;

        // Nothing in graph - all deps missing
        let missing = check_missing_dependencies(&spec, &graph, "test");
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(&"backend".to_string()));
        assert!(missing.contains(&"cache".to_string()));

        // Add backend - now only cache is missing
        graph.put_service("test", "backend", &sample_service_spec());
        let missing = check_missing_dependencies(&spec, &graph, "test");
        assert_eq!(missing.len(), 1);
        assert!(missing.contains(&"cache".to_string()));

        // Add cache - no deps missing
        graph.put_service("test", "cache", &sample_service_spec());
        let missing = check_missing_dependencies(&spec, &graph, "test");
        assert!(missing.is_empty());
    }

    // =========================================================================
    // Environment Isolation Tests
    // =========================================================================

    /// Story: Services are isolated by environment
    #[tokio::test]
    async fn services_isolated_by_environment() {
        let mock_kube = mock_kube();
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        // Add same-named service to different environments
        ctx.graph.put_service("prod", "api", &sample_service_spec());
        ctx.graph
            .put_service("staging", "api", &sample_service_spec());

        // Both should exist independently
        assert!(ctx.graph.get_service("prod", "api").is_some());
        assert!(ctx.graph.get_service("staging", "api").is_some());

        // Deleting one shouldn't affect the other
        ctx.graph.delete_service("prod", "api");
        assert!(ctx.graph.get_service("prod", "api").is_none());
        assert!(ctx.graph.get_service("staging", "api").is_some());
    }

    // =========================================================================
    // Context Builder Tests
    // =========================================================================

    /// Story: Context can share graph across instances
    #[test]
    fn shared_graph_across_contexts() {
        let mock_kube1 = Arc::new(mock_kube());
        let mock_kube2 = Arc::new(mock_kube());
        let shared_graph = Arc::new(ServiceGraph::new());
        let cedar = Arc::new(PolicyEngine::new());

        let cluster = ClusterConfig {
            cluster_name: "test-cluster".into(),
            provider_type: ProviderType::Docker,
            monitoring: MonitoringConfig::default(),
        };
        let ctx1 = ServiceContext::new(
            mock_kube1,
            Arc::clone(&shared_graph),
            cluster.clone(),
            Arc::clone(&cedar),
            Arc::new(NoopEventPublisher),
            Arc::new(lattice_common::crd::NoopMetricsScraper),
        );
        let ctx2 = ServiceContext::new(
            mock_kube2,
            Arc::clone(&shared_graph),
            cluster,
            Arc::clone(&cedar),
            Arc::new(NoopEventPublisher),
            Arc::new(lattice_common::crd::NoopMetricsScraper),
        );

        // Add service via ctx1
        ctx1.graph
            .put_service("shared", "svc", &sample_service_spec());

        // Should be visible via ctx2
        assert!(ctx2.graph.get_service("shared", "svc").is_some());
    }

    // =========================================================================
    // Reconcile Guard Tests (is_reconcile_current)
    // =========================================================================

    fn service_with_status(
        name: &str,
        phase: ServicePhase,
        generation: i64,
        observed_generation: Option<i64>,
        inputs_hash: Option<&str>,
    ) -> LatticeService {
        let mut svc = sample_service(name);
        svc.metadata.generation = Some(generation);
        svc.metadata.annotations = inputs_hash.map(|h| {
            let mut m = BTreeMap::new();
            m.insert(INPUTS_HASH_ANNOTATION.to_string(), h.to_string());
            m
        });
        svc.status =
            Some(LatticeServiceStatus::with_phase(phase).observed_generation(observed_generation));
        svc
    }

    #[test]
    fn reconcile_guard_skips_ready_with_matching_inputs() {
        let svc = service_with_status("svc", ServicePhase::Ready, 1, Some(1), Some("hash-abc"));
        assert!(is_reconcile_current(&svc, "hash-abc"));
    }

    #[test]
    fn reconcile_guard_retries_ready_on_generation_change() {
        let svc = service_with_status("svc", ServicePhase::Ready, 2, Some(1), Some("hash-abc"));
        assert!(!is_reconcile_current(&svc, "hash-abc"));
    }

    #[test]
    fn reconcile_guard_retries_ready_on_hash_change() {
        let svc = service_with_status("svc", ServicePhase::Ready, 1, Some(1), Some("hash-abc"));
        assert!(!is_reconcile_current(&svc, "hash-NEW"));
    }

    /// Failed services with matching inputs are skipped — recompiling with
    /// the same spec and graph state produces the same error. The 30-second
    /// requeue timer handles retries for transient failures without needing
    /// to re-enter the compile path on every watch event.
    #[test]
    fn reconcile_guard_skips_failed_with_matching_inputs() {
        let svc = service_with_status("svc", ServicePhase::Failed, 1, Some(1), Some("hash-abc"));
        assert!(
            is_reconcile_current(&svc, "hash-abc"),
            "Failed service with unchanged inputs should be skipped"
        );
    }

    /// Failed services should retry when the spec changes (generation bump).
    #[test]
    fn reconcile_guard_retries_failed_on_generation_change() {
        let svc = service_with_status("svc", ServicePhase::Failed, 2, Some(1), Some("hash-abc"));
        assert!(!is_reconcile_current(&svc, "hash-abc"));
    }

    /// Failed services should retry when external inputs change (Cedar policy, graph edges).
    #[test]
    fn reconcile_guard_retries_failed_on_hash_change() {
        let svc = service_with_status("svc", ServicePhase::Failed, 1, Some(1), Some("hash-abc"));
        assert!(!is_reconcile_current(&svc, "hash-NEW"));
    }

    /// Failed services without a stored hash always retry (apply failures don't record hash).
    #[test]
    fn reconcile_guard_retries_failed_without_hash() {
        let svc = service_with_status("svc", ServicePhase::Failed, 1, Some(1), None);
        assert!(
            !is_reconcile_current(&svc, "hash-abc"),
            "Failed service with no stored hash should always retry (transient apply failure)"
        );
    }

    /// ServiceStatusUpdate::failed() must set observed_generation so the guard works.
    #[test]
    fn failed_status_update_sets_observed_generation() {
        let update = ServiceStatusUpdate::failed("error", Some(3));
        assert_eq!(
            update.observed_generation,
            Some(3),
            "Failed status must include observed_generation for the reconcile guard to work"
        );
    }

    // =========================================================================
    // Orphan Cleanup Tests — verify resources are cleaned up on spec updates
    // =========================================================================

    /// Build a mock that tracks whether cleanup was called via an AtomicBool flag.
    fn mock_kube_tracking_cleanup(
        flag: Arc<std::sync::atomic::AtomicBool>,
    ) -> MockServiceKubeClient {
        let mut mock = mock_kube();
        mock.expect_cleanup_orphaned_resources()
            .returning(move |_, _, _| {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            });
        mock
    }

    /// Story: When a Ready service is updated and the compilation no longer produces
    /// a ScaledObject (autoscaling removed), cleanup_orphaned_resources is called
    /// with a compiled output that has `scaled_object: None`. This ensures KEDA
    /// doesn't keep auto-scaling with stale configuration.
    #[tokio::test]
    async fn spec_update_triggers_orphan_cleanup() {
        let cleanup_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mock = mock_kube_tracking_cleanup(Arc::clone(&cleanup_called));
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock)));

        let mut service = sample_service("my-svc");
        service.status = Some(LatticeServiceStatus::with_phase(ServicePhase::Compiling));
        let service = Arc::new(service);
        ctx.graph.put_service("test", "my-svc", &service.spec);

        let _action = reconcile(service, ctx).await.expect("reconcile ok");

        assert!(
            cleanup_called.load(std::sync::atomic::Ordering::SeqCst),
            "cleanup_orphaned_resources must be called after successful apply"
        );
    }

    /// Story: When compilation fails, orphan cleanup should NOT be called
    /// (we don't want to delete resources based on a failed compilation).
    #[tokio::test]
    async fn cleanup_not_called_on_compilation_failure() {
        let cleanup_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mock = mock_kube_tracking_cleanup(Arc::clone(&cleanup_called));
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock)));

        // Service with no containers → validation failure → never reaches apply
        let mut service = sample_service("bad-svc");
        service.spec.workload.containers.clear();
        let service = Arc::new(service);

        let _action = reconcile(service, ctx).await.expect("reconcile ok");

        assert!(
            !cleanup_called.load(std::sync::atomic::Ordering::SeqCst),
            "cleanup_orphaned_resources must NOT be called when compilation fails"
        );
    }

    /// Story: Orphan cleanup failure is non-fatal — the service should still
    /// transition to Ready even if cleanup encounters an error.
    #[tokio::test]
    async fn cleanup_failure_is_nonfatal() {
        let mut mock = mock_kube();
        mock.expect_cleanup_orphaned_resources()
            .returning(|_, _, _| Err(Error::internal("cleanup failed")));
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock)));

        let mut service = sample_service("my-svc");
        service.status = Some(LatticeServiceStatus::with_phase(ServicePhase::Compiling));
        let service = Arc::new(service);
        ctx.graph.put_service("test", "my-svc", &service.spec);

        let action = reconcile(service, ctx).await.expect("reconcile ok");

        assert_eq!(
            action,
            Action::requeue(REQUEUE_READY),
            "service should reach Ready even when orphan cleanup fails"
        );
    }
}
