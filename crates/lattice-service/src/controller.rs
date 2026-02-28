//! LatticeService controller implementation
//!
//! This module implements the reconciliation logic for LatticeService resources.
//! It follows the Kubernetes controller pattern: observe current state, determine
//! desired state, calculate diff, and apply changes.
//!
//! The controller maintains a ServiceGraph for tracking service dependencies
//! and allowed callers for network policy generation.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use kube::api::{Api, Patch, PatchParams};
use kube::discovery::ApiResource;
use kube::runtime::controller::Action;
use kube::runtime::events::EventType;
use kube::{Client, Resource, ResourceExt};
use tracing::{debug, error, info, instrument, warn};

#[cfg(test)]
use mockall::automock;

use lattice_common::status_check;
use lattice_common::{CrdKind, CrdRegistry};

use lattice_cedar::PolicyEngine;
use lattice_common::events::{actions, reasons, EventPublisher};
use lattice_common::KubeEventPublisher;
#[cfg(test)]
use lattice_common::NoopEventPublisher;

use crate::compiler::{ApplyLayer, CompiledService, CompilerPhase, ServiceCompiler};
use crate::crd::{
    Condition, ConditionStatus, LatticeService, LatticeServicePolicy, LatticeServiceSpec,
    LatticeServiceStatus, MonitoringConfig, ProviderType, ServiceBackupSpec, ServicePhase,
};
use crate::graph::ServiceGraph;
use crate::Error;
use lattice_workload::backup::merge_backup_specs;

const FIELD_MANAGER: &str = "lattice-service-controller";

/// Timeout waiting for ESO to sync imagePullSecret K8s Secrets.
const IMAGE_PULL_SECRET_TIMEOUT: Duration = Duration::from_secs(120);
/// Polling interval while waiting for imagePullSecrets.
const IMAGE_PULL_SECRET_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Requeue interval when service is in Pending phase.
const REQUEUE_PENDING: Duration = Duration::from_secs(5);
/// Requeue interval when waiting for dependencies or mesh readiness.
const REQUEUE_WAITING: Duration = Duration::from_secs(10);
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

    /// List all LatticeServicePolicies across all namespaces
    async fn list_policies(&self) -> Result<Vec<LatticeServicePolicy>, Error>;

    /// Get labels for a namespace (returns empty map if namespace not found)
    async fn get_namespace_labels(&self, name: &str) -> Result<BTreeMap<String, String>, Error>;

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

/// Fetch labels for a Kubernetes namespace. Returns empty map if not found.
pub(crate) async fn fetch_namespace_labels(
    client: &Client,
    name: &str,
) -> Result<BTreeMap<String, String>, kube::Error> {
    use k8s_openapi::api::core::v1::Namespace;
    let api: Api<Namespace> = Api::all(client.clone());
    Ok(api
        .get_opt(name)
        .await?
        .and_then(|ns| ns.metadata.labels)
        .unwrap_or_default())
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
        let api: Api<LatticeService> = Api::namespaced(self.client.clone(), namespace);
        let status_patch = serde_json::json!({ "status": status });

        api.patch_status(
            name,
            &PatchParams::apply(FIELD_MANAGER),
            &Patch::Merge(&status_patch),
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

    async fn list_policies(&self) -> Result<Vec<LatticeServicePolicy>, Error> {
        let api: Api<LatticeServicePolicy> = Api::all(self.client.clone());
        let list = api.list(&Default::default()).await?;
        Ok(list.items)
    }

    async fn get_namespace_labels(&self, name: &str) -> Result<BTreeMap<String, String>, Error> {
        Ok(fetch_namespace_labels(&self.client, name).await?)
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

use lattice_common::kube_utils::ApplyBatch;

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

        for secret_name in &secret_names {
            let start = std::time::Instant::now();
            loop {
                match api.get_opt(secret_name).await? {
                    Some(_) => {
                        debug!(secret = %secret_name, "imagePullSecret exists");
                        break;
                    }
                    None => {
                        if start.elapsed() >= timeout {
                            return Err(Error::internal_with_context(
                                "wait_for_image_pull_secrets",
                                format!(
                                    "timed out waiting for imagePullSecret '{}' in namespace '{}'",
                                    secret_name, namespace
                                ),
                            ));
                        }
                        debug!(
                            secret = %secret_name,
                            elapsed = ?start.elapsed(),
                            "waiting for imagePullSecret to be synced by ESO"
                        );
                        tokio::time::sleep(poll_interval).await;
                    }
                }
            }
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
}

impl ServiceContext {
    /// Create a new ServiceContext with the given dependencies
    pub fn new(
        kube: Arc<dyn ServiceKubeClient>,
        graph: Arc<ServiceGraph>,
        cluster_name: impl Into<String>,
        provider_type: ProviderType,
        cedar: Arc<PolicyEngine>,
        events: Arc<dyn EventPublisher>,
        monitoring: MonitoringConfig,
    ) -> Self {
        Self {
            kube,
            graph,
            cluster_name: cluster_name.into(),
            provider_type,
            cedar,
            events,
            monitoring,
            extension_phases: Vec::new(),
        }
    }

    /// Create a new ServiceContext from a Kubernetes client with a CRD registry
    ///
    /// This creates a new ServiceGraph and default-deny PolicyEngine.
    /// For shared state, create dependencies externally and use the constructor.
    pub fn from_client(
        client: Client,
        cluster_name: impl Into<String>,
        provider_type: ProviderType,
        cedar: Arc<PolicyEngine>,
        registry: Arc<CrdRegistry>,
        monitoring: MonitoringConfig,
    ) -> Self {
        let events = Arc::new(KubeEventPublisher::new(client.clone(), FIELD_MANAGER));
        Self {
            kube: Arc::new(ServiceKubeClientImpl::new(client, registry)),
            graph: Arc::new(ServiceGraph::new()),
            cluster_name: cluster_name.into(),
            provider_type,
            cedar,
            events,
            monitoring,
            extension_phases: Vec::new(),
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
/// Returns true when the service is Ready AND:
/// - observed_generation matches metadata.generation (spec unchanged)
/// - stored inputs hash matches the current graph + policy state
///
/// Failed services are NOT skipped — they always re-enter the compile
/// path so transient errors (e.g. webhook down) self-heal without
/// waiting for a spec change. The error_policy controls retry backoff.
fn is_reconcile_current(service: &LatticeService, current_inputs_hash: &str) -> bool {
    let status = match service.status.as_ref() {
        Some(s) if s.phase == ServicePhase::Ready => s,
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
        update_service_status(
            &service,
            &ctx,
            ServiceStatusUpdate::failed(&e.to_string(), service.metadata.generation),
        )
        .await?;
        // Don't requeue for validation errors - they require spec changes
        return Ok(Action::await_change());
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
            update_service_status(
                &service,
                &ctx,
                ServiceStatusUpdate::failed(
                    "Resource missing namespace",
                    service.metadata.generation,
                ),
            )
            .await?;
            return Ok(Action::await_change());
        }
    };

    // Always ensure this service is in the graph (crash recovery)
    // This is idempotent - put_service handles updates correctly
    ctx.graph.put_service(namespace, &name, &service.spec);

    // Pending → transition to Compiling and requeue immediately
    if current_phase == ServicePhase::Pending {
        update_service_status(&service, &ctx, ServiceStatusUpdate::compiling()).await?;
        return Ok(Action::requeue(REQUEUE_PENDING));
    }

    // All other phases share the same compile path with an inputs-hash guard.
    let active_in = ctx.graph.get_active_inbound_edges(namespace, &name);
    let active_out = ctx.graph.get_active_outbound_edges(namespace, &name);
    let inputs_hash = lattice_common::graph::compute_edge_hash(
        &active_in,
        &active_out,
        ctx.graph.policy_epoch(),
        ctx.cedar.reload_epoch(),
    );

    // Skip reconcile when spec and external inputs are unchanged (Ready only).
    // Compiling and Failed services always re-enter the compile path.
    if is_reconcile_current(&service, &inputs_hash) {
        debug!("generation and inputs unchanged, skipping reconcile");
        return Ok(Action::requeue(REQUEUE_READY));
    }

    let missing_deps = check_missing_dependencies(&service.spec, &ctx.graph, namespace);
    if !missing_deps.is_empty() {
        if current_phase == ServicePhase::Ready {
            warn!(?missing_deps, "dependencies no longer available");
        } else {
            debug!(?missing_deps, "waiting for dependencies");
        }
        update_service_status(&service, &ctx, ServiceStatusUpdate::compiling()).await?;
        return Ok(Action::requeue(REQUEUE_WAITING));
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

/// Resolve policy defaults (backup + ingress) for a service in one pass.
///
/// Reads cached policies and namespace labels from the ServiceGraph.
/// On the first reconcile for a namespace, fetches labels from the API
/// server and caches them in the graph.
///
/// Extracts:
/// - Backup: merged from matching policies (priority-ordered) + inline spec
/// - Ingress: first matching policy with ingress set wins (no deep merge)
async fn resolve_policy_defaults(
    service: &LatticeService,
    namespace: &str,
    ctx: &ServiceContext,
) -> (
    Option<ServiceBackupSpec>,
    Option<crate::crd::IngressPolicySpec>,
) {
    // Ensure namespace labels are cached
    if ctx.graph.get_namespace_labels(namespace).is_none() {
        match ctx.kube.get_namespace_labels(namespace).await {
            Ok(labels) => ctx.graph.put_namespace_labels(namespace, labels),
            Err(e) => {
                debug!(error = %e, "failed to get namespace labels");
            }
        }
    }

    let svc_labels = service.labels();
    let matched = ctx.graph.matching_policies(svc_labels, namespace);
    if matched.is_empty() {
        return (None, None);
    }

    // Backup: merge matching policy backup specs with inline spec
    let policy_backup_specs: Vec<&ServiceBackupSpec> =
        matched.iter().filter_map(|p| p.backup.as_ref()).collect();
    let effective_backup = if policy_backup_specs.is_empty() {
        None
    } else {
        merge_backup_specs(&policy_backup_specs, service.spec.backup.as_ref())
    };

    // Ingress: first matching policy with ingress wins
    let ingress_defaults = matched.into_iter().find_map(|p| p.ingress);

    (effective_backup, ingress_defaults)
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
    // Resolve policy defaults (backup + ingress) in one pass
    let (effective_backup, ingress_defaults) =
        resolve_policy_defaults(service, namespace, ctx).await;

    // Apply ingress defaults to service if needed
    let mut service_with_defaults;
    let effective_service = if let (Some(ref ingress_spec), Some(ref defaults)) =
        (&service.spec.ingress, &ingress_defaults)
    {
        let mut ingress = ingress_spec.clone();
        // Apply default gateway class if not set
        if ingress.gateway_class.is_none() {
            ingress.gateway_class.clone_from(&defaults.gateway_class);
        }
        // Apply default TLS to routes that have no TLS
        if let Some(ref default_tls) = defaults.tls {
            for (_route_name, route) in ingress.routes.iter_mut() {
                if route.tls.is_none() {
                    route.tls = Some(default_tls.clone());
                }
            }
        }
        service_with_defaults = service.clone();
        service_with_defaults.spec.ingress = Some(ingress);
        &service_with_defaults
    } else {
        service
    };

    let compiler = ServiceCompiler::new(
        &ctx.graph,
        &ctx.cluster_name,
        ctx.provider_type,
        &ctx.cedar,
        ctx.monitoring.clone(),
    )
    .with_phases(&ctx.extension_phases)
    .with_effective_backup(effective_backup);
    let compiled = match compiler.compile(effective_service).await {
        Ok(compiled) => compiled,
        Err(e) => {
            let msg = e.to_string();

            // Skip redundant events when status hasn't changed (status update
            // itself is guarded by update_service_status's idempotency check).
            if !status_check::is_status_unchanged(
                service.status.as_ref(),
                &ServicePhase::Failed,
                Some(&msg),
                service.metadata.generation,
            ) {
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
                ctx.events
                    .publish(
                        &service.object_ref(&()),
                        EventType::Warning,
                        event_reason,
                        actions::COMPILE,
                        Some(msg.clone()),
                    )
                    .await;
                warn!(error = %msg, "compilation failed");
            } else {
                debug!(error = %msg, "compilation still failing");
            }

            update_service_status(
                service,
                ctx,
                ServiceStatusUpdate::failed(&msg, service.metadata.generation),
            )
            .await?;
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
        let msg = e.to_string();
        if !status_check::is_status_unchanged(
            service.status.as_ref(),
            &ServicePhase::Failed,
            Some(&msg),
            service.metadata.generation,
        ) {
            error!(error = %msg, "failed to apply compiled resources");
        } else {
            debug!(error = %msg, "apply still failing");
        }
        update_service_status(
            service,
            ctx,
            ServiceStatusUpdate::failed(&msg, service.metadata.generation),
        )
        .await?;
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
        update_service_status(service, ctx, ServiceStatusUpdate::compiling()).await?;
        return Ok(Action::requeue(REQUEUE_PENDING));
    }

    update_service_status(
        service,
        ctx,
        ServiceStatusUpdate::ready(service.metadata.generation),
    )
    .await?;
    record_inputs_hash(ctx, name, namespace, inputs_hash).await;
    Ok(Action::requeue(REQUEUE_READY))
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

/// Status update configuration for LatticeService
struct ServiceStatusUpdate<'a> {
    phase: ServicePhase,
    message: &'a str,
    condition_type: &'a str,
    condition_status: ConditionStatus,
    reason: &'a str,
    set_compiled_at: bool,
    observed_generation: Option<i64>,
}

impl<'a> ServiceStatusUpdate<'a> {
    fn compiling() -> Self {
        Self {
            phase: ServicePhase::Compiling,
            message: "Compiling service dependencies",
            condition_type: "Compiling",
            condition_status: ConditionStatus::True,
            reason: "DependencyCheck",
            set_compiled_at: false,
            observed_generation: None,
        }
    }

    fn ready(generation: Option<i64>) -> Self {
        Self {
            phase: ServicePhase::Ready,
            message: "Service is operational",
            condition_type: "Ready",
            condition_status: ConditionStatus::True,
            reason: "ServiceReady",
            set_compiled_at: true,
            observed_generation: generation,
        }
    }

    fn failed(message: &'a str, generation: Option<i64>) -> Self {
        Self {
            phase: ServicePhase::Failed,
            message,
            condition_type: "Ready",
            condition_status: ConditionStatus::False,
            reason: "ValidationFailed",
            set_compiled_at: false,
            observed_generation: generation,
        }
    }
}

/// Update LatticeService status with the given configuration.
///
/// Skips the patch if phase and message already match the current status,
/// preventing a self-triggering reconcile storm.
async fn update_service_status(
    service: &LatticeService,
    ctx: &ServiceContext,
    update: ServiceStatusUpdate<'_>,
) -> Result<(), Error> {
    // Check if status already matches — avoid update loop
    if status_check::is_status_unchanged(
        service.status.as_ref(),
        &update.phase,
        Some(update.message),
        update.observed_generation,
    ) {
        debug!("status unchanged, skipping update");
        return Ok(());
    }

    let name = service.name_any();
    let namespace = service.namespace().unwrap_or_default();

    let mut status = LatticeServiceStatus::with_phase(update.phase)
        .message(update.message)
        .condition(Condition::new(
            update.condition_type,
            update.condition_status,
            update.reason,
            update.message,
        ))
        .observed_generation(update.observed_generation);

    if update.set_compiled_at {
        status = status.compiled_at(Utc::now());
    }

    ctx.kube
        .patch_service_status(&name, &namespace, &status)
        .await
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        BackupHook, BackupHooksSpec, ContainerSpec, DependencyDirection, HookErrorAction,
        LatticeServicePolicySpec, ResourceSpec, ServiceSelector, VolumeBackupDefault,
        VolumeBackupSpec, WorkloadSpec,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

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
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    // =========================================================================
    // Mock Setup
    // =========================================================================

    fn mock_kube_with_policies(policies: Vec<LatticeServicePolicy>) -> MockServiceKubeClient {
        let mut mock = MockServiceKubeClient::new();
        mock.expect_patch_service_status()
            .returning(|_, _, _| Ok(()));
        mock.expect_get_service().returning(|_, _| Ok(None));
        mock.expect_list_services().returning(|| Ok(vec![]));
        mock.expect_list_policies()
            .returning(move || Ok(policies.clone()));
        mock.expect_get_namespace_labels()
            .returning(|_| Ok(BTreeMap::new()));
        mock.expect_apply_compiled_service()
            .returning(|_, _, _| Ok(()));
        mock.expect_patch_service_annotation()
            .returning(|_, _, _, _| Ok(()));
        mock.expect_is_mesh_member_ready()
            .returning(|_, _| Ok(true));
        mock
    }

    /// Helper to populate the graph with policies from LatticeServicePolicy objects
    fn populate_graph_policies(ctx: &ServiceContext, policies: &[LatticeServicePolicy]) {
        for p in policies {
            ctx.graph.put_policy(p.into());
        }
    }

    fn make_hook(name: &str, cmd: &str) -> BackupHook {
        BackupHook {
            name: name.to_string(),
            container: "main".to_string(),
            command: vec!["/bin/sh".to_string(), "-c".to_string(), cmd.to_string()],
            timeout: None,
            on_error: HookErrorAction::Continue,
        }
    }

    // =========================================================================
    // Reconciliation Story Tests
    // =========================================================================

    /// Story: New service transitions from Pending to Compiling
    #[tokio::test]
    async fn new_service_transitions_to_compiling() {
        let service = Arc::new(sample_service("my-service"));
        let mock_kube = mock_kube_with_policies(vec![]);
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

    /// Story: Service with dependencies waits for them
    #[tokio::test]
    async fn service_waits_for_dependencies() {
        let mut service = service_with_deps("frontend", vec!["backend"]);
        service.status = Some(LatticeServiceStatus::with_phase(ServicePhase::Compiling));
        let service = Arc::new(service);

        let mock_kube = mock_kube_with_policies(vec![]);
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        // Put the service in the graph first
        ctx.graph.put_service("test", "frontend", &service.spec);

        let action = reconcile(service, ctx)
            .await
            .expect("reconcile should succeed");

        // Should requeue to wait for dependencies
        assert_eq!(action, Action::requeue(REQUEUE_WAITING));
    }

    /// Story: Service becomes ready when dependencies exist
    #[tokio::test]
    async fn service_becomes_ready_with_deps() {
        let mut service = service_with_deps("frontend", vec!["backend"]);
        service.status = Some(LatticeServiceStatus::with_phase(ServicePhase::Compiling));
        let service = Arc::new(service);

        let mut mock_kube = mock_kube_with_policies(vec![]);
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

        let mut mock_kube = mock_kube_with_policies(vec![]);
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

        let mock_kube = mock_kube_with_policies(vec![]);
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        let action = reconcile(service, ctx)
            .await
            .expect("reconcile should succeed");

        // Should await change (no requeue)
        assert_eq!(action, Action::await_change());
    }

    // =========================================================================
    // Graph Integration Tests
    // =========================================================================

    /// Story: Graph tracks active edges with bilateral agreements
    #[tokio::test]
    async fn graph_tracks_bilateral_agreements() {
        let mock_kube = mock_kube_with_policies(vec![]);
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
        let mock_kube = mock_kube_with_policies(vec![]);
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
        let mock_kube = mock_kube_with_policies(vec![]);
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
        let mock_kube1 = Arc::new(mock_kube_with_policies(vec![]));
        let mock_kube2 = Arc::new(mock_kube_with_policies(vec![]));
        let shared_graph = Arc::new(ServiceGraph::new());
        let cedar = Arc::new(PolicyEngine::new());

        let ctx1 = ServiceContext::new(
            mock_kube1,
            Arc::clone(&shared_graph),
            "test-cluster",
            ProviderType::Docker,
            Arc::clone(&cedar),
            Arc::new(NoopEventPublisher),
            MonitoringConfig::default(),
        );
        let ctx2 = ServiceContext::new(
            mock_kube2,
            Arc::clone(&shared_graph),
            "test-cluster",
            ProviderType::Docker,
            Arc::clone(&cedar),
            Arc::new(NoopEventPublisher),
            MonitoringConfig::default(),
        );

        // Add service via ctx1
        ctx1.graph
            .put_service("shared", "svc", &sample_service_spec());

        // Should be visible via ctx2
        assert!(ctx2.graph.get_service("shared", "svc").is_some());
    }

    // =========================================================================
    // Story: Policy-based backup merging in compile_and_apply
    // =========================================================================

    fn make_policy(
        name: &str,
        namespace: &str,
        priority: i32,
        backup: Option<ServiceBackupSpec>,
    ) -> LatticeServicePolicy {
        LatticeServicePolicy {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: LatticeServicePolicySpec {
                selector: ServiceSelector::default(), // matches all in same namespace
                description: None,
                priority,
                backup,
                ingress: None,
            },
            status: None,
        }
    }

    /// Story: When policies with backup specs match a service, compile_and_apply
    /// produces backup annotations on the deployment
    #[tokio::test]
    async fn policy_backup_applied_to_service() {
        let policy_backup = ServiceBackupSpec {
            hooks: Some(BackupHooksSpec {
                pre: vec![BackupHook {
                    timeout: Some("60s".to_string()),
                    on_error: HookErrorAction::Fail,
                    ..make_hook("policy-freeze", "sync")
                }],
                post: vec![],
            }),
            volumes: Some(VolumeBackupSpec {
                include: vec!["data".to_string()],
                exclude: vec![],
                default_policy: VolumeBackupDefault::OptIn,
            }),
            ..Default::default()
        };

        let policy = make_policy("db-backup", "test", 100, Some(policy_backup));
        let mut mock_kube = mock_kube_with_policies(vec![]);
        mock_kube
            .expect_cleanup_orphaned_resources()
            .returning(|_, _, _| Ok(()));

        let mut service = sample_service("my-db");
        service.status = Some(LatticeServiceStatus::with_phase(ServicePhase::Compiling));

        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));
        populate_graph_policies(&ctx, &[policy]);
        ctx.graph.put_service("test", "my-db", &service.spec);

        let result = reconcile(Arc::new(service), ctx).await;
        assert!(result.is_ok());
    }

    /// Story: resolve_policy_defaults merges policy + inline correctly
    #[tokio::test]
    async fn resolve_effective_backup_merges_policies() {
        // Low-priority policy: hooks + volumes
        let low_policy = make_policy(
            "low",
            "test",
            10,
            Some(ServiceBackupSpec {
                hooks: Some(BackupHooksSpec {
                    pre: vec![make_hook("low-hook", "low")],
                    post: vec![],
                }),
                volumes: Some(VolumeBackupSpec {
                    include: vec!["low-vol".to_string()],
                    exclude: vec![],
                    default_policy: VolumeBackupDefault::OptIn,
                }),
                ..Default::default()
            }),
        );

        // High-priority policy: hooks override low, no volumes
        let high_policy = make_policy(
            "high",
            "test",
            100,
            Some(ServiceBackupSpec {
                hooks: Some(BackupHooksSpec {
                    pre: vec![make_hook("high-hook", "high")],
                    post: vec![],
                }),
                volumes: None,
                ..Default::default()
            }),
        );

        let policies = vec![low_policy, high_policy];
        let mock_kube = mock_kube_with_policies(vec![]);
        let service = sample_service("my-app");
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));
        populate_graph_policies(&ctx, &policies);

        let (backup, _ingress) = resolve_policy_defaults(&service, "test", &ctx).await;

        let backup = backup.expect("should have merged backup");
        // Hooks from high-priority policy
        assert_eq!(backup.hooks.as_ref().unwrap().pre[0].name, "high-hook");
        // Volumes from low-priority (high didn't set them)
        assert_eq!(backup.volumes.as_ref().unwrap().include, vec!["low-vol"]);
    }

    /// Story: No matching policies returns None
    #[tokio::test]
    async fn resolve_effective_backup_no_policies() {
        let mock_kube = mock_kube_with_policies(vec![]);
        let service = sample_service("my-app");
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        let (backup, ingress) = resolve_policy_defaults(&service, "test", &ctx).await;

        assert!(backup.is_none());
        assert!(ingress.is_none());
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

    /// Failed services always retry — they are never skipped by the guard.
    /// Transient errors (webhook down, API blip) self-heal without needing
    /// a spec change. The error_policy controls retry backoff.
    #[test]
    fn reconcile_guard_retries_failed_even_with_matching_inputs() {
        let svc = service_with_status("svc", ServicePhase::Failed, 1, Some(1), Some("hash-abc"));
        assert!(
            !is_reconcile_current(&svc, "hash-abc"),
            "Failed service should always retry, even with matching generation + hash"
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

    /// Story: Policy matches only same namespace when no namespace selector
    #[tokio::test]
    async fn resolve_effective_backup_namespace_scoping() {
        // Policy in "other" namespace — should NOT match service in "test"
        let policy = make_policy(
            "other-ns-policy",
            "other",
            100,
            Some(ServiceBackupSpec {
                hooks: Some(BackupHooksSpec {
                    pre: vec![make_hook("should-not-match", "true")],
                    post: vec![],
                }),
                volumes: None,
                ..Default::default()
            }),
        );

        let mock_kube = mock_kube_with_policies(vec![]);
        let service = sample_service("my-app");
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));
        populate_graph_policies(&ctx, &[policy]);

        let (backup, _ingress) = resolve_policy_defaults(&service, "test", &ctx).await;

        // Policy is in "other" namespace, service is in "test" — no match
        assert!(backup.is_none());
    }

    // =========================================================================
    // Orphan Cleanup Tests — verify resources are cleaned up on spec updates
    // =========================================================================

    /// Build a mock that tracks whether cleanup was called via an AtomicBool flag.
    fn mock_kube_tracking_cleanup(
        flag: Arc<std::sync::atomic::AtomicBool>,
    ) -> MockServiceKubeClient {
        let mut mock = mock_kube_with_policies(vec![]);
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
        let mut mock = mock_kube_with_policies(vec![]);
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
