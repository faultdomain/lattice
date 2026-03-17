//! LatticeJob controller implementation
//!
//! Reconciles LatticeJob resources through a state machine:
//! Pending (compile + submit, wait for VCJob to start) -> Running -> Succeeded/Failed
//!
//! The LatticeJob stays in Pending until the VCJob is truly running. Short-lived
//! jobs that complete before we observe Running transition directly: Pending -> Succeeded.
//! VCJobs stuck in Pending past PENDING_TIMEOUT transition: Pending -> Failed.
//!
//! For training jobs, Volcano handles retries via its maxRetry mechanism.
//!
//! Resources are applied in layers to prevent race conditions:
//! - Layer 1: ConfigMaps, Secrets, ExternalSecrets, PVCs, MeshMembers, TracingPolicies,
//!   headless Service
//! - Layer 2: VCJob (only after mesh/security is ready)

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use kube::api::{Api, DynamicObject, PatchParams};
use kube::discovery::ApiResource;
use kube::runtime::controller::Action;
use kube::{Client, Resource, ResourceExt};
use tracing::{error, info, warn};

#[cfg(test)]
use mockall::automock;

use kube::runtime::events::EventType;
use lattice_cedar::PolicyEngine;
use lattice_common::crd::{
    CostEstimate, JobPhase, LatticeJob, LatticeJobStatus, MetricsScraper, MetricsSnapshot,
    ProviderType,
};
use lattice_common::events::{actions, reasons, EventPublisher};
use lattice_common::graph::ServiceGraph;
use lattice_common::kube_utils::ApplyBatch;
use lattice_common::{CrdKind, CrdRegistry, Retryable};
use lattice_cost::CostProvider;

use crate::compiler::{compile_job, CompiledJob, VolcanoWorkload};
use crate::error::JobError;

const FIELD_MANAGER: &str = "lattice-job-controller";

/// Requeue interval while waiting for job to complete
const REQUEUE_RUNNING: Duration = Duration::from_secs(15);

/// Timeout for VCJob stuck in Pending (e.g. ImagePullBackOff, unschedulable)
const PENDING_TIMEOUT: Duration = Duration::from_secs(300);

/// Message set when the job has been submitted but VCJob isn't running yet
const SUBMITTED_MESSAGE: &str = "Job submitted to Volcano";

// =============================================================================
// Trait for dependency injection and testability
// =============================================================================

/// Trait abstracting Kubernetes client operations for LatticeJob
#[cfg_attr(test, automock)]
#[async_trait]
pub trait JobKubeClient: Send + Sync {
    /// Patch the status of a LatticeJob
    async fn patch_job_status(
        &self,
        name: &str,
        namespace: &str,
        status: &LatticeJobStatus,
    ) -> Result<(), JobError>;

    /// Apply compiled job resources in layers
    async fn apply_compiled_job(
        &self,
        name: &str,
        namespace: &str,
        compiled: &CompiledJob,
        volcano_api: &ApiResource,
    ) -> Result<(), JobError>;

    /// Check VCJob status and return the phase (if the VCJob exists)
    async fn check_vcjob_status(
        &self,
        name: &str,
        namespace: &str,
        volcano_api: &ApiResource,
    ) -> Option<VCJobPhase>;

    /// Resolve a Volcano CRD by kind
    async fn resolve_volcano_crd(&self, kind: CrdKind) -> Result<Option<ApiResource>, JobError>;

    /// Check VCCronJob status and return (active_count, last_schedule_time)
    async fn check_cron_status(
        &self,
        name: &str,
        namespace: &str,
        cron_api: &ApiResource,
    ) -> Option<(usize, String)>;
}

/// Real Kubernetes client implementation
pub struct JobKubeClientImpl {
    client: Client,
    registry: Arc<CrdRegistry>,
}

impl JobKubeClientImpl {
    /// Create a new JobKubeClientImpl wrapping the given client and CRD registry
    pub fn new(client: Client, registry: Arc<CrdRegistry>) -> Self {
        Self { client, registry }
    }
}

#[async_trait]
impl JobKubeClient for JobKubeClientImpl {
    async fn patch_job_status(
        &self,
        name: &str,
        namespace: &str,
        status: &LatticeJobStatus,
    ) -> Result<(), JobError> {
        lattice_common::kube_utils::patch_resource_status::<LatticeJob>(
            &self.client,
            name,
            namespace,
            status,
            FIELD_MANAGER,
        )
        .await?;
        Ok(())
    }

    async fn apply_compiled_job(
        &self,
        _name: &str,
        namespace: &str,
        compiled: &CompiledJob,
        volcano_api: &ApiResource,
    ) -> Result<(), JobError> {
        apply_layers(
            &self.client,
            namespace,
            compiled,
            &self.registry,
            volcano_api,
        )
        .await
    }

    async fn check_vcjob_status(
        &self,
        name: &str,
        namespace: &str,
        volcano_api: &ApiResource,
    ) -> Option<VCJobPhase> {
        check_vcjob_status_impl(&self.client, name, namespace, volcano_api).await
    }

    async fn resolve_volcano_crd(&self, kind: CrdKind) -> Result<Option<ApiResource>, JobError> {
        Ok(self.registry.resolve(kind).await?)
    }

    async fn check_cron_status(
        &self,
        name: &str,
        namespace: &str,
        cron_api: &ApiResource,
    ) -> Option<(usize, String)> {
        let api: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), namespace, cron_api);
        match api.get(name).await {
            Ok(obj) => {
                let active = obj
                    .data
                    .get("status")
                    .and_then(|s| s.get("active"))
                    .and_then(|a| a.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                let last_schedule = obj
                    .data
                    .get("status")
                    .and_then(|s| s.get("lastScheduleTime"))
                    .and_then(|t| t.as_str())
                    .unwrap_or("never")
                    .to_string();
                Some((active, last_schedule))
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                warn!(job = %name, "VCCronJob not found — may have been deleted externally");
                None
            }
            Err(e) => {
                warn!(job = %name, error = %e, "failed to check VCCronJob status");
                None
            }
        }
    }
}

// =============================================================================
// VCJob phase (public for trait return type)
// =============================================================================

/// Phase of a Volcano VCJob, derived from its status
#[non_exhaustive]
pub enum VCJobPhase {
    /// VCJob is pending (queued, scheduling)
    Pending,
    /// VCJob is running
    Running,
    /// VCJob completed successfully
    Completed,
    /// VCJob failed (or timed out in Pending)
    Failed,
}

// =============================================================================
// Context
// =============================================================================

/// Shared context for the LatticeJob controller
pub struct JobContext {
    pub kube: Arc<dyn JobKubeClient>,
    pub graph: Arc<ServiceGraph>,
    pub cluster_name: String,
    pub provider_type: ProviderType,
    pub cedar: Arc<PolicyEngine>,
    pub events: Arc<dyn EventPublisher>,
    pub metrics_scraper: Arc<dyn MetricsScraper>,
    /// Cost provider for estimating workload costs (None = cost estimation disabled)
    pub cost_provider: Option<Arc<dyn CostProvider>>,
}

impl JobContext {
    /// Create a new JobContext with the given dependencies
    pub fn new(
        kube: Arc<dyn JobKubeClient>,
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
    pub fn for_testing(kube: Arc<dyn JobKubeClient>) -> Self {
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

// =============================================================================
// Status builder (fluent pattern matching Model controller)
// =============================================================================

/// Status update builder — avoids clone-and-mutate and makes optional fields explicit.
struct StatusUpdate<'a> {
    phase: JobPhase,
    message: Option<&'a str>,
    observed_generation: Option<i64>,
    start_time: Option<String>,
    completion_time: Option<String>,
    cost: Option<CostEstimate>,
    metrics: Option<MetricsSnapshot>,
}

impl<'a> StatusUpdate<'a> {
    fn new(phase: JobPhase) -> Self {
        Self {
            phase,
            message: None,
            observed_generation: None,
            start_time: None,
            completion_time: None,
            cost: None,
            metrics: None,
        }
    }

    fn cost(mut self, cost: &Option<CostEstimate>) -> Self {
        self.cost = cost.clone();
        self
    }

    fn message(mut self, msg: &'a str) -> Self {
        self.message = Some(msg);
        self
    }

    fn observed_generation(mut self, gen: i64) -> Self {
        self.observed_generation = Some(gen);
        self
    }

    fn start_time(mut self, t: String) -> Self {
        self.start_time = Some(t);
        self
    }

    fn completion_time(mut self, t: String) -> Self {
        self.completion_time = Some(t);
        self
    }

    fn metrics(mut self, snapshot: Option<MetricsSnapshot>) -> Self {
        self.metrics = snapshot;
        self
    }

    async fn apply(
        self,
        kube: &dyn JobKubeClient,
        job: &LatticeJob,
        namespace: &str,
    ) -> Result<(), JobError> {
        let name = job.name_any();
        // Preserve fields from existing status unless explicitly overridden
        let start_time = self
            .start_time
            .or_else(|| job.status.as_ref().and_then(|s| s.start_time.clone()));
        let completion_time = self
            .completion_time
            .or_else(|| job.status.as_ref().and_then(|s| s.completion_time.clone()));
        let metrics = self
            .metrics
            .or_else(|| job.status.as_ref().and_then(|s| s.metrics.clone()));
        let status = LatticeJobStatus {
            phase: self.phase,
            message: self.message.map(|m| m.to_string()),
            observed_generation: self.observed_generation,
            start_time,
            completion_time,
            cost: self.cost,
            metrics,
        };
        // Skip redundant writes
        if job.status.as_ref() == Some(&status) {
            return Ok(());
        }
        kube.patch_job_status(&name, namespace, &status).await?;
        Ok(())
    }
}

// =============================================================================
// Reconcile
// =============================================================================

/// Reconcile a LatticeJob resource
pub async fn reconcile(job: Arc<LatticeJob>, ctx: Arc<JobContext>) -> Result<Action, JobError> {
    let name = job.name_any();
    let namespace = job
        .metadata
        .namespace
        .as_deref()
        .ok_or(JobError::MissingNamespace)?;

    if job.metadata.deletion_timestamp.is_some() {
        cleanup_graph(&job, &ctx.graph, namespace);
        return Ok(Action::await_change());
    }

    let generation = job.metadata.generation.unwrap_or(0);

    // Compute cost once per reconcile — always fresh, no stale preservation.
    let job_spec = &job.spec;
    let cost = lattice_cost::try_estimate(&ctx.cost_provider, |rates, ts| {
        lattice_cost::estimate_job_cost(job_spec, rates, ts)
    })
    .await;

    let phase = job
        .status
        .as_ref()
        .map(|s| s.phase.clone())
        .unwrap_or(JobPhase::Pending);

    match phase {
        JobPhase::Pending => reconcile_pending(&job, &ctx, namespace, generation, &cost).await,
        JobPhase::Running => {
            reconcile_running(&job, &ctx, &name, namespace, generation, &cost).await
        }
        // Terminal/unknown phases: safety net requeue — watch events can be missed during pod restarts.
        _ => Ok(Action::requeue(Duration::from_secs(
            lattice_common::REQUEUE_SUCCESS_SECS,
        ))),
    }
}

async fn reconcile_pending(
    job: &LatticeJob,
    ctx: &JobContext,
    namespace: &str,
    generation: i64,
    cost: &Option<CostEstimate>,
) -> Result<Action, JobError> {
    let is_cron = job.spec.is_cron();
    let crd_kind = if is_cron {
        CrdKind::VolcanoCronJob
    } else {
        CrdKind::VolcanoJob
    };
    let volcano_api = match ctx.kube.resolve_volcano_crd(crd_kind).await? {
        Some(ar) => ar,
        None => {
            let msg = format!(
                "Volcano CRD {} not found — install Volcano or remove the job",
                crd_kind.kind_str()
            );
            let _ = StatusUpdate::new(JobPhase::Pending)
                .message(&msg)
                .apply(ctx.kube.as_ref(), job, namespace)
                .await;
            return Err(JobError::VolcanoCrdMissing {
                kind: crd_kind.kind_str(),
            });
        }
    };

    let already_submitted = job
        .status
        .as_ref()
        .and_then(|s| s.message.as_deref())
        .map(|m| m.starts_with(SUBMITTED_MESSAGE))
        .unwrap_or(false);

    if !already_submitted {
        // Guard against re-submitting a VCJob that already exists on the cluster.
        let vcjob_exists = ctx
            .kube
            .check_vcjob_status(&job.name_any(), namespace, &volcano_api)
            .await
            .is_some();
        if vcjob_exists {
            info!(job = %job.name_any(), "VCJob already exists, skipping re-submission");
            StatusUpdate::new(JobPhase::Pending)
                .message(SUBMITTED_MESSAGE)
                .observed_generation(generation)
                .cost(cost)
                .apply(ctx.kube.as_ref(), job, namespace)
                .await?;
        } else {
            submit_job(job, ctx, namespace, generation, is_cron, &volcano_api, cost).await?;
        }
    }

    // Cron jobs go straight to Running — they're perpetual and don't have a "pending" VCJob phase
    if is_cron {
        StatusUpdate::new(JobPhase::Running)
            .message("Cron job active")
            .observed_generation(generation)
            .cost(cost)
            .apply(ctx.kube.as_ref(), job, namespace)
            .await?;
        return Ok(Action::requeue(REQUEUE_RUNNING));
    }

    // Check VCJob phase — only transition to Running when VCJob is truly running.
    // Short jobs may complete before we see Running, so handle all terminal phases here too.
    let name = job.name_any();
    match ctx
        .kube
        .check_vcjob_status(&name, namespace, &volcano_api)
        .await
    {
        Some(VCJobPhase::Running) => {
            info!(job = %name, "VCJob running");
            StatusUpdate::new(JobPhase::Running)
                .message("Job running")
                .observed_generation(generation)
                .cost(cost)
                .apply(ctx.kube.as_ref(), job, namespace)
                .await?;
            Ok(Action::requeue(REQUEUE_RUNNING))
        }
        Some(VCJobPhase::Completed) => {
            handle_job_succeeded(job, ctx, &name, namespace, generation, cost).await
        }
        Some(VCJobPhase::Failed) => {
            handle_job_failure(job, ctx, &name, namespace, generation, cost).await
        }
        Some(VCJobPhase::Pending) | None => Ok(Action::requeue(REQUEUE_RUNNING)),
    }
}

async fn submit_job(
    job: &LatticeJob,
    ctx: &JobContext,
    namespace: &str,
    generation: i64,
    is_cron: bool,
    volcano_api: &ApiResource,
    cost: &Option<CostEstimate>,
) -> Result<(), JobError> {
    let compiled = match compile_job(
        job,
        &ctx.graph,
        &ctx.cluster_name,
        ctx.provider_type,
        &ctx.cedar,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            if e.is_retryable() {
                let msg = format!("Compile failed (will retry): {}", e);
                let _ = StatusUpdate::new(JobPhase::Pending)
                    .message(&msg)
                    .apply(ctx.kube.as_ref(), job, namespace)
                    .await;
            } else {
                cleanup_graph(job, &ctx.graph, namespace);
                let msg = format!("Failed to compile job: {}", e);
                ctx.events
                    .publish(
                        &job.object_ref(&()),
                        EventType::Warning,
                        reasons::JOB_FAILED,
                        actions::COMPILE,
                        Some(msg.clone()),
                    )
                    .await;
                let _ = StatusUpdate::new(JobPhase::Failed)
                    .message(&msg)
                    .observed_generation(generation)
                    .apply(ctx.kube.as_ref(), job, namespace)
                    .await;
            }
            return Err(e);
        }
    };

    let name = job.name_any();
    if let Err(e) = ctx
        .kube
        .apply_compiled_job(&name, namespace, &compiled, volcano_api)
        .await
    {
        cleanup_graph(job, &ctx.graph, namespace);
        let msg = format!("Apply failed (will retry): {}", e);
        let _ = StatusUpdate::new(JobPhase::Pending)
            .message(&msg)
            .apply(ctx.kube.as_ref(), job, namespace)
            .await;
        return Err(e);
    }

    info!(job = %name, cron = is_cron, "submitted job to Volcano");
    ctx.events
        .publish(
            &job.object_ref(&()),
            EventType::Normal,
            reasons::JOB_SUBMITTED,
            actions::RECONCILE,
            Some(format!("Job submitted to Volcano (cron={})", is_cron)),
        )
        .await;

    let mut s = StatusUpdate::new(JobPhase::Pending)
        .message(SUBMITTED_MESSAGE)
        .observed_generation(generation)
        .cost(cost);
    if job.spec.training.is_some() {
        s = s.start_time(chrono::Utc::now().to_rfc3339());
    }
    s.apply(ctx.kube.as_ref(), job, namespace).await?;
    Ok(())
}

async fn reconcile_running(
    job: &LatticeJob,
    ctx: &JobContext,
    name: &str,
    namespace: &str,
    generation: i64,
    cost: &Option<CostEstimate>,
) -> Result<Action, JobError> {
    let observed = job.status.as_ref().and_then(|s| s.observed_generation);
    if observed.is_some() && observed != Some(generation) {
        warn!(
            job = %name,
            observed = ?observed,
            current = generation,
            "spec changed while Running — jobs are immutable once submitted"
        );
    }

    if job.spec.is_cron() {
        return reconcile_running_cron(job, ctx, name, namespace, generation).await;
    }

    let volcano_api = match ctx.kube.resolve_volcano_crd(CrdKind::VolcanoJob).await? {
        Some(ar) => ar,
        None => {
            warn!(job = %name, "cannot check VCJob status: Volcano CRD not discovered");
            return Ok(Action::requeue(REQUEUE_RUNNING));
        }
    };

    match ctx
        .kube
        .check_vcjob_status(name, namespace, &volcano_api)
        .await
    {
        Some(VCJobPhase::Completed) => {
            handle_job_succeeded(job, ctx, name, namespace, generation, cost).await
        }
        Some(VCJobPhase::Failed) => {
            handle_job_failure(job, ctx, name, namespace, generation, cost).await
        }
        _ => {
            let existing_metrics = job.status.as_ref().and_then(|s| s.metrics.as_ref());
            let metrics = lattice_common::crd::scrape_metrics(
                ctx.metrics_scraper.as_ref(),
                job.spec.observability.as_ref(),
                namespace,
                name,
                existing_metrics,
            )
            .await;
            if metrics.as_ref() != existing_metrics {
                StatusUpdate::new(JobPhase::Running)
                    .cost(cost)
                    .metrics(metrics)
                    .apply(ctx.kube.as_ref(), job, namespace)
                    .await?;
            }
            Ok(Action::requeue(REQUEUE_RUNNING))
        }
    }
}

async fn reconcile_running_cron(
    job: &LatticeJob,
    ctx: &JobContext,
    name: &str,
    namespace: &str,
    generation: i64,
) -> Result<Action, JobError> {
    let cron_api = match ctx
        .kube
        .resolve_volcano_crd(CrdKind::VolcanoCronJob)
        .await?
    {
        Some(ar) => ar,
        None => {
            warn!(job = %name, "cannot check VCCronJob status: Volcano CronJob CRD not discovered");
            return Ok(Action::requeue(REQUEUE_RUNNING));
        }
    };

    if let Some((active, last_schedule)) =
        ctx.kube.check_cron_status(name, namespace, &cron_api).await
    {
        let msg = format!(
            "Cron active: {} job(s), last scheduled: {}",
            active, last_schedule
        );
        let _ = StatusUpdate::new(JobPhase::Running)
            .message(&msg)
            .observed_generation(generation)
            .apply(ctx.kube.as_ref(), job, namespace)
            .await;
    }

    Ok(Action::requeue(REQUEUE_RUNNING))
}

/// Handle a failed VCJob — Volcano has exhausted its retries, mark as Failed.
async fn handle_job_failure(
    job: &LatticeJob,
    ctx: &JobContext,
    name: &str,
    namespace: &str,
    generation: i64,
    cost: &Option<CostEstimate>,
) -> Result<Action, JobError> {
    error!(job = %name, "VCJob failed (Volcano exhausted retries)");
    ctx.events
        .publish(
            &job.object_ref(&()),
            EventType::Warning,
            reasons::JOB_FAILED,
            actions::RECONCILE,
            Some("Job failed (Volcano exhausted retries)".to_string()),
        )
        .await;
    cleanup_graph(job, &ctx.graph, namespace);
    StatusUpdate::new(JobPhase::Failed)
        .message("Job failed")
        .observed_generation(generation)
        .completion_time(chrono::Utc::now().to_rfc3339())
        .cost(cost)
        .apply(ctx.kube.as_ref(), job, namespace)
        .await?;
    // Safety net requeue — watch events can be missed during pod restarts.
    Ok(Action::requeue(Duration::from_secs(
        lattice_common::REQUEUE_SUCCESS_SECS,
    )))
}

async fn handle_job_succeeded(
    job: &LatticeJob,
    ctx: &JobContext,
    name: &str,
    namespace: &str,
    generation: i64,
    cost: &Option<CostEstimate>,
) -> Result<Action, JobError> {
    info!(job = %name, "job succeeded");
    ctx.events
        .publish(
            &job.object_ref(&()),
            EventType::Normal,
            reasons::JOB_SUCCEEDED,
            actions::RECONCILE,
            Some("All tasks completed successfully".to_string()),
        )
        .await;
    cleanup_graph(job, &ctx.graph, namespace);
    StatusUpdate::new(JobPhase::Succeeded)
        .message("All tasks completed successfully")
        .observed_generation(generation)
        .completion_time(chrono::Utc::now().to_rfc3339())
        .cost(cost)
        .apply(ctx.kube.as_ref(), job, namespace)
        .await?;
    // Safety net requeue — watch events can be missed during pod restarts.
    Ok(Action::requeue(Duration::from_secs(
        lattice_common::REQUEUE_SUCCESS_SECS,
    )))
}

// =============================================================================
// Graph management
// =============================================================================

fn cleanup_graph(job: &LatticeJob, graph: &ServiceGraph, namespace: &str) {
    let name = job.metadata.name.as_deref().unwrap_or_default();
    for task_name in job.spec.tasks.keys() {
        graph.delete_service(namespace, &format!("{}-{}", name, task_name));
    }
}

// =============================================================================
// Resource application (private — only used by JobKubeClientImpl)
// =============================================================================

async fn apply_layers(
    client: &Client,
    namespace: &str,
    compiled: &CompiledJob,
    registry: &CrdRegistry,
    volcano_api: &ApiResource,
) -> Result<(), JobError> {
    let params = PatchParams::apply(FIELD_MANAGER).force();

    lattice_common::kube_utils::ensure_namespace(client, namespace, None, FIELD_MANAGER).await?;

    // Layer 1: Infrastructure (config, mesh, security, service accounts)
    let cm_ar = ApiResource::erase::<k8s_openapi::api::core::v1::ConfigMap>(&());
    let secret_ar = ApiResource::erase::<k8s_openapi::api::core::v1::Secret>(&());
    let pvc_ar = ApiResource::erase::<k8s_openapi::api::core::v1::PersistentVolumeClaim>(&());
    let sa_ar = ApiResource::erase::<k8s_openapi::api::core::v1::ServiceAccount>(&());

    let mut layer1 = ApplyBatch::new(client.clone(), namespace, &params);

    let vcjob_tasks = match &compiled.workload {
        VolcanoWorkload::Job(vcjob) => &vcjob.spec.tasks,
        VolcanoWorkload::CronJob(cron) => &cron.spec.job_template.spec.tasks,
    };

    for task in vcjob_tasks {
        if let Some(sa_name) = task.template["spec"]["serviceAccountName"].as_str() {
            let sa = lattice_common::kube_utils::compile_service_account(sa_name, namespace);
            layer1.push("ServiceAccount", sa_name, &sa, &sa_ar)?;
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

    layer1.run("layer-1-infrastructure").await?;

    // Layer 2: Volcano workload (VCJob or VCCronJob, after mesh/security is ready)
    let mut layer2 = ApplyBatch::new(client.clone(), namespace, &params);
    let workload_name = match &compiled.workload {
        VolcanoWorkload::Job(vcjob) => {
            layer2.push("VCJob", &vcjob.metadata.name, vcjob, volcano_api)?;
            &vcjob.metadata.name
        }
        VolcanoWorkload::CronJob(cron) => {
            layer2.push("VCCronJob", &cron.metadata.name, cron, volcano_api)?;
            &cron.metadata.name
        }
    };
    layer2.run("layer-2-volcano-workload").await?;

    info!(
        namespace = %namespace,
        workload = %workload_name,
        mesh_members = compiled.mesh_members.len(),
        tracing_policies = compiled.tracing_policies.len(),
        "applied compiled job resources"
    );

    Ok(())
}

// =============================================================================
// VCJob status check (private — only used by JobKubeClientImpl)
// =============================================================================

async fn check_vcjob_status_impl(
    client: &Client,
    name: &str,
    namespace: &str,
    volcano_api: &ApiResource,
) -> Option<VCJobPhase> {
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, volcano_api);

    match api.get(name).await {
        Ok(obj) => {
            let phase = obj
                .data
                .get("status")
                .and_then(|s| s.get("state"))
                .and_then(|s| s.get("phase"))
                .and_then(|p| p.as_str());

            let result = match phase {
                Some("Completed") => VCJobPhase::Completed,
                Some("Failed" | "Terminated" | "Aborted") => VCJobPhase::Failed,
                Some("Restarting") => {
                    let max_retry = obj
                        .data
                        .get("spec")
                        .and_then(|s| s.get("maxRetry"))
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    if max_retry == 0 {
                        warn!(job = %name, "VCJob stuck in Restarting with maxRetry=0, treating as Failed");
                        VCJobPhase::Failed
                    } else {
                        VCJobPhase::Running
                    }
                }
                Some("Running" | "Completing") => VCJobPhase::Running,
                Some("Pending" | "Inqueue") | None => {
                    let age = obj.creation_timestamp().map(|ts| chrono::Utc::now() - ts.0);
                    let timeout = chrono::Duration::from_std(PENDING_TIMEOUT)
                        .unwrap_or(chrono::Duration::seconds(300));
                    if age.map(|a| a > timeout).unwrap_or(false) {
                        warn!(
                            job = %name,
                            age_secs = age.map(|a| a.num_seconds()).unwrap_or(0),
                            "VCJob stuck in Pending for {}s (timeout {}s), treating as Failed",
                            age.map(|a| a.num_seconds()).unwrap_or(0),
                            PENDING_TIMEOUT.as_secs()
                        );
                        VCJobPhase::Failed
                    } else {
                        VCJobPhase::Pending
                    }
                }
                Some(other) => {
                    info!(job = %name, phase = other, "unknown VCJob phase");
                    VCJobPhase::Running
                }
            };
            Some(result)
        }
        Err(kube::Error::Api(ae)) if ae.code == 404 => None,
        Err(e) => {
            warn!(job = %name, error = %e, "failed to check VCJob status");
            None
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use lattice_common::crd::{ContainerSpec, JobTaskSpec, LatticeJobSpec};
    use std::collections::BTreeMap;

    fn make_minimal_job(name: &str) -> LatticeJob {
        let mut tasks = BTreeMap::new();
        tasks.insert(
            "worker".to_string(),
            JobTaskSpec {
                replicas: None,
                workload: lattice_common::crd::workload::spec::WorkloadSpec {
                    containers: BTreeMap::from([(
                        "main".to_string(),
                        ContainerSpec {
                            image: "test:latest".to_string(),
                            ..Default::default()
                        },
                    )]),
                    ..Default::default()
                },
                runtime: Default::default(),
                restart_policy: None,
                policies: None,
            },
        );
        LatticeJob {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("test-ns".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: LatticeJobSpec {
                tasks,
                ..Default::default()
            },
            status: None,
        }
    }

    /// Pending job with successful compile+apply transitions to Pending(submitted) then checks VCJob
    #[tokio::test]
    async fn pending_submits_job() {
        let job = Arc::new(make_minimal_job("my-job"));

        let mut mock = MockJobKubeClient::new();
        let volcano_api = ApiResource::erase::<k8s_openapi::api::batch::v1::Job>(&()); // dummy
        let va = volcano_api.clone();
        mock.expect_resolve_volcano_crd()
            .returning(move |_| Ok(Some(va.clone())));
        mock.expect_apply_compiled_job()
            .returning(|_, _, _, _| Ok(()));
        mock.expect_patch_job_status().returning(|_, _, _| Ok(()));
        mock.expect_check_vcjob_status().returning(|_, _, _| None);

        let ctx = Arc::new(JobContext::for_testing(Arc::new(mock)));

        let action = reconcile(job, ctx).await.expect("reconcile should succeed");
        assert_eq!(action, Action::requeue(REQUEUE_RUNNING));
    }

    /// Running job with completed VCJob transitions to Succeeded
    #[tokio::test]
    async fn running_transitions_to_succeeded() {
        let mut job = make_minimal_job("my-job");
        job.status = Some(LatticeJobStatus {
            phase: JobPhase::Running,
            observed_generation: Some(1),
            ..Default::default()
        });
        let job = Arc::new(job);

        let mut mock = MockJobKubeClient::new();
        let volcano_api = ApiResource::erase::<k8s_openapi::api::batch::v1::Job>(&());
        let va = volcano_api.clone();
        mock.expect_resolve_volcano_crd()
            .returning(move |_| Ok(Some(va.clone())));
        mock.expect_check_vcjob_status()
            .returning(|_, _, _| Some(VCJobPhase::Completed));
        mock.expect_patch_job_status()
            .withf(|_, _, status| status.phase == JobPhase::Succeeded)
            .returning(|_, _, _| Ok(()));

        let ctx = Arc::new(JobContext::for_testing(Arc::new(mock)));

        let action = reconcile(job, ctx).await.expect("reconcile should succeed");
        assert_eq!(
            action,
            Action::requeue(Duration::from_secs(lattice_common::REQUEUE_SUCCESS_SECS))
        );
    }

    /// Running job with failed VCJob transitions to Failed
    #[tokio::test]
    async fn running_transitions_to_failed() {
        let mut job = make_minimal_job("my-job");
        job.status = Some(LatticeJobStatus {
            phase: JobPhase::Running,
            observed_generation: Some(1),
            ..Default::default()
        });
        let job = Arc::new(job);

        let mut mock = MockJobKubeClient::new();
        let volcano_api = ApiResource::erase::<k8s_openapi::api::batch::v1::Job>(&());
        let va = volcano_api.clone();
        mock.expect_resolve_volcano_crd()
            .returning(move |_| Ok(Some(va.clone())));
        mock.expect_check_vcjob_status()
            .returning(|_, _, _| Some(VCJobPhase::Failed));
        mock.expect_patch_job_status()
            .withf(|_, _, status| status.phase == JobPhase::Failed)
            .returning(|_, _, _| Ok(()));

        let ctx = Arc::new(JobContext::for_testing(Arc::new(mock)));

        let action = reconcile(job, ctx).await.expect("reconcile should succeed");
        assert_eq!(
            action,
            Action::requeue(Duration::from_secs(lattice_common::REQUEUE_SUCCESS_SECS))
        );
    }

    /// Succeeded/Failed jobs use safety net requeue
    #[tokio::test]
    async fn terminal_phase_awaits_change() {
        let mut job = make_minimal_job("my-job");
        job.status = Some(LatticeJobStatus {
            phase: JobPhase::Succeeded,
            ..Default::default()
        });
        let job = Arc::new(job);

        let mock = MockJobKubeClient::new();
        let ctx = Arc::new(JobContext::for_testing(Arc::new(mock)));

        let action = reconcile(job, ctx).await.expect("reconcile should succeed");
        assert_eq!(
            action,
            Action::requeue(Duration::from_secs(lattice_common::REQUEUE_SUCCESS_SECS))
        );
    }
}
