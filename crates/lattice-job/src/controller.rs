//! LatticeJob controller implementation
//!
//! Reconciles LatticeJob resources through a state machine:
//! Pending (compile + submit, wait for VCJob to start) -> Running -> Succeeded/Failed
//!
//! The LatticeJob stays in Pending until the VCJob is truly running. Short-lived
//! jobs that complete before we observe Running transition directly: Pending -> Succeeded.
//! VCJobs stuck in Pending past PENDING_TIMEOUT transition: Pending -> Failed.
//!
//! For training jobs with checkpoints, Volcano handles retries via its maxRetry
//! mechanism. PVCs persist across restarts so checkpoint data survives pod failures.
//!
//! Resources are applied in layers to prevent race conditions:
//! - Layer 1: ConfigMaps, Secrets, ExternalSecrets, PVCs, MeshMembers, TracingPolicies,
//!   headless Service
//! - Layer 2: VCJob (only after mesh/security is ready)

use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, DynamicObject, PatchParams};
use kube::discovery::ApiResource;
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{error, info, warn};

use lattice_cedar::PolicyEngine;
use lattice_common::crd::{JobPhase, LatticeJob, LatticeJobStatus, ProviderType};
use lattice_common::graph::ServiceGraph;
use lattice_common::kube_utils::ApplyBatch;
use lattice_common::{CrdKind, CrdRegistry, Retryable};

use crate::compiler::{compile_job, CompiledJob, VolcanoWorkload};
use crate::error::JobError;

const FIELD_MANAGER: &str = "lattice-job-controller";

/// Requeue interval while waiting for job to complete
const REQUEUE_RUNNING: Duration = Duration::from_secs(15);

/// Timeout for VCJob stuck in Pending (e.g. ImagePullBackOff, unschedulable)
const PENDING_TIMEOUT: Duration = Duration::from_secs(300);

/// Message set when the job has been submitted but VCJob isn't running yet
const SUBMITTED_MESSAGE: &str = "Job submitted to Volcano";

/// Shared context for the LatticeJob controller
pub struct JobContext {
    pub client: Client,
    pub graph: Arc<ServiceGraph>,
    pub cluster_name: String,
    pub provider_type: ProviderType,
    pub cedar: Arc<PolicyEngine>,
    pub registry: Arc<CrdRegistry>,
}

impl JobContext {
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
    let phase = job
        .status
        .as_ref()
        .map(|s| s.phase.clone())
        .unwrap_or(JobPhase::Pending);

    match phase {
        JobPhase::Pending => reconcile_pending(&job, &ctx, namespace, generation).await,
        JobPhase::Running => reconcile_running(&job, &ctx, &name, namespace, generation).await,
        _ => Ok(Action::await_change()),
    }
}

async fn reconcile_pending(
    job: &LatticeJob,
    ctx: &JobContext,
    namespace: &str,
    generation: i64,
) -> Result<Action, JobError> {
    let is_cron = job.spec.is_cron();
    let crd_kind = if is_cron {
        CrdKind::VolcanoCronJob
    } else {
        CrdKind::VolcanoJob
    };
    let volcano_api = match ctx.registry.resolve(crd_kind).await? {
        Some(ar) => ar,
        None => {
            let msg = format!(
                "Volcano CRD {} not found — install Volcano or remove the job",
                crd_kind.kind_str()
            );
            let mut status = current_status(job);
            status.message = Some(msg);
            let _ = patch_status(
                &ctx.client,
                &job.name_any(),
                namespace,
                &status,
                job.status.as_ref(),
            )
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
        submit_job(job, ctx, namespace, generation, is_cron, &volcano_api).await?;
    }

    // Cron jobs go straight to Running — they're perpetual and don't have a "pending" VCJob phase
    if is_cron {
        let name = job.name_any();
        let mut status = current_status(job);
        status.phase = JobPhase::Running;
        status.message = Some("Cron job active".to_string());
        status.observed_generation = Some(generation);
        patch_status(&ctx.client, &name, namespace, &status, job.status.as_ref()).await?;
        return Ok(Action::requeue(REQUEUE_RUNNING));
    }

    // Check VCJob phase — only transition to Running when VCJob is truly running.
    // Short jobs may complete before we see Running, so handle all terminal phases here too.
    let name = job.name_any();
    match check_vcjob_status(&ctx.client, &name, namespace, &volcano_api).await {
        Some(VCJobPhase::Running) => {
            info!(job = %name, "VCJob running");
            let mut status = current_status(job);
            status.phase = JobPhase::Running;
            status.message = Some("Job running".to_string());
            status.observed_generation = Some(generation);
            patch_status(&ctx.client, &name, namespace, &status, job.status.as_ref()).await?;
            Ok(Action::requeue(REQUEUE_RUNNING))
        }
        Some(VCJobPhase::Completed) => {
            handle_job_succeeded(job, ctx, &name, namespace, generation).await
        }
        Some(VCJobPhase::Failed) => {
            handle_job_failure(job, ctx, &name, namespace, generation).await
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
            let name = job.name_any();
            if e.is_retryable() {
                let mut status = current_status(job);
                status.message = Some(format!("Compile failed (will retry): {}", e));
                let _ =
                    patch_status(&ctx.client, &name, namespace, &status, job.status.as_ref()).await;
            } else {
                cleanup_graph(job, &ctx.graph, namespace);
                let mut status = current_status(job);
                status.phase = JobPhase::Failed;
                status.message = Some(format!("Failed to compile job: {}", e));
                status.observed_generation = Some(generation);
                let _ =
                    patch_status(&ctx.client, &name, namespace, &status, job.status.as_ref()).await;
            }
            return Err(e);
        }
    };

    let name = job.name_any();
    if let Err(e) = apply_layers(
        &ctx.client,
        namespace,
        &compiled,
        &ctx.registry,
        volcano_api,
    )
    .await
    {
        cleanup_graph(job, &ctx.graph, namespace);
        let mut status = current_status(job);
        status.message = Some(format!("Apply failed (will retry): {}", e));
        let _ = patch_status(&ctx.client, &name, namespace, &status, job.status.as_ref()).await;
        return Err(e);
    }

    info!(job = %name, cron = is_cron, "submitted job to Volcano");

    let mut status = current_status(job);
    status.message = Some(SUBMITTED_MESSAGE.to_string());
    status.observed_generation = Some(generation);
    if job.spec.training.is_some() {
        status.start_time = Some(chrono::Utc::now().to_rfc3339());
    }
    patch_status(&ctx.client, &name, namespace, &status, job.status.as_ref()).await?;
    Ok(())
}

async fn reconcile_running(
    job: &LatticeJob,
    ctx: &JobContext,
    name: &str,
    namespace: &str,
    generation: i64,
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

    let volcano_api = match ctx.registry.resolve(CrdKind::VolcanoJob).await? {
        Some(ar) => ar,
        None => {
            warn!(job = %name, "cannot check VCJob status: Volcano CRD not discovered");
            return Ok(Action::requeue(REQUEUE_RUNNING));
        }
    };

    match check_vcjob_status(&ctx.client, name, namespace, &volcano_api).await {
        Some(VCJobPhase::Completed) => {
            handle_job_succeeded(job, ctx, name, namespace, generation).await
        }
        Some(VCJobPhase::Failed) => handle_job_failure(job, ctx, name, namespace, generation).await,
        _ => Ok(Action::requeue(REQUEUE_RUNNING)),
    }
}

async fn reconcile_running_cron(
    job: &LatticeJob,
    ctx: &JobContext,
    name: &str,
    namespace: &str,
    generation: i64,
) -> Result<Action, JobError> {
    let cron_api = match ctx.registry.resolve(CrdKind::VolcanoCronJob).await? {
        Some(ar) => ar,
        None => {
            warn!(job = %name, "cannot check VCCronJob status: Volcano CronJob CRD not discovered");
            return Ok(Action::requeue(REQUEUE_RUNNING));
        }
    };

    let api: Api<DynamicObject> = Api::namespaced_with(ctx.client.clone(), namespace, &cron_api);
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
                .unwrap_or("never");

            let mut status = current_status(job);
            status.message = Some(format!(
                "Cron active: {} job(s), last scheduled: {}",
                active, last_schedule
            ));
            status.observed_generation = Some(generation);
            let _ = patch_status(&ctx.client, name, namespace, &status, job.status.as_ref()).await;
        }
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            warn!(job = %name, "VCCronJob not found — may have been deleted externally");
        }
        Err(e) => {
            warn!(job = %name, error = %e, "failed to check VCCronJob status");
        }
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
) -> Result<Action, JobError> {
    error!(job = %name, "VCJob failed (Volcano exhausted retries)");
    cleanup_graph(job, &ctx.graph, namespace);
    let mut status = current_status(job);
    status.phase = JobPhase::Failed;
    status.message = Some("Job failed".to_string());
    status.observed_generation = Some(generation);
    status.completion_time = Some(chrono::Utc::now().to_rfc3339());
    patch_status(&ctx.client, name, namespace, &status, job.status.as_ref()).await?;
    Ok(Action::await_change())
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
// Resource application
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
// VCJob status
// =============================================================================

enum VCJobPhase {
    Pending,
    Running,
    Completed,
    Failed,
}

async fn check_vcjob_status(
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

async fn handle_job_succeeded(
    job: &LatticeJob,
    ctx: &JobContext,
    name: &str,
    namespace: &str,
    generation: i64,
) -> Result<Action, JobError> {
    info!(job = %name, "job succeeded");
    cleanup_graph(job, &ctx.graph, namespace);
    let mut status = current_status(job);
    status.phase = JobPhase::Succeeded;
    status.message = Some("All tasks completed successfully".to_string());
    status.observed_generation = Some(generation);
    status.completion_time = Some(chrono::Utc::now().to_rfc3339());
    patch_status(&ctx.client, name, namespace, &status, job.status.as_ref()).await?;
    Ok(Action::await_change())
}

// =============================================================================
// Status helpers
// =============================================================================

fn current_status(job: &LatticeJob) -> LatticeJobStatus {
    job.status.clone().unwrap_or_default()
}

/// Patch the job status, skipping the write if nothing changed.
async fn patch_status(
    client: &Client,
    name: &str,
    namespace: &str,
    new_status: &LatticeJobStatus,
    current: Option<&LatticeJobStatus>,
) -> Result<(), JobError> {
    if current == Some(new_status) {
        return Ok(());
    }
    lattice_common::kube_utils::patch_resource_status::<LatticeJob>(
        client,
        name,
        namespace,
        new_status,
        FIELD_MANAGER,
    )
    .await?;
    Ok(())
}
