//! LatticeJob controller implementation
//!
//! Reconciles LatticeJob resources through a state machine:
//! Pending -> Running -> Succeeded/Failed
//!
//! For training jobs with checkpoints, adds a Recovering phase:
//! Running -> (failure) -> Recovering -> Running
//!
//! Recovery uses stop-the-world Velero checkpoint restore:
//! - Delete the VCJob and PVCs
//! - Create a Velero Restore from the latest checkpoint snapshot
//! - Wait for Restore to complete
//! - Re-apply the VCJob (PVCs now contain checkpoint data)
//!
//! Resources are applied in layers to prevent race conditions:
//! - Layer 1: ConfigMaps, Secrets, ExternalSecrets, PVCs, MeshMembers, TracingPolicies,
//!   headless Service, Velero Schedule
//! - Layer 2: VCJob (only after mesh/security is ready)

use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, DynamicObject, PatchParams};
use kube::discovery::ApiResource;
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{error, info, warn};

use lattice_cedar::PolicyEngine;
use lattice_common::crd::{JobPhase, LatticeJob, LatticeJobStatus, ProviderType, RecoveryPhase};
use lattice_common::graph::ServiceGraph;
use lattice_common::kube_utils::ApplyBatch;
use lattice_common::{CrdKind, CrdRegistry, Retryable};

use crate::compiler::{compile_job, CompiledJob, VolcanoWorkload};
use crate::error::JobError;

const FIELD_MANAGER: &str = "lattice-job-controller";

/// Requeue interval while waiting for job to complete
const REQUEUE_RUNNING: Duration = Duration::from_secs(15);

/// Requeue interval during recovery (checking Velero Restore status)
const REQUEUE_RECOVERING: Duration = Duration::from_secs(10);

/// Namespace where Velero resources (Schedules, Backups, Restores) live
pub(crate) const VELERO_NAMESPACE: &str = "velero";

/// Finalizer for cleaning up cross-namespace Velero Schedules on job deletion
const FINALIZER: &str = "lattice.dev/velero-schedule-cleanup";

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

    // Handle deletion: clean up cross-namespace Velero Schedule before allowing GC
    if job.metadata.deletion_timestamp.is_some() {
        let has_finalizer = job
            .metadata
            .finalizers
            .as_ref()
            .map(|f| f.iter().any(|s| s == FINALIZER))
            .unwrap_or(false);
        if has_finalizer {
            cleanup_training(&job, &ctx.client).await;
            cleanup_graph(&job, &ctx.graph, namespace);
            remove_finalizer(&ctx.client, &name, namespace).await?;
        }
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
        JobPhase::Recovering => {
            reconcile_recovering(&job, &ctx, &name, namespace, generation).await
        }
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
            let _ =
                patch_status(&ctx.client, &job.name_any(), namespace, &status, job.status.as_ref())
                    .await;
            return Err(JobError::VolcanoCrdMissing {
                kind: crd_kind.kind_str(),
            });
        }
    };

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
                    patch_status(&ctx.client, &name, namespace, &status, job.status.as_ref())
                        .await;
            } else {
                cleanup_graph(job, &ctx.graph, namespace);
                let mut status = current_status(job);
                status.phase = JobPhase::Failed;
                status.message = Some(format!("Failed to compile job: {}", e));
                status.observed_generation = Some(generation);
                let _ =
                    patch_status(&ctx.client, &name, namespace, &status, job.status.as_ref())
                        .await;
            }
            return Err(e);
        }
    };

    register_graph(job, &ctx.graph, namespace);

    // Add finalizer for training jobs with checkpoints (Velero Schedule is cross-namespace
    // and can't use ownerReferences, so we need a finalizer to clean it up on deletion)
    if job
        .spec
        .training
        .as_ref()
        .and_then(|t| t.checkpoint.as_ref())
        .is_some()
    {
        ensure_finalizer(&ctx.client, job, namespace).await?;
    }

    let name = job.name_any();
    if let Err(e) = apply_layers(
        &ctx.client,
        namespace,
        &compiled,
        &ctx.registry,
        &volcano_api,
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
    status.phase = JobPhase::Running;
    status.message = Some(if is_cron {
        "Cron job submitted to Volcano".to_string()
    } else {
        "Job submitted to Volcano".to_string()
    });
    status.observed_generation = Some(generation);
    if job.spec.training.is_some() {
        status.start_time = Some(chrono::Utc::now().to_rfc3339());
    }
    patch_status(&ctx.client, &name, namespace, &status, job.status.as_ref()).await?;
    Ok(Action::requeue(REQUEUE_RUNNING))
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
            info!(job = %name, "job succeeded");
            cleanup_graph(job, &ctx.graph, namespace);
            cleanup_training(job, &ctx.client).await;
            let mut status = current_status(job);
            status.phase = JobPhase::Succeeded;
            status.message = Some("All tasks completed successfully".to_string());
            status.observed_generation = Some(generation);
            status.completion_time = Some(chrono::Utc::now().to_rfc3339());
            patch_status(&ctx.client, name, namespace, &status, job.status.as_ref()).await?;
            Ok(Action::await_change())
        }
        Some(VCJobPhase::Failed) => {
            handle_job_failure(job, ctx, name, namespace, generation).await
        }
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

    let api: Api<DynamicObject> =
        Api::namespaced_with(ctx.client.clone(), namespace, &cron_api);
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
            let _ =
                patch_status(&ctx.client, name, namespace, &status, job.status.as_ref()).await;
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

/// Handle a failed VCJob. If training with checkpoint + retries left, transition
/// to Recovering. Otherwise, mark as Failed.
async fn handle_job_failure(
    job: &LatticeJob,
    ctx: &JobContext,
    name: &str,
    namespace: &str,
    generation: i64,
) -> Result<Action, JobError> {
    let has_checkpoint = job
        .spec
        .training
        .as_ref()
        .and_then(|t| t.checkpoint.as_ref())
        .is_some();
    let retry_count = job.status.as_ref().map(|s| s.retry_count).unwrap_or(0);
    let max_retry = job.spec.max_retry.unwrap_or(0);

    if has_checkpoint && retry_count < max_retry {
        info!(
            job = %name,
            retry = retry_count + 1,
            max_retry = max_retry,
            "VCJob failed, initiating stop-the-world checkpoint recovery"
        );
        let mut status = current_status(job);
        status.phase = JobPhase::Recovering;
        status.message = Some(format!(
            "Recovering from checkpoint (retry {}/{})",
            retry_count + 1,
            max_retry
        ));
        status.retry_count = retry_count + 1;
        status.observed_generation = Some(generation);
        status.recovery_phase = Some(RecoveryPhase::DeletingResources);
        patch_status(&ctx.client, name, namespace, &status, job.status.as_ref()).await?;
        Ok(Action::requeue(REQUEUE_RECOVERING))
    } else {
        error!(job = %name, "job failed (no retries left or no checkpoint configured)");
        cleanup_graph(job, &ctx.graph, namespace);
        cleanup_training(job, &ctx.client).await;
        let mut status = current_status(job);
        status.phase = JobPhase::Failed;
        status.message = Some("Job failed".to_string());
        status.observed_generation = Some(generation);
        status.completion_time = Some(chrono::Utc::now().to_rfc3339());
        patch_status(&ctx.client, name, namespace, &status, job.status.as_ref()).await?;
        Ok(Action::await_change())
    }
}

/// Stop-the-world recovery flow:
///
/// DeletingResources: Delete VCJob and checkpoint PVCs
/// WaitingForRestore: Create Velero Restore, poll until complete
/// Restarting: Re-compile and apply the VCJob
async fn reconcile_recovering(
    job: &LatticeJob,
    ctx: &JobContext,
    name: &str,
    namespace: &str,
    generation: i64,
) -> Result<Action, JobError> {
    let recovery_phase = job
        .status
        .as_ref()
        .and_then(|s| s.recovery_phase.clone())
        .unwrap_or(RecoveryPhase::DeletingResources);

    match recovery_phase {
        RecoveryPhase::DeletingResources => {
            recover_delete_resources(job, ctx, name, namespace).await
        }
        RecoveryPhase::WaitingForRestore => {
            recover_wait_for_restore(job, ctx, name, namespace, generation).await
        }
        RecoveryPhase::Restarting => {
            recover_restart(job, ctx, name, namespace, generation).await
        }
    }
}

async fn recover_delete_resources(
    job: &LatticeJob,
    ctx: &JobContext,
    name: &str,
    namespace: &str,
) -> Result<Action, JobError> {
    info!(job = %name, "recovery: deleting VCJob and checkpoint PVCs");

    let volcano_api = match ctx.registry.resolve(CrdKind::VolcanoJob).await? {
        Some(ar) => ar,
        None => return Ok(Action::requeue(REQUEUE_RECOVERING)),
    };
    let api: Api<DynamicObject> =
        Api::namespaced_with(ctx.client.clone(), namespace, &volcano_api);
    match api.delete(name, &kube::api::DeleteParams::default()).await {
        Ok(_) => info!(job = %name, "deleted VCJob for recovery"),
        Err(kube::Error::Api(ae)) if ae.code == 404 => {}
        Err(e) => {
            warn!(job = %name, error = %e, "failed to delete VCJob, will retry");
            return Ok(Action::requeue(REQUEUE_RECOVERING));
        }
    }

    delete_checkpoint_pvcs(&ctx.client, name, namespace).await;

    let mut status = current_status(job);
    status.recovery_phase = Some(RecoveryPhase::WaitingForRestore);
    status.message = Some("Waiting for Velero restore".to_string());
    patch_status(&ctx.client, name, namespace, &status, job.status.as_ref()).await?;
    Ok(Action::requeue(REQUEUE_RECOVERING))
}

async fn recover_wait_for_restore(
    job: &LatticeJob,
    ctx: &JobContext,
    name: &str,
    namespace: &str,
    generation: i64,
) -> Result<Action, JobError> {
    let retry_count = job.status.as_ref().map(|s| s.retry_count).unwrap_or(1);
    let restore_name = format!("lattice-training-{}-restore-{}", name, retry_count);

    match check_velero_restore_status(&ctx.client, &restore_name).await {
        Some(VeleroRestorePhase::Completed) => {
            info!(job = %name, "Velero restore completed");
            let mut status = current_status(job);
            status.recovery_phase = Some(RecoveryPhase::Restarting);
            status.message = Some("Restore complete, restarting training".to_string());
            patch_status(&ctx.client, name, namespace, &status, job.status.as_ref()).await?;
            Ok(Action::requeue(REQUEUE_RECOVERING))
        }
        Some(VeleroRestorePhase::InProgress) => Ok(Action::requeue(REQUEUE_RECOVERING)),
        Some(VeleroRestorePhase::Failed) => {
            error!(job = %name, "Velero restore failed");
            cleanup_graph(job, &ctx.graph, namespace);
            cleanup_training(job, &ctx.client).await;
            let mut status = current_status(job);
            status.phase = JobPhase::Failed;
            status.message = Some("Velero checkpoint restore failed".to_string());
            status.observed_generation = Some(generation);
            status.completion_time = Some(chrono::Utc::now().to_rfc3339());
            status.recovery_phase = None;
            patch_status(&ctx.client, name, namespace, &status, job.status.as_ref()).await?;
            Ok(Action::await_change())
        }
        None => {
            // Restore doesn't exist yet — create it
            let latest_backup = find_latest_velero_backup(&ctx.client, name).await;
            match latest_backup {
                Some(backup_name) => {
                    info!(job = %name, backup = %backup_name, "creating Velero Restore");
                    create_velero_restore(
                        &ctx.client,
                        &restore_name,
                        &backup_name,
                        namespace,
                    )
                    .await?;
                }
                None => {
                    warn!(job = %name, "no Velero backups found, restarting without checkpoint");
                    let mut status = current_status(job);
                    status.recovery_phase = Some(RecoveryPhase::Restarting);
                    status.message =
                        Some("No checkpoint found, restarting training".to_string());
                    patch_status(&ctx.client, name, namespace, &status, job.status.as_ref())
                        .await?;
                }
            }
            Ok(Action::requeue(REQUEUE_RECOVERING))
        }
    }
}

async fn recover_restart(
    job: &LatticeJob,
    ctx: &JobContext,
    name: &str,
    namespace: &str,
    generation: i64,
) -> Result<Action, JobError> {
    info!(job = %name, "recovery: re-applying VCJob");

    let volcano_api = match ctx.registry.resolve(CrdKind::VolcanoJob).await? {
        Some(ar) => ar,
        None => return Ok(Action::requeue(REQUEUE_RECOVERING)),
    };

    let compiled = compile_job(
        job,
        &ctx.graph,
        &ctx.cluster_name,
        ctx.provider_type,
        &ctx.cedar,
    )
    .await?;

    if let Err(e) = apply_layers(
        &ctx.client,
        namespace,
        &compiled,
        &ctx.registry,
        &volcano_api,
    )
    .await
    {
        warn!(job = %name, error = %e, "failed to re-apply VCJob during recovery, will retry");
        return Ok(Action::requeue(REQUEUE_RECOVERING));
    }

    let mut status = current_status(job);
    status.phase = JobPhase::Running;
    status.message = Some("Training restarted from checkpoint".to_string());
    status.observed_generation = Some(generation);
    status.recovery_phase = None;
    patch_status(&ctx.client, name, namespace, &status, job.status.as_ref()).await?;
    Ok(Action::requeue(REQUEUE_RUNNING))
}

// =============================================================================
// Graph management
// =============================================================================

fn register_graph(job: &LatticeJob, graph: &ServiceGraph, namespace: &str) {
    let name = job.metadata.name.as_deref().unwrap_or_default();
    for (task_name, task_spec) in &job.spec.tasks {
        graph.put_workload(
            namespace,
            &format!("{}-{}", name, task_name),
            &task_spec.workload,
        );
    }
}

fn cleanup_graph(job: &LatticeJob, graph: &ServiceGraph, namespace: &str) {
    let name = job.metadata.name.as_deref().unwrap_or_default();
    for task_name in job.spec.tasks.keys() {
        graph.delete_service(namespace, &format!("{}-{}", name, task_name));
    }
}

/// Clean up training-specific cross-namespace resources (Velero Schedule).
async fn cleanup_training(job: &LatticeJob, client: &Client) {
    if job.spec.training.as_ref().and_then(|t| t.checkpoint.as_ref()).is_some() {
        let name = job.metadata.name.as_deref().unwrap_or_default();
        cleanup_velero_schedule(client, name).await;
    }
}

// =============================================================================
// Finalizer management
// =============================================================================

/// Ensure the Velero cleanup finalizer is present on the job.
async fn ensure_finalizer(
    client: &Client,
    job: &LatticeJob,
    namespace: &str,
) -> Result<(), JobError> {
    let finalizers = job.metadata.finalizers.as_deref().unwrap_or(&[]);
    if finalizers.iter().any(|s| s == FINALIZER) {
        return Ok(());
    }
    let name = job.name_any();
    let mut new_finalizers: Vec<String> = finalizers.to_vec();
    new_finalizers.push(FINALIZER.to_string());
    let patch = serde_json::json!({
        "metadata": { "finalizers": new_finalizers }
    });
    let api: Api<LatticeJob> = Api::namespaced(client.clone(), namespace);
    api.patch(
        &name,
        &PatchParams::default(),
        &kube::api::Patch::Merge(&patch),
    )
    .await?;
    Ok(())
}

/// Remove the Velero cleanup finalizer from the job, allowing deletion to proceed.
async fn remove_finalizer(
    client: &Client,
    name: &str,
    namespace: &str,
) -> Result<(), JobError> {
    let api: Api<LatticeJob> = Api::namespaced(client.clone(), namespace);
    let job = api.get(name).await?;
    let finalizers: Vec<String> = job
        .metadata
        .finalizers
        .as_ref()
        .map(|f| f.iter().filter(|s| s.as_str() != FINALIZER).cloned().collect())
        .unwrap_or_default();
    let patch = serde_json::json!({
        "metadata": { "finalizers": finalizers }
    });
    api.patch(
        name,
        &PatchParams::default(),
        &kube::api::Patch::Merge(&patch),
    )
    .await?;
    Ok(())
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

    // Layer 1: Infrastructure (config, mesh, security, service accounts, headless svc, velero)
    let cm_ar = ApiResource::erase::<k8s_openapi::api::core::v1::ConfigMap>(&());
    let secret_ar = ApiResource::erase::<k8s_openapi::api::core::v1::Secret>(&());
    let pvc_ar = ApiResource::erase::<k8s_openapi::api::core::v1::PersistentVolumeClaim>(&());
    let sa_ar = ApiResource::erase::<k8s_openapi::api::core::v1::ServiceAccount>(&());
    let svc_ar = ApiResource::erase::<k8s_openapi::api::core::v1::Service>(&());

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

    if let Some(ref headless) = compiled.headless_service {
        let svc_name = headless["metadata"]["name"]
            .as_str()
            .unwrap_or("unknown");
        layer1.push("Service", svc_name, headless, &svc_ar)?;
    }

    layer1.run("layer-1-infrastructure").await?;

    // Training: Velero Schedule (applied to velero namespace, separate from layer1)
    if let Some(ref schedule) = compiled.velero_schedule {
        apply_velero_resource(client, schedule).await?;
    }

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
        has_headless_service = compiled.headless_service.is_some(),
        has_velero_schedule = compiled.velero_schedule.is_some(),
        "applied compiled job resources"
    );

    Ok(())
}

// =============================================================================
// Velero operations
// =============================================================================

/// Apply a Velero resource (Schedule, Restore) via server-side apply.
async fn apply_velero_resource(
    client: &Client,
    resource: &serde_json::Value,
) -> Result<(), JobError> {
    let kind = resource["kind"].as_str().unwrap_or("unknown");
    let name = resource["metadata"]["name"].as_str().unwrap_or("unknown");
    let namespace = resource["metadata"]["namespace"]
        .as_str()
        .unwrap_or(VELERO_NAMESPACE);

    let ar = ApiResource::from_gvk(&kube::api::GroupVersionKind::gvk(
        "velero.io",
        "v1",
        kind,
    ));
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
    let params = PatchParams::apply(FIELD_MANAGER).force();

    api.patch(name, &params, &kube::api::Patch::Apply(resource))
        .await?;

    Ok(())
}

/// Delete checkpoint PVCs labeled with `lattice.dev/training-job: <name>`.
async fn delete_checkpoint_pvcs(client: &Client, job_name: &str, namespace: &str) {
    let pvcs: Api<k8s_openapi::api::core::v1::PersistentVolumeClaim> =
        Api::namespaced(client.clone(), namespace);

    let label_selector = format!("lattice.dev/training-job={}", job_name);
    let list_params = kube::api::ListParams::default().labels(&label_selector);

    match pvcs.list(&list_params).await {
        Ok(list) => {
            for pvc in list.items {
                let pvc_name = pvc.metadata.name.as_deref().unwrap_or_default();
                match pvcs
                    .delete(pvc_name, &kube::api::DeleteParams::default())
                    .await
                {
                    Ok(_) => info!(job = %job_name, pvc = %pvc_name, "deleted checkpoint PVC"),
                    Err(e) => warn!(job = %job_name, pvc = %pvc_name, error = %e, "failed to delete PVC"),
                }
            }
        }
        Err(e) => warn!(job = %job_name, error = %e, "failed to list checkpoint PVCs"),
    }
}

/// Find the latest completed Velero Backup for a training job.
///
/// Sorts by `completionTimestamp` string comparison — works because Velero
/// uses RFC 3339 timestamps which sort lexicographically.
async fn find_latest_velero_backup(
    client: &Client,
    job_name: &str,
) -> Option<String> {
    let ar = ApiResource::from_gvk(&kube::api::GroupVersionKind::gvk(
        "velero.io",
        "v1",
        "Backup",
    ));
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), VELERO_NAMESPACE, &ar);

    let label_selector = format!("lattice.dev/training-job={}", job_name);
    let list_params = kube::api::ListParams::default().labels(&label_selector);

    match api.list(&list_params).await {
        Ok(list) => {
            list.items
                .into_iter()
                .filter(|b| {
                    b.data
                        .get("status")
                        .and_then(|s| s.get("phase"))
                        .and_then(|p| p.as_str())
                        == Some("Completed")
                })
                .max_by_key(|b| {
                    b.data
                        .get("status")
                        .and_then(|s| s.get("completionTimestamp"))
                        .and_then(|t| t.as_str())
                        .unwrap_or("")
                        .to_string()
                })
                .and_then(|b| b.metadata.name)
        }
        Err(e) => {
            warn!(job = %job_name, error = %e, "failed to list Velero backups");
            None
        }
    }
}

enum VeleroRestorePhase {
    InProgress,
    Completed,
    Failed,
}

/// Check the status of a Velero Restore CR.
async fn check_velero_restore_status(
    client: &Client,
    restore_name: &str,
) -> Option<VeleroRestorePhase> {
    let ar = ApiResource::from_gvk(&kube::api::GroupVersionKind::gvk(
        "velero.io",
        "v1",
        "Restore",
    ));
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), VELERO_NAMESPACE, &ar);

    match api.get(restore_name).await {
        Ok(obj) => {
            let phase = obj
                .data
                .get("status")
                .and_then(|s| s.get("phase"))
                .and_then(|p| p.as_str());

            match phase {
                Some("Completed") => Some(VeleroRestorePhase::Completed),
                Some("Failed" | "PartiallyFailed" | "FailedValidation") => {
                    Some(VeleroRestorePhase::Failed)
                }
                _ => Some(VeleroRestorePhase::InProgress),
            }
        }
        Err(kube::Error::Api(ae)) if ae.code == 404 => None,
        Err(e) => {
            warn!(restore = %restore_name, error = %e, "failed to check Velero Restore status");
            None
        }
    }
}

/// Create a Velero Restore CR targeting a specific backup.
async fn create_velero_restore(
    client: &Client,
    restore_name: &str,
    backup_name: &str,
    namespace: &str,
) -> Result<(), JobError> {
    let restore = serde_json::json!({
        "apiVersion": "velero.io/v1",
        "kind": "Restore",
        "metadata": {
            "name": restore_name,
            "namespace": VELERO_NAMESPACE,
            "labels": {
                "app.kubernetes.io/managed-by": "lattice"
            }
        },
        "spec": {
            "backupName": backup_name,
            "includedNamespaces": [namespace],
            "includedResources": [
                "persistentvolumeclaims",
                "persistentvolumes"
            ],
            "restorePVs": true
        }
    });

    apply_velero_resource(client, &restore).await
}

// =============================================================================
// VCJob status
// =============================================================================

enum VCJobPhase {
    Completed,
    Failed,
    Running,
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
                other => {
                    info!(job = %name, phase = ?other, "VCJob phase");
                    VCJobPhase::Running
                }
            };
            Some(result)
        }
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            warn!(job = %name, "VCJob not found");
            None
        }
        Err(e) => {
            warn!(job = %name, error = %e, "failed to check VCJob status");
            None
        }
    }
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

// =============================================================================
// Velero Schedule cleanup
// =============================================================================

/// Delete the Velero Schedule for a training job (cross-namespace, not GC'd by ownerRef).
async fn cleanup_velero_schedule(client: &Client, job_name: &str) {
    let schedule_name = format!("lattice-training-{}", job_name);
    let ar = ApiResource::from_gvk(&kube::api::GroupVersionKind::gvk(
        "velero.io",
        "v1",
        "Schedule",
    ));
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), VELERO_NAMESPACE, &ar);
    match api
        .delete(&schedule_name, &kube::api::DeleteParams::default())
        .await
    {
        Ok(_) => info!(job = %job_name, "deleted Velero Schedule"),
        Err(kube::Error::Api(ae)) if ae.code == 404 => {}
        Err(e) => warn!(job = %job_name, error = %e, "failed to delete Velero Schedule"),
    }
}
