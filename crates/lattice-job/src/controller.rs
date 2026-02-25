//! LatticeJob controller implementation
//!
//! Reconciles LatticeJob resources through a state machine:
//! Pending → Running → Succeeded/Failed
//!
//! Resources are applied in layers to prevent race conditions:
//! - Layer 1: ConfigMaps, Secrets, ExternalSecrets, PVCs, MeshMembers, TracingPolicies
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
use lattice_common::status_check;
use lattice_common::{CrdKind, CrdRegistry};

use crate::compiler::{compile_job, CompiledJob};
use crate::error::JobError;

const FIELD_MANAGER: &str = "lattice-job-controller";

/// Requeue interval while waiting for job to complete
const REQUEUE_RUNNING: Duration = Duration::from_secs(15);
/// Requeue interval after a reconciliation error
const REQUEUE_ERROR: Duration = Duration::from_secs(30);

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
    /// Create a new JobContext with a shared CRD registry
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

    let generation = job.metadata.generation.unwrap_or(0);
    let phase = job
        .status
        .as_ref()
        .map(|s| s.phase.clone())
        .unwrap_or(JobPhase::Pending);

    match phase {
        JobPhase::Pending => {
            let volcano_api = ctx
                .registry
                .resolve(CrdKind::VolcanoJob)
                .await
                .ok_or(JobError::VolcanoCrdMissing)?;

            let compiled = compile_job(
                &job,
                &ctx.graph,
                &ctx.cluster_name,
                ctx.provider_type,
                &ctx.cedar,
            )
            .await;

            let compiled = match compiled {
                Ok(c) => c,
                Err(e) => {
                    // Compilation failed — don't leave partial graph entries
                    cleanup_graph(&job, &ctx.graph, namespace);
                    let msg = format!("Failed to compile job: {}", e);
                    let _ = update_status(
                        &ctx.client,
                        &job,
                        namespace,
                        JobPhase::Failed,
                        Some(&msg),
                        None,
                    )
                    .await;
                    return Err(e);
                }
            };

            // Register tasks in the graph after successful compilation
            register_graph(&job, &ctx.graph, namespace);

            if let Err(e) = apply_compiled_job(
                &ctx.client,
                namespace,
                &compiled,
                &ctx.registry,
                &volcano_api,
            )
            .await
            {
                cleanup_graph(&job, &ctx.graph, namespace);
                let msg = format!("Failed to apply resources: {}", e);
                let _ = update_status(
                    &ctx.client,
                    &job,
                    namespace,
                    JobPhase::Failed,
                    Some(&msg),
                    None,
                )
                .await;
                return Err(e);
            }
            update_status(
                &ctx.client,
                &job,
                namespace,
                JobPhase::Running,
                Some("Job submitted to Volcano"),
                Some(generation),
            )
            .await?;
            Ok(Action::requeue(REQUEUE_RUNNING))
        }
        JobPhase::Running => {
            // Guard: spec is immutable once Running — warn if generation changed
            let observed = job.status.as_ref().and_then(|s| s.observed_generation);
            if observed.is_some() && observed != Some(generation) {
                warn!(
                    job = %name,
                    observed = ?observed,
                    current = generation,
                    "spec changed while Running — jobs are immutable once submitted"
                );
            }

            let volcano_api = match ctx.registry.resolve(CrdKind::VolcanoJob).await {
                Some(ar) => ar,
                None => {
                    warn!(job = %name, "cannot check VCJob status: Volcano CRD not discovered");
                    return Ok(Action::requeue(REQUEUE_RUNNING));
                }
            };

            match check_vcjob_status(&ctx.client, &name, namespace, &volcano_api).await {
                Some(VCJobPhase::Completed) => {
                    info!(job = %name, "job succeeded");
                    cleanup_graph(&job, &ctx.graph, namespace);
                    update_status(
                        &ctx.client,
                        &job,
                        namespace,
                        JobPhase::Succeeded,
                        Some("All tasks completed successfully"),
                        Some(generation),
                    )
                    .await?;
                    Ok(Action::await_change())
                }
                Some(VCJobPhase::Failed) => {
                    error!(job = %name, "job failed");
                    cleanup_graph(&job, &ctx.graph, namespace);
                    update_status(
                        &ctx.client,
                        &job,
                        namespace,
                        JobPhase::Failed,
                        Some("Job failed"),
                        Some(generation),
                    )
                    .await?;
                    Ok(Action::await_change())
                }
                _ => Ok(Action::requeue(REQUEUE_RUNNING)),
            }
        }
        JobPhase::Succeeded => Ok(Action::await_change()),
        JobPhase::Failed => {
            // Distinguish transient vs permanent failure:
            // - observed_generation is None → failed during Pending (compile/apply) → retry
            // - observed_generation is Some → failed during Running (VCJob execution) → permanent
            let observed = job.status.as_ref().and_then(|s| s.observed_generation);
            if observed.is_some() {
                // VCJob ran and failed — don't retry
                Ok(Action::await_change())
            } else {
                // Never made it to Running — transient error (e.g. webhook not ready)
                info!(job = %name, "retrying failed job (never reached Running)");
                update_status(
                    &ctx.client,
                    &job,
                    namespace,
                    JobPhase::Pending,
                    Some("Retrying after transient failure"),
                    None,
                )
                .await?;
                Ok(Action::requeue(REQUEUE_ERROR))
            }
        }
        _ => Ok(Action::await_change()),
    }
}

/// Register all job tasks in the service graph for bilateral agreements
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

/// Remove job tasks from the service graph on completion/failure
fn cleanup_graph(job: &LatticeJob, graph: &ServiceGraph, namespace: &str) {
    let name = job.metadata.name.as_deref().unwrap_or_default();
    for task_name in job.spec.tasks.keys() {
        graph.delete_service(namespace, &format!("{}-{}", name, task_name));
    }
}

/// Error policy for LatticeJob reconciliation
pub fn error_policy(job: Arc<LatticeJob>, error: &JobError, _ctx: Arc<JobContext>) -> Action {
    error!(
        ?error,
        job = %job.name_any(),
        "job reconciliation failed"
    );
    Action::requeue(REQUEUE_ERROR)
}

/// Apply compiled job resources in layers using ApplyBatch
async fn apply_compiled_job(
    client: &Client,
    namespace: &str,
    compiled: &CompiledJob,
    registry: &CrdRegistry,
    volcano_api: &ApiResource,
) -> Result<(), JobError> {
    let params = PatchParams::apply(FIELD_MANAGER).force();

    lattice_common::kube_utils::ensure_namespace_ssa(client, namespace, "lattice-job-controller")
        .await?;

    apply_layers(client, namespace, compiled, registry, volcano_api, &params).await
}

async fn apply_layers(
    client: &Client,
    namespace: &str,
    compiled: &CompiledJob,
    registry: &CrdRegistry,
    volcano_api: &ApiResource,
    params: &PatchParams,
) -> Result<(), JobError> {
    // Layer 1: Infrastructure (config, mesh, security, service accounts)
    let cm_ar = ApiResource::erase::<k8s_openapi::api::core::v1::ConfigMap>(&());
    let secret_ar = ApiResource::erase::<k8s_openapi::api::core::v1::Secret>(&());
    let pvc_ar = ApiResource::erase::<k8s_openapi::api::core::v1::PersistentVolumeClaim>(&());
    let sa_ar = ApiResource::erase::<k8s_openapi::api::core::v1::ServiceAccount>(&());

    let mut layer1 = ApplyBatch::new(client.clone(), namespace, params);

    // Create a ServiceAccount for each task (required before Volcano can create pods)
    for task in &compiled.vcjob.spec.tasks {
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

    // Layer 2: VCJob (after mesh/security is ready)
    let mut layer2 = ApplyBatch::new(client.clone(), namespace, params);
    layer2.push(
        "VCJob",
        &compiled.vcjob.metadata.name,
        &compiled.vcjob,
        volcano_api,
    )?;
    layer2.run("layer-2-vcjob").await?;

    info!(
        namespace = %namespace,
        vcjob = %compiled.vcjob.metadata.name,
        mesh_members = compiled.mesh_members.len(),
        tracing_policies = compiled.tracing_policies.len(),
        "applied compiled job resources"
    );

    Ok(())
}

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

            match phase {
                Some("Completed") => Some(VCJobPhase::Completed),
                Some("Failed" | "Terminated" | "Aborted") => Some(VCJobPhase::Failed),
                _ => Some(VCJobPhase::Running),
            }
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

async fn update_status(
    client: &Client,
    job: &LatticeJob,
    namespace: &str,
    phase: JobPhase,
    message: Option<&str>,
    observed_generation: Option<i64>,
) -> Result<(), JobError> {
    if status_check::is_status_unchanged(job.status.as_ref(), &phase, message, observed_generation)
    {
        return Ok(());
    }

    let name = job.name_any();
    let status = LatticeJobStatus {
        phase,
        message: message.map(|m| m.to_string()),
        observed_generation,
    };
    lattice_common::kube_utils::patch_resource_status::<LatticeJob>(
        client,
        &name,
        namespace,
        &status,
        FIELD_MANAGER,
    )
    .await?;
    Ok(())
}
