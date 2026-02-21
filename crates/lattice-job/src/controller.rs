//! LatticeJob controller implementation
//!
//! Reconciles LatticeJob resources through a state machine:
//! Pending → Running → Succeeded/Failed
//!
//! Resources are applied in layers to prevent race conditions:
//! - Layer 1: ConfigMaps, Secrets, ExternalSecrets, PVCs, MeshMembers, TracingPolicies
//! - Layer 2: VCJob (only after mesh/security is ready)

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use kube::api::{Api, DynamicObject, Patch, PatchParams};
use kube::discovery::ApiResource;
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{error, info, warn};

use lattice_cedar::PolicyEngine;
use lattice_common::crd::{JobPhase, LatticeJob, LatticeJobStatus, ProviderType};
use lattice_common::graph::ServiceGraph;
use lattice_common::kube_utils::{find_discovered_resource, ApplyBatch};

use crate::compiler::{compile_job, CompiledJob};
use crate::error::JobError;

/// Discovered CRD API versions for job resources.
///
/// Shared CRDs (external_secret, mesh_member, tracing_policy_namespaced) are
/// passed from the service controller and always available at startup.
/// Volcano Job is job-specific and may arrive later (installed as an addon).
pub struct JobDiscoveredCrds {
    pub external_secret: Option<ApiResource>,
    pub mesh_member: Option<ApiResource>,
    pub tracing_policy_namespaced: Option<ApiResource>,
    pub volcano_job: Option<ApiResource>,
}

impl JobDiscoveredCrds {
    /// Discover Volcano Job CRD, reusing already-discovered shared CRDs.
    pub async fn from_shared(
        client: &Client,
        external_secret: Option<ApiResource>,
        mesh_member: Option<ApiResource>,
        tracing_policy_namespaced: Option<ApiResource>,
    ) -> Self {
        let volcano_job = discover_volcano(client).await;
        Self {
            external_secret,
            mesh_member,
            tracing_policy_namespaced,
            volcano_job,
        }
    }
}

/// Discover the Volcano Job CRD via API discovery.
async fn discover_volcano(client: &Client) -> Option<ApiResource> {
    use kube::discovery::Discovery;

    let discovery = match Discovery::new(client.clone()).run().await {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "API discovery failed, cannot detect Volcano Job CRD");
            return None;
        }
    };
    let ar = find_discovered_resource(&discovery, "batch.volcano.sh", "Job");
    if ar.is_none() {
        warn!("Volcano Job CRD (batch.volcano.sh/Job) not found in API discovery");
    }
    ar
}

/// Shared context for the LatticeJob controller
pub struct JobContext {
    pub client: Client,
    pub graph: Arc<ServiceGraph>,
    pub cluster_name: String,
    pub provider_type: ProviderType,
    pub cedar: Arc<PolicyEngine>,
    /// Shared CRDs passed from the service controller (immutable after startup).
    pub crds: Arc<JobDiscoveredCrds>,
    /// Lazily resolved Volcano Job API resource. Populated from startup discovery
    /// if available, otherwise resolved on first use via API discovery and cached
    /// permanently. `OnceLock` gives zero-cost reads after initialization.
    volcano_api: OnceLock<ApiResource>,
}

impl JobContext {
    pub fn new(
        client: Client,
        graph: Arc<ServiceGraph>,
        cluster_name: String,
        provider_type: ProviderType,
        cedar: Arc<PolicyEngine>,
        crds: Arc<JobDiscoveredCrds>,
    ) -> Self {
        let volcano_api = OnceLock::new();
        if let Some(ar) = &crds.volcano_job {
            let _ = volcano_api.set(ar.clone());
        }
        Self {
            client,
            graph,
            cluster_name,
            provider_type,
            cedar,
            crds,
            volcano_api,
        }
    }

    /// Get the Volcano Job API resource, discovering lazily if not yet available.
    ///
    /// On first call (when Volcano wasn't installed at startup), runs API discovery
    /// and caches the result in a `OnceLock`. Subsequent calls return immediately
    /// with no discovery overhead. Returns `None` if Volcano is still not installed.
    async fn resolve_volcano_api(&self) -> Option<&ApiResource> {
        if let Some(ar) = self.volcano_api.get() {
            return Some(ar);
        }

        info!("Volcano Job CRD was missing at startup, attempting discovery");
        if let Some(ar) = discover_volcano(&self.client).await {
            // First writer wins; concurrent discovery is harmless (idempotent).
            let _ = self.volcano_api.set(ar);
        }
        self.volcano_api.get()
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
                    return Err(e);
                }
            };

            // Register tasks in the graph after successful compilation
            register_graph(&job, &ctx.graph, namespace);

            apply_compiled_job(&ctx.client, namespace, &compiled, &ctx).await?;
            update_status(
                &ctx.client,
                &name,
                namespace,
                JobPhase::Running,
                None,
                Some(generation),
            )
            .await?;
            Ok(Action::requeue(Duration::from_secs(15)))
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

            let volcano_api = match ctx.resolve_volcano_api().await {
                Some(ar) => ar,
                None => {
                    warn!(job = %name, "cannot check VCJob status: Volcano CRD not discovered");
                    return Ok(Action::requeue(Duration::from_secs(15)));
                }
            };

            match check_vcjob_status(&ctx.client, &name, namespace, volcano_api).await {
                Some(VCJobPhase::Completed) => {
                    info!(job = %name, "job succeeded");
                    cleanup_graph(&job, &ctx.graph, namespace);
                    update_status(
                        &ctx.client,
                        &name,
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
                        &name,
                        namespace,
                        JobPhase::Failed,
                        Some("Job failed"),
                        Some(generation),
                    )
                    .await?;
                    Ok(Action::await_change())
                }
                _ => Ok(Action::requeue(Duration::from_secs(15))),
            }
        }
        JobPhase::Succeeded | JobPhase::Failed => Ok(Action::await_change()),
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
    Action::requeue(Duration::from_secs(30))
}

/// Apply compiled job resources in layers using ApplyBatch
async fn apply_compiled_job(
    client: &Client,
    namespace: &str,
    compiled: &CompiledJob,
    ctx: &JobContext,
) -> Result<(), JobError> {
    let params = PatchParams::apply("lattice-job-controller").force();

    ensure_namespace(client, namespace).await?;

    let volcano_api = ctx
        .resolve_volcano_api()
        .await
        .ok_or(JobError::VolcanoCrdMissing)?;

    apply_layers(client, namespace, compiled, &ctx.crds, volcano_api, &params).await
}

async fn apply_layers(
    client: &Client,
    namespace: &str,
    compiled: &CompiledJob,
    crds: &JobDiscoveredCrds,
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
            let sa = serde_json::json!({
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {
                    "name": sa_name,
                    "namespace": namespace
                },
                "automountServiceAccountToken": false
            });
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
    layer1.push_crd(
        "ExternalSecret",
        crds.external_secret.as_ref(),
        &compiled.config.external_secrets,
        |es| &es.metadata.name,
    )?;
    for pvc in &compiled.config.pvcs {
        layer1.push("PersistentVolumeClaim", &pvc.metadata.name, pvc, &pvc_ar)?;
    }
    layer1.push_crd(
        "LatticeMeshMember",
        crds.mesh_member.as_ref(),
        &compiled.mesh_members,
        |mm| mm.metadata.name.as_deref().unwrap_or("unknown"),
    )?;
    layer1.push_crd(
        "TracingPolicyNamespaced",
        crds.tracing_policy_namespaced.as_ref(),
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

async fn ensure_namespace(client: &Client, name: &str) -> Result<(), JobError> {
    use k8s_openapi::api::core::v1::Namespace;

    let api: Api<Namespace> = Api::all(client.clone());
    let ns = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": { "name": name }
    });
    api.patch(
        name,
        &PatchParams::apply("lattice-job-controller"),
        &Patch::Apply(&ns),
    )
    .await?;
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
    name: &str,
    namespace: &str,
    phase: JobPhase,
    message: Option<&str>,
    observed_generation: Option<i64>,
) -> Result<(), JobError> {
    let api: Api<LatticeJob> = Api::namespaced(client.clone(), namespace);
    let status = LatticeJobStatus {
        phase,
        message: message.map(|m| m.to_string()),
        observed_generation,
    };
    let status_patch = serde_json::json!({ "status": status });
    api.patch_status(
        name,
        &PatchParams::apply("lattice-job-controller"),
        &Patch::Merge(&status_patch),
    )
    .await?;
    Ok(())
}
