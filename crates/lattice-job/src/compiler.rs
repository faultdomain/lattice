//! JobCompiler — orchestrates per-task compilation for LatticeJob
//!
//! For each task:
//! - Compiles workload via `WorkloadCompiler` → pod template + config resources
//! - Compiles Tetragon tracing policies via `lattice_tetragon`
//! - Aggregates mesh members, config, and tracing policies
//!
//! Then builds a Volcano VCJob from the aggregated pod templates.

use std::collections::BTreeMap;

use serde::de::Error as _;

use lattice_cedar::PolicyEngine;
use lattice_common::crd::{LatticeJob, LatticeMeshMember, ProviderType};
use lattice_common::graph::ServiceGraph;
use lattice_common::policy::tetragon::TracingPolicyNamespaced;
use lattice_volcano::VCJob;
use lattice_workload::{CompiledConfig, CompiledPodTemplate, WorkloadCompiler};

use crate::error::JobError;

/// Complete compiled output for a LatticeJob
#[derive(Debug)]
pub struct CompiledJob {
    /// Volcano VCJob resource
    pub vcjob: VCJob,
    /// Aggregated config resources from all tasks (ConfigMaps, Secrets, ESO, PVCs)
    pub config: CompiledConfig,
    /// LatticeMeshMember CRs — one per task that participates in the mesh
    pub mesh_members: Vec<LatticeMeshMember>,
    /// Tetragon TracingPolicyNamespaced resources — per-task runtime enforcement
    pub tracing_policies: Vec<TracingPolicyNamespaced>,
}

/// Compile a LatticeJob into Kubernetes resources.
///
/// For each task, runs the shared `WorkloadCompiler` pipeline and `lattice_tetragon`
/// policy compiler, then aggregates results into a single `CompiledJob`.
///
/// This function is pure compilation — it does NOT register tasks in the service graph.
/// The caller (controller) is responsible for graph registration after successful compilation
/// and cleanup on failure.
pub async fn compile_job(
    job: &LatticeJob,
    graph: &ServiceGraph,
    cluster_name: &str,
    provider_type: ProviderType,
    cedar: &PolicyEngine,
) -> Result<CompiledJob, JobError> {
    let name = job.metadata.name.as_deref().unwrap_or_default();
    let namespace = job
        .metadata
        .namespace
        .as_deref()
        .ok_or(JobError::MissingNamespace)?;

    if job.spec.tasks.is_empty() {
        return Err(JobError::NoTasks);
    }

    let mut pod_templates: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let mut config = CompiledConfig::default();
    let mut mesh_members = Vec::new();
    let mut tracing_policies = Vec::new();

    for (task_name, task_spec) in &job.spec.tasks {
        let task_full_name = format!("{}-{}", name, task_name);

        // Compile workload → pod template + config resources + mesh member
        let compiled = WorkloadCompiler::new(
            &task_full_name,
            namespace,
            &task_spec.workload,
            &task_spec.runtime,
            provider_type,
        )
        .with_cedar(cedar)
        .with_cluster_name(cluster_name)
        .with_graph(graph)
        .with_image_pull_secrets(&task_spec.runtime.image_pull_secrets)
        .compile()
        .await
        .map_err(|e| JobError::TaskCompilation {
            task: task_name.clone(),
            source: e,
        })?;

        // Convert CompiledPodTemplate to JSON for VCJob
        let template_json = pod_template_to_json(compiled.pod_template)?;
        pod_templates.insert(task_name.clone(), template_json);

        // Collect config resources
        config.merge(compiled.config);

        // Collect mesh member
        if let Some(mm) = compiled.mesh_member {
            mesh_members.push(mm);
        }

        // Compile Tetragon tracing policies for this task
        let policies = lattice_tetragon::compile_tracing_policies(
            &task_full_name,
            namespace,
            &task_spec.workload,
            &task_spec.runtime,
        );
        tracing_policies.extend(policies);
    }

    // Build VCJob from aggregated pod templates
    let vcjob = lattice_volcano::compile_vcjob(job, &pod_templates);

    Ok(CompiledJob {
        vcjob,
        config,
        mesh_members,
        tracing_policies,
    })
}

/// Convert a `CompiledPodTemplate` into a JSON value for Volcano VCJob task templates.
///
/// Produces the same structure as the service crate's `PodTemplateSpec` but as JSON,
/// avoiding dependency on the service crate's serialization types.
fn pod_template_to_json(pt: CompiledPodTemplate) -> Result<serde_json::Value, JobError> {
    let mut spec = serde_json::json!({
        "serviceAccountName": pt.service_account_name,
        "automountServiceAccountToken": false,
        "containers": pt.containers,
    });

    let spec_obj = spec.as_object_mut().ok_or_else(|| {
        JobError::Serialization(serde_json::Error::custom("pod spec is not a JSON object"))
    })?;

    if !pt.init_containers.is_empty() {
        spec_obj.insert(
            "initContainers".to_string(),
            serde_json::to_value(&pt.init_containers).unwrap_or_default(),
        );
    }
    if !pt.volumes.is_empty() {
        spec_obj.insert(
            "volumes".to_string(),
            serde_json::to_value(&pt.volumes).unwrap_or_default(),
        );
    }
    if let Some(ref affinity) = pt.affinity {
        spec_obj.insert(
            "affinity".to_string(),
            serde_json::to_value(affinity).unwrap_or_default(),
        );
    }
    if let Some(ref sc) = pt.security_context {
        spec_obj.insert(
            "securityContext".to_string(),
            serde_json::to_value(sc).unwrap_or_default(),
        );
    }
    if let Some(hn) = pt.host_network {
        spec_obj.insert("hostNetwork".to_string(), serde_json::Value::Bool(hn));
    }
    if let Some(spn) = pt.share_process_namespace {
        spec_obj.insert(
            "shareProcessNamespace".to_string(),
            serde_json::Value::Bool(spn),
        );
    }
    if !pt.topology_spread_constraints.is_empty() {
        spec_obj.insert(
            "topologySpreadConstraints".to_string(),
            serde_json::to_value(&pt.topology_spread_constraints).unwrap_or_default(),
        );
    }
    if let Some(ref ns) = pt.node_selector {
        spec_obj.insert(
            "nodeSelector".to_string(),
            serde_json::to_value(ns).unwrap_or_default(),
        );
    }
    if !pt.tolerations.is_empty() {
        spec_obj.insert(
            "tolerations".to_string(),
            serde_json::to_value(&pt.tolerations).unwrap_or_default(),
        );
    }
    if let Some(ref rcn) = pt.runtime_class_name {
        spec_obj.insert(
            "runtimeClassName".to_string(),
            serde_json::Value::String(rcn.clone()),
        );
    }
    if !pt.scheduling_gates.is_empty() {
        spec_obj.insert(
            "schedulingGates".to_string(),
            serde_json::to_value(&pt.scheduling_gates).unwrap_or_default(),
        );
    }
    if !pt.image_pull_secrets.is_empty() {
        spec_obj.insert(
            "imagePullSecrets".to_string(),
            serde_json::to_value(&pt.image_pull_secrets).unwrap_or_default(),
        );
    }

    Ok(serde_json::json!({
        "metadata": {
            "labels": pt.labels
        },
        "spec": spec
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use lattice_common::crd::{
        ContainerSpec, JobTaskSpec, LatticeJobSpec, RestartPolicy, RuntimeSpec, WorkloadSpec,
    };

    fn make_job(tasks: BTreeMap<String, JobTaskSpec>) -> LatticeJob {
        let spec = LatticeJobSpec {
            tasks,
            ..Default::default()
        };
        let mut job = LatticeJob::new("test-job", spec);
        job.metadata.namespace = Some("default".to_string());
        job.metadata.uid = Some("uid-123".to_string());
        job
    }

    fn make_task(image: &str, replicas: u32) -> JobTaskSpec {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: image.to_string(),
                ..Default::default()
            },
        );
        JobTaskSpec {
            replicas,
            workload: WorkloadSpec {
                containers,
                ..Default::default()
            },
            runtime: RuntimeSpec::default(),
            restart_policy: Some(RestartPolicy::Never),
        }
    }

    /// Create a permit-all Cedar engine for tests (avoids default-deny blocking compilation)
    fn permit_all_cedar() -> PolicyEngine {
        PolicyEngine::with_policies("permit(principal, action, resource);").unwrap()
    }

    #[tokio::test]
    async fn compile_single_task_job() {
        let mut tasks = BTreeMap::new();
        tasks.insert("worker".to_string(), make_task("worker:latest", 2));

        let job = make_job(tasks);
        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_job(&job, &graph, "test-cluster", ProviderType::Docker, &cedar)
            .await
            .unwrap();

        assert_eq!(compiled.vcjob.spec.tasks.len(), 1);
        assert_eq!(compiled.vcjob.spec.tasks[0].name, "worker");
        assert_eq!(compiled.vcjob.spec.tasks[0].replicas, 2);
        // No command = implicit wildcard = no binary restriction policies
        assert!(compiled.tracing_policies.is_empty());
    }

    #[tokio::test]
    async fn compile_multi_task_job() {
        let mut tasks = BTreeMap::new();
        tasks.insert("master".to_string(), make_task("master:latest", 1));
        tasks.insert("worker".to_string(), make_task("worker:latest", 4));

        let job = make_job(tasks);
        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_job(&job, &graph, "test-cluster", ProviderType::Docker, &cedar)
            .await
            .unwrap();

        assert_eq!(compiled.vcjob.spec.tasks.len(), 2);
        assert_eq!(compiled.vcjob.spec.min_available, Some(5));
    }

    #[tokio::test]
    async fn empty_tasks_returns_error() {
        let job = make_job(BTreeMap::new());
        let graph = ServiceGraph::new();
        let cedar = PolicyEngine::new();

        let result = compile_job(&job, &graph, "test-cluster", ProviderType::Docker, &cedar).await;
        assert!(matches!(result, Err(JobError::NoTasks)));
    }

    #[tokio::test]
    async fn missing_namespace_returns_error() {
        let mut tasks = BTreeMap::new();
        tasks.insert("worker".to_string(), make_task("worker:latest", 1));
        let spec = LatticeJobSpec {
            tasks,
            ..Default::default()
        };
        let job = LatticeJob::new("test-job", spec);
        // No namespace set

        let graph = ServiceGraph::new();
        let cedar = PolicyEngine::new();

        let result = compile_job(&job, &graph, "test-cluster", ProviderType::Docker, &cedar).await;
        assert!(matches!(result, Err(JobError::MissingNamespace)));
    }
}
