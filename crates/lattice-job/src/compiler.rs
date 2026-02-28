//! JobCompiler — orchestrates per-task compilation for LatticeJob
//!
//! For each task:
//! - Compiles workload via `WorkloadCompiler` → pod template + config resources
//! - Compiles Tetragon tracing policies via `lattice_tetragon`
//! - Aggregates mesh members, config, and tracing policies
//!
//! Then builds a Volcano VCJob from the aggregated pod templates.

use std::collections::BTreeMap;

use lattice_cedar::PolicyEngine;
use lattice_common::crd::{LatticeJob, LatticeMeshMember, ProviderType};
use lattice_common::graph::ServiceGraph;
use lattice_common::policy::tetragon::TracingPolicyNamespaced;
use lattice_volcano::{VCCronJob, VCJob};
use lattice_workload::{CompiledConfig, WorkloadCompiler};

use crate::error::JobError;

/// Discriminated Volcano workload — either a one-shot VCJob or a scheduled VCCronJob.
#[derive(Debug)]
pub enum VolcanoWorkload {
    Job(VCJob),
    CronJob(VCCronJob),
}

/// Complete compiled output for a LatticeJob
#[derive(Debug)]
pub struct CompiledJob {
    /// Volcano workload resource (VCJob or VCCronJob)
    pub workload: VolcanoWorkload,
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
        let mut compiler = WorkloadCompiler::new(
            &task_full_name,
            namespace,
            &task_spec.workload,
            &task_spec.runtime,
            provider_type,
        )
        .with_cedar(cedar)
        .with_cluster_name(cluster_name)
        .with_graph(graph)
        .with_image_pull_secrets(&task_spec.runtime.image_pull_secrets);

        if job.spec.topology.is_some() {
            compiler = compiler.with_topology();
        }

        let compiled = compiler
            .compile()
            .await
            .map_err(|e| JobError::TaskCompilation {
                task: task_name.clone(),
                source: e,
            })?;

        // Convert CompiledPodTemplate to JSON for VCJob
        let template_json = lattice_workload::pod_template_to_json(compiled.pod_template)
            .map_err(JobError::Serialization)?;
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
            &[],
        );
        tracing_policies.extend(policies);
    }

    // Build VCJob from aggregated pod templates, then wrap in VCCronJob if scheduled
    let vcjob = lattice_volcano::compile_vcjob(job, &pod_templates);
    let workload = if job.spec.is_cron() {
        VolcanoWorkload::CronJob(lattice_volcano::compile_vccronjob(job, vcjob))
    } else {
        VolcanoWorkload::Job(vcjob)
    };

    Ok(CompiledJob {
        workload,
        config,
        mesh_members,
        tracing_policies,
    })
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

        let vcjob = match &compiled.workload {
            VolcanoWorkload::Job(v) => v,
            VolcanoWorkload::CronJob(_) => panic!("expected VCJob, got VCCronJob"),
        };
        assert_eq!(vcjob.spec.tasks.len(), 1);
        assert_eq!(vcjob.spec.tasks[0].name, "worker");
        assert_eq!(vcjob.spec.tasks[0].replicas, 2);
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

        let vcjob = match &compiled.workload {
            VolcanoWorkload::Job(v) => v,
            VolcanoWorkload::CronJob(_) => panic!("expected VCJob, got VCCronJob"),
        };
        assert_eq!(vcjob.spec.tasks.len(), 2);
        assert_eq!(vcjob.spec.min_available, Some(5));
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

    #[tokio::test]
    async fn compile_cron_job_produces_vccronjob() {
        let mut tasks = BTreeMap::new();
        tasks.insert("worker".to_string(), make_task("worker:latest", 2));

        let spec = LatticeJobSpec {
            schedule: Some("*/15 * * * *".to_string()),
            tasks,
            ..Default::default()
        };
        let mut job = LatticeJob::new("cron-test", spec);
        job.metadata.namespace = Some("default".to_string());
        job.metadata.uid = Some("uid-cron".to_string());

        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_job(&job, &graph, "test-cluster", ProviderType::Docker, &cedar)
            .await
            .unwrap();

        let cron = match &compiled.workload {
            VolcanoWorkload::CronJob(c) => c,
            VolcanoWorkload::Job(_) => panic!("expected VCCronJob, got VCJob"),
        };
        assert_eq!(cron.spec.schedule, "*/15 * * * *");
        assert_eq!(cron.spec.job_template.spec.tasks.len(), 1);
    }
}
