//! JobCompiler — orchestrates per-task compilation for LatticeJob
//!
//! For each task:
//! - Compiles workload via `WorkloadCompiler` → pod template + config resources
//! - Compiles Tetragon tracing policies via `lattice_tetragon`
//! - Aggregates mesh members, config, and tracing policies
//!
//! Then builds a Volcano VCJob from the aggregated pod templates.
//!
//! When `spec.training` is set, the compiler additionally:
//! - Injects framework-specific env vars (MASTER_ADDR, WORLD_SIZE, NNODES, NCCL)
//! - Injects per-pod RANK and NODE_RANK via Volcano env plugin interpolation
//! - Injects NPROC_PER_NODE from GPU resource count (when GPUs are declared)
//! - Creates a headless Service for pod DNS resolution
//! - Adds checkpoint PVCs and a Velero Schedule for periodic snapshots

use std::collections::BTreeMap;

use lattice_cedar::PolicyEngine;
use lattice_common::crd::{
    CheckpointSpec, JobTaskSpec, LatticeJob, LatticeMeshMember, NcclConfig, ProviderType,
    ResourceSpec, ResourceType, TrainingConfig, TrainingFramework, VolumeMount, WorkloadSpec,
};
use lattice_common::graph::ServiceGraph;
use lattice_common::kube_utils::OwnerReference;
use lattice_common::policy::tetragon::TracingPolicyNamespaced;
use lattice_common::template::TemplateString;
use lattice_volcano::{VCCronJob, VCJob};
use lattice_workload::{CompiledConfig, WorkloadCompiler};

use crate::controller::VELERO_NAMESPACE;
use crate::error::JobError;

const DEFAULT_MASTER_PORT: u16 = 29500;
const DEFAULT_NCCL_DEBUG: &str = "WARN";

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
    /// Headless K8s Service for training pod DNS resolution (training jobs only)
    pub headless_service: Option<serde_json::Value>,
    /// Velero Schedule for periodic checkpoint PVC snapshots (training jobs with checkpoint)
    pub velero_schedule: Option<serde_json::Value>,
}

/// Compile a LatticeJob into Kubernetes resources.
///
/// For each task, runs the shared `WorkloadCompiler` pipeline and `lattice_tetragon`
/// policy compiler, then aggregates results into a single `CompiledJob`.
///
/// When `spec.training` is set, training env vars (framework, NCCL, checkpoint)
/// are injected into task workloads before compilation so they appear in the
/// final pod templates.
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

    // Validate: cron jobs with checkpoint makes no sense (recovery path is for one-shot jobs)
    if job.spec.is_cron() {
        if let Some(ref t) = job.spec.training {
            if t.checkpoint.is_some() {
                return Err(JobError::CronWithCheckpoint);
            }
        }
    }

    // Validate: coordinator task must exist
    if let Some(ref training) = job.spec.training {
        if !job.spec.tasks.contains_key(&training.coordinator_task) {
            return Err(JobError::CoordinatorTaskMissing(
                training.coordinator_task.clone(),
            ));
        }
    }

    // Pre-process tasks: if training is set, clone and inject training env vars
    // into each task's workload BEFORE the WorkloadCompiler runs.
    let tasks: BTreeMap<String, JobTaskSpec> = match job.spec.training {
        Some(ref training) => prepare_training_tasks(name, &job.spec.tasks, training)?,
        None => job.spec.tasks.clone(),
    };

    // Forward the LatticeJob's ownerReferences to VolumeCompiler for PVC GC.
    // For model downloads, the LatticeJob is owned by LatticeModel, so PVCs
    // get LatticeModel ownerReferences and survive job restarts.
    let owner_refs: Vec<OwnerReference> = job
        .metadata
        .owner_references
        .as_ref()
        .map(|refs| refs.iter().map(OwnerReference::from).collect())
        .unwrap_or_default();

    let mut pod_templates: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let mut config = CompiledConfig::default();
    let mut mesh_members = Vec::new();
    let mut tracing_policies = Vec::new();

    for (task_name, task_spec) in &tasks {
        let task_full_name = format!("{}-{}", name, task_name);

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
        .with_image_pull_secrets(&task_spec.runtime.image_pull_secrets)
        .with_owner_references(owner_refs.clone());

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

        let template_json = lattice_workload::pod_template_to_json(compiled.pod_template)
            .map_err(JobError::Serialization)?;
        pod_templates.insert(task_name.clone(), template_json);

        config.merge(compiled.config);

        if let Some(mm) = compiled.mesh_member {
            mesh_members.push(mm);
        }

        let policies = lattice_tetragon::compile_tracing_policies(
            &task_full_name,
            namespace,
            &task_spec.workload,
            &task_spec.runtime,
            &[],
        );
        tracing_policies.extend(policies);
    }

    // Training: label PVCs and pod templates so Velero's fs-backup can find them
    let has_checkpoint = job
        .spec
        .training
        .as_ref()
        .is_some_and(|t| t.checkpoint.is_some());
    if job.spec.training.is_some() {
        for pvc in &mut config.pvcs {
            pvc.metadata
                .labels
                .insert("lattice.dev/training-job".to_string(), name.to_string());
        }
        for template in pod_templates.values_mut() {
            let metadata = template
                .as_object_mut()
                .and_then(|t| t.get_mut("metadata"))
                .and_then(|m| m.as_object_mut());
            if let Some(metadata) = metadata {
                let labels = metadata
                    .entry("labels")
                    .or_insert_with(|| serde_json::json!({}));
                if let Some(labels) = labels.as_object_mut() {
                    labels.insert(
                        "lattice.dev/training-job".to_string(),
                        serde_json::json!(name),
                    );
                }

                // Tell Velero's node-agent which volumes to fs-backup.
                // defaultVolumesToFsBackup on the Schedule is unreliable;
                // explicit pod annotations are the guaranteed path.
                if has_checkpoint {
                    let annotations = metadata
                        .entry("annotations")
                        .or_insert_with(|| serde_json::json!({}));
                    if let Some(annotations) = annotations.as_object_mut() {
                        annotations.insert(
                            "backup.velero.io/backup-volumes".to_string(),
                            serde_json::json!("checkpoints"),
                        );
                    }
                }
            }
        }
    }

    // Training: inject RANK into pod templates via K8s env var interpolation.
    // The Volcano env plugin injects VC_TASK_INDEX per pod (globally unique
    // across all tasks). We map RANK = $(VC_TASK_INDEX) directly in the pod
    // spec so K8s interpolates it at pod creation time. This can't go in the
    // ConfigMap because K8s only interpolates $(VAR) in pod spec env entries.
    if job.spec.training.is_some() {
        for template in pod_templates.values_mut() {
            inject_rank_env(template);
        }
    }

    // Training: compile headless service and Velero schedule
    let uid = job.metadata.uid.as_deref().unwrap_or_default();
    let headless_service = job
        .spec
        .training
        .as_ref()
        .map(|_| compile_headless_service(name, namespace, uid));
    let velero_schedule = job
        .spec
        .training
        .as_ref()
        .and_then(|t| t.checkpoint.as_ref())
        .map(|ckpt| compile_velero_schedule(name, namespace, ckpt));

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
        headless_service,
        velero_schedule,
    })
}

// =============================================================================
// Training compilation
// =============================================================================

/// Clone tasks and inject training env vars into each task's workload.
///
/// Injects framework env vars, NCCL tuning, and checkpoint PVC/env. This runs
/// before `WorkloadCompiler` so the injected values appear in pod templates.
fn prepare_training_tasks(
    job_name: &str,
    tasks: &BTreeMap<String, JobTaskSpec>,
    training: &TrainingConfig,
) -> Result<BTreeMap<String, JobTaskSpec>, JobError> {
    let world_size: u32 = tasks.values().map(|t| t.replicas).sum();
    let coordinator = &training.coordinator_task;
    let coordinator_addr = format!("{}-{}-0.{}", job_name, coordinator, job_name);

    let mut result = BTreeMap::new();
    for (task_name, task_spec) in tasks {
        let mut task = task_spec.clone();

        // Checkpoint training: Never restart — let the failure propagate to
        // Volcano's PodFailed event so the Lattice controller can trigger
        // stop-the-world checkpoint recovery.
        // Non-checkpoint training: OnFailure — let K8s restart transient
        // container failures without full job restarts.
        if task.restart_policy.is_none() {
            task.restart_policy = Some(if training.checkpoint.is_some() {
                lattice_common::crd::RestartPolicy::Never
            } else {
                lattice_common::crd::RestartPolicy::OnFailure
            });
        }

        let gpu_count = detect_gpu_count(&task.workload);
        inject_framework_env(
            &mut task.workload,
            &training.framework,
            &coordinator_addr,
            world_size,
            gpu_count,
        )?;

        inject_nccl_env(&mut task.workload, training.nccl.as_ref());

        if let Some(ref ckpt) = training.checkpoint {
            inject_checkpoint_volume(&mut task.workload, ckpt);
        }

        result.insert(task_name.clone(), task);
    }
    Ok(result)
}

/// Inject framework-specific env vars into all containers.
///
/// `nnodes` is the total pod count (sum of all task replicas). `gpu_count`
/// is the number of GPUs on this specific task (None if no GPU resource).
///
/// RANK and NODE_RANK are NOT injected here — they're set at the pod spec
/// level via `$(VC_TASK_INDEX)` so K8s interpolates the per-pod value at
/// runtime. See `inject_rank_env`.
///
/// When `gpu_count` is `Some`, injects `NPROC_PER_NODE` (PyTorch/DeepSpeed)
/// or `JAX_LOCAL_DEVICE_COUNT` (JAX) so launchers like `torchrun` know how
/// many processes to spawn per node. `WORLD_SIZE` is then set to
/// `nnodes * nproc_per_node` (total processes). When `gpu_count` is `None`,
/// `WORLD_SIZE` equals `nnodes`.
fn inject_framework_env(
    workload: &mut WorkloadSpec,
    framework: &TrainingFramework,
    coordinator_addr: &str,
    nnodes: u32,
    gpu_count: Option<u32>,
) -> Result<(), JobError> {
    let nproc_per_node = gpu_count.unwrap_or(1);
    let world_size = nnodes * nproc_per_node;

    let env_vars: Vec<(&str, String)> = match framework {
        TrainingFramework::PyTorch | TrainingFramework::DeepSpeed => {
            let mut vars = vec![
                ("MASTER_ADDR", coordinator_addr.to_string()),
                ("MASTER_PORT", DEFAULT_MASTER_PORT.to_string()),
                ("WORLD_SIZE", world_size.to_string()),
                ("NNODES", nnodes.to_string()),
            ];
            if let Some(count) = gpu_count {
                vars.push(("NPROC_PER_NODE", count.to_string()));
            }
            vars
        }
        TrainingFramework::Jax => {
            let mut vars = vec![
                (
                    "JAX_COORDINATOR_ADDRESS",
                    format!("{}:{}", coordinator_addr, DEFAULT_MASTER_PORT),
                ),
                ("JAX_NUM_PROCESSES", world_size.to_string()),
            ];
            if let Some(count) = gpu_count {
                vars.push(("JAX_LOCAL_DEVICE_COUNT", count.to_string()));
            }
            vars
        }
        // #[non_exhaustive] requires a wildcard — new variants must add an explicit arm above
        _ => return Err(JobError::UnsupportedFramework(framework.to_string())),
    };

    inject_env_all(workload, &env_vars);
    Ok(())
}

/// Inject NCCL env vars into all containers based on config and GPU model.
fn inject_nccl_env(workload: &mut WorkloadSpec, nccl: Option<&NcclConfig>) {
    let default_nccl = NcclConfig::default();
    let nccl = nccl.unwrap_or(&default_nccl);

    let mut env_vars: Vec<(&str, String)> = vec![(
        "NCCL_DEBUG",
        nccl.debug
            .as_deref()
            .unwrap_or(DEFAULT_NCCL_DEBUG)
            .to_string(),
    )];

    if let Some(ref net_if) = nccl.net_if {
        env_vars.push(("NCCL_SOCKET_IFNAME", net_if.clone()));
    }
    if let Some(ref ib_hca) = nccl.ib_hca {
        env_vars.push(("NCCL_IB_HCA", ib_hca.clone()));
    }
    if let Some(gdr) = nccl.gdr {
        env_vars.push((
            "NCCL_NET_GDR_LEVEL",
            if gdr { "5" } else { "0" }.to_string(),
        ));
    }

    if let Some(model) = detect_gpu_model(workload) {
        env_vars.extend(nccl_defaults_for_gpu(&model));
    }

    inject_env_all(workload, &env_vars);

    // NCCL extra_env
    if let Some(ref extra) = nccl.extra_env {
        for container in workload.containers.values_mut() {
            for (key, value) in extra {
                container
                    .variables
                    .entry(key.clone())
                    .or_insert_with(|| TemplateString::new(value));
            }
        }
    }
}

/// Inject env vars into all containers (does not overwrite existing values).
fn inject_env_all(workload: &mut WorkloadSpec, vars: &[(&str, String)]) {
    for container in workload.containers.values_mut() {
        for (key, value) in vars {
            container
                .variables
                .entry(key.to_string())
                .or_insert_with(|| TemplateString::new(value));
        }
    }
}

/// Inject `RANK` and `NODE_RANK` env vars into a pod template JSON using
/// K8s variable interpolation.
///
/// Sets both `RANK = $(VC_TASK_INDEX)` and `NODE_RANK = $(VC_TASK_INDEX)`
/// directly in each container's `env` array. K8s interpolates
/// `$(VC_TASK_INDEX)` at pod creation time using the value injected by the
/// Volcano env plugin.
///
/// `RANK` is the traditional PyTorch env var. `NODE_RANK` is the name
/// expected by `torchrun` and DeepSpeed launchers.
fn inject_rank_env(template: &mut serde_json::Value) {
    let rank_env = serde_json::json!({"name": "RANK", "value": "$(VC_TASK_INDEX)"});
    let node_rank_env = serde_json::json!({"name": "NODE_RANK", "value": "$(VC_TASK_INDEX)"});

    let containers = template
        .pointer_mut("/spec/containers")
        .and_then(|c| c.as_array_mut());

    if let Some(containers) = containers {
        for container in containers {
            let env = container.as_object_mut().and_then(|c| {
                c.entry("env")
                    .or_insert_with(|| serde_json::json!([]))
                    .as_array_mut()
            });
            if let Some(env) = env {
                env.push(rank_env.clone());
                env.push(node_rank_env.clone());
            }
        }
    }
}

/// Add checkpoint PVC resource and CHECKPOINT_DIR env var to all containers.
fn inject_checkpoint_volume(workload: &mut WorkloadSpec, ckpt: &CheckpointSpec) {
    let local_path = ckpt.effective_local_path();

    // Add CHECKPOINT_DIR env var
    for container in workload.containers.values_mut() {
        container
            .variables
            .entry("CHECKPOINT_DIR".to_string())
            .or_insert_with(|| TemplateString::new(local_path));

        container.volumes.insert(
            local_path.to_string(),
            VolumeMount {
                source: Some(TemplateString::new("${resources.checkpoints}")),
                ..Default::default()
            },
        );
    }

    // Add checkpoint PVC resource
    workload.resources.insert(
        "checkpoints".to_string(),
        ResourceSpec {
            type_: ResourceType::Volume,
            params: Some(BTreeMap::from([(
                "size".to_string(),
                serde_json::json!(ckpt.effective_volume_size()),
            )])),
            ..Default::default()
        },
    );
}

/// Detect GPU model from workload resources.
fn detect_gpu_model(workload: &WorkloadSpec) -> Option<String> {
    workload
        .resources
        .values()
        .filter(|r| r.type_.is_gpu())
        .find_map(|r| r.gpu_params().ok().flatten().and_then(|p| p.model.clone()))
}

/// Detect GPU count per pod from workload resources.
///
/// Returns the `count` from the first GPU resource found, or `None` if the
/// task has no GPU resource declared.
fn detect_gpu_count(workload: &WorkloadSpec) -> Option<u32> {
    workload
        .resources
        .values()
        .filter(|r| r.type_.is_gpu())
        .find_map(|r| r.gpu_params().ok().flatten().map(|p| p.count))
}

/// NCCL defaults per GPU model.
fn nccl_defaults_for_gpu(model: &str) -> Vec<(&'static str, String)> {
    let m = model.to_uppercase();
    if m.contains("H100") && m.contains("SXM") {
        vec![
            ("NCCL_ALGO", "Ring,Tree".to_string()),
            ("NCCL_IB_DISABLE", "0".to_string()),
        ]
    } else if m.contains("H100") {
        vec![
            ("NCCL_ALGO", "Ring".to_string()),
            ("NCCL_IB_DISABLE", "0".to_string()),
        ]
    } else if m.contains("A100") {
        vec![("NCCL_ALGO", "Ring,Tree".to_string())]
    } else if m.contains("L4") || m.contains("L40") || m.contains("T4") {
        vec![
            ("NCCL_ALGO", "Ring".to_string()),
            ("NCCL_IB_DISABLE", "1".to_string()),
        ]
    } else {
        vec![]
    }
}

/// Compile a headless K8s Service for training pod DNS resolution.
fn compile_headless_service(name: &str, namespace: &str, owner_uid: &str) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/managed-by": "lattice",
                "app.kubernetes.io/name": name,
                "lattice.dev/training-job": name
            },
            "ownerReferences": [{
                "apiVersion": "lattice.dev/v1alpha1",
                "kind": "LatticeJob",
                "name": name,
                "uid": owner_uid,
                "controller": true,
                "blockOwnerDeletion": true
            }]
        },
        "spec": {
            "clusterIP": "None",
            "selector": {
                "volcano.sh/job-name": name
            },
            "publishNotReadyAddresses": true
        }
    })
}

/// Compile a Velero Schedule for periodic checkpoint backups.
///
/// Targets PVCs and pods labeled with `lattice.dev/training-job: <name>` in
/// the job's namespace. Uses Kopia file-system backup (via Velero's node-agent)
/// instead of CSI volume snapshots for broad storage class compatibility.
fn compile_velero_schedule(
    name: &str,
    namespace: &str,
    ckpt: &CheckpointSpec,
) -> serde_json::Value {
    let schedule_name = format!("lattice-training-{}", name);
    let mut template = serde_json::json!({
        "ttl": ckpt.effective_ttl(),
        "includedNamespaces": [namespace],
        "includedResources": [
            "persistentvolumeclaims",
            "persistentvolumes",
            "pods"
        ],
        "defaultVolumesToFsBackup": true,
        "snapshotVolumes": false,
        "labelSelector": {
            "matchLabels": {
                "lattice.dev/training-job": name
            }
        }
    });
    if let Some(ref bsl) = ckpt.backup_store {
        template["storageLocation"] = serde_json::json!(bsl);
    }
    serde_json::json!({
        "apiVersion": "velero.io/v1",
        "kind": "Schedule",
        "metadata": {
            "name": schedule_name,
            "namespace": VELERO_NAMESPACE,
            "labels": {
                "app.kubernetes.io/managed-by": "lattice",
                "lattice.dev/training-job": name
            }
        },
        "spec": {
            "schedule": ckpt.interval,
            "paused": false,
            "template": template
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use lattice_common::crd::{
        CheckpointSpec, ContainerSpec, JobTaskSpec, LatticeJobSpec, NcclConfig, ResourceSpec,
        ResourceType, RestartPolicy, RuntimeSpec, TrainingConfig, TrainingFramework, WorkloadSpec,
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

    fn permit_all_cedar() -> PolicyEngine {
        PolicyEngine::with_policies("permit(principal, action, resource);").unwrap()
    }

    // ── Non-training tests ──

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
        assert!(compiled.tracing_policies.is_empty());
        assert!(compiled.headless_service.is_none());
        assert!(compiled.velero_schedule.is_none());
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

    // ── Training compilation unit tests ──

    #[test]
    fn prepare_training_injects_pytorch_env() {
        let mut tasks = BTreeMap::new();
        tasks.insert("master".to_string(), make_task("train:latest", 1));
        tasks.insert("worker".to_string(), make_task("train:latest", 3));

        let training = TrainingConfig {
            framework: TrainingFramework::PyTorch,
            coordinator_task: "master".to_string(),
            checkpoint: None,
            nccl: None,
        };

        let prepared = prepare_training_tasks("my-job", &tasks, &training).unwrap();

        let master_vars = &prepared["master"].workload.containers["main"].variables;
        assert_eq!(
            master_vars["MASTER_ADDR"].as_str(),
            "my-job-master-0.my-job"
        );
        assert_eq!(master_vars["MASTER_PORT"].as_str(), "29500");
        // No GPU resource → WORLD_SIZE = NNODES (4 replicas, 1 process each)
        assert_eq!(master_vars["WORLD_SIZE"].as_str(), "4");
        assert_eq!(master_vars["NNODES"].as_str(), "4");
        // No GPU resource → NPROC_PER_NODE not injected
        assert!(!master_vars.contains_key("NPROC_PER_NODE"));
        // RANK/NODE_RANK are NOT in the ConfigMap — injected at pod spec level
        // via $(VC_TASK_INDEX) by inject_rank_env
        assert!(!master_vars.contains_key("RANK"));
        assert!(!master_vars.contains_key("NODE_RANK"));

        let worker_vars = &prepared["worker"].workload.containers["main"].variables;
        assert!(worker_vars.contains_key("MASTER_ADDR"));
        assert!(worker_vars.contains_key("NNODES"));
        assert!(!worker_vars.contains_key("RANK"));
    }

    #[test]
    fn prepare_training_injects_jax_env() {
        let mut tasks = BTreeMap::new();
        tasks.insert("master".to_string(), make_task("jax:latest", 1));
        tasks.insert("worker".to_string(), make_task("jax:latest", 2));

        let training = TrainingConfig {
            framework: TrainingFramework::Jax,
            coordinator_task: "master".to_string(),
            checkpoint: None,
            nccl: None,
        };

        let prepared = prepare_training_tasks("my-job", &tasks, &training).unwrap();
        let vars = &prepared["master"].workload.containers["main"].variables;
        assert!(vars.contains_key("JAX_COORDINATOR_ADDRESS"));
        // No GPU resource → JAX_NUM_PROCESSES = nnodes (3 replicas)
        assert_eq!(vars["JAX_NUM_PROCESSES"].as_str(), "3");
        assert!(!vars.contains_key("JAX_LOCAL_DEVICE_COUNT"));
        assert!(!vars.contains_key("MASTER_ADDR"));
    }

    #[test]
    fn prepare_training_injects_nccl_overrides() {
        let mut tasks = BTreeMap::new();
        tasks.insert("master".to_string(), make_task("train:latest", 1));

        let training = TrainingConfig {
            framework: TrainingFramework::PyTorch,
            coordinator_task: "master".to_string(),
            checkpoint: None,
            nccl: Some(NcclConfig {
                debug: Some("INFO".to_string()),
                net_if: Some("ib0".to_string()),
                gdr: Some(true),
                ..Default::default()
            }),
        };

        let prepared = prepare_training_tasks("my-job", &tasks, &training).unwrap();
        let vars = &prepared["master"].workload.containers["main"].variables;
        assert_eq!(vars["NCCL_DEBUG"].as_str(), "INFO");
        assert_eq!(vars["NCCL_SOCKET_IFNAME"].as_str(), "ib0");
        assert_eq!(vars["NCCL_NET_GDR_LEVEL"].as_str(), "5");
    }

    #[test]
    fn prepare_training_injects_checkpoint_volume() {
        let mut tasks = BTreeMap::new();
        tasks.insert("master".to_string(), make_task("train:latest", 1));
        tasks.insert("worker".to_string(), make_task("train:latest", 2));

        let training = TrainingConfig {
            framework: TrainingFramework::PyTorch,
            coordinator_task: "master".to_string(),
            checkpoint: Some(CheckpointSpec {
                interval: "*/30 * * * *".to_string(),
                local_path: None,
                volume_size: None,
                storage_class: None,
                backup_store: None,
            }),
            nccl: None,
        };

        let prepared = prepare_training_tasks("my-job", &tasks, &training).unwrap();

        // Both master and worker get checkpoint volume
        for task in prepared.values() {
            assert_eq!(
                task.workload.containers["main"].variables["CHECKPOINT_DIR"].as_str(),
                "/checkpoints"
            );
            assert!(task.workload.resources.contains_key("checkpoints"));
        }
    }

    #[test]
    fn prepare_training_defaults_restart_policy_to_on_failure() {
        let mut tasks = BTreeMap::new();
        let mut task = make_task("train:latest", 1);
        task.restart_policy = None; // unset
        tasks.insert("worker".to_string(), task);

        let training = TrainingConfig {
            framework: TrainingFramework::PyTorch,
            coordinator_task: "master".to_string(),
            checkpoint: None,
            nccl: None,
        };

        let prepared = prepare_training_tasks("my-job", &tasks, &training).unwrap();
        assert_eq!(
            prepared["worker"].restart_policy,
            Some(RestartPolicy::OnFailure)
        );
    }

    #[test]
    fn prepare_training_checkpoint_defaults_restart_policy_to_never() {
        let mut tasks = BTreeMap::new();
        let mut task = make_task("train:latest", 1);
        task.restart_policy = None; // unset
        tasks.insert("worker".to_string(), task);

        let training = TrainingConfig {
            framework: TrainingFramework::PyTorch,
            coordinator_task: "master".to_string(),
            checkpoint: Some(CheckpointSpec {
                interval: "*/30 * * * *".to_string(),
                local_path: None,
                volume_size: None,
                storage_class: None,
                backup_store: None,
            }),
            nccl: None,
        };

        let prepared = prepare_training_tasks("my-job", &tasks, &training).unwrap();
        // Checkpoint training: Never restart — failures must propagate to
        // Volcano so the Lattice controller can trigger checkpoint recovery
        assert_eq!(
            prepared["worker"].restart_policy,
            Some(RestartPolicy::Never)
        );
    }

    #[test]
    fn headless_service_structure() {
        let svc = compile_headless_service("my-training", "gpu-ns", "uid-abc");
        assert_eq!(svc["spec"]["clusterIP"], "None");
        assert_eq!(
            svc["spec"]["selector"]["volcano.sh/job-name"],
            "my-training"
        );
        assert_eq!(svc["spec"]["publishNotReadyAddresses"], true);
        assert_eq!(svc["metadata"]["namespace"], "gpu-ns");
        assert_eq!(svc["metadata"]["ownerReferences"][0]["kind"], "LatticeJob");
    }

    #[test]
    fn velero_schedule_structure() {
        let ckpt = CheckpointSpec {
            interval: "*/30 * * * *".to_string(),
            local_path: None,
            volume_size: None,
            storage_class: None,
            backup_store: Some("my-bsl".to_string()),
        };

        let schedule = compile_velero_schedule("my-training", "gpu-ns", &ckpt);
        assert_eq!(schedule["apiVersion"], "velero.io/v1");
        assert_eq!(schedule["kind"], "Schedule");
        assert_eq!(schedule["metadata"]["name"], "lattice-training-my-training");
        assert_eq!(schedule["spec"]["schedule"], "*/30 * * * *");
        // TTL auto-computed: 30min interval × 3 = 90min
        assert_eq!(schedule["spec"]["template"]["ttl"], "90m");
        assert_eq!(schedule["spec"]["template"]["storageLocation"], "my-bsl");
        assert_eq!(
            schedule["spec"]["template"]["defaultVolumesToFsBackup"],
            true
        );
        assert_eq!(schedule["spec"]["template"]["snapshotVolumes"], false);
        assert_eq!(
            schedule["spec"]["template"]["includedNamespaces"][0],
            "gpu-ns"
        );

        // Verify includedResources contains PVCs, PVs, and pods
        let resources = schedule["spec"]["template"]["includedResources"]
            .as_array()
            .expect("includedResources should be an array");
        let resource_strs: Vec<&str> = resources.iter().filter_map(|v| v.as_str()).collect();
        assert!(resource_strs.contains(&"persistentvolumeclaims"));
        assert!(resource_strs.contains(&"persistentvolumes"));
        assert!(resource_strs.contains(&"pods"));

        assert_eq!(
            schedule["spec"]["template"]["labelSelector"]["matchLabels"]
                ["lattice.dev/training-job"],
            "my-training"
        );
    }

    #[test]
    fn velero_schedule_omits_storage_location_when_none() {
        let ckpt = CheckpointSpec {
            interval: "*/30 * * * *".to_string(),
            local_path: None,
            volume_size: None,
            storage_class: None,
            backup_store: None,
        };

        let schedule = compile_velero_schedule("my-training", "gpu-ns", &ckpt);
        assert!(
            schedule["spec"]["template"]
                .get("storageLocation")
                .is_none(),
            "storageLocation should be absent when backup_store is None"
        );
        assert_eq!(
            schedule["spec"]["template"]["defaultVolumesToFsBackup"],
            true
        );
        assert_eq!(schedule["spec"]["template"]["snapshotVolumes"], false);
    }

    #[tokio::test]
    async fn compile_job_labels_pod_templates_for_training() {
        let mut tasks = BTreeMap::new();
        tasks.insert("master".to_string(), make_task("train:latest", 1));
        tasks.insert("worker".to_string(), make_task("train:latest", 2));

        let spec = LatticeJobSpec {
            training: Some(TrainingConfig {
                framework: TrainingFramework::PyTorch,
                coordinator_task: "master".to_string(),
                checkpoint: Some(CheckpointSpec {
                    interval: "*/30 * * * *".to_string(),
                    local_path: None,
                    volume_size: None,
                    storage_class: None,
                    backup_store: None,
                }),
                nccl: None,
            }),
            tasks,
            ..Default::default()
        };
        let mut job = LatticeJob::new("my-train", spec);
        job.metadata.namespace = Some("default".to_string());
        job.metadata.uid = Some("uid-train".to_string());

        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_job(&job, &graph, "test-cluster", ProviderType::Docker, &cedar)
            .await
            .unwrap();

        let vcjob = match &compiled.workload {
            VolcanoWorkload::Job(v) => v,
            VolcanoWorkload::CronJob(_) => panic!("expected VCJob"),
        };

        // Every task's pod template must carry the training-job label
        // and the Velero backup-volumes annotation (checkpoint is configured)
        for task in &vcjob.spec.tasks {
            let label = task.template["metadata"]["labels"]["lattice.dev/training-job"]
                .as_str()
                .unwrap_or_default();
            assert_eq!(
                label, "my-train",
                "Task '{}' pod template missing lattice.dev/training-job label",
                task.name
            );

            let annotation = task.template["metadata"]["annotations"]
                ["backup.velero.io/backup-volumes"]
                .as_str()
                .unwrap_or_default();
            assert_eq!(
                annotation, "checkpoints",
                "Task '{}' pod template missing backup.velero.io/backup-volumes annotation",
                task.name
            );
        }
    }

    #[test]
    fn nccl_defaults_h100_sxm() {
        let defaults = nccl_defaults_for_gpu("H100-SXM-80GB");
        assert!(defaults
            .iter()
            .any(|(k, v)| *k == "NCCL_ALGO" && v == "Ring,Tree"));
        assert!(defaults
            .iter()
            .any(|(k, v)| *k == "NCCL_IB_DISABLE" && v == "0"));
    }

    #[test]
    fn nccl_defaults_l4() {
        let defaults = nccl_defaults_for_gpu("L4");
        assert!(defaults
            .iter()
            .any(|(k, v)| *k == "NCCL_IB_DISABLE" && v == "1"));
    }

    #[test]
    fn nccl_defaults_unknown_gpu_empty() {
        let defaults = nccl_defaults_for_gpu("RTX-4090");
        assert!(defaults.is_empty());
    }

    // ── Multi-GPU tests ──

    fn make_gpu_task(image: &str, replicas: u32, gpu_count: u32) -> JobTaskSpec {
        let mut task = make_task(image, replicas);
        task.workload.resources.insert(
            "gpu".to_string(),
            ResourceSpec {
                type_: ResourceType::Gpu,
                params: Some(BTreeMap::from([(
                    "count".to_string(),
                    serde_json::json!(gpu_count),
                )])),
                ..Default::default()
            },
        );
        task
    }

    #[test]
    fn detect_gpu_count_returns_count_from_gpu_resource() {
        let task = make_gpu_task("train:latest", 1, 8);
        assert_eq!(detect_gpu_count(&task.workload), Some(8));
    }

    #[test]
    fn detect_gpu_count_returns_none_without_gpu_resource() {
        let task = make_task("train:latest", 1);
        assert_eq!(detect_gpu_count(&task.workload), None);
    }

    #[test]
    fn prepare_training_injects_nproc_per_node_for_pytorch() {
        let mut tasks = BTreeMap::new();
        tasks.insert("master".to_string(), make_gpu_task("train:latest", 1, 8));
        tasks.insert("worker".to_string(), make_gpu_task("train:latest", 4, 8));

        let training = TrainingConfig {
            framework: TrainingFramework::PyTorch,
            coordinator_task: "master".to_string(),
            checkpoint: None,
            nccl: None,
        };

        let prepared = prepare_training_tasks("my-job", &tasks, &training).unwrap();
        let vars = &prepared["worker"].workload.containers["main"].variables;

        // 5 pods × 8 GPUs = 40 total processes
        assert_eq!(vars["NNODES"].as_str(), "5");
        assert_eq!(vars["NPROC_PER_NODE"].as_str(), "8");
        assert_eq!(vars["WORLD_SIZE"].as_str(), "40");
    }

    #[test]
    fn prepare_training_injects_jax_local_device_count() {
        let mut tasks = BTreeMap::new();
        tasks.insert("master".to_string(), make_gpu_task("jax:latest", 1, 4));
        tasks.insert("worker".to_string(), make_gpu_task("jax:latest", 3, 4));

        let training = TrainingConfig {
            framework: TrainingFramework::Jax,
            coordinator_task: "master".to_string(),
            checkpoint: None,
            nccl: None,
        };

        let prepared = prepare_training_tasks("my-job", &tasks, &training).unwrap();
        let vars = &prepared["worker"].workload.containers["main"].variables;

        // 4 pods × 4 GPUs = 16 total processes
        assert_eq!(vars["JAX_NUM_PROCESSES"].as_str(), "16");
        assert_eq!(vars["JAX_LOCAL_DEVICE_COUNT"].as_str(), "4");
    }

    #[test]
    fn prepare_training_no_gpu_omits_nproc_per_node() {
        let mut tasks = BTreeMap::new();
        tasks.insert("master".to_string(), make_task("train:latest", 1));
        tasks.insert("worker".to_string(), make_task("train:latest", 3));

        let training = TrainingConfig {
            framework: TrainingFramework::PyTorch,
            coordinator_task: "master".to_string(),
            checkpoint: None,
            nccl: None,
        };

        let prepared = prepare_training_tasks("my-job", &tasks, &training).unwrap();
        let vars = &prepared["worker"].workload.containers["main"].variables;

        assert!(!vars.contains_key("NPROC_PER_NODE"));
        // Without GPU, WORLD_SIZE = NNODES (1 process per pod)
        assert_eq!(vars["NNODES"].as_str(), "4");
        assert_eq!(vars["WORLD_SIZE"].as_str(), "4");
    }

    #[test]
    fn inject_rank_env_adds_rank_and_node_rank() {
        let mut template = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "main",
                    "env": []
                }]
            }
        });

        inject_rank_env(&mut template);

        let env = template["spec"]["containers"][0]["env"]
            .as_array()
            .unwrap();
        let names: Vec<&str> = env.iter().filter_map(|e| e["name"].as_str()).collect();
        assert!(names.contains(&"RANK"), "missing RANK");
        assert!(names.contains(&"NODE_RANK"), "missing NODE_RANK");

        let rank_val = env.iter().find(|e| e["name"] == "RANK").unwrap();
        let node_rank_val = env.iter().find(|e| e["name"] == "NODE_RANK").unwrap();
        assert_eq!(rank_val["value"], "$(VC_TASK_INDEX)");
        assert_eq!(node_rank_val["value"], "$(VC_TASK_INDEX)");
    }
}
