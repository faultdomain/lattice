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
//! - Opts training pods out of ambient mesh for direct L4 peer traffic

use std::collections::BTreeMap;

use lattice_cedar::PolicyEngine;
use lattice_common::crd::{
    JobTaskSpec, LatticeJob, LatticeMeshMember, NcclConfig, PortSpec, ProviderType,
    ServicePortsSpec, TrainingConfig, TrainingFramework, WorkloadSpec,
};
use lattice_common::graph::ServiceGraph;
use lattice_common::kube_utils::OwnerReference;
use lattice_common::policy::tetragon::TracingPolicyNamespaced;
use lattice_common::template::TemplateString;
use lattice_common::LABEL_TRAINING_JOB;
use lattice_volcano::{VCCronJob, VCJob};
use lattice_workload::{inject_pod_labels, CompiledConfig, WorkloadCompiler};

use crate::error::JobError;

const DEFAULT_MASTER_PORT: u16 = 29500;
const DEFAULT_NCCL_DEBUG: &str = "WARN";
const RANK_INIT_IMAGE: &str = "busybox:latest";

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
/// When `spec.training` is set, training env vars (framework, NCCL) are
/// injected into task workloads before compilation so they appear in the
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

    // Apply defaults to each task via strategic merge patch (compile-time only)
    let tasks = job.spec.merged_tasks();

    // Validate: coordinator task must exist
    if let Some(ref training) = job.spec.training {
        if !tasks.contains_key(&training.coordinator_task) {
            return Err(JobError::CoordinatorTaskMissing(
                training.coordinator_task.clone(),
            ));
        }
    }

    // Pre-process tasks: if training is set, inject training env vars
    // into each task's workload BEFORE the WorkloadCompiler runs.
    let tasks: BTreeMap<String, JobTaskSpec> = match job.spec.training {
        Some(ref training) => prepare_training_tasks(name, &tasks, training)?,
        None => tasks,
    };

    // Register each task in the service graph so WorkloadCompiler finds them
    // and creates LatticeMeshMembers (same path as LatticeService).
    for (task_name, task_spec) in &tasks {
        graph.put_workload(
            namespace,
            &format!("{}-{}", name, task_name),
            &task_spec.workload,
            &[],
        );
    }

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
            cedar,
        )
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

    // Training: opt out of ambient mesh and use group-level selector for peer traffic.
    // All pods in the gang share the same `lattice.dev/training-job` label, so one
    // CiliumNetworkPolicy covers the entire gang with direct L4 peer rules.
    if job.spec.training.is_some() {
        for mm in &mut mesh_members {
            mm.spec.allow_peer_traffic = true;
            mm.spec.ambient = false;
            mm.spec.target = lattice_common::crd::MeshMemberTarget::Selector(
                [(LABEL_TRAINING_JOB.to_string(), name.to_string())]
                    .into_iter()
                    .collect(),
            );
        }

        for pvc in &mut config.pvcs {
            pvc.metadata
                .labels
                .insert(LABEL_TRAINING_JOB.to_string(), name.to_string());
        }
    }

    // Training: inject per-pod RANK via init container + emptyDir, and
    // add pod labels for mesh opt-out and peer group identification.
    // Volcano's VC_TASK_INDEX is per-task-group (not globally unique), so
    // multi-task jobs need an offset: RANK = rank_offset + VC_TASK_INDEX.
    // Tasks are iterated in BTreeMap order (alphabetical), accumulating
    // cumulative offsets from each task's replica count.
    if job.spec.training.is_some() {
        let mut cumulative_offset = 0u32;
        for (task_name, task_spec) in &tasks {
            if let Some(template) = pod_templates.get_mut(task_name) {
                inject_rank_env(template, cumulative_offset);
                inject_pod_labels(
                    template,
                    &[
                        (LABEL_TRAINING_JOB, name),
                        ("istio.io/dataplane-mode", "none"),
                    ],
                );
            }
            cumulative_offset += task_spec.replicas();
        }
    }

    // Build VCJob from aggregated pod templates, then wrap in VCCronJob if scheduled.
    // For training jobs, the Volcano `svc` plugin creates the headless Service
    // and sets hostname/subdomain on each pod — no manual service needed.
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

// =============================================================================
// Training compilation
// =============================================================================

/// Clone tasks and inject training env vars into each task's workload.
///
/// Injects framework env vars and NCCL tuning. This runs
/// before `WorkloadCompiler` so the injected values appear in pod templates.
fn prepare_training_tasks(
    job_name: &str,
    tasks: &BTreeMap<String, JobTaskSpec>,
    training: &TrainingConfig,
) -> Result<BTreeMap<String, JobTaskSpec>, JobError> {
    let world_size: u32 = tasks.values().map(|t| t.replicas()).sum();
    let coordinator = &training.coordinator_task;
    let coordinator_addr = format!("{}-{}-0.{}", job_name, coordinator, job_name);

    // Validate: every container in every training task must declare an explicit
    // command. The rank injection wraps the command with `. /lattice-env/rank.sh;
    // exec "$@"`, which requires a command to wrap.
    for (task_name, task_spec) in tasks {
        for (container_name, container) in &task_spec.workload.containers {
            if container.command.is_none() {
                return Err(JobError::TrainingContainerNoCommand {
                    task: task_name.clone(),
                    container: container_name.clone(),
                });
            }
        }
    }

    let mut result = BTreeMap::new();
    for (task_name, task_spec) in tasks {
        let mut task = task_spec.clone();

        // Training tasks MUST use restart_policy=Never. With OnFailure, kubelet
        // restarts the container locally, which prevents Volcano's PodFailed→RestartJob
        // gang restart from ever triggering. Override if the user set something else.
        match &task.restart_policy {
            Some(policy) if *policy != lattice_common::crd::RestartPolicy::Never => {
                tracing::warn!(
                    task = task_name.as_str(),
                    policy = %policy,
                    "overriding restart_policy to Never for training task \
                     (was '{}' — kubelet restarts prevent Volcano gang restart)",
                    policy,
                );
                task.restart_policy = Some(lattice_common::crd::RestartPolicy::Never);
            }
            None => {
                task.restart_policy = Some(lattice_common::crd::RestartPolicy::Never);
            }
            Some(_) => {} // Already Never
        }

        // Inject TaskCompleted→CompleteJob on the coordinator task so Volcano
        // marks the job as completed when the coordinator finishes. Only inject
        // if the user hasn't provided explicit task-level policies.
        if *task_name == *coordinator && task.policies.is_none() {
            task.policies = Some(vec![lattice_common::crd::VolcanoPolicy {
                event: lattice_common::crd::VolcanoPolicyEvent::TaskCompleted,
                action: lattice_common::crd::VolcanoPolicyAction::CompleteJob,
            }]);
        }

        // Inject the master port so WorkloadCompiler creates a LatticeMeshMember.
        // Without a service port, no mesh member is generated and the cluster-wide
        // default-deny blocks inter-pod traffic on port 29500.
        inject_training_service_port(&mut task.workload);

        let gpu_count = gpu_param(&task.workload, |p| Some(p.count));
        inject_framework_env(
            &mut task.workload,
            &training.framework,
            &coordinator_addr,
            world_size,
            gpu_count,
        )?;

        inject_nccl_env(&mut task.workload, training.nccl.as_ref());

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

    if let Some(model) = gpu_param(workload, |p| p.model.clone()) {
        env_vars.extend(nccl_defaults_for_gpu(&model));
    }

    if let Some(ref extra) = nccl.extra_env {
        let extra_vars: Vec<(&str, String)> =
            extra.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        env_vars.extend(extra_vars);
    }

    inject_env_all(workload, &env_vars);
}

/// Inject the training master port into the workload's service spec.
///
/// This ensures WorkloadCompiler creates a LatticeMeshMember with port 29500,
/// which in turn generates CiliumNetworkPolicy rules. Without this, the
/// cluster-wide default-deny blocks inter-pod training traffic.
fn inject_training_service_port(workload: &mut WorkloadSpec) {
    let service = workload
        .service
        .get_or_insert_with(ServicePortsSpec::default);
    service
        .ports
        .entry("master".to_string())
        .or_insert(PortSpec {
            port: DEFAULT_MASTER_PORT,
            target_port: None,
            protocol: None,
        });
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

/// Inject per-pod RANK computation into a pod template JSON.
///
/// Volcano's `VC_TASK_INDEX` is per-task-group (0-based within each task),
/// not globally unique across the job. For multi-task jobs (e.g. master x1 +
/// worker x3), both the master and worker-0 get `VC_TASK_INDEX=0`.
///
/// This function computes globally unique RANK = `rank_offset` + `VC_TASK_INDEX`
/// via an init container that writes the result to a shared emptyDir volume.
///
/// Specifically:
/// - Adds an `emptyDir` volume `lattice-env`
/// - Adds an init container `lattice-rank` that computes RANK and writes
///   `export RANK=<N> NODE_RANK=<N>` to `/lattice-env/rank.sh`
/// - Wraps each main container's command to source `rank.sh` before exec
fn inject_rank_env(template: &mut serde_json::Value, rank_offset: u32) {
    let spec = match template.pointer_mut("/spec") {
        Some(s) => s,
        None => return,
    };
    let spec_obj = match spec.as_object_mut() {
        Some(o) => o,
        None => return,
    };

    // Add emptyDir volumes for rank.sh and writable /tmp
    // (root filesystem is read-only; frameworks like PyTorch need a writable /tmp)
    let volumes = spec_obj
        .entry("volumes")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut();
    if let Some(volumes) = volumes {
        volumes.push(serde_json::json!({
            "name": "lattice-env",
            "emptyDir": {}
        }));
        volumes.push(serde_json::json!({
            "name": "lattice-tmp",
            "emptyDir": {}
        }));
    }

    // Add init container that computes RANK from offset + VC_TASK_INDEX.
    // busybox runs as root, so the container-level securityContext must
    // override the pod-level runAsNonRoot: true.
    let init_container = serde_json::json!({
        "name": "lattice-rank",
        "image": RANK_INIT_IMAGE,
        "env": [
            {"name": "LATTICE_RANK_OFFSET", "value": rank_offset.to_string()},
        ],
        "command": ["/bin/sh", "-c",
            "RANK=$((LATTICE_RANK_OFFSET + VC_TASK_INDEX)); echo \"export RANK=$RANK NODE_RANK=$RANK\" > /lattice-env/rank.sh"
        ],
        "volumeMounts": [
            {"name": "lattice-env", "mountPath": "/lattice-env"}
        ],
        "securityContext": {
            "runAsNonRoot": false,
            "runAsUser": 0,
            "readOnlyRootFilesystem": true,
            "allowPrivilegeEscalation": false,
            "capabilities": {"drop": ["ALL"]},
            "seccompProfile": {"type": "RuntimeDefault"}
        }
    });
    let init_containers = spec_obj
        .entry("initContainers")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut();
    if let Some(init_containers) = init_containers {
        init_containers.push(init_container);
    }

    // Wrap each main container's command to source rank.sh first.
    // Original: command: ["/usr/bin/python", "-c", "script"], args: ["--flag"]
    // Wrapped:  command: ["/bin/sh", "-c", ". /lattice-env/rank.sh; exec \"$@\"", "sh"]
    //           args: ["/usr/bin/python", "-c", "script", "--flag"]
    let containers = spec_obj
        .get_mut("containers")
        .and_then(|c| c.as_array_mut());
    if let Some(containers) = containers {
        for container in containers {
            let obj = match container.as_object_mut() {
                Some(o) => o,
                None => continue,
            };

            // Collect original command + args into new args
            let orig_command: Vec<String> = obj
                .get("command")
                .and_then(|c| serde_json::from_value(c.clone()).ok())
                .unwrap_or_default();
            let orig_args: Vec<String> = obj
                .get("args")
                .and_then(|a| serde_json::from_value(a.clone()).ok())
                .unwrap_or_default();

            let mut new_args: Vec<String> = orig_command;
            new_args.extend(orig_args);

            obj.insert(
                "command".to_string(),
                serde_json::json!(["/bin/sh", "-c", ". /lattice-env/rank.sh; exec \"$@\"", "sh"]),
            );
            obj.insert(
                "args".to_string(),
                serde_json::to_value(&new_args).expect("Vec<String> serializes to JSON"),
            );

            // Add volume mounts for lattice-env and writable /tmp
            let volume_mounts = obj
                .entry("volumeMounts")
                .or_insert_with(|| serde_json::json!([]))
                .as_array_mut();
            if let Some(vm) = volume_mounts {
                vm.push(serde_json::json!({
                    "name": "lattice-env",
                    "mountPath": "/lattice-env"
                }));
                vm.push(serde_json::json!({
                    "name": "lattice-tmp",
                    "mountPath": "/tmp"
                }));
            }
        }
    }
}

/// Extract a field from the first GPU resource in the workload.
fn gpu_param<T>(
    workload: &WorkloadSpec,
    f: impl Fn(&lattice_common::crd::GpuParams) -> Option<T>,
) -> Option<T> {
    workload
        .resources
        .values()
        .filter(|r| r.type_.is_gpu())
        .find_map(|r| r.params.as_gpu().and_then(&f))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use lattice_common::crd::{
        ContainerSpec, GpuParams, JobTaskSpec, LatticeJobSpec, NcclConfig, ResourceParams,
        ResourceSpec, ResourceType, RestartPolicy, RuntimeSpec, TrainingConfig, TrainingFramework,
        WorkloadSpec,
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
        make_task_with_command(image, replicas, None)
    }

    fn make_training_task(image: &str, replicas: u32) -> JobTaskSpec {
        make_task_with_command(
            image,
            replicas,
            Some(vec![
                "/usr/bin/python".to_string(),
                "-c".to_string(),
                "train()".to_string(),
            ]),
        )
    }

    fn make_task_with_command(
        image: &str,
        replicas: u32,
        command: Option<Vec<String>>,
    ) -> JobTaskSpec {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: image.to_string(),
                command,
                ..Default::default()
            },
        );
        JobTaskSpec {
            replicas: Some(replicas),
            workload: WorkloadSpec {
                containers,
                ..Default::default()
            },
            runtime: RuntimeSpec::default(),
            restart_policy: Some(RestartPolicy::Never),
            policies: None,
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
        tasks.insert("master".to_string(), make_training_task("train:latest", 1));
        tasks.insert("worker".to_string(), make_training_task("train:latest", 3));

        let training = TrainingConfig {
            framework: TrainingFramework::PyTorch,
            coordinator_task: "master".to_string(),
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
        tasks.insert("master".to_string(), make_training_task("jax:latest", 1));
        tasks.insert("worker".to_string(), make_training_task("jax:latest", 2));

        let training = TrainingConfig {
            framework: TrainingFramework::Jax,
            coordinator_task: "master".to_string(),
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
        tasks.insert("master".to_string(), make_training_task("train:latest", 1));

        let training = TrainingConfig {
            framework: TrainingFramework::PyTorch,
            coordinator_task: "master".to_string(),
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
    fn prepare_training_defaults_restart_policy_to_never() {
        let mut tasks = BTreeMap::new();
        let mut task = make_training_task("train:latest", 1);
        task.restart_policy = None; // unset
        tasks.insert("worker".to_string(), task);

        let training = TrainingConfig {
            framework: TrainingFramework::PyTorch,
            coordinator_task: "master".to_string(),
            nccl: None,
        };

        let prepared = prepare_training_tasks("my-job", &tasks, &training).unwrap();
        assert_eq!(
            prepared["worker"].restart_policy,
            Some(RestartPolicy::Never)
        );
    }

    #[test]
    fn prepare_training_overrides_on_failure_to_never() {
        let mut tasks = BTreeMap::new();
        let mut task = make_training_task("train:latest", 1);
        task.restart_policy = Some(RestartPolicy::OnFailure);
        tasks.insert("worker".to_string(), task);

        let training = TrainingConfig {
            framework: TrainingFramework::PyTorch,
            coordinator_task: "worker".to_string(),
            nccl: None,
        };

        let prepared = prepare_training_tasks("my-job", &tasks, &training).unwrap();
        assert_eq!(
            prepared["worker"].restart_policy,
            Some(RestartPolicy::Never),
            "training compiler must override OnFailure to Never"
        );
    }

    #[test]
    fn prepare_training_injects_coordinator_complete_policy() {
        let mut tasks = BTreeMap::new();
        tasks.insert("master".to_string(), make_training_task("train:latest", 1));
        tasks.insert("worker".to_string(), make_training_task("train:latest", 3));

        let training = TrainingConfig {
            framework: TrainingFramework::PyTorch,
            coordinator_task: "master".to_string(),
            nccl: None,
        };

        let prepared = prepare_training_tasks("my-job", &tasks, &training).unwrap();

        // Coordinator task should get TaskCompleted→CompleteJob
        let master_policies = prepared["master"].policies.as_ref().unwrap();
        assert_eq!(master_policies.len(), 1);
        assert_eq!(
            master_policies[0].event,
            lattice_common::crd::VolcanoPolicyEvent::TaskCompleted
        );
        assert_eq!(
            master_policies[0].action,
            lattice_common::crd::VolcanoPolicyAction::CompleteJob
        );

        // Worker task should have no policies injected
        assert!(prepared["worker"].policies.is_none());
    }

    #[test]
    fn prepare_training_respects_explicit_coordinator_policies() {
        let mut tasks = BTreeMap::new();
        let mut master = make_training_task("train:latest", 1);
        master.policies = Some(vec![lattice_common::crd::VolcanoPolicy {
            event: lattice_common::crd::VolcanoPolicyEvent::TaskCompleted,
            action: lattice_common::crd::VolcanoPolicyAction::TerminateJob,
        }]);
        tasks.insert("master".to_string(), master);
        tasks.insert("worker".to_string(), make_training_task("train:latest", 3));

        let training = TrainingConfig {
            framework: TrainingFramework::PyTorch,
            coordinator_task: "master".to_string(),
            nccl: None,
        };

        let prepared = prepare_training_tasks("my-job", &tasks, &training).unwrap();

        // User's explicit policy should be preserved, not overridden
        let master_policies = prepared["master"].policies.as_ref().unwrap();
        assert_eq!(master_policies.len(), 1);
        assert_eq!(
            master_policies[0].action,
            lattice_common::crd::VolcanoPolicyAction::TerminateJob,
            "user's explicit policy should not be overridden"
        );
    }

    #[tokio::test]
    async fn training_job_creates_mesh_members_with_peer_traffic() {
        let mut tasks = BTreeMap::new();
        tasks.insert("master".to_string(), make_training_task("train:latest", 1));
        tasks.insert("worker".to_string(), make_training_task("train:latest", 2));

        let spec = LatticeJobSpec {
            training: Some(TrainingConfig {
                framework: TrainingFramework::PyTorch,
                coordinator_task: "master".to_string(),
                nccl: None,
            }),
            tasks,
            ..Default::default()
        };
        let mut job = LatticeJob::new("my-train", spec);
        job.metadata.namespace = Some("default".to_string());
        job.metadata.uid = Some("uid-mesh".to_string());

        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_job(&job, &graph, "test-cluster", ProviderType::Docker, &cedar)
            .await
            .unwrap();

        assert!(
            !compiled.mesh_members.is_empty(),
            "training jobs must have mesh members for network policy"
        );
        for mm in &compiled.mesh_members {
            assert!(
                mm.spec.allow_peer_traffic,
                "training mesh member '{}' must have allow_peer_traffic=true",
                mm.metadata.name.as_deref().unwrap_or("?")
            );
        }
    }

    #[tokio::test]
    async fn training_job_opts_out_of_ambient() {
        let mut tasks = BTreeMap::new();
        tasks.insert("master".to_string(), make_training_task("train:latest", 1));
        tasks.insert("worker".to_string(), make_training_task("train:latest", 2));

        let spec = LatticeJobSpec {
            training: Some(TrainingConfig {
                framework: TrainingFramework::PyTorch,
                coordinator_task: "master".to_string(),
                nccl: None,
            }),
            tasks,
            ..Default::default()
        };
        let mut job = LatticeJob::new("my-train", spec);
        job.metadata.namespace = Some("default".to_string());
        job.metadata.uid = Some("uid-ambient".to_string());

        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_job(&job, &graph, "test-cluster", ProviderType::Docker, &cedar)
            .await
            .unwrap();

        assert!(
            compiled.mesh_members.len() >= 2,
            "expected at least 2 mesh members"
        );

        for mm in &compiled.mesh_members {
            assert!(
                !mm.spec.ambient,
                "training mesh members should opt out of ambient"
            );
            assert!(
                mm.spec.allow_peer_traffic,
                "training mesh members should allow peer traffic"
            );

            // Selector should use group-level training-job label, not per-task name
            let selector_labels = mm.spec.target_labels();
            assert_eq!(
                selector_labels.get(LABEL_TRAINING_JOB),
                Some(&"my-train".to_string()),
                "selector should use training-job group label"
            );
        }
    }

    #[tokio::test]
    async fn training_pod_templates_have_mesh_opt_out_labels() {
        let mut tasks = BTreeMap::new();
        tasks.insert("master".to_string(), make_training_task("train:latest", 1));
        tasks.insert("worker".to_string(), make_training_task("train:latest", 2));

        let spec = LatticeJobSpec {
            training: Some(TrainingConfig {
                framework: TrainingFramework::PyTorch,
                coordinator_task: "master".to_string(),
                nccl: None,
            }),
            tasks,
            ..Default::default()
        };
        let mut job = LatticeJob::new("my-train", spec);
        job.metadata.namespace = Some("default".to_string());
        job.metadata.uid = Some("uid-labels".to_string());

        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_job(&job, &graph, "test-cluster", ProviderType::Docker, &cedar)
            .await
            .unwrap();

        let vcjob = match &compiled.workload {
            VolcanoWorkload::Job(v) => v,
            VolcanoWorkload::CronJob(_) => panic!("expected VCJob"),
        };

        for task in &vcjob.spec.tasks {
            let labels = task.template.pointer("/metadata/labels").unwrap();
            assert_eq!(
                labels
                    .get("istio.io/dataplane-mode")
                    .and_then(|v| v.as_str()),
                Some("none"),
                "task {} should have dataplane-mode: none",
                task.name
            );
            assert_eq!(
                labels.get(LABEL_TRAINING_JOB).and_then(|v| v.as_str()),
                Some("my-train"),
                "task {} should have training-job label",
                task.name
            );
        }
    }

    #[tokio::test]
    async fn training_job_enables_svc_plugin() {
        let mut tasks = BTreeMap::new();
        tasks.insert("master".to_string(), make_training_task("train:latest", 1));
        tasks.insert("worker".to_string(), make_training_task("train:latest", 2));

        let spec = LatticeJobSpec {
            training: Some(TrainingConfig {
                framework: TrainingFramework::PyTorch,
                coordinator_task: "master".to_string(),
                nccl: None,
            }),
            tasks,
            ..Default::default()
        };
        let mut job = LatticeJob::new("my-train", spec);
        job.metadata.namespace = Some("default".to_string());
        job.metadata.uid = Some("uid-svc".to_string());

        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_job(&job, &graph, "test-cluster", ProviderType::Docker, &cedar)
            .await
            .unwrap();

        let vcjob = match &compiled.workload {
            VolcanoWorkload::Job(v) => v,
            VolcanoWorkload::CronJob(_) => panic!("expected VCJob"),
        };

        // svc plugin creates headless service + sets hostname/subdomain per pod
        assert!(vcjob.spec.plugins.contains_key("svc"));
        let svc_args = &vcjob.spec.plugins["svc"];
        assert!(
            svc_args
                .iter()
                .any(|a| a.contains("publish-not-ready-addresses")),
            "svc plugin must enable publishNotReadyAddresses for training pods"
        );
    }

    #[tokio::test]
    async fn non_training_job_omits_svc_plugin() {
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
            VolcanoWorkload::CronJob(_) => panic!("expected VCJob"),
        };

        assert!(!vcjob.spec.plugins.contains_key("svc"));
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

    fn add_gpu(mut task: JobTaskSpec, gpu_count: u32) -> JobTaskSpec {
        task.workload.resources.insert(
            "gpu".to_string(),
            ResourceSpec {
                type_: ResourceType::Gpu,
                params: ResourceParams::Gpu(GpuParams {
                    count: gpu_count,
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        task
    }

    #[test]
    fn gpu_param_returns_count_from_gpu_resource() {
        let task = add_gpu(make_task("train:latest", 1), 8);
        assert_eq!(gpu_param(&task.workload, |p| Some(p.count)), Some(8));
    }

    #[test]
    fn gpu_param_returns_none_without_gpu_resource() {
        let task = make_task("train:latest", 1);
        assert_eq!(gpu_param(&task.workload, |p| Some(p.count)), None);
    }

    #[test]
    fn prepare_training_injects_nproc_per_node_for_pytorch() {
        let mut tasks = BTreeMap::new();
        tasks.insert(
            "master".to_string(),
            add_gpu(make_training_task("train:latest", 1), 8),
        );
        tasks.insert(
            "worker".to_string(),
            add_gpu(make_training_task("train:latest", 4), 8),
        );

        let training = TrainingConfig {
            framework: TrainingFramework::PyTorch,
            coordinator_task: "master".to_string(),
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
        tasks.insert(
            "master".to_string(),
            add_gpu(make_training_task("jax:latest", 1), 4),
        );
        tasks.insert(
            "worker".to_string(),
            add_gpu(make_training_task("jax:latest", 3), 4),
        );

        let training = TrainingConfig {
            framework: TrainingFramework::Jax,
            coordinator_task: "master".to_string(),
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
        tasks.insert("master".to_string(), make_training_task("train:latest", 1));
        tasks.insert("worker".to_string(), make_training_task("train:latest", 3));

        let training = TrainingConfig {
            framework: TrainingFramework::PyTorch,
            coordinator_task: "master".to_string(),
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
    fn inject_rank_env_adds_init_container_and_wraps_command() {
        let mut template = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "main",
                    "command": ["/usr/bin/python", "-c", "print('hello')"],
                    "env": []
                }]
            }
        });

        inject_rank_env(&mut template, 0);

        // Init container should be present with correct offset
        let init_containers = template["spec"]["initContainers"].as_array().unwrap();
        assert_eq!(init_containers.len(), 1);
        assert_eq!(init_containers[0]["name"], "lattice-rank");
        assert_eq!(init_containers[0]["image"], RANK_INIT_IMAGE);

        let init_env = init_containers[0]["env"].as_array().unwrap();
        let offset_env = init_env
            .iter()
            .find(|e| e["name"] == "LATTICE_RANK_OFFSET")
            .unwrap();
        assert_eq!(offset_env["value"], "0");

        // Main container command should be wrapped
        let main = &template["spec"]["containers"][0];
        let cmd: Vec<String> = serde_json::from_value(main["command"].clone()).unwrap();
        assert_eq!(
            cmd,
            vec!["/bin/sh", "-c", ". /lattice-env/rank.sh; exec \"$@\"", "sh"]
        );

        // Original command becomes args
        let args: Vec<String> = serde_json::from_value(main["args"].clone()).unwrap();
        assert_eq!(args, vec!["/usr/bin/python", "-c", "print('hello')"]);

        // Volumes should be present
        let volumes = template["spec"]["volumes"].as_array().unwrap();
        assert!(volumes.iter().any(|v| v["name"] == "lattice-env"));
        assert!(volumes.iter().any(|v| v["name"] == "lattice-tmp"));

        // Volume mounts on main container
        let vm = main["volumeMounts"].as_array().unwrap();
        assert!(vm.iter().any(|v| v["name"] == "lattice-env"));
        assert!(vm
            .iter()
            .any(|v| v["name"] == "lattice-tmp" && v["mountPath"] == "/tmp"));
    }

    #[test]
    fn inject_rank_env_with_nonzero_offset() {
        let mut template = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "main",
                    "command": ["/usr/bin/torchrun"],
                    "env": []
                }]
            }
        });

        inject_rank_env(&mut template, 3);

        let init_containers = template["spec"]["initContainers"].as_array().unwrap();
        let init_env = init_containers[0]["env"].as_array().unwrap();
        let offset_env = init_env
            .iter()
            .find(|e| e["name"] == "LATTICE_RANK_OFFSET")
            .unwrap();
        assert_eq!(offset_env["value"], "3");
    }

    #[test]
    fn inject_rank_env_preserves_command_and_args() {
        let mut template = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "main",
                    "command": ["/usr/bin/python", "-c", "script"],
                    "args": ["--lr", "0.001", "--epochs", "10"]
                }]
            }
        });

        inject_rank_env(&mut template, 0);

        let main = &template["spec"]["containers"][0];
        let args: Vec<String> = serde_json::from_value(main["args"].clone()).unwrap();
        // Original command elements followed by original args elements
        assert_eq!(
            args,
            vec![
                "/usr/bin/python",
                "-c",
                "script",
                "--lr",
                "0.001",
                "--epochs",
                "10"
            ]
        );
    }

    #[test]
    fn training_container_no_command_returns_error() {
        let mut tasks = BTreeMap::new();
        // Container without command
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "train:latest".to_string(),
                ..Default::default()
            },
        );
        tasks.insert(
            "worker".to_string(),
            JobTaskSpec {
                replicas: Some(1),
                workload: WorkloadSpec {
                    containers,
                    ..Default::default()
                },
                runtime: RuntimeSpec::default(),
                restart_policy: Some(RestartPolicy::Never),
                policies: None,
            },
        );

        let training = TrainingConfig {
            framework: TrainingFramework::PyTorch,
            coordinator_task: "master".to_string(),
            nccl: None,
        };

        let result = prepare_training_tasks("my-job", &tasks, &training);
        assert!(matches!(
            result,
            Err(JobError::TrainingContainerNoCommand { .. })
        ));
    }
}
