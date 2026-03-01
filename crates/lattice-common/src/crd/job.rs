//! LatticeJob CRD types
//!
//! Defines `LatticeJob` — batch workloads backed by Volcano VCJob or VCCronJob.
//! Each job contains named tasks, each with its own `WorkloadSpec` and pod template.
//!
//! When `spec.schedule` is set, the controller compiles a VCCronJob (recurring)
//! instead of a bare VCJob (one-shot).
//!
//! When `spec.training` is set, the compiler injects framework-specific env vars
//! (MASTER_ADDR, WORLD_SIZE, NCCL), creates a headless Service for pod DNS, and
//! optionally creates checkpoint PVCs for fault tolerance.

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::workload::spec::{RuntimeSpec, WorkloadSpec};
use super::workload::topology::WorkloadNetworkTopology;

// =============================================================================
// Phase
// =============================================================================

/// Lifecycle phase of a LatticeJob
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[non_exhaustive]
pub enum JobPhase {
    /// Job is waiting to be scheduled
    #[default]
    Pending,
    /// Job is actively running
    Running,
    /// Job completed successfully
    Succeeded,
    /// Job has encountered an error
    Failed,
}

impl std::fmt::Display for JobPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Running => write!(f, "Running"),
            Self::Succeeded => write!(f, "Succeeded"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

// =============================================================================
// RestartPolicy
// =============================================================================

/// Pod restart policy for job tasks
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[non_exhaustive]
pub enum RestartPolicy {
    /// Never restart on failure
    #[default]
    Never,
    /// Restart on failure
    OnFailure,
    /// Always restart
    Always,
}

impl std::fmt::Display for RestartPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Never => write!(f, "Never"),
            Self::OnFailure => write!(f, "OnFailure"),
            Self::Always => write!(f, "Always"),
        }
    }
}

// =============================================================================
// ConcurrencyPolicy
// =============================================================================

/// Concurrency policy for cron jobs
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[non_exhaustive]
pub enum ConcurrencyPolicy {
    /// Allow concurrent job runs
    #[default]
    Allow,
    /// Skip new run if previous is still active
    Forbid,
    /// Replace the currently running job with a new one
    Replace,
}

impl std::fmt::Display for ConcurrencyPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "Allow"),
            Self::Forbid => write!(f, "Forbid"),
            Self::Replace => write!(f, "Replace"),
        }
    }
}

// =============================================================================
// Task Spec
// =============================================================================

/// A single task within a LatticeJob.
///
/// Each task maps to a Volcano VCJob task with its own pod template,
/// replica count, and restart policy.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JobTaskSpec {
    /// Number of replicas for this task
    #[serde(default = "default_one")]
    pub replicas: u32,

    /// Shared workload spec (containers, volumes, env, etc.)
    pub workload: WorkloadSpec,

    /// Lattice runtime extensions (sidecars, sysctls, hostNetwork, etc.)
    #[serde(default, flatten)]
    pub runtime: RuntimeSpec,

    /// Pod restart policy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_policy: Option<RestartPolicy>,
}

fn default_one() -> u32 {
    1
}

fn default_scheduler() -> String {
    "volcano".to_string()
}

// =============================================================================
// CRD
// =============================================================================

/// Batch workload specification backed by Volcano VCJob or VCCronJob
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "LatticeJob",
    plural = "latticejobs",
    shortname = "lj",
    namespaced,
    status = "LatticeJobStatus",
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Schedule","type":"string","jsonPath":".spec.schedule","priority":1}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LatticeJobSpec {
    /// Volcano scheduler name
    #[serde(default = "default_scheduler")]
    pub scheduler_name: String,

    /// Minimum available pods to consider the job running
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_available: Option<u32>,

    /// Max retry count
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_retry: Option<u32>,

    /// Volcano queue name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,

    /// Priority class name for Volcano fair-share scheduling
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority_class_name: Option<String>,

    /// Cron schedule expression (e.g. "*/5 * * * *"). When set, compiles to a
    /// Volcano VCCronJob instead of a VCJob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,

    /// How to handle concurrent job executions (only relevant for cron jobs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency_policy: Option<ConcurrencyPolicy>,

    /// Suspend future executions of this cron job
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspend: Option<bool>,

    /// Number of successful finished jobs to retain (default 3)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successful_jobs_history_limit: Option<u32>,

    /// Number of failed finished jobs to retain (default 1)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_jobs_history_limit: Option<u32>,

    /// Deadline in seconds for starting the job if it misses its scheduled time
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starting_deadline_seconds: Option<i64>,

    /// Network topology configuration for topology-aware scheduling.
    /// When set, the VCJob includes networkTopology for Volcano co-placement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topology: Option<WorkloadNetworkTopology>,

    /// Job tasks — each maps to a Volcano VCJob task with its own pod template
    #[serde(default)]
    pub tasks: BTreeMap<String, JobTaskSpec>,

    /// Distributed training configuration. When set, the compiler injects
    /// framework-specific env vars, NCCL tuning, headless Service for pod DNS,
    /// and checkpoint PVCs for fault tolerance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub training: Option<TrainingConfig>,
}

impl Default for LatticeJobSpec {
    fn default() -> Self {
        Self {
            scheduler_name: default_scheduler(),
            min_available: None,
            max_retry: None,
            queue: None,
            priority_class_name: None,
            schedule: None,
            concurrency_policy: None,
            suspend: None,
            successful_jobs_history_limit: None,
            failed_jobs_history_limit: None,
            starting_deadline_seconds: None,
            topology: None,
            tasks: BTreeMap::new(),
            training: None,
        }
    }
}

impl LatticeJobSpec {
    /// Returns `true` when this job should compile to a VCCronJob (has a schedule).
    pub fn is_cron(&self) -> bool {
        self.schedule.is_some()
    }
}

/// Status of a LatticeJob
///
/// All optional fields serialize as `null` (no `skip_serializing_if`) so that
/// merge-patch status updates correctly clear stale values.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatticeJobStatus {
    /// Current phase of the job lifecycle
    #[serde(default)]
    pub phase: JobPhase,

    /// Human-readable message about current state
    #[serde(default)]
    pub message: Option<String>,

    /// Generation of the spec that was last reconciled
    #[serde(default)]
    pub observed_generation: Option<i64>,

    /// Timestamp when the job started (training jobs only)
    #[serde(default)]
    pub start_time: Option<String>,

    /// Timestamp when the job completed (training jobs only)
    #[serde(default)]
    pub completion_time: Option<String>,
}

// =============================================================================
// Training
// =============================================================================

/// Supported distributed training frameworks
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[non_exhaustive]
pub enum TrainingFramework {
    /// PyTorch Distributed Data Parallel (torchrun / torch.distributed.launch)
    #[default]
    PyTorch,
    /// DeepSpeed (deepspeed launcher)
    DeepSpeed,
    /// JAX distributed (jax.distributed)
    Jax,
}

impl std::fmt::Display for TrainingFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PyTorch => write!(f, "PyTorch"),
            Self::DeepSpeed => write!(f, "DeepSpeed"),
            Self::Jax => write!(f, "Jax"),
        }
    }
}

/// Distributed training configuration for a LatticeJob.
///
/// When set on a LatticeJob, the compiler injects framework-specific env vars
/// (MASTER_ADDR, WORLD_SIZE, NCCL tuning), creates a headless Service for pod
/// DNS resolution, and optionally creates checkpoint PVCs.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TrainingConfig {
    /// Training framework. Determines env vars and rendezvous method.
    #[serde(default)]
    pub framework: TrainingFramework,

    /// Name of the coordinator (rank-0) task. Must match a key in `tasks`.
    /// Defaults to "master".
    #[serde(default = "TrainingConfig::default_coordinator_task")]
    pub coordinator_task: String,

    /// Checkpoint configuration. When set, a PVC is mounted on all tasks.
    /// PVCs persist across Volcano gang restarts so checkpoint data survives
    /// pod failures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<CheckpointSpec>,

    /// NCCL tuning overrides. Auto-configured by default based on GPU model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nccl: Option<NcclConfig>,
}

impl TrainingConfig {
    fn default_coordinator_task() -> String {
        "master".to_string()
    }
}

/// Checkpoint volume configuration for training fault tolerance.
///
/// The compiler creates a PVC mounted at `local_path` (default: `/checkpoints`)
/// on all training tasks with `CHECKPOINT_DIR` env var. PVCs persist across
/// Volcano gang restarts so checkpoint data survives pod failures.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointSpec {
    /// Local path inside containers where checkpoints are written (default: "/checkpoints")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_path: Option<String>,

    /// PVC size for checkpoint storage (default: "50Gi")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_size: Option<String>,

    /// Storage class for the checkpoint PVC
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
}

impl CheckpointSpec {
    /// Returns the local mount path, defaulting to "/checkpoints".
    pub fn effective_local_path(&self) -> &str {
        self.local_path.as_deref().unwrap_or("/checkpoints")
    }

    /// Returns the PVC size, defaulting to "50Gi".
    pub fn effective_volume_size(&self) -> &str {
        self.volume_size.as_deref().unwrap_or("50Gi")
    }
}

/// NCCL tuning overrides. Auto-configured by default based on GPU model.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NcclConfig {
    /// Network interface for NCCL traffic. Auto-detected if omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net_if: Option<String>,

    /// IB/RDMA HCA device. Auto-detected from NFD labels if omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ib_hca: Option<String>,

    /// Enable GDR (GPU Direct RDMA). Default: true if InfiniBand detected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gdr: Option<bool>,

    /// NCCL debug level (default: "WARN")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debug: Option<String>,

    /// Additional NCCL env vars (NCCL_ALGO, NCCL_PROTO, etc.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_env: Option<BTreeMap<String, String>>,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_spec_default_has_empty_tasks() {
        let spec = LatticeJobSpec::default();
        assert!(spec.tasks.is_empty());
        assert_eq!(spec.scheduler_name, "volcano");
    }

    #[test]
    fn job_task_spec_composes_with_workload() {
        let task = JobTaskSpec {
            replicas: 2,
            workload: WorkloadSpec::default(),
            runtime: RuntimeSpec::default(),
            restart_policy: Some(RestartPolicy::OnFailure),
        };
        assert!(task.workload.containers.is_empty());
        assert_eq!(task.replicas, 2);
    }

    #[test]
    fn job_with_multiple_tasks() {
        let mut tasks = BTreeMap::new();
        tasks.insert(
            "master".to_string(),
            JobTaskSpec {
                replicas: 1,
                workload: WorkloadSpec::default(),
                runtime: RuntimeSpec::default(),
                restart_policy: None,
            },
        );
        tasks.insert(
            "worker".to_string(),
            JobTaskSpec {
                replicas: 4,
                workload: WorkloadSpec::default(),
                runtime: RuntimeSpec::default(),
                restart_policy: Some(RestartPolicy::OnFailure),
            },
        );

        let spec = LatticeJobSpec {
            tasks,
            ..Default::default()
        };

        assert_eq!(spec.tasks.len(), 2);
        assert_eq!(spec.tasks["master"].replicas, 1);
        assert_eq!(spec.tasks["worker"].replicas, 4);
    }

    #[test]
    fn job_phase_display() {
        assert_eq!(JobPhase::Pending.to_string(), "Pending");
        assert_eq!(JobPhase::Running.to_string(), "Running");
        assert_eq!(JobPhase::Succeeded.to_string(), "Succeeded");
        assert_eq!(JobPhase::Failed.to_string(), "Failed");
    }

    #[test]
    fn restart_policy_display() {
        assert_eq!(RestartPolicy::Never.to_string(), "Never");
        assert_eq!(RestartPolicy::OnFailure.to_string(), "OnFailure");
        assert_eq!(RestartPolicy::Always.to_string(), "Always");
    }

    #[test]
    fn concurrency_policy_display() {
        assert_eq!(ConcurrencyPolicy::Allow.to_string(), "Allow");
        assert_eq!(ConcurrencyPolicy::Forbid.to_string(), "Forbid");
        assert_eq!(ConcurrencyPolicy::Replace.to_string(), "Replace");
    }

    #[test]
    fn is_cron_returns_true_when_schedule_set() {
        let spec = LatticeJobSpec {
            schedule: Some("*/5 * * * *".to_string()),
            ..Default::default()
        };
        assert!(spec.is_cron());
    }

    #[test]
    fn is_cron_returns_false_when_no_schedule() {
        let spec = LatticeJobSpec::default();
        assert!(!spec.is_cron());
    }

    #[test]
    fn cron_fields_serde_roundtrip() {
        let spec = LatticeJobSpec {
            schedule: Some("0 */6 * * *".to_string()),
            concurrency_policy: Some(ConcurrencyPolicy::Forbid),
            suspend: Some(false),
            successful_jobs_history_limit: Some(5),
            failed_jobs_history_limit: Some(2),
            starting_deadline_seconds: Some(300),
            ..Default::default()
        };

        let json = serde_json::to_string(&spec).unwrap();
        let de: LatticeJobSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, de);

        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["schedule"], "0 */6 * * *");
        assert_eq!(value["concurrencyPolicy"], "Forbid");
        assert_eq!(value["suspend"], false);
        assert_eq!(value["successfulJobsHistoryLimit"], 5);
        assert_eq!(value["failedJobsHistoryLimit"], 2);
        assert_eq!(value["startingDeadlineSeconds"], 300);
    }

    #[test]
    fn framework_display() {
        assert_eq!(TrainingFramework::PyTorch.to_string(), "PyTorch");
        assert_eq!(TrainingFramework::DeepSpeed.to_string(), "DeepSpeed");
        assert_eq!(TrainingFramework::Jax.to_string(), "Jax");
    }

    #[test]
    fn checkpoint_spec_defaults() {
        let ckpt = CheckpointSpec {
            local_path: None,
            volume_size: None,
            storage_class: None,
        };
        assert_eq!(ckpt.effective_local_path(), "/checkpoints");
        assert_eq!(ckpt.effective_volume_size(), "50Gi");
    }

    #[test]
    fn checkpoint_spec_overrides() {
        let ckpt = CheckpointSpec {
            local_path: Some("/data/checkpoints".to_string()),
            volume_size: Some("100Gi".to_string()),
            storage_class: Some("ssd".to_string()),
        };
        assert_eq!(ckpt.effective_local_path(), "/data/checkpoints");
        assert_eq!(ckpt.effective_volume_size(), "100Gi");
    }

    #[test]
    fn nccl_config_defaults() {
        let nccl = NcclConfig::default();
        assert!(nccl.net_if.is_none());
        assert!(nccl.ib_hca.is_none());
        assert!(nccl.gdr.is_none());
        assert!(nccl.debug.is_none());
        assert!(nccl.extra_env.is_none());
    }

    #[test]
    fn training_config_serde_roundtrip() {
        let training = TrainingConfig {
            framework: TrainingFramework::DeepSpeed,
            coordinator_task: "master".to_string(),
            checkpoint: Some(CheckpointSpec {
                local_path: None,
                volume_size: None,
                storage_class: None,
            }),
            nccl: Some(NcclConfig {
                debug: Some("INFO".to_string()),
                ..Default::default()
            }),
        };

        let json = serde_json::to_string(&training).unwrap();
        let de: TrainingConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(training, de);
    }

    #[test]
    fn job_spec_with_training() {
        let mut tasks = BTreeMap::new();
        tasks.insert(
            "master".to_string(),
            JobTaskSpec {
                replicas: 1,
                workload: WorkloadSpec::default(),
                runtime: RuntimeSpec::default(),
                restart_policy: None,
            },
        );

        let spec = LatticeJobSpec {
            tasks,
            training: Some(TrainingConfig {
                framework: TrainingFramework::PyTorch,
                coordinator_task: "master".to_string(),
                checkpoint: None,
                nccl: None,
            }),
            ..Default::default()
        };

        assert!(spec.training.is_some());
        assert_eq!(
            spec.training.as_ref().unwrap().framework,
            TrainingFramework::PyTorch
        );
    }

    #[test]
    fn job_status_training_fields() {
        let status = LatticeJobStatus {
            phase: JobPhase::Running,
            message: Some("Running".to_string()),
            observed_generation: Some(1),
            start_time: Some("2026-02-28T00:00:00Z".to_string()),
            completion_time: None,
        };
        assert_eq!(status.phase, JobPhase::Running);
        assert!(status.start_time.is_some());
    }
}
