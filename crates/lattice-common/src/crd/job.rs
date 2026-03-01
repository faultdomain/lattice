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
//! optionally configures Velero-based checkpoint snapshots for fault tolerance.

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
    /// and Velero-based checkpoint snapshots for fault tolerance.
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
/// DNS resolution, and optionally sets up Velero-based checkpoint snapshots.
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

    /// Checkpoint configuration. When set, a PVC is mounted on all tasks and
    /// a Velero Schedule periodically snapshots it. On failure the controller
    /// performs stop-the-world recovery: tear down → Velero Restore → restart.
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

/// Velero-backed checkpoint configuration for training fault tolerance.
///
/// The controller creates a PVC mounted at `local_path` (default: `/checkpoints`)
/// on all training tasks. User code writes checkpoints to this path. A Velero
/// Schedule periodically snapshots the PVC. On failure, the controller tears
/// down the job, creates a Velero Restore from the latest snapshot, waits for
/// completion, and restarts the job.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointSpec {
    /// Cron expression for Velero snapshot frequency (e.g., "*/30 * * * *" for every 30m)
    pub interval: String,

    /// Local path inside containers where checkpoints are written (default: "/checkpoints")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_path: Option<String>,

    /// PVC size for checkpoint storage (default: "50Gi")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_size: Option<String>,

    /// Storage class for the checkpoint PVC
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,

    /// Velero BackupStorageLocation name. If omitted, uses Velero's default BSL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_store: Option<String>,
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

    /// Compute Velero backup TTL to retain exactly 2 snapshots.
    ///
    /// Parses the cron `interval` to estimate the period between snapshots,
    /// then returns `3 × period` as a Velero duration string. This ensures
    /// 2 snapshots are always live (the 3rd fires just as the 1st expires,
    /// with a full period of buffer).
    ///
    /// Panics at compile-time validation if the cron expression is
    /// completely unparseable (invalid field count).
    pub fn effective_ttl(&self) -> String {
        let minutes = Self::parse_cron_period_minutes(&self.interval);
        let ttl_minutes = minutes * 3;
        if ttl_minutes >= 60 && ttl_minutes % 60 == 0 {
            format!("{}h", ttl_minutes / 60)
        } else {
            format!("{}m", ttl_minutes)
        }
    }

    /// Parse a standard 5-field cron expression and return the period in minutes.
    ///
    /// Determines the dominant frequency from the most-specific varying field:
    ///
    /// | minute    | hour   | dom | dow | Result                    |
    /// |-----------|--------|-----|-----|---------------------------|
    /// | `*/N`     | `*`    | `*` | `*` | every N minutes           |
    /// | fixed/`*` | `*/N`  | `*` | `*` | every N hours             |
    /// | fixed     | `*`    | `*` | `*` | every hour (60 min)       |
    /// | fixed     | fixed  | `*` | `*` | daily (1440 min)          |
    /// | fixed     | fixed  | `*` | set | weekly (10080 min)        |
    /// | fixed     | fixed  | set | `*` | monthly (43200 min)       |
    fn parse_cron_period_minutes(cron: &str) -> u64 {
        let fields: Vec<&str> = cron.split_whitespace().collect();
        assert!(
            fields.len() == 5,
            "checkpoint interval must be a 5-field cron expression, got: '{cron}'"
        );
        let (minute, hour, dom, _month, dow) =
            (fields[0], fields[1], fields[2], fields[3], fields[4]);

        // Minute step: `*/N ...` with wildcard hour → every N minutes
        if let Some(step) = minute.strip_prefix("*/") {
            if hour == "*" {
                return step.parse().expect("invalid minute step in cron interval");
            }
        }

        // Hour step: `M */N * * *` → every N hours
        if let Some(step) = hour.strip_prefix("*/") {
            return step
                .parse::<u64>()
                .expect("invalid hour step in cron interval")
                * 60;
        }

        // Fixed minute with wildcard hour: `30 * * * *` → hourly
        if hour == "*" {
            return 60;
        }

        // Both minute and hour are fixed — check day fields
        // Specific day-of-month: `0 2 15 * *` → monthly (~30 days)
        if dom != "*" {
            return 43200;
        }

        // Specific day-of-week: `0 9 * * MON-FRI` → weekly
        if dow != "*" {
            return 10080;
        }

        // All day fields wildcard: `0 2 * * *` → daily
        1440
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
            interval: "*/30 * * * *".to_string(),
            local_path: None,
            volume_size: None,
            storage_class: None,
            backup_store: None,
        };
        assert_eq!(ckpt.effective_local_path(), "/checkpoints");
        assert_eq!(ckpt.effective_volume_size(), "50Gi");
        // 30min × 3 = 90min
        assert_eq!(ckpt.effective_ttl(), "90m");
    }

    #[test]
    fn checkpoint_spec_ttl_scales_with_interval() {
        // Every-minute: 1min × 3 = 3min
        let ckpt = CheckpointSpec {
            interval: "*/1 * * * *".to_string(),
            local_path: None,
            volume_size: None,
            storage_class: None,
            backup_store: None,
        };
        assert_eq!(ckpt.effective_ttl(), "3m");

        // Every-30-min: 30min × 3 = 90min
        let ckpt = CheckpointSpec {
            interval: "*/30 * * * *".to_string(),
            local_path: None,
            volume_size: None,
            storage_class: None,
            backup_store: None,
        };
        assert_eq!(ckpt.effective_ttl(), "90m");

        // Hourly: 60min × 3 = 3h
        let ckpt = CheckpointSpec {
            interval: "0 */1 * * *".to_string(),
            local_path: None,
            volume_size: None,
            storage_class: None,
            backup_store: None,
        };
        assert_eq!(ckpt.effective_ttl(), "3h");

        // Every-2-hours: 120min × 3 = 6h
        let ckpt = CheckpointSpec {
            interval: "0 */2 * * *".to_string(),
            local_path: None,
            volume_size: None,
            storage_class: None,
            backup_store: None,
        };
        assert_eq!(ckpt.effective_ttl(), "6h");

        // Daily at midnight: 1440min × 3 = 72h
        let ckpt = CheckpointSpec {
            interval: "0 0 * * *".to_string(),
            local_path: None,
            volume_size: None,
            storage_class: None,
            backup_store: None,
        };
        assert_eq!(ckpt.effective_ttl(), "72h");

        // Daily at 2am: 1440min × 3 = 72h
        let ckpt = CheckpointSpec {
            interval: "0 2 * * *".to_string(),
            local_path: None,
            volume_size: None,
            storage_class: None,
            backup_store: None,
        };
        assert_eq!(ckpt.effective_ttl(), "72h");

        // Weekly (Sunday at midnight): 10080min × 3 = 504h
        let ckpt = CheckpointSpec {
            interval: "0 0 * * 0".to_string(),
            local_path: None,
            volume_size: None,
            storage_class: None,
            backup_store: None,
        };
        assert_eq!(ckpt.effective_ttl(), "504h");

        // Weekdays at 9am: weekly period → 504h
        let ckpt = CheckpointSpec {
            interval: "0 9 * * MON-FRI".to_string(),
            local_path: None,
            volume_size: None,
            storage_class: None,
            backup_store: None,
        };
        assert_eq!(ckpt.effective_ttl(), "504h");

        // Monthly (1st at midnight): 43200min × 3 = 2160h
        let ckpt = CheckpointSpec {
            interval: "0 0 1 * *".to_string(),
            local_path: None,
            volume_size: None,
            storage_class: None,
            backup_store: None,
        };
        assert_eq!(ckpt.effective_ttl(), "2160h");
    }

    #[test]
    #[should_panic(expected = "must be a 5-field cron expression")]
    fn checkpoint_spec_ttl_panics_on_invalid_cron() {
        let ckpt = CheckpointSpec {
            interval: "garbage".to_string(),
            local_path: None,
            volume_size: None,
            storage_class: None,
            backup_store: None,
        };
        ckpt.effective_ttl();
    }

    #[test]
    fn checkpoint_spec_ttl_hourly_fixed_minute() {
        // `30 * * * *` → every hour at :30
        let ckpt = CheckpointSpec {
            interval: "30 * * * *".to_string(),
            local_path: None,
            volume_size: None,
            storage_class: None,
            backup_store: None,
        };
        assert_eq!(ckpt.effective_ttl(), "3h");
    }

    #[test]
    fn checkpoint_spec_overrides() {
        let ckpt = CheckpointSpec {
            interval: "0 */1 * * *".to_string(),
            local_path: Some("/data/checkpoints".to_string()),
            volume_size: Some("100Gi".to_string()),
            storage_class: Some("ssd".to_string()),
            backup_store: Some("my-bsl".to_string()),
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
                interval: "*/30 * * * *".to_string(),
                local_path: None,
                volume_size: None,
                storage_class: None,
                backup_store: None,
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
