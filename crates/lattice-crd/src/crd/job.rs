//! LatticeJob CRD types
//!
//! Defines `LatticeJob` — batch workloads backed by Volcano VCJob or VCCronJob.
//! Each job contains named tasks, each with its own `WorkloadSpec` and pod template.
//!
//! When `spec.schedule` is set, the controller compiles a VCCronJob (recurring)
//! instead of a bare VCJob (one-shot).
//!
//! When `spec.training` is set, the compiler injects framework-specific env vars
//! (MASTER_ADDR, WORLD_SIZE, NCCL) and creates a headless Service for pod DNS.

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::observability::{MetricsSnapshot, ObservabilitySpec};
use super::workload::cost::CostEstimate;
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
// Volcano Policy Types
// =============================================================================

/// Volcano lifecycle policy event trigger
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[non_exhaustive]
pub enum VolcanoPolicyEvent {
    /// A pod in the job failed
    PodFailed,
    /// A pod in the job was evicted
    PodEvicted,
    /// A pod is stuck in Pending
    PodPending,
    /// A task completed (all replicas finished)
    TaskCompleted,
    /// Unknown event
    Unknown,
    /// Matches any event
    Any,
}

impl std::fmt::Display for VolcanoPolicyEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PodFailed => write!(f, "PodFailed"),
            Self::PodEvicted => write!(f, "PodEvicted"),
            Self::PodPending => write!(f, "PodPending"),
            Self::TaskCompleted => write!(f, "TaskCompleted"),
            Self::Unknown => write!(f, "Unknown"),
            Self::Any => write!(f, "*"),
        }
    }
}

/// Volcano lifecycle policy action
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[non_exhaustive]
pub enum VolcanoPolicyAction {
    /// Abort the entire job
    AbortJob,
    /// Restart the entire job (all tasks)
    RestartJob,
    /// Restart the failed task only
    RestartTask,
    /// Restart the failed pod only
    RestartPod,
    /// Terminate the job (mark as terminated)
    TerminateJob,
    /// Complete the job (mark as completed)
    CompleteJob,
}

impl std::fmt::Display for VolcanoPolicyAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AbortJob => write!(f, "AbortJob"),
            Self::RestartJob => write!(f, "RestartJob"),
            Self::RestartTask => write!(f, "RestartTask"),
            Self::RestartPod => write!(f, "RestartPod"),
            Self::TerminateJob => write!(f, "TerminateJob"),
            Self::CompleteJob => write!(f, "CompleteJob"),
        }
    }
}

/// A Volcano lifecycle policy binding an event to an action
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VolcanoPolicy {
    /// Event that triggers this policy
    pub event: VolcanoPolicyEvent,
    /// Action to take when the event occurs
    pub action: VolcanoPolicyAction,
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
    /// Number of replicas for this task (defaults to 1 when omitted)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<u32>,

    /// Shared workload spec (containers, volumes, env, etc.)
    #[serde(default)]
    pub workload: WorkloadSpec,

    /// Lattice runtime extensions (sidecars, sysctls, hostNetwork, etc.)
    #[serde(default, flatten)]
    pub runtime: RuntimeSpec,

    /// Pod restart policy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_policy: Option<RestartPolicy>,

    /// Volcano lifecycle policies for this task.
    /// When set, these are applied to the VCJobTask directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<VolcanoPolicy>>,
}

impl JobTaskSpec {
    /// Resolved replica count (defaults to 1 when unset).
    pub fn replicas(&self) -> u32 {
        self.replicas.unwrap_or(1)
    }
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

    /// Volcano lifecycle policies for the entire job.
    /// When set, overrides the default policies (PodEvicted→RestartJob,
    /// PodFailed→RestartJob). When absent, defaults are applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<VolcanoPolicy>>,

    /// Default values inherited by all tasks via strategic merge patch.
    /// Task-level fields override defaults. Applied at compile time only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defaults: Option<JobTaskSpec>,

    /// Job tasks — each maps to a Volcano VCJob task with its own pod template
    #[serde(default)]
    pub tasks: BTreeMap<String, JobTaskSpec>,

    /// Distributed training configuration. When set, the compiler injects
    /// framework-specific env vars, NCCL tuning, headless Service for pod DNS,
    /// and headless Service for pod DNS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub training: Option<TrainingConfig>,

    /// Observability configuration (metrics mappings, port overrides).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observability: Option<ObservabilitySpec>,
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
            policies: None,
            defaults: None,
            tasks: BTreeMap::new(),
            training: None,
            observability: None,
        }
    }
}

impl LatticeJobSpec {
    /// Returns `true` when this job should compile to a VCCronJob (has a schedule).
    pub fn is_cron(&self) -> bool {
        self.schedule.is_some()
    }

    /// Returns tasks with defaults merged in. Used by both validation and compilation.
    pub fn merged_tasks(&self) -> BTreeMap<String, JobTaskSpec> {
        use super::workload::merge::Merge;
        let mut tasks = self.tasks.clone();
        if let Some(ref defaults) = self.defaults {
            for task in tasks.values_mut() {
                task.merge_from(defaults);
            }
        }
        tasks
    }

    /// Validate the job specification at admission time.
    ///
    /// Runs validation on the **merged** result (defaults applied to each task)
    /// so that tasks relying on defaults for containers/commands are valid.
    ///
    /// Catches structural errors early (before compilation):
    /// - Empty tasks
    /// - Missing coordinator task
    /// - Training containers without explicit command
    /// - Training tasks with restart_policy != Never
    pub fn validate(&self) -> Result<(), crate::ValidationError> {
        if self.tasks.is_empty() {
            return Err(crate::ValidationError::new("job has no tasks"));
        }

        let tasks = self.merged_tasks();

        if let Some(ref training) = self.training {
            if !tasks.contains_key(&training.coordinator_task) {
                return Err(crate::ValidationError::new(format!(
                    "training coordinator task '{}' not found in job tasks",
                    training.coordinator_task
                )));
            }

            // Training containers must declare explicit commands so the rank
            // init container can wrap them with `. /lattice-env/rank.sh; exec "$@"`
            for (task_name, task_spec) in &tasks {
                for (container_name, container) in &task_spec.workload.containers {
                    if container.command.is_none() {
                        return Err(crate::ValidationError::new(format!(
                            "training task '{}' container '{}' must specify a command",
                            task_name, container_name
                        )));
                    }
                }
            }

            // Training tasks must use restart_policy=Never so that kubelet
            // doesn't locally restart containers, which would prevent Volcano's
            // PodFailed→RestartJob gang restart from triggering.
            for (task_name, task_spec) in &tasks {
                if let Some(ref policy) = task_spec.restart_policy {
                    if *policy != RestartPolicy::Never {
                        return Err(crate::ValidationError::new(format!(
                            "training task '{}' has restart_policy '{}', \
                             but training jobs require 'Never' so Volcano \
                             can manage gang restarts",
                            task_name, policy
                        )));
                    }
                }
            }
        }

        // Validate each task's workload containers
        for (task_name, task_spec) in &tasks {
            for (container_name, container) in &task_spec.workload.containers {
                container.validate(container_name).map_err(|e| {
                    crate::ValidationError::new(format!("task '{}': {}", task_name, e))
                })?;
            }
            task_spec.runtime.validate()?;
        }

        Ok(())
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

    /// Estimated cost based on resource requests and current rates
    #[serde(default)]
    pub cost: Option<CostEstimate>,

    /// Scraped metrics snapshot from VictoriaMetrics
    #[serde(default)]
    pub metrics: Option<MetricsSnapshot>,
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
/// (MASTER_ADDR, WORLD_SIZE, NCCL tuning) and creates a headless Service for
/// pod DNS resolution.
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

    /// NCCL tuning overrides. Auto-configured by default based on GPU model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nccl: Option<NcclConfig>,
}

impl TrainingConfig {
    fn default_coordinator_task() -> String {
        "master".to_string()
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
    use crate::crd::{ContainerSpec, ResourceQuantity, ResourceRequirements};

    #[test]
    fn job_spec_default_has_empty_tasks() {
        let spec = LatticeJobSpec::default();
        assert!(spec.tasks.is_empty());
        assert_eq!(spec.scheduler_name, "volcano");
    }

    #[test]
    fn job_task_spec_composes_with_workload() {
        let task = JobTaskSpec {
            replicas: Some(2),
            workload: WorkloadSpec::default(),
            runtime: RuntimeSpec::default(),
            restart_policy: Some(RestartPolicy::OnFailure),
            policies: None,
        };
        assert!(task.workload.containers.is_empty());
        assert_eq!(task.replicas, Some(2));
    }

    #[test]
    fn job_with_multiple_tasks() {
        let mut tasks = BTreeMap::new();
        tasks.insert(
            "master".to_string(),
            JobTaskSpec {
                replicas: Some(1),
                workload: WorkloadSpec::default(),
                runtime: RuntimeSpec::default(),
                restart_policy: None,
                policies: None,
            },
        );
        tasks.insert(
            "worker".to_string(),
            JobTaskSpec {
                replicas: Some(4),
                workload: WorkloadSpec::default(),
                runtime: RuntimeSpec::default(),
                restart_policy: Some(RestartPolicy::OnFailure),
                policies: None,
            },
        );

        let spec = LatticeJobSpec {
            tasks,
            ..Default::default()
        };

        assert_eq!(spec.tasks.len(), 2);
        assert_eq!(spec.tasks["master"].replicas, Some(1));
        assert_eq!(spec.tasks["worker"].replicas, Some(4));
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
                replicas: Some(1),
                workload: WorkloadSpec::default(),
                runtime: RuntimeSpec::default(),
                restart_policy: None,
                policies: None,
            },
        );

        let spec = LatticeJobSpec {
            tasks,
            training: Some(TrainingConfig {
                framework: TrainingFramework::PyTorch,
                coordinator_task: "master".to_string(),
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
            cost: None,
            metrics: None,
        };
        assert_eq!(status.phase, JobPhase::Running);
        assert!(status.start_time.is_some());
    }

    // =========================================================================
    // LatticeJobSpec::validate() tests
    // =========================================================================

    /// Helper: build a task with an explicit command (required for training jobs)
    fn task_with_command(replicas: u32) -> JobTaskSpec {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "train:latest".to_string(),
                command: Some(vec!["/usr/bin/python".to_string(), "train.py".to_string()]),
                resources: Some(ResourceRequirements {
                    limits: Some(ResourceQuantity {
                        cpu: Some("1".to_string()),
                        memory: Some("1Gi".to_string()),
                    }),
                    ..Default::default()
                }),
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
            restart_policy: None,
            policies: None,
        }
    }

    /// Helper: build a task without a command
    fn task_without_command(replicas: u32) -> JobTaskSpec {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "train:latest".to_string(),
                resources: Some(ResourceRequirements {
                    limits: Some(ResourceQuantity {
                        cpu: Some("1".to_string()),
                        memory: Some("1Gi".to_string()),
                    }),
                    ..Default::default()
                }),
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
            restart_policy: None,
            policies: None,
        }
    }

    #[test]
    fn validate_allows_valid_job() {
        let mut tasks = BTreeMap::new();
        tasks.insert("worker".to_string(), task_with_command(2));

        let spec = LatticeJobSpec {
            tasks,
            ..Default::default()
        };
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn validate_allows_valid_training_job() {
        let mut tasks = BTreeMap::new();
        tasks.insert("master".to_string(), task_with_command(1));
        tasks.insert("worker".to_string(), task_with_command(3));

        let spec = LatticeJobSpec {
            tasks,
            training: Some(TrainingConfig {
                framework: TrainingFramework::PyTorch,
                coordinator_task: "master".to_string(),
                nccl: None,
            }),
            ..Default::default()
        };
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn validate_denies_empty_tasks() {
        let spec = LatticeJobSpec {
            tasks: BTreeMap::new(),
            ..Default::default()
        };
        let err = spec.validate().unwrap_err();
        assert!(err.to_string().contains("no tasks"), "got: {err}");
    }

    #[test]
    fn validate_denies_missing_coordinator_task() {
        let mut tasks = BTreeMap::new();
        tasks.insert("worker".to_string(), task_with_command(1));

        let spec = LatticeJobSpec {
            tasks,
            training: Some(TrainingConfig {
                framework: TrainingFramework::PyTorch,
                coordinator_task: "nonexistent".to_string(),
                nccl: None,
            }),
            ..Default::default()
        };
        let err = spec.validate().unwrap_err();
        assert!(
            err.to_string().contains("nonexistent"),
            "should mention missing task name, got: {err}"
        );
    }

    #[test]
    fn validate_denies_training_container_without_command() {
        let mut tasks = BTreeMap::new();
        tasks.insert("worker".to_string(), task_without_command(1));

        let spec = LatticeJobSpec {
            tasks,
            training: Some(TrainingConfig {
                framework: TrainingFramework::PyTorch,
                coordinator_task: "worker".to_string(),
                nccl: None,
            }),
            ..Default::default()
        };
        let err = spec.validate().unwrap_err();
        assert!(
            err.to_string().contains("command"),
            "should mention missing command, got: {err}"
        );
    }

    #[test]
    fn validate_allows_non_training_container_without_command() {
        let mut tasks = BTreeMap::new();
        tasks.insert("worker".to_string(), task_without_command(1));

        let spec = LatticeJobSpec {
            tasks,
            // No training config — command is not required
            ..Default::default()
        };
        assert!(
            spec.validate().is_ok(),
            "non-training jobs should not require command"
        );
    }

    #[test]
    fn validate_denies_training_task_with_non_never_restart_policy() {
        let mut task = task_with_command(1);
        task.restart_policy = Some(RestartPolicy::OnFailure);

        let mut tasks = BTreeMap::new();
        tasks.insert("worker".to_string(), task);

        let spec = LatticeJobSpec {
            tasks,
            training: Some(TrainingConfig {
                framework: TrainingFramework::PyTorch,
                coordinator_task: "worker".to_string(),
                nccl: None,
            }),
            ..Default::default()
        };
        let err = spec.validate().unwrap_err();
        assert!(
            err.to_string().contains("restart_policy") || err.to_string().contains("OnFailure"),
            "should mention bad restart policy, got: {err}"
        );
    }

    #[test]
    fn validate_allows_training_task_with_never_restart_policy() {
        let mut task = task_with_command(1);
        task.restart_policy = Some(RestartPolicy::Never);

        let mut tasks = BTreeMap::new();
        tasks.insert("worker".to_string(), task);

        let spec = LatticeJobSpec {
            tasks,
            training: Some(TrainingConfig {
                framework: TrainingFramework::PyTorch,
                coordinator_task: "worker".to_string(),
                nccl: None,
            }),
            ..Default::default()
        };
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn validate_allows_training_task_with_no_restart_policy() {
        // None means the compiler will set it — validation should allow
        let task = task_with_command(1);
        assert!(task.restart_policy.is_none());

        let mut tasks = BTreeMap::new();
        tasks.insert("worker".to_string(), task);

        let spec = LatticeJobSpec {
            tasks,
            training: Some(TrainingConfig {
                framework: TrainingFramework::PyTorch,
                coordinator_task: "worker".to_string(),
                nccl: None,
            }),
            ..Default::default()
        };
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn validate_allows_non_training_task_with_on_failure() {
        let mut task = task_with_command(1);
        task.restart_policy = Some(RestartPolicy::OnFailure);

        let mut tasks = BTreeMap::new();
        tasks.insert("worker".to_string(), task);

        let spec = LatticeJobSpec {
            tasks,
            // No training config — OnFailure is fine
            ..Default::default()
        };
        assert!(spec.validate().is_ok());
    }

    // =========================================================================
    // Volcano policy types tests
    // =========================================================================

    #[test]
    fn volcano_policy_event_display() {
        assert_eq!(VolcanoPolicyEvent::PodFailed.to_string(), "PodFailed");
        assert_eq!(VolcanoPolicyEvent::PodEvicted.to_string(), "PodEvicted");
        assert_eq!(VolcanoPolicyEvent::PodPending.to_string(), "PodPending");
        assert_eq!(
            VolcanoPolicyEvent::TaskCompleted.to_string(),
            "TaskCompleted"
        );
        assert_eq!(VolcanoPolicyEvent::Unknown.to_string(), "Unknown");
        assert_eq!(VolcanoPolicyEvent::Any.to_string(), "*");
    }

    #[test]
    fn volcano_policy_action_display() {
        assert_eq!(VolcanoPolicyAction::AbortJob.to_string(), "AbortJob");
        assert_eq!(VolcanoPolicyAction::RestartJob.to_string(), "RestartJob");
        assert_eq!(VolcanoPolicyAction::RestartTask.to_string(), "RestartTask");
        assert_eq!(VolcanoPolicyAction::RestartPod.to_string(), "RestartPod");
        assert_eq!(
            VolcanoPolicyAction::TerminateJob.to_string(),
            "TerminateJob"
        );
        assert_eq!(VolcanoPolicyAction::CompleteJob.to_string(), "CompleteJob");
    }

    #[test]
    fn volcano_policy_serde_roundtrip() {
        let policies = vec![
            VolcanoPolicy {
                event: VolcanoPolicyEvent::PodFailed,
                action: VolcanoPolicyAction::RestartJob,
            },
            VolcanoPolicy {
                event: VolcanoPolicyEvent::TaskCompleted,
                action: VolcanoPolicyAction::CompleteJob,
            },
        ];

        let json = serde_json::to_string(&policies).unwrap();
        let de: Vec<VolcanoPolicy> = serde_json::from_str(&json).unwrap();
        assert_eq!(policies, de);
    }

    #[test]
    fn job_spec_with_explicit_policies_serde_roundtrip() {
        let spec = LatticeJobSpec {
            policies: Some(vec![VolcanoPolicy {
                event: VolcanoPolicyEvent::PodEvicted,
                action: VolcanoPolicyAction::AbortJob,
            }]),
            ..Default::default()
        };

        let json = serde_json::to_string(&spec).unwrap();
        let de: LatticeJobSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec.policies, de.policies);
    }

    #[test]
    fn task_spec_with_policies_serde_roundtrip() {
        let task = JobTaskSpec {
            replicas: Some(1),
            workload: WorkloadSpec::default(),
            runtime: RuntimeSpec::default(),
            restart_policy: None,
            policies: Some(vec![VolcanoPolicy {
                event: VolcanoPolicyEvent::TaskCompleted,
                action: VolcanoPolicyAction::CompleteJob,
            }]),
        };

        let json = serde_json::to_string(&task).unwrap();
        let de: JobTaskSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(task.policies, de.policies);
    }

    // =========================================================================
    // Defaults merge tests
    // =========================================================================

    /// Helper: build a defaults spec with image, command, resources, and pull secrets
    fn defaults_spec() -> JobTaskSpec {
        JobTaskSpec {
            replicas: Some(1),
            workload: WorkloadSpec {
                containers: BTreeMap::from([(
                    "main".to_string(),
                    ContainerSpec {
                        image: "train:latest".to_string(),
                        command: Some(vec!["/usr/bin/python".to_string(), "train.py".to_string()]),
                        resources: Some(ResourceRequirements {
                            limits: Some(ResourceQuantity {
                                cpu: Some("2".to_string()),
                                memory: Some("4Gi".to_string()),
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )]),
                ..Default::default()
            },
            runtime: RuntimeSpec {
                image_pull_secrets: vec!["default".to_string()],
                ..Default::default()
            },
            restart_policy: Some(RestartPolicy::Never),
            policies: None,
        }
    }

    #[test]
    fn job_spec_with_defaults_serde_roundtrip() {
        let spec = LatticeJobSpec {
            defaults: Some(JobTaskSpec {
                replicas: None,
                workload: WorkloadSpec::default(),
                runtime: RuntimeSpec::default(),
                restart_policy: Some(RestartPolicy::Never),
                policies: None,
            }),
            ..Default::default()
        };

        let json = serde_json::to_string(&spec).unwrap();
        let de: LatticeJobSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec.defaults, de.defaults);
    }

    #[test]
    fn merged_tasks_fills_missing_workload() {
        let spec = LatticeJobSpec {
            defaults: Some(defaults_spec()),
            tasks: BTreeMap::from([(
                "worker".to_string(),
                JobTaskSpec {
                    replicas: Some(3),
                    workload: WorkloadSpec::default(),
                    runtime: RuntimeSpec::default(),
                    restart_policy: None,
                    policies: None,
                },
            )]),
            ..Default::default()
        };

        let tasks = spec.merged_tasks();
        let task = &tasks["worker"];

        assert_eq!(task.replicas, Some(3));
        assert_eq!(task.workload.containers["main"].image, "train:latest");
        assert_eq!(
            task.workload.containers["main"].command,
            Some(vec!["/usr/bin/python".to_string(), "train.py".to_string()])
        );
        assert_eq!(task.runtime.image_pull_secrets, vec!["default"]);
        assert_eq!(task.restart_policy, Some(RestartPolicy::Never));
    }

    #[test]
    fn merged_tasks_preserves_task_overrides() {
        let spec = LatticeJobSpec {
            defaults: Some(defaults_spec()),
            tasks: BTreeMap::from([(
                "worker".to_string(),
                JobTaskSpec {
                    replicas: Some(1),
                    workload: WorkloadSpec {
                        containers: BTreeMap::from([(
                            "main".to_string(),
                            ContainerSpec {
                                image: "".to_string(),
                                resources: Some(ResourceRequirements {
                                    limits: Some(ResourceQuantity {
                                        memory: Some("8Gi".to_string()),
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                        )]),
                        ..Default::default()
                    },
                    restart_policy: Some(RestartPolicy::OnFailure),
                    runtime: RuntimeSpec::default(),
                    policies: None,
                },
            )]),
            ..Default::default()
        };

        let tasks = spec.merged_tasks();
        let task = &tasks["worker"];

        let limits = task.workload.containers["main"]
            .resources
            .as_ref()
            .unwrap()
            .limits
            .as_ref()
            .unwrap();
        assert_eq!(limits.cpu.as_deref(), Some("2"), "cpu from defaults");
        assert_eq!(
            limits.memory.as_deref(),
            Some("8Gi"),
            "memory from task override"
        );
        assert_eq!(
            task.restart_policy,
            Some(RestartPolicy::OnFailure),
            "task restart_policy should win"
        );
    }

    #[test]
    fn validate_works_with_defaults() {
        let spec = LatticeJobSpec {
            defaults: Some(defaults_spec()),
            tasks: BTreeMap::from([
                (
                    "master".to_string(),
                    JobTaskSpec {
                        replicas: Some(1),
                        workload: WorkloadSpec::default(),
                        runtime: RuntimeSpec::default(),
                        restart_policy: None,
                        policies: None,
                    },
                ),
                (
                    "worker".to_string(),
                    JobTaskSpec {
                        replicas: Some(3),
                        workload: WorkloadSpec::default(),
                        runtime: RuntimeSpec::default(),
                        restart_policy: None,
                        policies: None,
                    },
                ),
            ]),
            training: Some(TrainingConfig {
                framework: TrainingFramework::PyTorch,
                coordinator_task: "master".to_string(),
                nccl: None,
            }),
            ..Default::default()
        };

        assert!(spec.validate().is_ok());
    }
}
