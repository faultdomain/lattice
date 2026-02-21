//! LatticeJob CRD types
//!
//! Defines `LatticeJob` — batch workloads backed by Volcano VCJob.
//! Each job contains named tasks, each with its own `WorkloadSpec` and pod template.

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::workload::spec::{RuntimeSpec, WorkloadSpec};

// =============================================================================
// Phase
// =============================================================================

/// Lifecycle phase of a LatticeJob
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
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

/// Batch workload specification backed by Volcano VCJob
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

    /// Job tasks — each maps to a Volcano VCJob task with its own pod template
    #[serde(default)]
    pub tasks: BTreeMap<String, JobTaskSpec>,
}

impl Default for LatticeJobSpec {
    fn default() -> Self {
        Self {
            scheduler_name: default_scheduler(),
            min_available: None,
            max_retry: None,
            queue: None,
            priority_class_name: None,
            tasks: BTreeMap::new(),
        }
    }
}

/// Status of a LatticeJob
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatticeJobStatus {
    /// Current phase of the job lifecycle
    #[serde(default)]
    pub phase: JobPhase,

    /// Human-readable message about current state
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Generation of the spec that was last reconciled
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
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
}
