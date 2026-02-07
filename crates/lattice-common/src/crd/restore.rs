//! LatticeRestore Custom Resource Definition
//!
//! The LatticeRestore CRD triggers a restore from a Velero backup.
//! It supports both standard Velero ordering and Lattice-aware two-phase ordering.

use chrono::{DateTime, Utc};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::default_true;
use super::types::Condition;

/// Restore ordering strategy
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum RestoreOrdering {
    /// Use Velero's default restore ordering
    #[default]
    VeleroDefault,
    /// Two-phase restore: dependencies first, then workloads
    ///
    /// Phase 1: CRDs, namespaces, secrets, CloudProvider, CedarPolicy, GPUPool, GPUTenantQuota
    /// Phase 2: LatticeCluster, LatticeService, InferenceEndpoint, CAPI resources
    LatticeAware,
}

/// Phase of a LatticeRestore
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum RestorePhase {
    /// Restore is pending
    #[default]
    Pending,
    /// Restore is in progress
    InProgress,
    /// Dependencies phase complete (LatticeAware only)
    DependenciesRestored,
    /// Restore completed successfully
    Completed,
    /// Restore failed
    Failed,
}

impl std::fmt::Display for RestorePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::InProgress => write!(f, "InProgress"),
            Self::DependenciesRestored => write!(f, "DependenciesRestored"),
            Self::Completed => write!(f, "Completed"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Status of a LatticeRestore
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatticeRestoreStatus {
    /// Current phase
    #[serde(default)]
    pub phase: RestorePhase,

    /// Number of items restored
    #[serde(default)]
    pub restored_items: u32,

    /// Name of the Velero Restore resource (phase 1 for LatticeAware)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub velero_restore_name: Option<String>,

    /// Name of the Velero Restore resource for phase 2 (LatticeAware only)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub velero_restore_phase2_name: Option<String>,

    /// Timestamp when restore started
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_time: Option<DateTime<Utc>>,

    /// Timestamp when restore completed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_time: Option<DateTime<Utc>>,

    /// Status conditions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    /// Human-readable message
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Observed generation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

/// Specification for a LatticeRestore
///
/// Triggers a restore from a Velero backup. The restore creates Velero Restore
/// resources and monitors their progress.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "LatticeRestore",
    plural = "latticerestores",
    shortname = "lr",
    namespaced,
    status = "LatticeRestoreStatus",
    printcolumn = r#"{"name":"Backup","type":"string","jsonPath":".spec.backupName"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Items","type":"integer","jsonPath":".status.restoredItems"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LatticeRestoreSpec {
    /// Name of the Velero backup to restore from
    pub backup_name: String,

    /// Reference to the LatticeBackupPolicy that created the backup
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_policy_ref: Option<String>,

    /// Whether to restore persistent volumes
    #[serde(default = "default_true")]
    pub restore_volumes: bool,

    /// Restore ordering strategy
    #[serde(default)]
    pub ordering: RestoreOrdering,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_spec(yaml: &str) -> LatticeRestoreSpec {
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        serde_json::from_value(value).expect("parse spec")
    }

    #[test]
    fn test_restore_roundtrip() {
        let spec = parse_spec(
            r#"
backupName: lattice-default-20260205020012
backupPolicyRef: default
restoreVolumes: true
ordering: LatticeAware
"#,
        );

        assert_eq!(spec.backup_name, "lattice-default-20260205020012");
        assert_eq!(spec.backup_policy_ref, Some("default".to_string()));
        assert!(spec.restore_volumes);
        assert!(matches!(spec.ordering, RestoreOrdering::LatticeAware));
    }

    #[test]
    fn test_restore_defaults() {
        let spec = parse_spec(
            r#"
backupName: my-backup
"#,
        );

        assert!(spec.restore_volumes);
        assert!(matches!(spec.ordering, RestoreOrdering::VeleroDefault));
        assert!(spec.backup_policy_ref.is_none());
    }

    #[test]
    fn test_restore_phase_display() {
        assert_eq!(RestorePhase::Pending.to_string(), "Pending");
        assert_eq!(RestorePhase::InProgress.to_string(), "InProgress");
        assert_eq!(
            RestorePhase::DependenciesRestored.to_string(),
            "DependenciesRestored"
        );
        assert_eq!(RestorePhase::Completed.to_string(), "Completed");
        assert_eq!(RestorePhase::Failed.to_string(), "Failed");
    }
}
