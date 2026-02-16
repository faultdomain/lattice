//! LatticeRestore Custom Resource Definition
//!
//! The LatticeRestore CRD triggers a restore from a Velero backup.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::default_true;
use super::types::Condition;

/// Phase of a LatticeRestore
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum RestorePhase {
    /// Restore is pending
    #[default]
    Pending,
    /// Restore is in progress
    InProgress,
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

    /// Name of the Velero Restore resource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub velero_restore_name: Option<String>,

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
/// Triggers a restore from a Velero backup. The restore creates a Velero Restore
/// resource and monitors its progress.
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
"#,
        );

        assert_eq!(spec.backup_name, "lattice-default-20260205020012");
        assert_eq!(spec.backup_policy_ref, Some("default".to_string()));
        assert!(spec.restore_volumes);
    }

    #[test]
    fn test_restore_defaults() {
        let spec = parse_spec(
            r#"
backupName: my-backup
"#,
        );

        assert!(spec.restore_volumes);
        assert!(spec.backup_policy_ref.is_none());
    }

    #[test]
    fn test_restore_phase_display() {
        assert_eq!(RestorePhase::Pending.to_string(), "Pending");
        assert_eq!(RestorePhase::InProgress.to_string(), "InProgress");
        assert_eq!(RestorePhase::Completed.to_string(), "Completed");
        assert_eq!(RestorePhase::Failed.to_string(), "Failed");
    }
}
