//! LatticeBackupPolicy Custom Resource Definition
//!
//! The LatticeBackupPolicy CRD defines platform-level backup schedules and storage
//! configuration. It translates to Velero Schedule and BackupStorageLocation resources.

use chrono::{DateTime, Utc};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::service_policy::NamespaceSelector;
use super::types::Condition;

/// Storage provider type for backup destinations
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum BackupStorageProvider {
    /// Amazon S3
    #[default]
    S3,
    /// Google Cloud Storage
    Gcs,
    /// Azure Blob Storage
    Azure,
    /// S3-compatible storage (e.g., MinIO)
    S3Compatible,
}

/// S3 storage configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct S3StorageConfig {
    /// S3 bucket name
    pub bucket: String,

    /// AWS region
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// Custom endpoint for S3-compatible storage (e.g., MinIO)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// Use path-style addressing (required for MinIO)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_path_style: Option<bool>,
}

/// GCS storage configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GcsStorageConfig {
    /// GCS bucket name
    pub bucket: String,
}

/// Azure storage configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AzureStorageConfig {
    /// Azure Blob Storage container name
    pub container: String,

    /// Azure storage account name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_account: Option<String>,
}

/// Backup storage configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackupStorageSpec {
    /// Storage provider type
    #[serde(default)]
    pub provider: BackupStorageProvider,

    /// S3 configuration (when provider is s3 or s3Compatible)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s3: Option<S3StorageConfig>,

    /// GCS configuration (when provider is gcs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gcs: Option<GcsStorageConfig>,

    /// Azure configuration (when provider is azure)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure: Option<AzureStorageConfig>,

    /// Reference to a CloudProvider for credentials
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_provider_ref: Option<String>,

    /// Direct reference to a Kubernetes secret with credentials
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_secret_ref: Option<String>,
}

/// Default volume snapshot method
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum VolumeSnapshotMethod {
    /// File-level backup via Restic (default, works everywhere)
    #[default]
    Restic,
    /// CSI volume snapshots (faster for large volumes)
    CsiSnapshot,
    /// Skip volume backups
    None,
}

/// Volume snapshot configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VolumeSnapshotConfig {
    /// Default method for volume backups
    #[serde(default)]
    pub default_method: VolumeSnapshotMethod,

    /// PVCs above this size use CSI snapshots instead of Restic
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csi_snapshot_threshold: Option<String>,

    /// PVC name patterns that always use CSI snapshots
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub csi_snapshot_patterns: Vec<String>,
}

/// Backup scope configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackupScopeSpec {
    /// Backup Lattice control plane CRDs
    #[serde(default)]
    pub control_plane: bool,

    /// Backup GPU PaaS CRDs (GPUPool, InferenceEndpoint, ModelCache, GPUTenantQuota)
    #[serde(default)]
    pub gpu_paas_resources: bool,

    /// Select workload namespaces by labels
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_namespaces: Option<NamespaceSelector>,

    /// Explicitly include these namespaces
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_namespaces: Vec<String>,

    /// Explicitly exclude these namespaces
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_namespaces: Vec<String>,

    /// Volume snapshot configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_snapshots: Option<VolumeSnapshotConfig>,
}

/// Backup retention configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackupRetentionSpec {
    /// Number of daily backups to retain
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daily: Option<u32>,

    /// Time-to-live for backups (e.g., "720h" for 30 days)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
}

/// Phase of a LatticeBackupPolicy
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum BackupPolicyPhase {
    /// Policy is pending configuration
    #[default]
    Pending,
    /// Policy is active and backups are running
    Active,
    /// Policy is paused (no backups created)
    Paused,
    /// Policy has an error
    Failed,
}

impl std::fmt::Display for BackupPolicyPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Active => write!(f, "Active"),
            Self::Paused => write!(f, "Paused"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Status of a LatticeBackupPolicy
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatticeBackupPolicyStatus {
    /// Current phase
    #[serde(default)]
    pub phase: BackupPolicyPhase,

    /// Name of the generated Velero Schedule
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub velero_schedule_name: Option<String>,

    /// Name of the generated Velero BackupStorageLocation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub velero_bsl_name: Option<String>,

    /// Timestamp of the last successful backup
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_backup_time: Option<DateTime<Utc>>,

    /// Total number of backups created by this policy
    #[serde(default)]
    pub backup_count: u32,

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

/// Specification for a LatticeBackupPolicy
///
/// Defines a platform-level backup schedule with storage configuration and scope.
/// Translates to Velero Schedule and BackupStorageLocation resources.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "LatticeBackupPolicy",
    plural = "latticebackuppolicies",
    shortname = "lbp",
    namespaced,
    status = "LatticeBackupPolicyStatus",
    printcolumn = r#"{"name":"Schedule","type":"string","jsonPath":".spec.schedule"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Last Backup","type":"date","jsonPath":".status.lastBackupTime"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LatticeBackupPolicySpec {
    /// Cron schedule for backups (e.g., "0 2 * * *" for daily at 2am)
    pub schedule: String,

    /// Storage configuration (where to store backups)
    pub storage: BackupStorageSpec,

    /// Backup scope (what to back up)
    #[serde(default)]
    pub scope: BackupScopeSpec,

    /// Retention configuration
    #[serde(default)]
    pub retention: BackupRetentionSpec,

    /// Pause backup creation
    #[serde(default)]
    pub paused: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_spec(yaml: &str) -> LatticeBackupPolicySpec {
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        serde_json::from_value(value).expect("parse spec")
    }

    #[test]
    fn test_backup_policy_roundtrip() {
        let spec = parse_spec(
            r#"
schedule: "0 2 * * *"
storage:
  provider: s3
  s3:
    bucket: lattice-backups
    region: us-east-1
scope:
  controlPlane: true
  gpuPaasResources: true
retention:
  daily: 30
  ttl: "720h"
paused: false
"#,
        );

        assert_eq!(spec.schedule, "0 2 * * *");
        assert_eq!(spec.storage.s3.as_ref().unwrap().bucket, "lattice-backups");
        assert!(spec.scope.control_plane);
        assert!(spec.scope.gpu_paas_resources);
        assert_eq!(spec.retention.daily, Some(30));
        assert_eq!(spec.retention.ttl, Some("720h".to_string()));
        assert!(!spec.paused);
    }

    #[test]
    fn test_backup_policy_s3_compatible() {
        let spec = parse_spec(
            r#"
schedule: "0 */6 * * *"
storage:
  provider: s3Compatible
  s3:
    bucket: backups
    endpoint: "http://minio.minio-system.svc:9000"
    forcePathStyle: true
  credentialsSecretRef: minio-creds
scope:
  controlPlane: true
retention:
  ttl: "168h"
"#,
        );

        assert!(matches!(
            spec.storage.provider,
            BackupStorageProvider::S3Compatible
        ));
        let s3 = spec.storage.s3.unwrap();
        assert_eq!(
            s3.endpoint,
            Some("http://minio.minio-system.svc:9000".to_string())
        );
        assert_eq!(s3.force_path_style, Some(true));
        assert_eq!(
            spec.storage.credentials_secret_ref,
            Some("minio-creds".to_string())
        );
    }

    #[test]
    fn test_backup_policy_phase_display() {
        assert_eq!(BackupPolicyPhase::Pending.to_string(), "Pending");
        assert_eq!(BackupPolicyPhase::Active.to_string(), "Active");
        assert_eq!(BackupPolicyPhase::Paused.to_string(), "Paused");
        assert_eq!(BackupPolicyPhase::Failed.to_string(), "Failed");
    }

    #[test]
    fn test_backup_policy_defaults() {
        let spec = parse_spec(
            r#"
schedule: "0 3 * * *"
storage:
  provider: s3
  s3:
    bucket: my-bucket
"#,
        );

        assert!(!spec.paused);
        assert!(!spec.scope.control_plane);
        assert!(!spec.scope.gpu_paas_resources);
        assert!(spec.scope.include_namespaces.is_empty());
        assert!(spec.scope.exclude_namespaces.is_empty());
        assert!(spec.retention.daily.is_none());
    }

    #[test]
    fn test_volume_snapshot_config() {
        let spec = parse_spec(
            r#"
schedule: "0 2 * * *"
storage:
  provider: s3
  s3:
    bucket: backups
scope:
  controlPlane: true
  volumeSnapshots:
    defaultMethod: restic
    csiSnapshotThreshold: "100Gi"
    csiSnapshotPatterns:
      - "model-cache-*"
"#,
        );

        let vs = spec.scope.volume_snapshots.unwrap();
        assert!(matches!(vs.default_method, VolumeSnapshotMethod::Restic));
        assert_eq!(vs.csi_snapshot_threshold, Some("100Gi".to_string()));
        assert_eq!(vs.csi_snapshot_patterns, vec!["model-cache-*"]);
    }
}
