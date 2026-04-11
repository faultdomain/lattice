//! BackupStore Custom Resource Definition
//!
//! The BackupStore CRD defines where backups are stored (S3/GCS/Azure).
//! It translates to a single Velero BackupStorageLocation resource.
//! Storage concerns are fully separated from scheduling and scope.

use kube::{CustomResource, ResourceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::types::{Condition, CredentialSpec, SecretRef};
use crate::LATTICE_SYSTEM_NAMESPACE;

/// Storage provider type for backup destinations
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
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

    /// Reference to a InfraProvider for credentials
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_provider_ref: Option<String>,

    /// ESO-managed credential source for backup storage.
    /// The controller creates an ExternalSecret that syncs credentials
    /// from a ClusterSecretStore into a Velero-compatible secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<CredentialSpec>,
}

/// Phase of a BackupStore
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackupStorePhase {
    /// Store is pending configuration
    #[default]
    Pending,
    /// Store is ready (BSL exists)
    Ready,
    /// Store has an error
    Failed,
}

impl std::fmt::Display for BackupStorePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Ready => write!(f, "Ready"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Status of a BackupStore
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackupStoreStatus {
    /// Current phase
    #[serde(default)]
    pub phase: BackupStorePhase,

    /// Name of the generated Velero BackupStorageLocation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub velero_bsl_name: Option<String>,

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

/// Specification for a BackupStore
///
/// Defines where backups are stored. Each BackupStore maps to one Velero
/// BackupStorageLocation. One store can be marked as default for use by
/// LatticeClusterBackup and ServiceBackupSpec when no explicit store is specified.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "BackupStore",
    plural = "backupstores",
    shortname = "bs",
    namespaced,
    status = "BackupStoreStatus",
    printcolumn = r#"{"name":"Default","type":"boolean","jsonPath":".spec.default"}"#,
    printcolumn = r#"{"name":"Provider","type":"string","jsonPath":".spec.storage.provider"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct BackupStoreSpec {
    /// Whether this is the default store for backups that don't specify a storeRef
    #[serde(default)]
    pub default: bool,

    /// Storage configuration (where to store backups)
    pub storage: BackupStorageSpec,
}

impl BackupStore {
    /// Resolve the K8s Secret containing backup storage credentials.
    ///
    /// Returns a synthetic ref pointing to the ESO-synced secret
    /// `{name}-credentials` in `lattice-system`. Returns `None` if
    /// no credentials are configured.
    pub fn k8s_secret_ref(&self) -> Option<SecretRef> {
        self.spec
            .storage
            .credentials
            .as_ref()
            .map(|_| SecretRef::for_credentials(&self.name_any(), LATTICE_SYSTEM_NAMESPACE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_spec(yaml: &str) -> BackupStoreSpec {
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        serde_json::from_value(value).expect("parse spec")
    }

    #[test]
    fn test_backup_store_roundtrip() {
        let spec = parse_spec(
            r#"
default: true
storage:
  provider: s3
  s3:
    bucket: lattice-backups
    region: us-east-1
  cloudProviderRef: aws-prod
"#,
        );

        assert!(spec.default);
        assert_eq!(spec.storage.s3.as_ref().unwrap().bucket, "lattice-backups");
        assert_eq!(
            spec.storage.cloud_provider_ref,
            Some("aws-prod".to_string())
        );
    }

    #[test]
    fn test_backup_store_s3_compatible() {
        let spec = parse_spec(
            r#"
default: false
storage:
  provider: s3Compatible
  s3:
    bucket: backups
    endpoint: "http://minio.minio-system.svc:9000"
    forcePathStyle: true
  credentials:
    id: backup/minio-creds
    provider: lattice-local
"#,
        );

        assert!(!spec.default);
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
        assert!(spec.storage.credentials.is_some());
    }

    #[test]
    fn test_backup_store_phase_display() {
        assert_eq!(BackupStorePhase::Pending.to_string(), "Pending");
        assert_eq!(BackupStorePhase::Ready.to_string(), "Ready");
        assert_eq!(BackupStorePhase::Failed.to_string(), "Failed");
    }

    #[test]
    fn test_backup_store_defaults() {
        let spec = parse_spec(
            r#"
storage:
  provider: s3
  s3:
    bucket: my-bucket
"#,
        );

        assert!(!spec.default);
    }
}
