//! Velero resource types
//!
//! Typed structs for Velero resources (Schedule, BackupStorageLocation).
//! These implement `HasApiResource` for consistent API version handling.

use std::collections::BTreeMap;

use kube::api::{Api, DynamicObject, Patch, PatchParams};
use serde::{Deserialize, Serialize};

use lattice_common::kube_utils::{HasApiResource, ObjectMeta};
use lattice_common::ReconcileError;

/// Velero namespace where Schedule/BSL/Restore resources are created
pub(crate) const VELERO_NAMESPACE: &str = "velero";

/// Apply a Velero resource using server-side apply via DynamicObject
pub(crate) async fn apply_resource<T>(
    client: &kube::Client,
    resource: &T,
    field_manager: &str,
) -> Result<(), ReconcileError>
where
    T: serde::Serialize + HasApiResource,
{
    let ar = T::api_resource();
    let value = serde_json::to_value(resource)
        .map_err(|e| ReconcileError::Kube(format!("failed to serialize Velero resource: {}", e)))?;

    let name = value
        .pointer("/metadata/name")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let namespace = value
        .pointer("/metadata/namespace")
        .and_then(|v| v.as_str())
        .unwrap_or(VELERO_NAMESPACE);

    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
    let params = PatchParams::apply(field_manager).force();

    api.patch(name, &params, &Patch::Apply(&value))
        .await
        .map_err(|e| {
            ReconcileError::Kube(format!("failed to apply {}/{}: {}", ar.kind, name, e))
        })?;

    Ok(())
}

// =============================================================================
// BackupStorageLocation
// =============================================================================

/// Velero BackupStorageLocation resource
///
/// Defines where backups are stored (S3, GCS, Azure, etc.).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackupStorageLocation {
    /// API version
    #[serde(default = "BackupStorageLocation::default_api_version")]
    pub api_version: String,
    /// Resource kind
    #[serde(default = "BackupStorageLocation::default_kind")]
    pub kind: String,
    /// Resource metadata
    pub metadata: ObjectMeta,
    /// BSL specification
    pub spec: BackupStorageLocationSpec,
}

impl HasApiResource for BackupStorageLocation {
    const API_VERSION: &'static str = "velero.io/v1";
    const KIND: &'static str = "BackupStorageLocation";
}

impl BackupStorageLocation {
    fn default_api_version() -> String {
        <Self as HasApiResource>::API_VERSION.to_string()
    }
    fn default_kind() -> String {
        <Self as HasApiResource>::KIND.to_string()
    }

    /// Create a new BackupStorageLocation
    pub fn new(
        name: impl Into<String>,
        namespace: impl Into<String>,
        spec: BackupStorageLocationSpec,
    ) -> Self {
        Self {
            api_version: Self::default_api_version(),
            kind: Self::default_kind(),
            metadata: ObjectMeta::new(name, namespace),
            spec,
        }
    }
}

/// BackupStorageLocation spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackupStorageLocationSpec {
    /// Provider name (aws, gcp, azure)
    pub provider: String,
    /// Object storage configuration
    pub object_storage: ObjectStorageLocation,
    /// Provider-specific configuration
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub config: BTreeMap<String, String>,
    /// Credential reference
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<VeleroCredential>,
    /// Whether this is the default BSL
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<bool>,
}

/// Object storage configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ObjectStorageLocation {
    /// Bucket name
    pub bucket: String,
    /// Prefix within the bucket
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

/// Velero credential reference
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VeleroCredential {
    /// Name of the Kubernetes Secret
    pub name: String,
    /// Key within the Secret
    pub key: String,
}

// =============================================================================
// Schedule
// =============================================================================

/// Velero Schedule resource
///
/// Defines a periodic backup schedule.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Schedule {
    /// API version
    #[serde(default = "Schedule::default_api_version")]
    pub api_version: String,
    /// Resource kind
    #[serde(default = "Schedule::default_kind")]
    pub kind: String,
    /// Resource metadata
    pub metadata: ObjectMeta,
    /// Schedule specification
    pub spec: ScheduleSpec,
}

impl HasApiResource for Schedule {
    const API_VERSION: &'static str = "velero.io/v1";
    const KIND: &'static str = "Schedule";
}

impl Schedule {
    fn default_api_version() -> String {
        <Self as HasApiResource>::API_VERSION.to_string()
    }
    fn default_kind() -> String {
        <Self as HasApiResource>::KIND.to_string()
    }

    /// Create a new Schedule
    pub fn new(name: impl Into<String>, namespace: impl Into<String>, spec: ScheduleSpec) -> Self {
        Self {
            api_version: Self::default_api_version(),
            kind: Self::default_kind(),
            metadata: ObjectMeta::new(name, namespace),
            spec,
        }
    }
}

/// Schedule spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleSpec {
    /// Cron schedule expression
    pub schedule: String,
    /// Whether the schedule is paused
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused: Option<bool>,
    /// Backup template
    pub template: BackupTemplate,
}

/// Backup template within a Schedule
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackupTemplate {
    /// TTL for backups
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// Included namespaces
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub included_namespaces: Vec<String>,
    /// Excluded namespaces
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_namespaces: Vec<String>,
    /// Included resources
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub included_resources: Vec<String>,
    /// Excluded resources
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_resources: Vec<String>,
    /// Storage location name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_location: Option<String>,
    /// Default volumes to Restic/file-system backup
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_volumes_to_fs_backup: Option<bool>,
    /// Snapshot volumes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_volumes: Option<bool>,
    /// Label selector
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_selector: Option<LabelSelector>,
}

/// Label selector for backup filtering
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    /// Match labels
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub match_labels: BTreeMap<String, String>,
}

// =============================================================================
// Restore
// =============================================================================

/// Velero Restore resource
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Restore {
    /// API version
    #[serde(default = "Restore::default_api_version")]
    pub api_version: String,
    /// Resource kind
    #[serde(default = "Restore::default_kind")]
    pub kind: String,
    /// Resource metadata
    pub metadata: ObjectMeta,
    /// Restore specification
    pub spec: RestoreSpec,
}

impl HasApiResource for Restore {
    const API_VERSION: &'static str = "velero.io/v1";
    const KIND: &'static str = "Restore";
}

impl Restore {
    fn default_api_version() -> String {
        <Self as HasApiResource>::API_VERSION.to_string()
    }
    fn default_kind() -> String {
        <Self as HasApiResource>::KIND.to_string()
    }

    /// Create a new Restore
    pub fn new(name: impl Into<String>, namespace: impl Into<String>, spec: RestoreSpec) -> Self {
        Self {
            api_version: Self::default_api_version(),
            kind: Self::default_kind(),
            metadata: ObjectMeta::new(name, namespace),
            spec,
        }
    }
}

/// Restore spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RestoreSpec {
    /// Name of the Velero Backup to restore from
    pub backup_name: String,
    /// Included namespaces
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub included_namespaces: Vec<String>,
    /// Excluded namespaces
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_namespaces: Vec<String>,
    /// Included resources
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub included_resources: Vec<String>,
    /// Excluded resources
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_resources: Vec<String>,
    /// Restore PVs
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore_pvs: Option<bool>,
}

// =============================================================================
// Shared Types
// =============================================================================

// =============================================================================
// Builder Helpers
// =============================================================================

/// Lattice CRD resource names for backup scope
pub const LATTICE_CONTROL_PLANE_RESOURCES: &[&str] = &[
    "latticeclusters.lattice.dev",
    "latticeservices.lattice.dev",
    "latticeexternalservices.lattice.dev",
    "latticeservicepolicies.lattice.dev",
    "cloudproviders.lattice.dev",
    "secretproviders.lattice.dev",
    "cedarpolicies.lattice.dev",
    "oidcproviders.lattice.dev",
    "latticebackuppolicies.lattice.dev",
];

/// GPU PaaS resource names for backup scope
pub const GPU_PAAS_RESOURCES: &[&str] = &[
    "gpupools.lattice.dev",
    "inferenceendpoints.lattice.dev",
    "modelcaches.lattice.dev",
    "gputenantquotas.lattice.dev",
];

/// Build the list of included resources based on backup scope
pub fn build_included_resources(control_plane: bool, gpu_paas: bool) -> Vec<String> {
    let mut resources = Vec::new();
    if control_plane {
        resources.extend(
            LATTICE_CONTROL_PLANE_RESOURCES
                .iter()
                .map(|s| s.to_string()),
        );
    }
    if gpu_paas {
        resources.extend(GPU_PAAS_RESOURCES.iter().map(|s| s.to_string()));
    }
    resources
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bsl_serialization() {
        let bsl = BackupStorageLocation::new(
            "lattice-default",
            "velero",
            BackupStorageLocationSpec {
                provider: "aws".to_string(),
                object_storage: ObjectStorageLocation {
                    bucket: "lattice-backups".to_string(),
                    prefix: Some("cluster-1".to_string()),
                },
                config: {
                    let mut m = BTreeMap::new();
                    m.insert("region".to_string(), "us-east-1".to_string());
                    m
                },
                credential: Some(VeleroCredential {
                    name: "cloud-credentials".to_string(),
                    key: "cloud".to_string(),
                }),
                default: Some(true),
            },
        );

        let json = serde_json::to_string_pretty(&bsl).unwrap();
        assert!(json.contains("velero.io/v1"));
        assert!(json.contains("BackupStorageLocation"));
        assert!(json.contains("lattice-backups"));
        assert!(json.contains("us-east-1"));

        let parsed: BackupStorageLocation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, bsl);
    }

    #[test]
    fn test_schedule_serialization() {
        let schedule = Schedule::new(
            "lattice-default",
            "velero",
            ScheduleSpec {
                schedule: "0 2 * * *".to_string(),
                paused: Some(false),
                template: BackupTemplate {
                    ttl: Some("720h".to_string()),
                    included_namespaces: vec![],
                    excluded_namespaces: vec![],
                    included_resources: vec![
                        "latticeclusters.lattice.dev".to_string(),
                        "latticeservices.lattice.dev".to_string(),
                    ],
                    excluded_resources: vec![],
                    storage_location: Some("lattice-default".to_string()),
                    default_volumes_to_fs_backup: Some(true),
                    snapshot_volumes: None,
                    label_selector: None,
                },
            },
        );

        let json = serde_json::to_string_pretty(&schedule).unwrap();
        assert!(json.contains("velero.io/v1"));
        assert!(json.contains("Schedule"));
        assert!(json.contains("0 2 * * *"));
        assert!(json.contains("720h"));
        assert!(json.contains("latticeclusters.lattice.dev"));

        let parsed: Schedule = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, schedule);
    }

    #[test]
    fn test_restore_serialization() {
        let restore = Restore::new(
            "restore-20260205",
            "velero",
            RestoreSpec {
                backup_name: "lattice-default-20260205020012".to_string(),
                included_namespaces: vec![],
                excluded_namespaces: vec![],
                included_resources: vec![],
                excluded_resources: vec![],
                restore_pvs: Some(true),
            },
        );

        let json = serde_json::to_string_pretty(&restore).unwrap();
        assert!(json.contains("velero.io/v1"));
        assert!(json.contains("Restore"));
        assert!(json.contains("lattice-default-20260205020012"));

        let parsed: Restore = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, restore);
    }

    #[test]
    fn test_bsl_without_optional_fields() {
        let bsl = BackupStorageLocation::new(
            "minimal",
            "velero",
            BackupStorageLocationSpec {
                provider: "aws".to_string(),
                object_storage: ObjectStorageLocation {
                    bucket: "my-bucket".to_string(),
                    prefix: None,
                },
                config: BTreeMap::new(),
                credential: None,
                default: None,
            },
        );

        let json = serde_json::to_string_pretty(&bsl).unwrap();
        assert!(!json.contains("prefix"));
        assert!(!json.contains("credential"));
        assert!(!json.contains("\"default\""));
    }

    #[test]
    fn test_schedule_paused() {
        let schedule = Schedule::new(
            "paused-schedule",
            "velero",
            ScheduleSpec {
                schedule: "0 0 * * *".to_string(),
                paused: Some(true),
                template: BackupTemplate {
                    ttl: None,
                    included_namespaces: vec![],
                    excluded_namespaces: vec![],
                    included_resources: vec![],
                    excluded_resources: vec![],
                    storage_location: None,
                    default_volumes_to_fs_backup: None,
                    snapshot_volumes: None,
                    label_selector: None,
                },
            },
        );

        let json = serde_json::to_string_pretty(&schedule).unwrap();
        assert!(json.contains("\"paused\": true"));
    }

    #[test]
    fn test_build_included_resources_control_plane() {
        let resources = build_included_resources(true, false);
        assert!(resources.contains(&"latticeclusters.lattice.dev".to_string()));
        assert!(resources.contains(&"latticeservices.lattice.dev".to_string()));
        assert!(!resources.contains(&"gpupools.lattice.dev".to_string()));
    }

    #[test]
    fn test_build_included_resources_gpu_paas() {
        let resources = build_included_resources(false, true);
        assert!(!resources.contains(&"latticeclusters.lattice.dev".to_string()));
        assert!(resources.contains(&"gpupools.lattice.dev".to_string()));
        assert!(resources.contains(&"inferenceendpoints.lattice.dev".to_string()));
    }

    #[test]
    fn test_build_included_resources_both() {
        let resources = build_included_resources(true, true);
        assert!(resources.contains(&"latticeclusters.lattice.dev".to_string()));
        assert!(resources.contains(&"gpupools.lattice.dev".to_string()));
        assert_eq!(
            resources.len(),
            LATTICE_CONTROL_PLANE_RESOURCES.len() + GPU_PAAS_RESOURCES.len()
        );
    }

    #[test]
    fn test_velero_metadata_labels() {
        let meta = ObjectMeta::new("test", "velero");
        assert_eq!(
            meta.labels.get(lattice_common::LABEL_MANAGED_BY),
            Some(&lattice_common::LABEL_MANAGED_BY_LATTICE.to_string())
        );
    }
}
