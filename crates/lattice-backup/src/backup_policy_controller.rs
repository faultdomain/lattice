//! LatticeBackupPolicy controller
//!
//! Watches LatticeBackupPolicy CRDs and ensures the corresponding Velero
//! Schedule and BackupStorageLocation exist. If Velero is not installed,
//! requeues to retry later.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::ResourceExt;
use tracing::{debug, info, warn};

use lattice_common::crd::{
    BackupPolicyPhase, BackupStorageProvider, LatticeBackupPolicy, LatticeBackupPolicyStatus,
};
use lattice_common::{ControllerContext, ReconcileError, LATTICE_SYSTEM_NAMESPACE};

use crate::velero::{
    self, BackupStorageLocation, BackupStorageLocationSpec, BackupTemplate, ObjectStorageLocation,
    Schedule, ScheduleSpec, VeleroCredential, VELERO_NAMESPACE,
};

/// Requeue interval for successful reconciliation
const REQUEUE_SUCCESS_SECS: u64 = 300;
/// Requeue interval when Velero CRDs are not found
const REQUEUE_CRD_NOT_FOUND_SECS: u64 = 30;
/// Requeue interval on errors
const REQUEUE_ERROR_SECS: u64 = 60;

/// Reconcile a LatticeBackupPolicy
///
/// Ensures the corresponding Velero Schedule and BackupStorageLocation exist.
/// If Velero is not installed, requeues to retry later.
pub async fn reconcile(
    policy: Arc<LatticeBackupPolicy>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = policy.name_any();
    let client = &ctx.client;

    info!(backup_policy = %name, "Reconciling LatticeBackupPolicy");

    // Build the desired Velero resources
    let bsl = build_bsl(&name, &policy);
    let schedule = build_schedule(&name, &policy);

    // Try to apply BSL
    match velero::apply_resource(client, &bsl, "lattice-backup-controller").await {
        Ok(()) => {
            debug!(backup_policy = %name, "BackupStorageLocation applied");
        }
        Err(e) if is_crd_not_found(&e) => {
            warn!(
                backup_policy = %name,
                "Velero BackupStorageLocation CRD not found - Velero may not be installed"
            );
            update_status(
                client,
                &policy,
                BackupPolicyPhase::Pending,
                Some("Velero not installed".to_string()),
                None,
                None,
            )
            .await?;
            return Ok(Action::requeue(Duration::from_secs(
                REQUEUE_CRD_NOT_FOUND_SECS,
            )));
        }
        Err(e) => {
            warn!(backup_policy = %name, error = %e, "Failed to apply BSL");
            update_status(
                client,
                &policy,
                BackupPolicyPhase::Failed,
                Some(format!("BSL apply failed: {}", e)),
                None,
                None,
            )
            .await?;
            return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
        }
    }

    // Try to apply Schedule
    match velero::apply_resource(client, &schedule, "lattice-backup-controller").await {
        Ok(()) => {
            debug!(backup_policy = %name, "Schedule applied");
        }
        Err(e) => {
            warn!(backup_policy = %name, error = %e, "Failed to apply Schedule");
            update_status(
                client,
                &policy,
                BackupPolicyPhase::Failed,
                Some(format!("Schedule apply failed: {}", e)),
                None,
                None,
            )
            .await?;
            return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
        }
    }

    // Update status to Active
    let velero_schedule_name = format!("lattice-{}", name);
    let velero_bsl_name = format!("lattice-{}", name);
    update_status(
        client,
        &policy,
        BackupPolicyPhase::Active,
        Some("Velero Schedule and BSL are configured".to_string()),
        Some(velero_schedule_name),
        Some(velero_bsl_name),
    )
    .await?;

    Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)))
}

/// Build the desired Velero BackupStorageLocation from a LatticeBackupPolicy
fn build_bsl(name: &str, policy: &LatticeBackupPolicy) -> BackupStorageLocation {
    let bsl_name = format!("lattice-{}", name);
    let storage = &policy.spec.storage;

    let (provider, config) = match storage.provider {
        BackupStorageProvider::S3 | BackupStorageProvider::S3Compatible => {
            let mut cfg = BTreeMap::new();
            if let Some(ref s3) = storage.s3 {
                if let Some(ref region) = s3.region {
                    cfg.insert("region".to_string(), region.clone());
                }
                if let Some(ref endpoint) = s3.endpoint {
                    if !endpoint.is_empty() {
                        cfg.insert("s3Url".to_string(), endpoint.clone());
                        cfg.insert("s3ForcePathStyle".to_string(), "true".to_string());
                    }
                }
            }
            ("aws".to_string(), cfg)
        }
        BackupStorageProvider::Gcs => {
            let cfg = BTreeMap::new();
            ("gcp".to_string(), cfg)
        }
        BackupStorageProvider::Azure => {
            let cfg = BTreeMap::new();
            ("azure".to_string(), cfg)
        }
    };

    let bucket = storage
        .s3
        .as_ref()
        .map(|s| s.bucket.clone())
        .or_else(|| storage.gcs.as_ref().map(|g| g.bucket.clone()))
        .or_else(|| storage.azure.as_ref().map(|a| a.container.clone()))
        .unwrap_or_default();

    let credential = storage
        .cloud_provider_ref
        .as_ref()
        .map(|cp_ref| VeleroCredential {
            name: format!("velero-credentials-{}", cp_ref),
            key: "cloud".to_string(),
        });

    BackupStorageLocation::new(
        bsl_name,
        VELERO_NAMESPACE,
        BackupStorageLocationSpec {
            provider,
            object_storage: ObjectStorageLocation {
                bucket,
                prefix: Some(format!("lattice-{}", name)),
            },
            config,
            credential,
            default: None,
        },
    )
}

/// Build the desired Velero Schedule from a LatticeBackupPolicy
fn build_schedule(name: &str, policy: &LatticeBackupPolicy) -> Schedule {
    let schedule_name = format!("lattice-{}", name);

    // Build included resources from scope
    let included_resources = velero::build_included_resources(
        policy.spec.scope.control_plane,
        policy.spec.scope.gpu_paas_resources,
    );

    // Build included/excluded namespaces
    let included_namespaces = policy.spec.scope.include_namespaces.clone();
    let excluded_namespaces = policy.spec.scope.exclude_namespaces.clone();

    // Build TTL from retention
    let ttl = policy.spec.retention.ttl.clone();

    // Determine default volume backup method
    let default_volumes_to_fs_backup = policy.spec.scope.volume_snapshots.as_ref().map(|vs| {
        matches!(
            vs.default_method,
            lattice_common::crd::VolumeSnapshotMethod::Restic
        )
    });

    let snapshot_volumes = policy.spec.scope.volume_snapshots.as_ref().map(|vs| {
        matches!(
            vs.default_method,
            lattice_common::crd::VolumeSnapshotMethod::CsiSnapshot
        )
    });

    Schedule::new(
        schedule_name.clone(),
        VELERO_NAMESPACE,
        ScheduleSpec {
            schedule: policy.spec.schedule.clone(),
            paused: Some(policy.spec.paused),
            template: BackupTemplate {
                ttl,
                included_namespaces,
                excluded_namespaces,
                included_resources,
                excluded_resources: vec![],
                storage_location: Some(schedule_name),
                default_volumes_to_fs_backup,
                snapshot_volumes,
                label_selector: None,
            },
        },
    )
}

/// Check if an error indicates the CRD is not found
fn is_crd_not_found(e: &ReconcileError) -> bool {
    match e {
        ReconcileError::Kube(msg) => msg.contains("404") || msg.contains("not found"),
        _ => false,
    }
}

/// Update LatticeBackupPolicy status
async fn update_status(
    client: &kube::Client,
    policy: &LatticeBackupPolicy,
    phase: BackupPolicyPhase,
    message: Option<String>,
    velero_schedule_name: Option<String>,
    velero_bsl_name: Option<String>,
) -> Result<(), ReconcileError> {
    let name = policy.name_any();
    let namespace = policy
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());

    let status = LatticeBackupPolicyStatus {
        phase,
        velero_schedule_name,
        velero_bsl_name,
        conditions: vec![],
        message,
        observed_generation: policy.metadata.generation,
    };

    let patch = serde_json::json!({ "status": status });
    let api: Api<LatticeBackupPolicy> = Api::namespaced(client.clone(), &namespace);
    api.patch_status(
        &name,
        &PatchParams::apply("lattice-backup-controller"),
        &Patch::Merge(&patch),
    )
    .await
    .map_err(|e| ReconcileError::Kube(format!("status update failed: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{
        BackupRetentionSpec, BackupScopeSpec, BackupStorageSpec, S3StorageConfig,
    };

    fn sample_policy() -> LatticeBackupPolicy {
        use kube::core::ObjectMeta;
        use lattice_common::crd::LatticeBackupPolicySpec;

        LatticeBackupPolicy {
            metadata: ObjectMeta {
                name: Some("default".to_string()),
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                ..Default::default()
            },
            spec: LatticeBackupPolicySpec {
                schedule: "0 2 * * *".to_string(),
                storage: BackupStorageSpec {
                    provider: BackupStorageProvider::S3,
                    s3: Some(S3StorageConfig {
                        bucket: "lattice-backups".to_string(),
                        region: Some("us-east-1".to_string()),
                        endpoint: None,
                        force_path_style: None,
                    }),
                    gcs: None,
                    azure: None,
                    cloud_provider_ref: Some("aws-prod".to_string()),
                    credentials_secret_ref: None,
                },
                scope: BackupScopeSpec {
                    control_plane: true,
                    gpu_paas_resources: false,
                    workload_namespaces: None,
                    include_namespaces: vec![],
                    exclude_namespaces: vec![],
                    volume_snapshots: None,
                },
                retention: BackupRetentionSpec {
                    daily: Some(30),
                    ttl: Some("720h".to_string()),
                },
                paused: false,
            },
            status: None,
        }
    }

    #[test]
    fn test_build_bsl_s3() {
        let policy = sample_policy();
        let bsl = build_bsl("default", &policy);

        assert_eq!(bsl.metadata.name, "lattice-default");
        assert_eq!(bsl.metadata.namespace, VELERO_NAMESPACE);
        assert_eq!(bsl.spec.provider, "aws");
        assert_eq!(bsl.spec.object_storage.bucket, "lattice-backups");
        assert_eq!(bsl.spec.config.get("region").unwrap(), "us-east-1");
        assert!(bsl.spec.credential.is_some());
        assert_eq!(
            bsl.spec.credential.unwrap().name,
            "velero-credentials-aws-prod"
        );
    }

    #[test]
    fn test_build_bsl_s3_compatible_with_endpoint() {
        let mut policy = sample_policy();
        policy.spec.storage.provider = BackupStorageProvider::S3Compatible;
        policy.spec.storage.s3 = Some(S3StorageConfig {
            bucket: "lattice-backups".to_string(),
            region: Some("us-east-1".to_string()),
            endpoint: Some("http://minio.minio:9000".to_string()),
            force_path_style: Some(true),
        });
        policy.spec.storage.cloud_provider_ref = None;

        let bsl = build_bsl("minio", &policy);

        assert_eq!(bsl.spec.provider, "aws");
        assert_eq!(
            bsl.spec.config.get("s3Url").unwrap(),
            "http://minio.minio:9000"
        );
        assert_eq!(bsl.spec.config.get("s3ForcePathStyle").unwrap(), "true");
        assert!(bsl.spec.credential.is_none());
    }

    #[test]
    fn test_build_schedule() {
        let policy = sample_policy();
        let schedule = build_schedule("default", &policy);

        assert_eq!(schedule.metadata.name, "lattice-default");
        assert_eq!(schedule.metadata.namespace, VELERO_NAMESPACE);
        assert_eq!(schedule.spec.schedule, "0 2 * * *");
        assert_eq!(schedule.spec.paused, Some(false));
        assert_eq!(schedule.spec.template.ttl, Some("720h".to_string()));
        assert!(schedule
            .spec
            .template
            .included_resources
            .contains(&"latticeclusters.lattice.dev".to_string()));
        assert!(!schedule
            .spec
            .template
            .included_resources
            .contains(&"gpupools.lattice.dev".to_string()));
    }

    #[test]
    fn test_build_schedule_paused() {
        let mut policy = sample_policy();
        policy.spec.paused = true;

        let schedule = build_schedule("default", &policy);
        assert_eq!(schedule.spec.paused, Some(true));
    }

    #[test]
    fn test_build_schedule_with_gpu_paas() {
        let mut policy = sample_policy();
        policy.spec.scope.gpu_paas_resources = true;

        let schedule = build_schedule("default", &policy);
        assert!(schedule
            .spec
            .template
            .included_resources
            .contains(&"gpupools.lattice.dev".to_string()));
        assert!(schedule
            .spec
            .template
            .included_resources
            .contains(&"latticeclusters.lattice.dev".to_string()));
    }

    #[test]
    fn test_bsl_json_structure() {
        let policy = sample_policy();
        let bsl = build_bsl("default", &policy);
        let json = serde_json::to_value(&bsl).unwrap();

        assert_eq!(json["apiVersion"], "velero.io/v1");
        assert_eq!(json["kind"], "BackupStorageLocation");
        assert_eq!(json["metadata"]["name"], "lattice-default");
        assert_eq!(json["metadata"]["namespace"], "velero");
        assert_eq!(json["spec"]["provider"], "aws");
        assert_eq!(json["spec"]["objectStorage"]["bucket"], "lattice-backups");
    }

    #[test]
    fn test_schedule_json_structure() {
        let policy = sample_policy();
        let schedule = build_schedule("default", &policy);
        let json = serde_json::to_value(&schedule).unwrap();

        assert_eq!(json["apiVersion"], "velero.io/v1");
        assert_eq!(json["kind"], "Schedule");
        assert_eq!(json["metadata"]["name"], "lattice-default");
        assert_eq!(json["spec"]["schedule"], "0 2 * * *");
        assert_eq!(json["spec"]["template"]["ttl"], "720h");
    }
}
