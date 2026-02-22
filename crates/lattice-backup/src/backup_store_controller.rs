//! BackupStore controller
//!
//! Watches BackupStore CRDs and ensures the corresponding Velero
//! BackupStorageLocation exists. If Velero is not installed, requeues to retry.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;
use kube::ResourceExt;
use tracing::{debug, info, warn};

use lattice_common::crd::{
    BackupStorageProvider, BackupStore, BackupStorePhase, BackupStoreStatus,
};
use lattice_common::{ControllerContext, ReconcileError, LATTICE_SYSTEM_NAMESPACE};

use crate::velero::{
    self, BackupStorageLocation, BackupStorageLocationSpec, ObjectStorageLocation,
    VeleroCredential, VELERO_NAMESPACE,
};

use crate::{REQUEUE_CRD_NOT_FOUND_SECS, REQUEUE_ERROR_SECS, REQUEUE_SUCCESS_SECS};

/// Reconcile a BackupStore into a Velero BackupStorageLocation
pub async fn reconcile(
    store: Arc<BackupStore>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = store.name_any();
    let client = &ctx.client;

    info!(backup_store = %name, "Reconciling BackupStore");

    let bsl = build_bsl(&name, &store);

    match velero::apply_resource(client, &bsl, "lattice-backup-store-controller").await {
        Ok(()) => {
            debug!(backup_store = %name, "BackupStorageLocation applied");
        }
        Err(e) if e.is_crd_not_found() => {
            warn!(
                backup_store = %name,
                "Velero BackupStorageLocation CRD not found - Velero may not be installed"
            );
            update_status(
                client,
                &store,
                BackupStorePhase::Pending,
                Some("Velero not installed".to_string()),
                None,
            )
            .await?;
            return Ok(Action::requeue(Duration::from_secs(
                REQUEUE_CRD_NOT_FOUND_SECS,
            )));
        }
        Err(e) => {
            warn!(backup_store = %name, error = %e, "Failed to apply BSL");
            update_status(
                client,
                &store,
                BackupStorePhase::Failed,
                Some(format!("BSL apply failed: {}", e)),
                None,
            )
            .await?;
            return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
        }
    }

    let velero_bsl_name = format!("lattice-{}", name);
    update_status(
        client,
        &store,
        BackupStorePhase::Ready,
        Some("BackupStorageLocation is configured".to_string()),
        Some(velero_bsl_name),
    )
    .await?;

    Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)))
}

/// Build the desired Velero BackupStorageLocation from a BackupStore
pub fn build_bsl(name: &str, store: &BackupStore) -> BackupStorageLocation {
    let bsl_name = format!("lattice-{}", name);
    let storage = &store.spec.storage;

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
            default: Some(store.spec.default),
        },
    )
}

async fn update_status(
    client: &kube::Client,
    store: &BackupStore,
    phase: BackupStorePhase,
    message: Option<String>,
    velero_bsl_name: Option<String>,
) -> Result<(), ReconcileError> {
    if let Some(ref current) = store.status {
        if current.phase == phase && current.message == message {
            debug!(backup_store = %store.name_any(), "status unchanged, skipping update");
            return Ok(());
        }
    }

    let name = store.name_any();
    let namespace = store
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());

    let status = BackupStoreStatus {
        phase,
        velero_bsl_name,
        conditions: vec![],
        message,
        observed_generation: store.metadata.generation,
    };

    lattice_common::kube_utils::patch_resource_status::<BackupStore>(
        client,
        &name,
        &namespace,
        &status,
        "lattice-backup-store-controller",
    )
    .await
    .map_err(|e| ReconcileError::kube("status update failed", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{BackupStorageSpec, S3StorageConfig};

    fn sample_store() -> BackupStore {
        use kube::core::ObjectMeta;
        use lattice_common::crd::BackupStoreSpec;

        BackupStore {
            metadata: ObjectMeta {
                name: Some("production-s3".to_string()),
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                ..Default::default()
            },
            spec: BackupStoreSpec {
                default: true,
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
            },
            status: None,
        }
    }

    #[test]
    fn test_build_bsl_s3() {
        let store = sample_store();
        let bsl = build_bsl("production-s3", &store);

        assert_eq!(bsl.metadata.name, "lattice-production-s3");
        assert_eq!(bsl.metadata.namespace, VELERO_NAMESPACE);
        assert_eq!(bsl.spec.provider, "aws");
        assert_eq!(bsl.spec.object_storage.bucket, "lattice-backups");
        assert_eq!(bsl.spec.config.get("region").unwrap(), "us-east-1");
        assert!(bsl.spec.credential.is_some());
        assert_eq!(
            bsl.spec.credential.unwrap().name,
            "velero-credentials-aws-prod"
        );
        assert_eq!(bsl.spec.default, Some(true));
    }

    #[test]
    fn test_build_bsl_s3_compatible_with_endpoint() {
        let mut store = sample_store();
        store.spec.default = false;
        store.spec.storage.provider = BackupStorageProvider::S3Compatible;
        store.spec.storage.s3 = Some(S3StorageConfig {
            bucket: "lattice-backups".to_string(),
            region: Some("us-east-1".to_string()),
            endpoint: Some("http://minio.minio:9000".to_string()),
            force_path_style: Some(true),
        });
        store.spec.storage.cloud_provider_ref = None;

        let bsl = build_bsl("minio", &store);

        assert_eq!(bsl.spec.provider, "aws");
        assert_eq!(
            bsl.spec.config.get("s3Url").unwrap(),
            "http://minio.minio:9000"
        );
        assert_eq!(bsl.spec.config.get("s3ForcePathStyle").unwrap(), "true");
        assert!(bsl.spec.credential.is_none());
        assert_eq!(bsl.spec.default, Some(false));
    }

    #[test]
    fn test_bsl_json_structure() {
        let store = sample_store();
        let bsl = build_bsl("production-s3", &store);
        let json = serde_json::to_value(&bsl).unwrap();

        assert_eq!(json["apiVersion"], "velero.io/v1");
        assert_eq!(json["kind"], "BackupStorageLocation");
        assert_eq!(json["metadata"]["name"], "lattice-production-s3");
        assert_eq!(json["metadata"]["namespace"], "velero");
        assert_eq!(json["spec"]["provider"], "aws");
        assert_eq!(json["spec"]["objectStorage"]["bucket"], "lattice-backups");
    }
}
