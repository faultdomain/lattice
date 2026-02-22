//! LatticeClusterBackup controller
//!
//! Watches LatticeClusterBackup CRDs and creates Velero Schedule resources.
//! Resolves the referenced BackupStore (or default) for storage location.

use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, ListParams};
use kube::runtime::controller::Action;
use kube::ResourceExt;
use tracing::{debug, info, warn};

use lattice_common::crd::{
    BackupStore, ClusterBackupPhase, LatticeClusterBackup, LatticeClusterBackupStatus,
};
use lattice_common::{ControllerContext, ReconcileError, LATTICE_SYSTEM_NAMESPACE};

use crate::velero::{self, BackupTemplate, Schedule, ScheduleSpec, VELERO_NAMESPACE};

use crate::{REQUEUE_CRD_NOT_FOUND_SECS, REQUEUE_ERROR_SECS, REQUEUE_SUCCESS_SECS};

/// Reconcile a LatticeClusterBackup into a Velero Schedule
pub async fn reconcile(
    backup: Arc<LatticeClusterBackup>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = backup.name_any();
    let client = &ctx.client;
    let namespace = backup
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());

    info!(cluster_backup = %name, "Reconciling LatticeClusterBackup");

    // Resolve BackupStore
    let store_name = match resolve_store(client, &namespace, backup.spec.store_ref.as_deref()).await
    {
        Ok(name) => name,
        Err(msg) => {
            update_status(
                client,
                &backup,
                ClusterBackupPhase::Failed,
                Some(msg),
                None,
                None,
            )
            .await?;
            return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
        }
    };

    let bsl_name = format!("lattice-{}", store_name);
    let schedule = build_schedule(&name, &backup, &bsl_name);

    match velero::apply_resource(client, &schedule, "lattice-cluster-backup-controller").await {
        Ok(()) => {
            debug!(cluster_backup = %name, "Schedule applied");
        }
        Err(e) if e.is_crd_not_found() => {
            warn!(
                cluster_backup = %name,
                "Velero Schedule CRD not found - Velero may not be installed"
            );
            update_status(
                client,
                &backup,
                ClusterBackupPhase::Pending,
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
            warn!(cluster_backup = %name, error = %e, "Failed to apply Schedule");
            update_status(
                client,
                &backup,
                ClusterBackupPhase::Failed,
                Some(format!("Schedule apply failed: {}", e)),
                None,
                None,
            )
            .await?;
            return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
        }
    }

    let phase = if backup.spec.paused {
        ClusterBackupPhase::Paused
    } else {
        ClusterBackupPhase::Active
    };
    let schedule_name = format!("lattice-{}", name);
    update_status(
        client,
        &backup,
        phase,
        Some("Velero Schedule is configured".to_string()),
        Some(schedule_name),
        Some(store_name),
    )
    .await?;

    Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)))
}

/// Resolve a BackupStore by explicit name or find the default.
///
/// When `store_ref` is set, looks up the store in the given namespace.
/// When `store_ref` is None, searches `lattice-system` for a store with
/// `default: true`, since BackupStores are platform-level resources.
pub async fn resolve_store(
    client: &kube::Client,
    namespace: &str,
    store_ref: Option<&str>,
) -> Result<String, String> {
    if let Some(name) = store_ref {
        let api: Api<BackupStore> = Api::namespaced(client.clone(), namespace);
        match api.get(name).await {
            Ok(_) => Ok(name.to_string()),
            Err(e) => Err(format!("BackupStore '{}' not found: {}", name, e)),
        }
    } else {
        let api: Api<BackupStore> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
        match api.list(&ListParams::default()).await {
            Ok(list) => {
                for store in &list.items {
                    if store.spec.default {
                        return Ok(store.name_any());
                    }
                }
                Err("No default BackupStore found (set default: true on a BackupStore)".to_string())
            }
            Err(e) => Err(format!("Failed to list BackupStores: {}", e)),
        }
    }
}

/// Build the desired Velero Schedule from a LatticeClusterBackup
fn build_schedule(name: &str, backup: &LatticeClusterBackup, bsl_name: &str) -> Schedule {
    let schedule_name = format!("lattice-{}", name);

    let included_resources = velero::build_included_resources(
        backup.spec.scope.control_plane,
        backup.spec.scope.gpu_paas_resources,
    );

    let included_namespaces = backup.spec.scope.include_namespaces.clone();
    let excluded_namespaces = backup.spec.scope.exclude_namespaces.clone();
    let ttl = backup.spec.retention.ttl.clone();

    Schedule::new(
        schedule_name,
        VELERO_NAMESPACE,
        ScheduleSpec {
            schedule: backup.spec.schedule.clone(),
            paused: Some(backup.spec.paused),
            template: BackupTemplate {
                ttl,
                included_namespaces,
                excluded_namespaces,
                included_resources,
                excluded_resources: vec![],
                storage_location: Some(bsl_name.to_string()),
                default_volumes_to_fs_backup: None,
                snapshot_volumes: None,
                label_selector: None,
            },
        },
    )
}

async fn update_status(
    client: &kube::Client,
    backup: &LatticeClusterBackup,
    phase: ClusterBackupPhase,
    message: Option<String>,
    velero_schedule_name: Option<String>,
    resolved_store: Option<String>,
) -> Result<(), ReconcileError> {
    if let Some(ref current) = backup.status {
        if current.phase == phase && current.message == message {
            debug!(cluster_backup = %backup.name_any(), "status unchanged, skipping update");
            return Ok(());
        }
    }

    let name = backup.name_any();
    let namespace = backup
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());

    let status = LatticeClusterBackupStatus {
        phase,
        velero_schedule_name,
        resolved_store,
        conditions: vec![],
        message,
        observed_generation: backup.metadata.generation,
    };

    lattice_common::kube_utils::patch_resource_status::<LatticeClusterBackup>(
        client,
        &name,
        &namespace,
        &status,
        "lattice-cluster-backup-controller",
    )
    .await
    .map_err(|e| ReconcileError::kube("status update failed", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{BackupRetentionSpec, BackupScopeSpec, LatticeClusterBackupSpec};

    fn sample_backup() -> LatticeClusterBackup {
        use kube::core::ObjectMeta;

        LatticeClusterBackup {
            metadata: ObjectMeta {
                name: Some("daily-platform".to_string()),
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                ..Default::default()
            },
            spec: LatticeClusterBackupSpec {
                schedule: "0 2 * * *".to_string(),
                store_ref: Some("production-s3".to_string()),
                scope: BackupScopeSpec {
                    control_plane: true,
                    gpu_paas_resources: false,
                    workload_namespaces: None,
                    include_namespaces: vec![],
                    exclude_namespaces: vec![],
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
    fn test_build_schedule() {
        let backup = sample_backup();
        let schedule = build_schedule("daily-platform", &backup, "lattice-production-s3");

        assert_eq!(schedule.metadata.name, "lattice-daily-platform");
        assert_eq!(schedule.metadata.namespace, VELERO_NAMESPACE);
        assert_eq!(schedule.spec.schedule, "0 2 * * *");
        assert_eq!(schedule.spec.paused, Some(false));
        assert_eq!(schedule.spec.template.ttl, Some("720h".to_string()));
        assert_eq!(
            schedule.spec.template.storage_location,
            Some("lattice-production-s3".to_string())
        );
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
        let mut backup = sample_backup();
        backup.spec.paused = true;

        let schedule = build_schedule("daily-platform", &backup, "lattice-production-s3");
        assert_eq!(schedule.spec.paused, Some(true));
    }

    #[test]
    fn test_build_schedule_with_gpu_paas() {
        let mut backup = sample_backup();
        backup.spec.scope.gpu_paas_resources = true;

        let schedule = build_schedule("daily-platform", &backup, "lattice-production-s3");
        assert!(schedule
            .spec
            .template
            .included_resources
            .contains(&"gpupools.lattice.dev".to_string()));
    }

    #[test]
    fn test_schedule_json_structure() {
        let backup = sample_backup();
        let schedule = build_schedule("daily-platform", &backup, "lattice-production-s3");
        let json = serde_json::to_value(&schedule).unwrap();

        assert_eq!(json["apiVersion"], "velero.io/v1");
        assert_eq!(json["kind"], "Schedule");
        assert_eq!(json["metadata"]["name"], "lattice-daily-platform");
        assert_eq!(json["spec"]["schedule"], "0 2 * * *");
        assert_eq!(json["spec"]["template"]["ttl"], "720h");
    }
}
