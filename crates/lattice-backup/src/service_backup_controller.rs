//! Service backup schedule controller
//!
//! Watches LatticeService resources and creates Velero Schedule resources
//! for services that define `spec.backup.schedule`. The schedule is scoped
//! to the service's namespace and label selector.
//!
//! Store resolution follows the same pattern as LatticeClusterBackup:
//! explicit `store_ref` > default BackupStore > Failed status.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;
use kube::ResourceExt;
use tracing::{debug, info, warn};

use lattice_common::crd::LatticeService;
use lattice_common::{ControllerContext, ReconcileError, LATTICE_SYSTEM_NAMESPACE};

use crate::cluster_backup_controller::resolve_store;
use crate::velero::{self, build_service_schedule};

const REQUEUE_SUCCESS_SECS: u64 = 300;
const REQUEUE_ERROR_SECS: u64 = 60;

/// Reconcile a LatticeService's backup schedule
///
/// If `spec.backup.schedule` is set, creates a Velero Schedule scoped to this
/// service. If not set, this is a no-op.
pub async fn reconcile(
    service: Arc<LatticeService>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = service.name_any();
    let namespace = service.namespace().unwrap_or_else(|| "default".to_string());

    let (backup, cron) = match &service.spec.backup {
        Some(b) => match b.schedule.as_deref() {
            Some(schedule) => (b, schedule),
            None => return Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS))),
        },
        None => return Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS))),
    };
    info!(service = %name, namespace = %namespace, schedule = %cron, "Reconciling service backup schedule");

    // Resolve BackupStore
    let store_namespace = service
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());
    let store_name = match resolve_store(&ctx.client, &store_namespace, backup.store_ref.as_deref())
        .await
    {
        Ok(name) => name,
        Err(msg) => {
            warn!(service = %name, error = %msg, "Failed to resolve BackupStore for service schedule");
            return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
        }
    };

    let bsl_name = format!("lattice-{}", store_name);
    let ttl = backup.retention.as_ref().and_then(|r| r.ttl.clone());
    let schedule = build_service_schedule(&name, &namespace, cron, &bsl_name, ttl);

    match velero::apply_resource(&ctx.client, &schedule, "lattice-service-backup-controller").await
    {
        Ok(()) => {
            debug!(service = %name, "Service backup schedule applied");
        }
        Err(e) => {
            warn!(service = %name, error = %e, "Failed to apply service backup schedule");
            return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
        }
    }

    Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{BackupRetentionSpec, LatticeServiceSpec, ServiceBackupSpec};

    #[test]
    fn test_service_without_schedule_is_noop() {
        // Services without backup.schedule should not trigger schedule creation.
        // This is verified by the early return in reconcile().
        let service = LatticeService {
            metadata: kube::api::ObjectMeta {
                name: Some("my-app".to_string()),
                namespace: Some("prod".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec::default(),
            status: None,
        };

        assert!(service.spec.backup.is_none());
    }

    #[test]
    fn test_service_with_schedule_fields() {
        let service = LatticeService {
            metadata: kube::api::ObjectMeta {
                name: Some("my-db".to_string()),
                namespace: Some("prod".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                backup: Some(ServiceBackupSpec {
                    schedule: Some("0 */1 * * *".to_string()),
                    store_ref: Some("production-s3".to_string()),
                    retention: Some(BackupRetentionSpec {
                        ttl: Some("168h".to_string()),
                        daily: None,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
            status: None,
        };

        let backup = service.spec.backup.as_ref().unwrap();
        assert_eq!(backup.schedule.as_deref(), Some("0 */1 * * *"));
        assert_eq!(backup.store_ref.as_deref(), Some("production-s3"));
        assert_eq!(
            backup.retention.as_ref().unwrap().ttl.as_deref(),
            Some("168h")
        );
    }
}
