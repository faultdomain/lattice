//! LatticeRestore controller
//!
//! Watches LatticeRestore CRDs and creates the corresponding Velero Restore resource.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;
use kube::ResourceExt;
use tracing::{debug, info, warn};

use lattice_common::crd::{LatticeRestore, LatticeRestoreStatus, RestorePhase};
use lattice_common::{ControllerContext, ReconcileError, LATTICE_SYSTEM_NAMESPACE};

use crate::velero::{self, VELERO_NAMESPACE};

use crate::{REQUEUE_ERROR_SECS, REQUEUE_IN_PROGRESS_SECS};

/// Reconcile a LatticeRestore
///
/// Creates the corresponding Velero Restore resource.
pub async fn reconcile(
    restore: Arc<LatticeRestore>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = restore.name_any();
    let client = &ctx.client;

    info!(restore = %name, "Reconciling LatticeRestore");

    let current_phase = restore
        .status
        .as_ref()
        .map(|s| s.phase)
        .unwrap_or(RestorePhase::Pending);

    match current_phase {
        RestorePhase::Pending => {
            let velero_restore = build_velero_restore(&name, &restore);
            match velero::apply_resource(client, &velero_restore, "lattice-restore-controller")
                .await
            {
                Ok(()) => {
                    update_status(
                        client,
                        &restore,
                        RestorePhase::InProgress,
                        Some("Velero Restore created".to_string()),
                    )
                    .await?;
                }
                Err(e) => {
                    warn!(restore = %name, error = %e, "Failed to create Velero Restore");
                    update_status(
                        client,
                        &restore,
                        RestorePhase::Failed,
                        Some(format!("Failed to create Velero Restore: {}", e)),
                    )
                    .await?;
                    return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
                }
            }

            Ok(Action::requeue(Duration::from_secs(
                REQUEUE_IN_PROGRESS_SECS,
            )))
        }
        RestorePhase::InProgress => Ok(Action::requeue(Duration::from_secs(
            REQUEUE_IN_PROGRESS_SECS,
        ))),
        RestorePhase::Completed | RestorePhase::Failed => Ok(Action::await_change()),
    }
}

/// Build a Velero Restore from a LatticeRestore
fn build_velero_restore(name: &str, restore: &LatticeRestore) -> velero::Restore {
    velero::Restore::new(
        name,
        VELERO_NAMESPACE,
        velero::RestoreSpec {
            backup_name: restore.spec.backup_name.clone(),
            included_namespaces: vec![],
            excluded_namespaces: vec![],
            included_resources: vec![],
            excluded_resources: vec![],
            restore_pvs: Some(restore.spec.restore_volumes),
        },
    )
}

/// Update LatticeRestore status
async fn update_status(
    client: &kube::Client,
    restore: &LatticeRestore,
    phase: RestorePhase,
    message: Option<String>,
) -> Result<(), ReconcileError> {
    if let Some(ref current) = restore.status {
        if current.phase == phase && current.message == message {
            debug!(restore = %restore.name_any(), "status unchanged, skipping update");
            return Ok(());
        }
    }

    let name = restore.name_any();
    let namespace = restore
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());

    let status = LatticeRestoreStatus {
        phase,
        velero_restore_name: None,
        conditions: vec![],
        message,
        observed_generation: restore.metadata.generation,
    };

    lattice_common::kube_utils::patch_resource_status::<LatticeRestore>(
        client,
        &name,
        &namespace,
        &status,
        "lattice-restore-controller",
    )
    .await
    .map_err(|e| ReconcileError::kube("status update failed", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::LatticeRestoreSpec;

    fn sample_restore() -> LatticeRestore {
        use kube::core::ObjectMeta;

        LatticeRestore {
            metadata: ObjectMeta {
                name: Some("restore-20260205".to_string()),
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                ..Default::default()
            },
            spec: LatticeRestoreSpec {
                backup_name: "lattice-default-20260205020012".to_string(),
                cluster_backup_ref: Some("default".to_string()),
                restore_volumes: true,
            },
            status: None,
        }
    }

    #[test]
    fn test_build_velero_restore() {
        let restore = sample_restore();
        let velero_restore = build_velero_restore("restore-20260205", &restore);

        assert_eq!(velero_restore.metadata.name, "restore-20260205");
        assert_eq!(velero_restore.metadata.namespace, VELERO_NAMESPACE);
        assert_eq!(
            velero_restore.spec.backup_name,
            "lattice-default-20260205020012"
        );
        assert_eq!(velero_restore.spec.restore_pvs, Some(true));
        assert!(velero_restore.spec.included_resources.is_empty());
    }

    #[test]
    fn test_build_velero_restore_json_structure() {
        let restore = sample_restore();
        let velero_restore = build_velero_restore("test-restore", &restore);
        let json = serde_json::to_value(&velero_restore).unwrap();

        assert_eq!(json["apiVersion"], "velero.io/v1");
        assert_eq!(json["kind"], "Restore");
        assert_eq!(json["metadata"]["name"], "test-restore");
        assert_eq!(json["metadata"]["namespace"], "velero");
        assert_eq!(json["spec"]["backupName"], "lattice-default-20260205020012");
    }
}
