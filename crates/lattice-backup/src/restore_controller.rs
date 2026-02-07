//! LatticeRestore controller
//!
//! Watches LatticeRestore CRDs and creates the corresponding Velero Restore
//! resources. Supports LatticeAware ordering which creates two sequential
//! Velero Restores: dependencies first, then everything else.

use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::ResourceExt;
use tracing::{info, warn};

use lattice_common::crd::{LatticeRestore, LatticeRestoreStatus, RestoreOrdering, RestorePhase};
use lattice_common::{ControllerContext, ReconcileError, LATTICE_SYSTEM_NAMESPACE};

use crate::velero::{self, VELERO_NAMESPACE};

/// Requeue interval while restore is in progress
const REQUEUE_IN_PROGRESS_SECS: u64 = 15;
/// Requeue interval on error
const REQUEUE_ERROR_SECS: u64 = 60;

/// Dependency resources that must be restored first (LatticeAware ordering)
const DEPENDENCY_RESOURCES: &[&str] = &[
    "customresourcedefinitions.apiextensions.k8s.io",
    "namespaces",
    "secrets",
    "cloudproviders.lattice.dev",
    "cedarpolicies.lattice.dev",
    "secretsproviders.lattice.dev",
    "gpupools.lattice.dev",
    "gputenantquotas.lattice.dev",
];

/// Reconcile a LatticeRestore
///
/// Creates the corresponding Velero Restore resource(s).
/// For LatticeAware ordering, creates two sequential restores.
pub async fn reconcile(
    restore: Arc<LatticeRestore>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = restore.name_any();
    let client = &ctx.client;

    info!(restore = %name, "Reconciling LatticeRestore");

    // Check current phase
    let current_phase = restore
        .status
        .as_ref()
        .map(|s| s.phase.clone())
        .unwrap_or(RestorePhase::Pending);

    match current_phase {
        RestorePhase::Pending => {
            // Start the restore process
            match restore.spec.ordering {
                RestoreOrdering::VeleroDefault => {
                    // Single Velero Restore
                    let velero_restore = build_velero_restore(&name, &restore, None);
                    match velero::apply_resource(
                        client,
                        &velero_restore,
                        "lattice-restore-controller",
                    )
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
                }
                RestoreOrdering::LatticeAware => {
                    // Phase 1: Restore dependencies only
                    let deps_restore = build_velero_restore(
                        &name,
                        &restore,
                        Some(DEPENDENCY_RESOURCES.iter().map(|s| s.to_string()).collect()),
                    );
                    match velero::apply_resource(
                        client,
                        &deps_restore,
                        "lattice-restore-controller",
                    )
                    .await
                    {
                        Ok(()) => {
                            update_status(
                                client,
                                &restore,
                                RestorePhase::InProgress,
                                Some("Phase 1: Restoring dependencies".to_string()),
                            )
                            .await?;
                        }
                        Err(e) => {
                            warn!(restore = %name, error = %e, "Failed to create dependencies restore");
                            update_status(
                                client,
                                &restore,
                                RestorePhase::Failed,
                                Some(format!("Failed: {}", e)),
                            )
                            .await?;
                            return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
                        }
                    }
                }
            }

            Ok(Action::requeue(Duration::from_secs(
                REQUEUE_IN_PROGRESS_SECS,
            )))
        }
        RestorePhase::InProgress => {
            // Check if the Velero Restore has completed
            // In a real implementation, we'd poll the Velero Restore status
            // For now, requeue to check again
            Ok(Action::requeue(Duration::from_secs(
                REQUEUE_IN_PROGRESS_SECS,
            )))
        }
        RestorePhase::DependenciesRestored => {
            // Phase 2 of LatticeAware: Restore everything else
            let all_restore = build_velero_restore(
                &format!("{}-phase2", name),
                &restore,
                None, // All resources
            );
            match velero::apply_resource(client, &all_restore, "lattice-restore-controller").await {
                Ok(()) => {
                    update_status(
                        client,
                        &restore,
                        RestorePhase::InProgress,
                        Some("Phase 2: Restoring remaining resources".to_string()),
                    )
                    .await?;
                }
                Err(e) => {
                    warn!(restore = %name, error = %e, "Failed to create phase 2 restore");
                    update_status(
                        client,
                        &restore,
                        RestorePhase::Failed,
                        Some(format!("Phase 2 failed: {}", e)),
                    )
                    .await?;
                    return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
                }
            }
            Ok(Action::requeue(Duration::from_secs(
                REQUEUE_IN_PROGRESS_SECS,
            )))
        }
        RestorePhase::Completed | RestorePhase::Failed => {
            // Terminal states - no further action needed
            Ok(Action::await_change())
        }
    }
}

/// Build a Velero Restore from a LatticeRestore
fn build_velero_restore(
    name: &str,
    restore: &LatticeRestore,
    included_resources: Option<Vec<String>>,
) -> velero::Restore {
    velero::Restore::new(
        name,
        VELERO_NAMESPACE,
        velero::RestoreSpec {
            backup_name: restore.spec.backup_name.clone(),
            included_namespaces: vec![],
            excluded_namespaces: vec![],
            included_resources: included_resources.unwrap_or_default(),
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
    let name = restore.name_any();
    let namespace = restore
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());

    let status = LatticeRestoreStatus {
        phase,
        velero_restore_name: None,
        velero_restore_phase2_name: None,
        conditions: vec![],
        message,
        observed_generation: restore.metadata.generation,
    };

    let patch = serde_json::json!({ "status": status });
    let api: Api<LatticeRestore> = Api::namespaced(client.clone(), &namespace);
    api.patch_status(
        &name,
        &PatchParams::apply("lattice-restore-controller"),
        &Patch::Merge(&patch),
    )
    .await
    .map_err(|e| ReconcileError::Kube(format!("status update failed: {}", e)))?;

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
                backup_policy_ref: Some("default".to_string()),
                restore_volumes: true,
                ordering: RestoreOrdering::LatticeAware,
            },
            status: None,
        }
    }

    #[test]
    fn test_build_velero_restore_default() {
        let restore = sample_restore();
        let velero_restore = build_velero_restore("restore-20260205", &restore, None);

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
    fn test_build_velero_restore_with_resources() {
        let restore = sample_restore();
        let resources = DEPENDENCY_RESOURCES.iter().map(|s| s.to_string()).collect();
        let velero_restore =
            build_velero_restore("restore-20260205-deps", &restore, Some(resources));

        assert_eq!(velero_restore.metadata.name, "restore-20260205-deps");
        assert!(!velero_restore.spec.included_resources.is_empty());
        assert!(velero_restore
            .spec
            .included_resources
            .contains(&"namespaces".to_string()));
        assert!(velero_restore
            .spec
            .included_resources
            .contains(&"cloudproviders.lattice.dev".to_string()));
    }

    #[test]
    fn test_build_velero_restore_json_structure() {
        let restore = sample_restore();
        let velero_restore = build_velero_restore("test-restore", &restore, None);
        let json = serde_json::to_value(&velero_restore).unwrap();

        assert_eq!(json["apiVersion"], "velero.io/v1");
        assert_eq!(json["kind"], "Restore");
        assert_eq!(json["metadata"]["name"], "test-restore");
        assert_eq!(json["metadata"]["namespace"], "velero");
        assert_eq!(json["spec"]["backupName"], "lattice-default-20260205020012");
    }

    #[test]
    fn test_dependency_resources_list() {
        assert!(DEPENDENCY_RESOURCES.contains(&"namespaces"));
        assert!(DEPENDENCY_RESOURCES.contains(&"secrets"));
        assert!(DEPENDENCY_RESOURCES.contains(&"cloudproviders.lattice.dev"));
        assert!(DEPENDENCY_RESOURCES.contains(&"cedarpolicies.lattice.dev"));
        assert!(!DEPENDENCY_RESOURCES.contains(&"latticeservices.lattice.dev"));
    }
}
