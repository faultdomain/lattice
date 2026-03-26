//! Pivot/unpivot integration tests
//!
//! Deletion is a destructive, non-repeatable operation — there are no standalone
//! tests. Both deletion paths (child-initiated and parent-initiated) are covered
//! by the unified E2E test (Phase 8 and Phase 8c).

#![cfg(feature = "provider-e2e")]

use tracing::info;

use super::super::helpers::delete_cluster_and_wait;
use super::super::providers::InfraProvider;

/// Delete a cluster from the child side and verify CAPI resources unpivot to parent.
pub async fn delete_and_verify_unpivot(
    child_kubeconfig: &str,
    parent_kubeconfig: &str,
    cluster_name: &str,
    provider: InfraProvider,
) -> Result<(), String> {
    info!(
        "[Integration/Pivot] Deleting cluster {} (unpivot to parent)...",
        cluster_name
    );
    info!("[Integration/Pivot] CAPI resources will move back to parent cluster");

    delete_cluster_and_wait(child_kubeconfig, parent_kubeconfig, cluster_name, provider).await?;

    info!(
        "[Integration/Pivot] Cluster {} deleted and unpivoted successfully",
        cluster_name
    );
    Ok(())
}
