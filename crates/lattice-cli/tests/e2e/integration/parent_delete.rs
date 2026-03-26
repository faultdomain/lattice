//! Parent-initiated cluster deletion integration test.
//!
//! Verifies that deleting a LatticeCluster from the parent triggers the
//! full unpivot flow: parent sends DeleteCluster via gRPC, child
//! self-deletes, unpivot sends CAPI back, parent tears down infrastructure.
//!
//! Deletion is destructive and non-repeatable — there are no standalone tests.
//! This is exercised by the unified E2E test (Phase 8c).

#![cfg(feature = "provider-e2e")]

use tracing::info;

use super::super::helpers::delete_cluster_from_parent;
use super::super::providers::InfraProvider;

/// Delete a cluster from the parent and verify the full unpivot lifecycle.
pub async fn delete_from_parent_and_verify(
    parent_kubeconfig: &str,
    cluster_name: &str,
    provider: InfraProvider,
) -> Result<(), String> {
    info!(
        "[Integration/ParentDelete] Deleting cluster {} from parent...",
        cluster_name
    );

    delete_cluster_from_parent(parent_kubeconfig, cluster_name, provider).await?;

    info!(
        "[Integration/ParentDelete] Cluster {} deleted from parent successfully",
        cluster_name
    );
    Ok(())
}
