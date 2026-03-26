//! Pivot/unpivot integration tests
//!
//! Tests that verify the pivot and unpivot flows work correctly.
//! The unpivot flow moves CAPI resources back to the parent cluster
//! when a child cluster is deleted.
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/workload-kubeconfig \
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_unpivot_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use tracing::info;

use super::super::context::TestSession;
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

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone test — requires manual setup and teardown.
///
/// WARNING: This test deletes a cluster! Only run if you understand the implications.
///
/// Requires:
/// - `LATTICE_WORKLOAD_KUBECONFIG`: Cluster to delete
/// - `LATTICE_MGMT_KUBECONFIG`: Parent cluster
/// - `LATTICE_CLUSTER_TO_DELETE`: Name of cluster to delete
#[tokio::test]
#[ignore]
async fn test_unpivot_standalone() {
    let Ok(session) = TestSession::from_env(
        "Set LATTICE_MGMT_KUBECONFIG and LATTICE_WORKLOAD_KUBECONFIG for unpivot test",
    )
    .await
    else {
        eprintln!("Skipping: requires LATTICE_MGMT_KUBECONFIG + LATTICE_WORKLOAD_KUBECONFIG (multi-cluster test)");
        return;
    };
    let cluster_name =
        std::env::var("LATTICE_CLUSTER_TO_DELETE").expect("LATTICE_CLUSTER_TO_DELETE must be set");

    println!(
        "WARNING: This will delete cluster '{}'. Press Ctrl+C within 5s to abort.",
        cluster_name
    );
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let workload_kubeconfig = session.ctx.require_workload().unwrap();
    delete_and_verify_unpivot(
        workload_kubeconfig,
        &session.ctx.mgmt_kubeconfig,
        &cluster_name,
        session.ctx.provider,
    )
    .await
    .unwrap();
}
