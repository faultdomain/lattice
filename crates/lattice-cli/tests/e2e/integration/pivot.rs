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

use super::super::context::{InfraContext, TestSession};
use super::super::helpers::{delete_cluster_and_wait, watch_cluster_phases};
use super::super::providers::InfraProvider;

/// Delete a cluster and verify CAPI resources unpivot to parent
///
/// This initiates deletion on the child cluster and waits for:
/// 1. LatticeCluster to be deleted from parent
/// 2. CAPI resources to move back to parent
/// 3. Infrastructure to be cleaned up
///
/// # Arguments
///
/// * `child_kubeconfig` - Kubeconfig for the cluster being deleted
/// * `parent_kubeconfig` - Kubeconfig for the parent cluster receiving CAPI resources
/// * `cluster_name` - Name of the cluster to delete
/// * `provider` - Infrastructure provider (affects cleanup verification)
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

/// Delete workload cluster and verify unpivot to management
pub async fn delete_workload_and_verify_unpivot(
    ctx: &InfraContext,
    cluster_name: &str,
) -> Result<(), String> {
    let workload_kubeconfig = ctx.require_workload()?;

    delete_and_verify_unpivot(
        workload_kubeconfig,
        &ctx.mgmt_kubeconfig,
        cluster_name,
        ctx.provider,
    )
    .await
}

/// Watch a LatticeCluster and wait for it to reach Ready state
///
/// # Arguments
///
/// * `client` - Kubernetes client connected to the cluster hosting the LatticeCluster
/// * `cluster_name` - Name of the cluster to watch
/// * `timeout_secs` - Optional timeout in seconds (defaults to 30 minutes)
pub async fn wait_for_cluster_ready(
    client: &kube::Client,
    cluster_name: &str,
    timeout_secs: Option<u64>,
) -> Result<(), String> {
    info!(
        "[Integration/Pivot] Waiting for LatticeCluster {} to be Ready...",
        cluster_name
    );

    watch_cluster_phases(client, cluster_name, timeout_secs).await?;

    info!(
        "[Integration/Pivot] LatticeCluster {} is Ready",
        cluster_name
    );
    Ok(())
}

/// Start cluster deletion in background
///
/// Returns a join handle that can be awaited to wait for deletion completion.
pub fn start_cluster_deletion_async(
    child_kubeconfig: String,
    parent_kubeconfig: String,
    cluster_name: String,
    provider: InfraProvider,
) -> tokio::task::JoinHandle<Result<(), String>> {
    tokio::spawn(async move {
        delete_and_verify_unpivot(
            &child_kubeconfig,
            &parent_kubeconfig,
            &cluster_name,
            provider,
        )
        .await
    })
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone test - this test requires manual setup and teardown
///
/// WARNING: This test deletes a cluster! Only run if you understand the implications.
///
/// Requires:
/// - `LATTICE_WORKLOAD_KUBECONFIG`: Cluster to delete
/// - `LATTICE_MGMT_KUBECONFIG`: Parent cluster
/// - `LATTICE_CLUSTER_TO_DELETE`: Name of cluster to delete
///
/// Uses TestSession for consistent test initialization.
#[tokio::test]
#[ignore]
async fn test_unpivot_standalone() {
    let session = TestSession::from_env(
        "Set LATTICE_MGMT_KUBECONFIG and LATTICE_WORKLOAD_KUBECONFIG for unpivot test",
    )
    .unwrap();
    let cluster_name =
        std::env::var("LATTICE_CLUSTER_TO_DELETE").expect("LATTICE_CLUSTER_TO_DELETE must be set");

    println!(
        "WARNING: This will delete cluster '{}'. Press Ctrl+C within 5s to abort.",
        cluster_name
    );
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    delete_workload_and_verify_unpivot(&session.ctx, &cluster_name)
        .await
        .unwrap();
}
