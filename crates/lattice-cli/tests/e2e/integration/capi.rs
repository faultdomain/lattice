//! CAPI resource verification integration tests
//!
//! Tests that verify CAPI resources exist and are properly configured
//! after cluster provisioning and pivot.
//!
//! # Running Standalone
//!
//! ```bash
//! # Mgmt cluster (direct access)
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_capi_standalone -- --ignored --nocapture
//!
//! # Workload cluster (through proxy)
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/workload-proxy-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_capi_workload_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use tracing::info;

use super::super::context::{ClusterLevel, InfraContext, TestSession};
use super::super::helpers::{
    get_mgmt_cluster_name, get_workload_cluster_name, run_cmd, verify_cluster_capi_resources,
};
use super::cedar::apply_e2e_default_policy;

/// Verify CAPI resources exist on a cluster at the specified level
///
/// Checks that the cluster has its own CAPI Cluster resource,
/// indicating it is properly self-managing after pivot.
///
/// # Arguments
///
/// * `ctx` - Infrastructure context
/// * `cluster_name` - Name of the cluster to verify
/// * `level` - Which cluster level to verify (Mgmt, Workload, or Workload2)
pub async fn verify_capi_resources(
    ctx: &InfraContext,
    cluster_name: &str,
    level: ClusterLevel,
) -> Result<(), String> {
    let kubeconfig = ctx.kubeconfig_for(level)?;
    let level_name = level.display_name();

    info!(
        "[Integration/CAPI] Verifying {} cluster CAPI resources...",
        level_name
    );
    verify_cluster_capi_resources(kubeconfig, cluster_name).await?;
    info!(
        "[Integration/CAPI] {} cluster {} has CAPI resources",
        level_name, cluster_name
    );

    Ok(())
}

/// List all CAPI clusters visible from a kubeconfig
pub async fn list_capi_clusters(kubeconfig: &str) -> Result<String, String> {
    run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "get",
            "clusters",
            "-A",
            "-o",
            "wide",
        ],
    )
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone test - verify CAPI resources on management cluster
#[tokio::test]
#[ignore]
async fn test_capi_standalone() {
    let session =
        TestSession::from_env("Set LATTICE_MGMT_KUBECONFIG to run standalone CAPI tests").unwrap();
    let cluster_name = get_mgmt_cluster_name();
    verify_capi_resources(&session.ctx, &cluster_name, ClusterLevel::Mgmt)
        .await
        .unwrap();
}

/// Standalone test - verify CAPI resources on workload cluster
#[tokio::test]
#[ignore]
async fn test_capi_workload_standalone() {
    let session = TestSession::from_env(
        "Set LATTICE_MGMT_KUBECONFIG and LATTICE_WORKLOAD_KUBECONFIG to run standalone CAPI tests",
    )
    .unwrap();
    apply_e2e_default_policy(&session.ctx.mgmt_kubeconfig)
        .await
        .unwrap();
    let cluster_name = get_workload_cluster_name();
    verify_capi_resources(&session.ctx, &cluster_name, ClusterLevel::Workload)
        .await
        .unwrap();
}

/// Standalone test - list all CAPI clusters
///
/// Uses TestSession for consistent test initialization.
#[tokio::test]
#[ignore]
async fn test_list_capi_clusters_standalone() {
    let session =
        TestSession::from_env("Set LATTICE_MGMT_KUBECONFIG to run standalone CAPI tests").unwrap();
    let clusters = list_capi_clusters(&session.ctx.mgmt_kubeconfig)
        .await
        .unwrap();
    println!("CAPI Clusters:\n{}", clusters);
}
