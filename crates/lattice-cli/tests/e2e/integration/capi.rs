//! CAPI resource verification integration tests
//!
//! Tests that verify CAPI resources exist and are properly configured
//! after cluster provisioning and pivot.
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_capi_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use tracing::info;

use super::super::context::{init_test_env, InfraContext};
use super::super::helpers::{
    run_cmd, verify_cluster_capi_resources, MGMT_CLUSTER_NAME, WORKLOAD_CLUSTER_NAME,
};

/// Verify CAPI resources exist on management cluster
///
/// Checks that the management cluster has its own CAPI Cluster resource,
/// indicating it is properly self-managing after pivot.
///
/// # Arguments
///
/// * `ctx` - Infrastructure context with management cluster kubeconfig
/// * `cluster_name` - Name of the cluster to verify
pub async fn verify_mgmt_capi_resources(
    ctx: &InfraContext,
    cluster_name: &str,
) -> Result<(), String> {
    info!("[Integration/CAPI] Verifying management cluster CAPI resources...");

    let capi_check = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &ctx.mgmt_kubeconfig,
            "get",
            "clusters",
            "-A",
            "-o",
            "wide",
        ],
    )?;

    info!("[Integration/CAPI] CAPI clusters:\n{}", capi_check);

    if !capi_check.contains(cluster_name) {
        return Err(format!(
            "Management cluster {} should have its own CAPI Cluster resource",
            cluster_name
        ));
    }

    info!(
        "[Integration/CAPI] Management cluster {} has CAPI resources",
        cluster_name
    );
    Ok(())
}

/// Verify CAPI resources on a workload cluster after pivot
///
/// Checks that the workload cluster has its own CAPI Cluster resource,
/// confirming the pivot was successful and the cluster is self-managing.
///
/// # Arguments
///
/// * `ctx` - Infrastructure context (requires workload_kubeconfig)
/// * `cluster_name` - Name of the cluster to verify
pub async fn verify_workload_capi_resources(
    ctx: &InfraContext,
    cluster_name: &str,
) -> Result<(), String> {
    let kubeconfig = ctx.require_workload()?;

    info!("[Integration/CAPI] Verifying workload cluster CAPI resources...");
    verify_cluster_capi_resources(kubeconfig, cluster_name).await?;
    info!(
        "[Integration/CAPI] Workload cluster {} has CAPI resources",
        cluster_name
    );

    Ok(())
}

/// Verify CAPI resources on second workload cluster after pivot
///
/// # Arguments
///
/// * `ctx` - Infrastructure context (requires workload2_kubeconfig)
/// * `cluster_name` - Name of the cluster to verify
pub async fn verify_workload2_capi_resources(
    ctx: &InfraContext,
    cluster_name: &str,
) -> Result<(), String> {
    let kubeconfig = ctx.require_workload2()?;

    info!("[Integration/CAPI] Verifying workload2 cluster CAPI resources...");
    verify_cluster_capi_resources(kubeconfig, cluster_name).await?;
    info!(
        "[Integration/CAPI] Workload2 cluster {} has CAPI resources",
        cluster_name
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

/// Get detailed CAPI cluster info
pub async fn get_capi_cluster_details(
    kubeconfig: &str,
    cluster_name: &str,
) -> Result<String, String> {
    let namespace = format!("capi-{}", cluster_name);

    run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "describe",
            "cluster",
            cluster_name,
            "-n",
            &namespace,
        ],
    )
}

/// Verify CAPI machines are ready
pub async fn verify_capi_machines_ready(
    kubeconfig: &str,
    cluster_name: &str,
    expected_machines: usize,
) -> Result<(), String> {
    let namespace = format!("capi-{}", cluster_name);

    let output = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "get",
            "machines",
            "-n",
            &namespace,
            "-o",
            "jsonpath={range .items[*]}{.status.phase}{\"\\n\"}{end}",
        ],
    )?;

    let running_count = output.lines().filter(|l| *l == "Running").count();

    if running_count < expected_machines {
        return Err(format!(
            "Expected {} running machines, found {}",
            expected_machines, running_count
        ));
    }

    info!(
        "[Integration/CAPI] {} machines running for cluster {}",
        running_count, cluster_name
    );
    Ok(())
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone test - verify CAPI resources on management cluster
///
/// Requires `LATTICE_MGMT_KUBECONFIG` environment variable.
#[tokio::test]
#[ignore]
async fn test_capi_standalone() {
    let ctx = init_test_env("Set LATTICE_MGMT_KUBECONFIG to run standalone CAPI tests");
    let cluster_name = std::env::var("LATTICE_MGMT_CLUSTER_NAME")
        .unwrap_or_else(|_| MGMT_CLUSTER_NAME.to_string());
    verify_mgmt_capi_resources(&ctx, &cluster_name)
        .await
        .unwrap();
}

/// Standalone test - verify CAPI resources on workload cluster
#[tokio::test]
#[ignore]
async fn test_capi_workload_standalone() {
    let ctx = init_test_env("Set LATTICE_WORKLOAD_KUBECONFIG to run standalone CAPI tests");
    let cluster_name = std::env::var("LATTICE_WORKLOAD_CLUSTER_NAME")
        .unwrap_or_else(|_| WORKLOAD_CLUSTER_NAME.to_string());
    verify_workload_capi_resources(&ctx, &cluster_name)
        .await
        .unwrap();
}

/// Standalone test - list all CAPI clusters
#[tokio::test]
#[ignore]
async fn test_list_capi_clusters_standalone() {
    let ctx = init_test_env("Set LATTICE_MGMT_KUBECONFIG to run standalone CAPI tests");
    let clusters = list_capi_clusters(&ctx.mgmt_kubeconfig).await.unwrap();
    println!("CAPI Clusters:\n{}", clusters);
}
