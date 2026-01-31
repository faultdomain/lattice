//! Worker node scaling integration tests
//!
//! Tests that verify worker nodes scale correctly after cluster provisioning.
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/workload-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_scaling_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use tracing::info;

use super::super::context::{init_test_env, InfraContext};
use super::super::helpers::{
    run_cmd, run_cmd_allow_fail, watch_worker_scaling, WORKLOAD_CLUSTER_NAME,
};

/// Verify worker node count on workload cluster
///
/// Waits for the expected number of worker nodes to be ready.
///
/// # Arguments
///
/// * `ctx` - Infrastructure context (requires workload_kubeconfig)
/// * `cluster_name` - Name of the cluster
/// * `expected_workers` - Expected number of ready worker nodes
pub async fn verify_workers(
    ctx: &InfraContext,
    cluster_name: &str,
    expected_workers: u32,
) -> Result<(), String> {
    let kubeconfig = ctx.require_workload()?;

    info!(
        "[Integration/Scaling] Verifying {} workers on cluster {}...",
        expected_workers, cluster_name
    );

    watch_worker_scaling(kubeconfig, cluster_name, expected_workers).await?;

    info!(
        "[Integration/Scaling] Cluster {} has {} workers",
        cluster_name, expected_workers
    );
    Ok(())
}

/// Verify worker node count on management cluster
pub async fn verify_mgmt_workers(
    ctx: &InfraContext,
    cluster_name: &str,
    expected_workers: u32,
) -> Result<(), String> {
    info!(
        "[Integration/Scaling] Verifying {} workers on management cluster {}...",
        expected_workers, cluster_name
    );

    watch_worker_scaling(&ctx.mgmt_kubeconfig, cluster_name, expected_workers).await?;

    info!(
        "[Integration/Scaling] Management cluster {} has {} workers",
        cluster_name, expected_workers
    );
    Ok(())
}

/// Get current worker count for a cluster
pub async fn get_worker_count(kubeconfig: &str) -> Result<u32, String> {
    let nodes_output = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "get",
            "nodes",
            "-l",
            "!node-role.kubernetes.io/control-plane",
            "-o",
            "jsonpath={range .items[*]}{.status.conditions[?(@.type=='Ready')].status}{\"\\n\"}{end}",
        ],
    );

    let ready_workers = nodes_output.lines().filter(|line| *line == "True").count() as u32;
    Ok(ready_workers)
}

/// List all nodes with their status
pub async fn list_nodes(kubeconfig: &str) -> Result<String, String> {
    run_cmd(
        "kubectl",
        &["--kubeconfig", kubeconfig, "get", "nodes", "-o", "wide"],
    )
}

/// Get control plane node count
pub async fn get_control_plane_count(kubeconfig: &str) -> Result<u32, String> {
    let nodes_output = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "get",
            "nodes",
            "-l",
            "node-role.kubernetes.io/control-plane",
            "-o",
            "jsonpath={range .items[*]}{.status.conditions[?(@.type=='Ready')].status}{\"\\n\"}{end}",
        ],
    );

    let ready_cp = nodes_output.lines().filter(|line| *line == "True").count() as u32;
    Ok(ready_cp)
}

/// Verify total node count (control plane + workers)
pub async fn verify_total_nodes(kubeconfig: &str, expected_total: u32) -> Result<(), String> {
    let workers = get_worker_count(kubeconfig).await?;
    let cp = get_control_plane_count(kubeconfig).await?;
    let total = workers + cp;

    if total < expected_total {
        return Err(format!(
            "Expected {} total nodes, found {} ({} control plane, {} workers)",
            expected_total, total, cp, workers
        ));
    }

    info!(
        "[Integration/Scaling] Total nodes: {} ({} control plane, {} workers)",
        total, cp, workers
    );
    Ok(())
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone test - verify worker scaling on workload cluster
///
/// Requires `LATTICE_WORKLOAD_KUBECONFIG` environment variable.
#[tokio::test]
#[ignore]
async fn test_scaling_standalone() {
    let ctx = init_test_env("Set LATTICE_WORKLOAD_KUBECONFIG to run standalone scaling tests");
    let cluster_name = std::env::var("LATTICE_WORKLOAD_CLUSTER_NAME")
        .unwrap_or_else(|_| WORKLOAD_CLUSTER_NAME.to_string());
    let expected_workers: u32 = std::env::var("LATTICE_EXPECTED_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    verify_workers(&ctx, &cluster_name, expected_workers)
        .await
        .unwrap();
}

/// Standalone test - list all nodes
#[tokio::test]
#[ignore]
async fn test_list_nodes_standalone() {
    let ctx = init_test_env("Set LATTICE_MGMT_KUBECONFIG or LATTICE_WORKLOAD_KUBECONFIG");
    let kubeconfig = ctx
        .workload_kubeconfig
        .as_deref()
        .unwrap_or(&ctx.mgmt_kubeconfig);
    let nodes = list_nodes(kubeconfig).await.unwrap();
    println!("Nodes:\n{}", nodes);
}
