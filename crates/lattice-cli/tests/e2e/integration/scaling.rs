//! Worker node scaling integration tests
//!
//! Tests that verify worker nodes scale correctly after cluster provisioning.
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/workload-proxy-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_scaling_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use tracing::info;

use super::super::context::{ClusterLevel, InfraContext, TestSession};
use super::super::helpers::{
    count_ready_nodes, get_workload_cluster_name, run_cmd, watch_worker_scaling,
};
use super::cedar::apply_e2e_default_policy;

/// Verify worker node count on a cluster at the specified level
///
/// Waits for the expected number of worker nodes to be ready.
///
/// # Arguments
///
/// * `ctx` - Infrastructure context
/// * `cluster_name` - Name of the cluster
/// * `expected_workers` - Expected number of ready worker nodes
/// * `level` - Which cluster level to verify (Mgmt, Workload, or Workload2)
pub async fn verify_cluster_workers(
    ctx: &InfraContext,
    cluster_name: &str,
    expected_workers: u32,
    level: ClusterLevel,
) -> Result<(), String> {
    let kubeconfig = ctx.kubeconfig_for(level)?;
    let level_name = level.display_name();

    info!(
        "[Integration/Scaling] Verifying {} workers on {} cluster {}...",
        expected_workers, level_name, cluster_name
    );

    watch_worker_scaling(kubeconfig, cluster_name, expected_workers).await?;

    info!(
        "[Integration/Scaling] {} cluster {} has {} workers",
        level_name, cluster_name, expected_workers
    );
    Ok(())
}

/// Get current worker count for a cluster
pub async fn get_worker_count(kubeconfig: &str) -> Result<u32, String> {
    let output = run_cmd(
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
    )
    .unwrap_or_default();
    Ok(count_ready_nodes(&output))
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
    let output = run_cmd(
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
    )
    .unwrap_or_default();
    Ok(count_ready_nodes(&output))
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
#[tokio::test]
#[ignore]
async fn test_scaling_standalone() {
    let session = TestSession::from_env(
        "Set LATTICE_MGMT_KUBECONFIG and LATTICE_WORKLOAD_KUBECONFIG to run standalone scaling tests",
    )
    .unwrap();
    apply_e2e_default_policy(&session.ctx.mgmt_kubeconfig)
        .await
        .unwrap();
    let cluster_name = get_workload_cluster_name();
    let expected_workers: u32 = std::env::var("LATTICE_EXPECTED_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    verify_cluster_workers(
        &session.ctx,
        &cluster_name,
        expected_workers,
        ClusterLevel::Workload,
    )
    .await
    .unwrap();
}

/// Standalone test - list all nodes
#[tokio::test]
#[ignore]
async fn test_list_nodes_standalone() {
    let session =
        TestSession::from_env("Set LATTICE_MGMT_KUBECONFIG and LATTICE_WORKLOAD_KUBECONFIG")
            .unwrap();
    apply_e2e_default_policy(&session.ctx.mgmt_kubeconfig)
        .await
        .unwrap();
    let kubeconfig = session
        .ctx
        .workload_kubeconfig
        .as_deref()
        .unwrap_or(&session.ctx.mgmt_kubeconfig);
    let nodes = list_nodes(kubeconfig).await.unwrap();
    println!("Nodes:\n{}", nodes);
}
