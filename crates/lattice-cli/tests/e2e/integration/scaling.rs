//! Worker node scaling integration tests
//!
//! Tests that verify worker nodes scale correctly after cluster provisioning.
//!
//! # Running Standalone
//!
//! ```bash
//! # Direct access
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_scaling_standalone -- --ignored --nocapture
//!
//! # Or via proxy
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/workload-proxy-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_scaling_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use tracing::info;

use super::super::helpers::{
    count_ready_nodes, get_workload_cluster_name, run_kubectl, watch_worker_scaling,
};

/// Verify worker node count on a cluster
///
/// Waits for the expected number of worker nodes to be ready.
///
/// # Arguments
///
/// * `kubeconfig` - Path to kubeconfig for the target cluster
/// * `cluster_name` - Name of the cluster
/// * `expected_workers` - Expected number of ready worker nodes
pub async fn verify_cluster_workers(
    kubeconfig: &str,
    cluster_name: &str,
    expected_workers: u32,
) -> Result<(), String> {
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

/// Get current worker count for a cluster
pub async fn get_worker_count(kubeconfig: &str) -> Result<u32, String> {
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "nodes",
        "-l",
        "!node-role.kubernetes.io/control-plane",
        "-o",
        "jsonpath={range .items[*]}{.status.conditions[?(@.type=='Ready')].status}{\"\\n\"}{end}",
    ])
    .await
    .unwrap_or_default();
    Ok(count_ready_nodes(&output))
}

/// List all nodes with their status
pub async fn list_nodes(kubeconfig: &str) -> Result<String, String> {
    run_kubectl(&["--kubeconfig", kubeconfig, "get", "nodes", "-o", "wide"]).await
}

/// Get control plane node count
pub async fn get_control_plane_count(kubeconfig: &str) -> Result<u32, String> {
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "nodes",
        "-l",
        "node-role.kubernetes.io/control-plane",
        "-o",
        "jsonpath={range .items[*]}{.status.conditions[?(@.type=='Ready')].status}{\"\\n\"}{end}",
    ])
    .await
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
///
/// Uses `LATTICE_KUBECONFIG` for direct access, or falls back to
/// `LATTICE_MGMT_KUBECONFIG` + `LATTICE_WORKLOAD_KUBECONFIG` with proxy + Cedar policy.
#[tokio::test]
#[ignore]
async fn test_scaling_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    let cluster_name = get_workload_cluster_name();
    let expected_workers: u32 = std::env::var("LATTICE_EXPECTED_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);

    verify_cluster_workers(&resolved.kubeconfig, &cluster_name, expected_workers)
        .await
        .unwrap();
}

/// Standalone test - list all nodes
#[tokio::test]
#[ignore]
async fn test_list_nodes_standalone() {
    use super::super::context::{init_e2e_test, standalone_kubeconfig};

    init_e2e_test();
    let kubeconfig = standalone_kubeconfig().expect("Set LATTICE_KUBECONFIG to list nodes");
    let nodes = list_nodes(&kubeconfig).await.unwrap();
    println!("Nodes:\n{}", nodes);
}
