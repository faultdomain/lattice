//! Mesh integration tests - run against existing cluster
//!
//! Tests the bilateral agreement pattern for service mesh policies.
//! Can be run standalone against an existing cluster or composed by E2E tests.
//!
//! # Running Standalone
//!
//! ```bash
//! # Direct access (simplest)
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_mesh_standalone -- --ignored --nocapture
//!
//! # Or via proxy (applies Cedar policy automatically)
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/workload-proxy-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_mesh_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use tracing::info;

use super::super::mesh_random::run_random_mesh_test;
use super::super::mesh_tests::run_mesh_test;

/// Run all mesh bilateral agreement tests
///
/// This runs both the fixed 10-service test and the randomized large-scale test.
///
/// # Arguments
///
/// * `kubeconfig` - Path to kubeconfig for the target cluster
///
/// # Tests Run
///
/// 1. Fixed 10-service bilateral agreement test (includes wildcard service)
/// 2. Randomized large-scale mesh test (10-20 services)
pub async fn run_mesh_tests(kubeconfig: &str) -> Result<(), String> {
    info!(
        "[Integration/Mesh] Running mesh tests on cluster at {}",
        kubeconfig
    );

    // Run deterministic mesh test
    info!("[Integration/Mesh] Running fixed 10-service bilateral agreement test...");
    run_mesh_test(kubeconfig).await?;
    info!("[Integration/Mesh] Fixed mesh test passed!");

    // Run randomized mesh test
    info!("[Integration/Mesh] Running randomized large-scale mesh test...");
    run_random_mesh_test(kubeconfig).await?;
    info!("[Integration/Mesh] Random mesh test passed!");

    info!("[Integration/Mesh] All mesh tests passed!");
    Ok(())
}

/// Check if mesh tests should be enabled based on environment
pub fn mesh_tests_enabled() -> bool {
    std::env::var("LATTICE_ENABLE_MESH_TEST")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true) // Enabled by default
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone test - run mesh tests on existing cluster
///
/// Uses `LATTICE_KUBECONFIG` for direct access, or falls back to
/// `LATTICE_MGMT_KUBECONFIG` + `LATTICE_WORKLOAD_KUBECONFIG` with proxy + Cedar policy.
#[tokio::test]
#[ignore]
async fn test_mesh_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_mesh_tests(&resolved.kubeconfig).await.unwrap();
}
