//! Mesh integration tests - run against existing cluster
//!
//! Tests the bilateral agreement pattern for service mesh policies.
//! Can be run standalone against an existing cluster or composed by E2E tests.
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/workload-proxy-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_mesh_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use tracing::info;

use super::super::context::{InfraContext, TestSession};
use super::super::mesh_tests::{run_mesh_test, run_random_mesh_test, start_mesh_test};
use super::super::providers::InfraProvider;
use super::cedar::apply_e2e_default_policy;

/// Run all mesh bilateral agreement tests
///
/// This runs both the fixed 10-service test and the randomized large-scale test.
///
/// # Requirements
///
/// - `workload_kubeconfig` must be set in InfraContext
///
/// # Tests Run
///
/// 1. Fixed 10-service bilateral agreement test (includes wildcard service)
/// 2. Randomized large-scale mesh test (10-20 services)
pub async fn run_mesh_tests(ctx: &InfraContext) -> Result<(), String> {
    let kubeconfig = ctx.require_workload()?;

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

/// Run only the fixed 10-service mesh test
pub async fn run_fixed_mesh_test(ctx: &InfraContext) -> Result<(), String> {
    let kubeconfig = ctx.require_workload()?;
    info!(
        "[Integration/Mesh] Running fixed mesh test on {}",
        kubeconfig
    );
    run_mesh_test(kubeconfig).await
}

/// Run only the randomized mesh test
pub async fn run_randomized_mesh_test(ctx: &InfraContext) -> Result<(), String> {
    let kubeconfig = ctx.require_workload()?;
    info!(
        "[Integration/Mesh] Running random mesh test on {}",
        kubeconfig
    );
    run_random_mesh_test(kubeconfig).await
}

/// Start mesh tests in background and return a handle
///
/// Use this when you want to run mesh tests concurrently with other operations.
/// The returned handle can be used to wait for completion and get results.
///
/// If `is_docker` is true, also runs the media server test.
pub async fn start_mesh_tests_async(
    ctx: &InfraContext,
    is_docker: bool,
) -> Result<tokio::task::JoinHandle<Result<(), String>>, String> {
    let kubeconfig = ctx.require_workload()?.to_string();

    let handle = tokio::spawn(async move {
        info!("[Integration/Mesh] Running service mesh tests in background...");

        // Run all mesh tests in parallel (including media server for Docker)
        if is_docker {
            let (r1, r2, r3) = tokio::join!(
                run_mesh_test(&kubeconfig),
                run_random_mesh_test(&kubeconfig),
                super::super::media_server_e2e::run_media_server_test(&kubeconfig)
            );
            r1?;
            r2?;
            r3?;
        } else {
            let (r1, r2) = tokio::join!(
                run_mesh_test(&kubeconfig),
                run_random_mesh_test(&kubeconfig)
            );
            r1?;
            r2?;
        }

        info!("[Integration/Mesh] All background mesh tests complete!");
        Ok(())
    });

    Ok(handle)
}

/// Start mesh test and return handle for later verification
///
/// This starts traffic generators but doesn't wait for completion.
/// Call `stop_and_verify()` on the returned handle when ready to verify results.
pub async fn start_mesh_test_with_handle(
    ctx: &InfraContext,
) -> Result<super::super::mesh_tests::MeshTestHandle, String> {
    let kubeconfig = ctx.require_workload()?;
    info!("[Integration/Mesh] Starting mesh test (will verify later)...");
    start_mesh_test(kubeconfig).await
}

/// Check if mesh tests should be enabled based on environment
pub fn mesh_tests_enabled() -> bool {
    std::env::var("LATTICE_ENABLE_MESH_TEST")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true) // Enabled by default
}

/// Helper to determine if provider is Docker
pub fn is_docker_provider(ctx: &InfraContext) -> bool {
    ctx.provider == InfraProvider::Docker
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone test - run mesh tests on existing cluster
///
/// Applies Cedar policy, then runs mesh tests through the proxy.
#[tokio::test]
#[ignore]
async fn test_mesh_standalone() {
    let session =
        TestSession::from_env("Set LATTICE_MGMT_KUBECONFIG and LATTICE_WORKLOAD_KUBECONFIG")
            .unwrap();
    apply_e2e_default_policy(&session.ctx.mgmt_kubeconfig)
        .await
        .unwrap();
    run_mesh_tests(&session.ctx).await.unwrap();
}

/// Standalone test - run only the fixed 10-service mesh test
#[tokio::test]
#[ignore]
async fn test_fixed_mesh_standalone() {
    let session =
        TestSession::from_env("Set LATTICE_MGMT_KUBECONFIG and LATTICE_WORKLOAD_KUBECONFIG")
            .unwrap();
    apply_e2e_default_policy(&session.ctx.mgmt_kubeconfig)
        .await
        .unwrap();
    run_fixed_mesh_test(&session.ctx).await.unwrap();
}

/// Standalone test - run only the randomized mesh test
#[tokio::test]
#[ignore]
async fn test_random_mesh_standalone() {
    let session =
        TestSession::from_env("Set LATTICE_MGMT_KUBECONFIG and LATTICE_WORKLOAD_KUBECONFIG")
            .unwrap();
    apply_e2e_default_policy(&session.ctx.mgmt_kubeconfig)
        .await
        .unwrap();
    run_randomized_mesh_test(&session.ctx).await.unwrap();
}
