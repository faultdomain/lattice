//! Unified E2E test for Lattice: full lifecycle with all integration tests
//!
//! This test validates the complete Lattice lifecycle by running ALL integration
//! tests in sequence against a shared cluster hierarchy. Use this when you want
//! comprehensive coverage in a single run.
//!
//! For isolated, per-integration E2E tests, see the individual `*_e2e.rs` files.
//!
//! # Phases
//!
//! 1. Set up cluster hierarchy (mgmt -> workload, optionally -> workload2)
//! 2. Kubeconfig + proxy verification
//! 3. Cedar policy enforcement
//! 4. Multi-hop proxy (if workload2)
//! 5. Mesh + secrets tests (parallel) + workload2 deletion
//! 6. Workload deletion (unpivot to mgmt)
//! 7. Management cluster uninstall
//!
//! # Running
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_configurable_provider_pivot -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use super::context::init_e2e_test;
use super::helpers::{
    run_id, teardown_mgmt_cluster, MGMT_CLUSTER_NAME, WORKLOAD2_CLUSTER_NAME, WORKLOAD_CLUSTER_NAME,
};
use super::integration::{self, setup};

const E2E_TIMEOUT: Duration = Duration::from_secs(3600);

#[tokio::test]
async fn test_configurable_provider_pivot() {
    init_e2e_test();
    info!("Starting E2E test: Full Lifecycle");

    let result = tokio::time::timeout(E2E_TIMEOUT, run_full_e2e()).await;

    match result {
        Ok(Ok(())) => {
            info!("TEST PASSED");
        }
        Ok(Err(e)) => {
            setup::cleanup_bootstrap_cluster(run_id());
            panic!("E2E test failed: {} (manual cleanup may be required)", e);
        }
        Err(_) => {
            setup::cleanup_bootstrap_cluster(run_id());
            panic!(
                "E2E test timed out after {:?} (manual cleanup required)",
                E2E_TIMEOUT
            );
        }
    }
}

async fn run_full_e2e() -> Result<(), String> {
    // =========================================================================
    // Phase 1-6: Set up full hierarchy using integration module
    // =========================================================================
    // Allow disabling chaos via environment variable for debugging
    let config = if std::env::var("LATTICE_DISABLE_CHAOS").is_ok() {
        info!("[E2E] Chaos monkey disabled via LATTICE_DISABLE_CHAOS");
        setup::SetupConfig::default()
    } else {
        setup::SetupConfig::with_chaos()
    };
    let mut setup_result = integration::setup::setup_full_hierarchy(&config).await?;
    let ctx = setup_result.ctx.clone();

    // Chaos was stopped inside setup before proxy kubeconfig generation (Phase 7).
    // Ensure port-forwards are alive before continuing.
    setup_result.ensure_proxies_alive().await?;

    // =========================================================================
    // Phase 6.5: Verify kubeconfig patching + test proxy access
    // =========================================================================
    info!("[Phase 6.5] Verifying kubeconfig patching and proxy access...");

    // Verify kubeconfigs are patched for proxy
    let workload2_name = if ctx.has_workload2() {
        Some(WORKLOAD2_CLUSTER_NAME)
    } else {
        None
    };
    integration::kubeconfig::run_kubeconfig_verification(
        &ctx,
        WORKLOAD_CLUSTER_NAME,
        workload2_name,
    )
    .await?;

    // Test proxy access through the hierarchy
    integration::proxy::run_proxy_tests(&ctx, WORKLOAD_CLUSTER_NAME, workload2_name).await?;

    info!("SUCCESS: Kubeconfig and proxy verification complete!");

    // =========================================================================
    // Phase 6.6: Test Cedar policy enforcement for proxy access
    // =========================================================================
    // Pause chaos on mgmt cluster only - we want to test resilience to workload
    // operator restarts. The retry logic should handle "cluster not found" errors
    // when the agent temporarily disconnects.
    setup_result.pause_chaos_on_cluster(MGMT_CLUSTER_NAME);
    info!("[Phase 6.6] Testing Cedar policy enforcement (chaos paused on mgmt)...");

    // Test Cedar policies for access from mgmt -> workload
    // (Multi-hop tests in Phase 6.7 validate the full mgmt -> workload -> workload2 chain)
    integration::cedar::run_cedar_hierarchy_tests(&ctx, WORKLOAD_CLUSTER_NAME).await?;

    info!("SUCCESS: Cedar policy enforcement verified!");

    // Test Cedar secret authorization (default-deny, permit, forbid, namespace isolation)
    integration::cedar_secrets::run_cedar_secret_tests(&ctx).await?;
    info!("SUCCESS: Cedar secret authorization tests verified!");

    // =========================================================================
    // Phase 6.7: Test multi-hop proxy operations (if workload2 exists)
    // =========================================================================
    if ctx.has_workload2() {
        info!("[Phase 6.7] Testing multi-hop proxy operations (mgmt -> workload -> workload2)...");
        integration::multi_hop::run_multi_hop_proxy_tests(&ctx).await?;
        info!("SUCCESS: Multi-hop proxy tests complete!");
    }

    // =========================================================================
    // Phase 7: Run mesh + secrets tests + delete workload2 (parallel, if workload2 exists)
    // =========================================================================
    if ctx.has_workload2() {
        info!("[Phase 7] Running mesh/secrets tests + deleting workload2...");
    } else {
        info!("[Phase 7] Running mesh/secrets tests (workload2 disabled)...");
    }

    // Start mesh tests in background
    let mesh_handle = if integration::mesh::mesh_tests_enabled() {
        let is_docker = integration::mesh::is_docker_provider(&ctx);
        Some(integration::mesh::start_mesh_tests_async(&ctx, is_docker).await?)
    } else {
        None
    };

    // Start secrets tests in background (if Vault is configured)
    let secrets_handle = if integration::secrets::secrets_tests_enabled() {
        info!("[Phase 7] Vault configured - starting secrets tests...");
        Some(integration::secrets::start_secrets_tests_async(&ctx).await?)
    } else {
        info!("[Phase 7] Vault not configured - skipping secrets tests");
        None
    };

    // Start workload2 deletion in background (if workload2 exists)
    let delete_handle = if ctx.has_workload2() {
        Some(integration::pivot::start_cluster_deletion_async(
            ctx.require_workload2()?.to_string(),
            ctx.require_workload()?.to_string(),
            WORKLOAD2_CLUSTER_NAME.to_string(),
            ctx.provider,
        ))
    } else {
        None
    };

    // Wait for mesh tests
    if let Some(handle) = mesh_handle {
        info!("[Phase 7] Waiting for mesh tests to complete...");
        handle
            .await
            .map_err(|e| format!("Mesh test task panicked: {}", e))??;
        info!("SUCCESS: Mesh tests complete!");
    }

    // Wait for secrets tests
    if let Some(handle) = secrets_handle {
        info!("[Phase 7] Waiting for secrets tests to complete...");
        handle
            .await
            .map_err(|e| format!("Secrets test task panicked: {}", e))??;
        info!("SUCCESS: Secrets tests complete!");
    }

    // Wait for workload2 deletion (if started)
    if let Some(handle) = delete_handle {
        info!("[Phase 7] Waiting for workload2 deletion...");
        handle
            .await
            .map_err(|e| format!("Delete task panicked: {}", e))??;
        info!("SUCCESS: Workload2 deleted and unpivoted!");
    }

    // =========================================================================
    // Phase 8: Delete workload (unpivot to mgmt)
    // =========================================================================
    // Resume chaos on mgmt cluster for deletion/unpivot testing
    setup_result.resume_chaos_on_cluster(MGMT_CLUSTER_NAME, &ctx.mgmt_kubeconfig, None);
    setup_result.restart_chaos();

    info!("[Phase 8] Deleting workload cluster (unpivot to mgmt)...");

    integration::pivot::delete_and_verify_unpivot(
        ctx.require_workload()?,
        &ctx.mgmt_kubeconfig,
        WORKLOAD_CLUSTER_NAME,
        ctx.provider,
    )
    .await?;

    info!("SUCCESS: Workload deleted and unpivoted!");

    // =========================================================================
    // Phase 9: Uninstall management cluster
    // =========================================================================
    // Chaos continues running - uninstall should be resilient to pod restarts
    info!("[Phase 9] Uninstalling management cluster...");

    teardown_mgmt_cluster(&ctx.mgmt_kubeconfig, MGMT_CLUSTER_NAME).await?;

    info!("E2E test complete: full lifecycle verified");

    Ok(())
}
