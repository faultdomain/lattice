//! Full E2E test for Lattice installation, pivot, and unpivot flow
//!
//! This test validates the complete Lattice lifecycle:
//! 1. Set up cluster hierarchy (mgmt -> workload, optionally -> workload2)
//! 2. Run mesh tests on workload cluster
//! 3. Delete workload2 if enabled (unpivot to workload)
//! 4. Delete workload (unpivot to mgmt)
//! 5. Uninstall management cluster
//!
//! # Running
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e pivot_e2e -- --nocapture
//! ```
//!
//! # Environment Variables
//!
//! - `LATTICE_MGMT_CLUSTER_CONFIG`: Path to LatticeCluster YAML for management cluster
//! - `LATTICE_WORKLOAD_CLUSTER_CONFIG`: Path to LatticeCluster YAML for workload cluster
//! - `LATTICE_WORKLOAD2_CLUSTER_CONFIG`: Path to LatticeCluster YAML for second workload cluster
//! - `LATTICE_ENABLE_WORKLOAD2=1`: Enable workload2 cluster (default: disabled for faster iteration)
//! - `LATTICE_ENABLE_MESH_TEST=true`: Enable service mesh validation tests (default: true)

#![cfg(feature = "provider-e2e")]

use std::path::PathBuf;
use std::time::Duration;

use tracing::info;

use lattice_cli::commands::uninstall::{UninstallArgs, Uninstaller};

use super::context::init_e2e_test;
use super::helpers::{run_id, MGMT_CLUSTER_NAME, WORKLOAD2_CLUSTER_NAME, WORKLOAD_CLUSTER_NAME};
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

    // =========================================================================
    // Phase 6.5: Verify kubeconfig patching + test proxy access
    // =========================================================================
    // Note: chaos is already stopped by setup_full_hierarchy before creating proxy sessions

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
    info!("[Phase 6.6] Testing Cedar policy enforcement...");

    // Test Cedar policies for access from mgmt -> workload
    integration::cedar::run_cedar_hierarchy_tests(&ctx, WORKLOAD_CLUSTER_NAME).await?;

    // Test Cedar policies for access from workload -> workload2 (if workload2 exists)
    if ctx.has_workload2() {
        if let Some(workload_kubeconfig) = &ctx.workload_kubeconfig {
            let mut workload_ctx = super::context::InfraContext::new(
                workload_kubeconfig.clone(),
                None,
                None,
                ctx.provider,
            );
            // Pass workload's proxy URL so Cedar tests use the existing port-forward
            if let Some(proxy_url) = &ctx.workload_proxy_url {
                workload_ctx = workload_ctx.with_mgmt_proxy_url(proxy_url.clone());
            }
            integration::cedar::run_cedar_hierarchy_tests(&workload_ctx, WORKLOAD2_CLUSTER_NAME)
                .await?;
        }
    }

    info!("SUCCESS: Cedar policy enforcement verified!");

    // =========================================================================
    // Phase 7: Run mesh tests + delete workload2 (parallel, if workload2 exists)
    // =========================================================================
    if ctx.has_workload2() {
        info!("[Phase 7] Running mesh tests + deleting workload2...");
    } else {
        info!("[Phase 7] Running mesh tests (workload2 disabled)...");
    }

    // Start mesh tests in background
    let mesh_handle = if integration::mesh::mesh_tests_enabled() {
        let is_docker = integration::mesh::is_docker_provider(&ctx);
        Some(integration::mesh::start_mesh_tests_async(&ctx, is_docker).await?)
    } else {
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
    // Re-enable chaos during cluster deletion to test unpivot resilience
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
    info!("[Phase 9] Uninstalling management cluster...");

    // Stop chaos before uninstall
    setup_result.stop_chaos().await;

    let uninstall_args = UninstallArgs {
        kubeconfig: PathBuf::from(&ctx.mgmt_kubeconfig),
        name: Some(MGMT_CLUSTER_NAME.to_string()),
        yes: true,
        keep_bootstrap_on_failure: false,
        run_id: Some(run_id().to_string()),
    };

    let uninstaller = Uninstaller::new(&uninstall_args)
        .await
        .map_err(|e| format!("Failed to create uninstaller: {}", e))?;

    uninstaller
        .run()
        .await
        .map_err(|e| format!("Uninstall failed: {}", e))?;

    info!("SUCCESS: Management cluster uninstalled!");
    info!("E2E test complete: full lifecycle verified");

    Ok(())
}
