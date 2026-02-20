//! Per-integration E2E test: workload2 (3-cluster hierarchy)
//!
//! Sets up the full 3-cluster hierarchy (mgmt -> workload -> workload2),
//! runs workload2-specific validations (kubeconfig, proxy, cedar, multi-hop),
//! then tears down in reverse order.
//!
//! This test deliberately excludes mesh, secrets, cedar_secrets, tetragon,
//! and autoscaling — those only need 2 clusters and live in unified_e2e.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_workload2_e2e -- --nocapture
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
async fn test_workload2_e2e() {
    init_e2e_test();
    info!("Starting E2E test: Workload2 (3-cluster hierarchy)");

    let result = tokio::time::timeout(E2E_TIMEOUT, run()).await;
    match result {
        Ok(Ok(())) => info!("TEST PASSED: workload2"),
        Ok(Err(e)) => {
            setup::cleanup_bootstrap_cluster(run_id()).await;
            panic!("Workload2 E2E failed: {}", e);
        }
        Err(_) => {
            setup::cleanup_bootstrap_cluster(run_id()).await;
            panic!("Workload2 E2E timed out after {:?}", E2E_TIMEOUT);
        }
    }
}

async fn run() -> Result<(), String> {
    // =========================================================================
    // Phase 1: Set up full 3-cluster hierarchy
    // =========================================================================
    let config = setup::SetupConfig::default().with_workload2();
    let mut setup_result = setup::setup_full_hierarchy(&config).await?;
    let ctx = setup_result.ctx.clone();

    setup_result.ensure_proxies_alive().await?;

    // =========================================================================
    // Phase 2: Kubeconfig verification (all 3 clusters)
    // =========================================================================
    info!("[Phase 2] Verifying kubeconfig patching...");

    integration::kubeconfig::run_kubeconfig_verification(
        &ctx,
        WORKLOAD_CLUSTER_NAME,
        Some(WORKLOAD2_CLUSTER_NAME),
    )
    .await?;

    info!("SUCCESS: Kubeconfig verification complete!");

    // =========================================================================
    // Phase 3: Proxy access (all 3 clusters)
    // =========================================================================
    info!("[Phase 3] Testing proxy access...");

    integration::proxy::run_proxy_tests(&ctx, WORKLOAD_CLUSTER_NAME, Some(WORKLOAD2_CLUSTER_NAME))
        .await?;

    info!("SUCCESS: Proxy access verified!");

    // =========================================================================
    // Phase 4: Cedar hierarchy tests
    // =========================================================================
    info!("[Phase 4] Testing Cedar policy enforcement...");

    integration::cedar::run_cedar_hierarchy_tests(&ctx, WORKLOAD_CLUSTER_NAME).await?;

    info!("SUCCESS: Cedar policy enforcement verified!");

    // =========================================================================
    // Phase 5: Multi-hop proxy (mgmt -> workload -> workload2)
    // =========================================================================
    info!("[Phase 5] Testing multi-hop proxy operations...");

    integration::multi_hop::run_multi_hop_proxy_tests(&ctx).await?;

    info!("SUCCESS: Multi-hop proxy tests complete!");

    // =========================================================================
    // Phase 6: Delete workload2 (unpivot to workload)
    // =========================================================================
    info!("[Phase 6] Deleting workload2 cluster (unpivot to workload)...");

    integration::pivot::delete_and_verify_unpivot(
        ctx.require_workload2()?,
        ctx.require_workload()?,
        WORKLOAD2_CLUSTER_NAME,
        ctx.provider,
    )
    .await?;

    info!("SUCCESS: Workload2 deleted and unpivoted!");

    // =========================================================================
    // Phase 7: Delete workload (unpivot to mgmt)
    // =========================================================================
    info!("[Phase 7] Deleting workload cluster (unpivot to mgmt)...");

    integration::pivot::delete_and_verify_unpivot(
        ctx.require_workload()?,
        &ctx.mgmt_kubeconfig,
        WORKLOAD_CLUSTER_NAME,
        ctx.provider,
    )
    .await?;

    info!("SUCCESS: Workload deleted and unpivoted!");

    // =========================================================================
    // Phase 8: Teardown management cluster
    // =========================================================================
    info!("[Phase 8] Uninstalling management cluster...");

    teardown_mgmt_cluster(&ctx.mgmt_kubeconfig, MGMT_CLUSTER_NAME).await?;

    info!("Workload2 E2E test complete: 3-cluster hierarchy verified");

    Ok(())
}
