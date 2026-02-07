//! Per-integration E2E test: multi-hop proxy operations
//!
//! Sets up the full 3-cluster hierarchy (mgmt -> workload -> workload2),
//! tests multi-hop proxy path, then tears down.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_multi_hop_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use super::context::init_e2e_test;
use super::helpers::{run_id, teardown_mgmt_cluster, MGMT_CLUSTER_NAME};
use super::integration::{self, setup};

const E2E_TIMEOUT: Duration = Duration::from_secs(3600);

#[tokio::test]
async fn test_multi_hop_e2e() {
    init_e2e_test();
    info!("Starting E2E test: Multi-Hop Proxy");

    let result = tokio::time::timeout(E2E_TIMEOUT, run()).await;
    match result {
        Ok(Ok(())) => info!("TEST PASSED: multi_hop"),
        Ok(Err(e)) => {
            setup::cleanup_bootstrap_cluster(run_id());
            panic!("Multi-Hop E2E failed: {}", e);
        }
        Err(_) => {
            setup::cleanup_bootstrap_cluster(run_id());
            panic!("Multi-Hop E2E timed out after {:?}", E2E_TIMEOUT);
        }
    }
}

async fn run() -> Result<(), String> {
    let config = setup::SetupConfig::default().with_workload2();
    let mut result = setup::setup_full_hierarchy(&config).await?;
    result.ensure_proxies_alive().await?;

    integration::multi_hop::run_multi_hop_proxy_tests(&result.ctx).await?;

    teardown_mgmt_cluster(&result.ctx.mgmt_kubeconfig, MGMT_CLUSTER_NAME).await
}
