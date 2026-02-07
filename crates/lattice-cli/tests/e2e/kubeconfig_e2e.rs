//! Per-integration E2E test: kubeconfig patching and proxy verification
//!
//! Sets up mgmt + workload, verifies kubeconfigs are patched for proxy, then tears down.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_kubeconfig_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use super::context::init_e2e_test;
use super::helpers::{run_id, teardown_mgmt_cluster, MGMT_CLUSTER_NAME, WORKLOAD_CLUSTER_NAME};
use super::integration::{self, setup};

const E2E_TIMEOUT: Duration = Duration::from_secs(1800);

#[tokio::test]
async fn test_kubeconfig_e2e() {
    init_e2e_test();
    info!("Starting E2E test: Kubeconfig");

    let result = tokio::time::timeout(E2E_TIMEOUT, run()).await;
    match result {
        Ok(Ok(())) => info!("TEST PASSED: kubeconfig"),
        Ok(Err(e)) => {
            setup::cleanup_bootstrap_cluster(run_id());
            panic!("Kubeconfig E2E failed: {}", e);
        }
        Err(_) => {
            setup::cleanup_bootstrap_cluster(run_id());
            panic!("Kubeconfig E2E timed out after {:?}", E2E_TIMEOUT);
        }
    }
}

async fn run() -> Result<(), String> {
    let result = setup::setup_mgmt_and_workload(&setup::SetupConfig::default()).await?;
    integration::kubeconfig::run_kubeconfig_verification(&result.ctx, WORKLOAD_CLUSTER_NAME, None)
        .await?;
    teardown_mgmt_cluster(&result.ctx.mgmt_kubeconfig, MGMT_CLUSTER_NAME).await
}
