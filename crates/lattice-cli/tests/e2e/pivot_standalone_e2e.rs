//! Per-integration E2E test: cluster deletion and unpivot verification
//!
//! Sets up mgmt + workload, deletes the workload cluster (triggering unpivot
//! back to mgmt), verifies the unpivot, then tears down mgmt.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_pivot_standalone_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use super::context::init_e2e_test;
use super::helpers::{run_id, teardown_mgmt_cluster, MGMT_CLUSTER_NAME, WORKLOAD_CLUSTER_NAME};
use super::integration::{self, setup};

const E2E_TIMEOUT: Duration = Duration::from_secs(2400);

#[tokio::test]
async fn test_pivot_standalone_e2e() {
    init_e2e_test();
    info!("Starting E2E test: Pivot/Unpivot");

    let result = tokio::time::timeout(E2E_TIMEOUT, run()).await;
    match result {
        Ok(Ok(())) => info!("TEST PASSED: pivot"),
        Ok(Err(e)) => {
            setup::cleanup_bootstrap_cluster(run_id());
            panic!("Pivot E2E failed: {}", e);
        }
        Err(_) => {
            setup::cleanup_bootstrap_cluster(run_id());
            panic!("Pivot E2E timed out after {:?}", E2E_TIMEOUT);
        }
    }
}

async fn run() -> Result<(), String> {
    let result = setup::setup_mgmt_and_workload(&setup::SetupConfig::default()).await?;

    // Delete workload cluster and verify unpivot to mgmt
    integration::pivot::delete_and_verify_unpivot(
        result.ctx.require_workload()?,
        &result.ctx.mgmt_kubeconfig,
        WORKLOAD_CLUSTER_NAME,
        result.ctx.provider,
    )
    .await?;

    teardown_mgmt_cluster(&result.ctx.mgmt_kubeconfig, MGMT_CLUSTER_NAME).await
}
