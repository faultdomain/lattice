//! Per-integration E2E test: OIDC authentication
//!
//! Sets up mgmt + workload, runs OIDC hierarchy tests, then tears down.
//! Skips internally if Keycloak is not available.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_oidc_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use super::context::init_e2e_test;
use super::helpers::{run_id, teardown_mgmt_cluster, MGMT_CLUSTER_NAME, WORKLOAD_CLUSTER_NAME};
use super::integration::{self, setup};

const E2E_TIMEOUT: Duration = Duration::from_secs(1800);

#[tokio::test]
async fn test_oidc_e2e() {
    init_e2e_test();
    info!("Starting E2E test: OIDC");

    let result = tokio::time::timeout(E2E_TIMEOUT, run()).await;
    match result {
        Ok(Ok(())) => info!("TEST PASSED: oidc"),
        Ok(Err(e)) => {
            setup::cleanup_bootstrap_cluster(run_id()).await;
            panic!("OIDC E2E failed: {}", e);
        }
        Err(_) => {
            setup::cleanup_bootstrap_cluster(run_id()).await;
            panic!("OIDC E2E timed out after {:?}", E2E_TIMEOUT);
        }
    }
}

async fn run() -> Result<(), String> {
    let result = setup::setup_mgmt_and_workload(&setup::SetupConfig::default()).await?;
    integration::oidc::run_oidc_hierarchy_tests(&result.ctx, WORKLOAD_CLUSTER_NAME).await?;
    teardown_mgmt_cluster(&result.ctx.mgmt_kubeconfig, MGMT_CLUSTER_NAME).await
}
