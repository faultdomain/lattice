//! Per-integration E2E test: Vault secrets integration
//!
//! Sets up mgmt + workload, runs secrets tests if Vault is reachable, then tears down.
//! Skips gracefully if Vault is not configured (docker-compose not running).
//!
//! ```bash
//! # Start Vault first
//! docker compose up -d
//!
//! cargo test --features provider-e2e --test e2e test_secrets_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use super::context::init_e2e_test;
use super::helpers::{run_id, teardown_mgmt_cluster, MGMT_CLUSTER_NAME};
use super::integration::{self, setup};

const E2E_TIMEOUT: Duration = Duration::from_secs(2400);

#[tokio::test]
async fn test_secrets_e2e() {
    init_e2e_test();
    info!("Starting E2E test: Secrets");

    let result = tokio::time::timeout(E2E_TIMEOUT, run()).await;
    match result {
        Ok(Ok(())) => info!("TEST PASSED: secrets"),
        Ok(Err(e)) => {
            setup::cleanup_bootstrap_cluster(run_id());
            panic!("Secrets E2E failed: {}", e);
        }
        Err(_) => {
            setup::cleanup_bootstrap_cluster(run_id());
            panic!("Secrets E2E timed out after {:?}", E2E_TIMEOUT);
        }
    }
}

async fn run() -> Result<(), String> {
    if !integration::secrets::secrets_tests_enabled() {
        info!("Vault not reachable - skipping secrets E2E test");
        return Ok(());
    }

    let result = setup::setup_mgmt_and_workload(&setup::SetupConfig::default()).await?;
    integration::secrets::run_secrets_tests(&result.ctx).await?;
    teardown_mgmt_cluster(&result.ctx.mgmt_kubeconfig, MGMT_CLUSTER_NAME).await
}
