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

use super::context::run_per_integration_e2e;
use super::helpers::WORKLOAD_CLUSTER_NAME;
use super::integration;

#[tokio::test]
async fn test_oidc_e2e() {
    run_per_integration_e2e("OIDC", Duration::from_secs(1800), |ctx| async move {
        integration::oidc::run_oidc_hierarchy_tests(&ctx, WORKLOAD_CLUSTER_NAME).await
    })
    .await;
}
