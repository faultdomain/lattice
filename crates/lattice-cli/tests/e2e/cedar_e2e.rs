//! Per-integration E2E test: Cedar policy enforcement for proxy access
//!
//! Sets up mgmt + workload, tests Cedar hierarchy policies, then tears down.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_cedar_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::helpers::WORKLOAD_CLUSTER_NAME;
use super::integration;

#[tokio::test]
async fn test_cedar_e2e() {
    run_per_integration_e2e("Cedar", Duration::from_secs(2400), |ctx| async move {
        integration::cedar::run_cedar_hierarchy_tests(&ctx, WORKLOAD_CLUSTER_NAME).await
    })
    .await;
}
