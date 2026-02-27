//! Per-integration E2E test: Gateway API routing
//!
//! Sets up mgmt + workload, runs gateway tests, then tears down.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_gateway_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::integration;

#[tokio::test]
async fn test_gateway_e2e() {
    run_per_integration_e2e("Gateway", Duration::from_secs(2400), |ctx| async move {
        integration::gateway::run_gateway_tests(ctx.require_workload()?).await
    })
    .await;
}
