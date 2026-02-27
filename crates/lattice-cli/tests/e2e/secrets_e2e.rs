//! Per-integration E2E test: Secrets integration (local webhook ESO)
//!
//! Sets up mgmt + workload, runs secrets tests (local webhook ESO backend), then tears down.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_secrets_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::integration;

#[tokio::test]
async fn test_secrets_e2e() {
    run_per_integration_e2e("Secrets", Duration::from_secs(2400), |ctx| async move {
        integration::secrets::run_secrets_tests(ctx.require_workload()?).await
    })
    .await;
}
