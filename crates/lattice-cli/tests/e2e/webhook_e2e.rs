//! Per-integration E2E test: Admission webhook validation
//!
//! Sets up mgmt + workload, tests webhook accept/reject, then tears down.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_webhook_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::integration;

#[tokio::test]
async fn test_webhook_e2e() {
    run_per_integration_e2e("Webhook", Duration::from_secs(2400), |ctx| async move {
        integration::webhook::run_webhook_tests(ctx.require_workload()?).await
    })
    .await;
}
