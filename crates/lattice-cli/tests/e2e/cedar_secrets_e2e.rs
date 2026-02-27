//! Per-integration E2E test: Cedar secret authorization
//!
//! Sets up mgmt + workload, tests Cedar secret policies (default-deny, permit,
//! forbid, namespace isolation), then tears down.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_cedar_secrets_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::integration;

#[tokio::test]
async fn test_cedar_secrets_e2e() {
    run_per_integration_e2e(
        "Cedar Secrets",
        Duration::from_secs(2400),
        |ctx| async move {
            integration::cedar_secrets::run_cedar_secret_tests(ctx.require_workload()?).await
        },
    )
    .await;
}
