//! Per-integration E2E test: Cedar security override authorization
//!
//! Sets up mgmt + workload, tests Cedar security override policies (default-deny,
//! permit, forbid, namespace isolation, lifecycle recovery), then tears down.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_cedar_security_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::integration;

#[tokio::test]
async fn test_cedar_security_e2e() {
    run_per_integration_e2e(
        "Cedar Security",
        Duration::from_secs(2400),
        |ctx| async move {
            integration::cedar_security::run_cedar_security_tests(ctx.require_workload()?).await
        },
    )
    .await;
}
