//! Per-integration E2E test: Secret rollout on ESO secret rotation
//!
//! Sets up mgmt + workload, runs secret rollout tests, then tears down.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_secret_rollout_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::integration;

#[tokio::test]
async fn test_secret_rollout_e2e() {
    run_per_integration_e2e(
        "SecretRollout",
        Duration::from_secs(2400),
        |ctx| async move {
            integration::secret_rollout::run_secret_rollout_tests(ctx.require_workload()?).await
        },
    )
    .await;
}
