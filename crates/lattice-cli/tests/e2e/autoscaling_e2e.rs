//! Per-integration E2E test: KEDA pod autoscaling
//!
//! Sets up mgmt + workload, deploys a CPU-burning LatticeService with autoscaling,
//! verifies KEDA ScaledObject creation and actual pod scale-up, then tears down.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_autoscaling_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::integration;

#[tokio::test]
async fn test_autoscaling_e2e() {
    run_per_integration_e2e("Autoscaling", Duration::from_secs(2400), |ctx| async move {
        integration::autoscaling::run_autoscaling_tests(ctx.require_workload()?).await
    })
    .await;
}
