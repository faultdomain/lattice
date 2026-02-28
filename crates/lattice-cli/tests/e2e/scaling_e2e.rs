//! Per-integration E2E test: worker node scaling
//!
//! Sets up mgmt + workload, verifies workload worker scaling, then tears down.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_scaling_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::helpers::WORKLOAD_CLUSTER_NAME;
use super::integration;

#[tokio::test]
async fn test_scaling_e2e() {
    run_per_integration_e2e("Scaling", Duration::from_secs(1800), |ctx| async move {
        integration::scaling::verify_cluster_workers(
            ctx.require_workload()?,
            WORKLOAD_CLUSTER_NAME,
            5,
        )
        .await
    })
    .await;
}
