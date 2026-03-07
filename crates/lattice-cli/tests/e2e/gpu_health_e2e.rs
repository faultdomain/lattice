//! Per-integration E2E test: GPU health monitoring
//!
//! Sets up mgmt + workload, patches GPU annotations on worker nodes, and verifies
//! the operator correctly cordons, drains, and uncordons based on health signals.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_gpu_health_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::integration;

#[tokio::test]
async fn test_gpu_health_e2e() {
    run_per_integration_e2e("GPU Health", Duration::from_secs(600), |ctx| async move {
        integration::gpu_health::run_gpu_health_tests(ctx.require_workload()?).await
    })
    .await;
}
