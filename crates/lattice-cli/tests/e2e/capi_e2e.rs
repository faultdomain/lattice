//! Per-integration E2E test: CAPI resource verification
//!
//! Sets up mgmt + workload, verifies CAPI resources on both clusters, then tears down.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_capi_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::helpers::{MGMT_CLUSTER_NAME, WORKLOAD_CLUSTER_NAME};
use super::integration;

#[tokio::test]
async fn test_capi_e2e() {
    run_per_integration_e2e("CAPI", Duration::from_secs(1800), |ctx| async move {
        integration::capi::verify_capi_resources(&ctx.mgmt_kubeconfig, MGMT_CLUSTER_NAME).await?;
        integration::capi::verify_capi_resources(ctx.require_workload()?, WORKLOAD_CLUSTER_NAME)
            .await
    })
    .await;
}
