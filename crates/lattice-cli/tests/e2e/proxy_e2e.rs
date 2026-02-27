//! Per-integration E2E test: K8s API proxy access
//!
//! Sets up mgmt + workload, tests proxy access through hierarchy, then tears down.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_proxy_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::helpers::WORKLOAD_CLUSTER_NAME;
use super::integration;

#[tokio::test]
async fn test_proxy_e2e() {
    run_per_integration_e2e("Proxy", Duration::from_secs(1800), |ctx| async move {
        integration::proxy::run_proxy_tests(&ctx, WORKLOAD_CLUSTER_NAME, None).await
    })
    .await;
}
