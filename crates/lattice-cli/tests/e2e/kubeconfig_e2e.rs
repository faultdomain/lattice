//! Per-integration E2E test: kubeconfig patching and proxy verification
//!
//! Sets up mgmt + workload, verifies kubeconfigs are patched for proxy, then tears down.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_kubeconfig_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::helpers::WORKLOAD_CLUSTER_NAME;
use super::integration;

#[tokio::test]
async fn test_kubeconfig_e2e() {
    run_per_integration_e2e("Kubeconfig", Duration::from_secs(1800), |ctx| async move {
        integration::kubeconfig::run_kubeconfig_verification(&ctx, WORKLOAD_CLUSTER_NAME, None)
            .await
    })
    .await;
}
