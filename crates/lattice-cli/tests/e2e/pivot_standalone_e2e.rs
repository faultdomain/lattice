//! Per-integration E2E test: cluster deletion and unpivot verification
//!
//! Sets up mgmt + workload, deletes the workload cluster (triggering unpivot
//! back to mgmt), verifies the unpivot, then tears down mgmt.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_pivot_standalone_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::helpers::WORKLOAD_CLUSTER_NAME;
use super::integration;

#[tokio::test]
async fn test_pivot_standalone_e2e() {
    run_per_integration_e2e("Pivot", Duration::from_secs(2400), |ctx| async move {
        integration::pivot::delete_and_verify_unpivot(
            ctx.require_workload()?,
            &ctx.mgmt_kubeconfig,
            WORKLOAD_CLUSTER_NAME,
            ctx.provider,
        )
        .await
    })
    .await;
}
