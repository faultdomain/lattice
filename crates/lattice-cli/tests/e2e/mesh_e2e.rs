//! Per-integration E2E test: service mesh bilateral agreements
//!
//! Sets up mgmt + workload, runs mesh tests, then tears down.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_mesh_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::integration;

#[tokio::test]
async fn test_mesh_e2e() {
    run_per_integration_e2e("Mesh", Duration::from_secs(2400), |ctx| async move {
        integration::mesh::run_mesh_tests(ctx.require_workload()?).await
    })
    .await;
}
