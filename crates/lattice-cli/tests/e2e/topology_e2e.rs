//! Per-integration E2E test: network topology-aware scheduling
//!
//! Sets up mgmt + workload (with topology-labeled node pools),
//! verifies topology labels, PodGroup creation, and scheduler assignment.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_topology_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::integration;

#[tokio::test]
async fn test_topology_e2e() {
    run_per_integration_e2e("Topology", Duration::from_secs(1800), |ctx| async move {
        integration::topology::run_topology_tests(ctx.require_workload()?).await
    })
    .await;
}
