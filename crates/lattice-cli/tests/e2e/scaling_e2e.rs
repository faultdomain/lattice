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
use super::helpers::{load_cluster_config, WORKLOAD_CLUSTER_NAME};
use super::integration;

#[tokio::test]
async fn test_scaling_e2e() {
    let (_, workload_cluster) =
        load_cluster_config("LATTICE_WORKLOAD_CLUSTER_CONFIG", "docker-workload.yaml").unwrap();
    let expected_workers = workload_cluster.spec.nodes.total_workers();

    run_per_integration_e2e("Scaling", Duration::from_secs(1800), |ctx| async move {
        integration::scaling::verify_cluster_workers(
            ctx.require_workload()?,
            WORKLOAD_CLUSTER_NAME,
            expected_workers,
        )
        .await
    })
    .await;
}
