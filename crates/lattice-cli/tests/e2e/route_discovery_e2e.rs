//! Per-integration E2E: Route discovery and cross-cluster connectivity
//!
//! Sets up mgmt + workload, deploys advertised services, verifies the full
//! pipeline: heartbeat → LatticeClusterRoutes → Istio remote secret → native discovery.

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::integration;

#[tokio::test]
async fn test_route_discovery_e2e() {
    run_per_integration_e2e(
        "RouteDiscovery",
        Duration::from_secs(1200),
        |ctx| async move {
            let workload_kc = ctx.require_workload()?;

            integration::route_discovery::run_route_discovery_tests(
                &ctx.mgmt_kubeconfig,
                workload_kc,
            )
            .await?;

            integration::route_discovery::run_restricted_advertise_tests(workload_kc).await?;

            Ok(())
        },
    )
    .await;
}
