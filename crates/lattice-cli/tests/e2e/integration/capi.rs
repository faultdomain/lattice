//! CAPI resource verification integration tests
//!
//! Tests that verify CAPI resources exist and are properly configured
//! after cluster provisioning and pivot. Standalone tests are disabled;
//! CAPI verification runs only within full E2E tests.

#![cfg(feature = "provider-e2e")]

use tracing::info;

use super::super::helpers::{run_kubectl, verify_cluster_capi_resources};

/// Verify CAPI resources exist on a cluster
///
/// Checks that the cluster has its own CAPI Cluster resource,
/// indicating it is properly self-managing after pivot.
///
/// # Arguments
///
/// * `kubeconfig` - Path to kubeconfig for the target cluster
/// * `cluster_name` - Name of the cluster to verify
pub async fn verify_capi_resources(kubeconfig: &str, cluster_name: &str) -> Result<(), String> {
    info!(
        "[Integration/CAPI] Verifying cluster {} CAPI resources...",
        cluster_name
    );
    verify_cluster_capi_resources(kubeconfig, cluster_name).await?;
    info!(
        "[Integration/CAPI] Cluster {} has CAPI resources",
        cluster_name
    );

    Ok(())
}

/// List all CAPI clusters visible from a kubeconfig
pub async fn list_capi_clusters(kubeconfig: &str) -> Result<String, String> {
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "clusters",
        "-A",
        "-o",
        "wide",
    ])
    .await
}

// CAPI standalone tests are disabled — CAPI verification is only meaningful
// within full E2E tests where clusters have been provisioned and pivoted.
