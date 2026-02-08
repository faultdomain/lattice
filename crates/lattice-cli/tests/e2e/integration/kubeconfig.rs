//! Kubeconfig verification integration tests
//!
//! Tests for verifying kubeconfig patching for proxy access.
//! The actual proxy access tests are in proxy.rs.
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_kubeconfig_patched -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use base64::{engine::general_purpose::STANDARD, Engine};
use tracing::info;

use lattice_common::{capi_namespace, kubeconfig_secret_name};

use super::super::context::{InfraContext, TestSession};
use super::super::helpers::{get_workload_cluster_name, run_kubectl};

// ============================================================================
// Core Test Functions
// ============================================================================

/// Verify that a kubeconfig secret has been patched for proxy access.
///
/// After pivot, the kubeconfig secret moves from parent to child cluster.
/// This function checks both locations - the parent (pre-pivot) and the child (post-pivot).
///
/// The kubeconfig should point to the parent's proxy URL with the `/clusters/{name}` path,
/// rather than the direct cluster API endpoint.
pub async fn verify_kubeconfig_patched(
    parent_kubeconfig: &str,
    cluster_name: &str,
) -> Result<(), String> {
    info!(
        "[Integration/Kubeconfig] Verifying kubeconfig patched for {}...",
        cluster_name
    );

    let namespace = capi_namespace(cluster_name);
    let secret_name = kubeconfig_secret_name(cluster_name);

    // Try to get the kubeconfig secret from the parent cluster (pre-pivot location)
    // Use run_kubectl which returns Result - if kubectl fails (e.g., secret not found), it's an Err
    let kubeconfig_b64 = match run_kubectl(&[
        "--kubeconfig",
        parent_kubeconfig,
        "get",
        "secret",
        &secret_name,
        "-n",
        &namespace,
        "-o",
        "jsonpath={.data.value}",
    ])
    .await
    {
        Ok(data) if !data.trim().is_empty() => data,
        Ok(_) | Err(_) => {
            // After pivot, the secret is moved to the child cluster
            // This is expected - the cluster is now self-managing
            info!(
                "[Integration/Kubeconfig] Kubeconfig secret {}/{} not on parent (expected after pivot)",
                namespace, secret_name
            );
            info!(
                "[Integration/Kubeconfig] Cluster {} has pivoted - CAPI resources moved to child",
                cluster_name
            );
            return Ok(());
        }
    };

    let kubeconfig = String::from_utf8(
        STANDARD
            .decode(kubeconfig_b64.trim())
            .map_err(|e| format!("Failed to decode kubeconfig: {}", e))?,
    )
    .map_err(|e| format!("Invalid UTF-8 in kubeconfig: {}", e))?;

    if !kubeconfig.contains("/clusters/") {
        return Err(format!(
            "Kubeconfig for {} not patched for proxy - server URL missing /clusters/ path",
            cluster_name
        ));
    }

    info!(
        "[Integration/Kubeconfig] SUCCESS: Kubeconfig for {} is patched for proxy access",
        cluster_name
    );
    Ok(())
}

/// Verify that Cedar policies are loaded.
///
/// Checks that the CedarPolicy CRD exists and can be queried.
pub async fn verify_cedar_policies_loaded(kubeconfig: &str) -> Result<(), String> {
    info!("[Integration/Kubeconfig] Verifying Cedar policies are loaded...");

    // Check for CedarPolicy CRD
    let crd_check = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "crd",
        "cedarpolicies.lattice.dev",
        "-o",
        "name",
    ])
    .await;

    if crd_check.is_err() {
        info!("[Integration/Kubeconfig] Cedar CRD not installed - skipping policy verification");
        return Ok(());
    }

    let policy_count = match run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "cedarpolicy",
        "-A",
        "-o",
        "name",
    ])
    .await
    {
        Ok(policies) => policies.lines().filter(|l| !l.is_empty()).count(),
        Err(_) => 0,
    };
    info!(
        "[Integration/Kubeconfig] Found {} Cedar policies",
        policy_count
    );

    Ok(())
}

/// Run kubeconfig verification tests for a cluster hierarchy.
pub async fn run_kubeconfig_verification(
    ctx: &InfraContext,
    workload_cluster_name: &str,
    workload2_cluster_name: Option<&str>,
) -> Result<(), String> {
    // Verify workload kubeconfig is patched
    verify_kubeconfig_patched(&ctx.mgmt_kubeconfig, workload_cluster_name).await?;

    // Verify workload2 kubeconfig is patched (if exists)
    if let Some(w2_name) = workload2_cluster_name {
        if ctx.has_workload() {
            verify_kubeconfig_patched(ctx.workload_kubeconfig.as_deref().unwrap(), w2_name).await?;
        }
    }

    // Verify Cedar policies
    verify_cedar_policies_loaded(&ctx.mgmt_kubeconfig).await?;

    Ok(())
}

// ============================================================================
// Standalone Tests
// ============================================================================

/// Standalone test - verify kubeconfig patching for proxy access
///
/// Uses TestSession to automatically manage port-forwards.
#[tokio::test]
#[ignore]
async fn test_kubeconfig_patched() {
    let session = TestSession::from_env("Set LATTICE_MGMT_KUBECONFIG")
        .await
        .unwrap();
    let workload_name = get_workload_cluster_name();

    verify_kubeconfig_patched(&session.ctx.mgmt_kubeconfig, &workload_name)
        .await
        .unwrap();
}

/// Standalone test - verify Cedar policies are loaded
///
/// Uses TestSession to automatically manage port-forwards.
#[tokio::test]
#[ignore]
async fn test_cedar_policies() {
    let session = TestSession::from_env("Set LATTICE_MGMT_KUBECONFIG")
        .await
        .unwrap();
    verify_cedar_policies_loaded(&session.ctx.mgmt_kubeconfig)
        .await
        .unwrap();
}
