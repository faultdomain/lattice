//! Hierarchy proxy integration tests
//!
//! Tests the K8s API proxy through the cluster hierarchy.
//! Parent clusters can access child cluster APIs through the auth proxy.
//!
//! # Architecture
//!
//! The proxy flow is:
//! 1. Client sends request to auth proxy with Bearer token
//! 2. Auth proxy validates token via TokenReview API
//! 3. Cedar policy engine authorizes the request
//! 4. Proxy routes request through gRPC tunnel to child's agent
//! 5. Agent executes request against local K8s API
//! 6. Response returned through the tunnel
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_proxy_access_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;
use tokio::time::sleep;
use tracing::info;

use super::super::context::{init_test_env, InfraContext};
use super::super::helpers::{
    get_proxy_url_for_provider, get_sa_token, http_get_with_token, run_cmd_allow_fail,
    WORKLOAD2_CLUSTER_NAME, WORKLOAD_CLUSTER_NAME,
};
use super::super::providers::InfraProvider;
use super::cedar::{apply_e2e_default_policy, remove_e2e_default_policy};

// ============================================================================
// Constants
// ============================================================================

/// Namespace for proxy test ServiceAccount
const PROXY_TEST_NAMESPACE: &str = "lattice-system";

/// ServiceAccount name for proxy tests (uses default SA in lattice-system)
const PROXY_TEST_SA: &str = "default";

// ============================================================================
// Core Test Functions
// ============================================================================

/// Wait for cluster to be ready for proxy testing.
///
/// Checks that the cluster is in a state where proxy access should work:
/// - Pivoted or Ready phase means the cluster was successfully bootstrapped
/// - For pivoted clusters, the agent connection is implicit (pivot requires agent)
pub async fn wait_for_agent_ready(
    parent_kubeconfig: &str,
    child_cluster_name: &str,
) -> Result<(), String> {
    info!(
        "[Integration/Proxy] Checking cluster {} is ready for proxy access...",
        child_cluster_name
    );

    for attempt in 1..=30 {
        let phase = run_cmd_allow_fail(
            "kubectl",
            &[
                "--kubeconfig",
                parent_kubeconfig,
                "get",
                "latticecluster",
                child_cluster_name,
                "-o",
                "jsonpath={.status.phase}",
            ],
        );

        let phase_trimmed = phase.trim();

        // Pivoted or Ready means the cluster is operational
        // Pivoted specifically means the agent was connected (pivot requires agent)
        if phase_trimmed == "Pivoted" || phase_trimmed == "Ready" {
            info!(
                "[Integration/Proxy] Cluster {} is {} - ready for proxy access",
                child_cluster_name, phase_trimmed
            );
            return Ok(());
        }

        if attempt < 30 {
            info!(
                "[Integration/Proxy] Waiting for cluster to be ready (attempt {}/30, phase: {})...",
                attempt, phase_trimmed
            );
            sleep(Duration::from_secs(5)).await;
        }
    }

    Err(format!(
        "Cluster {} did not reach Ready/Pivoted state within timeout",
        child_cluster_name
    ))
}

/// Test proxy access to a child cluster via the auth proxy.
///
/// This test:
/// 1. Gets a ServiceAccount token from the parent cluster
/// 2. Calls the auth proxy endpoint directly with curl
/// 3. Verifies we get a valid K8s API response
pub async fn test_proxy_access_to_child(
    parent_kubeconfig: &str,
    child_cluster_name: &str,
    provider: InfraProvider,
) -> Result<(), String> {
    info!(
        "[Integration/Proxy] Testing proxy access to {}...",
        child_cluster_name
    );

    // Get the proxy URL (provider-aware for Docker vs cloud)
    info!(
        "[Integration/Proxy] Getting proxy URL for {:?} provider...",
        provider
    );
    let proxy_url = get_proxy_url_for_provider(parent_kubeconfig, provider)?;
    info!("[Integration/Proxy] Using proxy URL: {}", proxy_url);

    // Get a ServiceAccount token from the parent cluster
    let token = get_sa_token(parent_kubeconfig, PROXY_TEST_NAMESPACE, PROXY_TEST_SA)?;
    info!(
        "[Integration/Proxy] Got SA token for {}/{}",
        PROXY_TEST_NAMESPACE, PROXY_TEST_SA
    );

    // Test proxy access and validate response
    verify_proxy_namespace_access(&proxy_url, &token, child_cluster_name, "child")
}

/// Test proxy access from root cluster to grandchild cluster.
///
/// This tests hierarchical proxy routing:
/// Root (mgmt) → Child (workload) → Grandchild (workload2)
///
/// The request should route through the hierarchy via gRPC tunnels.
pub async fn test_proxy_access_to_grandchild(
    root_kubeconfig: &str,
    grandchild_cluster_name: &str,
    provider: InfraProvider,
) -> Result<(), String> {
    info!(
        "[Integration/Proxy] Testing proxy access from root to grandchild {}...",
        grandchild_cluster_name
    );

    // Get the proxy URL from root cluster
    let proxy_url = get_proxy_url_for_provider(root_kubeconfig, provider)?;

    // Get a ServiceAccount token from the root cluster
    let token = get_sa_token(root_kubeconfig, PROXY_TEST_NAMESPACE, PROXY_TEST_SA)?;

    // Test proxy access and validate response
    verify_proxy_namespace_access(&proxy_url, &token, grandchild_cluster_name, "grandchild")
}

/// Verify proxy access to a cluster by fetching namespaces.
///
/// This is the core validation logic used by both direct child and grandchild tests.
fn verify_proxy_namespace_access(
    proxy_url: &str,
    token: &str,
    cluster_name: &str,
    cluster_type: &str,
) -> Result<(), String> {
    let url = format!("{}/clusters/{}/api/v1/namespaces", proxy_url, cluster_name);
    let response = http_get_with_token(&url, token, 30);

    // Check for successful response
    if response.is_success() {
        if response.body.contains("\"kind\":\"NamespaceList\"")
            || response.body.contains("\"kind\": \"NamespaceList\"")
        {
            let namespace_count = response.body.matches("\"kind\":\"Namespace\"").count()
                + response.body.matches("\"kind\": \"Namespace\"").count();
            info!(
                "[Integration/Proxy] SUCCESS: {} proxy access to {} worked - {} namespaces visible",
                cluster_type, cluster_name, namespace_count
            );
            return Ok(());
        }
    }

    // Check for specific error types
    if response.is_forbidden() {
        return Err(format!(
            "Proxy access denied (403 Forbidden) to {} {} - Cedar policy may be missing. Response: {}",
            cluster_type, cluster_name, truncate_response(&response.body)
        ));
    }

    if response.is_unauthorized() {
        return Err(format!(
            "Proxy authentication failed (401 Unauthorized) to {} {} - token validation failed. Response: {}",
            cluster_type, cluster_name, truncate_response(&response.body)
        ));
    }

    if response.body.contains("agent not connected") || response.body.contains("ClusterNotFound") {
        return Err(format!(
            "{} {} not reachable - cluster may not be registered or agent disconnected",
            cluster_type, cluster_name
        ));
    }

    if response.status_code == 0 {
        return Err(format!(
            "Proxy request failed - could not connect to {}",
            url
        ));
    }

    Err(format!(
        "Unexpected proxy response for {} {} (HTTP {}) - expected NamespaceList. Response: {}",
        cluster_type,
        cluster_name,
        response.status_code,
        truncate_response(&response.body)
    ))
}

/// Run full proxy hierarchy tests with proper setup/teardown.
///
/// This function:
/// 1. Applies a default Cedar policy to allow E2E access
/// 2. Tests proxy access through the hierarchy
/// 3. Cleans up the policy
pub async fn run_proxy_hierarchy_tests(
    ctx: &InfraContext,
    workload_cluster_name: &str,
    workload2_cluster_name: &str,
) -> Result<(), String> {
    info!("[Integration/Proxy] Running full hierarchy proxy tests...");
    info!(
        "[Integration/Proxy] Hierarchy: mgmt -> {} -> {}",
        workload_cluster_name, workload2_cluster_name
    );

    // Apply default E2E policy to allow proxy access
    apply_e2e_default_policy(&ctx.mgmt_kubeconfig)?;

    // Use a closure to ensure cleanup happens even on error
    let result = run_proxy_tests_inner(ctx, workload_cluster_name, workload2_cluster_name).await;

    // Note: We don't remove the policy here because other tests may need it
    // The policy is labeled for E2E cleanup at test suite end

    result
}

/// Inner proxy test logic (separated for cleanup handling)
async fn run_proxy_tests_inner(
    ctx: &InfraContext,
    workload_cluster_name: &str,
    workload2_cluster_name: &str,
) -> Result<(), String> {
    // Wait for child agent
    wait_for_agent_ready(&ctx.mgmt_kubeconfig, workload_cluster_name).await?;

    // Test direct child access through proxy
    test_proxy_access_to_child(&ctx.mgmt_kubeconfig, workload_cluster_name, ctx.provider).await?;

    // Wait for grandchild agent and test hierarchical access
    if ctx.has_workload() {
        wait_for_agent_ready(
            ctx.workload_kubeconfig.as_deref().unwrap(),
            workload2_cluster_name,
        )
        .await?;

        // Test grandchild access through hierarchy
        test_proxy_access_to_grandchild(&ctx.mgmt_kubeconfig, workload2_cluster_name, ctx.provider)
            .await?;
    }

    info!("[Integration/Proxy] Proxy hierarchy tests complete");
    Ok(())
}

/// Truncate long responses for error messages
fn truncate_response(response: &str) -> String {
    if response.len() > 500 {
        format!("{}...(truncated)", &response[..500])
    } else {
        response.to_string()
    }
}

// ============================================================================
// Standalone Tests
// ============================================================================

/// Standalone test - test proxy access to child cluster
#[tokio::test]
#[ignore]
async fn test_proxy_access_standalone() {
    let ctx = init_test_env("Set LATTICE_MGMT_KUBECONFIG");
    let workload_name = std::env::var("LATTICE_WORKLOAD_CLUSTER_NAME")
        .unwrap_or_else(|_| WORKLOAD_CLUSTER_NAME.to_string());

    // Apply E2E policy
    apply_e2e_default_policy(&ctx.mgmt_kubeconfig).unwrap();

    wait_for_agent_ready(&ctx.mgmt_kubeconfig, &workload_name)
        .await
        .unwrap();

    let result =
        test_proxy_access_to_child(&ctx.mgmt_kubeconfig, &workload_name, ctx.provider).await;

    // Cleanup
    remove_e2e_default_policy(&ctx.mgmt_kubeconfig);

    result.unwrap();
}

/// Standalone test - test full hierarchy proxy
#[tokio::test]
#[ignore]
async fn test_proxy_hierarchy_standalone() {
    let ctx = init_test_env("Set LATTICE_MGMT_KUBECONFIG and LATTICE_WORKLOAD_KUBECONFIG");
    let workload_name = std::env::var("LATTICE_WORKLOAD_CLUSTER_NAME")
        .unwrap_or_else(|_| WORKLOAD_CLUSTER_NAME.to_string());
    let workload2_name = std::env::var("LATTICE_WORKLOAD2_CLUSTER_NAME")
        .unwrap_or_else(|_| WORKLOAD2_CLUSTER_NAME.to_string());

    run_proxy_hierarchy_tests(&ctx, &workload_name, &workload2_name)
        .await
        .unwrap();
}
