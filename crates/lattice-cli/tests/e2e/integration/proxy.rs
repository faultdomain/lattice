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

use super::super::context::{InfraContext, TestSession};
use super::super::helpers::{
    get_or_create_proxy, get_sa_token, get_workload2_cluster_name, get_workload_cluster_name,
    http_get_with_retry, run_cmd,
};
use super::cedar::{apply_e2e_default_policy, remove_e2e_default_policy};

// ============================================================================
// Constants
// ============================================================================

/// Namespace for proxy test ServiceAccount
const PROXY_TEST_NAMESPACE: &str = "lattice-system";

/// ServiceAccount name for proxy tests (uses the operator SA which has proper permissions)
const PROXY_TEST_SA: &str = "lattice-operator";

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
        let phase_trimmed = match run_cmd(
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
        ) {
            Ok(output) => output.trim().to_string(),
            Err(_) => String::new(),
        };

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
///
/// # Arguments
/// * `parent_kubeconfig` - Kubeconfig for the parent cluster
/// * `child_cluster_name` - Name of the child cluster to access
/// * `existing_proxy_url` - Optional existing proxy URL (avoids creating new port-forward)
pub async fn test_proxy_access_to_child(
    parent_kubeconfig: &str,
    child_cluster_name: &str,
    existing_proxy_url: Option<&str>,
) -> Result<(), String> {
    info!(
        "[Integration/Proxy] Testing proxy access to {}...",
        child_cluster_name
    );

    // Get or create proxy connection
    let (proxy_url, _port_forward) = get_or_create_proxy(parent_kubeconfig, existing_proxy_url)?;

    // Get a ServiceAccount token from the parent cluster
    let token = get_sa_token(parent_kubeconfig, PROXY_TEST_NAMESPACE, PROXY_TEST_SA)?;
    info!(
        "[Integration/Proxy] Got SA token for {}/{}",
        PROXY_TEST_NAMESPACE, PROXY_TEST_SA
    );

    // Test proxy access and validate response
    verify_proxy_namespace_access(&proxy_url, &token, child_cluster_name, "child").await
}

/// Test proxy access from root cluster to grandchild cluster.
///
/// This tests hierarchical proxy routing:
/// Root (mgmt) → Child (workload) → Grandchild (workload2)
///
/// The request should route through the hierarchy via gRPC tunnels.
///
/// # Arguments
/// * `root_kubeconfig` - Kubeconfig for the root cluster
/// * `grandchild_cluster_name` - Name of the grandchild cluster to access
/// * `existing_proxy_url` - Optional existing proxy URL (avoids creating new port-forward)
pub async fn test_proxy_access_to_grandchild(
    root_kubeconfig: &str,
    grandchild_cluster_name: &str,
    existing_proxy_url: Option<&str>,
) -> Result<(), String> {
    info!(
        "[Integration/Proxy] Testing proxy access from root to grandchild {}...",
        grandchild_cluster_name
    );

    // Get or create proxy connection
    let (proxy_url, _port_forward) = get_or_create_proxy(root_kubeconfig, existing_proxy_url)?;

    // Get a ServiceAccount token from the root cluster
    let token = get_sa_token(root_kubeconfig, PROXY_TEST_NAMESPACE, PROXY_TEST_SA)?;

    // Test proxy access and validate response
    verify_proxy_namespace_access(&proxy_url, &token, grandchild_cluster_name, "grandchild").await
}

/// Verify proxy access to a cluster by fetching namespaces.
///
/// This is the core validation logic used by both direct child and grandchild tests.
/// Uses retry logic to handle transient failures from chaos testing.
async fn verify_proxy_namespace_access(
    proxy_url: &str,
    token: &str,
    cluster_name: &str,
    cluster_type: &str,
) -> Result<(), String> {
    let url = format!("{}/clusters/{}/api/v1/namespaces", proxy_url, cluster_name);
    let response = http_get_with_retry(&url, token, 30).await?;

    // Check for successful response
    if response.is_success() {
        // Parse the JSON response to count items properly
        // K8s list responses have items array but don't include "kind" on each item
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response.body) {
            if json.get("kind").and_then(|k| k.as_str()) == Some("NamespaceList") {
                let namespace_count = json
                    .get("items")
                    .and_then(|items| items.as_array())
                    .map(|arr| arr.len())
                    .unwrap_or(0);

                // Every cluster has at least kube-system, default, etc.
                if namespace_count == 0 {
                    return Err(format!(
                        "Proxy returned NamespaceList but 0 namespaces visible for {} {} - this indicates a permission issue",
                        cluster_type, cluster_name
                    ));
                }

                info!(
                    "[Integration/Proxy] SUCCESS: {} proxy access to {} worked - {} namespaces visible",
                    cluster_type, cluster_name, namespace_count
                );
                return Ok(());
            }
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

    Err(format!(
        "Unexpected proxy response for {} {} (HTTP {}) - expected NamespaceList. Response: {}",
        cluster_type,
        cluster_name,
        response.status_code,
        truncate_response(&response.body)
    ))
}

/// Run proxy tests with proper setup/teardown.
///
/// This function:
/// 1. Applies a default Cedar policy to allow E2E access
/// 2. Tests proxy access to workload cluster
/// 3. Optionally tests proxy access to workload2 cluster (if provided)
pub async fn run_proxy_tests(
    ctx: &InfraContext,
    workload_cluster_name: &str,
    workload2_cluster_name: Option<&str>,
) -> Result<(), String> {
    if let Some(w2_name) = workload2_cluster_name {
        info!(
            "[Integration/Proxy] Running proxy tests (hierarchy: mgmt -> {} -> {})...",
            workload_cluster_name, w2_name
        );
    } else {
        info!(
            "[Integration/Proxy] Running proxy tests (hierarchy: mgmt -> {})...",
            workload_cluster_name
        );
    }

    // Apply default E2E policy to allow proxy access
    apply_e2e_default_policy(&ctx.mgmt_kubeconfig).await?;

    // Use existing proxy URL from context if available
    let mgmt_proxy_url = ctx.mgmt_proxy_url.as_deref();

    // Wait for child agent
    wait_for_agent_ready(&ctx.mgmt_kubeconfig, workload_cluster_name).await?;

    // Test direct child access through proxy
    test_proxy_access_to_child(&ctx.mgmt_kubeconfig, workload_cluster_name, mgmt_proxy_url).await?;

    // Wait for grandchild agent and test hierarchical access (if workload2 exists)
    if let Some(w2_name) = workload2_cluster_name {
        if ctx.has_workload() {
            wait_for_agent_ready(ctx.workload_kubeconfig.as_deref().unwrap(), w2_name).await?;

            // Test grandchild access through hierarchy
            test_proxy_access_to_grandchild(&ctx.mgmt_kubeconfig, w2_name, mgmt_proxy_url).await?;
        }
    }

    info!("[Integration/Proxy] Proxy tests complete");
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
///
/// Uses TestSession to automatically manage port-forwards for proxy access.
#[tokio::test]
#[ignore]
async fn test_proxy_access_standalone() {
    let session = TestSession::from_env("Set LATTICE_MGMT_KUBECONFIG").unwrap();
    let workload_name = get_workload_cluster_name();

    // Apply E2E policy
    apply_e2e_default_policy(&session.ctx.mgmt_kubeconfig)
        .await
        .unwrap();

    wait_for_agent_ready(&session.ctx.mgmt_kubeconfig, &workload_name)
        .await
        .unwrap();

    // Use proxy URL from session (port-forward is managed by TestSession)
    let result = test_proxy_access_to_child(
        &session.ctx.mgmt_kubeconfig,
        &workload_name,
        session.ctx.mgmt_proxy_url.as_deref(),
    )
    .await;

    // Cleanup
    remove_e2e_default_policy(&session.ctx.mgmt_kubeconfig);

    result.unwrap();
}

/// Standalone test - test full hierarchy proxy
#[tokio::test]
#[ignore]
async fn test_proxy_hierarchy_standalone() {
    let session =
        TestSession::from_env("Set LATTICE_MGMT_KUBECONFIG and LATTICE_WORKLOAD_KUBECONFIG")
            .unwrap();
    let workload_name = get_workload_cluster_name();
    let workload2_name = if session.ctx.has_workload2() {
        Some(get_workload2_cluster_name())
    } else {
        None
    };

    run_proxy_tests(&session.ctx, &workload_name, workload2_name.as_deref())
        .await
        .unwrap();
}
