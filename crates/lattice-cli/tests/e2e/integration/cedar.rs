//! Cedar policy integration tests
//!
//! Tests ServiceAccount token authentication and Cedar policy enforcement.
//! Can be run standalone against an existing cluster or composed by E2E tests.
//!
//! # Architecture
//!
//! The proxy runs on parent clusters and authenticates requests using:
//! 1. OIDC tokens (for human users)
//! 2. ServiceAccount tokens via TokenReview API (for pods/services)
//!
//! Cedar policies control which identities can access which child clusters.
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_cedar_sa_auth_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;
use tracing::info;

use lattice_common::LATTICE_SYSTEM_NAMESPACE;

use super::super::context::{InfraContext, TestSession};
use super::super::helpers::{
    apply_yaml_with_retry, get_child_cluster_name, get_or_create_proxy, get_sa_token,
    http_get_with_retry, proxy_service_exists, run_cmd,
};

// =============================================================================
// Constants
// =============================================================================

/// Test namespace for Cedar tests
const CEDAR_TEST_NAMESPACE: &str = "cedar-test";

/// Test ServiceAccount name that will be allowed
const ALLOWED_SA_NAME: &str = "cedar-allowed-sa";

/// Test ServiceAccount name that will be denied
const DENIED_SA_NAME: &str = "cedar-denied-sa";

// =============================================================================
// Setup Functions
// =============================================================================

/// Create test namespace and ServiceAccounts for Cedar tests
pub async fn setup_cedar_test_resources(kubeconfig: &str) -> Result<(), String> {
    info!("[Integration/Cedar] Creating test namespace and ServiceAccounts...");

    // Create namespace
    let namespace_yaml = format!(
        r#"apiVersion: v1
kind: Namespace
metadata:
  name: {}"#,
        CEDAR_TEST_NAMESPACE
    );
    apply_yaml_with_retry(kubeconfig, &namespace_yaml).await?;

    // Create allowed ServiceAccount
    let allowed_sa_yaml = format!(
        r#"apiVersion: v1
kind: ServiceAccount
metadata:
  name: {}
  namespace: {}"#,
        ALLOWED_SA_NAME, CEDAR_TEST_NAMESPACE
    );
    apply_yaml_with_retry(kubeconfig, &allowed_sa_yaml).await?;

    // Create denied ServiceAccount
    let denied_sa_yaml = format!(
        r#"apiVersion: v1
kind: ServiceAccount
metadata:
  name: {}
  namespace: {}"#,
        DENIED_SA_NAME, CEDAR_TEST_NAMESPACE
    );
    apply_yaml_with_retry(kubeconfig, &denied_sa_yaml).await?;

    info!("[Integration/Cedar] Test resources created successfully");
    Ok(())
}

/// Apply a CedarPolicy that allows a specific ServiceAccount to access a cluster
pub async fn apply_cedar_policy_allow_sa(
    kubeconfig: &str,
    policy_name: &str,
    sa_namespace: &str,
    sa_name: &str,
    cluster_name: &str,
) -> Result<(), String> {
    let full_sa_name = format!("system:serviceaccount:{}:{}", sa_namespace, sa_name);

    let policy_yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: CedarPolicy
metadata:
  name: {}
  namespace: lattice-system
  labels:
    lattice.dev/test: cedar
spec:
  enabled: true
  priority: 100
  policies: |
    permit(
      principal == Lattice::User::"{}",
      action,
      resource == Lattice::Cluster::"{}"
    );"#,
        policy_name, full_sa_name, cluster_name
    );

    apply_yaml_with_retry(kubeconfig, &policy_yaml).await?;
    info!(
        "[Integration/Cedar] Applied CedarPolicy allowing {} on {}",
        full_sa_name, cluster_name
    );

    // Wait for policy to be loaded
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(())
}

/// Apply a CedarPolicy that allows a group of ServiceAccounts
pub async fn apply_cedar_policy_allow_group(
    kubeconfig: &str,
    policy_name: &str,
    group_name: &str,
    cluster_name: &str,
) -> Result<(), String> {
    let policy_yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: CedarPolicy
metadata:
  name: {}
  namespace: lattice-system
  labels:
    lattice.dev/test: cedar
spec:
  enabled: true
  priority: 100
  policies: |
    permit(
      principal in Lattice::Group::"{}",
      action,
      resource == Lattice::Cluster::"{}"
    );"#,
        policy_name, group_name, cluster_name
    );

    apply_yaml_with_retry(kubeconfig, &policy_yaml).await?;
    info!(
        "[Integration/Cedar] Applied CedarPolicy allowing group {} on {}",
        group_name, cluster_name
    );

    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(())
}

/// Delete a CedarPolicy
pub fn delete_cedar_policy(kubeconfig: &str, policy_name: &str) -> Result<(), String> {
    run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "delete",
            "cedarpolicy",
            policy_name,
            "-n",
            LATTICE_SYSTEM_NAMESPACE,
            "--ignore-not-found",
        ],
    )?;
    info!("[Integration/Cedar] Deleted CedarPolicy {}", policy_name);
    Ok(())
}

/// Clean up test resources (policies only, namespace persists for subsequent tests)
pub fn cleanup_cedar_test_resources(kubeconfig: &str) {
    info!("[Integration/Cedar] Cleaning up test resources...");

    // Delete test policies only - namespace persists to avoid race conditions
    // between consecutive tests. Namespace gets cleaned up with cluster deletion.
    let _ = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "delete",
            "cedarpolicy",
            "-n",
            LATTICE_SYSTEM_NAMESPACE,
            "-l",
            "lattice.dev/test=cedar",
            "--ignore-not-found",
        ],
    );

    info!("[Integration/Cedar] Cleanup complete");
}

/// E2E default policy name
pub const E2E_DEFAULT_POLICY_NAME: &str = "e2e-allow-all";

/// Apply a default Cedar policy for E2E tests that allows all authenticated access.
///
/// This policy permits any authenticated user/service to access any cluster.
/// It should be applied during E2E setup and removed during cleanup.
pub async fn apply_e2e_default_policy(kubeconfig: &str) -> Result<(), String> {
    info!("[Integration/Cedar] Applying default E2E policy (permit all authenticated)...");

    let policy_yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: CedarPolicy
metadata:
  name: {}
  namespace: lattice-system
  labels:
    lattice.dev/e2e: "true"
spec:
  enabled: true
  priority: 1000
  policies: |
    // E2E test policy - permit all authenticated users to access all clusters
    permit(principal, action, resource);"#,
        E2E_DEFAULT_POLICY_NAME
    );

    apply_yaml_with_retry(kubeconfig, &policy_yaml).await?;

    // Wait for policy to be loaded by the operator
    tokio::time::sleep(Duration::from_secs(3)).await;

    info!("[Integration/Cedar] Default E2E policy applied");
    Ok(())
}

/// Remove the default E2E Cedar policy.
pub fn remove_e2e_default_policy(kubeconfig: &str) {
    info!("[Integration/Cedar] Removing default E2E policy...");
    let _ = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "delete",
            "cedarpolicy",
            E2E_DEFAULT_POLICY_NAME,
            "-n",
            LATTICE_SYSTEM_NAMESPACE,
            "--ignore-not-found",
        ],
    );
}

// =============================================================================
// Verification Functions
// =============================================================================

/// Verify SA has access to the proxy (expects 200 OK)
///
/// Uses retry logic to handle transient failures from chaos testing.
async fn verify_sa_access_allowed(
    proxy_url: &str,
    token: &str,
    cluster_name: &str,
) -> Result<(), String> {
    let url = format!("{}/clusters/{}/api/v1/namespaces", proxy_url, cluster_name);
    let response = http_get_with_retry(&url, token, 10).await?;

    if response.is_success() {
        info!(
            "[Integration/Cedar] Access allowed as expected (HTTP {})",
            response.status_code
        );
        Ok(())
    } else {
        Err(format!(
            "Expected HTTP 200, got {} for allowed SA at {}",
            response.status_code, url
        ))
    }
}

/// Verify SA is denied access to the proxy (expects 403 Forbidden)
///
/// Uses retry logic to handle transient failures from chaos testing.
/// Note: 403 responses are NOT retried (correct behavior for this test).
async fn verify_sa_access_denied(
    proxy_url: &str,
    token: &str,
    cluster_name: &str,
) -> Result<(), String> {
    let url = format!("{}/clusters/{}/api/v1/namespaces", proxy_url, cluster_name);
    let response = http_get_with_retry(&url, token, 10).await?;

    if response.is_forbidden() {
        info!(
            "[Integration/Cedar] Access denied as expected (HTTP {})",
            response.status_code
        );
        Ok(())
    } else {
        Err(format!(
            "Expected HTTP 403, got {} for denied SA at {}",
            response.status_code, url
        ))
    }
}

// =============================================================================
// Core Test Functions (E2E Compatible)
// =============================================================================

/// Run Cedar policy tests for proxy access to a child cluster
///
/// This test:
/// 1. Creates ServiceAccounts on the parent cluster
/// 2. Creates a CedarPolicy allowing one SA to access the child cluster
/// 3. Verifies the allowed SA can access the child through the proxy
/// 4. Verifies the denied SA cannot access the child through the proxy
///
/// # Arguments
/// * `parent_kubeconfig` - Kubeconfig for the parent cluster (where proxy runs)
/// * `child_cluster_name` - Name of the child cluster to test access to
/// * `existing_proxy_url` - Optional existing proxy URL (avoids creating new port-forward)
pub async fn run_cedar_proxy_test(
    parent_kubeconfig: &str,
    child_cluster_name: &str,
    existing_proxy_url: Option<&str>,
) -> Result<(), String> {
    info!(
        "[Integration/Cedar] Running Cedar proxy test for access to {}...",
        child_cluster_name
    );

    // Remove any existing default E2E policy that would override our test policies
    // This is important for standalone tests where the E2E setup might have left it behind
    remove_e2e_default_policy(parent_kubeconfig);
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Get or create proxy connection
    let (proxy_url, _port_forward) = get_or_create_proxy(parent_kubeconfig, existing_proxy_url)?;

    // Setup test resources on parent cluster
    setup_cedar_test_resources(parent_kubeconfig).await?;

    // Apply policy allowing the "allowed" SA to access the child cluster
    apply_cedar_policy_allow_sa(
        parent_kubeconfig,
        &format!("cedar-test-allow-{}", child_cluster_name),
        CEDAR_TEST_NAMESPACE,
        ALLOWED_SA_NAME,
        child_cluster_name,
    )
    .await?;

    // Get tokens from parent cluster
    let allowed_token = get_sa_token(parent_kubeconfig, CEDAR_TEST_NAMESPACE, ALLOWED_SA_NAME)?;
    let denied_token = get_sa_token(parent_kubeconfig, CEDAR_TEST_NAMESPACE, DENIED_SA_NAME)?;

    // Verify allowed SA has access
    info!("[Integration/Cedar] Testing allowed SA access...");
    verify_sa_access_allowed(&proxy_url, &allowed_token, child_cluster_name).await?;

    // Verify denied SA is denied
    info!("[Integration/Cedar] Testing denied SA access...");
    verify_sa_access_denied(&proxy_url, &denied_token, child_cluster_name).await?;

    // Cleanup
    delete_cedar_policy(
        parent_kubeconfig,
        &format!("cedar-test-allow-{}", child_cluster_name),
    )?;
    cleanup_cedar_test_resources(parent_kubeconfig);

    info!(
        "[Integration/Cedar] Cedar proxy test for {} passed!",
        child_cluster_name
    );
    Ok(())
}

/// Run Cedar group policy test
///
/// Tests that Cedar policies can grant access based on ServiceAccount groups.
///
/// # Arguments
/// * `parent_kubeconfig` - Kubeconfig for the parent cluster (where proxy runs)
/// * `child_cluster_name` - Name of the child cluster to test access to
/// * `existing_proxy_url` - Optional existing proxy URL (avoids creating new port-forward)
pub async fn run_cedar_group_test(
    parent_kubeconfig: &str,
    child_cluster_name: &str,
    existing_proxy_url: Option<&str>,
) -> Result<(), String> {
    info!(
        "[Integration/Cedar] Running group policy test for {}...",
        child_cluster_name
    );

    // Remove any existing default E2E policy that would override our test policies
    remove_e2e_default_policy(parent_kubeconfig);
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Get or create proxy connection
    let (proxy_url, _port_forward) = get_or_create_proxy(parent_kubeconfig, existing_proxy_url)?;

    // Setup
    setup_cedar_test_resources(parent_kubeconfig).await?;

    // Apply policy allowing all SAs in the test namespace group
    let group_name = format!("system:serviceaccounts:{}", CEDAR_TEST_NAMESPACE);
    apply_cedar_policy_allow_group(
        parent_kubeconfig,
        &format!("cedar-test-group-{}", child_cluster_name),
        &group_name,
        child_cluster_name,
    )
    .await?;

    // Get tokens for SAs in the group (both should be allowed)
    let in_group_token1 = get_sa_token(parent_kubeconfig, CEDAR_TEST_NAMESPACE, ALLOWED_SA_NAME)?;
    let in_group_token2 = get_sa_token(parent_kubeconfig, CEDAR_TEST_NAMESPACE, DENIED_SA_NAME)?;

    // Get token for SA outside the group (should be denied)
    let outside_group_token = get_sa_token(parent_kubeconfig, LATTICE_SYSTEM_NAMESPACE, "default")?;

    // SAs in the group should have access
    info!("[Integration/Cedar] Testing SA in group (should be allowed)...");
    verify_sa_access_allowed(&proxy_url, &in_group_token1, child_cluster_name).await?;

    info!("[Integration/Cedar] Testing second SA in group (should be allowed)...");
    verify_sa_access_allowed(&proxy_url, &in_group_token2, child_cluster_name).await?;

    // SA outside the group should be denied
    info!("[Integration/Cedar] Testing SA outside group (should be denied)...");
    verify_sa_access_denied(&proxy_url, &outside_group_token, child_cluster_name).await?;

    // Cleanup
    delete_cedar_policy(
        parent_kubeconfig,
        &format!("cedar-test-group-{}", child_cluster_name),
    )?;
    cleanup_cedar_test_resources(parent_kubeconfig);

    info!("[Integration/Cedar] Group policy test passed!");
    Ok(())
}

/// Run all Cedar integration tests for a parent-child cluster pair
///
/// This is the main entry point for E2E tests.
/// If the proxy service is not deployed, tests are skipped gracefully.
/// Uses the proxy URL from the context if available to avoid creating redundant port-forwards.
pub async fn run_cedar_hierarchy_tests(
    ctx: &InfraContext,
    child_cluster_name: &str,
) -> Result<(), String> {
    info!(
        "[Integration/Cedar] Running Cedar hierarchy tests (parent -> {})...",
        child_cluster_name
    );

    // Check if proxy service exists
    if !proxy_service_exists(&ctx.mgmt_kubeconfig) {
        info!("[Integration/Cedar] Proxy service not deployed - skipping Cedar tests");
        info!("[Integration/Cedar] (This is expected if lattice-api is not yet implemented)");
        return Ok(());
    }

    // Use existing proxy URL from context if available
    let proxy_url = ctx.mgmt_proxy_url.as_deref();

    // Run SA-specific policy test
    run_cedar_proxy_test(&ctx.mgmt_kubeconfig, child_cluster_name, proxy_url).await?;

    // Run group policy test
    run_cedar_group_test(&ctx.mgmt_kubeconfig, child_cluster_name, proxy_url).await?;

    // Restore the default E2E policy after tests complete
    // This is critical - subsequent tests (mesh, secrets) use the proxy kubeconfig
    // and will fail without a Cedar policy allowing access
    apply_e2e_default_policy(&ctx.mgmt_kubeconfig).await?;

    info!("[Integration/Cedar] All Cedar hierarchy tests passed!");
    Ok(())
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone test - test SA token authentication with Cedar policies
///
/// Requires `LATTICE_MGMT_KUBECONFIG` and `LATTICE_CHILD_CLUSTER_NAME` environment variables.
/// Uses TestSession to automatically manage port-forwards for proxy access.
#[tokio::test]
#[ignore]
async fn test_cedar_sa_auth_standalone() {
    let session =
        TestSession::from_env("Set LATTICE_MGMT_KUBECONFIG to run standalone Cedar tests").unwrap();
    let child_cluster_name = get_child_cluster_name();

    run_cedar_proxy_test(
        &session.ctx.mgmt_kubeconfig,
        &child_cluster_name,
        session.ctx.mgmt_proxy_url.as_deref(),
    )
    .await
    .unwrap();
}

/// Standalone test - test group-based Cedar policies
///
/// Uses TestSession to automatically manage port-forwards for proxy access.
#[tokio::test]
#[ignore]
async fn test_cedar_group_policy_standalone() {
    let session =
        TestSession::from_env("Set LATTICE_MGMT_KUBECONFIG to run standalone Cedar tests").unwrap();
    let child_cluster_name = get_child_cluster_name();

    run_cedar_group_test(
        &session.ctx.mgmt_kubeconfig,
        &child_cluster_name,
        session.ctx.mgmt_proxy_url.as_deref(),
    )
    .await
    .unwrap();
}

/// Standalone test - run all Cedar tests
///
/// Uses TestSession to automatically manage port-forwards for proxy access.
#[tokio::test]
#[ignore]
async fn test_cedar_all_standalone() {
    let session =
        TestSession::from_env("Set LATTICE_MGMT_KUBECONFIG to run standalone Cedar tests").unwrap();
    let child_cluster_name = get_child_cluster_name();

    run_cedar_hierarchy_tests(&session.ctx, &child_cluster_name)
        .await
        .unwrap();
}
