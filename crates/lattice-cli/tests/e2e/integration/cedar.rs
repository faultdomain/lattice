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
    apply_cedar_policy_crd, apply_yaml_with_retry, delete_cedar_policies_by_label,
    delete_namespace, get_child_cluster_name, get_or_create_proxy, get_sa_token,
    http_get_with_retry, proxy_service_exists, run_kubectl,
};

// =============================================================================
// Constants
// =============================================================================

/// Namespace for Cedar proxy SA tests
const CEDAR_PROXY_TEST_NS: &str = "cedar-proxy-test";

/// Namespace for Cedar group policy tests
const CEDAR_GROUP_TEST_NS: &str = "cedar-group-test";

/// Test ServiceAccount name that will be allowed
const ALLOWED_SA_NAME: &str = "cedar-allowed-sa";

/// Test ServiceAccount name that will be denied
const DENIED_SA_NAME: &str = "cedar-denied-sa";

// =============================================================================
// Setup Functions
// =============================================================================

/// Create test namespace and ServiceAccounts for Cedar tests
async fn setup_cedar_test_resources(kubeconfig: &str, namespace: &str) -> Result<(), String> {
    info!(
        "[Integration/Cedar] Creating test namespace {} and ServiceAccounts...",
        namespace
    );

    // Create namespace
    let namespace_yaml = format!(
        r#"apiVersion: v1
kind: Namespace
metadata:
  name: {}"#,
        namespace
    );
    apply_yaml_with_retry(kubeconfig, &namespace_yaml).await?;

    // Create allowed ServiceAccount
    let allowed_sa_yaml = format!(
        r#"apiVersion: v1
kind: ServiceAccount
metadata:
  name: {}
  namespace: {}"#,
        ALLOWED_SA_NAME, namespace
    );
    apply_yaml_with_retry(kubeconfig, &allowed_sa_yaml).await?;

    // Create denied ServiceAccount
    let denied_sa_yaml = format!(
        r#"apiVersion: v1
kind: ServiceAccount
metadata:
  name: {}
  namespace: {}"#,
        DENIED_SA_NAME, namespace
    );
    apply_yaml_with_retry(kubeconfig, &denied_sa_yaml).await?;

    info!("[Integration/Cedar] Test resources created successfully");
    Ok(())
}

/// Apply a CedarPolicy that allows a specific ServiceAccount to access a cluster
async fn apply_cedar_policy_allow_sa(
    kubeconfig: &str,
    policy_name: &str,
    sa_namespace: &str,
    sa_name: &str,
    cluster_name: &str,
) -> Result<(), String> {
    let full_sa_name = format!("system:serviceaccount:{}:{}", sa_namespace, sa_name);
    let cedar = format!(
        r#"permit(
  principal == Lattice::User::"{sa}",
  action,
  resource == Lattice::Cluster::"{cluster}"
);"#,
        sa = full_sa_name,
        cluster = cluster_name,
    );
    apply_cedar_policy_crd(kubeconfig, policy_name, "cedar", 100, &cedar).await
}

/// Apply a CedarPolicy that allows a group of ServiceAccounts
pub async fn apply_cedar_policy_allow_group(
    kubeconfig: &str,
    policy_name: &str,
    group_name: &str,
    cluster_name: &str,
) -> Result<(), String> {
    let cedar = format!(
        r#"permit(
  principal in Lattice::Group::"{group}",
  action,
  resource == Lattice::Cluster::"{cluster}"
);"#,
        group = group_name,
        cluster = cluster_name,
    );
    apply_cedar_policy_crd(kubeconfig, policy_name, "cedar", 100, &cedar).await
}

/// Delete a CedarPolicy
pub async fn delete_cedar_policy(kubeconfig: &str, policy_name: &str) -> Result<(), String> {
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "cedarpolicy",
        policy_name,
        "-n",
        LATTICE_SYSTEM_NAMESPACE,
        "--ignore-not-found",
    ])
    .await?;
    info!("[Integration/Cedar] Deleted CedarPolicy {}", policy_name);
    Ok(())
}

/// Clean up all Cedar test policies (safety net for failures)
pub async fn cleanup_cedar_test_policies(kubeconfig: &str) {
    delete_cedar_policies_by_label(kubeconfig, "lattice.dev/test=cedar").await;
}

/// E2E default policy name
pub const E2E_DEFAULT_POLICY_NAME: &str = "e2e-allow-all";

/// Apply a default Cedar policy for E2E tests that allows all authenticated access.
///
/// This policy permits any authenticated user/service to access any cluster.
/// It should be applied during E2E setup and removed during cleanup.
pub async fn apply_e2e_default_policy(kubeconfig: &str) -> Result<(), String> {
    info!("[Integration/Cedar] Applying default E2E policy (permit all authenticated)...");
    apply_cedar_policy_crd(
        kubeconfig,
        E2E_DEFAULT_POLICY_NAME,
        "e2e",
        1000,
        "// E2E test policy - permit all authenticated users to access all clusters\n// Scoped to AccessCluster only — must NOT permit AccessSecret (Cedar secrets tests rely on default-deny)\npermit(principal, action == Lattice::Action::\"AccessCluster\", resource);",
    ).await?;
    info!("[Integration/Cedar] Default E2E policy applied");
    Ok(())
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

    let (proxy_url, _port_forward) =
        get_or_create_proxy(parent_kubeconfig, existing_proxy_url).await?;

    setup_cedar_test_resources(parent_kubeconfig, CEDAR_PROXY_TEST_NS).await?;

    let policy_name = format!("cedar-test-allow-{}", child_cluster_name);
    apply_cedar_policy_allow_sa(
        parent_kubeconfig,
        &policy_name,
        CEDAR_PROXY_TEST_NS,
        ALLOWED_SA_NAME,
        child_cluster_name,
    )
    .await?;

    let allowed_token =
        get_sa_token(parent_kubeconfig, CEDAR_PROXY_TEST_NS, ALLOWED_SA_NAME).await?;
    let denied_token = get_sa_token(parent_kubeconfig, CEDAR_PROXY_TEST_NS, DENIED_SA_NAME).await?;

    info!("[Integration/Cedar] Testing allowed SA access...");
    verify_sa_access_allowed(&proxy_url, &allowed_token, child_cluster_name).await?;

    info!("[Integration/Cedar] Testing denied SA access...");
    verify_sa_access_denied(&proxy_url, &denied_token, child_cluster_name).await?;

    delete_cedar_policy(parent_kubeconfig, &policy_name).await?;
    delete_namespace(parent_kubeconfig, CEDAR_PROXY_TEST_NS).await;

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

    let (proxy_url, _port_forward) =
        get_or_create_proxy(parent_kubeconfig, existing_proxy_url).await?;

    setup_cedar_test_resources(parent_kubeconfig, CEDAR_GROUP_TEST_NS).await?;

    let policy_name = format!("cedar-test-group-{}", child_cluster_name);
    let group_name = format!("system:serviceaccounts:{}", CEDAR_GROUP_TEST_NS);
    apply_cedar_policy_allow_group(
        parent_kubeconfig,
        &policy_name,
        &group_name,
        child_cluster_name,
    )
    .await?;

    let in_group_token1 =
        get_sa_token(parent_kubeconfig, CEDAR_GROUP_TEST_NS, ALLOWED_SA_NAME).await?;
    let in_group_token2 =
        get_sa_token(parent_kubeconfig, CEDAR_GROUP_TEST_NS, DENIED_SA_NAME).await?;
    let outside_group_token =
        get_sa_token(parent_kubeconfig, LATTICE_SYSTEM_NAMESPACE, "default").await?;

    info!("[Integration/Cedar] Testing SA in group (should be allowed)...");
    verify_sa_access_allowed(&proxy_url, &in_group_token1, child_cluster_name).await?;

    info!("[Integration/Cedar] Testing second SA in group (should be allowed)...");
    verify_sa_access_allowed(&proxy_url, &in_group_token2, child_cluster_name).await?;

    info!("[Integration/Cedar] Testing SA outside group (should be denied)...");
    verify_sa_access_denied(&proxy_url, &outside_group_token, child_cluster_name).await?;

    delete_cedar_policy(parent_kubeconfig, &policy_name).await?;
    delete_namespace(parent_kubeconfig, CEDAR_GROUP_TEST_NS).await;

    info!("[Integration/Cedar] Group policy test passed!");
    Ok(())
}

/// Run all Cedar integration tests for a parent-child cluster pair.
///
/// Main entry point for E2E tests. Each test uses its own namespace so both
/// run concurrently. The E2E default policy is removed before tests (so deny
/// checks work) and restored after (so subsequent tests have access).
pub async fn run_cedar_hierarchy_tests(
    ctx: &InfraContext,
    child_cluster_name: &str,
) -> Result<(), String> {
    info!(
        "[Integration/Cedar] Running Cedar hierarchy tests (parent -> {})...",
        child_cluster_name
    );

    if !proxy_service_exists(&ctx.mgmt_kubeconfig).await {
        info!("[Integration/Cedar] Proxy service not deployed - skipping Cedar tests");
        return Ok(());
    }

    // Remove default E2E policy so deny checks work correctly
    let _ = delete_cedar_policy(&ctx.mgmt_kubeconfig, E2E_DEFAULT_POLICY_NAME).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let proxy_url = ctx.mgmt_proxy_url.as_deref();
    let kubeconfig = &ctx.mgmt_kubeconfig;

    let result = tokio::try_join!(
        run_cedar_proxy_test(kubeconfig, child_cluster_name, proxy_url),
        run_cedar_group_test(kubeconfig, child_cluster_name, proxy_url),
    );

    // Safety net: clean up any leftover policies on failure
    cleanup_cedar_test_policies(kubeconfig).await;

    // Restore default policy for subsequent tests (mesh, secrets, etc.)
    apply_e2e_default_policy(kubeconfig).await?;

    result.map_err(|e| e.to_string())?;

    info!("[Integration/Cedar] All Cedar hierarchy tests passed!");
    Ok(())
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone test - test SA token authentication with Cedar policies
#[tokio::test]
#[ignore]
async fn test_cedar_sa_auth_standalone() {
    let session =
        TestSession::from_env("Set LATTICE_MGMT_KUBECONFIG to run standalone Cedar tests")
            .await
            .unwrap();
    let child_cluster_name = get_child_cluster_name();

    let _ = delete_cedar_policy(&session.ctx.mgmt_kubeconfig, E2E_DEFAULT_POLICY_NAME).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    run_cedar_proxy_test(
        &session.ctx.mgmt_kubeconfig,
        &child_cluster_name,
        session.ctx.mgmt_proxy_url.as_deref(),
    )
    .await
    .unwrap();
}

/// Standalone test - test group-based Cedar policies
#[tokio::test]
#[ignore]
async fn test_cedar_group_policy_standalone() {
    let session =
        TestSession::from_env("Set LATTICE_MGMT_KUBECONFIG to run standalone Cedar tests")
            .await
            .unwrap();
    let child_cluster_name = get_child_cluster_name();

    let _ = delete_cedar_policy(&session.ctx.mgmt_kubeconfig, E2E_DEFAULT_POLICY_NAME).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    run_cedar_group_test(
        &session.ctx.mgmt_kubeconfig,
        &child_cluster_name,
        session.ctx.mgmt_proxy_url.as_deref(),
    )
    .await
    .unwrap();
}

/// Standalone test - run all Cedar tests
#[tokio::test]
#[ignore]
async fn test_cedar_all_standalone() {
    let session =
        TestSession::from_env("Set LATTICE_MGMT_KUBECONFIG to run standalone Cedar tests")
            .await
            .unwrap();
    let child_cluster_name = get_child_cluster_name();

    run_cedar_hierarchy_tests(&session.ctx, &child_cluster_name)
        .await
        .unwrap();
}
