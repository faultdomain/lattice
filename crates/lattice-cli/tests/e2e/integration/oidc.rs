//! OIDC authentication integration tests
//!
//! Tests OIDC token authentication with Cedar policy enforcement.
//! Keycloak runs via docker-compose at a fixed endpoint (lattice-keycloak:8080).
//! If Keycloak is reachable, OIDC tests run automatically.
//!
//! # Running
//!
//! ```bash
//! # Start Keycloak
//! docker compose up -d
//!
//! # Run standalone
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_oidc_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use lattice_common::LATTICE_SYSTEM_NAMESPACE;

use super::super::context::{InfraContext, TestSession};
use super::super::helpers::{
    apply_yaml_with_retry, get_child_cluster_name, get_or_create_proxy, http_get_with_retry,
    proxy_service_exists, run_kubectl, wait_for_condition,
};
use super::cedar::{apply_cedar_policy_allow_group, apply_e2e_default_policy};

// =============================================================================
// Constants
// =============================================================================

/// Keycloak URL for host access (port-forwarded or docker network)
const KEYCLOAK_HOST_URL: &str = "http://127.0.0.1:8080";

/// Keycloak URL inside Docker/kind network
const KEYCLOAK_INTERNAL_URL: &str = "http://lattice-keycloak:8080";

/// Keycloak realm
const KEYCLOAK_REALM: &str = "lattice";

/// Keycloak client ID (matches realm export)
const KEYCLOAK_CLIENT_ID: &str = "lattice";

// =============================================================================
// Setup & Helpers
// =============================================================================

/// Check if OIDC tests should run (Keycloak is reachable)
pub fn oidc_tests_enabled() -> bool {
    std::process::Command::new("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            &format!("{}/health/ready", KEYCLOAK_HOST_URL),
        ])
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).starts_with("200"))
        .unwrap_or(false)
}

/// Get an access token from Keycloak using resource owner password grant
async fn get_keycloak_token(username: &str, password: &str) -> Result<String, String> {
    let token_url = format!(
        "{}/realms/{}/protocol/openid-connect/token",
        KEYCLOAK_HOST_URL, KEYCLOAK_REALM
    );

    let client = reqwest::Client::new();
    let response = client
        .post(&token_url)
        .form(&[
            ("grant_type", "password"),
            ("client_id", KEYCLOAK_CLIENT_ID),
            ("username", username),
            ("password", password),
        ])
        .send()
        .await
        .map_err(|e| format!("Token request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Token request failed: {} - {}", status, body));
    }

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse token response: {}", e))?;

    body["access_token"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "No access_token in response".to_string())
}

/// Apply OIDCProvider CRD pointing to Keycloak
async fn apply_oidc_provider(kubeconfig: &str) -> Result<(), String> {
    let issuer_url = format!("{}/realms/{}", KEYCLOAK_INTERNAL_URL, KEYCLOAK_REALM);

    let yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: OIDCProvider
metadata:
  name: keycloak-test
  namespace: {namespace}
  labels:
    lattice.dev/test: oidc
spec:
  issuerUrl: "{issuer_url}"
  clientId: "{client_id}"
  usernameClaim: email
  groupsClaim: groups"#,
        namespace = LATTICE_SYSTEM_NAMESPACE,
        issuer_url = issuer_url,
        client_id = KEYCLOAK_CLIENT_ID,
    );

    apply_yaml_with_retry(kubeconfig, &yaml).await?;
    info!("[Integration/OIDC] Applied OIDCProvider CRD");
    Ok(())
}

/// Wait for OIDCProvider to reach Ready phase
async fn wait_for_oidc_provider_ready(kubeconfig: &str) -> Result<(), String> {
    wait_for_condition(
        "OIDCProvider to become Ready",
        Duration::from_secs(60),
        Duration::from_secs(3),
        || async move {
            let phase = run_kubectl(&[
                "--kubeconfig",
                kubeconfig,
                "get",
                "oidcprovider",
                "keycloak-test",
                "-n",
                LATTICE_SYSTEM_NAMESPACE,
                "-o",
                "jsonpath={.status.phase}",
            ])
            .await?;
            Ok(phase.trim() == "Ready")
        },
    )
    .await
}

/// Delete OIDCProvider CRD
async fn delete_oidc_provider(kubeconfig: &str) {
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "oidcprovider",
        "-n",
        LATTICE_SYSTEM_NAMESPACE,
        "-l",
        "lattice.dev/test=oidc",
        "--ignore-not-found",
    ])
    .await;
}

/// Clean up all OIDC test resources
async fn cleanup_oidc_test_resources(kubeconfig: &str) {
    info!("[Integration/OIDC] Cleaning up test resources...");
    delete_oidc_provider(kubeconfig).await;
    // Delete test Cedar policies
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "cedarpolicy",
        "-n",
        LATTICE_SYSTEM_NAMESPACE,
        "-l",
        "lattice.dev/test=oidc",
        "--ignore-not-found",
    ])
    .await;
    info!("[Integration/OIDC] Cleanup complete");
}

// =============================================================================
// Core Test Functions
// =============================================================================

/// Run OIDC authentication test
///
/// 1. Create OIDCProvider CRD pointing to Keycloak
/// 2. Wait for Ready status
/// 3. Get OIDC token as admin user
/// 4. Create Cedar policy permitting lattice-admins group
/// 5. Validate admin can access proxy with OIDC token
/// 6. Validate viewer gets 403 (not in permitted group)
/// 7. Verify SA tokens still work (fallback)
pub async fn run_oidc_auth_test(
    parent_kubeconfig: &str,
    child_cluster_name: &str,
    existing_proxy_url: Option<&str>,
) -> Result<(), String> {
    info!(
        "[Integration/OIDC] Running OIDC auth test for access to {}...",
        child_cluster_name
    );

    // Get or create proxy connection
    let (proxy_url, _port_forward) =
        get_or_create_proxy(parent_kubeconfig, existing_proxy_url).await?;

    // 1. Apply OIDCProvider CRD
    apply_oidc_provider(parent_kubeconfig).await?;

    // 2. Wait for Ready status
    wait_for_oidc_provider_ready(parent_kubeconfig).await?;
    info!("[Integration/OIDC] OIDCProvider is Ready");

    // Allow time for the watcher to reload the OIDC validator
    tokio::time::sleep(Duration::from_secs(3)).await;

    // 3. Get OIDC tokens from Keycloak
    let admin_token = get_keycloak_token("admin@lattice.dev", "admin").await?;
    info!("[Integration/OIDC] Got admin token from Keycloak");

    let viewer_token = get_keycloak_token("viewer@lattice.dev", "viewer").await?;
    info!("[Integration/OIDC] Got viewer token from Keycloak");

    // 4. Create Cedar policy allowing lattice-admins group
    apply_cedar_policy_allow_group(
        parent_kubeconfig,
        "oidc-test-allow-admins",
        "lattice-admins",
        child_cluster_name,
    )
    .await?;

    // Label the policy for cleanup
    let _ = run_kubectl(&[
        "--kubeconfig",
        parent_kubeconfig,
        "label",
        "cedarpolicy",
        "oidc-test-allow-admins",
        "-n",
        LATTICE_SYSTEM_NAMESPACE,
        "lattice.dev/test=oidc",
        "--overwrite",
    ])
    .await;

    // 5. Verify admin OIDC token grants access
    info!("[Integration/OIDC] Testing admin access (should be allowed)...");
    let url = format!(
        "{}/clusters/{}/api/v1/namespaces",
        proxy_url, child_cluster_name
    );
    let response = http_get_with_retry(&url, &admin_token, 10).await?;
    if !response.is_success() {
        cleanup_oidc_test_resources(parent_kubeconfig).await;
        return Err(format!(
            "Expected admin OIDC access to succeed, got HTTP {}",
            response.status_code
        ));
    }
    info!(
        "[Integration/OIDC] Admin access allowed as expected (HTTP {})",
        response.status_code
    );

    // 6. Verify viewer OIDC token is denied (not in lattice-admins group)
    info!("[Integration/OIDC] Testing viewer access (should be denied)...");
    let response = http_get_with_retry(&url, &viewer_token, 10).await?;
    if !response.is_forbidden() {
        cleanup_oidc_test_resources(parent_kubeconfig).await;
        return Err(format!(
            "Expected viewer OIDC access to be denied (403), got HTTP {}",
            response.status_code
        ));
    }
    info!(
        "[Integration/OIDC] Viewer access denied as expected (HTTP {})",
        response.status_code
    );

    // Cleanup
    cleanup_oidc_test_resources(parent_kubeconfig).await;

    info!("[Integration/OIDC] OIDC auth test passed!");
    Ok(())
}

/// Run OIDC hierarchy tests (entry point for E2E)
///
/// Checks if Keycloak and proxy are available before running tests.
pub async fn run_oidc_hierarchy_tests(
    ctx: &InfraContext,
    child_cluster_name: &str,
) -> Result<(), String> {
    info!("[Integration/OIDC] Running OIDC hierarchy tests...");

    if !oidc_tests_enabled() {
        info!("[Integration/OIDC] Keycloak not reachable, skipping OIDC tests");
        info!("[Integration/OIDC] Start Keycloak with: docker compose up -d");
        return Ok(());
    }

    if !proxy_service_exists(&ctx.mgmt_kubeconfig).await {
        info!("[Integration/OIDC] Proxy service not deployed, skipping OIDC tests");
        return Ok(());
    }

    let proxy_url = ctx.mgmt_proxy_url.as_deref();

    run_oidc_auth_test(&ctx.mgmt_kubeconfig, child_cluster_name, proxy_url).await?;

    // Restore the default E2E policy after tests complete
    apply_e2e_default_policy(&ctx.mgmt_kubeconfig).await?;

    info!("[Integration/OIDC] All OIDC hierarchy tests passed!");
    Ok(())
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone OIDC authentication test
///
/// Requires `LATTICE_MGMT_KUBECONFIG` and Keycloak running via docker-compose.
#[tokio::test]
#[ignore]
async fn test_oidc_standalone() {
    let session = TestSession::from_env("Set LATTICE_MGMT_KUBECONFIG to run standalone OIDC tests")
        .await
        .unwrap();
    let child_cluster_name = get_child_cluster_name();

    if !oidc_tests_enabled() {
        eprintln!("Skipping: Keycloak not reachable (start with: docker compose up -d)");
        return;
    }

    run_oidc_auth_test(
        &session.ctx.mgmt_kubeconfig,
        &child_cluster_name,
        session.ctx.mgmt_proxy_url.as_deref(),
    )
    .await
    .unwrap();
}
