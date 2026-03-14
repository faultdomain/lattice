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
//! LATTICE_KUBECONFIG=/path/to/kubeconfig \
//! cargo test --features provider-e2e --test e2e test_oidc_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use lattice_common::LATTICE_SYSTEM_NAMESPACE;

use super::super::context::InfraContext;
use super::super::helpers::{
    apply_cedar_policy_crd, apply_yaml, dev_service_reachable, dev_service_url,
    ensure_operator_env, get_or_create_proxy, http_get_with_retry, proxy_service_exists,
    run_kubectl, wait_for_condition, with_diagnostics, DiagnosticContext, DEFAULT_TIMEOUT,
};
use super::cedar::apply_cedar_policy_allow_group;

// =============================================================================
// Constants
// =============================================================================

fn keycloak_host_url() -> String {
    dev_service_url("LATTICE_KEYCLOAK_HOST_URL", "http://127.0.0.1:8080")
}

fn keycloak_internal_url() -> String {
    dev_service_url(
        "LATTICE_KEYCLOAK_INTERNAL_URL",
        "http://lattice-keycloak:8080",
    )
}

/// Keycloak realm
const KEYCLOAK_REALM: &str = "lattice";

/// Keycloak client ID (matches realm export)
const KEYCLOAK_CLIENT_ID: &str = "lattice";

// =============================================================================
// Setup & Helpers
// =============================================================================

/// Check if OIDC tests should run (Keycloak is reachable)
pub fn oidc_tests_enabled() -> bool {
    dev_service_reachable(&format!("{}/health/ready", keycloak_host_url()))
}

/// Get an access token from Keycloak using resource owner password grant
async fn get_keycloak_token(username: &str, password: &str) -> Result<String, String> {
    let token_url = format!(
        "{}/realms/{}/protocol/openid-connect/token",
        keycloak_host_url(),
        KEYCLOAK_REALM
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
    let issuer_url = format!("{}/realms/{}", keycloak_internal_url(), KEYCLOAK_REALM);

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

    apply_yaml(kubeconfig, &yaml).await?;
    info!("[Integration/OIDC] Applied OIDCProvider CRD");
    Ok(())
}

/// Wait for OIDCProvider to reach Ready phase
async fn wait_for_oidc_provider_ready(kubeconfig: &str) -> Result<(), String> {
    wait_for_condition(
        "OIDCProvider to become Ready",
        DEFAULT_TIMEOUT,
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

/// Clean up all OIDC test resources
async fn cleanup_oidc_test_resources(kubeconfig: &str) {
    info!("[Integration/OIDC] Cleaning up test resources...");
    for kind in ["oidcprovider", "cedarpolicy"] {
        let _ = run_kubectl(&[
            "--kubeconfig",
            kubeconfig,
            "delete",
            kind,
            "-n",
            LATTICE_SYSTEM_NAMESPACE,
            "-l",
            "lattice.dev/test=oidc",
            "--ignore-not-found",
        ])
        .await;
    }
    // Clean up cluster-scoped RBAC resources
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "clusterrolebinding",
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
/// - Register Docker container DNS so the operator can resolve Keycloak
/// - Apply OIDCProvider CRD pointing to Keycloak and wait for Ready
/// - Get OIDC tokens from Keycloak for admin and viewer users
/// - Create K8s RBAC + Cedar policy permitting lattice-admins group
/// - Validate admin can access proxy with OIDC token
/// - Validate viewer gets 403 (not in permitted group)
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

    // Allow HTTP issuer URLs when Keycloak uses HTTP (dev/test)
    if keycloak_internal_url().starts_with("http://") {
        ensure_operator_env(parent_kubeconfig, "LATTICE_OIDC_ALLOW_INSECURE_HTTP").await?;
    }

    // 1. Apply OIDCProvider CRD
    //    The OIDC controller creates an egress LMM which the mesh compiler turns
    //    into a ServiceEntry (MESH_EXTERNAL, resolution: DNS). Istio assigns a
    //    virtual IP so the operator pod can resolve the hostname without a K8s
    //    Service. A headless Service would conflict — ztunnel would see the
    //    endpoint IP as a mesh workload and attempt HBONE to the Docker container.
    apply_oidc_provider(parent_kubeconfig).await?;

    // 2. Wait for Ready status
    wait_for_oidc_provider_ready(parent_kubeconfig).await?;
    info!("[Integration/OIDC] OIDCProvider is Ready");

    // 3. Get OIDC tokens from Keycloak (does not depend on operator OIDC reload)
    let admin_token = get_keycloak_token("admin@lattice.dev", "admin").await?;
    info!("[Integration/OIDC] Got admin token from Keycloak");

    let viewer_token = get_keycloak_token("viewer@lattice.dev", "viewer").await?;
    info!("[Integration/OIDC] Got viewer token from Keycloak");

    // 4. Create K8s RBAC bindings so the impersonated OIDC user can list namespaces
    let rbac_yaml = r#"apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: oidc-test-lattice-admins
  labels:
    lattice.dev/test: oidc
subjects:
  - kind: Group
    name: lattice-admins
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io"#;
    apply_yaml(parent_kubeconfig, rbac_yaml).await?;
    info!("[Integration/OIDC] Created K8s RBAC for lattice-admins group");

    // Create Cedar policy allowing lattice-admins group
    apply_cedar_policy_allow_group(
        parent_kubeconfig,
        "oidc-test-allow-admins",
        "lattice-admins",
        child_cluster_name,
    )
    .await?;

    // Add a forbid policy for the viewer user. Cedar forbid overrides permit
    // regardless of priority, so the viewer is denied even with the e2e-allow-all
    // policy in place. This avoids removing the default policy, which would break
    // other concurrent tests that need proxy access.
    let forbid_cedar = format!(
        r#"forbid(
  principal == Lattice::User::"{viewer}",
  action,
  resource == Lattice::Cluster::"{cluster}"
);"#,
        viewer = "viewer@lattice.dev",
        cluster = child_cluster_name,
    );
    apply_cedar_policy_crd(
        parent_kubeconfig,
        "oidc-test-deny-viewer",
        "oidc",
        100,
        &forbid_cedar,
    )
    .await?;

    // Label both policies for cleanup
    for policy_name in ["oidc-test-allow-admins", "oidc-test-deny-viewer"] {
        let _ = run_kubectl(&[
            "--kubeconfig",
            parent_kubeconfig,
            "label",
            "cedarpolicy",
            policy_name,
            "-n",
            LATTICE_SYSTEM_NAMESPACE,
            "lattice.dev/test=oidc",
            "--overwrite",
        ])
        .await;
    }

    // Wait for the OIDC validator to reload and the admin token to be accepted.
    //    Polls until the proxy returns 200 for the admin OIDC token, which confirms
    //    both the OIDCProvider watcher has reloaded and the Cedar policy is active.
    info!("[Integration/OIDC] Testing admin access (should be allowed)...");
    let url = format!(
        "{}/clusters/{}/api/v1/namespaces",
        proxy_url, child_cluster_name
    );
    let admin_url = url.clone();
    let admin_token_owned = admin_token.clone();
    wait_for_condition(
        "OIDC admin token accepted by proxy",
        Duration::from_secs(30),
        Duration::from_secs(2),
        || {
            let url = admin_url.clone();
            let token = admin_token_owned.clone();
            async move {
                let response = http_get_with_retry(&url, &token, 1).await?;
                Ok(response.is_success())
            }
        },
    )
    .await
    .map_err(|e| format!("Expected admin OIDC access to succeed, but it never did: {e}"))?;
    info!("[Integration/OIDC] Admin access allowed as expected");

    // Verify viewer OIDC token is denied (not in lattice-admins group)
    info!("[Integration/OIDC] Testing viewer access (should be denied)...");
    let response = http_get_with_retry(&url, &viewer_token, 10).await?;
    if !response.is_forbidden() {
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

    let diag = DiagnosticContext::new(&ctx.mgmt_kubeconfig, LATTICE_SYSTEM_NAMESPACE);
    with_diagnostics(&diag, "OIDC Hierarchy", || async {
        // The test uses a Cedar forbid policy for the viewer user instead of
        // removing the default e2e-allow-all policy. This keeps the default
        // policy in place so concurrent tests that need proxy access are not
        // disrupted. Cedar forbid overrides permit regardless of priority.
        let proxy_url = ctx.mgmt_proxy_url.as_deref();
        run_oidc_auth_test(&ctx.mgmt_kubeconfig, child_cluster_name, proxy_url).await?;

        info!("[Integration/OIDC] All OIDC hierarchy tests passed!");
        Ok(())
    })
    .await
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone OIDC authentication test
///
/// Requires `LATTICE_KUBECONFIG` and Keycloak running via docker-compose.
/// Discovers the cluster name from the LatticeCluster CRD and tests the
/// full OIDC flow: Keycloak token -> lattice proxy -> Cedar -> K8s API.
#[tokio::test]
#[ignore]
async fn test_oidc_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();

    if !oidc_tests_enabled() {
        eprintln!("Skipping: Keycloak not reachable (start with: docker compose up -d)");
        return;
    }

    let resolved = StandaloneKubeconfig::resolve().await.unwrap();

    // Discover the cluster's own name from the LatticeCluster CRD
    let cluster_name = run_kubectl(&[
        "--kubeconfig",
        &resolved.kubeconfig,
        "get",
        "latticecluster",
        "-n",
        LATTICE_SYSTEM_NAMESPACE,
        "-o",
        "jsonpath={.items[0].metadata.name}",
    ])
    .await
    .expect("Failed to get LatticeCluster name");
    let cluster_name = cluster_name.trim();
    assert!(
        !cluster_name.is_empty(),
        "No LatticeCluster found in {LATTICE_SYSTEM_NAMESPACE}"
    );

    run_oidc_auth_test(&resolved.kubeconfig, cluster_name, None)
        .await
        .unwrap();
}
