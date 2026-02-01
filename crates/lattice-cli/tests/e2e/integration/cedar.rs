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

use super::super::context::{init_test_env, InfraContext};
use super::super::helpers::{http_get_with_token, run_cmd, run_cmd_allow_fail};

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
    apply_yaml(kubeconfig, &namespace_yaml)?;

    // Create allowed ServiceAccount
    let allowed_sa_yaml = format!(
        r#"apiVersion: v1
kind: ServiceAccount
metadata:
  name: {}
  namespace: {}"#,
        ALLOWED_SA_NAME, CEDAR_TEST_NAMESPACE
    );
    apply_yaml(kubeconfig, &allowed_sa_yaml)?;

    // Create denied ServiceAccount
    let denied_sa_yaml = format!(
        r#"apiVersion: v1
kind: ServiceAccount
metadata:
  name: {}
  namespace: {}"#,
        DENIED_SA_NAME, CEDAR_TEST_NAMESPACE
    );
    apply_yaml(kubeconfig, &denied_sa_yaml)?;

    info!("[Integration/Cedar] Test resources created successfully");
    Ok(())
}

/// Apply a CedarPolicy that allows a specific ServiceAccount to access a cluster
pub fn apply_cedar_policy_allow_sa(
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

    apply_yaml(kubeconfig, &policy_yaml)?;
    info!(
        "[Integration/Cedar] Applied CedarPolicy allowing {} on {}",
        full_sa_name, cluster_name
    );

    // Wait for policy to be loaded
    sleep_sync(Duration::from_secs(2));
    Ok(())
}

/// Apply a CedarPolicy that allows a group of ServiceAccounts
pub fn apply_cedar_policy_allow_group(
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

    apply_yaml(kubeconfig, &policy_yaml)?;
    info!(
        "[Integration/Cedar] Applied CedarPolicy allowing group {} on {}",
        group_name, cluster_name
    );

    sleep_sync(Duration::from_secs(2));
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
            "lattice-system",
            "--ignore-not-found",
        ],
    )?;
    info!("[Integration/Cedar] Deleted CedarPolicy {}", policy_name);
    Ok(())
}

/// Get a ServiceAccount token using kubectl create token
pub fn get_sa_token(kubeconfig: &str, namespace: &str, sa_name: &str) -> Result<String, String> {
    let token = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "create",
            "token",
            sa_name,
            "-n",
            namespace,
            "--duration=1h",
        ],
    )?;
    Ok(token.trim().to_string())
}

/// Clean up test resources
pub fn cleanup_cedar_test_resources(kubeconfig: &str) {
    info!("[Integration/Cedar] Cleaning up test resources...");

    // Delete test policies
    let _ = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "delete",
            "cedarpolicy",
            "-n",
            "lattice-system",
            "-l",
            "lattice.dev/test=cedar",
            "--ignore-not-found",
        ],
    );

    // Delete namespace (cascades to ServiceAccounts)
    let _ = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "delete",
            "namespace",
            CEDAR_TEST_NAMESPACE,
            "--ignore-not-found",
            "--wait=false",
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
pub fn apply_e2e_default_policy(kubeconfig: &str) -> Result<(), String> {
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

    apply_yaml(kubeconfig, &policy_yaml)?;

    // Wait for policy to be loaded by the operator
    sleep_sync(Duration::from_secs(3));

    info!("[Integration/Cedar] Default E2E policy applied");
    Ok(())
}

/// Remove the default E2E Cedar policy.
pub fn remove_e2e_default_policy(kubeconfig: &str) {
    info!("[Integration/Cedar] Removing default E2E policy...");
    let _ = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "delete",
            "cedarpolicy",
            E2E_DEFAULT_POLICY_NAME,
            "-n",
            "lattice-system",
            "--ignore-not-found",
        ],
    );
}

/// The auth proxy runs as part of the lattice-cell service on port 8082
const PROXY_SERVICE_NAME: &str = "lattice-cell";
const PROXY_PORT: u16 = 8082;

use super::super::providers::InfraProvider;

// =============================================================================
// Proxy URL Resolution
// =============================================================================

/// Check if the lattice-cell proxy service exists
pub fn proxy_service_exists(kubeconfig: &str) -> bool {
    let result = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "get",
            "svc",
            PROXY_SERVICE_NAME,
            "-n",
            "lattice-system",
            "-o",
            "name",
        ],
    );
    !result.trim().is_empty() && !result.contains("not found")
}

/// Get the proxy URL with provider-specific handling.
///
/// - Docker: Uses control plane container IP + NodePort (LB IPs aren't accessible from localhost)
/// - Cloud: Uses LoadBalancer external IP
pub fn get_proxy_url_for_provider(
    kubeconfig: &str,
    provider: InfraProvider,
) -> Result<String, String> {
    if !proxy_service_exists(kubeconfig) {
        return Err(format!(
            "{} service not found - proxy may not be deployed",
            PROXY_SERVICE_NAME
        ));
    }

    match provider {
        InfraProvider::Docker => get_proxy_url_docker(kubeconfig),
        _ => get_proxy_url_cloud(kubeconfig),
    }
}

/// Get proxy URL for Docker/CAPD clusters via NodePort on control plane container.
fn get_proxy_url_docker(kubeconfig: &str) -> Result<String, String> {
    // Get cluster name from kubeconfig context
    let context = run_cmd_allow_fail(
        "kubectl",
        &["--kubeconfig", kubeconfig, "config", "current-context"],
    );
    let cluster_name = context.trim().replace("-admin@", "").replace("kind-", "");
    if cluster_name.is_empty() {
        return Err("Could not determine cluster name from kubeconfig".to_string());
    }

    // Get NodePort for proxy service
    let node_port = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "get",
            "svc",
            PROXY_SERVICE_NAME,
            "-n",
            "lattice-system",
            "-o",
            &format!(
                "jsonpath={{.spec.ports[?(@.port=={})].nodePort}}",
                PROXY_PORT
            ),
        ],
    );
    if node_port.trim().is_empty() {
        return Err(format!(
            "Proxy service {} does not have a NodePort for port {}",
            PROXY_SERVICE_NAME, PROXY_PORT
        ));
    }

    // Get control plane container IP (accessible from localhost via Docker network)
    let cp_container = format!("{}-control-plane", cluster_name);
    let cp_ip = run_cmd_allow_fail(
        "docker",
        &[
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            &cp_container,
        ],
    );
    if cp_ip.trim().is_empty() {
        return Err(format!(
            "Could not get IP for control plane container {}",
            cp_container
        ));
    }

    info!(
        "[Integration/Cedar] Using Docker control plane {}:{} for proxy",
        cp_ip.trim(),
        node_port.trim()
    );
    Ok(format!("https://{}:{}", cp_ip.trim(), node_port.trim()))
}

/// Get proxy URL for cloud providers via LoadBalancer IP.
fn get_proxy_url_cloud(kubeconfig: &str) -> Result<String, String> {
    let lb_ip = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "get",
            "svc",
            PROXY_SERVICE_NAME,
            "-n",
            "lattice-system",
            "-o",
            "jsonpath={.status.loadBalancer.ingress[0].ip}",
        ],
    );

    if lb_ip.trim().is_empty() {
        return Err(format!(
            "LoadBalancer IP not available for {} service",
            PROXY_SERVICE_NAME
        ));
    }

    Ok(format!("https://{}:{}", lb_ip.trim(), PROXY_PORT))
}

// =============================================================================
// Verification Functions
// =============================================================================

/// Verify SA has access to the proxy (expects 200 OK)
fn verify_sa_access_allowed(
    proxy_url: &str,
    token: &str,
    cluster_name: &str,
) -> Result<(), String> {
    let url = format!("{}/clusters/{}/api/v1/namespaces", proxy_url, cluster_name);
    let response = http_get_with_token(&url, token, 10);

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
fn verify_sa_access_denied(proxy_url: &str, token: &str, cluster_name: &str) -> Result<(), String> {
    let url = format!("{}/clusters/{}/api/v1/namespaces", proxy_url, cluster_name);
    let response = http_get_with_token(&url, token, 10);

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
/// * `provider` - Infrastructure provider (affects proxy URL resolution)
pub async fn run_cedar_proxy_test(
    parent_kubeconfig: &str,
    child_cluster_name: &str,
    provider: InfraProvider,
) -> Result<(), String> {
    info!(
        "[Integration/Cedar] Running Cedar proxy test for access to {}...",
        child_cluster_name
    );

    // Get proxy URL from parent cluster (provider-aware)
    let proxy_url = get_proxy_url_for_provider(parent_kubeconfig, provider)?;
    info!("[Integration/Cedar] Using proxy URL: {}", proxy_url);

    // Setup test resources on parent cluster
    setup_cedar_test_resources(parent_kubeconfig).await?;

    // Apply policy allowing the "allowed" SA to access the child cluster
    apply_cedar_policy_allow_sa(
        parent_kubeconfig,
        &format!("cedar-test-allow-{}", child_cluster_name),
        CEDAR_TEST_NAMESPACE,
        ALLOWED_SA_NAME,
        child_cluster_name,
    )?;

    // Get tokens from parent cluster
    let allowed_token = get_sa_token(parent_kubeconfig, CEDAR_TEST_NAMESPACE, ALLOWED_SA_NAME)?;
    let denied_token = get_sa_token(parent_kubeconfig, CEDAR_TEST_NAMESPACE, DENIED_SA_NAME)?;

    // Verify allowed SA has access
    info!("[Integration/Cedar] Testing allowed SA access...");
    verify_sa_access_allowed(&proxy_url, &allowed_token, child_cluster_name)?;

    // Verify denied SA is denied
    info!("[Integration/Cedar] Testing denied SA access...");
    verify_sa_access_denied(&proxy_url, &denied_token, child_cluster_name)?;

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
/// * `provider` - Infrastructure provider (affects proxy URL resolution)
pub async fn run_cedar_group_test(
    parent_kubeconfig: &str,
    child_cluster_name: &str,
    provider: InfraProvider,
) -> Result<(), String> {
    info!(
        "[Integration/Cedar] Running group policy test for {}...",
        child_cluster_name
    );

    let proxy_url = get_proxy_url_for_provider(parent_kubeconfig, provider)?;

    // Setup
    setup_cedar_test_resources(parent_kubeconfig).await?;

    // Apply policy allowing all SAs in the test namespace group
    let group_name = format!("system:serviceaccounts:{}", CEDAR_TEST_NAMESPACE);
    apply_cedar_policy_allow_group(
        parent_kubeconfig,
        &format!("cedar-test-group-{}", child_cluster_name),
        &group_name,
        child_cluster_name,
    )?;

    // Get tokens for both SAs (both should be allowed via group)
    let allowed_token = get_sa_token(parent_kubeconfig, CEDAR_TEST_NAMESPACE, ALLOWED_SA_NAME)?;
    let denied_token = get_sa_token(parent_kubeconfig, CEDAR_TEST_NAMESPACE, DENIED_SA_NAME)?;

    // Both SAs should have access via group membership
    info!("[Integration/Cedar] Testing first SA access via group...");
    verify_sa_access_allowed(&proxy_url, &allowed_token, child_cluster_name)?;

    info!("[Integration/Cedar] Testing second SA access via group...");
    verify_sa_access_allowed(&proxy_url, &denied_token, child_cluster_name)?;

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

    // Run SA-specific policy test
    run_cedar_proxy_test(&ctx.mgmt_kubeconfig, child_cluster_name, ctx.provider).await?;

    // Run group policy test
    run_cedar_group_test(&ctx.mgmt_kubeconfig, child_cluster_name, ctx.provider).await?;

    info!("[Integration/Cedar] All Cedar hierarchy tests passed!");
    Ok(())
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Apply YAML manifest using kubectl
fn apply_yaml(kubeconfig: &str, yaml: &str) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("kubectl")
        .args(["--kubeconfig", kubeconfig, "apply", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn kubectl: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(yaml.as_bytes())
            .map_err(|e| format!("Failed to write to kubectl stdin: {}", e))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for kubectl: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "kubectl apply failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

/// Synchronous sleep for use in non-async contexts
fn sleep_sync(duration: Duration) {
    std::thread::sleep(duration);
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone test - test SA token authentication with Cedar policies
///
/// Requires `LATTICE_MGMT_KUBECONFIG` and `LATTICE_CHILD_CLUSTER_NAME` environment variables.
#[tokio::test]
#[ignore]
async fn test_cedar_sa_auth_standalone() {
    let ctx = init_test_env("Set LATTICE_MGMT_KUBECONFIG to run standalone Cedar tests");
    let child_cluster_name =
        std::env::var("LATTICE_CHILD_CLUSTER_NAME").unwrap_or_else(|_| "e2e-workload".to_string());

    run_cedar_proxy_test(&ctx.mgmt_kubeconfig, &child_cluster_name, ctx.provider)
        .await
        .unwrap();
}

/// Standalone test - test group-based Cedar policies
#[tokio::test]
#[ignore]
async fn test_cedar_group_policy_standalone() {
    let ctx = init_test_env("Set LATTICE_MGMT_KUBECONFIG to run standalone Cedar tests");
    let child_cluster_name =
        std::env::var("LATTICE_CHILD_CLUSTER_NAME").unwrap_or_else(|_| "e2e-workload".to_string());

    run_cedar_group_test(&ctx.mgmt_kubeconfig, &child_cluster_name, ctx.provider)
        .await
        .unwrap();
}

/// Standalone test - run all Cedar tests
#[tokio::test]
#[ignore]
async fn test_cedar_all_standalone() {
    let ctx = init_test_env("Set LATTICE_MGMT_KUBECONFIG to run standalone Cedar tests");
    let child_cluster_name =
        std::env::var("LATTICE_CHILD_CLUSTER_NAME").unwrap_or_else(|_| "e2e-workload".to_string());

    run_cedar_hierarchy_tests(&ctx, &child_cluster_name)
        .await
        .unwrap();
}
