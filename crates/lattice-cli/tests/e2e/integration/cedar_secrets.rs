//! Cedar secret authorization integration tests
//!
//! Tests that Cedar policies control which LatticeServices can access secrets.
//! Validates the CedarPolicy CRD → PolicyEngine reload → ServiceCompiler
//! deny/allow pipeline. No secret backend needed — Cedar checks happen before ESO.
//!
//! # Architecture
//!
//! The operator evaluates Cedar policies during `ServiceCompiler::compile()`:
//! - Principal: `Lattice::Service::"namespace/name"` (service identity)
//! - Action: `Lattice::Action::"AccessSecret"`
//! - Resource: `Lattice::SecretPath::"provider:remote_key"` (secret identity)
//!
//! Default-deny: no policies = all secret access denied.
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/kubeconfig \
//! cargo test --features provider-e2e --test e2e test_cedar_secret_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use lattice_common::crd::LatticeService;
use tracing::info;

use super::super::context::InfraContext;
use super::super::helpers::{
    apply_cedar_policy_crd, create_service_with_secrets, delete_cedar_policies_by_label,
    delete_namespace, deploy_and_wait_for_phase, ensure_fresh_namespace,
    setup_regcreds_infrastructure, wait_for_service_phase,
};

// =============================================================================
// Constants
// =============================================================================

/// Per-test namespace prefixes (each test gets its own namespace, cleaned up at end)
const NS_DEFAULT_DENY: &str = "cedar-secret-t1";
const NS_PERMIT_PATH: &str = "cedar-secret-t2";
const NS_FORBID_OVERRIDE: &str = "cedar-secret-t3";
const NS_ISOLATION_A: &str = "cedar-secret-t4a";
const NS_ISOLATION_B: &str = "cedar-secret-t4b";
const NS_LIFECYCLE: &str = "cedar-secret-t5";
const NS_PROVIDER: &str = "cedar-secret-t6";

/// Test SecretProvider name (does not need to exist — Cedar checks happen before ESO)
const TEST_PROVIDER: &str = "test-provider";

/// Alternative provider name for provider-scoped tests
const TEST_PROVIDER_ALT: &str = "test-provider-denied";

// =============================================================================
// Cedar Policy Helpers
// =============================================================================

/// Apply a CedarPolicy CRD that permits AccessSecret for a namespace+path pattern
async fn apply_cedar_secret_permit_policy(
    kubeconfig: &str,
    name: &str,
    namespace: &str,
    path_pattern: &str,
) -> Result<(), String> {
    let cedar = format!(
        r#"permit(
  principal,
  action == Lattice::Action::"AccessSecret",
  resource
) when {{
  principal.namespace == "{namespace}" &&
  resource.path like "{path_pattern}"
}};"#,
    );
    apply_cedar_policy_crd(kubeconfig, name, "cedar-secret", 100, &cedar).await
}

/// Apply a CedarPolicy CRD that forbids AccessSecret for a path pattern
async fn apply_cedar_secret_forbid_policy(
    kubeconfig: &str,
    name: &str,
    path_pattern: &str,
) -> Result<(), String> {
    let cedar = format!(
        r#"forbid(
  principal,
  action == Lattice::Action::"AccessSecret",
  resource
) when {{
  resource.path like "{path_pattern}"
}};"#,
    );
    apply_cedar_policy_crd(kubeconfig, name, "cedar-secret", 200, &cedar).await
}

/// Apply a CedarPolicy CRD that permits AccessSecret scoped to a specific provider
async fn apply_cedar_secret_provider_policy(
    kubeconfig: &str,
    name: &str,
    namespace: &str,
    provider: &str,
) -> Result<(), String> {
    let cedar = format!(
        r#"permit(
  principal,
  action == Lattice::Action::"AccessSecret",
  resource
) when {{
  principal.namespace == "{namespace}" &&
  resource.provider == "{provider}"
}};"#,
    );
    apply_cedar_policy_crd(kubeconfig, name, "cedar-secret", 100, &cedar).await
}

// =============================================================================
// Verification Helpers
// =============================================================================

/// Clean up all Cedar secret test policies
async fn cleanup_cedar_secret_policies(kubeconfig: &str) {
    delete_cedar_policies_by_label(kubeconfig, "lattice.dev/test=cedar-secret").await;
}

// =============================================================================
// Service Factory (wraps shared helper with no-keys default)
// =============================================================================

/// Create a test service with secrets (no explicit keys — simpler for Cedar tests)
fn cedar_test_service(
    name: &str,
    namespace: &str,
    secrets: Vec<(&str, &str, &str)>,
) -> LatticeService {
    create_service_with_secrets(
        name,
        namespace,
        secrets
            .into_iter()
            .map(|(rn, vp, pr)| (rn, vp, pr, None))
            .collect(),
    )
}

// =============================================================================
// Test Scenarios
// =============================================================================

/// Test 1: Default deny — no CedarPolicy, service with secrets → Failed
async fn test_default_deny(kubeconfig: &str) -> Result<(), String> {
    info!("[CedarSecrets] Test 1: Default deny (no policies)...");
    ensure_fresh_namespace(kubeconfig, NS_DEFAULT_DENY).await?;

    deploy_and_wait_for_phase(
        kubeconfig,
        NS_DEFAULT_DENY,
        cedar_test_service(
            "svc-no-policy",
            NS_DEFAULT_DENY,
            vec![("db-creds", "database/prod/creds", TEST_PROVIDER)],
        ),
        "Failed",
        Some("secret access denied"),
        Duration::from_secs(60),
    )
    .await?;

    delete_namespace(kubeconfig, NS_DEFAULT_DENY).await;
    info!("[CedarSecrets] Test 1 passed: default deny works");
    Ok(())
}

/// Test 2: Permit specific path — apply permit policy → service reaches Ready
async fn test_permit_specific_path(kubeconfig: &str) -> Result<(), String> {
    info!("[CedarSecrets] Test 2: Permit specific path...");
    ensure_fresh_namespace(kubeconfig, NS_PERMIT_PATH).await?;

    apply_cedar_secret_permit_policy(
        kubeconfig,
        "permit-test2-path",
        NS_PERMIT_PATH,
        "database/staging/*",
    )
    .await?;

    deploy_and_wait_for_phase(
        kubeconfig,
        NS_PERMIT_PATH,
        cedar_test_service(
            "svc-permitted",
            NS_PERMIT_PATH,
            vec![("db-creds", "database/staging/creds", TEST_PROVIDER)],
        ),
        "Ready",
        None,
        Duration::from_secs(90),
    )
    .await?;

    delete_namespace(kubeconfig, NS_PERMIT_PATH).await;
    info!("[CedarSecrets] Test 2 passed: permit specific path works");
    Ok(())
}

/// Test 3: Forbid overrides permit — permit-all + forbid prod path → service fails
async fn test_forbid_overrides_permit(kubeconfig: &str) -> Result<(), String> {
    info!("[CedarSecrets] Test 3: Forbid overrides permit...");
    ensure_fresh_namespace(kubeconfig, NS_FORBID_OVERRIDE).await?;

    apply_cedar_secret_permit_policy(kubeconfig, "permit-test3-all", NS_FORBID_OVERRIDE, "*")
        .await?;
    apply_cedar_secret_forbid_policy(kubeconfig, "forbid-test3-prod", "*/prod/*").await?;

    deploy_and_wait_for_phase(
        kubeconfig,
        NS_FORBID_OVERRIDE,
        cedar_test_service(
            "svc-prod-denied",
            NS_FORBID_OVERRIDE,
            vec![("db-creds", "database/prod/creds", TEST_PROVIDER)],
        ),
        "Failed",
        Some("secret access denied"),
        Duration::from_secs(60),
    )
    .await?;

    delete_namespace(kubeconfig, NS_FORBID_OVERRIDE).await;
    info!("[CedarSecrets] Test 3 passed: forbid overrides permit");
    Ok(())
}

/// Test 4: Namespace isolation — permit for ns-a, service in ns-b denied
async fn test_namespace_isolation(kubeconfig: &str) -> Result<(), String> {
    info!("[CedarSecrets] Test 4: Namespace isolation...");
    ensure_fresh_namespace(kubeconfig, NS_ISOLATION_A).await?;
    ensure_fresh_namespace(kubeconfig, NS_ISOLATION_B).await?;

    apply_cedar_secret_permit_policy(
        kubeconfig,
        "permit-test4-ns-a",
        NS_ISOLATION_A,
        "services/*",
    )
    .await?;

    // Service in namespace B (not permitted) → should fail
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_ISOLATION_B,
        cedar_test_service(
            "svc-wrong-ns",
            NS_ISOLATION_B,
            vec![("api-key", "services/api-key", TEST_PROVIDER)],
        ),
        "Failed",
        None,
        Duration::from_secs(60),
    )
    .await?;

    // Service in namespace A (permitted) → should succeed
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_ISOLATION_A,
        cedar_test_service(
            "svc-right-ns",
            NS_ISOLATION_A,
            vec![("api-key", "services/api-key", TEST_PROVIDER)],
        ),
        "Ready",
        None,
        Duration::from_secs(90),
    )
    .await?;

    delete_namespace(kubeconfig, NS_ISOLATION_A).await;
    delete_namespace(kubeconfig, NS_ISOLATION_B).await;
    info!("[CedarSecrets] Test 4 passed: namespace isolation works");
    Ok(())
}

/// Test 5: Policy lifecycle — service fails → apply permit → service recovers to Ready
async fn test_policy_lifecycle(kubeconfig: &str) -> Result<(), String> {
    info!("[CedarSecrets] Test 5: Policy lifecycle (fail → permit → recover)...");
    ensure_fresh_namespace(kubeconfig, NS_LIFECYCLE).await?;

    // Deploy without policy → should fail
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_LIFECYCLE,
        cedar_test_service(
            "svc-lifecycle",
            NS_LIFECYCLE,
            vec![("config", "services/config", TEST_PROVIDER)],
        ),
        "Failed",
        None,
        Duration::from_secs(60),
    )
    .await?;

    info!("[CedarSecrets] Service failed as expected, applying permit policy...");

    // Apply permit → controller retries every 30s → service should recover
    apply_cedar_secret_permit_policy(
        kubeconfig,
        "permit-test5-lifecycle",
        NS_LIFECYCLE,
        "services/*",
    )
    .await?;

    wait_for_service_phase(
        kubeconfig,
        NS_LIFECYCLE,
        "svc-lifecycle",
        "Ready",
        Duration::from_secs(90),
    )
    .await?;

    delete_namespace(kubeconfig, NS_LIFECYCLE).await;
    info!("[CedarSecrets] Test 5 passed: policy lifecycle recovery works");
    Ok(())
}

/// Test 6: Provider-scoped access — permit for one provider, deny for another
async fn test_provider_scoped_access(kubeconfig: &str) -> Result<(), String> {
    info!("[CedarSecrets] Test 6: Provider-scoped access...");
    ensure_fresh_namespace(kubeconfig, NS_PROVIDER).await?;

    apply_cedar_secret_provider_policy(
        kubeconfig,
        "permit-test6-provider",
        NS_PROVIDER,
        TEST_PROVIDER,
    )
    .await?;

    // Wrong provider → denied
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_PROVIDER,
        cedar_test_service(
            "svc-wrong-provider",
            NS_PROVIDER,
            vec![("secret", "admin/key", TEST_PROVIDER_ALT)],
        ),
        "Failed",
        Some("secret access denied"),
        Duration::from_secs(60),
    )
    .await?;

    // Right provider → allowed
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_PROVIDER,
        cedar_test_service(
            "svc-right-provider",
            NS_PROVIDER,
            vec![("secret", "admin/key", TEST_PROVIDER)],
        ),
        "Ready",
        None,
        Duration::from_secs(90),
    )
    .await?;

    delete_namespace(kubeconfig, NS_PROVIDER).await;
    info!("[CedarSecrets] Test 6 passed: provider-scoped access works");
    Ok(())
}

// =============================================================================
// Orchestrators
// =============================================================================

/// Run all Cedar secret authorization tests.
///
/// Called from unified_e2e.rs and per-integration cedar_secrets_e2e.rs.
/// Each test uses its own namespace so all tests run concurrently.
pub async fn run_cedar_secret_tests(ctx: &InfraContext) -> Result<(), String> {
    let kubeconfig = ctx.require_workload()?;

    info!(
        "[CedarSecrets] Running Cedar secret authorization tests concurrently on {}",
        kubeconfig
    );

    // Set up regcreds infrastructure — all services now include ghcr-creds
    setup_regcreds_infrastructure(kubeconfig).await?;

    // Clean up any leftover policies from previous runs
    cleanup_cedar_secret_policies(kubeconfig).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Run all tests concurrently — each uses its own namespace
    let result = tokio::try_join!(
        test_default_deny(kubeconfig),
        test_permit_specific_path(kubeconfig),
        test_forbid_overrides_permit(kubeconfig),
        test_namespace_isolation(kubeconfig),
        test_policy_lifecycle(kubeconfig),
        test_provider_scoped_access(kubeconfig),
    );

    // Only clean up policies on success — on failure, leave them in place so the
    // operator can self-heal after crashes/restarts. The pre-test cleanup (above)
    // handles leftovers from previous failed runs.
    let result = result.map_err(|e| e.to_string());
    if result.is_ok() {
        cleanup_cedar_secret_policies(kubeconfig).await;
    }

    result?;

    info!("[CedarSecrets] All Cedar secret authorization tests passed!");
    Ok(())
}

/// Start Cedar secret tests asynchronously (for parallel execution in E2E)
pub async fn start_cedar_secret_tests_async(
    ctx: &InfraContext,
) -> Result<tokio::task::JoinHandle<Result<(), String>>, String> {
    let ctx = ctx.clone();
    Ok(tokio::spawn(
        async move { run_cedar_secret_tests(&ctx).await },
    ))
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone test — run Cedar secret authorization tests on existing cluster
#[tokio::test]
#[ignore]
async fn test_cedar_secret_standalone() {
    use super::super::context::TestSession;

    let session = TestSession::from_env(
        "Set LATTICE_WORKLOAD_KUBECONFIG to run standalone Cedar secret tests",
    )
    .await
    .expect("Failed to create test session");

    if let Err(e) = run_cedar_secret_tests(&session.ctx).await {
        panic!("Cedar secret tests failed: {}", e);
    }
}
