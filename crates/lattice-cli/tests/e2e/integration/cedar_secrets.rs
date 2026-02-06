//! Cedar secret authorization integration tests
//!
//! Tests that Cedar policies control which LatticeServices can access secrets.
//! These tests do NOT require Vault — they validate the CedarPolicy CRD →
//! PolicyEngine reload → ServiceCompiler deny/allow pipeline.
//!
//! # Architecture
//!
//! The operator evaluates Cedar policies during `ServiceCompiler::compile()`:
//! - Principal: `Lattice::Service::"namespace/name"` (service identity)
//! - Action: `Lattice::Action::"AccessSecret"`
//! - Resource: `Lattice::SecretPath::"provider:vault_path"` (secret identity)
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

use kube::api::{Api, PostParams};
use lattice_operator::crd::LatticeService;
use tracing::info;

use super::super::context::InfraContext;
use super::super::helpers::{
    apply_cedar_policy_crd, client_from_kubeconfig, create_service_with_secrets,
    delete_cedar_policies_by_label, ensure_fresh_namespace, wait_for_service_phase,
    wait_for_service_phase_with_message,
};

// =============================================================================
// Constants
// =============================================================================

/// Test namespace for Cedar secret tests
const CEDAR_SECRET_TEST_NAMESPACE: &str = "cedar-secret-test";

/// Secondary namespace for isolation tests
const CEDAR_SECRET_TEST_NAMESPACE_B: &str = "cedar-secret-test-b";

/// Test SecretsProvider name (does not need to exist — Cedar checks happen before ESO)
const TEST_PROVIDER: &str = "vault-test";

/// Alternative provider name for provider-scoped tests
const TEST_PROVIDER_ALT: &str = "vault-denied";

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

/// Apply a CedarPolicy that permits all secrets (for use by other tests like secrets.rs)
pub async fn apply_cedar_secret_permit_all(kubeconfig: &str) -> Result<(), String> {
    apply_cedar_policy_crd(
        kubeconfig,
        "e2e-permit-all-secrets",
        "cedar-secret",
        50,
        "// E2E test policy — permit all services to access all secrets\npermit(\n  principal,\n  action == Lattice::Action::\"AccessSecret\",\n  resource\n);",
    )
    .await
}

/// Remove the permit-all-secrets policy
pub fn remove_cedar_secret_permit_all(kubeconfig: &str) {
    let _ = super::cedar::delete_cedar_policy(kubeconfig, "e2e-permit-all-secrets");
}

// =============================================================================
// Verification Helpers
// =============================================================================

/// Clean up all Cedar secret test policies
fn cleanup_cedar_secret_policies(kubeconfig: &str) {
    delete_cedar_policies_by_label(kubeconfig, "lattice.dev/test=cedar-secret");
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

/// Deploy a service and assert it reaches the expected phase with optional message check.
async fn deploy_and_assert(
    kubeconfig: &str,
    namespace: &str,
    service: LatticeService,
    expected_phase: &str,
    expected_message: Option<&str>,
    timeout: Duration,
) -> Result<(), String> {
    let name = service
        .metadata
        .name
        .as_deref()
        .ok_or("service missing name")?
        .to_string();

    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, namespace);

    api.create(&PostParams::default(), &service)
        .await
        .map_err(|e| format!("Failed to create service {}: {}", name, e))?;

    match expected_message {
        Some(substring) => {
            wait_for_service_phase_with_message(
                kubeconfig,
                namespace,
                &name,
                expected_phase,
                substring,
                timeout,
            )
            .await
        }
        None => wait_for_service_phase(kubeconfig, namespace, &name, expected_phase, timeout).await,
    }
}

/// Test 1: Default deny — no CedarPolicy, service with secrets → Failed
async fn test_default_deny(kubeconfig: &str) -> Result<(), String> {
    info!("[CedarSecrets] Test 1: Default deny (no policies)...");
    ensure_fresh_namespace(kubeconfig, CEDAR_SECRET_TEST_NAMESPACE).await?;

    deploy_and_assert(
        kubeconfig,
        CEDAR_SECRET_TEST_NAMESPACE,
        cedar_test_service(
            "svc-no-policy",
            CEDAR_SECRET_TEST_NAMESPACE,
            vec![("db-creds", "database/prod/creds", TEST_PROVIDER)],
        ),
        "Failed",
        Some("secret access denied"),
        Duration::from_secs(60),
    )
    .await?;

    info!("[CedarSecrets] Test 1 passed: default deny works");
    Ok(())
}

/// Test 2: Permit specific path — apply permit policy → service reaches Ready
async fn test_permit_specific_path(kubeconfig: &str) -> Result<(), String> {
    info!("[CedarSecrets] Test 2: Permit specific path...");
    ensure_fresh_namespace(kubeconfig, CEDAR_SECRET_TEST_NAMESPACE).await?;

    apply_cedar_secret_permit_policy(
        kubeconfig,
        "permit-test2-path",
        CEDAR_SECRET_TEST_NAMESPACE,
        "database/staging/*",
    )
    .await?;

    deploy_and_assert(
        kubeconfig,
        CEDAR_SECRET_TEST_NAMESPACE,
        cedar_test_service(
            "svc-permitted",
            CEDAR_SECRET_TEST_NAMESPACE,
            vec![("db-creds", "database/staging/creds", TEST_PROVIDER)],
        ),
        "Ready",
        None,
        Duration::from_secs(90),
    )
    .await?;

    info!("[CedarSecrets] Test 2 passed: permit specific path works");
    Ok(())
}

/// Test 3: Forbid overrides permit — permit-all + forbid prod path → service fails
async fn test_forbid_overrides_permit(kubeconfig: &str) -> Result<(), String> {
    info!("[CedarSecrets] Test 3: Forbid overrides permit...");
    ensure_fresh_namespace(kubeconfig, CEDAR_SECRET_TEST_NAMESPACE).await?;

    apply_cedar_secret_permit_policy(
        kubeconfig,
        "permit-test3-all",
        CEDAR_SECRET_TEST_NAMESPACE,
        "*",
    )
    .await?;
    apply_cedar_secret_forbid_policy(kubeconfig, "forbid-test3-prod", "*/prod/*").await?;

    deploy_and_assert(
        kubeconfig,
        CEDAR_SECRET_TEST_NAMESPACE,
        cedar_test_service(
            "svc-prod-denied",
            CEDAR_SECRET_TEST_NAMESPACE,
            vec![("db-creds", "database/prod/creds", TEST_PROVIDER)],
        ),
        "Failed",
        Some("secret access denied"),
        Duration::from_secs(60),
    )
    .await?;

    info!("[CedarSecrets] Test 3 passed: forbid overrides permit");
    Ok(())
}

/// Test 4: Namespace isolation — permit for ns-a, service in ns-b denied
async fn test_namespace_isolation(kubeconfig: &str) -> Result<(), String> {
    info!("[CedarSecrets] Test 4: Namespace isolation...");
    ensure_fresh_namespace(kubeconfig, CEDAR_SECRET_TEST_NAMESPACE).await?;
    ensure_fresh_namespace(kubeconfig, CEDAR_SECRET_TEST_NAMESPACE_B).await?;

    apply_cedar_secret_permit_policy(
        kubeconfig,
        "permit-test4-ns-a",
        CEDAR_SECRET_TEST_NAMESPACE,
        "services/*",
    )
    .await?;

    // Service in namespace B (not permitted) → should fail
    deploy_and_assert(
        kubeconfig,
        CEDAR_SECRET_TEST_NAMESPACE_B,
        cedar_test_service(
            "svc-wrong-ns",
            CEDAR_SECRET_TEST_NAMESPACE_B,
            vec![("api-key", "services/api-key", TEST_PROVIDER)],
        ),
        "Failed",
        None,
        Duration::from_secs(60),
    )
    .await?;

    // Service in namespace A (permitted) → should succeed
    deploy_and_assert(
        kubeconfig,
        CEDAR_SECRET_TEST_NAMESPACE,
        cedar_test_service(
            "svc-right-ns",
            CEDAR_SECRET_TEST_NAMESPACE,
            vec![("api-key", "services/api-key", TEST_PROVIDER)],
        ),
        "Ready",
        None,
        Duration::from_secs(90),
    )
    .await?;

    info!("[CedarSecrets] Test 4 passed: namespace isolation works");
    Ok(())
}

/// Test 5: Policy lifecycle — service fails → apply permit → service recovers to Ready
async fn test_policy_lifecycle(kubeconfig: &str) -> Result<(), String> {
    info!("[CedarSecrets] Test 5: Policy lifecycle (fail → permit → recover)...");
    ensure_fresh_namespace(kubeconfig, CEDAR_SECRET_TEST_NAMESPACE).await?;

    // Deploy without policy → should fail
    deploy_and_assert(
        kubeconfig,
        CEDAR_SECRET_TEST_NAMESPACE,
        cedar_test_service(
            "svc-lifecycle",
            CEDAR_SECRET_TEST_NAMESPACE,
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
        CEDAR_SECRET_TEST_NAMESPACE,
        "services/*",
    )
    .await?;

    wait_for_service_phase(
        kubeconfig,
        CEDAR_SECRET_TEST_NAMESPACE,
        "svc-lifecycle",
        "Ready",
        Duration::from_secs(90),
    )
    .await?;

    info!("[CedarSecrets] Test 5 passed: policy lifecycle recovery works");
    Ok(())
}

/// Test 6: Provider-scoped access — permit for one provider, deny for another
async fn test_provider_scoped_access(kubeconfig: &str) -> Result<(), String> {
    info!("[CedarSecrets] Test 6: Provider-scoped access...");
    ensure_fresh_namespace(kubeconfig, CEDAR_SECRET_TEST_NAMESPACE).await?;

    apply_cedar_secret_provider_policy(
        kubeconfig,
        "permit-test6-provider",
        CEDAR_SECRET_TEST_NAMESPACE,
        TEST_PROVIDER,
    )
    .await?;

    // Wrong provider → denied
    deploy_and_assert(
        kubeconfig,
        CEDAR_SECRET_TEST_NAMESPACE,
        cedar_test_service(
            "svc-wrong-provider",
            CEDAR_SECRET_TEST_NAMESPACE,
            vec![("secret", "admin/key", TEST_PROVIDER_ALT)],
        ),
        "Failed",
        Some("secret access denied"),
        Duration::from_secs(60),
    )
    .await?;

    // Right provider → allowed
    deploy_and_assert(
        kubeconfig,
        CEDAR_SECRET_TEST_NAMESPACE,
        cedar_test_service(
            "svc-right-provider",
            CEDAR_SECRET_TEST_NAMESPACE,
            vec![("secret", "admin/key", TEST_PROVIDER)],
        ),
        "Ready",
        None,
        Duration::from_secs(90),
    )
    .await?;

    info!("[CedarSecrets] Test 6 passed: provider-scoped access works");
    Ok(())
}

// =============================================================================
// Orchestrators
// =============================================================================

/// Run all Cedar secret authorization tests.
///
/// Called from E2E pivot_e2e.rs Phase 6.6 and from standalone test below.
pub async fn run_cedar_secret_tests(ctx: &InfraContext) -> Result<(), String> {
    let kubeconfig = ctx.require_workload()?;

    info!(
        "[CedarSecrets] Running Cedar secret authorization tests on {}",
        kubeconfig
    );

    // Clean up any leftover policies from previous runs
    cleanup_cedar_secret_policies(kubeconfig);
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Run tests sequentially, cleaning up policies between each
    let result = async {
        test_default_deny(kubeconfig).await?;
        cleanup_cedar_secret_policies(kubeconfig);
        tokio::time::sleep(Duration::from_secs(2)).await;

        test_permit_specific_path(kubeconfig).await?;
        cleanup_cedar_secret_policies(kubeconfig);
        tokio::time::sleep(Duration::from_secs(2)).await;

        test_forbid_overrides_permit(kubeconfig).await?;
        cleanup_cedar_secret_policies(kubeconfig);
        tokio::time::sleep(Duration::from_secs(2)).await;

        test_namespace_isolation(kubeconfig).await?;
        cleanup_cedar_secret_policies(kubeconfig);
        tokio::time::sleep(Duration::from_secs(2)).await;

        test_policy_lifecycle(kubeconfig).await?;
        cleanup_cedar_secret_policies(kubeconfig);
        tokio::time::sleep(Duration::from_secs(2)).await;

        test_provider_scoped_access(kubeconfig).await?;

        Ok::<(), String>(())
    }
    .await;

    // Always clean up, even on failure
    cleanup_cedar_secret_policies(kubeconfig);

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
