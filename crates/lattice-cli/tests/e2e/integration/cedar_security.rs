//! Cedar security override authorization integration tests
//!
//! Tests that Cedar policies control which LatticeServices can relax PSS
//! restricted profile defaults (capabilities, privileged, hostNetwork, etc.).
//! Validates the CedarPolicy CRD -> PolicyEngine reload -> ServiceCompiler
//! deny/allow pipeline. No runtime enforcement needed — Cedar checks happen
//! during compilation before any K8s resources are created.
//!
//! # Architecture
//!
//! The operator evaluates Cedar policies during `ServiceCompiler::compile()`:
//! - Principal: `Lattice::Service::"namespace/name"` (service identity)
//! - Action: `Lattice::Action::"OverrideSecurity"`
//! - Resource: `Lattice::SecurityOverride::"<feature>"` (override identity)
//!
//! Default-deny: no policies = no security relaxations allowed.
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/kubeconfig \
//! cargo test --features provider-e2e --test e2e test_cedar_security_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use lattice_common::crd::{LatticeService, SecurityContext};
use tracing::info;

use super::super::context::InfraContext;
use super::super::helpers::{
    apply_apparmor_override_policy, apply_cedar_policy_crd, create_service_with_security_overrides,
    delete_cedar_policies_by_label, delete_namespace, deploy_and_wait_for_phase,
    ensure_fresh_namespace, wait_for_service_phase,
};

// =============================================================================
// Constants
// =============================================================================

const NS_DEFAULT_DENY: &str = "cedar-sec-t1";
const NS_PERMIT_CAP: &str = "cedar-sec-t2";
const NS_FORBID_OVERRIDE: &str = "cedar-sec-t3";
const NS_ISOLATION_A: &str = "cedar-sec-t4a";
const NS_ISOLATION_B: &str = "cedar-sec-t4b";
const NS_LIFECYCLE: &str = "cedar-sec-t5";
const NS_NO_OVERRIDES: &str = "cedar-sec-t6";
const NS_RUN_AS_ROOT: &str = "cedar-sec-t7";

const TEST_LABEL: &str = "cedar-security";

// =============================================================================
// Cedar Policy Helpers
// =============================================================================

/// Apply a CedarPolicy CRD that permits OverrideSecurity for a namespace
async fn apply_security_permit_namespace(
    kubeconfig: &str,
    name: &str,
    namespace: &str,
) -> Result<(), String> {
    let cedar = format!(
        r#"permit(
  principal,
  action == Lattice::Action::"OverrideSecurity",
  resource
) when {{
  principal.namespace == "{namespace}"
}};"#,
    );
    apply_cedar_policy_crd(kubeconfig, name, TEST_LABEL, 100, &cedar).await
}

/// Apply a CedarPolicy CRD that permits a specific override for a specific service
async fn apply_security_permit_specific(
    kubeconfig: &str,
    name: &str,
    service_id: &str,
    override_id: &str,
) -> Result<(), String> {
    let cedar = format!(
        r#"permit(
  principal == Lattice::Service::"{service_id}",
  action == Lattice::Action::"OverrideSecurity",
  resource == Lattice::SecurityOverride::"{override_id}"
);"#,
    );
    apply_cedar_policy_crd(kubeconfig, name, TEST_LABEL, 100, &cedar).await
}

/// Apply a CedarPolicy CRD that forbids a specific security override globally
async fn apply_security_forbid(
    kubeconfig: &str,
    name: &str,
    override_id: &str,
) -> Result<(), String> {
    let cedar = format!(
        r#"forbid(
  principal,
  action == Lattice::Action::"OverrideSecurity",
  resource == Lattice::SecurityOverride::"{override_id}"
);"#,
    );
    apply_cedar_policy_crd(kubeconfig, name, TEST_LABEL, 200, &cedar).await
}

// =============================================================================
// Service Factories
// =============================================================================

fn service_with_cap(name: &str, namespace: &str, cap: &str) -> LatticeService {
    create_service_with_security_overrides(
        name,
        namespace,
        SecurityContext {
            capabilities: vec![cap.to_string()],
            ..Default::default()
        },
        None,
    )
}

fn service_with_privileged(name: &str, namespace: &str) -> LatticeService {
    create_service_with_security_overrides(
        name,
        namespace,
        SecurityContext {
            privileged: Some(true),
            ..Default::default()
        },
        None,
    )
}

fn service_with_run_as_root(name: &str, namespace: &str) -> LatticeService {
    create_service_with_security_overrides(
        name,
        namespace,
        SecurityContext {
            run_as_user: Some(0),
            ..Default::default()
        },
        None,
    )
}

fn service_no_overrides(name: &str, namespace: &str) -> LatticeService {
    create_service_with_security_overrides(name, namespace, SecurityContext::default(), None)
}

// =============================================================================
// Cleanup
// =============================================================================

async fn cleanup_cedar_security_policies(kubeconfig: &str) {
    delete_cedar_policies_by_label(kubeconfig, &format!("lattice.dev/test={}", TEST_LABEL)).await;
}

// =============================================================================
// Test Scenarios
// =============================================================================

/// Test 1: Default deny — no CedarPolicy, service with capabilities -> Failed
async fn test_default_deny(kubeconfig: &str) -> Result<(), String> {
    info!("[CedarSecurity] Test 1: Default deny (no policies)...");
    ensure_fresh_namespace(kubeconfig, NS_DEFAULT_DENY).await?;

    deploy_and_wait_for_phase(
        kubeconfig,
        NS_DEFAULT_DENY,
        service_with_cap("svc-no-policy", NS_DEFAULT_DENY, "NET_ADMIN"),
        "Failed",
        Some("security override denied"),
        Duration::from_secs(60),
    )
    .await?;

    delete_namespace(kubeconfig, NS_DEFAULT_DENY).await;
    info!("[CedarSecurity] Test 1 passed: default deny works");
    Ok(())
}

/// Test 2: Permit specific capability — apply permit -> service reaches Ready
async fn test_permit_capability(kubeconfig: &str) -> Result<(), String> {
    info!("[CedarSecurity] Test 2: Permit specific capability...");
    ensure_fresh_namespace(kubeconfig, NS_PERMIT_CAP).await?;

    let service_id = format!("{}/svc-permitted", NS_PERMIT_CAP);
    apply_security_permit_specific(
        kubeconfig,
        "permit-t2-cap",
        &service_id,
        "capability:NET_ADMIN",
    )
    .await?;

    deploy_and_wait_for_phase(
        kubeconfig,
        NS_PERMIT_CAP,
        service_with_cap("svc-permitted", NS_PERMIT_CAP, "NET_ADMIN"),
        "Ready",
        None,
        Duration::from_secs(90),
    )
    .await?;

    delete_namespace(kubeconfig, NS_PERMIT_CAP).await;
    info!("[CedarSecurity] Test 2 passed: permit specific capability works");
    Ok(())
}

/// Test 3: Forbid overrides permit — permit-all for namespace + forbid privileged -> service fails
async fn test_forbid_overrides_permit(kubeconfig: &str) -> Result<(), String> {
    info!("[CedarSecurity] Test 3: Forbid overrides permit...");
    ensure_fresh_namespace(kubeconfig, NS_FORBID_OVERRIDE).await?;

    apply_security_permit_namespace(kubeconfig, "permit-t3-all", NS_FORBID_OVERRIDE).await?;
    apply_security_forbid(kubeconfig, "forbid-t3-priv", "privileged").await?;

    // Privileged -> denied by forbid despite namespace permit
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_FORBID_OVERRIDE,
        service_with_privileged("svc-priv-denied", NS_FORBID_OVERRIDE),
        "Failed",
        Some("security override denied"),
        Duration::from_secs(60),
    )
    .await?;

    delete_namespace(kubeconfig, NS_FORBID_OVERRIDE).await;
    info!("[CedarSecurity] Test 3 passed: forbid overrides permit");
    Ok(())
}

/// Test 4: Namespace isolation — permit for ns-a, service in ns-b denied
async fn test_namespace_isolation(kubeconfig: &str) -> Result<(), String> {
    info!("[CedarSecurity] Test 4: Namespace isolation...");
    ensure_fresh_namespace(kubeconfig, NS_ISOLATION_A).await?;
    ensure_fresh_namespace(kubeconfig, NS_ISOLATION_B).await?;

    apply_security_permit_namespace(kubeconfig, "permit-t4-ns-a", NS_ISOLATION_A).await?;

    // Service in namespace B (not permitted) -> should fail
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_ISOLATION_B,
        service_with_cap("svc-wrong-ns", NS_ISOLATION_B, "NET_ADMIN"),
        "Failed",
        None,
        Duration::from_secs(60),
    )
    .await?;

    // Service in namespace A (permitted) -> should succeed
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_ISOLATION_A,
        service_with_cap("svc-right-ns", NS_ISOLATION_A, "NET_ADMIN"),
        "Ready",
        None,
        Duration::from_secs(90),
    )
    .await?;

    delete_namespace(kubeconfig, NS_ISOLATION_A).await;
    delete_namespace(kubeconfig, NS_ISOLATION_B).await;
    info!("[CedarSecurity] Test 4 passed: namespace isolation works");
    Ok(())
}

/// Test 5: Policy lifecycle — service fails -> apply permit -> service recovers
async fn test_policy_lifecycle(kubeconfig: &str) -> Result<(), String> {
    info!("[CedarSecurity] Test 5: Policy lifecycle (fail -> permit -> recover)...");
    ensure_fresh_namespace(kubeconfig, NS_LIFECYCLE).await?;

    // Deploy without policy -> should fail
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_LIFECYCLE,
        service_with_cap("svc-lifecycle", NS_LIFECYCLE, "SYS_MODULE"),
        "Failed",
        None,
        Duration::from_secs(60),
    )
    .await?;

    info!("[CedarSecurity] Service failed as expected, applying permit policy...");

    let service_id = format!("{}/svc-lifecycle", NS_LIFECYCLE);
    apply_security_permit_specific(
        kubeconfig,
        "permit-t5-lifecycle",
        &service_id,
        "capability:SYS_MODULE",
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
    info!("[CedarSecurity] Test 5 passed: policy lifecycle recovery works");
    Ok(())
}

/// Test 6: No overrides -> no policy needed, service reaches Ready
async fn test_no_overrides_no_policy(kubeconfig: &str) -> Result<(), String> {
    info!("[CedarSecurity] Test 6: No overrides, no policy needed...");
    ensure_fresh_namespace(kubeconfig, NS_NO_OVERRIDES).await?;

    deploy_and_wait_for_phase(
        kubeconfig,
        NS_NO_OVERRIDES,
        service_no_overrides("svc-default", NS_NO_OVERRIDES),
        "Ready",
        None,
        Duration::from_secs(90),
    )
    .await?;

    delete_namespace(kubeconfig, NS_NO_OVERRIDES).await;
    info!("[CedarSecurity] Test 6 passed: no overrides = no policy needed");
    Ok(())
}

/// Test 7: runAsRoot denied without policy, permitted with policy
async fn test_run_as_root(kubeconfig: &str) -> Result<(), String> {
    info!("[CedarSecurity] Test 7: runAsRoot override...");
    ensure_fresh_namespace(kubeconfig, NS_RUN_AS_ROOT).await?;

    // No policy for runAsRoot -> denied
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_RUN_AS_ROOT,
        service_with_run_as_root("svc-root-denied", NS_RUN_AS_ROOT),
        "Failed",
        Some("security override denied"),
        Duration::from_secs(60),
    )
    .await?;

    // Apply permit for runAsRoot -> recover
    apply_security_permit_specific(
        kubeconfig,
        "permit-test7-root",
        &format!("{}/svc-root-permitted", NS_RUN_AS_ROOT),
        "runAsRoot",
    )
    .await?;

    deploy_and_wait_for_phase(
        kubeconfig,
        NS_RUN_AS_ROOT,
        service_with_run_as_root("svc-root-permitted", NS_RUN_AS_ROOT),
        "Ready",
        None,
        Duration::from_secs(90),
    )
    .await?;

    delete_namespace(kubeconfig, NS_RUN_AS_ROOT).await;
    info!("[CedarSecurity] Test 7 passed: runAsRoot override works");
    Ok(())
}

// =============================================================================
// Orchestrators
// =============================================================================

/// Run all Cedar security override authorization tests.
///
/// Called from unified_e2e.rs and per-integration cedar_security_e2e.rs.
/// Each test uses its own namespace so all tests run concurrently.
pub async fn run_cedar_security_tests(ctx: &InfraContext) -> Result<(), String> {
    let kubeconfig = ctx.require_workload()?;

    info!(
        "[CedarSecurity] Running Cedar security override tests concurrently on {}",
        kubeconfig
    );

    // Clean up any leftover policies from previous runs
    cleanup_cedar_security_policies(kubeconfig).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Docker KIND clusters don't have AppArmor — permit the Unconfined override.
    // Uses "e2e" label so the cedar-security cleanup (which deletes by "cedar-security"
    // label) doesn't remove it.
    apply_apparmor_override_policy(kubeconfig).await?;

    // Run all tests concurrently — each uses its own namespace
    let result = tokio::try_join!(
        test_default_deny(kubeconfig),
        test_permit_capability(kubeconfig),
        test_forbid_overrides_permit(kubeconfig),
        test_namespace_isolation(kubeconfig),
        test_policy_lifecycle(kubeconfig),
        test_no_overrides_no_policy(kubeconfig),
        test_run_as_root(kubeconfig),
    );

    // Always clean up policies, even on failure
    cleanup_cedar_security_policies(kubeconfig).await;

    result.map_err(|e| e.to_string())?;

    info!("[CedarSecurity] All Cedar security override tests passed!");
    Ok(())
}

/// Start Cedar security tests asynchronously (for parallel execution in E2E)
pub async fn start_cedar_security_tests_async(
    ctx: &InfraContext,
) -> Result<tokio::task::JoinHandle<Result<(), String>>, String> {
    let ctx = ctx.clone();
    Ok(tokio::spawn(
        async move { run_cedar_security_tests(&ctx).await },
    ))
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone test — run Cedar security override tests on existing cluster
#[tokio::test]
#[ignore]
async fn test_cedar_security_standalone() {
    use super::super::context::TestSession;

    let session = TestSession::from_env(
        "Set LATTICE_WORKLOAD_KUBECONFIG to run standalone Cedar security tests",
    )
    .await
    .expect("Failed to create test session");

    if let Err(e) = run_cedar_security_tests(&session.ctx).await {
        panic!("Cedar security tests failed: {}", e);
    }
}
