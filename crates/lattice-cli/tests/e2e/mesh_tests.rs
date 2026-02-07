//! Service mesh bilateral agreement tests
//!
//! Orchestrates both the fixed 10-service test and the randomized large-scale test.
//! Service construction lives in `mesh_fixtures`, test utilities in `mesh_helpers`,
//! and random mesh generation in `mesh_random`.

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use kube::api::{Api, PostParams};
use tokio::time::sleep;
use tracing::info;

use lattice_common::crd::LatticeService;

use super::helpers::{client_from_kubeconfig, delete_namespace, ensure_fresh_namespace, run_cmd};
use super::mesh_fixtures::*;
use super::mesh_helpers::*;
pub use super::mesh_random::run_random_mesh_test;

// =============================================================================
// Expected Results (Fixed Mesh)
// =============================================================================

const FRONTEND_WEB_EXPECTED: &[(&str, bool)] = &[
    ("api-gateway", true),
    ("api-users", true),
    ("api-orders", false),
    ("db-users", false),
    ("db-orders", false),
    ("cache", false),
    ("frontend-mobile", false),
    ("frontend-admin", false),
    ("public-api", true),
];

const FRONTEND_MOBILE_EXPECTED: &[(&str, bool)] = &[
    ("api-gateway", true),
    ("api-users", false),
    ("api-orders", true),
    ("db-users", false),
    ("db-orders", false),
    ("cache", false),
    ("frontend-web", false),
    ("frontend-admin", false),
    ("public-api", false),
];

const FRONTEND_ADMIN_EXPECTED: &[(&str, bool)] = &[
    ("api-gateway", true),
    ("api-users", true),
    ("api-orders", true),
    ("db-users", false),
    ("db-orders", false),
    ("cache", false),
    ("frontend-web", false),
    ("frontend-mobile", false),
    ("public-api", true),
];

// =============================================================================
// Deployment
// =============================================================================

async fn deploy_test_services(kubeconfig_path: &str) -> Result<(), String> {
    ensure_fresh_namespace(kubeconfig_path, TEST_SERVICES_NAMESPACE).await?;

    let client = client_from_kubeconfig(kubeconfig_path).await?;
    let api: Api<LatticeService> = Api::namespaced(client, TEST_SERVICES_NAMESPACE);

    info!("[Fixed Mesh] [Layer 3] Deploying backend services...");
    for (name, svc) in [
        ("db-users", create_db_users()),
        ("db-orders", create_db_orders()),
        ("cache", create_cache()),
        ("public-api", create_public_api()),
    ] {
        info!("[Fixed Mesh] Deploying {}...", name);
        api.create(&PostParams::default(), &svc)
            .await
            .map_err(|e| format!("Failed to create {}: {}", name, e))?;
    }

    info!("[Fixed Mesh] [Layer 2] Deploying API services...");
    for (name, svc) in [
        ("api-gateway", create_api_gateway()),
        ("api-users", create_api_users()),
        ("api-orders", create_api_orders()),
    ] {
        info!("[Fixed Mesh] Deploying {}...", name);
        api.create(&PostParams::default(), &svc)
            .await
            .map_err(|e| format!("Failed to create {}: {}", name, e))?;
    }

    info!("[Fixed Mesh] [Layer 1] Deploying frontend services...");
    for (name, svc) in [
        ("frontend-web", create_frontend_web()),
        ("frontend-mobile", create_frontend_mobile()),
        ("frontend-admin", create_frontend_admin()),
    ] {
        info!("[Fixed Mesh] Deploying {}...", name);
        api.create(&PostParams::default(), &svc)
            .await
            .map_err(|e| format!("Failed to create {}: {}", name, e))?;
    }

    info!("[Fixed Mesh] All {} services deployed!", TOTAL_SERVICES);
    sleep(Duration::from_secs(5)).await;
    Ok(())
}

// =============================================================================
// Verification
// =============================================================================

async fn verify_traffic_patterns(kubeconfig_path: &str) -> Result<(), String> {
    let mut total_pass = 0;
    let mut total_fail = 0;
    let mut failures: Vec<String> = Vec::new();

    for (frontend_name, expected_results) in [
        ("frontend-web", FRONTEND_WEB_EXPECTED),
        ("frontend-mobile", FRONTEND_MOBILE_EXPECTED),
        ("frontend-admin", FRONTEND_ADMIN_EXPECTED),
    ] {
        info!("[Fixed Mesh] Checking {} logs...", frontend_name);

        let logs = run_cmd(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "logs",
                "-n",
                TEST_SERVICES_NAMESPACE,
                "-l",
                &format!("{}={}", lattice_common::LABEL_NAME, frontend_name),
                "--tail",
                "100",
            ],
        )?;

        for (target, expected_allowed) in expected_results.iter() {
            let expected_str = if *expected_allowed {
                "ALLOWED"
            } else {
                "BLOCKED"
            };
            let allowed_pattern = format!("{}: ALLOWED", target);
            let blocked_pattern = format!("{}: BLOCKED", target);

            let actual_str = match parse_traffic_result(&logs, &allowed_pattern, &blocked_pattern) {
                Some(true) => "ALLOWED",
                Some(false) => "BLOCKED",
                None => "UNKNOWN",
            };

            let result_ok = actual_str == expected_str;
            let status = if result_ok { "PASS" } else { "FAIL" };

            info!(
                "[Fixed Mesh]   [{}] {} -> {}: {} (expected: {})",
                status, frontend_name, target, actual_str, expected_str
            );

            if result_ok {
                total_pass += 1;
            } else {
                total_fail += 1;
                failures.push(format!(
                    "{} -> {}: got {}, expected {}",
                    frontend_name, target, actual_str, expected_str
                ));
            }
        }
    }

    let total_tests = total_pass + total_fail;
    info!("[Fixed Mesh] ========================================");
    info!("[Fixed Mesh] SERVICE MESH VERIFICATION SUMMARY");
    info!("[Fixed Mesh] ========================================");
    info!("[Fixed Mesh] Total tests: {}", total_tests);
    info!(
        "[Fixed Mesh] Passed: {} ({:.1}%)",
        total_pass,
        (total_pass as f64 / total_tests as f64) * 100.0
    );
    info!("[Fixed Mesh] Failed: {}", total_fail);

    if !failures.is_empty() {
        info!("[Fixed Mesh] Failures:");
        for failure in &failures {
            info!("[Fixed Mesh] - {}", failure);
        }
        return Err(format!(
            "[Fixed Mesh] Service mesh verification failed: {} of {} tests failed",
            total_fail, total_tests
        ));
    }

    info!(
        "[Fixed Mesh] SUCCESS: All {} bilateral agreement tests passed!",
        total_tests
    );
    Ok(())
}

// =============================================================================
// Public API
// =============================================================================

/// Handle for a running fixed mesh test
pub struct MeshTestHandle {
    kubeconfig_path: String,
}

impl MeshTestHandle {
    /// Stop the mesh test and verify traffic patterns.
    pub async fn stop_and_verify(self) -> Result<(), String> {
        verify_traffic_patterns(&self.kubeconfig_path).await
    }

    /// Check for security violations only (incorrectly allowed traffic).
    ///
    /// Less strict than full verification - only fails if traffic that should
    /// be BLOCKED was ALLOWED. Useful during upgrades where some allowed traffic
    /// may fail due to pod restarts.
    pub async fn check_no_policy_gaps(&self) -> Result<(), String> {
        check_no_incorrectly_allowed(&self.kubeconfig_path, TEST_SERVICES_NAMESPACE).await
    }
}

/// Wait for N complete test cycles on fixed mesh traffic generators.
pub async fn wait_for_mesh_test_cycles(
    kubeconfig_path: &str,
    min_cycles: usize,
) -> Result<(), String> {
    wait_for_cycles(
        kubeconfig_path,
        TEST_SERVICES_NAMESPACE,
        &["frontend-web", "frontend-mobile", "frontend-admin"],
        min_cycles,
        "Fixed Mesh",
    )
    .await
}

/// Start the fixed 10-service mesh test and return a handle.
///
/// The test runs traffic generators continuously until `stop_and_verify()` is called.
pub async fn start_mesh_test(kubeconfig_path: &str) -> Result<MeshTestHandle, String> {
    info!(
        "[Fixed Mesh] Starting service mesh bilateral agreement test ({} services)...",
        TOTAL_SERVICES
    );
    deploy_test_services(kubeconfig_path).await?;
    wait_for_services_ready(kubeconfig_path, TEST_SERVICES_NAMESPACE, TOTAL_SERVICES).await?;
    wait_for_pods_running(
        kubeconfig_path,
        TEST_SERVICES_NAMESPACE,
        TOTAL_SERVICES,
        "Fixed Mesh",
        Duration::from_secs(300),
        Duration::from_secs(10),
    )
    .await?;

    Ok(MeshTestHandle {
        kubeconfig_path: kubeconfig_path.to_string(),
    })
}

/// Run the fixed 10-service mesh test end-to-end.
pub async fn run_mesh_test(kubeconfig_path: &str) -> Result<(), String> {
    let handle = start_mesh_test(kubeconfig_path).await?;
    wait_for_mesh_test_cycles(kubeconfig_path, 2).await?;

    let result = handle.stop_and_verify().await;
    if result.is_ok() {
        delete_namespace(kubeconfig_path, TEST_SERVICES_NAMESPACE);
    } else {
        info!(
            "[Mesh] Leaving namespace {} for debugging (test failed)",
            TEST_SERVICES_NAMESPACE
        );
    }
    result
}
