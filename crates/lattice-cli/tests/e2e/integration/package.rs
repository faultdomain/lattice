//! LatticePackage integration tests
//!
//! Verifies the full lifecycle: install, upgrade, delete.
//!
//! Run standalone:
//! ```
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_package_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::collections::BTreeMap;

use tracing::info;

use super::super::helpers::{
    apply_cedar_secret_policy_for_service, apply_yaml, delete_cedar_policies_by_label,
    ensure_fresh_namespace, run_kubectl, seed_local_secret, setup_regcreds_infrastructure,
    wait_for_condition, wait_for_resource_phase, with_diagnostics, DiagnosticContext,
    DEFAULT_TIMEOUT, POLL_INTERVAL,
};

const PACKAGE_NAMESPACE: &str = "package-test";
const PACKAGE_NAME: &str = "podinfo-test";

// =============================================================================
// Public test entry points
// =============================================================================

/// Run all package integration tests: install, upgrade, delete
pub async fn run_package_tests(kubeconfig: &str) -> Result<(), String> {
    info!("[Package] Running LatticePackage integration tests...");

    let diag = DiagnosticContext::new(kubeconfig, PACKAGE_NAMESPACE);
    with_diagnostics(&diag, "Package", || async {
        // Install
        setup_package_test(kubeconfig).await?;
        test_package_reaches_ready(kubeconfig).await?;
        test_external_secret_created(kubeconfig).await?;
        test_chart_resources_created(kubeconfig).await?;

        // Upgrade
        test_upgrade(kubeconfig).await?;

        // Delete
        test_delete(kubeconfig).await?;

        // Cleanup
        delete_cedar_policies_by_label(kubeconfig, "lattice.dev/test=package-test").await;

        info!("[Package] All package tests passed!");
        Ok(())
    })
    .await
}

// =============================================================================
// Setup
// =============================================================================

async fn setup_package_test(kubeconfig: &str) -> Result<(), String> {
    info!("[Package] Setting up package test infrastructure...");

    ensure_fresh_namespace(kubeconfig, PACKAGE_NAMESPACE).await?;
    setup_regcreds_infrastructure(kubeconfig).await?;

    // Seed the local secret
    let mut data = BTreeMap::new();
    data.insert("token".to_string(), "test-token-abc123".to_string());
    seed_local_secret(kubeconfig, "podinfo-test-creds", &data).await?;

    // Cedar policy: allow the package to access the secret
    apply_cedar_secret_policy_for_service(
        kubeconfig,
        "permit-package-secrets",
        "package-test",
        PACKAGE_NAMESPACE,
        &["podinfo-test-creds"],
    )
    .await?;

    // Apply the LatticePackage
    let package_yaml = include_str!("../fixtures/services/package-redis.yaml");
    apply_yaml(kubeconfig, package_yaml).await?;

    info!("[Package] Package applied, waiting for reconciliation...");
    Ok(())
}

// =============================================================================
// Install tests
// =============================================================================

async fn test_package_reaches_ready(kubeconfig: &str) -> Result<(), String> {
    info!("[Package] Waiting for package to reach Ready...");

    wait_for_resource_phase(
        kubeconfig,
        "latticepackage",
        PACKAGE_NAMESPACE,
        PACKAGE_NAME,
        "Ready",
        DEFAULT_TIMEOUT,
    )
    .await?;

    let chart_version = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticepackage",
        PACKAGE_NAME,
        "-n",
        PACKAGE_NAMESPACE,
        "-o",
        "jsonpath={.status.chartVersion}",
    ])
    .await
    .map_err(|e| format!("failed to get package status: {}", e))?;

    if chart_version.is_empty() {
        return Err("status.chartVersion is empty".to_string());
    }

    info!("[Package] Package Ready: chart={}", chart_version);
    Ok(())
}

async fn test_external_secret_created(kubeconfig: &str) -> Result<(), String> {
    info!("[Package] Verifying ExternalSecret creation...");

    let kc = kubeconfig.to_string();
    let es_json: String = wait_for_condition(
        "ExternalSecret to exist",
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "externalsecret",
                    "-n",
                    PACKAGE_NAMESPACE,
                    "-o",
                    "jsonpath={.items[*].metadata.name}",
                ])
                .await
                .map_err(|e| format!("kubectl failed: {}", e))?;
                if output.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(output))
                }
            }
        },
    )
    .await?;

    info!("[Package] ExternalSecrets found: {}", es_json);

    let es_names: Vec<&str> = es_json.split_whitespace().collect();
    if es_names.is_empty() {
        return Err("no ExternalSecrets found in package namespace".to_string());
    }

    let detail = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "externalsecret",
        es_names[0],
        "-n",
        PACKAGE_NAMESPACE,
        "-o",
        "json",
    ])
    .await
    .map_err(|e| format!("failed to get ExternalSecret detail: {}", e))?;

    let es: serde_json::Value = serde_json::from_str(&detail)
        .map_err(|e| format!("failed to parse ExternalSecret JSON: {}", e))?;

    let store = es["spec"]["secretStoreRef"]["name"].as_str().unwrap_or("");
    if store != "lattice-local" {
        return Err(format!(
            "expected secretStoreRef.name = lattice-local, got: {}",
            store
        ));
    }

    let data = es["spec"]["data"]
        .as_array()
        .ok_or("ExternalSecret spec.data is not an array")?;

    let has_token_key = data
        .iter()
        .any(|d| d["secretKey"].as_str() == Some("token"));

    if !has_token_key {
        return Err(format!(
            "ExternalSecret data should contain 'token' key mapping, got: {:?}",
            data
        ));
    }

    info!("[Package] ExternalSecret verified with correct key mapping");
    Ok(())
}

async fn test_chart_resources_created(kubeconfig: &str) -> Result<(), String> {
    info!("[Package] Verifying chart resources...");

    let kc = kubeconfig.to_string();
    wait_for_condition(
        "podinfo Deployment to exist",
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "deployment",
                    "-n",
                    PACKAGE_NAMESPACE,
                    "-o",
                    "jsonpath={.items[*].metadata.name}",
                ])
                .await
                .map_err(|e| format!("kubectl failed: {}", e))?;
                if output.contains("podinfo") {
                    Ok(Some(output))
                } else {
                    Ok(None)
                }
            }
        },
    )
    .await?;

    info!("[Package] podinfo Deployment found");

    let svc_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "svc",
        "-n",
        PACKAGE_NAMESPACE,
        "-o",
        "jsonpath={.items[*].metadata.name}",
    ])
    .await
    .map_err(|e| format!("failed to list services: {}", e))?;

    if !svc_output.contains("podinfo") {
        return Err(format!("expected a podinfo Service, got: {}", svc_output));
    }

    info!("[Package] podinfo Service found");
    Ok(())
}

// =============================================================================
// Upgrade test
// =============================================================================

async fn test_upgrade(kubeconfig: &str) -> Result<(), String> {
    info!("[Package] Testing upgrade — changing replicaCount...");

    // Patch the LatticePackage to change replicaCount from 1 to 2
    let patch = r#"{"spec":{"values":{"replicaCount":2}}}"#;
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "patch",
        "latticepackage",
        PACKAGE_NAME,
        "-n",
        PACKAGE_NAMESPACE,
        "--type=merge",
        "-p",
        patch,
    ])
    .await
    .map_err(|e| format!("failed to patch package: {}", e))?;

    // Wait for Ready again (generation will have advanced)
    wait_for_resource_phase(
        kubeconfig,
        "latticepackage",
        PACKAGE_NAMESPACE,
        PACKAGE_NAME,
        "Ready",
        DEFAULT_TIMEOUT,
    )
    .await?;

    // Verify the Deployment was updated to 2 replicas
    let kc = kubeconfig.to_string();
    wait_for_condition(
        "podinfo Deployment to have 2 replicas",
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "deployment",
                    PACKAGE_NAME,
                    "-n",
                    PACKAGE_NAMESPACE,
                    "-o",
                    "jsonpath={.spec.replicas}",
                ])
                .await
                .map_err(|e| format!("kubectl failed: {}", e))?;
                if output.trim() == "2" {
                    Ok(Some(()))
                } else {
                    Ok(None)
                }
            }
        },
    )
    .await?;

    info!("[Package] Upgrade verified: replicaCount=2");
    Ok(())
}

// =============================================================================
// Delete test
// =============================================================================

async fn test_delete(kubeconfig: &str) -> Result<(), String> {
    info!("[Package] Testing delete...");

    // Delete the LatticePackage
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "latticepackage",
        PACKAGE_NAME,
        "-n",
        PACKAGE_NAMESPACE,
    ])
    .await
    .map_err(|e| format!("failed to delete package: {}", e))?;

    // Wait for the LatticePackage to be gone
    let kc = kubeconfig.to_string();
    wait_for_condition(
        "LatticePackage to be deleted",
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            async move {
                let result = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "latticepackage",
                    PACKAGE_NAME,
                    "-n",
                    PACKAGE_NAMESPACE,
                    "-o",
                    "name",
                ])
                .await;
                match result {
                    // Still exists
                    Ok(output) if !output.trim().is_empty() => Ok(None),
                    // Gone (NotFound or empty output)
                    _ => Ok(Some(())),
                }
            }
        },
    )
    .await?;

    info!("[Package] LatticePackage deleted");

    // Verify Helm release was uninstalled — Deployment should be gone
    let kc = kubeconfig.to_string();
    wait_for_condition(
        "podinfo Deployment to be deleted",
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "deployment",
                    "-n",
                    PACKAGE_NAMESPACE,
                    "-o",
                    "jsonpath={.items[*].metadata.name}",
                ])
                .await
                .map_err(|e| format!("kubectl failed: {}", e))?;
                if output.contains("podinfo") {
                    Ok(None)
                } else {
                    Ok(Some(()))
                }
            }
        },
    )
    .await?;

    info!("[Package] Helm release uninstalled — Deployment gone");

    // Verify ExternalSecrets were cleaned up
    let kc = kubeconfig.to_string();
    wait_for_condition(
        "ExternalSecrets to be cleaned up",
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "externalsecret",
                    "-n",
                    PACKAGE_NAMESPACE,
                    "-o",
                    "jsonpath={.items[*].metadata.name}",
                ])
                .await
                .unwrap_or_default();
                if output.trim().is_empty() {
                    Ok(Some(()))
                } else {
                    Ok(None)
                }
            }
        },
    )
    .await?;

    info!("[Package] ExternalSecrets cleaned up");
    info!("[Package] Delete lifecycle verified");
    Ok(())
}

// =============================================================================
// Standalone test entry point
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_package_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    setup_regcreds_infrastructure(&resolved.kubeconfig)
        .await
        .unwrap();
    run_package_tests(&resolved.kubeconfig).await.unwrap();
}
