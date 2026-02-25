//! Secrets integration tests — local webhook ESO backend
//!
//! Tests LatticeService secret resource integration with ESO ExternalSecrets
//! via the local webhook secret store. The webhook serves K8s Secrets from
//! `lattice-secrets` namespace as flat JSON for ESO ExternalSecrets.
//!
//! ## Test Suites
//!
//! ### Basic test
//! - Secret with explicit keys (CRD + synced Secret verification)
//!
//! ### 5-route tests
//! - Pure env var, mixed-content env var, file mount,
//!   imagePullSecrets, dataFrom (all keys)
//! - Combined all-routes test
//!
//! # Running
//!
//! ```bash
//! # All secrets tests (basic + 5-route) — direct access
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_secrets_standalone -- --ignored --nocapture
//!
//! # 5-route tests only
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_secrets_routes_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use kube::Api;
use lattice_common::crd::LatticeService;
use lattice_common::LOCAL_WEBHOOK_STORE_NAME;
use tracing::info;

use super::super::helpers::{
    apply_cedar_secret_policy_for_service, apply_run_as_root_override_policy,
    client_from_kubeconfig, create_service_with_all_secret_routes, create_service_with_secrets,
    create_with_retry, delete_cedar_policies_by_label, delete_namespace, deploy_and_wait_for_phase,
    ensure_fresh_namespace, run_kubectl, seed_all_local_test_secrets, seed_local_secret,
    service_pod_selector, setup_regcreds_infrastructure, verify_pod_env_var,
    verify_pod_file_content, verify_pod_image_pull_secrets, verify_synced_secret_keys,
    wait_for_service_phase, with_run_as_root, DEFAULT_TIMEOUT,
};

// =============================================================================
// Constants
// =============================================================================

/// Namespace for basic local secret test
const BASIC_TEST_NAMESPACE: &str = "local-secrets-test";

/// Namespace for 5-route local secrets tests
const ROUTES_TEST_NAMESPACE: &str = "local-secrets-routes";

// =============================================================================
// ExternalSecret Verification
// =============================================================================

/// Verify an ExternalSecret's structure matches expectations.
///
/// Checks apiVersion, kind, secretStoreRef, target name, data/dataFrom mappings,
/// and refreshInterval.
async fn verify_external_secret(
    kubeconfig_path: &str,
    namespace: &str,
    name: &str,
    expected_store: &str,
    expected_remote_key: &str,
    expected_keys: Option<&[&str]>,
) -> Result<(), String> {
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig_path,
        "get",
        "externalsecret",
        name,
        "-n",
        namespace,
        "-o",
        "json",
    ])
    .await?;

    let json: serde_json::Value =
        serde_json::from_str(&output).map_err(|e| format!("Failed to parse JSON: {}", e))?;

    let api_version = json["apiVersion"].as_str().ok_or("Missing apiVersion")?;
    assert_eq!(
        api_version, "external-secrets.io/v1",
        "ExternalSecret should have correct apiVersion"
    );

    let kind = json["kind"].as_str().ok_or("Missing kind")?;
    assert_eq!(kind, "ExternalSecret", "Should be ExternalSecret");

    let store_ref = &json["spec"]["secretStoreRef"];
    let store_name = store_ref["name"]
        .as_str()
        .ok_or("Missing secretStoreRef.name")?;
    assert_eq!(
        store_name, expected_store,
        "secretStoreRef.name should match provider"
    );

    let store_kind = store_ref["kind"]
        .as_str()
        .ok_or("Missing secretStoreRef.kind")?;
    assert_eq!(
        store_kind, "ClusterSecretStore",
        "secretStoreRef.kind should be ClusterSecretStore"
    );

    let target_name = json["spec"]["target"]["name"]
        .as_str()
        .ok_or("Missing target.name")?;
    assert_eq!(
        target_name, name,
        "target.name should match ExternalSecret name"
    );

    if let Some(keys) = expected_keys {
        let data = json["spec"]["data"]
            .as_array()
            .ok_or("Expected data array for explicit keys")?;

        assert_eq!(
            data.len(),
            keys.len(),
            "Should have {} data mappings",
            keys.len()
        );

        for (i, key) in keys.iter().enumerate() {
            let entry = &data[i];
            let secret_key = entry["secretKey"]
                .as_str()
                .ok_or("Missing data[].secretKey")?;
            assert_eq!(secret_key, *key, "secretKey should match");

            let remote_key = entry["remoteRef"]["key"]
                .as_str()
                .ok_or("Missing remoteRef.key")?;
            assert_eq!(
                remote_key, expected_remote_key,
                "remoteRef.key should match"
            );

            let property = entry["remoteRef"]["property"]
                .as_str()
                .ok_or("Missing remoteRef.property")?;
            assert_eq!(property, *key, "remoteRef.property should match key");
        }
    } else {
        let data_from = json["spec"]["dataFrom"]
            .as_array()
            .ok_or("Expected dataFrom array when no explicit keys")?;

        assert!(!data_from.is_empty(), "dataFrom should not be empty");

        let extract_key = data_from[0]["extract"]["key"]
            .as_str()
            .ok_or("Missing dataFrom[].extract.key")?;
        assert_eq!(extract_key, expected_remote_key, "extract.key should match");
    }

    let refresh_interval = json["spec"]["refreshInterval"].as_str();
    assert_eq!(
        refresh_interval,
        Some("1h"),
        "refreshInterval should be set"
    );

    info!(
        "[Secrets] ExternalSecret {} verified: store={}, path={}, keys={:?}",
        name, store_name, expected_remote_key, expected_keys
    );

    Ok(())
}

// =============================================================================
// Secrets Integration Tests
// =============================================================================

/// Run all secrets integration tests (local webhook ESO backend).
///
/// Runs the basic CRD-level test first, then the comprehensive 5-route tests.
///
/// Cedar proxy access policy must be applied by the caller when running through a proxy.
/// E2E tests apply it during setup; standalone tests apply it in their dual-mode fallback.
pub async fn run_secrets_tests(kubeconfig: &str) -> Result<(), String> {
    info!("[Secrets] Running secrets integration tests...");

    // Set up local provider + regcreds (needed for ghcr-creds on every service)
    setup_regcreds_infrastructure(kubeconfig).await?;

    // Seed the basic test secret (uses a distinct source secret name to avoid
    // collisions with route tests that seed "local-db-creds" with different values)
    let mut test_data = std::collections::BTreeMap::new();
    test_data.insert("username".to_string(), "admin".to_string());
    test_data.insert("password".to_string(), "local-secret-123".to_string());
    seed_local_secret(kubeconfig, "local-basic-db-creds", &test_data).await?;

    // Fine-grained: permit basic test namespace to access local-basic-db-creds only
    apply_cedar_secret_policy_for_service(
        kubeconfig,
        "permit-basic-secrets",
        "local-secrets",
        BASIC_TEST_NAMESPACE,
        &["local-basic-db-creds"],
    )
    .await?;

    // busybox runs as root
    apply_run_as_root_override_policy(kubeconfig, BASIC_TEST_NAMESPACE, "local-api").await?;

    run_basic_secret_test(kubeconfig).await?;
    delete_namespace(kubeconfig, BASIC_TEST_NAMESPACE).await;
    delete_cedar_policies_by_label(kubeconfig, "lattice.dev/test=local-secrets").await;

    // Run the comprehensive 5-route tests (manages its own Cedar policies)
    run_secrets_route_tests(kubeconfig, ROUTES_TEST_NAMESPACE).await?;

    info!("[Secrets] All secrets tests passed!");
    Ok(())
}

/// Test local secrets with explicit keys (CRD-level verification)
async fn run_basic_secret_test(kubeconfig: &str) -> Result<(), String> {
    ensure_fresh_namespace(kubeconfig, BASIC_TEST_NAMESPACE).await?;

    let service = with_run_as_root(create_service_with_secrets(
        "local-api",
        BASIC_TEST_NAMESPACE,
        vec![(
            "db-creds",
            "local-basic-db-creds",
            LOCAL_WEBHOOK_STORE_NAME,
            Some(vec!["username", "password"]),
        )],
    ));

    info!("[Secrets/Basic] Deploying LatticeService local-api...");
    deploy_and_wait_for_phase(
        kubeconfig,
        BASIC_TEST_NAMESPACE,
        service,
        "Ready",
        None,
        DEFAULT_TIMEOUT,
    )
    .await?;

    verify_external_secret(
        kubeconfig,
        BASIC_TEST_NAMESPACE,
        "local-api-db-creds",
        LOCAL_WEBHOOK_STORE_NAME,
        "local-basic-db-creds",
        Some(&["username", "password"]),
    )
    .await?;

    verify_synced_secret_keys(
        kubeconfig,
        BASIC_TEST_NAMESPACE,
        "local-api-db-creds",
        &["username", "password"],
    )
    .await?;

    info!("[Secrets/Basic] Basic local secret test passed!");
    Ok(())
}

// =============================================================================
// Route Verification (pods already running)
// =============================================================================

/// Route 1: Pure secret env var -> secretKeyRef
async fn verify_route1(kubeconfig: &str, namespace: &str) -> Result<(), String> {
    let selector = service_pod_selector("route1-pure-env");
    verify_pod_env_var(
        kubeconfig,
        namespace,
        &selector,
        "DB_PASSWORD",
        "s3cret-p@ss",
    )
    .await?;
    verify_pod_env_var(kubeconfig, namespace, &selector, "DB_USERNAME", "admin").await?;
    info!("[Route1] Pure secret env var test passed!");
    Ok(())
}

/// Route 2: Mixed-content env var -> ESO templated env var
async fn verify_route2(kubeconfig: &str, namespace: &str) -> Result<(), String> {
    verify_pod_env_var(
        kubeconfig,
        namespace,
        &service_pod_selector("route2-mixed-env"),
        "DATABASE_URL",
        "postgres://admin:s3cret-p@ss@db.svc:5432/mydb",
    )
    .await?;
    info!("[Route2] Mixed-content env var test passed!");
    Ok(())
}

/// Route 3: File mount with secrets
async fn verify_route3(kubeconfig: &str, namespace: &str) -> Result<(), String> {
    let selector = service_pod_selector("route3-file-mount");
    verify_pod_file_content(
        kubeconfig,
        namespace,
        &selector,
        "/etc/app/config.yaml",
        "password: s3cret-p@ss",
    )
    .await?;
    verify_pod_file_content(
        kubeconfig,
        namespace,
        &selector,
        "/etc/app/config.yaml",
        "api_key: ak-test-12345",
    )
    .await?;
    info!("[Route3] File mount secret test passed!");
    Ok(())
}

/// Route 4: imagePullSecrets
async fn verify_route4(kubeconfig: &str, namespace: &str) -> Result<(), String> {
    verify_pod_image_pull_secrets(
        kubeconfig,
        namespace,
        &service_pod_selector("route4-pull-secrets"),
        "route4-pull-secrets-ghcr-creds",
    )
    .await?;
    info!("[Route4] imagePullSecrets test passed!");
    Ok(())
}

/// Route 5: dataFrom (all keys)
async fn verify_route5(kubeconfig: &str, namespace: &str) -> Result<(), String> {
    verify_external_secret(
        kubeconfig,
        namespace,
        "route5-data-from-all-db-config",
        LOCAL_WEBHOOK_STORE_NAME,
        "local-database-config",
        None,
    )
    .await?;
    verify_synced_secret_keys(
        kubeconfig,
        namespace,
        "route5-data-from-all-db-config",
        &["host", "port", "name", "ssl"],
    )
    .await?;
    info!("[Route5] dataFrom (all keys) test passed!");
    Ok(())
}

/// Combined: all 5 routes in a single service
async fn verify_combined(kubeconfig: &str, namespace: &str) -> Result<(), String> {
    let label = service_pod_selector("secret-routes-combined");
    verify_pod_env_var(kubeconfig, namespace, &label, "DB_PASSWORD", "s3cret-p@ss").await?;
    verify_pod_env_var(kubeconfig, namespace, &label, "DB_USERNAME", "admin").await?;
    verify_pod_env_var(
        kubeconfig,
        namespace,
        &label,
        "DATABASE_URL",
        "postgres://admin:s3cret-p@ss@db.svc:5432/mydb",
    )
    .await?;
    verify_pod_env_var(
        kubeconfig,
        namespace,
        &label,
        "APP_NAME",
        "secret-routes-test",
    )
    .await?;
    verify_pod_file_content(
        kubeconfig,
        namespace,
        &label,
        "/etc/app/config.yaml",
        "password: s3cret-p@ss",
    )
    .await?;
    verify_pod_image_pull_secrets(
        kubeconfig,
        namespace,
        &label,
        "secret-routes-combined-ghcr-creds",
    )
    .await?;
    verify_synced_secret_keys(
        kubeconfig,
        namespace,
        "secret-routes-combined-all-db-config",
        &["host", "port", "name", "ssl"],
    )
    .await?;
    info!("[Combined] All 5 secret routes verified in combined service!");
    Ok(())
}

// =============================================================================
// Route Test Orchestrator
// =============================================================================

/// Run all local secret route tests (5 routes + combined).
///
/// Sets up the local provider and secrets, runs per-route + combined tests.
/// Each route test verifies a different secret delivery mechanism (env var,
/// mixed-content env, file mount, imagePullSecrets, dataFrom).
pub async fn run_secrets_route_tests(kubeconfig: &str, namespace: &str) -> Result<(), String> {
    info!("[Routes] Running secrets route tests (5 routes + combined) in namespace {namespace}...");

    // Set up local provider + regcreds (idempotent if already called)
    setup_regcreds_infrastructure(kubeconfig).await?;

    // Seed all test secrets (db-creds, api-key, database-config, regcreds)
    seed_all_local_test_secrets(kubeconfig).await?;

    // Fine-grained: permit route test namespace to access exactly these secrets.
    // Label is namespace-scoped so concurrent test runs don't delete each other's policies.
    let label = format!("secret-routes-{namespace}");
    apply_cedar_secret_policy_for_service(
        kubeconfig,
        &format!("permit-route-secrets-{namespace}"),
        &label,
        namespace,
        &["local-db-creds", "local-api-key", "local-database-config"],
    )
    .await?;

    // busybox runs as root
    for svc in [
        "route1-pure-env",
        "route2-mixed-env",
        "route3-file-mount",
        "route4-pull-secrets",
        "route5-data-from",
        "secret-routes-combined",
    ] {
        apply_run_as_root_override_policy(kubeconfig, namespace, svc).await?;
    }

    async {
        ensure_fresh_namespace(kubeconfig, namespace).await?;

        // Build all services
        let svc1 = add_secret_env_vars(
            with_run_as_root(create_service_with_secrets(
                "route1-pure-env",
                namespace,
                vec![("db-creds", "local-db-creds", LOCAL_WEBHOOK_STORE_NAME, Some(vec!["username", "password"]))],
            )),
            &[("DB_PASSWORD", "${secret.db-creds.password}"), ("DB_USERNAME", "${secret.db-creds.username}")],
        );
        let svc2 = add_secret_env_vars(
            with_run_as_root(create_service_with_secrets(
                "route2-mixed-env",
                namespace,
                vec![("db-creds", "local-db-creds", LOCAL_WEBHOOK_STORE_NAME, Some(vec!["username", "password"]))],
            )),
            &[("DATABASE_URL", "postgres://${secret.db-creds.username}:${secret.db-creds.password}@db.svc:5432/mydb")],
        );
        let svc3 = with_run_as_root(create_service_with_all_secret_routes("route3-file-mount", namespace, LOCAL_WEBHOOK_STORE_NAME));
        let svc4 = with_run_as_root(create_service_with_all_secret_routes("route4-pull-secrets", namespace, LOCAL_WEBHOOK_STORE_NAME));
        let svc5 = with_run_as_root(create_service_with_secrets(
            "route5-data-from",
            namespace,
            vec![("all-db-config", "local-database-config", LOCAL_WEBHOOK_STORE_NAME, None)],
        ));
        let svc6 = with_run_as_root(create_service_with_all_secret_routes("secret-routes-combined", namespace, LOCAL_WEBHOOK_STORE_NAME));

        // Deploy all services
        let client = client_from_kubeconfig(kubeconfig).await?;
        let api: Api<LatticeService> = Api::namespaced(client, namespace);
        for svc in [&svc1, &svc2, &svc3, &svc4, &svc5, &svc6] {
            let name = svc.metadata.name.as_deref().unwrap();
            create_with_retry(&api, svc, name).await?;
        }

        // Wait for all to reach Ready in parallel
        let timeout = DEFAULT_TIMEOUT;
        let names = ["route1-pure-env", "route2-mixed-env", "route3-file-mount",
                      "route4-pull-secrets", "route5-data-from", "secret-routes-combined"];
        let wait_futures: Vec<_> = names.iter()
            .map(|name| wait_for_service_phase(kubeconfig, namespace, name, "Ready", None, timeout))
            .collect();
        let results = futures::future::join_all(wait_futures).await;
        for result in results {
            result?;
        }

        // Verify each route (fast — pods are already running)
        verify_route1(kubeconfig, namespace).await?;
        verify_route2(kubeconfig, namespace).await?;
        verify_route3(kubeconfig, namespace).await?;
        verify_route4(kubeconfig, namespace).await?;
        verify_route5(kubeconfig, namespace).await?;
        verify_combined(kubeconfig, namespace).await?;

        Ok::<(), String>(())
    }
    .await?;

    delete_namespace(kubeconfig, namespace).await;
    delete_cedar_policies_by_label(kubeconfig, &format!("lattice.dev/test={label}")).await;

    info!("[Routes] All secrets route tests passed!");
    Ok(())
}

// =============================================================================
// Service Builder Helpers (local to this module)
// =============================================================================

/// Add secret-referencing environment variables to a LatticeService's main container.
///
/// Takes an existing service and patches its `main` container's variables.
fn add_secret_env_vars(mut service: LatticeService, vars: &[(&str, &str)]) -> LatticeService {
    use lattice_common::template::TemplateString;

    if let Some(container) = service.spec.workload.containers.get_mut("main") {
        for (name, value) in vars {
            container
                .variables
                .insert(name.to_string(), TemplateString::new(*value));
        }
    }
    service
}

// =============================================================================
// Standalone Tests (run with --ignored)
// =============================================================================

/// Standalone test — run all secrets tests on existing cluster
///
/// Uses `LATTICE_KUBECONFIG` for direct access, or falls back to
/// `LATTICE_MGMT_KUBECONFIG` + `LATTICE_WORKLOAD_KUBECONFIG` with proxy + Cedar policy.
#[tokio::test]
#[ignore]
async fn test_secrets_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_secrets_tests(&resolved.kubeconfig).await.unwrap();
}

/// Standalone test — run only the 5-route secrets tests (uses a separate namespace
/// so it can run concurrently with `test_secrets_standalone`)
#[tokio::test]
#[ignore]
async fn test_secrets_routes_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_secrets_route_tests(&resolved.kubeconfig, "local-secrets-routes-sa")
        .await
        .unwrap();
}
