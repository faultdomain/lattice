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
//! # All secrets tests (basic + 5-route)
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/kubeconfig \
//! cargo test --features provider-e2e --test e2e test_secrets_standalone -- --ignored --nocapture
//!
//! # 5-route tests only
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/kubeconfig \
//! cargo test --features provider-e2e --test e2e test_secrets_routes_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use lattice_common::crd::LatticeService;
use tracing::info;

use super::super::context::InfraContext;
use super::super::helpers::{
    apply_cedar_secret_policy_for_service, create_service_with_all_secret_routes,
    create_service_with_secrets, delete_cedar_policies_by_label, delete_namespace,
    deploy_and_wait_for_phase, ensure_fresh_namespace, run_cmd, seed_all_local_test_secrets,
    seed_local_secret, service_pod_selector, setup_regcreds_infrastructure, verify_pod_env_var,
    verify_pod_file_content, verify_pod_image_pull_secrets, verify_synced_secret_keys,
};
use super::cedar::apply_e2e_default_policy;

// =============================================================================
// Constants
// =============================================================================

/// Local test SecretProvider name
const LOCAL_TEST_PROVIDER: &str = "local-test";

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
    let output = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "get",
            "externalsecret",
            name,
            "-n",
            namespace,
            "-o",
            "json",
        ],
    )?;

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
pub async fn run_secrets_tests(ctx: &InfraContext) -> Result<(), String> {
    let kubeconfig = ctx.require_workload()?;

    info!("[Secrets] Running secrets integration tests...");

    apply_e2e_default_policy(&ctx.mgmt_kubeconfig).await?;

    // Set up local provider + regcreds (needed for ghcr-creds on every service)
    setup_regcreds_infrastructure(kubeconfig).await?;

    // Seed the basic test secret
    let mut test_data = std::collections::BTreeMap::new();
    test_data.insert("username".to_string(), "admin".to_string());
    test_data.insert("password".to_string(), "local-secret-123".to_string());
    seed_local_secret(kubeconfig, "local-db-creds", &test_data).await?;

    // Fine-grained: permit basic test namespace to access local-db-creds only
    apply_cedar_secret_policy_for_service(
        kubeconfig,
        "permit-basic-secrets",
        "local-secrets",
        BASIC_TEST_NAMESPACE,
        &["local-db-creds"],
    )
    .await?;

    let result = run_basic_secret_test(kubeconfig).await;

    // Clean up services before policies — the controller re-checks Cedar on every
    // reconcile, so deleting policies while services still exist causes them to fail.
    delete_namespace(kubeconfig, BASIC_TEST_NAMESPACE);
    delete_cedar_policies_by_label(kubeconfig, "lattice.dev/test=local-secrets");
    result?;

    // Run the comprehensive 5-route tests (manages its own Cedar policies)
    run_secrets_route_tests(ctx).await?;

    info!("[Secrets] All secrets tests passed!");
    Ok(())
}

/// Test local secrets with explicit keys (CRD-level verification)
async fn run_basic_secret_test(kubeconfig: &str) -> Result<(), String> {
    ensure_fresh_namespace(kubeconfig, BASIC_TEST_NAMESPACE).await?;

    let service = create_service_with_secrets(
        "local-api",
        BASIC_TEST_NAMESPACE,
        vec![(
            "db-creds",
            "local-db-creds",
            LOCAL_TEST_PROVIDER,
            Some(vec!["username", "password"]),
        )],
    );

    info!("[Secrets/Basic] Deploying LatticeService local-api...");
    deploy_and_wait_for_phase(
        kubeconfig,
        BASIC_TEST_NAMESPACE,
        service,
        "Ready",
        None,
        Duration::from_secs(300),
    )
    .await?;

    verify_external_secret(
        kubeconfig,
        BASIC_TEST_NAMESPACE,
        "local-api-db-creds",
        LOCAL_TEST_PROVIDER,
        "local-db-creds",
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
// 5-Route Tests
// =============================================================================

/// Route 1: Pure secret env var -> secretKeyRef
///
/// Verifies that `${secret.db-creds.password}` compiles to a K8s `secretKeyRef`
/// and the pod receives the secret value as an environment variable.
async fn run_route1_pure_secret_env_test(kubeconfig: &str) -> Result<(), String> {
    info!("[Route1] Testing pure secret env var (secretKeyRef)...");

    let service = create_service_with_secrets(
        "route1-pure-env",
        ROUTES_TEST_NAMESPACE,
        vec![(
            "db-creds",
            "local-db-creds",
            LOCAL_TEST_PROVIDER,
            Some(vec!["username", "password"]),
        )],
    );

    // Patch to add the env var reference
    let service = add_secret_env_vars(
        service,
        &[
            ("DB_PASSWORD", "${secret.db-creds.password}"),
            ("DB_USERNAME", "${secret.db-creds.username}"),
        ],
    );

    deploy_and_wait_for_phase(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        service,
        "Ready",
        None,
        Duration::from_secs(300),
    )
    .await?;

    let selector = service_pod_selector("route1-pure-env");
    verify_pod_env_var(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        &selector,
        "DB_PASSWORD",
        "s3cret-p@ss",
    )
    .await?;

    verify_pod_env_var(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        &selector,
        "DB_USERNAME",
        "admin",
    )
    .await?;

    info!("[Route1] Pure secret env var test passed!");
    Ok(())
}

/// Route 2: Mixed-content env var -> ESO templated env var
///
/// Verifies that `postgres://${secret.db-creds.username}:${secret.db-creds.password}@...`
/// compiles to an ESO-templated ExternalSecret and the pod gets the resolved composite string.
async fn run_route2_mixed_content_env_test(kubeconfig: &str) -> Result<(), String> {
    info!("[Route2] Testing mixed-content env var (ESO template)...");

    let service = create_service_with_secrets(
        "route2-mixed-env",
        ROUTES_TEST_NAMESPACE,
        vec![(
            "db-creds",
            "local-db-creds",
            LOCAL_TEST_PROVIDER,
            Some(vec!["username", "password"]),
        )],
    );

    let service = add_secret_env_vars(
        service,
        &[(
            "DATABASE_URL",
            "postgres://${secret.db-creds.username}:${secret.db-creds.password}@db.svc:5432/mydb",
        )],
    );

    deploy_and_wait_for_phase(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        service,
        "Ready",
        None,
        Duration::from_secs(300),
    )
    .await?;

    verify_pod_env_var(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        &service_pod_selector("route2-mixed-env"),
        "DATABASE_URL",
        "postgres://admin:s3cret-p@ss@db.svc:5432/mydb",
    )
    .await?;

    info!("[Route2] Mixed-content env var test passed!");
    Ok(())
}

/// Route 3: File mount with secrets -> ESO ExternalSecret with template
///
/// Verifies that a file with `${secret.*}` placeholders compiles to an
/// ESO-backed volume mount, and the pod can read the resolved file content.
async fn run_route3_file_mount_secret_test(kubeconfig: &str) -> Result<(), String> {
    info!("[Route3] Testing file mount with secrets...");

    let service = create_service_with_all_secret_routes(
        "route3-file-mount",
        ROUTES_TEST_NAMESPACE,
        LOCAL_TEST_PROVIDER,
    );

    deploy_and_wait_for_phase(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        service,
        "Ready",
        None,
        Duration::from_secs(300),
    )
    .await?;

    let selector = service_pod_selector("route3-file-mount");
    verify_pod_file_content(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        &selector,
        "/etc/app/config.yaml",
        "password: s3cret-p@ss",
    )
    .await?;

    verify_pod_file_content(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        &selector,
        "/etc/app/config.yaml",
        "api_key: ak-test-12345",
    )
    .await?;

    info!("[Route3] File mount secret test passed!");
    Ok(())
}

/// Route 4: imagePullSecrets -> ESO synced Secret -> pod imagePullSecrets
///
/// Verifies that a secret resource referenced in `imagePullSecrets` gets synced
/// by ESO and appears in the pod's `spec.imagePullSecrets`.
async fn run_route4_image_pull_secrets_test(kubeconfig: &str) -> Result<(), String> {
    info!("[Route4] Testing imagePullSecrets...");

    let service = create_service_with_all_secret_routes(
        "route4-pull-secrets",
        ROUTES_TEST_NAMESPACE,
        LOCAL_TEST_PROVIDER,
    );

    deploy_and_wait_for_phase(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        service,
        "Ready",
        None,
        Duration::from_secs(300),
    )
    .await?;

    verify_pod_image_pull_secrets(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        &service_pod_selector("route4-pull-secrets"),
        "route4-pull-secrets-ghcr-creds",
    )
    .await?;

    info!("[Route4] imagePullSecrets test passed!");
    Ok(())
}

/// Route 5: dataFrom (all keys) -> ExternalSecret with dataFrom.extract
///
/// Verifies that a secret resource with no explicit `keys` compiles to a
/// `dataFrom.extract` ExternalSecret, and the synced K8s Secret has all seeded keys.
async fn run_route5_data_from_test(kubeconfig: &str) -> Result<(), String> {
    info!("[Route5] Testing dataFrom (all keys)...");

    let service = create_service_with_secrets(
        "route5-data-from",
        ROUTES_TEST_NAMESPACE,
        vec![(
            "all-db-config",
            "local-database-config",
            LOCAL_TEST_PROVIDER,
            None, // No explicit keys -> dataFrom
        )],
    );

    deploy_and_wait_for_phase(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        service,
        "Ready",
        None,
        Duration::from_secs(300),
    )
    .await?;

    verify_external_secret(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        "route5-data-from-all-db-config",
        LOCAL_TEST_PROVIDER,
        "local-database-config",
        None,
    )
    .await?;

    verify_synced_secret_keys(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        "route5-data-from-all-db-config",
        &["host", "port", "name", "ssl"],
    )
    .await?;

    info!("[Route5] dataFrom (all keys) test passed!");
    Ok(())
}

/// Combined test: deploy the full fixture and verify all routes in one pod
async fn run_all_routes_combined_test(kubeconfig: &str) -> Result<(), String> {
    info!("[Combined] Testing all 5 secret routes in a single service...");

    let service = create_service_with_all_secret_routes(
        "secret-routes-combined",
        ROUTES_TEST_NAMESPACE,
        LOCAL_TEST_PROVIDER,
    );

    deploy_and_wait_for_phase(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        service,
        "Ready",
        None,
        Duration::from_secs(300),
    )
    .await?;

    let label = service_pod_selector("secret-routes-combined");

    // Route 1: Pure secret env vars
    verify_pod_env_var(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        &label,
        "DB_PASSWORD",
        "s3cret-p@ss",
    )
    .await?;
    verify_pod_env_var(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        &label,
        "DB_USERNAME",
        "admin",
    )
    .await?;

    // Route 2: Mixed-content env var
    verify_pod_env_var(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        &label,
        "DATABASE_URL",
        "postgres://admin:s3cret-p@ss@db.svc:5432/mydb",
    )
    .await?;

    // Non-secret env var (sanity check)
    verify_pod_env_var(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        &label,
        "APP_NAME",
        "secret-routes-test",
    )
    .await?;

    // Route 3: File mount
    verify_pod_file_content(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        &label,
        "/etc/app/config.yaml",
        "password: s3cret-p@ss",
    )
    .await?;

    // Route 4: imagePullSecrets
    verify_pod_image_pull_secrets(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        &label,
        "secret-routes-combined-ghcr-creds",
    )
    .await?;

    // Route 5: dataFrom (verify synced secret has all keys)
    verify_synced_secret_keys(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
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
pub async fn run_secrets_route_tests(ctx: &InfraContext) -> Result<(), String> {
    let kubeconfig = ctx.require_workload()?;

    info!("[Routes] Running secrets route tests (5 routes + combined)...");

    // Set up local provider + regcreds (idempotent if already called)
    setup_regcreds_infrastructure(kubeconfig).await?;

    // Seed all test secrets (db-creds, api-key, database-config, regcreds)
    seed_all_local_test_secrets(kubeconfig).await?;

    // Fine-grained: permit route test namespace to access exactly these secrets
    apply_cedar_secret_policy_for_service(
        kubeconfig,
        "permit-route-secrets",
        "secret-routes",
        ROUTES_TEST_NAMESPACE,
        &["local-db-creds", "local-api-key", "local-database-config"],
    )
    .await?;

    let result = async {
        ensure_fresh_namespace(kubeconfig, ROUTES_TEST_NAMESPACE).await?;

        // Run per-route tests
        run_route1_pure_secret_env_test(kubeconfig).await?;
        run_route2_mixed_content_env_test(kubeconfig).await?;
        run_route3_file_mount_secret_test(kubeconfig).await?;
        run_route4_image_pull_secrets_test(kubeconfig).await?;
        run_route5_data_from_test(kubeconfig).await?;

        // Run combined test
        run_all_routes_combined_test(kubeconfig).await?;

        Ok::<(), String>(())
    }
    .await;

    // Clean up services before policies — the controller re-checks Cedar on every
    // reconcile, so deleting policies while services still exist causes them to fail.
    delete_namespace(kubeconfig, ROUTES_TEST_NAMESPACE);
    delete_cedar_policies_by_label(kubeconfig, "lattice.dev/test=secret-routes");
    result?;

    info!("[Routes] All secrets route tests passed!");
    Ok(())
}

// =============================================================================
// Async Starter (for parallel execution in E2E)
// =============================================================================

/// Start secrets tests asynchronously (for parallel execution in E2E)
pub async fn start_secrets_tests_async(
    ctx: &InfraContext,
) -> Result<tokio::task::JoinHandle<Result<(), String>>, String> {
    let ctx = ctx.clone();
    Ok(tokio::spawn(async move { run_secrets_tests(&ctx).await }))
}

// =============================================================================
// Service Builder Helpers (local to this module)
// =============================================================================

/// Add secret-referencing environment variables to a LatticeService's main container.
///
/// Takes an existing service and patches its `main` container's variables.
fn add_secret_env_vars(mut service: LatticeService, vars: &[(&str, &str)]) -> LatticeService {
    use lattice_common::template::TemplateString;

    if let Some(container) = service.spec.containers.get_mut("main") {
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
#[tokio::test]
#[ignore]
async fn test_secrets_standalone() {
    use super::super::context::TestSession;

    let session = TestSession::from_env("Set LATTICE_WORKLOAD_KUBECONFIG to run secrets tests")
        .await
        .expect("Failed to create test session");

    if let Err(e) = run_secrets_tests(&session.ctx).await {
        panic!("Secrets tests failed: {}", e);
    }
}

/// Standalone test — run only the 5-route secrets tests
#[tokio::test]
#[ignore]
async fn test_secrets_routes_standalone() {
    use super::super::context::TestSession;

    let session =
        TestSession::from_env("Set LATTICE_WORKLOAD_KUBECONFIG to run secrets route tests")
            .await
            .expect("Failed to create test session");

    if let Err(e) = run_secrets_route_tests(&session.ctx).await {
        panic!("Secrets route tests failed: {}", e);
    }
}
