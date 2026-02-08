//! Secrets integration tests - run against existing cluster
//!
//! Tests LatticeService secret resource integration with ESO ExternalSecrets.
//! These tests verify that secret resources in LatticeService correctly generate
//! ExternalSecret objects that reference ClusterSecretStore.
//!
//! ## Test Suites
//!
//! ### Vault-backed tests (require docker-compose Vault)
//! - Basic secret with explicit keys
//! - Secret without keys (dataFrom pattern)
//! - Multiple secrets in one service
//! - Cedar + Secrets pipeline (deny → permit → verify)
//!
//! ### Local-backed tests (no Vault required)
//! - Basic local secret via webhook
//! - **5-route tests**: pure env var, mixed-content env var, file mount,
//!   imagePullSecrets, dataFrom (all keys)
//! - Combined all-routes test
//!
//! # Running
//!
//! ```bash
//! # Vault tests (start Vault first)
//! docker compose up -d
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/kubeconfig \
//! cargo test --features provider-e2e --test e2e test_secrets_standalone -- --ignored --nocapture
//!
//! # Local tests (no Vault)
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/kubeconfig \
//! cargo test --features provider-e2e --test e2e test_local_secrets_standalone -- --ignored --nocapture
//!
//! # 5-route tests only
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/kubeconfig \
//! cargo test --features provider-e2e --test e2e test_local_secrets_routes_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use kube::api::{Api, PostParams};
use lattice_common::crd::LatticeService;
use tracing::info;

use super::super::context::InfraContext;
use super::super::helpers::{
    apply_yaml_with_retry, client_from_kubeconfig, create_local_secrets_provider,
    create_service_with_all_secret_routes, create_service_with_secrets, ensure_fresh_namespace,
    run_cmd, seed_all_local_test_secrets, seed_local_secret, verify_pod_env_var,
    verify_pod_file_content, verify_pod_image_pull_secrets, verify_synced_secret_keys,
    wait_for_secrets_provider_ready, wait_for_service_phase,
};
use super::cedar::apply_e2e_default_policy;
use super::cedar_secrets::{apply_cedar_secret_permit_all, remove_cedar_secret_permit_all};

/// Test namespace for Vault secrets integration tests
const TEST_NAMESPACE: &str = "secrets-test";

/// Test SecretsProvider name for Vault
const TEST_PROVIDER: &str = "vault-test";

/// Local test SecretsProvider name
const LOCAL_TEST_PROVIDER: &str = "local-test";

/// Namespace for 5-route local secrets tests
const ROUTES_TEST_NAMESPACE: &str = "local-secrets-routes";

/// Fixed Vault endpoint (from docker-compose, cluster-internal)
const VAULT_URL: &str = "http://lattice-vault:8200";

/// Fixed Vault token (from docker-compose)
const VAULT_TOKEN: &str = "root";

/// Vault URL for host access (port-forwarded)
const VAULT_HOST_URL: &str = "http://127.0.0.1:8200";

// =============================================================================
// Vault Setup
// =============================================================================

/// Check if Vault-backed secrets tests should run (Vault is reachable)
pub fn secrets_tests_enabled() -> bool {
    std::process::Command::new("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            &format!("{}/v1/sys/health", VAULT_HOST_URL),
        ])
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).starts_with("200"))
        .unwrap_or(false)
}

/// Set up test secrets in Vault via HTTP API
async fn setup_vault_test_secrets() -> Result<(), String> {
    info!("[Secrets/Vault] Setting up test secrets in Vault...");

    let test_secrets = [
        (
            "database/prod/credentials",
            r#"{"data":{"username":"admin","password":"secret123"}}"#,
        ),
        (
            "services/all-secrets",
            r#"{"data":{"api_key":"key123","api_secret":"secret456","endpoint":"https://api.example.com"}}"#,
        ),
        (
            "database/credentials",
            r#"{"data":{"username":"dbuser","password":"dbpass"}}"#,
        ),
        ("services/api-key", r#"{"data":{"key":"my-api-key-12345"}}"#),
        (
            "pki/certificates",
            r#"{"data":{"cert":"-----BEGIN CERTIFICATE-----...","key":"-----BEGIN PRIVATE KEY-----..."}}"#,
        ),
    ];

    let client = reqwest::Client::new();
    for (path, data) in test_secrets {
        info!("[Secrets/Vault] Creating secret at {}", path);

        let response = client
            .post(format!("{}/v1/secret/data/{}", VAULT_HOST_URL, path))
            .header("X-Vault-Token", VAULT_TOKEN)
            .header("Content-Type", "application/json")
            .body(data.to_string())
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!(
                "Failed to create secret at {}: {} - {}",
                path, status, body
            ));
        }
    }

    info!("[Secrets/Vault] Test secrets created successfully");
    Ok(())
}

/// Create the Vault token K8s Secret in lattice-system
async fn create_vault_token_secret(kubeconfig: &str) -> Result<(), String> {
    info!("[Secrets/Setup] Creating Vault token secret...");

    let secret_yaml = format!(
        r#"apiVersion: v1
kind: Secret
metadata:
  name: vault-test-token
  namespace: lattice-system
type: Opaque
stringData:
  token: {token}
"#,
        token = VAULT_TOKEN
    );

    apply_yaml_with_retry(kubeconfig, &secret_yaml).await?;
    info!("[Secrets/Setup] Vault token secret created");
    Ok(())
}

/// Create the Vault-backed SecretsProvider CRD
async fn create_vault_secrets_provider(kubeconfig: &str) -> Result<(), String> {
    info!("[Secrets/Setup] Creating Vault SecretsProvider CRD...");

    let provider_yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: SecretsProvider
metadata:
  name: {provider_name}
  namespace: lattice-system
spec:
  server: {vault_url}
  path: secret
  authMethod: token
  credentialsSecretRef:
    name: vault-test-token
    namespace: lattice-system
"#,
        provider_name = TEST_PROVIDER,
        vault_url = VAULT_URL,
    );

    apply_yaml_with_retry(kubeconfig, &provider_yaml).await?;
    info!("[Secrets/Setup] Vault SecretsProvider created");
    Ok(())
}

/// Set up full Vault infrastructure for secrets testing
pub async fn setup_vault_infrastructure(kubeconfig: &str) -> Result<(), String> {
    info!("[Secrets/Setup] Setting up Vault infrastructure...");

    setup_vault_test_secrets().await?;
    create_vault_token_secret(kubeconfig).await?;
    create_vault_secrets_provider(kubeconfig).await?;
    wait_for_secrets_provider_ready(kubeconfig, TEST_PROVIDER).await?;

    info!("[Secrets/Setup] Vault infrastructure setup complete!");
    Ok(())
}

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
// Vault-Backed Integration Tests
// =============================================================================

/// Run all Vault-backed secrets integration tests
pub async fn run_secrets_tests(ctx: &InfraContext) -> Result<(), String> {
    apply_e2e_default_policy(&ctx.mgmt_kubeconfig).await?;

    let kubeconfig = ctx.require_workload()?;

    info!(
        "[Integration/Secrets] Running secrets tests on cluster at {}",
        kubeconfig
    );

    apply_cedar_secret_permit_all(kubeconfig).await?;
    setup_vault_infrastructure(kubeconfig).await?;

    let result = async {
        info!("[Integration/Secrets] Test 1: Basic secret with explicit keys...");
        run_basic_secret_test(kubeconfig).await?;

        info!("[Integration/Secrets] Test 2: Secret without explicit keys (dataFrom)...");
        run_data_from_secret_test(kubeconfig).await?;

        info!("[Integration/Secrets] Test 3: Multiple secrets in one service...");
        run_multiple_secrets_test(kubeconfig).await?;

        info!("[Integration/Secrets] Test 4: Cedar + Secrets pipeline...");
        run_cedar_secrets_pipeline_test(kubeconfig).await?;

        Ok::<(), String>(())
    }
    .await;

    remove_cedar_secret_permit_all(kubeconfig);
    result?;

    info!("[Integration/Secrets] All secrets tests passed!");
    Ok(())
}

/// Test basic secret resource with explicit keys
async fn run_basic_secret_test(kubeconfig: &str) -> Result<(), String> {
    ensure_fresh_namespace(kubeconfig, TEST_NAMESPACE).await?;

    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, TEST_NAMESPACE);

    let service = create_service_with_secrets(
        "api-with-secrets",
        TEST_NAMESPACE,
        vec![(
            "db-creds",
            "database/prod/credentials",
            TEST_PROVIDER,
            Some(vec!["username", "password"]),
        )],
    );

    info!("[Secrets/Basic] Creating LatticeService api-with-secrets...");
    api.create(&PostParams::default(), &service)
        .await
        .map_err(|e| format!("Failed to create service: {}", e))?;

    wait_for_service_phase(
        kubeconfig,
        TEST_NAMESPACE,
        "api-with-secrets",
        "Ready",
        Duration::from_secs(120),
    )
    .await?;

    verify_external_secret(
        kubeconfig,
        TEST_NAMESPACE,
        "api-with-secrets-db-creds",
        TEST_PROVIDER,
        "database/prod/credentials",
        Some(&["username", "password"]),
    )
    .await?;

    verify_synced_secret_keys(
        kubeconfig,
        TEST_NAMESPACE,
        "api-with-secrets-db-creds",
        &["username", "password"],
    )
    .await?;

    info!("[Secrets/Basic] Test passed!");
    Ok(())
}

/// Test secret without explicit keys (uses dataFrom)
async fn run_data_from_secret_test(kubeconfig: &str) -> Result<(), String> {
    ensure_fresh_namespace(kubeconfig, TEST_NAMESPACE).await?;

    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, TEST_NAMESPACE);

    let service = create_service_with_secrets(
        "api-all-keys",
        TEST_NAMESPACE,
        vec![("all-secrets", "services/all-secrets", TEST_PROVIDER, None)],
    );

    info!("[Secrets/DataFrom] Creating LatticeService api-all-keys...");
    api.create(&PostParams::default(), &service)
        .await
        .map_err(|e| format!("Failed to create service: {}", e))?;

    wait_for_service_phase(
        kubeconfig,
        TEST_NAMESPACE,
        "api-all-keys",
        "Ready",
        Duration::from_secs(120),
    )
    .await?;

    verify_external_secret(
        kubeconfig,
        TEST_NAMESPACE,
        "api-all-keys-all-secrets",
        TEST_PROVIDER,
        "services/all-secrets",
        None,
    )
    .await?;

    info!("[Secrets/DataFrom] Test passed!");
    Ok(())
}

/// Test multiple secrets in one service
async fn run_multiple_secrets_test(kubeconfig: &str) -> Result<(), String> {
    ensure_fresh_namespace(kubeconfig, TEST_NAMESPACE).await?;

    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, TEST_NAMESPACE);

    let service = create_service_with_secrets(
        "api-multi-secrets",
        TEST_NAMESPACE,
        vec![
            (
                "db-creds",
                "database/credentials",
                TEST_PROVIDER,
                Some(vec!["username", "password"]),
            ),
            (
                "api-key",
                "services/api-key",
                TEST_PROVIDER,
                Some(vec!["key"]),
            ),
            ("tls-certs", "pki/certificates", TEST_PROVIDER, None),
        ],
    );

    info!("[Secrets/Multi] Creating LatticeService api-multi-secrets...");
    api.create(&PostParams::default(), &service)
        .await
        .map_err(|e| format!("Failed to create service: {}", e))?;

    wait_for_service_phase(
        kubeconfig,
        TEST_NAMESPACE,
        "api-multi-secrets",
        "Ready",
        Duration::from_secs(120),
    )
    .await?;

    verify_external_secret(
        kubeconfig,
        TEST_NAMESPACE,
        "api-multi-secrets-db-creds",
        TEST_PROVIDER,
        "database/credentials",
        Some(&["username", "password"]),
    )
    .await?;

    verify_external_secret(
        kubeconfig,
        TEST_NAMESPACE,
        "api-multi-secrets-api-key",
        TEST_PROVIDER,
        "services/api-key",
        Some(&["key"]),
    )
    .await?;

    verify_external_secret(
        kubeconfig,
        TEST_NAMESPACE,
        "api-multi-secrets-tls-certs",
        TEST_PROVIDER,
        "pki/certificates",
        None,
    )
    .await?;

    info!("[Secrets/Multi] Test passed!");
    Ok(())
}

/// Test Cedar + Secrets pipeline: deny → permit → verify ESO resources
async fn run_cedar_secrets_pipeline_test(kubeconfig: &str) -> Result<(), String> {
    const PIPELINE_NAMESPACE: &str = "secrets-pipeline-test";

    ensure_fresh_namespace(kubeconfig, PIPELINE_NAMESPACE).await?;

    // Remove the permit-all policy so we start with default-deny
    remove_cedar_secret_permit_all(kubeconfig);
    tokio::time::sleep(Duration::from_secs(3)).await;

    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, PIPELINE_NAMESPACE);

    let service = create_service_with_secrets(
        "pipeline-svc",
        PIPELINE_NAMESPACE,
        vec![(
            "db-creds",
            "database/credentials",
            TEST_PROVIDER,
            Some(vec!["username", "password"]),
        )],
    );

    info!("[Secrets/Pipeline] Creating LatticeService pipeline-svc (expect Failed)...");
    api.create(&PostParams::default(), &service)
        .await
        .map_err(|e| format!("Failed to create service: {}", e))?;

    wait_for_service_phase(
        kubeconfig,
        PIPELINE_NAMESPACE,
        "pipeline-svc",
        "Failed",
        Duration::from_secs(60),
    )
    .await?;

    // Verify NO ExternalSecret was created (Cedar denied before ESO generation)
    let es_output = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "get",
            "externalsecret",
            "pipeline-svc-db-creds",
            "-n",
            PIPELINE_NAMESPACE,
            "--ignore-not-found",
            "-o",
            "name",
        ],
    );
    match es_output {
        Ok(output) if output.trim().is_empty() => {
            info!("[Secrets/Pipeline] Confirmed: no ExternalSecret created while denied");
        }
        Ok(output) => {
            return Err(format!(
                "ExternalSecret should not exist while Cedar denies access, but found: {}",
                output.trim()
            ));
        }
        Err(_) => {
            info!("[Secrets/Pipeline] ExternalSecret not found (expected)");
        }
    }

    // Apply permit policy → service should recover
    info!("[Secrets/Pipeline] Applying Cedar permit policy...");
    apply_cedar_secret_permit_all(kubeconfig).await?;

    wait_for_service_phase(
        kubeconfig,
        PIPELINE_NAMESPACE,
        "pipeline-svc",
        "Ready",
        Duration::from_secs(90),
    )
    .await?;

    verify_external_secret(
        kubeconfig,
        PIPELINE_NAMESPACE,
        "pipeline-svc-db-creds",
        TEST_PROVIDER,
        "database/credentials",
        Some(&["username", "password"]),
    )
    .await?;

    info!("[Secrets/Pipeline] Test passed: Cedar deny -> permit -> ESO pipeline works!");
    Ok(())
}

/// Start Vault secrets tests asynchronously (for parallel execution in E2E)
pub async fn start_secrets_tests_async(
    ctx: &InfraContext,
) -> Result<tokio::task::JoinHandle<Result<(), String>>, String> {
    let ctx = ctx.clone();
    Ok(tokio::spawn(async move { run_secrets_tests(&ctx).await }))
}

// =============================================================================
// Local Secrets Tests (no Vault required)
// =============================================================================

/// Run local secrets integration tests (webhook-backed, no Vault).
///
/// Runs the basic CRD-level test first, then the comprehensive 5-route tests.
pub async fn run_local_secrets_tests(ctx: &InfraContext) -> Result<(), String> {
    let kubeconfig = ctx.require_workload()?;

    info!("[Integration/LocalSecrets] Running local secrets tests...");

    apply_e2e_default_policy(&ctx.mgmt_kubeconfig).await?;
    apply_cedar_secret_permit_all(kubeconfig).await?;

    let result = async {
        // Seed source secrets for basic test
        let mut test_data = std::collections::BTreeMap::new();
        test_data.insert("username".to_string(), "admin".to_string());
        test_data.insert("password".to_string(), "local-secret-123".to_string());
        seed_local_secret(kubeconfig, "local-db-creds", &test_data).await?;

        // Create local SecretsProvider + wait for Ready
        create_local_secrets_provider(kubeconfig, LOCAL_TEST_PROVIDER).await?;
        wait_for_secrets_provider_ready(kubeconfig, LOCAL_TEST_PROVIDER).await?;

        // Basic CRD-level test
        run_local_basic_secret_test(kubeconfig).await?;

        Ok::<(), String>(())
    }
    .await;

    remove_cedar_secret_permit_all(kubeconfig);
    result?;

    // Run the comprehensive 5-route tests (manages its own Cedar policies)
    run_local_secrets_route_tests(ctx).await?;

    info!("[Integration/LocalSecrets] All local secrets tests passed!");
    Ok(())
}

/// Test local secrets with explicit keys (CRD-level verification)
async fn run_local_basic_secret_test(kubeconfig: &str) -> Result<(), String> {
    const LOCAL_TEST_NAMESPACE: &str = "local-secrets-test";

    ensure_fresh_namespace(kubeconfig, LOCAL_TEST_NAMESPACE).await?;

    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, LOCAL_TEST_NAMESPACE);

    let service = create_service_with_secrets(
        "local-api",
        LOCAL_TEST_NAMESPACE,
        vec![(
            "db-creds",
            "local-db-creds",
            LOCAL_TEST_PROVIDER,
            Some(vec!["username", "password"]),
        )],
    );

    info!("[LocalSecrets] Creating LatticeService local-api...");
    api.create(&PostParams::default(), &service)
        .await
        .map_err(|e| format!("Failed to create service: {}", e))?;

    wait_for_service_phase(
        kubeconfig,
        LOCAL_TEST_NAMESPACE,
        "local-api",
        "Ready",
        Duration::from_secs(120),
    )
    .await?;

    verify_external_secret(
        kubeconfig,
        LOCAL_TEST_NAMESPACE,
        "local-api-db-creds",
        LOCAL_TEST_PROVIDER,
        "local-db-creds",
        Some(&["username", "password"]),
    )
    .await?;

    verify_synced_secret_keys(
        kubeconfig,
        LOCAL_TEST_NAMESPACE,
        "local-api-db-creds",
        &["username", "password"],
    )
    .await?;

    info!("[LocalSecrets] Basic local secret test passed!");
    Ok(())
}

// =============================================================================
// Local Secrets Route Tests (5 routes + combined)
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

    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, ROUTES_TEST_NAMESPACE);
    api.create(&PostParams::default(), &service)
        .await
        .map_err(|e| format!("Failed to create service: {}", e))?;

    wait_for_service_phase(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        "route1-pure-env",
        "Ready",
        Duration::from_secs(120),
    )
    .await?;

    verify_pod_env_var(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        "app=route1-pure-env",
        "DB_PASSWORD",
        "s3cret-p@ss",
    )
    .await?;

    verify_pod_env_var(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        "app=route1-pure-env",
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

    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, ROUTES_TEST_NAMESPACE);
    api.create(&PostParams::default(), &service)
        .await
        .map_err(|e| format!("Failed to create service: {}", e))?;

    wait_for_service_phase(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        "route2-mixed-env",
        "Ready",
        Duration::from_secs(120),
    )
    .await?;

    verify_pod_env_var(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        "app=route2-mixed-env",
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

    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, ROUTES_TEST_NAMESPACE);
    api.create(&PostParams::default(), &service)
        .await
        .map_err(|e| format!("Failed to create service: {}", e))?;

    wait_for_service_phase(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        "route3-file-mount",
        "Ready",
        Duration::from_secs(120),
    )
    .await?;

    verify_pod_file_content(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        "app=route3-file-mount",
        "/etc/app/config.yaml",
        "password: s3cret-p@ss",
    )
    .await?;

    verify_pod_file_content(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        "app=route3-file-mount",
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

    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, ROUTES_TEST_NAMESPACE);
    api.create(&PostParams::default(), &service)
        .await
        .map_err(|e| format!("Failed to create service: {}", e))?;

    wait_for_service_phase(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        "route4-pull-secrets",
        "Ready",
        Duration::from_secs(120),
    )
    .await?;

    verify_pod_image_pull_secrets(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        "app=route4-pull-secrets",
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

    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, ROUTES_TEST_NAMESPACE);
    api.create(&PostParams::default(), &service)
        .await
        .map_err(|e| format!("Failed to create service: {}", e))?;

    wait_for_service_phase(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        "route5-data-from",
        "Ready",
        Duration::from_secs(120),
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

    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, ROUTES_TEST_NAMESPACE);
    api.create(&PostParams::default(), &service)
        .await
        .map_err(|e| format!("Failed to create service: {}", e))?;

    wait_for_service_phase(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        "secret-routes-combined",
        "Ready",
        Duration::from_secs(180),
    )
    .await?;

    let label = "app=secret-routes-combined";

    // Route 1: Pure secret env vars
    verify_pod_env_var(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        label,
        "DB_PASSWORD",
        "s3cret-p@ss",
    )
    .await?;
    verify_pod_env_var(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        label,
        "DB_USERNAME",
        "admin",
    )
    .await?;

    // Route 2: Mixed-content env var
    verify_pod_env_var(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        label,
        "DATABASE_URL",
        "postgres://admin:s3cret-p@ss@db.svc:5432/mydb",
    )
    .await?;

    // Non-secret env var (sanity check)
    verify_pod_env_var(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        label,
        "APP_NAME",
        "secret-routes-test",
    )
    .await?;

    // Route 3: File mount
    verify_pod_file_content(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        label,
        "/etc/app/config.yaml",
        "password: s3cret-p@ss",
    )
    .await?;

    // Route 4: imagePullSecrets
    verify_pod_image_pull_secrets(
        kubeconfig,
        ROUTES_TEST_NAMESPACE,
        label,
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

/// Orchestrator: run all local secret route tests
///
/// Sets up the local provider and secrets, runs per-route + combined tests.
pub async fn run_local_secrets_route_tests(ctx: &InfraContext) -> Result<(), String> {
    let kubeconfig = ctx.require_workload()?;

    info!("[Routes] Running local secrets route tests (5 routes + combined)...");

    // Setup: Cedar permit-all, seed secrets, ensure provider exists
    apply_cedar_secret_permit_all(kubeconfig).await?;

    let result = async {
        seed_all_local_test_secrets(kubeconfig).await?;
        create_local_secrets_provider(kubeconfig, LOCAL_TEST_PROVIDER).await?;
        wait_for_secrets_provider_ready(kubeconfig, LOCAL_TEST_PROVIDER).await?;

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

    remove_cedar_secret_permit_all(kubeconfig);
    result?;

    info!("[Routes] All local secrets route tests passed!");
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

/// Standalone test - run Vault-backed secrets tests on existing cluster
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

/// Standalone test - run all local secrets tests (no Vault required)
#[tokio::test]
#[ignore]
async fn test_local_secrets_standalone() {
    use super::super::context::TestSession;

    let session =
        TestSession::from_env("Set LATTICE_WORKLOAD_KUBECONFIG to run local secrets tests")
            .await
            .expect("Failed to create test session");

    if let Err(e) = run_local_secrets_tests(&session.ctx).await {
        panic!("Local secrets tests failed: {}", e);
    }
}

/// Standalone test - run only the 5-route local secrets tests
#[tokio::test]
#[ignore]
async fn test_local_secrets_routes_standalone() {
    use super::super::context::TestSession;

    let session =
        TestSession::from_env("Set LATTICE_WORKLOAD_KUBECONFIG to run local secrets route tests")
            .await
            .expect("Failed to create test session");

    if let Err(e) = run_local_secrets_route_tests(&session.ctx).await {
        panic!("Local secrets route tests failed: {}", e);
    }
}

/// Standalone test - only basic Vault secret test
#[tokio::test]
#[ignore]
async fn test_basic_secret_standalone() {
    use super::super::context::TestSession;

    let session = TestSession::from_env("Set LATTICE_WORKLOAD_KUBECONFIG")
        .await
        .expect("Failed to create test session");
    let kubeconfig = session
        .ctx
        .require_workload()
        .expect("Need workload kubeconfig");

    if let Err(e) = run_basic_secret_test(kubeconfig).await {
        panic!("Basic secret test failed: {}", e);
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::ResourceType;

    #[test]
    fn test_create_service_with_secrets_structure() {
        let service = create_service_with_secrets(
            "test-svc",
            "test-ns",
            vec![("db", "path/to/db", "vault", Some(vec!["user", "pass"]))],
        );

        assert_eq!(service.metadata.name, Some("test-svc".to_string()));
        assert_eq!(service.metadata.namespace, Some("test-ns".to_string()));

        let db_resource = service.spec.resources.get("db").expect("db resource");
        assert!(matches!(db_resource.type_, ResourceType::Secret));
        assert_eq!(db_resource.id, Some("path/to/db".to_string()));

        let params = db_resource.params.as_ref().expect("params");
        assert_eq!(params.get("provider").unwrap(), &serde_json::json!("vault"));
        assert_eq!(
            params.get("keys").unwrap(),
            &serde_json::json!(["user", "pass"])
        );
    }

    #[test]
    fn test_create_service_no_keys_uses_data_from() {
        let service = create_service_with_secrets(
            "test-svc",
            "test-ns",
            vec![("all", "path/to/all", "vault", None)],
        );

        let all_resource = service.spec.resources.get("all").expect("all resource");
        let params = all_resource.params.as_ref().expect("params");

        assert!(params.get("provider").is_some());
        assert!(params.get("keys").is_none());
    }

    #[test]
    fn test_create_service_with_all_secret_routes() {
        let service = create_service_with_all_secret_routes("test", "test-ns", "local-test");

        // Should have 4 secret resources
        assert_eq!(service.spec.resources.len(), 4);
        assert!(service.spec.resources.contains_key("db-creds"));
        assert!(service.spec.resources.contains_key("api-key"));
        assert!(service.spec.resources.contains_key("all-db-config"));
        assert!(service.spec.resources.contains_key("ghcr-creds"));

        // Should have imagePullSecrets
        assert_eq!(service.spec.image_pull_secrets, vec!["ghcr-creds"]);

        // Main container should have env vars and files
        let main = service.spec.containers.get("main").expect("main container");
        assert!(main.variables.contains_key("DB_PASSWORD"));
        assert!(main.variables.contains_key("DATABASE_URL"));
        assert!(main.files.contains_key("/etc/app/config.yaml"));
    }

    #[test]
    fn test_add_secret_env_vars() {
        let service =
            create_service_with_secrets("test", "test-ns", vec![("s", "path", "vault", None)]);

        let patched = add_secret_env_vars(service, &[("FOO", "bar")]);

        let main = patched.spec.containers.get("main").expect("main");
        assert_eq!(main.variables.get("FOO").unwrap().as_str(), "bar");
    }
}
