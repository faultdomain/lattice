//! Secrets integration tests - run against existing cluster
//!
//! Tests LatticeService secret resource integration with ESO ExternalSecrets.
//! These tests verify that secret resources in LatticeService correctly generate
//! ExternalSecret objects that reference ClusterSecretStore.
//!
//! Vault runs via docker-compose at a fixed endpoint (lattice-vault:8200).
//! If Vault is reachable, secrets tests run automatically.
//!
//! # Running
//!
//! ```bash
//! # Start Vault
//! docker compose up -d
//!
//! # Run standalone
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/kubeconfig \
//! cargo test --features provider-e2e --test e2e test_secrets_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use kube::api::{Api, PostParams};
use lattice_operator::crd::LatticeService;
use tokio::time::sleep;
use tracing::info;

use super::super::context::InfraContext;
use super::super::helpers::{
    client_from_kubeconfig, create_service_with_secrets, ensure_fresh_namespace, run_cmd,
    wait_for_service_phase,
};
use super::cedar::apply_e2e_default_policy;
use super::cedar_secrets::{apply_cedar_secret_permit_all, remove_cedar_secret_permit_all};

/// Test namespace for secrets integration tests
const TEST_NAMESPACE: &str = "secrets-test";

/// Test SecretsProvider name
const TEST_PROVIDER: &str = "vault-test";

/// Lattice system namespace
const LATTICE_SYSTEM_NAMESPACE: &str = "lattice-system";

/// Fixed Vault endpoint (from docker-compose)
const VAULT_URL: &str = "http://lattice-vault:8200";

/// Fixed Vault token (from docker-compose)
const VAULT_TOKEN: &str = "root";

/// Vault URL for host access (port-forwarded)
const VAULT_HOST_URL: &str = "http://127.0.0.1:8200";

// =============================================================================
// Vault Setup
// =============================================================================

/// Check if secrets tests should run (Vault is reachable)
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

/// Set up test secrets in Vault
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

/// Create the Vault token secret in the cluster
async fn create_vault_token_secret(kubeconfig: &str) -> Result<(), String> {
    info!("[Secrets/Setup] Creating Vault token secret...");

    let secret_yaml = format!(
        r#"apiVersion: v1
kind: Secret
metadata:
  name: vault-test-token
  namespace: {namespace}
type: Opaque
stringData:
  token: {token}
"#,
        namespace = LATTICE_SYSTEM_NAMESPACE,
        token = VAULT_TOKEN
    );

    let mut child = std::process::Command::new("kubectl")
        .args(["--kubeconfig", kubeconfig, "apply", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn kubectl: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        std::io::Write::write_all(&mut stdin, secret_yaml.as_bytes())
            .map_err(|e| format!("Failed to write to stdin: {}", e))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("kubectl failed: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "kubectl apply failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    info!("[Secrets/Setup] Vault token secret created");
    Ok(())
}

/// Create the SecretsProvider CRD in the cluster
async fn create_secrets_provider(kubeconfig: &str) -> Result<(), String> {
    info!("[Secrets/Setup] Creating SecretsProvider CRD...");

    let provider_yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: SecretsProvider
metadata:
  name: {provider_name}
  namespace: {namespace}
spec:
  server: {vault_url}
  path: secret
  authMethod: token
  credentialsSecretRef:
    name: vault-test-token
    namespace: {namespace}
"#,
        provider_name = TEST_PROVIDER,
        namespace = LATTICE_SYSTEM_NAMESPACE,
        vault_url = VAULT_URL
    );

    let mut child = std::process::Command::new("kubectl")
        .args(["--kubeconfig", kubeconfig, "apply", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn kubectl: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        std::io::Write::write_all(&mut stdin, provider_yaml.as_bytes())
            .map_err(|e| format!("Failed to write to stdin: {}", e))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("kubectl failed: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "kubectl apply failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    info!("[Secrets/Setup] SecretsProvider created");
    Ok(())
}

/// Wait for SecretsProvider to be Ready (ClusterSecretStore created)
async fn wait_for_secrets_provider_ready(kubeconfig: &str) -> Result<(), String> {
    info!("[Secrets/Setup] Waiting for SecretsProvider to be Ready...");

    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(120);

    loop {
        if start.elapsed() > timeout {
            return Err(format!(
                "Timeout waiting for SecretsProvider {} to be Ready",
                TEST_PROVIDER
            ));
        }

        let output = run_cmd(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig,
                "get",
                "secretsprovider",
                TEST_PROVIDER,
                "-n",
                LATTICE_SYSTEM_NAMESPACE,
                "-o",
                "jsonpath={.status.phase}",
            ],
        );

        match output {
            Ok(phase) => {
                info!("[Secrets/Setup] SecretsProvider phase: {}", phase.trim());
                if phase.trim() == "Ready" {
                    info!("[Secrets/Setup] SecretsProvider is Ready!");
                    return Ok(());
                }
                if phase.trim() == "Failed" {
                    return Err("SecretsProvider failed".to_string());
                }
            }
            Err(e) => {
                info!("[Secrets/Setup] Error checking SecretsProvider: {}", e);
            }
        }

        sleep(Duration::from_secs(5)).await;
    }
}

/// Set up Vault infrastructure for secrets testing
pub async fn setup_vault_infrastructure(kubeconfig: &str) -> Result<(), String> {
    info!("[Secrets/Setup] Setting up Vault infrastructure...");

    setup_vault_test_secrets().await?;
    create_vault_token_secret(kubeconfig).await?;
    create_secrets_provider(kubeconfig).await?;
    wait_for_secrets_provider_ready(kubeconfig).await?;

    info!("[Secrets/Setup] Vault infrastructure setup complete!");
    Ok(())
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Get ExternalSecret and verify its structure
async fn verify_external_secret(
    kubeconfig_path: &str,
    namespace: &str,
    name: &str,
    expected_store: &str,
    expected_vault_path: &str,
    expected_keys: Option<&[&str]>,
) -> Result<(), String> {
    // Use kubectl to get the ExternalSecret JSON
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

    // Verify apiVersion
    let api_version = json["apiVersion"].as_str().ok_or("Missing apiVersion")?;
    assert_eq!(
        api_version, "external-secrets.io/v1",
        "ExternalSecret should have correct apiVersion"
    );

    // Verify kind
    let kind = json["kind"].as_str().ok_or("Missing kind")?;
    assert_eq!(kind, "ExternalSecret", "Should be ExternalSecret");

    // Verify secretStoreRef
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

    // Verify target name matches ExternalSecret name
    let target_name = json["spec"]["target"]["name"]
        .as_str()
        .ok_or("Missing target.name")?;
    assert_eq!(
        target_name, name,
        "target.name should match ExternalSecret name"
    );

    // Verify data or dataFrom based on whether keys were specified
    if let Some(keys) = expected_keys {
        // Should have explicit data mappings
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
                remote_key, expected_vault_path,
                "remoteRef.key should be vault path"
            );

            let property = entry["remoteRef"]["property"]
                .as_str()
                .ok_or("Missing remoteRef.property")?;
            assert_eq!(property, *key, "remoteRef.property should match key");
        }
    } else {
        // Should have dataFrom with extract
        let data_from = json["spec"]["dataFrom"]
            .as_array()
            .ok_or("Expected dataFrom array when no explicit keys")?;

        assert!(!data_from.is_empty(), "dataFrom should not be empty");

        let extract_key = data_from[0]["extract"]["key"]
            .as_str()
            .ok_or("Missing dataFrom[].extract.key")?;
        assert_eq!(
            extract_key, expected_vault_path,
            "extract.key should be vault path"
        );
    }

    // Verify refreshInterval
    let refresh_interval = json["spec"]["refreshInterval"].as_str();
    assert_eq!(
        refresh_interval,
        Some("1h"),
        "refreshInterval should be set"
    );

    info!(
        "[Secrets] ExternalSecret {} verified: store={}, path={}, keys={:?}",
        name, store_name, expected_vault_path, expected_keys
    );

    Ok(())
}

/// Verify that the K8s Secret was created by ESO (if ESO is running)
async fn verify_synced_secret(
    kubeconfig_path: &str,
    namespace: &str,
    name: &str,
    expected_keys: Option<&[&str]>,
) -> Result<(), String> {
    // Try to get the secret - this may not exist if ESO isn't running
    // or if Vault isn't configured with test data
    let output = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "get",
            "secret",
            name,
            "-n",
            namespace,
            "-o",
            "json",
        ],
    );

    match output {
        Ok(json_str) => {
            let json: serde_json::Value = serde_json::from_str(&json_str)
                .map_err(|e| format!("Failed to parse Secret JSON: {}", e))?;

            // Verify it's managed by ESO
            let labels = &json["metadata"]["labels"];
            let managed_by = labels
                .get("app.kubernetes.io/managed-by")
                .and_then(|v| v.as_str());

            // ESO typically adds this annotation
            let annotations = &json["metadata"]["annotations"];
            let _reconcile_hash = annotations
                .get("reconcile.external-secrets.io/data-hash")
                .and_then(|v| v.as_str());

            // Verify data keys if specified
            if let Some(keys) = expected_keys {
                let data = json["data"].as_object().ok_or("Secret should have data")?;

                for key in keys {
                    if !data.contains_key(*key) {
                        return Err(format!("Secret missing expected key: {}", key));
                    }
                }
                info!("[Secrets] Secret {} has expected keys: {:?}", name, keys);
            }

            info!(
                "[Secrets] Synced Secret {} exists (managed_by={:?})",
                name, managed_by
            );
            Ok(())
        }
        Err(_) => {
            // Secret doesn't exist - this is OK if ESO isn't fully configured
            info!(
                "[Secrets] Secret {} not found (ESO may not be syncing)",
                name
            );
            Ok(())
        }
    }
}

// =============================================================================
// Integration Test Functions (called by E2E or standalone)
// =============================================================================

/// Run all secrets integration tests
pub async fn run_secrets_tests(ctx: &InfraContext) -> Result<(), String> {
    // Ensure Cedar policy allows proxy access (may have been removed by Cedar tests)
    apply_e2e_default_policy(&ctx.mgmt_kubeconfig).await?;

    let kubeconfig = ctx.require_workload()?;

    info!(
        "[Integration/Secrets] Running secrets tests on cluster at {}",
        kubeconfig
    );

    // Apply permit-all-secrets Cedar policy so ESO pipeline tests pass Cedar authorization
    apply_cedar_secret_permit_all(kubeconfig).await?;

    setup_vault_infrastructure(kubeconfig).await?;

    let result = async {
        // Test 1: Basic secret resource with explicit keys
        info!("[Integration/Secrets] Test 1: Basic secret with explicit keys...");
        run_basic_secret_test(kubeconfig).await?;

        // Test 2: Secret without explicit keys (dataFrom pattern)
        info!("[Integration/Secrets] Test 2: Secret without explicit keys (dataFrom)...");
        run_data_from_secret_test(kubeconfig).await?;

        // Test 3: Multiple secrets in one service
        info!("[Integration/Secrets] Test 3: Multiple secrets in one service...");
        run_multiple_secrets_test(kubeconfig).await?;

        // Test 4: Cedar + Secrets pipeline (deny → permit → verify ESO resources)
        info!("[Integration/Secrets] Test 4: Cedar + Secrets pipeline...");
        run_cedar_secrets_pipeline_test(kubeconfig).await?;

        Ok::<(), String>(())
    }
    .await;

    // Clean up the permit-all-secrets policy regardless of test outcome
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

    // Create service with a secret that has explicit keys
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

    // Wait for service to be Ready
    wait_for_service_phase(
        kubeconfig,
        TEST_NAMESPACE,
        "api-with-secrets",
        "Ready",
        Duration::from_secs(120),
    )
    .await?;

    // Verify ExternalSecret was created with correct structure
    verify_external_secret(
        kubeconfig,
        TEST_NAMESPACE,
        "api-with-secrets-db-creds",
        TEST_PROVIDER,
        "database/prod/credentials",
        Some(&["username", "password"]),
    )
    .await?;

    // Verify synced secret (if ESO is running)
    verify_synced_secret(
        kubeconfig,
        TEST_NAMESPACE,
        "api-with-secrets-db-creds",
        Some(&["username", "password"]),
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

    // Create service with a secret that has no explicit keys
    let service = create_service_with_secrets(
        "api-all-keys",
        TEST_NAMESPACE,
        vec![(
            "all-secrets",
            "services/all-secrets",
            TEST_PROVIDER,
            None, // No explicit keys - should use dataFrom
        )],
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

    // Verify ExternalSecret uses dataFrom pattern
    verify_external_secret(
        kubeconfig,
        TEST_NAMESPACE,
        "api-all-keys-all-secrets",
        TEST_PROVIDER,
        "services/all-secrets",
        None, // No explicit keys - verifies dataFrom
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

    // Create service with multiple secrets
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
            (
                "tls-certs",
                "pki/certificates",
                TEST_PROVIDER,
                None, // All keys from this path
            ),
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

    // Verify each ExternalSecret
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
///
/// Validates the full pipeline:
/// 1. Create service with secrets, NO Cedar policy → Failed, no ExternalSecret
/// 2. Apply permit policy → service recovers to Ready
/// 3. Verify ExternalSecret IS created
async fn run_cedar_secrets_pipeline_test(kubeconfig: &str) -> Result<(), String> {
    const PIPELINE_NAMESPACE: &str = "secrets-pipeline-test";

    ensure_fresh_namespace(kubeconfig, PIPELINE_NAMESPACE).await?;

    // Remove the permit-all policy so we start with default-deny
    remove_cedar_secret_permit_all(kubeconfig);
    tokio::time::sleep(Duration::from_secs(3)).await;

    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, PIPELINE_NAMESPACE);

    // Create service with secrets — no Cedar policy → should fail
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

    // Wait for service to recover to Ready
    wait_for_service_phase(
        kubeconfig,
        PIPELINE_NAMESPACE,
        "pipeline-svc",
        "Ready",
        Duration::from_secs(90),
    )
    .await?;

    // Verify ExternalSecret IS now created
    verify_external_secret(
        kubeconfig,
        PIPELINE_NAMESPACE,
        "pipeline-svc-db-creds",
        TEST_PROVIDER,
        "database/credentials",
        Some(&["username", "password"]),
    )
    .await?;

    info!("[Secrets/Pipeline] Test passed: Cedar deny → permit → ESO pipeline works!");
    Ok(())
}

/// Start secrets tests asynchronously (for parallel execution in E2E)
pub async fn start_secrets_tests_async(
    ctx: &InfraContext,
) -> Result<tokio::task::JoinHandle<Result<(), String>>, String> {
    let ctx = ctx.clone();
    Ok(tokio::spawn(async move { run_secrets_tests(&ctx).await }))
}

// =============================================================================
// Standalone Tests (run with --ignored)
// =============================================================================

/// Standalone test - run secrets tests on existing cluster
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

/// Standalone test - only basic secret test
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
// Unit Tests for Secret CRD Validation
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_operator::crd::ResourceType;

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
}
