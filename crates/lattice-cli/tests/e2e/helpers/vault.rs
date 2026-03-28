//! Vault integration test helpers
//!
//! Provides utilities for setting up HashiCorp Vault as an ESO backend
//! in E2E tests. Uses the dev-mode Vault from docker-compose with token auth
//! and KV v2 mounted at `secret/`.

#![cfg(feature = "provider-e2e")]

use std::collections::BTreeMap;
use std::time::Duration;

use lattice_common::LATTICE_SYSTEM_NAMESPACE;
use tracing::info;

use super::cedar::apply_yaml;
use super::docker::run_kubectl;
use super::{dev_service_reachable, dev_service_url, wait_for_condition};

// =============================================================================
// Constants
// =============================================================================

fn vault_url() -> String {
    dev_service_url("LATTICE_VAULT_URL", "http://127.0.0.1:8200")
}

/// Dev-mode root token (set via VAULT_DEV_ROOT_TOKEN_ID in docker-compose)
const VAULT_DEV_TOKEN: &str = "root";

/// KV v2 mount path (dev-mode default)
const VAULT_KV_MOUNT: &str = "secret";

/// SecretProvider CRD name for Vault E2E tests
pub const VAULT_STORE_NAME: &str = "vault-e2e";

/// K8s Secret name for the Vault token
const VAULT_TOKEN_SECRET_NAME: &str = "vault-e2e-token";

// =============================================================================
// Availability Check
// =============================================================================

/// Check if Vault tests should run (Vault dev server is reachable)
pub fn vault_tests_enabled() -> bool {
    dev_service_reachable(&format!("{}/v1/sys/health", vault_url()))
}

// =============================================================================
// Vault HTTP API Helpers
// =============================================================================

/// Write a secret to Vault KV v2 at the given path.
pub async fn vault_kv_put(path: &str, data: &BTreeMap<String, String>) -> Result<(), String> {
    let url = format!("{}/v1/{}/data/{}", vault_url(), VAULT_KV_MOUNT, path);
    let payload = serde_json::json!({ "data": data });

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .header("X-Vault-Token", VAULT_DEV_TOKEN)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Vault KV put failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Vault KV put to '{}' failed: {} - {}",
            path, status, body
        ));
    }

    info!("[Vault] Wrote secret at {}/{}", VAULT_KV_MOUNT, path);
    Ok(())
}

// =============================================================================
// Secret Seeding
// =============================================================================

/// Seed all test secrets into Vault for the 5-route secret tests.
///
/// Seeds the same structure as `seed_all_local_test_secrets` but into Vault KV v2
/// with distinct paths and values.
pub async fn seed_all_vault_test_secrets() -> Result<(), String> {
    info!("[Vault] Seeding all test secrets into Vault...");

    // db-creds (Routes 1, 2, 3)
    vault_kv_put(
        "vault-db-creds",
        &BTreeMap::from([
            ("username".to_string(), "admin".to_string()),
            ("password".to_string(), "v@ult-s3cret".to_string()),
        ]),
    )
    .await?;

    // api-key (Route 3 file mount)
    vault_kv_put(
        "vault-api-key",
        &BTreeMap::from([("key".to_string(), "vk-test-67890".to_string())]),
    )
    .await?;

    // database-config (Route 5 dataFrom — all keys)
    vault_kv_put(
        "vault-database-config",
        &BTreeMap::from([
            ("host".to_string(), "db.vault-prod".to_string()),
            ("port".to_string(), "5432".to_string()),
            ("name".to_string(), "vaultdb".to_string()),
            ("ssl".to_string(), "true".to_string()),
        ]),
    )
    .await?;

    // regcreds (imagePullSecrets — needed for Route 4)
    let docker_config = super::cluster::load_registry_credentials()
        .ok_or("No GHCR credentials (check .env or GHCR_USER/GHCR_TOKEN env vars)")?;
    vault_kv_put(
        "vault-regcreds",
        &BTreeMap::from([(".dockerconfigjson".to_string(), docker_config)]),
    )
    .await?;

    info!("[Vault] All test secrets seeded");
    Ok(())
}

// =============================================================================
// Infrastructure Setup
// =============================================================================

/// Set up Vault as an ESO backend for integration tests.
///
/// Creates a K8s Secret with the Vault dev root token, applies a SecretProvider
/// CRD pointing at Vault with token auth, and waits for Ready phase.
pub async fn setup_vault_infrastructure(kubeconfig: &str) -> Result<(), String> {
    info!("[Vault] Setting up Vault ESO infrastructure...");

    // Create K8s Secret with Vault token in lattice-system
    let token_secret_yaml = format!(
        r#"apiVersion: v1
kind: Secret
metadata:
  name: {token_secret}
  namespace: {namespace}
  labels:
    lattice.dev/test: vault
type: Opaque
stringData:
  token: "{token}""#,
        token_secret = VAULT_TOKEN_SECRET_NAME,
        namespace = LATTICE_SYSTEM_NAMESPACE,
        token = VAULT_DEV_TOKEN,
    );
    apply_yaml(kubeconfig, &token_secret_yaml).await?;
    info!("[Vault] Created token secret '{}'", VAULT_TOKEN_SECRET_NAME);

    // Apply SecretProvider CRD
    let provider_yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: SecretProvider
metadata:
  name: {store_name}
  namespace: {namespace}
  labels:
    lattice.dev/test: vault
spec:
  provider:
    vault:
      server: "{vault_url}"
      path: {kv_mount}
      version: v2
      auth:
        tokenSecretRef:
          name: {token_secret}
          namespace: {namespace}
          key: token"#,
        store_name = VAULT_STORE_NAME,
        namespace = LATTICE_SYSTEM_NAMESPACE,
        vault_url = vault_internal_url(),
        kv_mount = VAULT_KV_MOUNT,
        token_secret = VAULT_TOKEN_SECRET_NAME,
    );
    apply_yaml(kubeconfig, &provider_yaml).await?;
    info!("[Vault] Applied SecretProvider '{}'", VAULT_STORE_NAME);

    // Wait for SecretProvider to reach Ready phase.
    // ESO re-validation can take >120s when a stale ClusterSecretStore exists
    // from a previous run, so allow 180s.
    wait_for_condition(
        &format!("SecretProvider '{}' to become Ready", VAULT_STORE_NAME),
        Duration::from_secs(180),
        Duration::from_secs(3),
        || async move {
            let phase = run_kubectl(&[
                "--kubeconfig",
                kubeconfig,
                "get",
                "secretprovider",
                VAULT_STORE_NAME,
                "-n",
                LATTICE_SYSTEM_NAMESPACE,
                "-o",
                "jsonpath={.status.phase}",
            ])
            .await?;
            Ok(phase.trim() == "Ready")
        },
    )
    .await?;

    info!("[Vault] SecretProvider '{}' is Ready", VAULT_STORE_NAME);
    Ok(())
}

/// Clean up all Vault test resources.
pub async fn cleanup_vault_infrastructure(kubeconfig: &str) {
    info!("[Vault] Cleaning up Vault test resources...");

    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "secretprovider",
        "-n",
        LATTICE_SYSTEM_NAMESPACE,
        "-l",
        "lattice.dev/test=vault",
        "--ignore-not-found",
    ])
    .await;

    // Delete the ClusterSecretStore directly so subsequent runs start clean.
    // The controller normally manages this, but in endurance tests the operator
    // may not process the SP deletion before the next run begins, leaving a
    // stale CSS that ESO must re-validate (slow).
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "clustersecretstore",
        VAULT_STORE_NAME,
        "--ignore-not-found",
    ])
    .await;

    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "secret",
        VAULT_TOKEN_SECRET_NAME,
        "-n",
        LATTICE_SYSTEM_NAMESPACE,
        "--ignore-not-found",
    ])
    .await;

    info!("[Vault] Cleanup complete");
}
