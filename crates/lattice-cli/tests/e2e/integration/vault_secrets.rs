//! Vault secrets integration tests — Vault KV v2 ESO backend
//!
//! Tests LatticeService secret resource integration with ESO ExternalSecrets
//! via a Vault KV v2 backend. Uses the dev-mode Vault from docker-compose
//! with token auth.
//!
//! ## Test Suites
//!
//! ### 5-route tests
//! - Pure env var, mixed-content env var, file mount,
//!   imagePullSecrets, dataFrom (all keys)
//! - Combined all-routes test
//!
//! # Running
//!
//! ```bash
//! # Start Vault
//! docker compose up -d
//!
//! # Run standalone
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_vault_secrets_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::collections::BTreeMap;

use kube::Api;
use lattice_common::crd::LatticeService;
use tracing::info;

use super::super::helpers::{
    apply_cedar_secret_policy_for_service, apply_run_as_root_override_policy,
    build_busybox_service, cleanup_vault_infrastructure, client_from_kubeconfig,
    create_service_with_secrets, create_with_retry, delete_cedar_policies_by_label,
    delete_namespace, ensure_fresh_namespace, seed_all_vault_test_secrets, service_pod_selector,
    setup_regcreds_infrastructure, setup_vault_infrastructure, vault_tests_enabled,
    verify_pod_env_var, verify_pod_file_content, verify_pod_image_pull_secrets,
    verify_synced_secret_keys, wait_for_service_phase, with_run_as_root, BUSYBOX_IMAGE,
    DEFAULT_TIMEOUT, VAULT_STORE_NAME,
};
use super::secrets::verify_external_secret;

// =============================================================================
// Constants
// =============================================================================

/// Namespace for Vault 5-route secrets tests
const VAULT_TEST_NAMESPACE: &str = "vault-secrets-routes";

const TEST_LABEL: &str = "vault-secrets";

// =============================================================================
// Route Verification (pods already running)
// =============================================================================

/// Route 1: Pure secret env var -> secretKeyRef (Vault backend)
async fn verify_route1(kubeconfig: &str, namespace: &str) -> Result<(), String> {
    let selector = service_pod_selector("vr1-pure-env");
    verify_pod_env_var(
        kubeconfig,
        namespace,
        &selector,
        "DB_PASSWORD",
        "v@ult-s3cret",
    )
    .await?;
    verify_pod_env_var(kubeconfig, namespace, &selector, "DB_USERNAME", "admin").await?;
    info!("[Vault/Route1] Pure secret env var test passed!");
    Ok(())
}

/// Route 2: Mixed-content env var -> ESO templated env var (Vault backend)
async fn verify_route2(kubeconfig: &str, namespace: &str) -> Result<(), String> {
    verify_pod_env_var(
        kubeconfig,
        namespace,
        &service_pod_selector("vr2-mixed-env"),
        "DATABASE_URL",
        "postgres://admin:v@ult-s3cret@db.svc:5432/mydb",
    )
    .await?;
    info!("[Vault/Route2] Mixed-content env var test passed!");
    Ok(())
}

/// Route 3: File mount with secrets (Vault backend)
async fn verify_route3(kubeconfig: &str, namespace: &str) -> Result<(), String> {
    let selector = service_pod_selector("vr3-file-mount");
    verify_pod_file_content(
        kubeconfig,
        namespace,
        &selector,
        "/etc/app/config.yaml",
        "password: v@ult-s3cret",
    )
    .await?;
    verify_pod_file_content(
        kubeconfig,
        namespace,
        &selector,
        "/etc/app/config.yaml",
        "api_key: vk-test-67890",
    )
    .await?;
    info!("[Vault/Route3] File mount secret test passed!");
    Ok(())
}

/// Route 4: imagePullSecrets (Vault backend)
async fn verify_route4(kubeconfig: &str, namespace: &str) -> Result<(), String> {
    verify_pod_image_pull_secrets(
        kubeconfig,
        namespace,
        &service_pod_selector("vr4-pull-secrets"),
        "vr4-pull-secrets-ghcr-creds",
    )
    .await?;
    info!("[Vault/Route4] imagePullSecrets test passed!");
    Ok(())
}

/// Route 5: dataFrom (all keys) (Vault backend)
async fn verify_route5(kubeconfig: &str, namespace: &str) -> Result<(), String> {
    verify_external_secret(
        kubeconfig,
        namespace,
        "vr5-data-from-all-db-config",
        VAULT_STORE_NAME,
        "vault-database-config",
        None,
    )
    .await?;
    verify_synced_secret_keys(
        kubeconfig,
        namespace,
        "vr5-data-from-all-db-config",
        &["host", "port", "name", "ssl"],
    )
    .await?;
    info!("[Vault/Route5] dataFrom (all keys) test passed!");
    Ok(())
}

/// Combined: all 5 routes in a single service (Vault backend)
async fn verify_combined(kubeconfig: &str, namespace: &str) -> Result<(), String> {
    let label = service_pod_selector("vault-routes-combined");
    verify_pod_env_var(kubeconfig, namespace, &label, "DB_PASSWORD", "v@ult-s3cret").await?;
    verify_pod_env_var(kubeconfig, namespace, &label, "DB_USERNAME", "admin").await?;
    verify_pod_env_var(
        kubeconfig,
        namespace,
        &label,
        "DATABASE_URL",
        "postgres://admin:v@ult-s3cret@db.svc:5432/mydb",
    )
    .await?;
    verify_pod_env_var(
        kubeconfig,
        namespace,
        &label,
        "APP_NAME",
        "vault-routes-test",
    )
    .await?;
    verify_pod_file_content(
        kubeconfig,
        namespace,
        &label,
        "/etc/app/config.yaml",
        "password: v@ult-s3cret",
    )
    .await?;
    verify_pod_image_pull_secrets(
        kubeconfig,
        namespace,
        &label,
        "vault-routes-combined-ghcr-creds",
    )
    .await?;
    verify_synced_secret_keys(
        kubeconfig,
        namespace,
        "vault-routes-combined-all-db-config",
        &["host", "port", "name", "ssl"],
    )
    .await?;
    info!("[Vault/Combined] All 5 secret routes verified in combined service!");
    Ok(())
}

// =============================================================================
// Service Builder Helpers (Vault-specific)
// =============================================================================

/// Add secret-referencing environment variables to a LatticeService's main container.
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

/// Build a LatticeService exercising all 5 secret routes with Vault backend.
///
/// Similar to `create_service_with_all_secret_routes` but with Vault-specific
/// resource paths and provider.
fn create_vault_all_routes_service(name: &str, namespace: &str) -> LatticeService {
    use lattice_common::crd::{
        ContainerSpec, FileMount, ResourceParams, ResourceQuantity, ResourceRequirements,
        ResourceSpec, ResourceType, SecretParams,
    };
    use lattice_common::template::TemplateString;

    // Container with env vars and file mounts exercising routes 1-3
    let mut variables = BTreeMap::new();
    // Route 1: Pure secret env vars
    variables.insert(
        "DB_PASSWORD".to_string(),
        TemplateString::new("${secret.db-creds.password}"),
    );
    variables.insert(
        "DB_USERNAME".to_string(),
        TemplateString::new("${secret.db-creds.username}"),
    );
    // Route 2: Mixed-content env var
    variables.insert(
        "DATABASE_URL".to_string(),
        TemplateString::new(
            "postgres://${secret.db-creds.username}:${secret.db-creds.password}@db.svc:5432/mydb",
        ),
    );
    // Plain env var (contrast)
    variables.insert(
        "APP_NAME".to_string(),
        TemplateString::new("vault-routes-test"),
    );

    // Route 3: File mount with secret templates
    let mut files = BTreeMap::new();
    files.insert(
        "/etc/app/config.yaml".to_string(),
        FileMount {
            content: Some(TemplateString::new(
                "database:\n  password: ${secret.db-creds.password}\n  username: ${secret.db-creds.username}\napi_key: ${secret.api-key.key}\n",
            )),
            ..Default::default()
        },
    );

    let mut containers = BTreeMap::new();
    containers.insert(
        "main".to_string(),
        ContainerSpec {
            image: BUSYBOX_IMAGE.to_string(),
            command: Some(vec!["/bin/sleep".to_string(), "infinity".to_string()]),
            variables,
            files,
            resources: Some(ResourceRequirements {
                requests: Some(ResourceQuantity {
                    cpu: Some("50m".to_string()),
                    memory: Some("64Mi".to_string()),
                }),
                limits: Some(ResourceQuantity {
                    cpu: Some("200m".to_string()),
                    memory: Some("128Mi".to_string()),
                }),
            }),
            security: Some(lattice_common::crd::SecurityContext {
                apparmor_profile: Some("Unconfined".to_string()),
                allowed_binaries: vec!["/bin/printenv".to_string(), "/bin/cat".to_string()],
                run_as_user: Some(65534),
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    // Resources: 4 secret resources covering all 5 routes (Vault backend)
    let mut resources = BTreeMap::new();

    // Routes 1, 2, 3: db-creds with explicit keys
    resources.insert(
        "db-creds".to_string(),
        ResourceSpec {
            type_: ResourceType::Secret,
            id: Some("vault-db-creds".to_string()),
            params: ResourceParams::Secret(SecretParams {
                provider: VAULT_STORE_NAME.to_string(),
                keys: Some(vec!["username".to_string(), "password".to_string()]),
                refresh_interval: Some("1h".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    // Route 3: api-key with explicit key
    resources.insert(
        "api-key".to_string(),
        ResourceSpec {
            type_: ResourceType::Secret,
            id: Some("vault-api-key".to_string()),
            params: ResourceParams::Secret(SecretParams {
                provider: VAULT_STORE_NAME.to_string(),
                keys: Some(vec!["key".to_string()]),
                refresh_interval: Some("1h".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    // Route 5: dataFrom (all keys, no explicit keys param)
    resources.insert(
        "all-db-config".to_string(),
        ResourceSpec {
            type_: ResourceType::Secret,
            id: Some("vault-database-config".to_string()),
            params: ResourceParams::Secret(SecretParams {
                provider: VAULT_STORE_NAME.to_string(),
                refresh_interval: Some("1h".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    // Route 4: ghcr-creds for imagePullSecrets (Vault-backed)
    resources.insert(
        "ghcr-creds".to_string(),
        ResourceSpec {
            type_: ResourceType::Secret,
            id: Some("vault-regcreds".to_string()),
            params: ResourceParams::Secret(SecretParams {
                provider: VAULT_STORE_NAME.to_string(),
                refresh_interval: Some("1h".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    build_busybox_service(name, namespace, containers, resources)
}

// =============================================================================
// Route Test Orchestrator
// =============================================================================

/// Run all Vault secret route tests (5 routes + combined).
///
/// Sets up Vault infrastructure, seeds test secrets, deploys services with
/// Vault-backed secrets, and verifies all 5 secret delivery routes work
/// end-to-end through the ESO pipeline.
pub async fn run_vault_secrets_tests(kubeconfig: &str) -> Result<(), String> {
    info!("[Vault/Secrets] Running Vault secrets integration tests...");

    if !vault_tests_enabled() {
        info!("[Vault/Secrets] Vault not reachable, skipping Vault secrets tests");
        info!("[Vault/Secrets] Start Vault with: docker compose up -d");
        return Ok(());
    }

    // Set up local provider + regcreds (needed for services that use lattice-local for ghcr-creds)
    setup_regcreds_infrastructure(kubeconfig).await?;

    // Set up Vault infrastructure (SecretProvider CRD + token secret)
    setup_vault_infrastructure(kubeconfig).await?;

    // Seed all test secrets into Vault
    seed_all_vault_test_secrets().await?;

    // Cedar policies: permit test namespace to access Vault secret paths
    apply_cedar_secret_policy_for_service(
        kubeconfig,
        "permit-vault-route-secrets",
        TEST_LABEL,
        VAULT_TEST_NAMESPACE,
        &[
            "vault-db-creds",
            "vault-api-key",
            "vault-database-config",
            "vault-regcreds",
        ],
    )
    .await?;

    // busybox runs as root
    for svc in [
        "vr1-pure-env",
        "vr2-mixed-env",
        "vr3-file-mount",
        "vr4-pull-secrets",
        "vr5-data-from",
        "vault-routes-combined",
    ] {
        apply_run_as_root_override_policy(kubeconfig, VAULT_TEST_NAMESPACE, svc).await?;
    }

    // Run the tests, always cleanup afterward
    let result = run_vault_route_tests_inner(kubeconfig, VAULT_TEST_NAMESPACE).await;

    delete_namespace(kubeconfig, VAULT_TEST_NAMESPACE).await;
    delete_cedar_policies_by_label(kubeconfig, &format!("lattice.dev/test={TEST_LABEL}")).await;
    cleanup_vault_infrastructure(kubeconfig).await;

    result?;

    info!("[Vault/Secrets] All Vault secrets tests passed!");
    Ok(())
}

async fn run_vault_route_tests_inner(kubeconfig: &str, namespace: &str) -> Result<(), String> {
    ensure_fresh_namespace(kubeconfig, namespace).await?;

    // Build all services
    let svc1 = add_secret_env_vars(
        with_run_as_root(create_service_with_secrets(
            "vr1-pure-env",
            namespace,
            vec![(
                "db-creds",
                "vault-db-creds",
                VAULT_STORE_NAME,
                Some(vec!["username", "password"]),
            )],
        )),
        &[
            ("DB_PASSWORD", "${secret.db-creds.password}"),
            ("DB_USERNAME", "${secret.db-creds.username}"),
        ],
    );
    let svc2 = add_secret_env_vars(
        with_run_as_root(create_service_with_secrets(
            "vr2-mixed-env",
            namespace,
            vec![(
                "db-creds",
                "vault-db-creds",
                VAULT_STORE_NAME,
                Some(vec!["username", "password"]),
            )],
        )),
        &[(
            "DATABASE_URL",
            "postgres://${secret.db-creds.username}:${secret.db-creds.password}@db.svc:5432/mydb",
        )],
    );
    let svc3 = with_run_as_root(create_vault_all_routes_service("vr3-file-mount", namespace));
    let svc4 = with_run_as_root(create_vault_all_routes_service(
        "vr4-pull-secrets",
        namespace,
    ));
    let svc5 = with_run_as_root(create_service_with_secrets(
        "vr5-data-from",
        namespace,
        vec![(
            "all-db-config",
            "vault-database-config",
            VAULT_STORE_NAME,
            None,
        )],
    ));
    let svc6 = with_run_as_root(create_vault_all_routes_service(
        "vault-routes-combined",
        namespace,
    ));

    // Deploy all services
    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, namespace);
    for svc in [&svc1, &svc2, &svc3, &svc4, &svc5, &svc6] {
        let name = svc.metadata.name.as_deref().unwrap();
        create_with_retry(&api, svc, name).await?;
    }

    // Wait for all to reach Ready in parallel
    let timeout = DEFAULT_TIMEOUT;
    let names = [
        "vr1-pure-env",
        "vr2-mixed-env",
        "vr3-file-mount",
        "vr4-pull-secrets",
        "vr5-data-from",
        "vault-routes-combined",
    ];
    let wait_futures: Vec<_> = names
        .iter()
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

    Ok(())
}

// =============================================================================
// Standalone Tests (run with --ignored)
// =============================================================================

/// Standalone test — run Vault secrets tests on existing cluster
///
/// Requires `LATTICE_KUBECONFIG` and Vault running via docker-compose.
#[tokio::test]
#[ignore]
async fn test_vault_secrets_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();

    if !vault_tests_enabled() {
        eprintln!("Skipping: Vault not reachable (start with: docker compose up -d)");
        return;
    }

    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_vault_secrets_tests(&resolved.kubeconfig).await.unwrap();
}
