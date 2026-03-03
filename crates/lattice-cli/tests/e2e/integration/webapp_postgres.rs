//! Web App + PostgreSQL integration test (3 services)
//!
//! Deploys a simple 3-tier web application:
//!   nginx-frontend -> app-server -> postgres
//!
//! Verifies:
//! - Third-party container (postgres:alpine) runs as LatticeService
//! - Postgres responds to `pg_isready` exec probe
//! - Bilateral mesh agreements enforce correct access patterns
//! - Env var injection on app-server (DB_HOST, DB_PORT)
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_webapp_postgres_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::collections::BTreeMap;
use std::time::Duration;

use futures::future::try_join_all;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::Api;
use lattice_common::crd::{
    LatticeService, LatticeServiceSpec, ResourceParams, ResourceSpec, ResourceType, RuntimeSpec,
    SecretParams, WorkloadSpec,
};
use lattice_common::template::TemplateString;
use tracing::info;

use super::super::helpers::{
    apply_cedar_policies_batch, client_from_kubeconfig, create_with_retry, delete_namespace,
    ensure_fresh_namespace, run_kubectl, setup_regcreds_infrastructure, wait_for_condition,
    CedarPolicySpec, DEFAULT_TIMEOUT, REGCREDS_PROVIDER, REGCREDS_REMOTE_KEY,
};
use super::super::mesh_fixtures::{
    curl_container, inbound_allow, nginx_container, outbound_dep, postgres_container, postgres_port,
};
use super::super::mesh_helpers::{
    parse_traffic_result, retry_verification, wait_for_services_ready, TestTarget,
};

const NAMESPACE: &str = "webapp-postgres-test";

// =============================================================================
// Service Construction
// =============================================================================

/// Build the postgres LatticeService with port 5432 and inbound from app-server.
fn build_postgres_service() -> LatticeService {
    let container = postgres_container("webapp", "appuser", "testpass123");
    let mut containers = BTreeMap::new();
    containers.insert("main".to_string(), container);

    let mut resources: BTreeMap<String, ResourceSpec> = BTreeMap::new();
    let (k, v) = inbound_allow("app-server");
    resources.insert(k, v);
    resources.insert(
        "ghcr-creds".to_string(),
        ResourceSpec {
            type_: ResourceType::Secret,
            id: Some(REGCREDS_REMOTE_KEY.to_string()),
            params: ResourceParams::Secret(SecretParams {
                provider: REGCREDS_PROVIDER.to_string(),
                refresh_interval: Some("1h".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    let mut labels = BTreeMap::new();
    labels.insert("lattice.dev/environment".to_string(), NAMESPACE.to_string());

    LatticeService {
        metadata: ObjectMeta {
            name: Some("postgres".to_string()),
            namespace: Some(NAMESPACE.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: LatticeServiceSpec {
            workload: WorkloadSpec {
                containers,
                resources,
                service: Some(postgres_port()),
            },
            runtime: RuntimeSpec {
                image_pull_secrets: vec!["ghcr-creds".to_string()],
                ..Default::default()
            },
            ..Default::default()
        },
        status: None,
    }
}

/// Build the app-server: nginx serving HTTP on port 8080 with DB env vars,
/// outbound to postgres, inbound from nginx-frontend.
fn build_app_server() -> LatticeService {
    let mut container = nginx_container();
    container
        .variables
        .insert("DB_HOST".to_string(), TemplateString::new("postgres"));
    container
        .variables
        .insert("DB_PORT".to_string(), TemplateString::new("5432"));

    let mut resources: BTreeMap<String, ResourceSpec> = BTreeMap::new();
    let (k, v) = outbound_dep("postgres");
    resources.insert(k, v);
    let (k, v) = inbound_allow("nginx-frontend");
    resources.insert(k, v);

    super::super::mesh_fixtures::build_lattice_service(
        "app-server",
        NAMESPACE,
        resources,
        true,
        container,
    )
}

/// Build nginx-frontend: traffic generator with outbound to app-server and postgres
/// (postgres outbound to test that it's blocked without bilateral agreement).
fn build_nginx_frontend() -> LatticeService {
    use super::super::mesh_helpers::generate_test_script;

    let targets = vec![
        TestTarget::internal("app-server", NAMESPACE, true, "frontend->app allowed"),
        TestTarget {
            url: format!("http://postgres.{}.svc.cluster.local:5432/", NAMESPACE),
            expected_allowed: false,
            success_msg: "postgres: ALLOWED (UNEXPECTED - frontend->db blocked)".to_string(),
            fail_msg: "postgres: BLOCKED (frontend->db blocked)".to_string(),
        },
    ];

    let container = curl_container(generate_test_script("nginx-frontend", targets));

    let mut resources: BTreeMap<String, ResourceSpec> = BTreeMap::new();
    let (k, v) = outbound_dep("app-server");
    resources.insert(k, v);
    let (k, v) = outbound_dep("postgres");
    resources.insert(k, v);

    super::super::mesh_fixtures::build_lattice_service(
        "nginx-frontend",
        NAMESPACE,
        resources,
        false,
        container,
    )
}

// =============================================================================
// Deploy & Verify
// =============================================================================

async fn deploy_services(kubeconfig: &str) -> Result<(), String> {
    info!("[WebApp+PG] Deploying 3-service web app stack...");

    ensure_fresh_namespace(kubeconfig, NAMESPACE).await?;
    setup_regcreds_infrastructure(kubeconfig).await?;

    // Cedar: permit postgres to run as root with capabilities needed by its entrypoint
    // (chown data dir, gosu/su-exec to drop privileges)
    apply_cedar_policies_batch(
        kubeconfig,
        vec![CedarPolicySpec {
            name: format!("permit-postgres-security-{}", NAMESPACE),
            test_label: "webapp-pg".to_string(),
            priority: 50,
            cedar_text: format!(
                r#"permit(
  principal == Lattice::Service::"{ns}/postgres",
  action == Lattice::Action::"OverrideSecurity",
  resource
) when {{
  resource == Lattice::SecurityOverride::"runAsRoot" ||
  resource == Lattice::SecurityOverride::"capability:CHOWN" ||
  resource == Lattice::SecurityOverride::"capability:DAC_OVERRIDE" ||
  resource == Lattice::SecurityOverride::"capability:FOWNER" ||
  resource == Lattice::SecurityOverride::"capability:SETUID" ||
  resource == Lattice::SecurityOverride::"capability:SETGID"
}};"#,
                ns = NAMESPACE,
            ),
        }],
        5,
    )
    .await?;

    // Label namespace for Istio ambient mesh
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "label",
        "namespace",
        NAMESPACE,
        "istio.io/dataplane-mode=ambient",
        "--overwrite",
    ])
    .await?;

    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, NAMESPACE);

    let services = [
        build_postgres_service(),
        build_app_server(),
        build_nginx_frontend(),
    ];
    let futs: Vec<_> = services
        .iter()
        .map(|svc| {
            let name = svc.metadata.name.as_deref().unwrap_or("unknown");
            info!("[WebApp+PG] Deploying {}...", name);
            create_with_retry(&api, svc, name)
        })
        .collect();
    try_join_all(futs).await?;

    Ok(())
}

async fn verify_postgres_ready(kubeconfig: &str) -> Result<(), String> {
    info!("[WebApp+PG] Verifying postgres responds to pg_isready...");

    wait_for_condition(
        "postgres pg_isready",
        DEFAULT_TIMEOUT,
        Duration::from_secs(5),
        || async move {
            let result = run_kubectl(&[
                "--kubeconfig",
                kubeconfig,
                "exec",
                "-n",
                NAMESPACE,
                "deploy/postgres",
                "--",
                "pg_isready",
                "-U",
                "appuser",
            ])
            .await;

            match result {
                Ok(output) => {
                    let ready = output.contains("accepting connections");
                    if ready {
                        info!("[WebApp+PG] postgres: pg_isready OK");
                    }
                    Ok(ready)
                }
                Err(_) => Ok(false),
            }
        },
    )
    .await
}

async fn verify_env_vars(kubeconfig: &str) -> Result<(), String> {
    info!("[WebApp+PG] Verifying env vars on app-server...");

    let futs: Vec<_> = [("DB_HOST", "postgres"), ("DB_PORT", "5432")]
        .iter()
        .map(|(var, expected)| async move {
            wait_for_condition(
                &format!("app-server env {}={}", var, expected),
                DEFAULT_TIMEOUT,
                Duration::from_secs(5),
                || async move {
                    let result = run_kubectl(&[
                        "--kubeconfig",
                        kubeconfig,
                        "exec",
                        "-n",
                        NAMESPACE,
                        "deploy/app-server",
                        "--",
                        "printenv",
                        var,
                    ])
                    .await;

                    match result {
                        Ok(val) => {
                            let matches = val.trim() == *expected;
                            if matches {
                                info!("[WebApp+PG] app-server: {}={}", var, expected);
                            }
                            Ok(matches)
                        }
                        Err(_) => Ok(false),
                    }
                },
            )
            .await
        })
        .collect();
    try_join_all(futs).await?;

    Ok(())
}

async fn verify_traffic_logs(kubeconfig: &str) -> Result<(), String> {
    info!("[WebApp+PG] Verifying traffic patterns from logs...");

    let generators: &[(&str, &[(&str, bool)])] = &[(
        "nginx-frontend",
        &[("app-server", true), ("postgres", false)],
    )];

    let mut failures: Vec<String> = Vec::new();
    let mut total = 0;

    for (generator, expectations) in generators {
        let logs = run_kubectl(&[
            "--kubeconfig",
            kubeconfig,
            "logs",
            "-n",
            NAMESPACE,
            "-l",
            &format!("{}={}", lattice_common::LABEL_NAME, generator),
            "--tail",
            "200",
        ])
        .await?;

        for (target, expected_allowed) in *expectations {
            total += 1;
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

            if actual_str != expected_str {
                failures.push(format!(
                    "{}->{}: got {}, expected {}",
                    generator, target, actual_str, expected_str
                ));
            } else {
                info!(
                    "[WebApp+PG]   {} -> {}: {} (OK)",
                    generator, target, actual_str
                );
            }
        }
    }

    if !failures.is_empty() {
        return Err(format!(
            "[WebApp+PG] {} of {} checks failed: {}",
            failures.len(),
            total,
            failures.join("; ")
        ));
    }

    info!("[WebApp+PG] All {} traffic checks passed!", total);
    Ok(())
}

// =============================================================================
// Public API
// =============================================================================

pub async fn run_webapp_postgres_tests(kubeconfig: &str) -> Result<(), String> {
    info!("\n========================================");
    info!("Web App + PostgreSQL Integration Test");
    info!("========================================\n");

    deploy_services(kubeconfig).await?;
    wait_for_services_ready(kubeconfig, NAMESPACE, 3).await?;
    verify_postgres_ready(kubeconfig).await?;
    verify_env_vars(kubeconfig).await?;

    let kc = kubeconfig.to_string();
    retry_verification("WebApp+PG", || verify_traffic_logs(&kc)).await?;

    info!("\n========================================");
    info!("Web App + PostgreSQL: PASSED");
    info!("========================================\n");

    delete_namespace(kubeconfig, NAMESPACE).await;
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_webapp_postgres_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_webapp_postgres_tests(&resolved.kubeconfig)
        .await
        .unwrap();
}
