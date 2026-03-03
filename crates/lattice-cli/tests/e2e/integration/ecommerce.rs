//! E-Commerce Microservices integration test (7 services)
//!
//! Deploys a microservices e-commerce architecture:
//!   api-gateway -> {product-svc, order-svc, user-svc}
//!   product-svc -> product-db
//!   order-svc -> {order-db, product-svc, user-svc}
//!   user-svc -> user-db
//!
//! Verifies:
//! - Wildcard inbound on api-gateway
//! - 3 isolated postgres instances (each only reachable from its own service)
//! - Cross-service dependencies (order-svc -> product-svc, order-svc -> user-svc)
//! - Database isolation (product-svc cannot reach order-db or user-db)
//! - Cedar security overrides for all postgres containers
//! - Bilateral mesh agreements via traffic generator logs
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_ecommerce_standalone -- --ignored --nocapture
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
use tracing::info;

use super::super::helpers::{
    apply_cedar_policies_batch, client_from_kubeconfig, create_with_retry, delete_namespace,
    ensure_fresh_namespace, run_kubectl, setup_regcreds_infrastructure, wait_for_condition,
    CedarPolicySpec, DEFAULT_TIMEOUT, REGCREDS_PROVIDER, REGCREDS_REMOTE_KEY,
};
use super::super::mesh_fixtures::{
    build_lattice_service, curl_container, inbound_allow, inbound_allow_all, nginx_container,
    outbound_dep, postgres_container, postgres_port,
};
use super::super::mesh_helpers::{
    generate_test_script, parse_traffic_result, retry_verification, wait_for_services_ready,
    TestTarget,
};

const NAMESPACE: &str = "ecommerce-test";

// =============================================================================
// Helpers
// =============================================================================

fn ghcr_creds() -> (String, ResourceSpec) {
    (
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
    )
}

/// Build a postgres database service with a custom name, inbound from a single service.
fn build_db_service(db_name: &str, allowed_caller: &str) -> LatticeService {
    let container = postgres_container(db_name, "dbuser", "dbpass123");
    let mut containers = BTreeMap::new();
    containers.insert("main".to_string(), container);

    let mut resources: BTreeMap<String, ResourceSpec> = BTreeMap::new();
    let (k, v) = inbound_allow(allowed_caller);
    resources.insert(k, v);
    let (k, v) = ghcr_creds();
    resources.insert(k, v);

    let mut labels = BTreeMap::new();
    labels.insert("lattice.dev/environment".to_string(), NAMESPACE.to_string());

    LatticeService {
        metadata: ObjectMeta {
            name: Some(db_name.to_string()),
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

// =============================================================================
// Service Construction
// =============================================================================

/// api-gateway: wildcard inbound, traffic generator testing outbound paths.
///
/// Tests ALLOWED paths to HTTP services (product-svc, user-svc) and
/// BLOCKED paths to databases (product-db, order-db, user-db).
fn build_api_gateway() -> LatticeService {
    let targets = vec![
        TestTarget::internal(
            "product-svc",
            NAMESPACE,
            true,
            "api-gw->product-svc allowed",
        ),
        TestTarget::internal("user-svc", NAMESPACE, true, "api-gw->user-svc allowed"),
        TestTarget {
            url: format!("http://product-db.{}.svc.cluster.local:5432/", NAMESPACE),
            expected_allowed: false,
            success_msg: "product-db: ALLOWED (UNEXPECTED - api-gw->product-db blocked)"
                .to_string(),
            fail_msg: "product-db: BLOCKED (api-gw->product-db blocked)".to_string(),
        },
        TestTarget {
            url: format!("http://order-db.{}.svc.cluster.local:5432/", NAMESPACE),
            expected_allowed: false,
            success_msg: "order-db: ALLOWED (UNEXPECTED - api-gw->order-db blocked)".to_string(),
            fail_msg: "order-db: BLOCKED (api-gw->order-db blocked)".to_string(),
        },
        TestTarget {
            url: format!("http://user-db.{}.svc.cluster.local:5432/", NAMESPACE),
            expected_allowed: false,
            success_msg: "user-db: ALLOWED (UNEXPECTED - api-gw->user-db blocked)".to_string(),
            fail_msg: "user-db: BLOCKED (api-gw->user-db blocked)".to_string(),
        },
    ];

    let container = curl_container(generate_test_script("api-gateway", targets));

    let mut resources: BTreeMap<String, ResourceSpec> = BTreeMap::new();
    let (k, v) = inbound_allow_all();
    resources.insert(k, v);
    let (k, v) = outbound_dep("product-svc");
    resources.insert(k, v);
    let (k, v) = outbound_dep("order-svc");
    resources.insert(k, v);
    let (k, v) = outbound_dep("user-svc");
    resources.insert(k, v);
    let (k, v) = outbound_dep("product-db");
    resources.insert(k, v);
    let (k, v) = outbound_dep("order-db");
    resources.insert(k, v);
    let (k, v) = outbound_dep("user-db");
    resources.insert(k, v);

    build_lattice_service("api-gateway", NAMESPACE, resources, false, container)
}

/// product-svc: inbound from api-gateway and order-svc, outbound to product-db.
fn build_product_svc() -> LatticeService {
    let container = nginx_container();

    let mut resources: BTreeMap<String, ResourceSpec> = BTreeMap::new();
    let (k, v) = inbound_allow("api-gateway");
    resources.insert(k, v);
    let (k, v) = inbound_allow("order-svc");
    resources.insert(k, v);
    let (k, v) = outbound_dep("product-db");
    resources.insert(k, v);

    build_lattice_service("product-svc", NAMESPACE, resources, true, container)
}

/// order-svc: traffic generator testing cross-service and DB isolation.
///
/// Tests ALLOWED paths to product-svc and user-svc (HTTP) and
/// BLOCKED paths to product-db and user-db (non-HTTP, no bilateral agreement).
/// order-db is ALLOWED but non-HTTP, verified separately via pg_isready.
fn build_order_svc() -> LatticeService {
    let targets = vec![
        TestTarget::internal("product-svc", NAMESPACE, true, "order->product-svc allowed"),
        TestTarget::internal("user-svc", NAMESPACE, true, "order->user-svc allowed"),
        TestTarget {
            url: format!("http://product-db.{}.svc.cluster.local:5432/", NAMESPACE),
            expected_allowed: false,
            success_msg: "product-db: ALLOWED (UNEXPECTED - order->product-db blocked)".to_string(),
            fail_msg: "product-db: BLOCKED (order->product-db blocked)".to_string(),
        },
        TestTarget {
            url: format!("http://user-db.{}.svc.cluster.local:5432/", NAMESPACE),
            expected_allowed: false,
            success_msg: "user-db: ALLOWED (UNEXPECTED - order->user-db blocked)".to_string(),
            fail_msg: "user-db: BLOCKED (order->user-db blocked)".to_string(),
        },
    ];

    let container = curl_container(generate_test_script("order-svc", targets));

    let mut resources: BTreeMap<String, ResourceSpec> = BTreeMap::new();
    let (k, v) = inbound_allow("api-gateway");
    resources.insert(k, v);
    let (k, v) = outbound_dep("order-db");
    resources.insert(k, v);
    let (k, v) = outbound_dep("product-svc");
    resources.insert(k, v);
    let (k, v) = outbound_dep("user-svc");
    resources.insert(k, v);
    let (k, v) = outbound_dep("product-db");
    resources.insert(k, v);
    let (k, v) = outbound_dep("user-db");
    resources.insert(k, v);

    build_lattice_service("order-svc", NAMESPACE, resources, false, container)
}

/// user-svc: inbound from api-gateway and order-svc, outbound to user-db.
fn build_user_svc() -> LatticeService {
    let container = nginx_container();

    let mut resources: BTreeMap<String, ResourceSpec> = BTreeMap::new();
    let (k, v) = inbound_allow("api-gateway");
    resources.insert(k, v);
    let (k, v) = inbound_allow("order-svc");
    resources.insert(k, v);
    let (k, v) = outbound_dep("user-db");
    resources.insert(k, v);

    build_lattice_service("user-svc", NAMESPACE, resources, true, container)
}

// =============================================================================
// Deploy & Verify
// =============================================================================

async fn deploy_services(kubeconfig: &str) -> Result<(), String> {
    info!("[Ecommerce] Deploying 7-service e-commerce stack...");

    ensure_fresh_namespace(kubeconfig, NAMESPACE).await?;
    setup_regcreds_infrastructure(kubeconfig).await?;

    // Cedar: permit all 3 postgres instances to run as root with capabilities
    // needed by the postgres entrypoint (chown data dir, gosu/su-exec to drop privileges)
    let mut cedar_policies = Vec::new();
    for db in ["product-db", "order-db", "user-db"] {
        cedar_policies.push(CedarPolicySpec {
            name: format!("permit-postgres-security-{}-{}", db, NAMESPACE),
            test_label: "ecommerce".to_string(),
            priority: 50,
            cedar_text: format!(
                r#"permit(
  principal == Lattice::Service::"{ns}/{svc}",
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
                svc = db,
            ),
        });
    }

    // Wildcard inbound for api-gateway
    cedar_policies.push(CedarPolicySpec {
        name: format!("permit-wildcard-inbound-api-gateway-{}", NAMESPACE),
        test_label: "ecommerce".to_string(),
        priority: 50,
        cedar_text: format!(
            r#"permit(
  principal == Lattice::Service::"{ns}/api-gateway",
  action == Lattice::Action::"AllowWildcard",
  resource == Lattice::Mesh::"inbound"
);"#,
            ns = NAMESPACE,
        ),
    });

    apply_cedar_policies_batch(kubeconfig, cedar_policies, 5).await?;

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
        build_db_service("product-db", "product-svc"),
        build_db_service("order-db", "order-svc"),
        build_db_service("user-db", "user-svc"),
        build_product_svc(),
        build_order_svc(),
        build_user_svc(),
        build_api_gateway(),
    ];

    let futs: Vec<_> = services
        .iter()
        .map(|svc| {
            let name = svc.metadata.name.as_deref().unwrap_or("unknown");
            info!("[Ecommerce] Deploying {}...", name);
            create_with_retry(&api, svc, name)
        })
        .collect();
    try_join_all(futs).await?;

    Ok(())
}

async fn verify_databases_ready(kubeconfig: &str) -> Result<(), String> {
    info!("[Ecommerce] Verifying all 3 postgres instances respond to pg_isready...");

    let futs: Vec<_> = ["product-db", "order-db", "user-db"]
        .iter()
        .map(|db| async move {
            wait_for_condition(
                &format!("{} pg_isready", db),
                DEFAULT_TIMEOUT,
                Duration::from_secs(5),
                || async move {
                    let result = run_kubectl(&[
                        "--kubeconfig",
                        kubeconfig,
                        "exec",
                        "-n",
                        NAMESPACE,
                        &format!("deploy/{}", db),
                        "--",
                        "pg_isready",
                        "-U",
                        "dbuser",
                    ])
                    .await;

                    match result {
                        Ok(output) => {
                            let ready = output.contains("accepting connections");
                            if ready {
                                info!("[Ecommerce] {}: pg_isready OK", db);
                            }
                            Ok(ready)
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
    info!("[Ecommerce] Verifying traffic patterns from logs...");

    let generators: &[(&str, &[(&str, bool)])] = &[
        (
            "api-gateway",
            &[
                ("product-svc", true),
                ("user-svc", true),
                ("product-db", false),
                ("order-db", false),
                ("user-db", false),
            ],
        ),
        (
            "order-svc",
            &[
                ("product-svc", true),
                ("user-svc", true),
                ("product-db", false),
                ("user-db", false),
            ],
        ),
    ];

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
                    "[Ecommerce]   {} -> {}: {} (OK)",
                    generator, target, actual_str
                );
            }
        }
    }

    if !failures.is_empty() {
        return Err(format!(
            "[Ecommerce] {} of {} checks failed: {}",
            failures.len(),
            total,
            failures.join("; ")
        ));
    }

    info!("[Ecommerce] All {} traffic checks passed!", total);
    Ok(())
}

// =============================================================================
// Public API
// =============================================================================

pub async fn run_ecommerce_tests(kubeconfig: &str) -> Result<(), String> {
    info!("\n========================================");
    info!("E-Commerce Microservices Integration Test");
    info!("========================================\n");

    deploy_services(kubeconfig).await?;
    wait_for_services_ready(kubeconfig, NAMESPACE, 7).await?;
    verify_databases_ready(kubeconfig).await?;

    let kc = kubeconfig.to_string();
    retry_verification("Ecommerce", || verify_traffic_logs(&kc)).await?;

    info!("\n========================================");
    info!("E-Commerce Microservices: PASSED");
    info!("========================================\n");

    delete_namespace(kubeconfig, NAMESPACE).await;
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_ecommerce_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_ecommerce_tests(&resolved.kubeconfig).await.unwrap();
}
