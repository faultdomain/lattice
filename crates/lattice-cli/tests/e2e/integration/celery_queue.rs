//! Celery Task Queue integration test (5 services)
//!
//! Deploys a Celery-style task queue architecture:
//!   web-api -> redis <- worker-default
//!   web-api -> flower -> redis <- worker-priority
//!
//! Verifies:
//! - Third-party container (redis:alpine) runs as LatticeService
//! - Redis responds to `redis-cli ping` with PONG
//! - Multiple services depending on the same backend (4 -> redis)
//! - Asymmetric dependencies (workers can only access redis, not each other)
//! - Env var injection (CELERY_BROKER_URL, WORKER_QUEUES)
//! - Bilateral mesh agreements enforce correct access patterns
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_celery_queue_standalone -- --ignored --nocapture
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
    client_from_kubeconfig, create_with_retry, delete_namespace, ensure_fresh_namespace,
    run_kubectl, setup_regcreds_infrastructure, wait_for_condition, DEFAULT_TIMEOUT,
    REGCREDS_PROVIDER, REGCREDS_REMOTE_KEY,
};
use super::super::mesh_fixtures::{
    build_lattice_service, curl_container, inbound_allow, outbound_dep, redis_container, redis_port,
};
use super::super::mesh_helpers::{
    parse_traffic_result, retry_verification, wait_for_services_ready, DiagnosticContext, TestTarget,
};

const NAMESPACE: &str = "celery-queue-test";

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

// =============================================================================
// Service Construction
// =============================================================================

/// Redis: inbound from web-api, worker-default, worker-priority, flower.
fn build_redis_service() -> LatticeService {
    let container = redis_container();
    let mut containers = BTreeMap::new();
    containers.insert("main".to_string(), container);

    let mut resources: BTreeMap<String, ResourceSpec> = BTreeMap::new();
    for caller in ["web-api", "worker-default", "worker-priority", "flower"] {
        let (k, v) = inbound_allow(caller);
        resources.insert(k, v);
    }
    let (k, v) = ghcr_creds();
    resources.insert(k, v);

    let mut labels = BTreeMap::new();
    labels.insert("lattice.dev/environment".to_string(), NAMESPACE.to_string());

    LatticeService {
        metadata: ObjectMeta {
            name: Some("redis".to_string()),
            namespace: Some(NAMESPACE.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: LatticeServiceSpec {
            workload: WorkloadSpec {
                containers,
                resources,
                service: Some(redis_port()),
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

/// web-api: traffic generator, outbound to redis and flower.
///
/// Tests outbound to flower (ALLOWED, HTTP) and workers (BLOCKED).
/// Redis connectivity is verified separately via redis-cli ping (non-HTTP).
fn build_web_api() -> LatticeService {
    use super::super::mesh_helpers::generate_test_script;

    let targets = vec![
        TestTarget::internal("flower", NAMESPACE, true, "web-api->flower allowed"),
        TestTarget::internal(
            "worker-default",
            NAMESPACE,
            false,
            "web-api->worker blocked",
        ),
        TestTarget::internal(
            "worker-priority",
            NAMESPACE,
            false,
            "web-api->worker blocked",
        ),
    ];

    let mut container = curl_container(generate_test_script("web-api", targets));
    container.variables.insert(
        "CELERY_BROKER_URL".to_string(),
        TemplateString::new("redis://redis:6379/0"),
    );

    let mut resources: BTreeMap<String, ResourceSpec> = BTreeMap::new();
    let (k, v) = outbound_dep("redis");
    resources.insert(k, v);
    let (k, v) = outbound_dep("flower");
    resources.insert(k, v);
    let (k, v) = outbound_dep("worker-default");
    resources.insert(k, v);
    let (k, v) = outbound_dep("worker-priority");
    resources.insert(k, v);

    build_lattice_service("web-api", NAMESPACE, resources, true, container)
}

/// flower: monitoring UI, outbound to redis, inbound from web-api.
fn build_flower() -> LatticeService {
    use super::super::mesh_fixtures::nginx_container;

    let container = nginx_container();

    let mut resources: BTreeMap<String, ResourceSpec> = BTreeMap::new();
    let (k, v) = outbound_dep("redis");
    resources.insert(k, v);
    let (k, v) = inbound_allow("web-api");
    resources.insert(k, v);

    build_lattice_service("flower", NAMESPACE, resources, true, container)
}

/// Worker with outbound to redis only. Name and queue configurable.
///
/// Tests that workers are isolated from each other, from web-api, and from flower.
/// Redis connectivity is verified separately via redis-cli ping (non-HTTP).
fn build_worker(name: &str, queue: &str) -> LatticeService {
    use super::super::mesh_helpers::generate_test_script;

    let peer = if name == "worker-default" {
        "worker-priority"
    } else {
        "worker-default"
    };

    let targets = vec![
        TestTarget::internal(
            "web-api",
            NAMESPACE,
            false,
            &format!("{}->web-api blocked", name),
        ),
        TestTarget::internal(
            "flower",
            NAMESPACE,
            false,
            &format!("{}->flower blocked", name),
        ),
        TestTarget::internal(peer, NAMESPACE, false, &format!("{}->peer blocked", name)),
    ];

    let mut container = curl_container(generate_test_script(name, targets));
    container.variables.insert(
        "CELERY_BROKER_URL".to_string(),
        TemplateString::new("redis://redis:6379/0"),
    );
    container
        .variables
        .insert("WORKER_QUEUES".to_string(), TemplateString::new(queue));

    let mut resources: BTreeMap<String, ResourceSpec> = BTreeMap::new();
    let (k, v) = outbound_dep("redis");
    resources.insert(k, v);
    let (k, v) = outbound_dep("web-api");
    resources.insert(k, v);
    let (k, v) = outbound_dep("flower");
    resources.insert(k, v);
    let (k, v) = outbound_dep(peer);
    resources.insert(k, v);

    build_lattice_service(name, NAMESPACE, resources, false, container)
}

// =============================================================================
// Deploy & Verify
// =============================================================================

async fn deploy_services(kubeconfig: &str) -> Result<(), String> {
    info!("[Celery] Deploying 5-service task queue stack...");

    ensure_fresh_namespace(kubeconfig, NAMESPACE).await?;
    setup_regcreds_infrastructure(kubeconfig).await?;

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
        build_redis_service(),
        build_web_api(),
        build_flower(),
        build_worker("worker-default", "default"),
        build_worker("worker-priority", "priority,default"),
    ];

    let futs: Vec<_> = services
        .iter()
        .map(|svc| {
            let name = svc.metadata.name.as_deref().unwrap_or("unknown");
            info!("[Celery] Deploying {}...", name);
            create_with_retry(&api, svc, name)
        })
        .collect();
    try_join_all(futs).await?;

    Ok(())
}

async fn verify_redis_ready(kubeconfig: &str) -> Result<(), String> {
    info!("[Celery] Verifying redis responds to PING...");

    wait_for_condition(
        "redis PING/PONG",
        DEFAULT_TIMEOUT,
        Duration::from_secs(5),
        || async move {
            let result = run_kubectl(&[
                "--kubeconfig",
                kubeconfig,
                "exec",
                "-n",
                NAMESPACE,
                "deploy/redis",
                "--",
                "redis-cli",
                "ping",
            ])
            .await;

            match result {
                Ok(output) => {
                    let ready = output.trim() == "PONG";
                    if ready {
                        info!("[Celery] redis: PONG received");
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
    info!("[Celery] Verifying env vars...");

    tokio::try_join!(
        async {
            wait_for_condition(
                "web-api CELERY_BROKER_URL",
                DEFAULT_TIMEOUT,
                Duration::from_secs(5),
                || async move {
                    let result = run_kubectl(&[
                        "--kubeconfig",
                        kubeconfig,
                        "exec",
                        "-n",
                        NAMESPACE,
                        "deploy/web-api",
                        "--",
                        "printenv",
                        "CELERY_BROKER_URL",
                    ])
                    .await;
                    match result {
                        Ok(val) => Ok(val.trim() == "redis://redis:6379/0"),
                        Err(_) => Ok(false),
                    }
                },
            )
            .await?;
            info!("[Celery] web-api: CELERY_BROKER_URL=redis://redis:6379/0");
            Ok::<_, String>(())
        },
        async {
            wait_for_condition(
                "worker-default WORKER_QUEUES",
                DEFAULT_TIMEOUT,
                Duration::from_secs(5),
                || async move {
                    let result = run_kubectl(&[
                        "--kubeconfig",
                        kubeconfig,
                        "exec",
                        "-n",
                        NAMESPACE,
                        "deploy/worker-default",
                        "--",
                        "printenv",
                        "WORKER_QUEUES",
                    ])
                    .await;
                    match result {
                        Ok(val) => Ok(val.trim() == "default"),
                        Err(_) => Ok(false),
                    }
                },
            )
            .await?;
            info!("[Celery] worker-default: WORKER_QUEUES=default");
            Ok::<_, String>(())
        },
        async {
            wait_for_condition(
                "worker-priority WORKER_QUEUES",
                DEFAULT_TIMEOUT,
                Duration::from_secs(5),
                || async move {
                    let result = run_kubectl(&[
                        "--kubeconfig",
                        kubeconfig,
                        "exec",
                        "-n",
                        NAMESPACE,
                        "deploy/worker-priority",
                        "--",
                        "printenv",
                        "WORKER_QUEUES",
                    ])
                    .await;
                    match result {
                        Ok(val) => Ok(val.trim() == "priority,default"),
                        Err(_) => Ok(false),
                    }
                },
            )
            .await?;
            info!("[Celery] worker-priority: WORKER_QUEUES=priority,default");
            Ok::<_, String>(())
        },
    )?;

    Ok(())
}

async fn verify_traffic_logs(kubeconfig: &str) -> Result<(), String> {
    info!("[Celery] Verifying traffic patterns from logs...");

    let generators: &[(&str, &[(&str, bool)])] = &[
        (
            "web-api",
            &[
                ("flower", true),
                ("worker-default", false),
                ("worker-priority", false),
            ],
        ),
        (
            "worker-default",
            &[
                ("web-api", false),
                ("flower", false),
                ("worker-priority", false),
            ],
        ),
        (
            "worker-priority",
            &[
                ("web-api", false),
                ("flower", false),
                ("worker-default", false),
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
                    "[Celery]   {} -> {}: {} (OK)",
                    generator, target, actual_str
                );
            }
        }
    }

    if !failures.is_empty() {
        return Err(format!(
            "[Celery] {} of {} checks failed: {}",
            failures.len(),
            total,
            failures.join("; ")
        ));
    }

    info!("[Celery] All {} traffic checks passed!", total);
    Ok(())
}

// =============================================================================
// Public API
// =============================================================================

pub async fn run_celery_queue_tests(kubeconfig: &str) -> Result<(), String> {
    info!("\n========================================");
    info!("Celery Task Queue Integration Test");
    info!("========================================\n");

    deploy_services(kubeconfig).await?;
    wait_for_services_ready(kubeconfig, NAMESPACE, 5).await?;
    verify_redis_ready(kubeconfig).await?;
    verify_env_vars(kubeconfig).await?;

    let kc = kubeconfig.to_string();
    let svc_names: Vec<String> = Vec::new();
    let diag = DiagnosticContext {
        kubeconfig,
        namespace: NAMESPACE,
        service_names: &svc_names,
    };
    retry_verification("Celery", Some(&diag), || verify_traffic_logs(&kc)).await?;

    info!("\n========================================");
    info!("Celery Task Queue: PASSED");
    info!("========================================\n");

    delete_namespace(kubeconfig, NAMESPACE).await;
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_celery_queue_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_celery_queue_tests(&resolved.kubeconfig).await.unwrap();
}
