//! KEDA pod autoscaling integration tests
//!
//! Tests that verify KEDA ScaledObject creation and actual pod scale-up
//! for LatticeService resources with autoscaling configured.
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/workload-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_autoscaling_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::collections::BTreeMap;
use std::time::Duration;

use tracing::info;

use lattice_common::crd::{
    AutoscalingMetric, AutoscalingSpec, ContainerSpec, PortSpec, ResourceQuantity,
    ResourceRequirements, SecurityContext, ServicePortsSpec, VolumeMount,
};

use super::super::context::{InfraContext, TestSession};
use super::super::helpers::{
    delete_namespace, deploy_and_wait_for_phase, ensure_fresh_namespace, run_kubectl,
    service_pod_selector, setup_regcreds_infrastructure, wait_for_condition, BUSYBOX_IMAGE,
};
use super::super::mesh_fixtures::build_lattice_service;
use super::cedar::apply_e2e_default_policy;

// =============================================================================
// Constants
// =============================================================================

const AUTOSCALING_NAMESPACE: &str = "autoscaling-test";
const PROM_NAMESPACE: &str = "autoscaling-prom-test";
const CPU_BURNER_NAME: &str = "cpu-burner";
const METRICS_SERVER_NAME: &str = "metrics-server";
const CUSTOM_METRIC_NAME: &str = "test_scale_metric";

const SCALEDOBJECT_TIMEOUT: Duration = Duration::from_secs(120);
const SCALEUP_TIMEOUT: Duration = Duration::from_secs(300);
const PROM_SCALEUP_TIMEOUT: Duration = Duration::from_secs(420);
const DEPLOY_TIMEOUT: Duration = Duration::from_secs(300);
const POLL_INTERVAL: Duration = Duration::from_secs(10);

// =============================================================================
// Service Builder
// =============================================================================

/// Build a LatticeService that burns CPU to trigger KEDA autoscaling.
///
/// Uses busybox with an infinite loop (`while true; do :; done`) to consume
/// 100% of one CPU core. With a 10m CPU request and 20% target threshold,
/// KEDA will immediately detect massive utilization and scale up.
fn build_cpu_burner_service() -> lattice_common::crd::LatticeService {
    let container = ContainerSpec {
        image: BUSYBOX_IMAGE.to_string(),
        command: Some(vec!["/bin/sh".to_string()]),
        args: Some(vec!["-c".to_string(), "while true; do :; done".to_string()]),
        resources: Some(ResourceRequirements {
            requests: Some(ResourceQuantity {
                cpu: Some("10m".to_string()),
                memory: Some("32Mi".to_string()),
            }),
            limits: Some(ResourceQuantity {
                cpu: Some("1000m".to_string()),
                memory: Some("64Mi".to_string()),
            }),
        }),
        security: Some(SecurityContext {
            apparmor_profile: Some("Unconfined".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let resources = BTreeMap::new();
    let mut svc = build_lattice_service(
        CPU_BURNER_NAME,
        AUTOSCALING_NAMESPACE,
        resources,
        false,
        container,
    );

    svc.spec.replicas = 1;
    svc.spec.autoscaling = Some(AutoscalingSpec {
        max: 3,
        metrics: vec![AutoscalingMetric {
            metric: "cpu".to_string(),
            target: 20,
        }],
    });

    svc
}

/// Build a LatticeService that serves a static Prometheus metric to trigger
/// KEDA Prometheus-based autoscaling.
///
/// Uses busybox httpd to serve a `/metrics` endpoint returning a high-value
/// gauge. The service exposes a port named `metrics` (port 9090) which triggers
/// automatic ServiceMonitor generation by the compiler. VictoriaMetrics scrapes
/// this via the ServiceMonitor, and KEDA queries VictoriaMetrics to trigger scale-up.
fn build_metrics_server_service() -> lattice_common::crd::LatticeService {
    // busybox httpd serves static files — write metrics content then start httpd
    let script = format!(
        concat!(
            "mkdir -p /tmp/www && ",
            "printf '# HELP {m} A test metric for autoscaling\\n",
            "# TYPE {m} gauge\\n",
            "{m} 100\\n' > /tmp/www/metrics && ",
            "httpd -f -p 9090 -h /tmp/www"
        ),
        m = CUSTOM_METRIC_NAME,
    );

    let mut volumes = BTreeMap::new();
    volumes.insert(
        "/tmp".to_string(),
        VolumeMount {
            source: None,
            path: None,
            read_only: None,
            medium: None,
            size_limit: None,
        },
    );

    let container = ContainerSpec {
        image: BUSYBOX_IMAGE.to_string(),
        command: Some(vec!["/bin/sh".to_string()]),
        args: Some(vec!["-c".to_string(), script]),
        resources: Some(ResourceRequirements {
            requests: Some(ResourceQuantity {
                cpu: Some("10m".to_string()),
                memory: Some("32Mi".to_string()),
            }),
            limits: Some(ResourceQuantity {
                cpu: Some("100m".to_string()),
                memory: Some("64Mi".to_string()),
            }),
        }),
        volumes,
        security: Some(SecurityContext {
            apparmor_profile: Some("Unconfined".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let resources = BTreeMap::new();

    // Build with a metrics port so the compiler generates a ServiceMonitor
    let mut containers = BTreeMap::new();
    containers.insert("main".to_string(), container);

    let mut ports = BTreeMap::new();
    ports.insert(
        "metrics".to_string(),
        PortSpec {
            port: 9090,
            target_port: None,
            protocol: None,
        },
    );

    let mut svc = build_lattice_service(
        METRICS_SERVER_NAME,
        PROM_NAMESPACE,
        resources,
        false, // we set the port manually below
        ContainerSpec {
            image: BUSYBOX_IMAGE.to_string(),
            ..Default::default()
        },
    );

    // Override the workload with our actual container and metrics port
    svc.spec.workload.containers = containers;
    svc.spec.workload.service = Some(ServicePortsSpec { ports });

    svc.spec.replicas = 1;
    svc.spec.autoscaling = Some(AutoscalingSpec {
        max: 3,
        metrics: vec![AutoscalingMetric {
            metric: CUSTOM_METRIC_NAME.to_string(),
            target: 10,
        }],
    });

    svc
}

// =============================================================================
// Test Logic
// =============================================================================

/// Run all KEDA autoscaling tests against an existing workload cluster.
///
/// Runs the CPU-based test and the Prometheus-based test sequentially.
pub async fn run_autoscaling_tests(ctx: &InfraContext) -> Result<(), String> {
    run_cpu_autoscaling_test(ctx).await?;
    run_prometheus_autoscaling_test(ctx).await?;
    info!("[Integration/Autoscaling] All autoscaling tests passed!");
    Ok(())
}

/// CPU-based autoscaling test:
/// 1. Deploys a CPU-burning LatticeService with autoscaling configured
/// 2. Verifies the ScaledObject is created with correct spec
/// 3. Waits for KEDA to scale pods beyond the initial replica count
async fn run_cpu_autoscaling_test(ctx: &InfraContext) -> Result<(), String> {
    let kubeconfig = ctx.require_workload()?;

    info!("[Integration/Autoscaling/CPU] Starting CPU autoscaling test...");

    ensure_fresh_namespace(kubeconfig, AUTOSCALING_NAMESPACE).await?;
    setup_regcreds_infrastructure(kubeconfig).await?;

    info!("[Integration/Autoscaling/CPU] Deploying cpu-burner service...");
    let service = build_cpu_burner_service();
    deploy_and_wait_for_phase(
        kubeconfig,
        AUTOSCALING_NAMESPACE,
        service,
        "Ready",
        None,
        DEPLOY_TIMEOUT,
    )
    .await?;

    info!("[Integration/Autoscaling/CPU] Verifying ScaledObject...");
    verify_scaled_object(
        kubeconfig,
        AUTOSCALING_NAMESPACE,
        CPU_BURNER_NAME,
        "1",
        "3",
        "cpu",
    )
    .await?;

    info!("[Integration/Autoscaling/CPU] Waiting for scale-up...");
    wait_for_scale_up(
        kubeconfig,
        AUTOSCALING_NAMESPACE,
        CPU_BURNER_NAME,
        SCALEUP_TIMEOUT,
    )
    .await?;

    info!("[Integration/Autoscaling/CPU] Cleaning up...");
    delete_namespace(kubeconfig, AUTOSCALING_NAMESPACE).await;

    info!("[Integration/Autoscaling/CPU] CPU autoscaling test passed!");
    Ok(())
}

/// Prometheus-based autoscaling test:
/// 1. Deploys an HTTP server exposing a custom Prometheus metric via /metrics
/// 2. Verifies the ScaledObject is created with a prometheus trigger
/// 3. Waits for VictoriaMetrics to scrape the metric and KEDA to scale up
async fn run_prometheus_autoscaling_test(ctx: &InfraContext) -> Result<(), String> {
    let kubeconfig = ctx.require_workload()?;

    info!("[Integration/Autoscaling/Prom] Starting Prometheus autoscaling test...");

    ensure_fresh_namespace(kubeconfig, PROM_NAMESPACE).await?;
    setup_regcreds_infrastructure(kubeconfig).await?;

    info!("[Integration/Autoscaling/Prom] Deploying metrics-server service...");
    let service = build_metrics_server_service();
    deploy_and_wait_for_phase(
        kubeconfig,
        PROM_NAMESPACE,
        service,
        "Ready",
        None,
        DEPLOY_TIMEOUT,
    )
    .await?;

    info!("[Integration/Autoscaling/Prom] Verifying ScaledObject...");
    verify_scaled_object(
        kubeconfig,
        PROM_NAMESPACE,
        METRICS_SERVER_NAME,
        "1",
        "3",
        "prometheus",
    )
    .await?;

    info!("[Integration/Autoscaling/Prom] Verifying ServiceMonitor exists...");
    verify_service_monitor(kubeconfig).await?;

    info!("[Integration/Autoscaling/Prom] Waiting for Prometheus-driven scale-up...");
    wait_for_scale_up(
        kubeconfig,
        PROM_NAMESPACE,
        METRICS_SERVER_NAME,
        PROM_SCALEUP_TIMEOUT,
    )
    .await?;

    info!("[Integration/Autoscaling/Prom] Cleaning up...");
    delete_namespace(kubeconfig, PROM_NAMESPACE).await;

    info!("[Integration/Autoscaling/Prom] Prometheus autoscaling test passed!");
    Ok(())
}

// =============================================================================
// Helpers
// =============================================================================

/// Verify the ScaledObject was created by the operator with correct fields.
async fn verify_scaled_object(
    kubeconfig: &str,
    namespace: &str,
    name: &str,
    expected_min: &str,
    expected_max: &str,
    expected_trigger: &str,
) -> Result<(), String> {
    let kc = kubeconfig.to_string();
    let ns = namespace.to_string();
    let svc_name = name.to_string();
    let exp_min = expected_min.to_string();
    let exp_max = expected_max.to_string();
    let exp_trigger = expected_trigger.to_string();

    wait_for_condition(
        &format!("ScaledObject to exist for {}", name),
        SCALEDOBJECT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            let ns = ns.clone();
            let svc_name = svc_name.clone();
            let exp_min = exp_min.clone();
            let exp_max = exp_max.clone();
            let exp_trigger = exp_trigger.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig", &kc,
                    "get", "scaledobject", &svc_name,
                    "-n", &ns,
                    "-o", "jsonpath={.apiVersion} {.spec.scaleTargetRef.name} {.spec.minReplicaCount} {.spec.maxReplicaCount} {.spec.triggers[0].type}",
                ]).await;

                match output {
                    Ok(raw) => {
                        let parts: Vec<&str> = raw.split_whitespace().collect();
                        if parts.len() < 5 {
                            info!("[Integration/Autoscaling] ScaledObject not yet available (got {} fields)", parts.len());
                            return Ok(false);
                        }

                        let api_version = parts[0];
                        let target_name = parts[1];
                        let min_replicas = parts[2];
                        let max_replicas = parts[3];
                        let trigger_type = parts[4];

                        info!(
                            "[Integration/Autoscaling] ScaledObject: apiVersion={}, target={}, min={}, max={}, trigger={}",
                            api_version, target_name, min_replicas, max_replicas, trigger_type
                        );

                        if api_version != "keda.sh/v1alpha1" {
                            return Err(format!("Expected apiVersion keda.sh/v1alpha1, got {}", api_version));
                        }
                        if target_name != svc_name {
                            return Err(format!("Expected scaleTargetRef.name {}, got {}", svc_name, target_name));
                        }
                        if min_replicas != exp_min {
                            return Err(format!("Expected minReplicaCount {}, got {}", exp_min, min_replicas));
                        }
                        if max_replicas != exp_max {
                            return Err(format!("Expected maxReplicaCount {}, got {}", exp_max, max_replicas));
                        }
                        if trigger_type != exp_trigger {
                            return Err(format!("Expected trigger type {}, got {}", exp_trigger, trigger_type));
                        }

                        Ok(true)
                    }
                    Err(_) => Ok(false),
                }
            }
        },
    ).await
}

/// Verify the ServiceMonitor was created for the metrics-server service.
async fn verify_service_monitor(kubeconfig: &str) -> Result<(), String> {
    let kc = kubeconfig.to_string();
    let monitor_name = format!("{}-monitor", METRICS_SERVER_NAME);

    wait_for_condition(
        &format!("ServiceMonitor {} to exist", monitor_name),
        SCALEDOBJECT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            let monitor_name = monitor_name.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "servicemonitor",
                    &monitor_name,
                    "-n",
                    PROM_NAMESPACE,
                    "-o",
                    "jsonpath={.spec.endpoints[0].port}",
                ])
                .await;

                match output {
                    Ok(port) => {
                        if port == "metrics" {
                            info!(
                                "[Integration/Autoscaling/Prom] ServiceMonitor {} found, scraping port: {}",
                                monitor_name, port
                            );
                            Ok(true)
                        } else {
                            info!(
                                "[Integration/Autoscaling/Prom] ServiceMonitor port mismatch: {}",
                                port
                            );
                            Ok(false)
                        }
                    }
                    Err(_) => Ok(false),
                }
            }
        },
    )
    .await
}

/// Wait for KEDA to scale a deployment beyond 1 replica.
async fn wait_for_scale_up(
    kubeconfig: &str,
    namespace: &str,
    name: &str,
    timeout: Duration,
) -> Result<(), String> {
    let kc = kubeconfig.to_string();
    let ns = namespace.to_string();
    let selector = service_pod_selector(name);
    let desc = format!("{} to scale beyond 1 replica", name);

    wait_for_condition(&desc, timeout, POLL_INTERVAL, || {
        let kc = kc.clone();
        let ns = ns.clone();
        let selector = selector.clone();
        async move {
            let output = run_kubectl(&[
                "--kubeconfig",
                &kc,
                "get",
                "pods",
                "-n",
                &ns,
                "-l",
                &selector,
                "-o",
                "jsonpath={.items[*].status.phase}",
            ])
            .await;

            match output {
                Ok(phases) => {
                    let running = phases
                        .split_whitespace()
                        .filter(|p| *p == "Running")
                        .count();
                    info!(
                        "[Integration/Autoscaling] {} pods running: {} (need > 1)",
                        name, running
                    );
                    Ok(running > 1)
                }
                Err(_) => Ok(false),
            }
        }
    })
    .await
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone test — verify KEDA pod autoscaling on workload cluster
#[tokio::test]
#[ignore]
async fn test_autoscaling_standalone() {
    let session = TestSession::from_env(
        "Set LATTICE_MGMT_KUBECONFIG and LATTICE_WORKLOAD_KUBECONFIG to run standalone autoscaling tests",
    )
    .await
    .unwrap();
    apply_e2e_default_policy(&session.ctx.mgmt_kubeconfig)
        .await
        .unwrap();
    run_autoscaling_tests(&session.ctx).await.unwrap();
}
