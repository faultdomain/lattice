//! Observability integration tests for Lattice workloads
//!
//! Tests that verify VMServiceScrape creation and metrics scraping for
//! LatticeService resources with observability mappings configured.
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_observability_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::collections::BTreeMap;
use std::time::Duration;

use tracing::info;

use lattice_common::crd::{
    ContainerSpec, MetricsConfig, ObservabilitySpec, PortSpec, ResourceQuantity,
    ResourceRequirements, SecurityContext, ServicePortsSpec, VolumeMount,
};

use super::super::helpers::{
    delete_namespace, deploy_and_wait_for_phase, ensure_fresh_namespace, run_kubectl,
    setup_regcreds_infrastructure, wait_for_condition, BUSYBOX_IMAGE, DEFAULT_TIMEOUT,
};
use super::super::mesh_fixtures::build_lattice_service;

// =============================================================================
// Constants
// =============================================================================

const OBSERVABILITY_NAMESPACE: &str = "observability-test";
const METRICS_SVC_NAME: &str = "obs-metrics-svc";
const TEST_METRIC_NAME: &str = "test_obs_gauge";

const DEPLOY_TIMEOUT: Duration = DEFAULT_TIMEOUT;
const SCRAPE_TIMEOUT: Duration = Duration::from_secs(300);
const POLL_INTERVAL: Duration = Duration::from_secs(10);

// =============================================================================
// Service Builder
// =============================================================================

/// Build a service that exposes Prometheus metrics and has observability mappings.
///
/// The service:
/// - Runs busybox httpd serving a static `/metrics` endpoint on port 9090
/// - Has a port named `"metrics"` (triggers VMServiceScrape generation)
/// - Has `observability.metrics.mappings` configured with a PromQL query
fn build_observability_service() -> lattice_common::crd::LatticeService {
    let script = format!(
        concat!(
            "mkdir -p /tmp/www && ",
            "printf '# HELP {m} A test gauge for observability\\n",
            "# TYPE {m} gauge\\n",
            "{m} 42.5\\n' > /tmp/www/metrics && ",
            "httpd -f -p 9090 -h /tmp/www"
        ),
        m = TEST_METRIC_NAME,
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
            run_as_user: Some(65534),
            apparmor_profile: Some("Unconfined".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

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

    let resources = BTreeMap::new();
    let mut svc = build_lattice_service(
        METRICS_SVC_NAME,
        OBSERVABILITY_NAMESPACE,
        resources,
        false,
        ContainerSpec {
            image: BUSYBOX_IMAGE.to_string(),
            ..Default::default()
        },
    );

    svc.spec.workload.containers = containers;
    svc.spec.workload.service = Some(ServicePortsSpec { ports });
    svc.spec.replicas = 1;

    // Configure observability with a PromQL mapping that queries our test metric
    svc.spec.observability = Some(ObservabilitySpec {
        metrics: Some(MetricsConfig {
            mappings: BTreeMap::from([(
                "test_gauge".to_string(),
                format!("avg({TEST_METRIC_NAME}{{$SELECTORS}})"),
            )]),
            port: None, // auto-detect the "metrics" named port
        }),
    });

    svc
}

// =============================================================================
// Test Logic
// =============================================================================

/// Run observability integration tests against an existing workload cluster.
pub async fn run_observability_tests(kubeconfig: &str) -> Result<(), String> {
    info!("[Integration/Observability] Starting observability tests");

    ensure_fresh_namespace(kubeconfig, OBSERVABILITY_NAMESPACE).await?;
    setup_regcreds_infrastructure(kubeconfig).await?;

    let svc = build_observability_service();

    // Deploy the service and wait for Ready
    info!("[Integration/Observability] Deploying {} with metrics port and observability mappings", METRICS_SVC_NAME);
    deploy_and_wait_for_phase(
        kubeconfig,
        OBSERVABILITY_NAMESPACE,
        svc,
        "Ready",
        None,
        DEPLOY_TIMEOUT,
    )
    .await?;

    // Verify VMServiceScrape was created with the correct port
    verify_vm_service_scrape(kubeconfig).await?;

    // Wait for the controller to scrape VictoriaMetrics and write status.metrics
    verify_status_metrics(kubeconfig).await?;

    info!("[Integration/Observability] All observability tests passed");
    delete_namespace(kubeconfig, OBSERVABILITY_NAMESPACE).await;
    Ok(())
}

/// Verify the VMServiceScrape was created for the observability service.
async fn verify_vm_service_scrape(kubeconfig: &str) -> Result<(), String> {
    let kc = kubeconfig.to_string();
    let scrape_name = format!("{METRICS_SVC_NAME}-scrape");

    wait_for_condition(
        &format!("VMServiceScrape {scrape_name} to exist with port=metrics"),
        DEPLOY_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            let scrape_name = scrape_name.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "vmservicescrape",
                    &scrape_name,
                    "-n",
                    OBSERVABILITY_NAMESPACE,
                    "-o",
                    "jsonpath={.spec.endpoints[0].port}",
                ])
                .await;

                match output {
                    Ok(port) => {
                        if port == "metrics" {
                            info!(
                                "[Integration/Observability] VMServiceScrape {} found, port: {}",
                                scrape_name, port
                            );
                            Ok(true)
                        } else {
                            info!(
                                "[Integration/Observability] VMServiceScrape port mismatch: {}",
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

/// Verify that the controller writes scraped metrics to status.metrics.values.
///
/// Polls the LatticeService status until `status.metrics.values.test_gauge` appears
/// with a reasonable value (the busybox httpd serves a static gauge of 42.5).
async fn verify_status_metrics(kubeconfig: &str) -> Result<(), String> {
    let kc = kubeconfig.to_string();

    wait_for_condition(
        "status.metrics.values to be populated",
        SCRAPE_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "latticeservice",
                    METRICS_SVC_NAME,
                    "-n",
                    OBSERVABILITY_NAMESPACE,
                    "-o",
                    "jsonpath={.status.metrics.values.test_gauge}",
                ])
                .await;

                match output {
                    Ok(val) if !val.is_empty() => {
                        match val.parse::<f64>() {
                            Ok(v) => {
                                info!(
                                    "[Integration/Observability] status.metrics.values.test_gauge = {}",
                                    v
                                );
                                // The busybox httpd serves 42.5 — allow some tolerance
                                // for aggregation rounding
                                if (v - 42.5).abs() < 1.0 {
                                    Ok(true)
                                } else {
                                    info!(
                                        "[Integration/Observability] Value {} not close to expected 42.5, retrying",
                                        v
                                    );
                                    Ok(false)
                                }
                            }
                            Err(_) => {
                                info!(
                                    "[Integration/Observability] Could not parse value: {}",
                                    val
                                );
                                Ok(false)
                            }
                        }
                    }
                    Ok(_) => {
                        info!("[Integration/Observability] status.metrics.values.test_gauge not yet populated");
                        Ok(false)
                    }
                    Err(_) => Ok(false),
                }
            }
        },
    )
    .await?;

    Ok(())
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone test — verify observability metrics scraping on workload cluster
#[tokio::test]
#[ignore]
async fn test_observability_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_observability_tests(&resolved.kubeconfig).await.unwrap();
}
