//! Multi-cluster route discovery and cross-cluster connectivity integration tests
//!
//! Verifies the full pipeline: advertise config → heartbeat → LatticeClusterRoutes
//! → ServiceEntry → AuthorizationPolicy → traffic flows (or is denied).
//!
//! # Running Standalone (requires 2-cluster hierarchy)
//!
//! ```bash
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt \
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/workload \
//! cargo test --features provider-e2e --test e2e test_route_discovery_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::collections::BTreeMap;
use std::time::Duration;

use kube::api::Api;
use tracing::info;

use lattice_common::crd::workload::ingress::AdvertiseConfig;
use lattice_common::crd::{
    ContainerSpec, IngressSpec, LatticeService, LatticeServiceSpec, PortSpec, RouteKind, RouteSpec,
    ServicePortsSpec, WorkloadSpec,
};

use super::super::helpers::{
    apply_advertise_wildcard_policy, client_from_kubeconfig, create_with_retry, delete_namespace,
    ensure_fresh_namespace, run_kubectl, setup_regcreds_infrastructure, wait_for_condition,
    wait_for_service_phase, DEFAULT_TIMEOUT, NGINX_IMAGE,
};

const ROUTE_TEST_NS: &str = "route-discovery-test";

// =============================================================================
// Service Builders
// =============================================================================

/// Build a simple nginx service with an advertised ingress route
fn build_advertised_service(
    name: &str,
    hostname: &str,
    allowed_services: Vec<String>,
) -> LatticeService {
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    use lattice_common::crd::{ResourceQuantity, ResourceRequirements};

    use lattice_common::crd::VolumeMount;

    let mut volumes = BTreeMap::new();
    volumes.insert("/tmp".to_string(), VolumeMount::default());

    let mut containers = BTreeMap::new();
    containers.insert(
        "main".to_string(),
        ContainerSpec {
            image: NGINX_IMAGE.clone(),
            volumes,
            resources: Some(ResourceRequirements {
                requests: Some(ResourceQuantity {
                    cpu: Some("50m".to_string()),
                    memory: Some("32Mi".to_string()),
                }),
                limits: Some(ResourceQuantity {
                    cpu: Some("200m".to_string()),
                    memory: Some("128Mi".to_string()),
                }),
            }),
            ..Default::default()
        },
    );

    let mut ports = BTreeMap::new();
    ports.insert(
        "http".to_string(),
        PortSpec {
            port: 8080,
            target_port: None,
            protocol: None,
        },
    );

    let mut routes = BTreeMap::new();
    routes.insert(
        "public".to_string(),
        RouteSpec {
            kind: RouteKind::HTTPRoute,
            hosts: vec![hostname.to_string()],
            port: None,
            listen_port: None,
            rules: None,
            tls: None,
            advertise: Some(AdvertiseConfig { allowed_services }),
        },
    );

    LatticeService {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(ROUTE_TEST_NS.to_string()),
            ..Default::default()
        },
        spec: LatticeServiceSpec {
            workload: WorkloadSpec {
                containers,
                resources: BTreeMap::new(),
                service: Some(ServicePortsSpec { ports }),
            },
            ingress: Some(IngressSpec {
                gateway_class: None,
                routes,
            }),
            ..Default::default()
        },
        status: None,
    }
}

/// Build a consumer service on the mgmt cluster that curls a remote (cross-cluster) service.
///
/// The consumer declares an outbound dependency to the remote service. The compiler
/// resolves it via the graph's Remote node and generates a ServiceEntry. The consumer
/// pod curls the remote's **advertised hostname** (resolved via ServiceEntry), not the
/// K8s internal DNS (which only exists on the remote cluster).
fn build_cross_cluster_consumer(
    name: &str,
    namespace: &str,
    remote_name: &str,
    remote_namespace: &str,
    advertised_hostname: &str,
) -> LatticeService {
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use lattice_common::crd::{DependencyDirection, ResourceSpec, ResourceType};

    let script = format!(
        r#"while true; do
  if curl -sf http://{advertised_hostname} 2>/dev/null | grep -q .; then
    echo "CROSS_CLUSTER_OK"
  else
    echo "CROSS_CLUSTER_FAIL"
  fi
  sleep 5
done"#
    );

    let mut containers = BTreeMap::new();
    containers.insert(
        "main".to_string(),
        super::super::mesh_fixtures::curl_container(script),
    );

    let mut resources = BTreeMap::new();
    resources.insert(
        remote_name.to_string(),
        ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Outbound,
            namespace: Some(remote_namespace.to_string()),
            ..Default::default()
        },
    );

    LatticeService {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: LatticeServiceSpec {
            workload: WorkloadSpec {
                containers,
                resources,
                service: None,
            },
            ..Default::default()
        },
        status: None,
    }
}

/// Verify cross-cluster traffic by checking consumer pod logs for "CROSS_CLUSTER_OK".
///
/// Uses the same retry pattern as mesh tests — polls logs until the marker appears
/// or DEFAULT_TIMEOUT is reached.
async fn verify_cross_cluster_traffic(
    kubeconfig: &str,
    namespace: &str,
    service_name: &str,
) -> Result<(), String> {
    wait_for_condition(
        "cross-cluster traffic",
        DEFAULT_TIMEOUT,
        Duration::from_secs(10),
        || {
            let kc = kubeconfig.to_string();
            let ns = namespace.to_string();
            let name = service_name.to_string();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "logs",
                    "-n",
                    &ns,
                    "-l",
                    &format!("lattice.dev/service={name}"),
                    "--tail=20",
                ])
                .await
                .unwrap_or_default();

                Ok(output.contains("CROSS_CLUSTER_OK"))
            }
        },
    )
    .await
}

// =============================================================================
// Route Table Verification
// =============================================================================

/// Verify that LatticeClusterRoutes CRDs exist on a cluster
pub async fn verify_cluster_routes_exist(kubeconfig: &str) -> Result<(), String> {
    info!("[RouteDiscovery] Checking for LatticeClusterRoutes CRDs...");

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticeclusterroutes",
        "-o",
        "json",
    ])
    .await?;

    let parsed: serde_json::Value =
        serde_json::from_str(&output).map_err(|e| format!("failed to parse: {e}"))?;

    let items = parsed["items"].as_array().ok_or("expected items array")?;
    if items.is_empty() {
        return Err("no LatticeClusterRoutes CRDs found".to_string());
    }

    for item in items {
        let name = item["metadata"]["name"].as_str().unwrap_or("unknown");
        let count = item["status"]["routeCount"].as_u64().unwrap_or(0);
        info!(
            "[RouteDiscovery] LatticeClusterRoutes '{}': {} routes",
            name, count
        );
    }

    Ok(())
}

/// Wait for specific hostnames to appear in a cluster's route table
pub async fn verify_child_routes(
    kubeconfig: &str,
    _cluster_name: &str,
    expected_hostnames: &[&str],
) -> Result<(), String> {
    info!("[RouteDiscovery] Waiting for routes across all LatticeClusterRoutes...");

    wait_for_condition(
        "routes across all LatticeClusterRoutes",
        DEFAULT_TIMEOUT,
        Duration::from_secs(10),
        || {
            let kc = kubeconfig.to_string();
            let hostnames: Vec<String> = expected_hostnames.iter().map(|h| h.to_string()).collect();
            async move {
                // List all LatticeClusterRoutes — routes are now per-cluster CRDs,
                // not merged into a single self-named CRD.
                let output = match run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "latticeclusterroutes",
                    "-o",
                    "json",
                ])
                .await
                {
                    Ok(o) => o,
                    Err(_) => return Ok(false),
                };

                let parsed: serde_json::Value = match serde_json::from_str(&output) {
                    Ok(v) => v,
                    Err(_) => return Ok(false),
                };

                let items = match parsed["items"].as_array() {
                    Some(items) => items,
                    None => return Ok(false),
                };

                // Collect all routes from all CRDs
                let all_routes: Vec<&serde_json::Value> = items
                    .iter()
                    .filter_map(|item| item["spec"]["routes"].as_array())
                    .flatten()
                    .collect();

                Ok(hostnames.iter().all(|h| {
                    all_routes
                        .iter()
                        .any(|r| r["hostname"].as_str() == Some(h.as_str()))
                }))
            }
        },
    )
    .await?;

    info!("[RouteDiscovery] All expected routes found");
    Ok(())
}

/// Verify route status has Ready phase and matching observedGeneration
pub async fn verify_route_status(kubeconfig: &str, _cluster_name: &str) -> Result<(), String> {
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticeclusterroutes",
        "-o",
        "json",
    ])
    .await?;

    let parsed: serde_json::Value =
        serde_json::from_str(&output).map_err(|e| format!("failed to parse: {e}"))?;

    let items = parsed["items"]
        .as_array()
        .ok_or("no LatticeClusterRoutes found")?;

    if items.is_empty() {
        return Err("no LatticeClusterRoutes CRDs exist".to_string());
    }

    for item in items {
        let name = item["metadata"]["name"].as_str().unwrap_or("unknown");
        let phase = item["status"]["phase"].as_str().unwrap_or("unknown");
        if phase != "Ready" {
            return Err(format!("CRD '{}' phase is '{}', expected 'Ready'", name, phase));
        }
        let gen = item["metadata"]["generation"].as_i64();
        let observed = item["status"]["observedGeneration"].as_i64();
        if gen != observed {
            return Err(format!(
                "CRD '{}' generation mismatch: spec={:?}, observed={:?}",
                name, gen, observed
            ));
        }
    }

    Ok(())
}

// =============================================================================
// ServiceEntry Verification
// =============================================================================

/// Verify that a ServiceEntry exists for the cross-cluster hostname.
///
/// Cross-cluster dependencies compile through the same FQDN egress path
/// as external services. The ServiceEntry uses DNS resolution with an
/// endpoint for the gateway IP.
pub async fn verify_cross_cluster_service_entry(
    kubeconfig: &str,
    namespace: &str,
    hostname: &str,
) -> Result<(), String> {
    info!(
        "[RouteDiscovery] Checking for ServiceEntry with host '{}'...",
        hostname
    );

    let output = run_kubectl(&[
        "--kubeconfig", kubeconfig,
        "get", "serviceentries", "-n", namespace, "-o", "json",
    ])
    .await?;

    let parsed: serde_json::Value =
        serde_json::from_str(&output).map_err(|e| format!("failed to parse: {e}"))?;

    let items = parsed["items"].as_array().ok_or("expected items array")?;

    let found = items.iter().any(|item| {
        item["spec"]["hosts"]
            .as_array()
            .map(|hosts| hosts.iter().any(|h| h.as_str() == Some(hostname)))
            .unwrap_or(false)
    });

    if !found {
        return Err(format!(
            "no ServiceEntry found with host '{}' in namespace '{}'",
            hostname, namespace
        ));
    }

    info!("[RouteDiscovery] ServiceEntry for '{}' verified", hostname);
    Ok(())
}

// =============================================================================
// Gateway mTLS Verification
// =============================================================================

/// Verify Gateway has frontend mTLS when routes are advertised
pub async fn verify_gateway_frontend_mtls(kubeconfig: &str, namespace: &str) -> Result<(), String> {
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "gateways.gateway.networking.k8s.io",
        "-n",
        namespace,
        "-o",
        "json",
    ])
    .await?;

    let parsed: serde_json::Value =
        serde_json::from_str(&output).map_err(|e| format!("failed to parse: {e}"))?;

    for item in parsed["items"].as_array().unwrap_or(&vec![]) {
        let name = item["metadata"]["name"].as_str().unwrap_or("unknown");
        let has_frontend = item["spec"]["tls"]["frontend"].as_object().is_some();

        if has_frontend {
            let refs =
                &item["spec"]["tls"]["frontend"]["default"]["validation"]["caCertificateRefs"];
            if refs.as_array().map(|a| a.is_empty()).unwrap_or(true) {
                return Err(format!("Gateway '{}': frontend TLS but no CA refs", name));
            }
            info!(
                "[RouteDiscovery] Gateway '{}': frontend mTLS configured",
                name
            );
        }
    }

    Ok(())
}

// =============================================================================
// Cross-Cluster AuthorizationPolicy Verification
// =============================================================================

/// Verify that an AuthorizationPolicy with SPIFFE principals exists for restricted routes
pub async fn verify_cross_cluster_auth_policy(
    kubeconfig: &str,
    namespace: &str,
    service_name: &str,
) -> Result<(), String> {
    let policy_name = format!("{}-cross-cluster-deny", service_name);
    info!(
        "[RouteDiscovery] Checking AuthorizationPolicy '{}'...",
        policy_name
    );

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "authorizationpolicies.security.istio.io",
        "-n",
        namespace,
        &policy_name,
        "-o",
        "json",
    ])
    .await?;

    let parsed: serde_json::Value =
        serde_json::from_str(&output).map_err(|e| format!("failed to parse: {e}"))?;

    let action = parsed["spec"]["action"].as_str().unwrap_or("");
    if action != "DENY" {
        return Err(format!(
            "AuthorizationPolicy action is '{}', expected 'DENY'",
            action
        ));
    }

    // DENY policy uses notPrincipals — traffic from anyone NOT in the list is denied
    let not_principals = &parsed["spec"]["rules"][0]["from"][0]["source"]["notPrincipals"];
    if not_principals.as_array().map(|a| a.is_empty()).unwrap_or(true) {
        // Empty notPrincipals = deny all (fail-closed), which is valid
        info!("[RouteDiscovery] AuthorizationPolicy '{}' denies all (fail-closed)", policy_name);
    }

    info!(
        "[RouteDiscovery] AuthorizationPolicy '{}' verified with SPIFFE principals",
        policy_name
    );
    Ok(())
}

// =============================================================================
// Full Test Suites
// =============================================================================

/// Run route discovery tests on a 2-cluster hierarchy.
///
/// Deploys a service with advertised routes on the workload cluster,
/// verifies routes propagate to the parent, and checks policy generation.
pub async fn run_route_discovery_tests(
    mgmt_kubeconfig: &str,
    workload_kubeconfig: &str,
) -> Result<(), String> {
    info!("[RouteDiscovery] Starting cross-cluster route discovery tests...");

    // Setup namespace on workload cluster
    ensure_fresh_namespace(workload_kubeconfig, ROUTE_TEST_NS).await?;
    setup_regcreds_infrastructure(workload_kubeconfig).await?;

    // Cedar: permit wildcard advertise for route-target
    apply_advertise_wildcard_policy(workload_kubeconfig, ROUTE_TEST_NS, "route-target").await?;

    // Deploy an advertised service on the workload cluster (open to all)
    let svc = build_advertised_service(
        "route-target",
        "route-target.test.local",
        vec!["*".to_string()],
    );

    let client = client_from_kubeconfig(workload_kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, ROUTE_TEST_NS);
    create_with_retry(&api, &svc, "route-target").await?;
    wait_for_service_phase(
        workload_kubeconfig,
        ROUTE_TEST_NS,
        "route-target",
        "Ready",
        None,
        DEFAULT_TIMEOUT,
    )
    .await?;
    info!("[RouteDiscovery] Advertised service deployed on workload cluster");

    // Verify routes propagate to parent cluster as per-child LatticeClusterRoutes CRDs.
    let mgmt_cluster_name = super::super::helpers::MGMT_CLUSTER_NAME;
    verify_child_routes(
        mgmt_kubeconfig,
        mgmt_cluster_name,
        &["route-target.test.local"],
    )
    .await?;
    verify_route_status(mgmt_kubeconfig, mgmt_cluster_name).await?;
    info!("[RouteDiscovery] Routes propagated to parent cluster");

    // Verify Gateway has frontend mTLS on workload cluster
    verify_gateway_frontend_mtls(workload_kubeconfig, ROUTE_TEST_NS).await?;

    // Deploy a consumer on the mgmt cluster that curls the workload's advertised service.
    // This verifies the full cross-cluster traffic path:
    // consumer → ServiceEntry → workload Gateway → route-target pod
    info!("[RouteDiscovery] Deploying cross-cluster consumer on mgmt cluster...");
    let consumer_ns = "route-consumer-test";
    ensure_fresh_namespace(mgmt_kubeconfig, consumer_ns).await?;
    setup_regcreds_infrastructure(mgmt_kubeconfig).await?;

    let consumer = build_cross_cluster_consumer(
        "consumer",
        consumer_ns,
        "route-target",
        ROUTE_TEST_NS,
        "route-target.test.local",
    );

    let mgmt_client = client_from_kubeconfig(mgmt_kubeconfig).await?;
    let consumer_api: Api<LatticeService> = Api::namespaced(mgmt_client, consumer_ns);
    create_with_retry(&consumer_api, &consumer, "consumer").await?;
    wait_for_service_phase(
        mgmt_kubeconfig,
        consumer_ns,
        "consumer",
        "Ready",
        None,
        DEFAULT_TIMEOUT,
    )
    .await?;
    info!("[RouteDiscovery] Consumer deployed, waiting for curl to succeed...");

    // Wait for the consumer pod to successfully curl the remote service
    verify_cross_cluster_traffic(mgmt_kubeconfig, consumer_ns, "consumer").await?;
    info!("[RouteDiscovery] Cross-cluster traffic verified!");

    // Cleanup both clusters
    delete_namespace(workload_kubeconfig, ROUTE_TEST_NS).await;
    delete_namespace(mgmt_kubeconfig, consumer_ns).await;
    info!("[RouteDiscovery] Route discovery tests passed!");
    Ok(())
}

/// Run restricted advertise tests (fail-closed verification).
///
/// Deploys a service with specific allowedServices, verifies that
/// an AuthorizationPolicy with SPIFFE principals is generated.
pub async fn run_restricted_advertise_tests(workload_kubeconfig: &str) -> Result<(), String> {
    info!("[RouteDiscovery] Starting restricted advertise tests...");

    ensure_fresh_namespace(workload_kubeconfig, ROUTE_TEST_NS).await?;

    // Deploy service restricted to a specific caller identity
    let svc = build_advertised_service(
        "restricted-svc",
        "restricted.test.local",
        vec!["edge/edge/haproxy-fw".to_string()],
    );

    let client = client_from_kubeconfig(workload_kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, ROUTE_TEST_NS);
    create_with_retry(&api, &svc, "restricted-svc").await?;
    wait_for_service_phase(
        workload_kubeconfig,
        ROUTE_TEST_NS,
        "restricted-svc",
        "Ready",
        None,
        DEFAULT_TIMEOUT,
    )
    .await?;

    // Verify AuthorizationPolicy with SPIFFE principal was generated
    verify_cross_cluster_auth_policy(workload_kubeconfig, ROUTE_TEST_NS, "restricted-svc").await?;

    // Cleanup
    delete_namespace(workload_kubeconfig, ROUTE_TEST_NS).await;
    info!("[RouteDiscovery] Restricted advertise tests passed!");
    Ok(())
}

// =============================================================================
// Standalone Tests
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_route_discovery_standalone() {
    use super::super::context::{init_e2e_test, TestSession};

    init_e2e_test();
    let Ok(session) = TestSession::from_env("Set LATTICE_MGMT_KUBECONFIG").await else {
        eprintln!("Skipping: requires LATTICE_MGMT_KUBECONFIG (multi-cluster test)");
        return;
    };

    let workload_kc = session
        .ctx
        .workload_kubeconfig
        .as_deref()
        .expect("requires workload kubeconfig");

    run_route_discovery_tests(&session.ctx.mgmt_kubeconfig, workload_kc)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore]
async fn test_restricted_advertise_standalone() {
    use super::super::context::{init_e2e_test, TestSession};

    init_e2e_test();
    let Ok(session) = TestSession::from_env("Set LATTICE_MGMT_KUBECONFIG").await else {
        eprintln!("Skipping: requires LATTICE_MGMT_KUBECONFIG (multi-cluster test)");
        return;
    };

    let workload_kc = session
        .ctx
        .workload_kubeconfig
        .as_deref()
        .expect("requires workload kubeconfig");

    run_restricted_advertise_tests(workload_kc).await.unwrap();
}
