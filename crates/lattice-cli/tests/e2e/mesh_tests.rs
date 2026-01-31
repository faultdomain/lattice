//! Service mesh bilateral agreement tests
//!
//! This module contains tests for verifying the bilateral agreement pattern:
//! - Fixed 9-service test: Deterministic test with known expected results
//! - Randomized mesh test: 10-20 services with random bilateral agreements
//!
//! Both tests run in parallel when enabled via LATTICE_ENABLE_MESH_TEST=true

#![cfg(feature = "provider-e2e")]

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, PostParams};
use rand::prelude::*;
use tokio::time::sleep;
use tracing::info;

use lattice_operator::crd::{
    ContainerSpec, DependencyDirection, DeploySpec, LatticeExternalService,
    LatticeExternalServiceSpec, LatticeService, LatticeServiceSpec, PortSpec, ReplicaSpec,
    Resolution, ResourceSpec, ResourceType, ServicePhase, ServicePortsSpec,
};

use super::helpers::{client_from_kubeconfig, run_cmd, run_cmd_allow_fail};

// =============================================================================
// Namespace Helpers
// =============================================================================

/// Create a namespace using kubectl
fn create_namespace(kubeconfig_path: &str, namespace: &str) {
    info!("Creating namespace {}...", namespace);
    let _ = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "create",
            "namespace",
            namespace,
        ],
    );
}

/// Delete a namespace using kubectl (non-blocking)
fn delete_namespace(kubeconfig_path: &str, namespace: &str) {
    info!("[Mesh Cleanup] Deleting namespace {}...", namespace);
    let _ = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "delete",
            "namespace",
            namespace,
            "--wait=false",
        ],
    );
}

/// Wait for all LatticeServices in a namespace to be Ready
async fn wait_for_services_ready(
    kubeconfig_path: &str,
    namespace: &str,
    expected_count: usize,
) -> Result<(), String> {
    use kube::api::ListParams;

    let client = client_from_kubeconfig(kubeconfig_path).await?;
    let api: Api<LatticeService> = Api::namespaced(client, namespace);

    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(300);

    info!(
        "Waiting for {} LatticeServices to be Ready...",
        expected_count
    );

    loop {
        if start.elapsed() > timeout {
            return Err(format!(
                "Timeout waiting for LatticeServices to be Ready (expected {})",
                expected_count
            ));
        }

        let services = api
            .list(&ListParams::default())
            .await
            .map_err(|e| format!("Failed to list services: {}", e))?;

        let ready_count = services
            .items
            .iter()
            .filter(|svc| {
                svc.status
                    .as_ref()
                    .map(|s| s.phase == ServicePhase::Ready)
                    .unwrap_or(false)
            })
            .count();

        let total = services.items.len();

        info!(
            "{}/{} LatticeServices ready (total: {})",
            ready_count, expected_count, total
        );

        if ready_count >= expected_count {
            info!("All {} LatticeServices are Ready!", expected_count);
            return Ok(());
        }

        // Log which services are not ready yet
        let not_ready: Vec<_> = services
            .items
            .iter()
            .filter(|svc| {
                svc.status
                    .as_ref()
                    .map(|s| s.phase != ServicePhase::Ready)
                    .unwrap_or(true)
            })
            .filter_map(|svc| {
                let name = svc.metadata.name.as_deref()?;
                let phase = svc
                    .status
                    .as_ref()
                    .map(|s| format!("{:?}", s.phase))
                    .unwrap_or_else(|| "NoStatus".to_string());
                Some(format!("{}:{}", name, phase))
            })
            .collect();

        if !not_ready.is_empty() && not_ready.len() <= 5 {
            info!("  Not ready: {}", not_ready.join(", "));
        }

        sleep(Duration::from_secs(5)).await;
    }
}

// =============================================================================
// Shared Test Script Generation
// =============================================================================

struct TestTarget {
    url: String,
    expected_allowed: bool,
    success_msg: String,
    fail_msg: String,
}

impl TestTarget {
    /// Create a test target for an internal service
    fn internal(name: &str, namespace: &str, expected: bool, reason: &str) -> Self {
        let (success_msg, fail_msg) = if expected {
            (
                format!("{}: ALLOWED ({})", name, reason),
                format!("{}: BLOCKED (UNEXPECTED - {})", name, reason),
            )
        } else {
            (
                format!("{}: ALLOWED (UNEXPECTED - {})", name, reason),
                format!("{}: BLOCKED ({})", name, reason),
            )
        };
        Self {
            url: format!("http://{}.{}.svc.cluster.local/", name, namespace),
            expected_allowed: expected,
            success_msg,
            fail_msg,
        }
    }

    /// Create a test target for an external service (random mesh format)
    fn external(source: &str, target: &str, url: &str, expected: bool) -> Self {
        let (success_msg, fail_msg) = if expected {
            (
                format!("{}->{}:ALLOWED", source, target),
                format!("{}->{}:BLOCKED(UNEXPECTED)", source, target),
            )
        } else {
            (
                format!("{}->{}:ALLOWED(UNEXPECTED)", source, target),
                format!("{}->{}:BLOCKED", source, target),
            )
        };
        Self {
            url: url.to_string(),
            expected_allowed: expected,
            success_msg,
            fail_msg,
        }
    }

    /// Create a test target for an internal service (random mesh format)
    fn internal_random(source: &str, target: &str, namespace: &str, expected: bool) -> Self {
        let (success_msg, fail_msg) = if expected {
            (
                format!("{}->{}:ALLOWED", source, target),
                format!("{}->{}:BLOCKED(UNEXPECTED)", source, target),
            )
        } else {
            (
                format!("{}->{}:ALLOWED(UNEXPECTED)", source, target),
                format!("{}->{}:BLOCKED", source, target),
            )
        };
        Self {
            url: format!("http://{}.{}.svc.cluster.local/", target, namespace),
            expected_allowed: expected,
            success_msg,
            fail_msg,
        }
    }
}

/// Generate a traffic test script that waits for policies and tests connections
fn generate_test_script(source_name: &str, targets: Vec<TestTarget>) -> String {
    // Separate blocked endpoints for policy wait check
    let blocked_targets: Vec<&TestTarget> =
        targets.iter().filter(|t| !t.expected_allowed).collect();

    // Build checks for blocked endpoints (longer timeout for reliability)
    let endpoint_checks: String = blocked_targets
        .iter()
        .enumerate()
        .map(|(i, t)| {
            format!(
                r#"
    R{i}=$(curl -s -o /dev/null -w "%{{http_code}}" --connect-timeout 3 --max-time 5 {url} 2>/dev/null || echo "000")"#,
                i = i,
                url = t.url,
            )
        })
        .collect();

    // Check that ALL blocked endpoints return non-2xx
    let all_blocked_check: String = if blocked_targets.is_empty() {
        "true".to_string()
    } else {
        blocked_targets
            .iter()
            .enumerate()
            .map(|(i, _)| {
                format!(
                    "\"$R{}\" != \"200\" ] && [ \"$R{}\" != \"201\" ] && [ \"$R{}\" != \"204\"",
                    i, i, i
                )
            })
            .collect::<Vec<_>>()
            .join(" ] && [ ")
    };

    let mut script = format!(
        r#"
echo "=== {} Traffic Tests ==="
echo "Testing {} endpoints..."

# Wait for blocked endpoints to NOT return 2xx (policy active or service not ready)
echo "Waiting for policies on {} blocked endpoints..."
MAX_RETRIES=30
RETRY=0
while [ $RETRY -lt $MAX_RETRIES ]; do{endpoint_checks}
    if [ {all_blocked_check} ]; then
        echo "Blocked endpoints not returning 2xx - policies likely active"
        sleep 5
        break
    fi
    RETRY=$((RETRY + 1))
    echo "Waiting for policies... (attempt $RETRY/$MAX_RETRIES)"
    sleep 2
done

if [ $RETRY -eq $MAX_RETRIES ]; then
    echo "Warning: Policy propagation wait timed out, proceeding anyway"
fi

"#,
        source_name,
        targets.len(),
        blocked_targets.len(),
        endpoint_checks = endpoint_checks,
        all_blocked_check = all_blocked_check,
    );

    // Add individual test checks with retries that distinguish policy blocks from transient failures
    for target in &targets {
        script.push_str(&format!(
            r#"
# Test {url} - retry transient failures, accept 403 as definitive block
MAX_ATTEMPTS=5
ATTEMPT=0
RESULT="UNKNOWN"
while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{{http_code}}" --connect-timeout 5 --max-time 10 {url} 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "204" ] || [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ]; then
        RESULT="ALLOWED"
        break
    elif [ "$HTTP_CODE" = "403" ]; then
        # Policy block - definitive, no retry needed
        RESULT="BLOCKED"
        break
    else
        # Transient failure (000=connection error, 5xx=server error) - retry
        ATTEMPT=$((ATTEMPT + 1))
        if [ $ATTEMPT -lt $MAX_ATTEMPTS ]; then
            sleep 2
        fi
    fi
done
if [ "$RESULT" = "ALLOWED" ]; then
    echo "{success_msg}"
elif [ "$RESULT" = "BLOCKED" ]; then
    echo "{fail_msg}"
else
    # All attempts failed with transient errors - treat as blocked but note it
    echo "{fail_msg} (transient)"
fi
"#,
            url = target.url,
            success_msg = target.success_msg,
            fail_msg = target.fail_msg,
        ));
    }

    script.push_str(&format!(
        r#"
echo "=== End {} Tests ==="
sleep 30
"#,
        source_name
    ));

    // Loop forever
    script.insert_str(0, "while true; do\n");
    script.push_str("done\n");

    script
}

// =============================================================================
// Fixed 9-Service Mesh Test
// =============================================================================
//
// Tests a 3-layer microservice architecture with 9 services:
// - LAYER 1: FRONTEND (3 services) - Traffic generators
// - LAYER 2: API (3 services) - Business logic
// - LAYER 3: BACKEND (3 services) - Data layer

const TEST_SERVICES_NAMESPACE: &str = "mesh-test";
const TOTAL_SERVICES: usize = 10; // 9 original + 1 public-api (wildcard)

fn nginx_container() -> ContainerSpec {
    ContainerSpec {
        image: "nginx:alpine".to_string(),
        command: None,
        args: None,
        variables: BTreeMap::new(),
        files: BTreeMap::new(),
        volumes: BTreeMap::new(),
        resources: None,
        liveness_probe: None,
        readiness_probe: None,
        startup_probe: None,
        security: None,
    }
}

fn http_port() -> ServicePortsSpec {
    let mut ports = BTreeMap::new();
    ports.insert(
        "http".to_string(),
        PortSpec {
            port: 80,
            target_port: None,
            protocol: None,
        },
    );
    ServicePortsSpec { ports }
}

fn outbound_dep(name: &str) -> (String, ResourceSpec) {
    (
        name.to_string(),
        ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Outbound,
            id: None,
            class: None,
            metadata: None,
            params: None,
            namespace: None,
            inbound: None,
            outbound: None,
        },
    )
}

fn inbound_allow(name: &str) -> (String, ResourceSpec) {
    (
        name.to_string(),
        ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Inbound,
            id: None,
            class: None,
            metadata: None,
            params: None,
            namespace: None,
            inbound: None,
            outbound: None,
        },
    )
}

/// Create an inbound resource that allows ALL callers (wildcard)
fn inbound_allow_all() -> (String, ResourceSpec) {
    (
        "any-caller".to_string(),
        ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Inbound,
            id: Some("*".to_string()), // Wildcard - allow all callers
            class: None,
            metadata: None,
            params: None,
            namespace: None,
            inbound: None,
            outbound: None,
        },
    )
}

fn create_service(
    name: &str,
    outbound: Vec<&str>,
    inbound: Vec<&str>,
    has_port: bool,
    container: ContainerSpec,
) -> LatticeService {
    create_service_with_options(name, outbound, inbound, false, has_port, container)
}

fn create_service_with_options(
    name: &str,
    outbound: Vec<&str>,
    inbound: Vec<&str>,
    allows_all_inbound: bool,
    has_port: bool,
    container: ContainerSpec,
) -> LatticeService {
    let mut containers = BTreeMap::new();
    containers.insert("main".to_string(), container);

    let mut resources: BTreeMap<String, ResourceSpec> =
        outbound.iter().map(|s| outbound_dep(s)).collect();

    if allows_all_inbound {
        // Use wildcard to allow all callers
        let (key, spec) = inbound_allow_all();
        resources.insert(key, spec);
    } else {
        resources.extend(inbound.iter().map(|s| inbound_allow(s)));
    }

    let mut labels = BTreeMap::new();
    labels.insert(
        "lattice.dev/environment".to_string(),
        TEST_SERVICES_NAMESPACE.to_string(),
    );

    LatticeService {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(TEST_SERVICES_NAMESPACE.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: LatticeServiceSpec {
            containers,
            resources,
            service: if has_port { Some(http_port()) } else { None },
            replicas: ReplicaSpec { min: 1, max: None },
            deploy: DeploySpec::default(),
            ingress: None,
            sidecars: BTreeMap::new(),
            sysctls: BTreeMap::new(),
            host_network: None,
            share_process_namespace: None,
        },
        status: None,
    }
}

fn create_frontend_web() -> LatticeService {
    let ns = TEST_SERVICES_NAMESPACE;
    let targets = vec![
        TestTarget::internal("api-gateway", ns, true, "bilateral agreement"),
        TestTarget::internal("api-users", ns, true, "bilateral agreement"),
        TestTarget::internal("api-orders", ns, false, "web not allowed by orders"),
        TestTarget::internal("db-users", ns, false, "no direct DB access"),
        TestTarget::internal("db-orders", ns, false, "no direct DB access"),
        TestTarget::internal("cache", ns, false, "no direct cache access"),
        TestTarget::internal("frontend-mobile", ns, false, "no peer access"),
        TestTarget::internal("frontend-admin", ns, false, "no peer access"),
        // Test wildcard service - web declares outbound so should be allowed
        TestTarget::internal("public-api", ns, true, "wildcard allows all with outbound"),
    ];

    let script = generate_test_script("frontend-web", targets);
    let container = ContainerSpec {
        image: "curlimages/curl:latest".to_string(),
        command: Some(vec!["/bin/sh".to_string()]),
        args: Some(vec!["-c".to_string(), script]),
        variables: BTreeMap::new(),
        files: BTreeMap::new(),
        volumes: BTreeMap::new(),
        resources: None,
        liveness_probe: None,
        readiness_probe: None,
        startup_probe: None,
        security: None,
    };

    create_service(
        "frontend-web",
        vec![
            "api-gateway",
            "api-users",
            "api-orders",
            "db-users",
            "db-orders",
            "cache",
            "frontend-mobile",
            "frontend-admin",
            "public-api", // Declares outbound to wildcard service
        ],
        vec![],
        false,
        container,
    )
}

fn create_frontend_mobile() -> LatticeService {
    let ns = TEST_SERVICES_NAMESPACE;
    let targets = vec![
        TestTarget::internal("api-gateway", ns, true, "bilateral agreement"),
        TestTarget::internal("api-users", ns, false, "mobile not allowed by users"),
        TestTarget::internal("api-orders", ns, true, "bilateral agreement"),
        TestTarget::internal("db-users", ns, false, "no direct DB access"),
        TestTarget::internal("db-orders", ns, false, "no direct DB access"),
        TestTarget::internal("cache", ns, false, "no direct cache access"),
        TestTarget::internal("frontend-web", ns, false, "no peer access"),
        TestTarget::internal("frontend-admin", ns, false, "no peer access"),
        // Test wildcard service - mobile does NOT declare outbound, should be BLOCKED
        // This verifies that wildcard still requires outbound declaration from caller
        TestTarget::internal("public-api", ns, false, "no outbound declared to wildcard"),
    ];

    let script = generate_test_script("frontend-mobile", targets);
    let container = ContainerSpec {
        image: "curlimages/curl:latest".to_string(),
        command: Some(vec!["/bin/sh".to_string()]),
        args: Some(vec!["-c".to_string(), script]),
        variables: BTreeMap::new(),
        files: BTreeMap::new(),
        volumes: BTreeMap::new(),
        resources: None,
        liveness_probe: None,
        readiness_probe: None,
        startup_probe: None,
        security: None,
    };

    create_service(
        "frontend-mobile",
        vec![
            "api-gateway",
            "api-users",
            "api-orders",
            "db-users",
            "db-orders",
            "cache",
            "frontend-web",
            "frontend-admin",
            // NOTE: Intentionally NOT including "public-api" to test wildcard still requires outbound
        ],
        vec![],
        false,
        container,
    )
}

fn create_frontend_admin() -> LatticeService {
    let ns = TEST_SERVICES_NAMESPACE;
    let targets = vec![
        TestTarget::internal("api-gateway", ns, true, "bilateral agreement"),
        TestTarget::internal("api-users", ns, true, "bilateral agreement"),
        TestTarget::internal("api-orders", ns, true, "bilateral agreement"),
        TestTarget::internal("db-users", ns, false, "no direct DB access"),
        TestTarget::internal("db-orders", ns, false, "no direct DB access"),
        TestTarget::internal("cache", ns, false, "no direct cache access"),
        TestTarget::internal("frontend-web", ns, false, "no peer access"),
        TestTarget::internal("frontend-mobile", ns, false, "no peer access"),
        // Test wildcard service - admin declares outbound so should be allowed
        TestTarget::internal("public-api", ns, true, "wildcard allows all with outbound"),
    ];

    let script = generate_test_script("frontend-admin", targets);
    let container = ContainerSpec {
        image: "curlimages/curl:latest".to_string(),
        command: Some(vec!["/bin/sh".to_string()]),
        args: Some(vec!["-c".to_string(), script]),
        variables: BTreeMap::new(),
        files: BTreeMap::new(),
        volumes: BTreeMap::new(),
        resources: None,
        liveness_probe: None,
        readiness_probe: None,
        startup_probe: None,
        security: None,
    };

    create_service(
        "frontend-admin",
        vec![
            "api-gateway",
            "api-users",
            "api-orders",
            "db-users",
            "db-orders",
            "cache",
            "frontend-web",
            "frontend-mobile",
            "public-api", // Declares outbound to wildcard service
        ],
        vec![],
        false,
        container,
    )
}

fn create_api_gateway() -> LatticeService {
    create_service(
        "api-gateway",
        vec!["db-users", "db-orders", "cache"],
        vec!["frontend-web", "frontend-mobile", "frontend-admin"],
        true,
        nginx_container(),
    )
}

fn create_api_users() -> LatticeService {
    create_service(
        "api-users",
        vec!["db-users", "cache"],
        vec!["frontend-web", "frontend-admin"],
        true,
        nginx_container(),
    )
}

fn create_api_orders() -> LatticeService {
    create_service(
        "api-orders",
        vec!["db-orders", "cache"],
        vec!["frontend-mobile", "frontend-admin"],
        true,
        nginx_container(),
    )
}

fn create_db_users() -> LatticeService {
    create_service(
        "db-users",
        vec![],
        vec!["api-gateway", "api-users"],
        true,
        nginx_container(),
    )
}

fn create_db_orders() -> LatticeService {
    create_service(
        "db-orders",
        vec![],
        vec!["api-gateway", "api-orders"],
        true,
        nginx_container(),
    )
}

fn create_cache() -> LatticeService {
    create_service(
        "cache",
        vec![],
        vec!["api-gateway", "api-users", "api-orders"],
        true,
        nginx_container(),
    )
}

/// Create the public-api service that allows ALL inbound traffic via wildcard.
/// This tests the "allow all inbound" pattern where only the caller needs to
/// declare outbound - the service accepts anyone.
fn create_public_api() -> LatticeService {
    create_service_with_options(
        "public-api",
        vec![], // no outbound dependencies
        vec![], // explicit inbound list is ignored when allows_all_inbound=true
        true,   // allows_all_inbound = true (wildcard)
        true,   // has_port
        nginx_container(),
    )
}

async fn deploy_test_services(kubeconfig_path: &str) -> Result<(), String> {
    create_namespace(kubeconfig_path, TEST_SERVICES_NAMESPACE);

    let client = client_from_kubeconfig(kubeconfig_path).await?;
    let api: Api<LatticeService> = Api::namespaced(client, TEST_SERVICES_NAMESPACE);

    info!("[Layer 3] Deploying backend services...");
    for (name, svc) in [
        ("db-users", create_db_users()),
        ("db-orders", create_db_orders()),
        ("cache", create_cache()),
        ("public-api", create_public_api()), // Wildcard service - allows all inbound
    ] {
        info!("Deploying {}...", name);
        api.create(&PostParams::default(), &svc)
            .await
            .map_err(|e| format!("Failed to create {}: {}", name, e))?;
    }

    info!("[Layer 2] Deploying API services...");
    for (name, svc) in [
        ("api-gateway", create_api_gateway()),
        ("api-users", create_api_users()),
        ("api-orders", create_api_orders()),
    ] {
        info!("Deploying {}...", name);
        api.create(&PostParams::default(), &svc)
            .await
            .map_err(|e| format!("Failed to create {}: {}", name, e))?;
    }

    info!("[Layer 1] Deploying frontend services...");
    for (name, svc) in [
        ("frontend-web", create_frontend_web()),
        ("frontend-mobile", create_frontend_mobile()),
        ("frontend-admin", create_frontend_admin()),
    ] {
        info!("Deploying {}...", name);
        api.create(&PostParams::default(), &svc)
            .await
            .map_err(|e| format!("Failed to create {}: {}", name, e))?;
    }

    info!("All {} services deployed!", TOTAL_SERVICES);
    sleep(Duration::from_secs(5)).await;
    Ok(())
}

async fn wait_for_service_pods(kubeconfig_path: &str) -> Result<(), String> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(300);
    // +1 for the Istio ambient waypoint proxy pod created per namespace
    let expected_pods = TOTAL_SERVICES + 1;

    info!("Waiting for {} pods to be ready...", expected_pods);

    loop {
        if start.elapsed() > timeout {
            return Err(format!(
                "Timeout waiting for test pods (expected {})",
                expected_pods
            ));
        }

        let pods_output = run_cmd_allow_fail(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "get",
                "pods",
                "-n",
                TEST_SERVICES_NAMESPACE,
                "-o",
                "jsonpath={range .items[*]}{.status.phase}{\"\\n\"}{end}",
            ],
        );

        let running_count = pods_output.lines().filter(|l| *l == "Running").count();
        info!("{}/{} pods running", running_count, expected_pods);

        if running_count >= expected_pods {
            info!("All {} pods are running!", expected_pods);
            return Ok(());
        }

        sleep(Duration::from_secs(10)).await;
    }
}

const FRONTEND_WEB_EXPECTED: &[(&str, bool)] = &[
    ("api-gateway", true),
    ("api-users", true),
    ("api-orders", false),
    ("db-users", false),
    ("db-orders", false),
    ("cache", false),
    ("frontend-mobile", false),
    ("frontend-admin", false),
    ("public-api", true), // Wildcard service - web declares outbound so allowed
];

const FRONTEND_MOBILE_EXPECTED: &[(&str, bool)] = &[
    ("api-gateway", true),
    ("api-users", false),
    ("api-orders", true),
    ("db-users", false),
    ("db-orders", false),
    ("cache", false),
    ("frontend-web", false),
    ("frontend-admin", false),
    ("public-api", false), // Wildcard service - mobile does NOT declare outbound so blocked
];

const FRONTEND_ADMIN_EXPECTED: &[(&str, bool)] = &[
    ("api-gateway", true),
    ("api-users", true),
    ("api-orders", true),
    ("db-users", false),
    ("db-orders", false),
    ("cache", false),
    ("frontend-web", false),
    ("frontend-mobile", false),
    ("public-api", true), // Wildcard service - admin declares outbound so allowed
];

async fn verify_traffic_patterns(kubeconfig_path: &str) -> Result<(), String> {
    let mut total_pass = 0;
    let mut total_fail = 0;
    let mut failures: Vec<String> = Vec::new();

    for (frontend_name, expected_results) in [
        ("frontend-web", FRONTEND_WEB_EXPECTED),
        ("frontend-mobile", FRONTEND_MOBILE_EXPECTED),
        ("frontend-admin", FRONTEND_ADMIN_EXPECTED),
    ] {
        info!("Checking {} logs...", frontend_name);

        let logs = run_cmd(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "logs",
                "-n",
                TEST_SERVICES_NAMESPACE,
                "-l",
                &format!("{}={}", lattice_common::LABEL_NAME, frontend_name),
                "--tail",
                "100",
            ],
        )?;

        for (target, expected_allowed) in expected_results.iter() {
            let expected_str = if *expected_allowed {
                "ALLOWED"
            } else {
                "BLOCKED"
            };
            let allowed_pattern = format!("{}: ALLOWED", target);
            let blocked_pattern = format!("{}: BLOCKED", target);

            // Check for ANY occurrence (handles partial logs from in-progress runs)
            let has_allowed = logs.contains(&allowed_pattern);
            let has_blocked = logs.contains(&blocked_pattern);

            let actual_str = match (has_allowed, has_blocked) {
                (true, true) => {
                    // Both found - use the LAST occurrence to get most recent result
                    let last_allowed = logs.rfind(&allowed_pattern).unwrap();
                    let last_blocked = logs.rfind(&blocked_pattern).unwrap();
                    if last_allowed > last_blocked {
                        "ALLOWED"
                    } else {
                        "BLOCKED"
                    }
                }
                (true, false) => "ALLOWED",
                (false, true) => "BLOCKED",
                (false, false) => "UNKNOWN",
            };

            let result_ok = actual_str == expected_str;
            let status = if result_ok { "PASS" } else { "FAIL" };

            info!(
                "  [{}] {} -> {}: {} (expected: {})",
                status, frontend_name, target, actual_str, expected_str
            );

            if result_ok {
                total_pass += 1;
            } else {
                total_fail += 1;
                failures.push(format!(
                    "{} -> {}: got {}, expected {}",
                    frontend_name, target, actual_str, expected_str
                ));
            }
        }
    }

    let total_tests = total_pass + total_fail;
    info!("========================================");
    info!("SERVICE MESH VERIFICATION SUMMARY");
    info!("========================================");
    info!("Total tests: {}", total_tests);
    info!(
        "Passed: {} ({:.1}%)",
        total_pass,
        (total_pass as f64 / total_tests as f64) * 100.0
    );
    info!("Failed: {}", total_fail);

    if !failures.is_empty() {
        info!("Failures:");
        for failure in &failures {
            info!("- {}", failure);
        }
        return Err(format!(
            "Service mesh verification failed: {} of {} tests failed",
            total_fail, total_tests
        ));
    }

    info!(
        "\n  SUCCESS: All {} bilateral agreement tests passed!",
        total_tests
    );
    Ok(())
}

/// Handle for a running mesh test that can be stopped on demand
pub struct MeshTestHandle {
    kubeconfig_path: String,
    namespace: &'static str,
}

impl MeshTestHandle {
    /// Stop the mesh test and verify traffic patterns
    ///
    /// Returns Ok(()) if all bilateral agreements were enforced correctly.
    /// Returns Err if any "ALLOWED(UNEXPECTED)" entries are found (policy gaps).
    pub async fn stop_and_verify(self) -> Result<(), String> {
        verify_traffic_patterns(&self.kubeconfig_path).await
    }

    /// Check for security violations only (incorrectly allowed traffic)
    ///
    /// This is less strict than full verification - it only fails if traffic
    /// that should be BLOCKED was ALLOWED. Useful during upgrades where
    /// some allowed traffic may fail due to pod restarts.
    pub async fn check_no_policy_gaps(&self) -> Result<(), String> {
        check_no_incorrectly_allowed(&self.kubeconfig_path, self.namespace).await
    }
}

/// Check that no traffic was incorrectly allowed (security violation check)
async fn check_no_incorrectly_allowed(
    kubeconfig_path: &str,
    namespace: &str,
) -> Result<(), String> {
    let mut violations: Vec<String> = Vec::new();

    // Get all pods with traffic generators (frontend-* pods)
    let pods_output = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "get",
            "pods",
            "-n",
            namespace,
            "-o",
            "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}",
        ],
    )?;

    for pod in pods_output.lines() {
        let pod = pod.trim();
        if pod.is_empty() {
            continue;
        }

        let logs = run_cmd_allow_fail(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "logs",
                "-n",
                namespace,
                pod,
                "--tail",
                "500",
            ],
        );

        // Look for "ALLOWED(UNEXPECTED)" or "ALLOWED (UNEXPECTED" patterns
        for line in logs.lines() {
            if line.contains("ALLOWED(UNEXPECTED)") || line.contains("ALLOWED (UNEXPECTED") {
                violations.push(format!("{}: {}", pod, line.trim()));
            }
        }
    }

    if !violations.is_empty() {
        info!("SECURITY VIOLATIONS DETECTED:");
        for v in &violations {
            info!("{}", v);
        }
        return Err(format!(
            "Policy gaps detected: {} instances of incorrectly allowed traffic",
            violations.len()
        ));
    }

    Ok(())
}

/// Start the fixed 9-service mesh test and return a handle
///
/// The test runs traffic generators continuously until `stop_and_verify()` is called.
pub async fn start_mesh_test(kubeconfig_path: &str) -> Result<MeshTestHandle, String> {
    info!("\n[Mesh Test] Starting service mesh bilateral agreement test...");
    deploy_test_services(kubeconfig_path).await?;

    // Wait for LatticeServices to be Ready (controller has reconciled)
    wait_for_services_ready(kubeconfig_path, TEST_SERVICES_NAMESPACE, TOTAL_SERVICES).await?;

    // Wait for pods to be running
    wait_for_service_pods(kubeconfig_path).await?;

    // Wait for initial policy propagation
    info!("Waiting for initial policy propagation (30s)...");
    sleep(Duration::from_secs(30)).await;

    Ok(MeshTestHandle {
        kubeconfig_path: kubeconfig_path.to_string(),
        namespace: TEST_SERVICES_NAMESPACE,
    })
}

/// Run the fixed 9-service mesh test
pub async fn run_mesh_test(kubeconfig_path: &str) -> Result<(), String> {
    let handle = start_mesh_test(kubeconfig_path).await?;
    // Additional wait for traffic patterns to stabilize
    info!("Waiting for traffic tests to complete (120s)...");
    sleep(Duration::from_secs(120)).await;
    let result = handle.stop_and_verify().await;
    // Clean up immediately to free CPU resources
    cleanup_mesh_test(kubeconfig_path);
    result
}

// =============================================================================
// Randomized Large-Scale Mesh Test (10-20 services)
// =============================================================================

#[derive(Debug, Clone)]
struct RandomMeshConfig {
    min_services: usize,
    max_services: usize,
    num_layers: usize,
    outbound_probability: f64,
    bilateral_probability: f64,
    seed: Option<u64>,
    num_external_services: usize,
    external_outbound_probability: f64,
    external_allow_probability: f64,
    /// Probability that a non-frontend service uses wildcard "allow all inbound"
    wildcard_probability: f64,
}

impl Default for RandomMeshConfig {
    fn default() -> Self {
        Self {
            min_services: 10,
            max_services: 20,
            num_layers: 3,
            outbound_probability: 0.3,
            bilateral_probability: 0.6,
            seed: None,
            num_external_services: 10,
            external_outbound_probability: 0.3,
            external_allow_probability: 0.6,
            wildcard_probability: 0.15, // 15% chance a service allows all inbound
        }
    }
}

#[derive(Debug, Clone)]
struct RandomExternalService {
    url: String,
    allowed_requesters: HashSet<String>,
    resolution: Resolution,
}

#[derive(Debug, Clone)]
struct RandomService {
    name: String,
    outbound: HashSet<String>,
    external_outbound: HashSet<String>,
    inbound: HashSet<String>,
    is_traffic_generator: bool,
    /// If true, this service allows ALL inbound via wildcard (only caller needs outbound)
    allows_all_inbound: bool,
}

#[derive(Debug)]
struct RandomMesh {
    services: BTreeMap<String, RandomService>,
    layers: Vec<Vec<String>>,
    external_services: BTreeMap<String, RandomExternalService>,
    expected_connections: Vec<(String, String, bool, bool)>,
}

impl RandomMesh {
    fn generate(config: &RandomMeshConfig) -> Self {
        let mut rng = match config.seed {
            Some(seed) => StdRng::seed_from_u64(seed),
            None => StdRng::from_entropy(),
        };

        let num_services = rng.gen_range(config.min_services..=config.max_services);
        info!(
            "Generating {} services across {} layers...",
            num_services, config.num_layers
        );

        let mut layer_sizes = Vec::with_capacity(config.num_layers);
        let base_size = num_services / config.num_layers;
        let mut remaining = num_services;

        for i in 0..config.num_layers {
            let size = if i == config.num_layers - 1 {
                remaining
            } else {
                let variance = if i == 0 || i == config.num_layers - 1 {
                    base_size / 2
                } else {
                    base_size / 3
                };
                // Clamp size to not exceed remaining (leave at least 1 per remaining layer)
                let remaining_layers = config.num_layers - i - 1;
                let max_size = remaining.saturating_sub(remaining_layers);
                let size = (base_size + rng.gen_range(0..=variance)).min(max_size);
                remaining -= size;
                size
            };
            layer_sizes.push(size);
        }

        let layer_prefixes = ["frontend", "gateway", "api", "backend", "data"];
        let mut layers: Vec<Vec<String>> = Vec::with_capacity(config.num_layers);
        let mut services = BTreeMap::new();

        for (layer_idx, &size) in layer_sizes.iter().enumerate() {
            let prefix = layer_prefixes.get(layer_idx).unwrap_or(&"svc");
            let mut layer_services = Vec::with_capacity(size);
            let is_traffic_generator = layer_idx == 0;

            for i in 0..size {
                let name = format!("{}-{}", prefix, i);
                layer_services.push(name.clone());

                // Non-frontend services can randomly use wildcard "allow all inbound"
                let allows_all_inbound =
                    !is_traffic_generator && rng.gen::<f64>() < config.wildcard_probability;

                services.insert(
                    name.clone(),
                    RandomService {
                        name,
                        outbound: HashSet::new(),
                        external_outbound: HashSet::new(),
                        inbound: HashSet::new(),
                        is_traffic_generator,
                        allows_all_inbound,
                    },
                );
            }
            layers.push(layer_services);
        }

        let mut expected_connections = Vec::new();

        for layer_idx in 0..config.num_layers.saturating_sub(1) {
            for source_name in &layers[layer_idx] {
                for target_layer in layers.iter().skip(layer_idx + 1) {
                    for target_name in target_layer {
                        if rng.gen::<f64>() < config.outbound_probability {
                            services
                                .get_mut(source_name)
                                .expect("source service should exist in services map")
                                .outbound
                                .insert(target_name.clone());

                            // Check if target allows all inbound (wildcard) - if so, bilateral is automatic
                            let target_allows_all = services[target_name].allows_all_inbound;
                            let is_bilateral = if target_allows_all {
                                // Wildcard service: bilateral agreement is automatic when source declares outbound
                                true
                            } else {
                                // Normal service: need explicit inbound declaration
                                let bilateral = rng.gen::<f64>() < config.bilateral_probability;
                                if bilateral {
                                    services
                                        .get_mut(target_name)
                                        .expect("target service should exist in services map")
                                        .inbound
                                        .insert(source_name.clone());
                                }
                                bilateral
                            };

                            if services[source_name].is_traffic_generator {
                                expected_connections.push((
                                    source_name.clone(),
                                    target_name.clone(),
                                    is_bilateral,
                                    false,
                                ));
                            }
                        }
                    }
                }

                if services[source_name].is_traffic_generator {
                    for target_layer in layers.iter().skip(layer_idx + 1) {
                        let not_dependent: Vec<_> = target_layer
                            .iter()
                            .filter(|t| !services[source_name].outbound.contains(*t))
                            .collect();
                        let sample_size = not_dependent.len().min(3);
                        for target_name in not_dependent.choose_multiple(&mut rng, sample_size) {
                            // No outbound declared - should be blocked even for wildcard services
                            // (wildcard still requires the caller to declare outbound)
                            expected_connections.push((
                                source_name.clone(),
                                (*target_name).clone(),
                                false,
                                false,
                            ));
                        }
                    }
                }
            }
        }

        for layer in &layers {
            if layer.len() < 2 {
                continue;
            }
            let traffic_generators: Vec<_> = layer
                .iter()
                .filter(|s| services[*s].is_traffic_generator)
                .collect();
            for source in &traffic_generators {
                let peers: Vec<_> = layer.iter().filter(|s| *s != *source).collect();
                if let Some(peer) = peers.choose(&mut rng) {
                    expected_connections.push(((*source).clone(), (*peer).clone(), false, false));
                }
            }
        }

        let external_urls = [
            ("httpbin", "https://httpbin.org/status/200"),
            ("example", "https://example.com"),
            ("google", "https://www.google.com"),
            ("cloudflare", "https://one.one.one.one"),
            ("github", "https://github.com"),
        ];

        let mut external_services = BTreeMap::new();
        let num_external = config.num_external_services.min(external_urls.len());

        for (name, url) in external_urls.iter().take(num_external) {
            let resolution = if Self::is_ip_based_url(url) {
                Resolution::Static
            } else {
                Resolution::Dns
            };
            external_services.insert(
                name.to_string(),
                RandomExternalService {
                    url: url.to_string(),
                    allowed_requesters: HashSet::new(),
                    resolution,
                },
            );
        }

        let traffic_generators: Vec<String> = services
            .values()
            .filter(|s| s.is_traffic_generator)
            .map(|s| s.name.clone())
            .collect();
        let ext_names: Vec<String> = external_services.keys().cloned().collect();

        for source_name in &traffic_generators {
            for ext_name in &ext_names {
                if rng.gen::<f64>() < config.external_outbound_probability {
                    services
                        .get_mut(source_name)
                        .expect("source service should exist in services map")
                        .external_outbound
                        .insert(ext_name.clone());
                    let is_allowed = rng.gen::<f64>() < config.external_allow_probability;
                    if is_allowed {
                        external_services
                            .get_mut(ext_name)
                            .expect("external service should exist in external_services map")
                            .allowed_requesters
                            .insert(source_name.clone());
                    }
                    expected_connections.push((
                        source_name.clone(),
                        ext_name.clone(),
                        is_allowed,
                        true,
                    ));
                }
            }

            let not_dependent: Vec<_> = ext_names
                .iter()
                .filter(|e| !services[source_name].external_outbound.contains(*e))
                .cloned()
                .collect();
            for ext_name in not_dependent
                .choose_multiple(&mut rng, not_dependent.len().min(2))
                .cloned()
            {
                expected_connections.push((source_name.clone(), ext_name, false, true));
            }
        }

        Self {
            services,
            layers,
            external_services,
            expected_connections,
        }
    }

    fn is_ip_based_url(url: &str) -> bool {
        use std::net::IpAddr;
        let host = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);
        let host = host.split(':').next().unwrap_or(host);
        let host = host.split('/').next().unwrap_or(host);
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host.parse::<IpAddr>().is_ok()
    }

    fn stats(&self) -> String {
        let total_tests = self.expected_connections.len();
        let expected_allowed = self
            .expected_connections
            .iter()
            .filter(|(_, _, a, _)| *a)
            .count();
        let external_tests = self
            .expected_connections
            .iter()
            .filter(|(_, _, _, e)| *e)
            .count();
        let wildcard_services = self
            .services
            .values()
            .filter(|s| s.allows_all_inbound)
            .count();
        format!(
            "Services: {} across {} layers ({} wildcard)\n  Tests: {} ({} allowed, {} blocked)\n  External: {} services, {} tests",
            self.services.len(),
            self.layers.len(),
            wildcard_services,
            total_tests,
            expected_allowed,
            total_tests - expected_allowed,
            self.external_services.len(),
            external_tests
        )
    }

    fn print_manifest(&self) {
        let allowed: Vec<_> = self
            .expected_connections
            .iter()
            .filter(|(_, _, a, _)| *a)
            .collect();
        let blocked: Vec<_> = self
            .expected_connections
            .iter()
            .filter(|(_, _, a, _)| !*a)
            .collect();

        info!("=== EXPECTED ALLOWED ({}) ===", allowed.len());
        for (src, tgt, _, is_ext) in allowed.iter().take(20) {
            info!(
                "  {} -> {}{}",
                src,
                tgt,
                if *is_ext { " [EXT]" } else { "" }
            );
        }
        if allowed.len() > 20 {
            info!("... and {} more", allowed.len() - 20);
        }

        info!("=== EXPECTED BLOCKED ({}) ===", blocked.len());
        for (src, tgt, _, is_ext) in blocked.iter().take(20) {
            info!(
                "  {} -> {}{}",
                src,
                tgt,
                if *is_ext { " [EXT]" } else { "" }
            );
        }
        if blocked.len() > 20 {
            info!("... and {} more", blocked.len() - 20);
        }
    }

    fn create_lattice_service(&self, name: &str, namespace: &str) -> LatticeService {
        let svc = &self.services[name];
        let mut containers = BTreeMap::new();
        let mut resources: BTreeMap<String, ResourceSpec> = BTreeMap::new();

        for dep in &svc.outbound {
            resources.insert(
                dep.clone(),
                ResourceSpec {
                    type_: ResourceType::Service,
                    direction: DependencyDirection::Outbound,
                    id: None,
                    class: None,
                    metadata: None,
                    params: None,
                    namespace: None,
                    inbound: None,
                    outbound: None,
                },
            );
        }

        // Handle inbound: either wildcard (allow all) or explicit list
        if svc.allows_all_inbound {
            // Use wildcard to allow all callers
            resources.insert(
                "any-caller".to_string(),
                ResourceSpec {
                    type_: ResourceType::Service,
                    direction: DependencyDirection::Inbound,
                    id: Some("*".to_string()), // Wildcard
                    class: None,
                    metadata: None,
                    params: None,
                    namespace: None,
                    inbound: None,
                    outbound: None,
                },
            );
        } else {
            // Explicit inbound list
            for allow in &svc.inbound {
                resources.insert(
                    allow.clone(),
                    ResourceSpec {
                        type_: ResourceType::Service,
                        direction: DependencyDirection::Inbound,
                        id: None,
                        class: None,
                        metadata: None,
                        params: None,
                        namespace: None,
                        inbound: None,
                        outbound: None,
                    },
                );
            }
        }

        for ext_name in &svc.external_outbound {
            resources.insert(
                ext_name.clone(),
                ResourceSpec {
                    type_: ResourceType::ExternalService,
                    direction: DependencyDirection::Outbound,
                    id: None,
                    class: None,
                    metadata: None,
                    params: None,
                    namespace: None,
                    inbound: None,
                    outbound: None,
                },
            );
        }

        if svc.is_traffic_generator {
            let targets = self.build_test_targets(name, namespace);
            let script = generate_test_script(name, targets);
            containers.insert(
                "main".to_string(),
                ContainerSpec {
                    image: "curlimages/curl:latest".to_string(),
                    command: Some(vec!["/bin/sh".to_string()]),
                    args: Some(vec!["-c".to_string(), script]),
                    variables: BTreeMap::new(),
                    files: BTreeMap::new(),
                    volumes: BTreeMap::new(),
                    resources: None,
                    liveness_probe: None,
                    readiness_probe: None,
                    startup_probe: None,
                    security: None,
                },
            );
        } else {
            containers.insert(
                "main".to_string(),
                ContainerSpec {
                    image: "nginx:alpine".to_string(),
                    command: None,
                    args: None,
                    variables: BTreeMap::new(),
                    files: BTreeMap::new(),
                    volumes: BTreeMap::new(),
                    resources: None,
                    liveness_probe: None,
                    readiness_probe: None,
                    startup_probe: None,
                    security: None,
                },
            );
        }

        let mut labels = BTreeMap::new();
        labels.insert("lattice.dev/environment".to_string(), namespace.to_string());

        LatticeService {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                labels: Some(labels),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                containers,
                resources,
                service: if svc.is_traffic_generator {
                    None
                } else {
                    let mut ports = BTreeMap::new();
                    ports.insert(
                        "http".to_string(),
                        PortSpec {
                            port: 80,
                            target_port: None,
                            protocol: None,
                        },
                    );
                    Some(ServicePortsSpec { ports })
                },
                replicas: ReplicaSpec { min: 1, max: None },
                deploy: DeploySpec::default(),
                ingress: None,
                sidecars: BTreeMap::new(),
                sysctls: BTreeMap::new(),
                host_network: None,
                share_process_namespace: None,
            },
            status: None,
        }
    }

    fn create_external_service(&self, name: &str, namespace: &str) -> LatticeExternalService {
        let ext_svc = &self.external_services[name];
        let mut endpoints = BTreeMap::new();
        endpoints.insert("default".to_string(), ext_svc.url.clone());

        LatticeExternalService {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: LatticeExternalServiceSpec {
                endpoints,
                allowed_requesters: ext_svc.allowed_requesters.iter().cloned().collect(),
                resolution: ext_svc.resolution.clone(),
                description: Some(format!("External service: {}", ext_svc.url)),
            },
            status: None,
        }
    }

    fn build_test_targets(&self, source_name: &str, namespace: &str) -> Vec<TestTarget> {
        self.expected_connections
            .iter()
            .filter(|(src, _, _, _)| src == source_name)
            .map(|(_, target, expected_allowed, is_external)| {
                if *is_external {
                    let url = &self.external_services[target].url;
                    TestTarget::external(source_name, target, url, *expected_allowed)
                } else {
                    TestTarget::internal_random(source_name, target, namespace, *expected_allowed)
                }
            })
            .collect()
    }
}

const RANDOM_MESH_NAMESPACE: &str = "random-mesh";

async fn deploy_random_mesh(mesh: &RandomMesh, kubeconfig_path: &str) -> Result<(), String> {
    create_namespace(kubeconfig_path, RANDOM_MESH_NAMESPACE);

    let client = client_from_kubeconfig(kubeconfig_path).await?;

    if !mesh.external_services.is_empty() {
        info!(
            "Deploying {} external services...",
            mesh.external_services.len()
        );
        let ext_api: Api<LatticeExternalService> =
            Api::namespaced(client.clone(), RANDOM_MESH_NAMESPACE);
        for name in mesh.external_services.keys() {
            let ext_svc = mesh.create_external_service(name, RANDOM_MESH_NAMESPACE);
            ext_api
                .create(&PostParams::default(), &ext_svc)
                .await
                .map_err(|e| format!("Failed to create external service {}: {}", name, e))?;
        }
    }

    let api: Api<LatticeService> = Api::namespaced(client, RANDOM_MESH_NAMESPACE);

    for (layer_idx, layer) in mesh.layers.iter().enumerate().rev() {
        info!(
            "[Layer {}] Deploying {} services...",
            layer_idx,
            layer.len()
        );
        for name in layer {
            let svc = mesh.create_lattice_service(name, RANDOM_MESH_NAMESPACE);
            api.create(&PostParams::default(), &svc)
                .await
                .map_err(|e| format!("Failed to create {}: {}", name, e))?;
        }
        sleep(Duration::from_secs(2)).await;
    }

    info!("All {} services deployed!", mesh.services.len());
    Ok(())
}

async fn wait_for_random_mesh_pods(mesh: &RandomMesh, kubeconfig_path: &str) -> Result<(), String> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(1200);
    // +1 for the Istio ambient waypoint proxy pod created per namespace
    let expected_pods = mesh.services.len() + 1;

    info!("Waiting for {} pods to be ready...", expected_pods);

    loop {
        if start.elapsed() > timeout {
            return Err(format!(
                "Timeout waiting for pods (expected {})",
                expected_pods
            ));
        }

        let output = run_cmd_allow_fail(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "get",
                "pods",
                "-n",
                RANDOM_MESH_NAMESPACE,
                "-o",
                "jsonpath={range .items[*]}{.status.phase}{\"\\n\"}{end}",
            ],
        );

        let running = output.lines().filter(|l| l.trim() == "Running").count();
        info!("{}/{} pods running", running, expected_pods);

        if running >= expected_pods {
            return Ok(());
        }

        sleep(Duration::from_secs(15)).await;
    }
}

async fn verify_random_mesh_traffic(
    mesh: &RandomMesh,
    kubeconfig_path: &str,
) -> Result<(), String> {
    let mut results: BTreeMap<(String, String), (bool, bool, Option<bool>)> = BTreeMap::new();
    for (src, tgt, expected, is_external) in &mesh.expected_connections {
        results.insert((src.clone(), tgt.clone()), (*expected, *is_external, None));
    }

    let traffic_generators: Vec<_> = mesh
        .services
        .values()
        .filter(|s| s.is_traffic_generator)
        .map(|s| s.name.clone())
        .collect();

    info!(
        "Checking logs from {} traffic generators...",
        traffic_generators.len()
    );

    for source in &traffic_generators {
        let logs = run_cmd(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "logs",
                "-n",
                RANDOM_MESH_NAMESPACE,
                "-l",
                &format!("{}={}", lattice_common::LABEL_NAME, source),
                "--tail",
                "1000",
            ],
        )
        .unwrap_or_default();

        for ((src, tgt), (_, _, actual)) in results.iter_mut() {
            if src != source {
                continue;
            }
            // Find ANY occurrence of ALLOWED or BLOCKED (accept results from any test run)
            let allowed_pattern = format!("{}->{}:ALLOWED", src, tgt);
            let blocked_pattern = format!("{}->{}:BLOCKED", src, tgt);
            let has_allowed = logs.contains(&allowed_pattern);
            let has_blocked = logs.contains(&blocked_pattern);

            match (has_allowed, has_blocked) {
                (true, true) => {
                    // Both found - use the LAST occurrence to get most recent result
                    let last_allowed = logs.rfind(&allowed_pattern).unwrap();
                    let last_blocked = logs.rfind(&blocked_pattern).unwrap();
                    *actual = Some(last_allowed > last_blocked);
                }
                (true, false) => *actual = Some(true),
                (false, true) => *actual = Some(false),
                (false, false) => {} // No result found
            }
        }
    }

    let mut mismatches: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();

    for ((src, tgt), (expected, is_external, actual)) in &results {
        let marker = if *is_external { " [EXT]" } else { "" };
        match actual {
            None => missing.push(format!("{} -> {}{}", src, tgt, marker)),
            Some(got) => {
                if got != expected {
                    mismatches.push(format!(
                        "{} -> {}{}: expected {}, got {}",
                        src,
                        tgt,
                        marker,
                        if *expected { "ALLOWED" } else { "BLOCKED" },
                        if *got { "ALLOWED" } else { "BLOCKED" }
                    ));
                }
            }
        }
    }

    let total = results.len();
    let passed = total - mismatches.len() - missing.len();

    info!("========================================");
    info!("RANDOMIZED MESH VERIFICATION");
    info!("========================================");
    info!(
        "Total: {}, Passed: {}, Mismatches: {}, Missing: {}",
        total,
        passed,
        mismatches.len(),
        missing.len()
    );

    if !mismatches.is_empty() || !missing.is_empty() {
        if !mismatches.is_empty() {
            info!("MISMATCHES:");
            for m in mismatches.iter().take(20) {
                info!("{}", m);
            }
            if mismatches.len() > 20 {
                info!("... and {} more", mismatches.len() - 20);
            }
        }
        if !missing.is_empty() {
            info!("MISSING:");
            for m in missing.iter().take(20) {
                info!("{}", m);
            }
            if missing.len() > 20 {
                info!("... and {} more", missing.len() - 20);
            }
        }
        return Err(format!(
            "Random mesh failed: {} mismatches, {} missing",
            mismatches.len(),
            missing.len()
        ));
    }

    info!("SUCCESS: All {} tests passed!", total);
    Ok(())
}

/// Handle for a running random mesh test that can be stopped on demand
pub struct RandomMeshTestHandle {
    kubeconfig_path: String,
    mesh: RandomMesh,
}

impl RandomMeshTestHandle {
    /// Stop the mesh test and verify traffic patterns
    pub async fn stop_and_verify(self) -> Result<(), String> {
        verify_random_mesh_traffic(&self.mesh, &self.kubeconfig_path).await
    }
}

/// Start the randomized mesh test and return a handle
pub async fn start_random_mesh_test(kubeconfig_path: &str) -> Result<RandomMeshTestHandle, String> {
    info!("\n[Mesh Test] Starting randomized large-scale mesh test (10-20 services)...");

    let mesh = RandomMesh::generate(&RandomMeshConfig::default());
    info!("{}", mesh.stats());
    mesh.print_manifest();

    deploy_random_mesh(&mesh, kubeconfig_path).await?;

    // Wait for LatticeServices to be Ready (controller has reconciled)
    wait_for_services_ready(kubeconfig_path, RANDOM_MESH_NAMESPACE, mesh.services.len()).await?;

    // Wait for pods to be running
    info!("Waiting for pods...");
    wait_for_random_mesh_pods(&mesh, kubeconfig_path).await?;

    // Wait for initial policy propagation
    info!("Waiting for initial policy propagation (30s)...");
    sleep(Duration::from_secs(30)).await;

    Ok(RandomMeshTestHandle {
        kubeconfig_path: kubeconfig_path.to_string(),
        mesh,
    })
}

/// Run the randomized 10-20 service mesh test
pub async fn run_random_mesh_test(kubeconfig_path: &str) -> Result<(), String> {
    let handle = start_random_mesh_test(kubeconfig_path).await?;
    // Additional wait for traffic patterns to stabilize
    info!("Waiting for traffic tests to complete (120s)...");
    sleep(Duration::from_secs(120)).await;
    let result = handle.stop_and_verify().await;
    // Clean up immediately to free CPU resources
    cleanup_random_mesh_test(kubeconfig_path);
    result
}

// =============================================================================
// Cleanup Functions
// =============================================================================

/// Clean up the fixed 9-service mesh test namespace
fn cleanup_mesh_test(kubeconfig_path: &str) {
    delete_namespace(kubeconfig_path, TEST_SERVICES_NAMESPACE);
}

/// Clean up the random mesh test namespace
fn cleanup_random_mesh_test(kubeconfig_path: &str) {
    delete_namespace(kubeconfig_path, RANDOM_MESH_NAMESPACE);
}
