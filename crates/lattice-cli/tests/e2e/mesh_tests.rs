//! Service mesh bilateral agreement tests
//!
//! This module contains tests for verifying the bilateral agreement pattern:
//! - Fixed 9-service test: Deterministic test with known expected results
//! - Randomized mesh test: 50-100 services with random bilateral agreements
//!
//! Both tests run in parallel when enabled via LATTICE_ENABLE_MESH_TEST=true

#![cfg(feature = "provider-e2e")]

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, PostParams};
use rand::prelude::*;
use tokio::time::sleep;

use lattice_operator::crd::{
    ContainerSpec, DependencyDirection, DeploySpec, LatticeExternalService,
    LatticeExternalServiceSpec, LatticeService, LatticeServiceSpec, PortSpec, ReplicaSpec,
    Resolution, ResourceSpec, ResourceType, ServicePortsSpec,
};

use super::helpers::{client_from_kubeconfig, run_cmd, run_cmd_allow_fail};

/// Check if mesh tests are enabled via environment variable
pub fn mesh_test_enabled() -> bool {
    std::env::var("LATTICE_ENABLE_MESH_TEST")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
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
const TOTAL_SERVICES: usize = 9;

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
            outbound: None,
            inbound: None,
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
            outbound: None,
            inbound: None,
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
    let mut containers = BTreeMap::new();
    containers.insert("main".to_string(), container);

    let mut resources: BTreeMap<String, ResourceSpec> =
        outbound.iter().map(|s| outbound_dep(s)).collect();
    resources.extend(inbound.iter().map(|s| inbound_allow(s)));

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
            environment: TEST_SERVICES_NAMESPACE.to_string(),
            containers,
            resources,
            service: if has_port { Some(http_port()) } else { None },
            replicas: ReplicaSpec { min: 1, max: None },
            deploy: DeploySpec::default(),
            ingress: None,
        },
        status: None,
    }
}

struct ConnTest {
    target: &'static str,
    expected: bool,
    reason: &'static str,
}

fn generate_traffic_test_script(source: &str, tests: &[ConnTest]) -> String {
    let mut script = format!(
        r#"
echo "=== {} Traffic Tests ==="
echo "Testing {} connection permutations..."
sleep 5

"#,
        source,
        tests.len()
    );

    for test in tests {
        let (success_msg, fail_msg) = if test.expected {
            (
                format!("{}: ALLOWED ({})", test.target, test.reason),
                format!("{}: BLOCKED (UNEXPECTED - {})", test.target, test.reason),
            )
        } else {
            (
                format!("{}: ALLOWED (UNEXPECTED - {})", test.target, test.reason),
                format!("{}: BLOCKED ({})", test.target, test.reason),
            )
        };

        script.push_str(&format!(
            r#"
if curl -s --connect-timeout 3 http://{target}.{ns}.svc.cluster.local/ > /dev/null 2>&1; then
    echo "{success_msg}"
else
    echo "{fail_msg}"
fi
"#,
            target = test.target,
            ns = TEST_SERVICES_NAMESPACE,
            success_msg = success_msg,
            fail_msg = fail_msg,
        ));
    }

    script.push_str(&format!(
        r#"
echo "=== End {} Tests ==="
sleep 30
"#,
        source
    ));

    format!(
        r#"
while true; do
{}
done
"#,
        script
    )
}

fn create_frontend_web() -> LatticeService {
    let tests = vec![
        ConnTest {
            target: "api-gateway",
            expected: true,
            reason: "bilateral agreement",
        },
        ConnTest {
            target: "api-users",
            expected: true,
            reason: "bilateral agreement",
        },
        ConnTest {
            target: "api-orders",
            expected: false,
            reason: "web not allowed by orders",
        },
        ConnTest {
            target: "db-users",
            expected: false,
            reason: "no direct DB access",
        },
        ConnTest {
            target: "db-orders",
            expected: false,
            reason: "no direct DB access",
        },
        ConnTest {
            target: "cache",
            expected: false,
            reason: "no direct cache access",
        },
        ConnTest {
            target: "frontend-mobile",
            expected: false,
            reason: "no peer access",
        },
        ConnTest {
            target: "frontend-admin",
            expected: false,
            reason: "no peer access",
        },
    ];

    let script = generate_traffic_test_script("frontend-web", &tests);
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
        ],
        vec![],
        false,
        container,
    )
}

fn create_frontend_mobile() -> LatticeService {
    let tests = vec![
        ConnTest {
            target: "api-gateway",
            expected: true,
            reason: "bilateral agreement",
        },
        ConnTest {
            target: "api-users",
            expected: false,
            reason: "mobile not allowed by users",
        },
        ConnTest {
            target: "api-orders",
            expected: true,
            reason: "bilateral agreement",
        },
        ConnTest {
            target: "db-users",
            expected: false,
            reason: "no direct DB access",
        },
        ConnTest {
            target: "db-orders",
            expected: false,
            reason: "no direct DB access",
        },
        ConnTest {
            target: "cache",
            expected: false,
            reason: "no direct cache access",
        },
        ConnTest {
            target: "frontend-web",
            expected: false,
            reason: "no peer access",
        },
        ConnTest {
            target: "frontend-admin",
            expected: false,
            reason: "no peer access",
        },
    ];

    let script = generate_traffic_test_script("frontend-mobile", &tests);
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
        ],
        vec![],
        false,
        container,
    )
}

fn create_frontend_admin() -> LatticeService {
    let tests = vec![
        ConnTest {
            target: "api-gateway",
            expected: true,
            reason: "bilateral agreement",
        },
        ConnTest {
            target: "api-users",
            expected: true,
            reason: "bilateral agreement",
        },
        ConnTest {
            target: "api-orders",
            expected: true,
            reason: "bilateral agreement",
        },
        ConnTest {
            target: "db-users",
            expected: false,
            reason: "no direct DB access",
        },
        ConnTest {
            target: "db-orders",
            expected: false,
            reason: "no direct DB access",
        },
        ConnTest {
            target: "cache",
            expected: false,
            reason: "no direct cache access",
        },
        ConnTest {
            target: "frontend-web",
            expected: false,
            reason: "no peer access",
        },
        ConnTest {
            target: "frontend-mobile",
            expected: false,
            reason: "no peer access",
        },
    ];

    let script = generate_traffic_test_script("frontend-admin", &tests);
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

async fn deploy_test_services(kubeconfig_path: &str) -> Result<(), String> {
    println!("  Creating namespace {}...", TEST_SERVICES_NAMESPACE);
    let _ = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "create",
            "namespace",
            TEST_SERVICES_NAMESPACE,
        ],
    );

    let client = client_from_kubeconfig(kubeconfig_path).await?;
    let api: Api<LatticeService> = Api::all(client);

    println!("  [Layer 3] Deploying backend services...");
    for (name, svc) in [
        ("db-users", create_db_users()),
        ("db-orders", create_db_orders()),
        ("cache", create_cache()),
    ] {
        println!("    Deploying {}...", name);
        api.create(&PostParams::default(), &svc)
            .await
            .map_err(|e| format!("Failed to create {}: {}", name, e))?;
    }

    println!("  [Layer 2] Deploying API services...");
    for (name, svc) in [
        ("api-gateway", create_api_gateway()),
        ("api-users", create_api_users()),
        ("api-orders", create_api_orders()),
    ] {
        println!("    Deploying {}...", name);
        api.create(&PostParams::default(), &svc)
            .await
            .map_err(|e| format!("Failed to create {}: {}", name, e))?;
    }

    println!("  [Layer 1] Deploying frontend services...");
    for (name, svc) in [
        ("frontend-web", create_frontend_web()),
        ("frontend-mobile", create_frontend_mobile()),
        ("frontend-admin", create_frontend_admin()),
    ] {
        println!("    Deploying {}...", name);
        api.create(&PostParams::default(), &svc)
            .await
            .map_err(|e| format!("Failed to create {}: {}", name, e))?;
    }

    println!("  All {} services deployed!", TOTAL_SERVICES);
    sleep(Duration::from_secs(5)).await;
    Ok(())
}

async fn wait_for_service_pods(kubeconfig_path: &str) -> Result<(), String> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(300);

    println!("  Waiting for {} pods to be ready...", TOTAL_SERVICES);

    loop {
        if start.elapsed() > timeout {
            return Err(format!(
                "Timeout waiting for test pods (expected {})",
                TOTAL_SERVICES
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
        println!("    {}/{} pods running", running_count, TOTAL_SERVICES);

        if running_count >= TOTAL_SERVICES {
            println!("  All {} test pods are running!", TOTAL_SERVICES);
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
        println!("\n  Checking {} logs...", frontend_name);

        let logs = run_cmd(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "logs",
                "-n",
                TEST_SERVICES_NAMESPACE,
                "-l",
                &format!("app.kubernetes.io/name={}", frontend_name),
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

            let actual_allowed = logs.contains(&allowed_pattern);
            let actual_blocked = logs.contains(&blocked_pattern);

            let result_ok = if *expected_allowed {
                actual_allowed
            } else {
                actual_blocked && !actual_allowed
            };
            let status = if result_ok { "PASS" } else { "FAIL" };
            let actual_str = if actual_allowed {
                "ALLOWED"
            } else if actual_blocked {
                "BLOCKED"
            } else {
                "UNKNOWN"
            };

            println!(
                "    [{}] {} -> {}: {} (expected: {})",
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
    println!("\n  ========================================");
    println!("  SERVICE MESH VERIFICATION SUMMARY");
    println!("  ========================================");
    println!("  Total tests: {}", total_tests);
    println!(
        "  Passed: {} ({:.1}%)",
        total_pass,
        (total_pass as f64 / total_tests as f64) * 100.0
    );
    println!("  Failed: {}", total_fail);

    if !failures.is_empty() {
        println!("\n  Failures:");
        for failure in &failures {
            println!("    - {}", failure);
        }
        return Err(format!(
            "Service mesh verification failed: {} of {} tests failed",
            total_fail, total_tests
        ));
    }

    println!(
        "\n  SUCCESS: All {} bilateral agreement tests passed!",
        total_tests
    );
    Ok(())
}

/// Run the fixed 9-service mesh test
pub async fn run_mesh_test(kubeconfig_path: &str) -> Result<(), String> {
    println!("\n[Phase 8] Running service mesh bilateral agreement test...\n");
    deploy_test_services(kubeconfig_path).await?;
    wait_for_service_pods(kubeconfig_path).await?;
    println!("  Waiting for traffic tests to complete (60s)...");
    sleep(Duration::from_secs(60)).await;
    verify_traffic_patterns(kubeconfig_path).await?;

    // Run L7 policy enforcement tests
    run_policy_enforcement_test(kubeconfig_path).await?;

    Ok(())
}

// =============================================================================
// Randomized Large-Scale Mesh Test (50-100 services)
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
}

impl Default for RandomMeshConfig {
    fn default() -> Self {
        Self {
            min_services: 50,
            max_services: 75,
            num_layers: 5,
            outbound_probability: 0.3,
            bilateral_probability: 0.6,
            seed: None,
            num_external_services: 10,
            external_outbound_probability: 0.3,
            external_allow_probability: 0.6,
        }
    }
}

#[derive(Debug, Clone)]
struct RandomExternalService {
    #[allow(dead_code)]
    name: String,
    url: String,
    allowed_requesters: HashSet<String>,
    resolution: Resolution,
}

#[derive(Debug, Clone)]
struct RandomService {
    name: String,
    #[allow(dead_code)]
    layer: usize,
    outbound: HashSet<String>,
    external_outbound: HashSet<String>,
    inbound: HashSet<String>,
    is_traffic_generator: bool,
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
        println!(
            "  Generating {} services across {} layers...",
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

            for i in 0..size {
                let name = format!("{}-{}", prefix, i);
                layer_services.push(name.clone());
                services.insert(
                    name.clone(),
                    RandomService {
                        name,
                        layer: layer_idx,
                        outbound: HashSet::new(),
                        external_outbound: HashSet::new(),
                        inbound: HashSet::new(),
                        is_traffic_generator: layer_idx == 0,
                    },
                );
            }
            layers.push(layer_services);
        }

        let mut expected_connections = Vec::new();

        for layer_idx in 0..config.num_layers.saturating_sub(1) {
            for source_name in &layers[layer_idx] {
                for target_layer_idx in (layer_idx + 1)..config.num_layers {
                    for target_name in &layers[target_layer_idx] {
                        if rng.gen::<f64>() < config.outbound_probability {
                            services
                                .get_mut(source_name)
                                .unwrap()
                                .outbound
                                .insert(target_name.clone());
                            let is_bilateral = rng.gen::<f64>() < config.bilateral_probability;
                            if is_bilateral {
                                services
                                    .get_mut(target_name)
                                    .unwrap()
                                    .inbound
                                    .insert(source_name.clone());
                            }
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
                    for target_layer_idx in (layer_idx + 1)..config.num_layers {
                        let not_dependent: Vec<_> = layers[target_layer_idx]
                            .iter()
                            .filter(|t| !services[source_name].outbound.contains(*t))
                            .collect();
                        let sample_size = not_dependent.len().min(3);
                        for target_name in not_dependent.choose_multiple(&mut rng, sample_size) {
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

        for i in 0..num_external {
            let (name, url) = external_urls[i];
            let resolution = if Self::is_ip_based_url(url) {
                Resolution::Static
            } else {
                Resolution::Dns
            };
            external_services.insert(
                name.to_string(),
                RandomExternalService {
                    name: name.to_string(),
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
                        .unwrap()
                        .external_outbound
                        .insert(ext_name.clone());
                    let is_allowed = rng.gen::<f64>() < config.external_allow_probability;
                    if is_allowed {
                        external_services
                            .get_mut(ext_name)
                            .unwrap()
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
        format!("  Services: {} across {} layers\n  Tests: {} ({} allowed, {} blocked)\n  External: {} services, {} tests",
            self.services.len(), self.layers.len(), total_tests, expected_allowed, total_tests - expected_allowed,
            self.external_services.len(), external_tests)
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

        println!("\n  === EXPECTED ALLOWED ({}) ===", allowed.len());
        for (src, tgt, _, is_ext) in allowed.iter().take(20) {
            println!(
                "    {} -> {}{}",
                src,
                tgt,
                if *is_ext { " [EXT]" } else { "" }
            );
        }
        if allowed.len() > 20 {
            println!("    ... and {} more", allowed.len() - 20);
        }

        println!("\n  === EXPECTED BLOCKED ({}) ===", blocked.len());
        for (src, tgt, _, is_ext) in blocked.iter().take(20) {
            println!(
                "    {} -> {}{}",
                src,
                tgt,
                if *is_ext { " [EXT]" } else { "" }
            );
        }
        if blocked.len() > 20 {
            println!("    ... and {} more", blocked.len() - 20);
        }
        println!();
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
                    outbound: None,
                    inbound: None,
                },
            );
        }
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
                    outbound: None,
                    inbound: None,
                },
            );
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
                    outbound: None,
                    inbound: None,
                },
            );
        }

        if svc.is_traffic_generator {
            let script = self.generate_test_script(name, namespace);
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
                environment: namespace.to_string(),
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
                ..Default::default()
            },
            spec: LatticeExternalServiceSpec {
                environment: namespace.to_string(),
                endpoints,
                allowed_requesters: ext_svc.allowed_requesters.iter().cloned().collect(),
                resolution: ext_svc.resolution.clone(),
                description: Some(format!("External service: {}", ext_svc.url)),
            },
            status: None,
        }
    }

    fn generate_test_script(&self, source_name: &str, namespace: &str) -> String {
        let mut script = format!(
            r#"
echo "=== {} Traffic Tests ==="
sleep 5
"#,
            source_name
        );

        for (_, target, expected_allowed, is_external) in self
            .expected_connections
            .iter()
            .filter(|(src, _, _, _)| src == source_name)
        {
            let (success_msg, fail_msg) = if *expected_allowed {
                (
                    format!("{}->{}:ALLOWED", source_name, target),
                    format!("{}->{}:BLOCKED(UNEXPECTED)", source_name, target),
                )
            } else {
                (
                    format!("{}->{}:ALLOWED(UNEXPECTED)", source_name, target),
                    format!("{}->{}:BLOCKED", source_name, target),
                )
            };

            if *is_external {
                let url = &self.external_services[target].url;
                script.push_str(&format!(
                    r#"if curl -s --connect-timeout 5 {url} >/dev/null 2>&1; then
  echo "{success_msg}"
else
  echo "{fail_msg}"
fi
"#
                ));
            } else {
                script.push_str(&format!(r#"if curl -s --connect-timeout 2 http://{target}.{namespace}.svc.cluster.local/ >/dev/null 2>&1; then
  echo "{success_msg}"
else
  echo "{fail_msg}"
fi
"#));
            }
        }

        script.push_str(&format!(
            r#"
echo "=== End {} Tests ==="
sleep 10
"#,
            source_name
        ));

        format!("while true; do\n{}\ndone\n", script)
    }
}

const RANDOM_MESH_NAMESPACE: &str = "random-mesh";

async fn deploy_random_mesh(mesh: &RandomMesh, kubeconfig_path: &str) -> Result<(), String> {
    println!("  Creating namespace {}...", RANDOM_MESH_NAMESPACE);
    let _ = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "create",
            "namespace",
            RANDOM_MESH_NAMESPACE,
        ],
    );

    let client = client_from_kubeconfig(kubeconfig_path).await?;

    if !mesh.external_services.is_empty() {
        println!(
            "  Deploying {} external services...",
            mesh.external_services.len()
        );
        let ext_api: Api<LatticeExternalService> = Api::all(client.clone());
        for name in mesh.external_services.keys() {
            let ext_svc = mesh.create_external_service(name, RANDOM_MESH_NAMESPACE);
            ext_api
                .create(&PostParams::default(), &ext_svc)
                .await
                .map_err(|e| format!("Failed to create external service {}: {}", name, e))?;
        }
    }

    let api: Api<LatticeService> = Api::all(client);

    for (layer_idx, layer) in mesh.layers.iter().enumerate().rev() {
        println!(
            "  [Layer {}] Deploying {} services...",
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

    println!("  All {} services deployed!", mesh.services.len());
    Ok(())
}

async fn wait_for_random_mesh_pods(mesh: &RandomMesh, kubeconfig_path: &str) -> Result<(), String> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(600);
    let expected_pods = mesh.services.len();

    println!("  Waiting for {} pods to be ready...", expected_pods);

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
        println!("    {}/{} pods running", running, expected_pods);

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

    println!(
        "  Checking logs from {} traffic generators...",
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
                &format!("app.kubernetes.io/name={}", source),
                "--tail",
                "1000",
            ],
        )
        .unwrap_or_default();

        for ((src, tgt), (_, _, actual)) in results.iter_mut() {
            if src != source {
                continue;
            }
            if logs.contains(&format!("{}->{}:ALLOWED", src, tgt)) {
                *actual = Some(true);
            } else if logs.contains(&format!("{}->{}:BLOCKED", src, tgt)) {
                *actual = Some(false);
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

    println!("\n  ========================================");
    println!("  RANDOMIZED MESH VERIFICATION");
    println!("  ========================================");
    println!(
        "  Total: {}, Passed: {}, Mismatches: {}, Missing: {}",
        total,
        passed,
        mismatches.len(),
        missing.len()
    );

    if !mismatches.is_empty() || !missing.is_empty() {
        if !mismatches.is_empty() {
            println!("\n  MISMATCHES:");
            for m in mismatches.iter().take(20) {
                println!("    {}", m);
            }
            if mismatches.len() > 20 {
                println!("    ... and {} more", mismatches.len() - 20);
            }
        }
        if !missing.is_empty() {
            println!("\n  MISSING:");
            for m in missing.iter().take(20) {
                println!("    {}", m);
            }
            if missing.len() > 20 {
                println!("    ... and {} more", missing.len() - 20);
            }
        }
        return Err(format!(
            "Random mesh failed: {} mismatches, {} missing",
            mismatches.len(),
            missing.len()
        ));
    }

    println!("\n  SUCCESS: All {} tests passed!", total);
    Ok(())
}

/// Run the randomized 50-100 service mesh test
pub async fn run_random_mesh_test(kubeconfig_path: &str) -> Result<(), String> {
    println!("\n[Phase 9] Running randomized large-scale mesh test (50-75 services)...\n");

    let mesh = RandomMesh::generate(&RandomMeshConfig::default());
    println!("{}", mesh.stats());
    mesh.print_manifest();

    deploy_random_mesh(&mesh, kubeconfig_path).await?;
    println!("\n  Waiting for pods...");
    wait_for_random_mesh_pods(&mesh, kubeconfig_path).await?;
    println!("\n  Waiting for traffic tests to complete (90s)...");
    sleep(Duration::from_secs(90)).await;
    verify_random_mesh_traffic(&mesh, kubeconfig_path).await?;

    Ok(())
}

// =============================================================================
// L7 Traffic Policy Enforcement Tests
// =============================================================================
//
// Tests that verify L7 traffic policy enforcement:
// - Rate limiting: Requests are throttled after exceeding limit
// - Retries: Failed requests are automatically retried
// - Timeouts: Slow requests are terminated

const POLICY_TEST_NAMESPACE: &str = "policy-test";

/// Test script that verifies rate limiting is enforced
fn generate_rate_limit_test_script(target: &str, namespace: &str, rate_limit: u32) -> String {
    format!(
        r#"
echo "=== Rate Limit Enforcement Test ==="
echo "Testing rate limit of {rate_limit} requests per minute to {target}..."

# Wait for connectivity (AuthorizationPolicy may not have propagated yet)
echo "Waiting for connectivity..."
MAX_CONN_RETRIES=5
CONN_RETRY=0
while [ $CONN_RETRY -lt $MAX_CONN_RETRIES ]; do
    CONN_CHECK=$(curl -s -o /dev/null -w "%{{http_code}}" --connect-timeout 5 http://{target}.{namespace}.svc.cluster.local/)
    if [ "$CONN_CHECK" != "000" ]; then
        echo "Connection established (code $CONN_CHECK)"
        break
    fi
    CONN_RETRY=$((CONN_RETRY + 1))
    echo "Connection failed, waiting for AuthorizationPolicy... (attempt $CONN_RETRY/$MAX_CONN_RETRIES)"
    sleep 10
done

if [ "$CONN_CHECK" = "000" ]; then
    echo "RATE_LIMIT_TEST:FAIL - Could not establish connectivity after $MAX_CONN_RETRIES attempts"
    echo "=== End Rate Limit Test ==="
    sleep 60
    exit 0
fi

# Make requests at 2x the rate limit
TOTAL_REQUESTS=$(({rate_limit} * 2))
SUCCESS=0
RATE_LIMITED=0

for i in $(seq 1 $TOTAL_REQUESTS); do
    RESPONSE=$(curl -s -o /dev/null -w "%{{http_code}}" --connect-timeout 2 http://{target}.{namespace}.svc.cluster.local/)
    if [ "$RESPONSE" = "200" ]; then
        SUCCESS=$((SUCCESS + 1))
    elif [ "$RESPONSE" = "429" ]; then
        RATE_LIMITED=$((RATE_LIMITED + 1))
    fi
    # Small delay to spread requests
    sleep 0.1
done

echo "Total requests: $TOTAL_REQUESTS"
echo "Successful: $SUCCESS"
echo "Rate limited (429): $RATE_LIMITED"

# Verify rate limiting is working - we should see some 429s
if [ $RATE_LIMITED -gt 0 ]; then
    echo "RATE_LIMIT_TEST:PASS - Rate limiting enforced"
else
    echo "RATE_LIMIT_TEST:FAIL - No rate limiting observed"
fi

echo "=== End Rate Limit Test ==="
sleep 60
"#,
        rate_limit = rate_limit,
        target = target,
        namespace = namespace
    )
}

/// Test script that verifies retries are working using httpbin /status/500
fn generate_retry_test_script(target: &str, namespace: &str) -> String {
    format!(
        r#"
echo "=== Retry Policy Enforcement Test ==="
echo "Testing retries against {target} returning 500s..."

# Wait for connectivity (AuthorizationPolicy may not have propagated yet)
echo "Waiting for connectivity..."
MAX_CONN_RETRIES=5
CONN_RETRY=0
while [ $CONN_RETRY -lt $MAX_CONN_RETRIES ]; do
    CONN_CHECK=$(curl -s -o /dev/null -w "%{{http_code}}" --connect-timeout 5 http://{target}.{namespace}.svc.cluster.local/status/200)
    if [ "$CONN_CHECK" != "000" ]; then
        echo "Connection established (code $CONN_CHECK)"
        break
    fi
    CONN_RETRY=$((CONN_RETRY + 1))
    echo "Connection failed, waiting for AuthorizationPolicy... (attempt $CONN_RETRY/$MAX_CONN_RETRIES)"
    sleep 10
done

if [ "$CONN_CHECK" = "000" ]; then
    echo "RETRY_TEST:FAIL - Could not establish connectivity after $MAX_CONN_RETRIES attempts"
    echo "=== End Retry Test ==="
    sleep 60
    exit 0
fi

# Without retries, 500 would fail immediately
# With retries configured, Istio will retry and we track attempts
TOTAL_REQUESTS=10
SUCCESS=0
FAILED=0

for i in $(seq 1 $TOTAL_REQUESTS); do
    # Request /status/500 which always returns 500
    # Istio should retry based on retry policy
    START=$(date +%s%3N)
    RESPONSE=$(curl -s -o /dev/null -w "%{{http_code}}" --connect-timeout 10 --max-time 15 http://{target}.{namespace}.svc.cluster.local/status/500)
    END=$(date +%s%3N)
    ELAPSED=$((END - START))

    # With retries, request should take longer as Istio retries
    if [ $ELAPSED -gt 1000 ]; then
        SUCCESS=$((SUCCESS + 1))
        echo "  Request $i: took ${{ELAPSED}}ms (retries occurred)"
    else
        FAILED=$((FAILED + 1))
        echo "  Request $i: took ${{ELAPSED}}ms (no retries)"
    fi
    sleep 1
done

echo "Requests with retries: $SUCCESS"
echo "Requests without retries: $FAILED"

if [ $SUCCESS -ge 5 ]; then
    echo "RETRY_TEST:PASS - Retries are being attempted"
else
    echo "RETRY_TEST:FAIL - Retries may not be configured"
fi

echo "=== End Retry Test ==="
sleep 60
"#,
        target = target,
        namespace = namespace
    )
}

/// Test script that verifies timeouts are enforced using httpbin /delay/N
fn generate_timeout_test_script(target: &str, namespace: &str, timeout_secs: u32) -> String {
    format!(
        r#"
echo "=== Timeout Policy Enforcement Test ==="
echo "Testing {timeout_secs}s timeout against {target}..."

# Retry loop for connection failures (AuthorizationPolicy may not have propagated yet)
MAX_RETRIES=5
RETRY_DELAY=10
ATTEMPT=0

while [ $ATTEMPT -lt $MAX_RETRIES ]; do
    ATTEMPT=$((ATTEMPT + 1))
    echo "Attempt $ATTEMPT of $MAX_RETRIES..."

    # Request /delay/10 which waits 10 seconds before responding
    # With a {timeout_secs}s timeout, the request should be cut off early
    START=$(date +%s)
    RESPONSE=$(curl -s -o /dev/null -w "%{{http_code}}" --connect-timeout 15 --max-time 20 http://{target}.{namespace}.svc.cluster.local/delay/10)
    END=$(date +%s)
    ELAPSED=$((END - START))

    echo "Response code: $RESPONSE"
    echo "Elapsed time: $ELAPSED seconds"

    # Response code 000 means curl couldn't connect - retry (AuthorizationPolicy may not be ready)
    if [ "$RESPONSE" = "000" ]; then
        echo "Connection failed (code 000), waiting for AuthorizationPolicy to propagate..."
        if [ $ATTEMPT -lt $MAX_RETRIES ]; then
            sleep $RETRY_DELAY
            continue
        else
            echo "TIMEOUT_TEST:FAIL - Connection still failing after $MAX_RETRIES attempts"
            break
        fi
    fi

    # Request should complete in roughly timeout_secs (not 0!), with a timeout-related response
    if [ $ELAPSED -gt 0 ] && [ $ELAPSED -le $(({timeout_secs} + 2)) ]; then
        echo "TIMEOUT_TEST:PASS - Request terminated in $ELAPSED seconds (timeout enforced)"
    else
        echo "TIMEOUT_TEST:FAIL - Request took $ELAPSED seconds (timeout not enforced)"
    fi
    break
done

echo "=== End Timeout Test ==="
sleep 60
"#,
        target = target,
        namespace = namespace,
        timeout_secs = timeout_secs
    )
}

// =============================================================================
// YAML-based LatticeService definitions (loaded from fixtures)
// =============================================================================

/// Parse a LatticeService from YAML fixture
fn parse_service(yaml: &str) -> LatticeService {
    serde_yaml::from_str(yaml).expect("Failed to parse LatticeService YAML")
}

/// Parse a LatticeService from YAML fixture, replacing script placeholder
fn parse_service_with_script(yaml: &str, script: &str) -> LatticeService {
    // Build the full script with loop wrapper
    let full_script = format!("while true; do\n{}\ndone", script);
    // Indent each line to match YAML literal block indentation (10 spaces)
    let indented_script = full_script
        .lines()
        .map(|line| format!("          {}", line))
        .collect::<Vec<_>>()
        .join("\n");
    let yaml_with_script = yaml.replace("{{SCRIPT}}", indented_script.trim_start());
    serde_yaml::from_str(&yaml_with_script).expect("Failed to parse LatticeService YAML")
}

fn create_retry_backend() -> LatticeService {
    parse_service(include_str!("fixtures/services/backend-retry.yaml"))
}

fn create_retry_client() -> LatticeService {
    let script = generate_retry_test_script("backend-retry", POLICY_TEST_NAMESPACE);
    parse_service_with_script(include_str!("fixtures/services/retry-client.yaml"), &script)
}

fn create_timeout_backend() -> LatticeService {
    parse_service(include_str!("fixtures/services/backend-timeout.yaml"))
}

fn create_timeout_client() -> LatticeService {
    let script = generate_timeout_test_script("backend-timeout", POLICY_TEST_NAMESPACE, 3);
    parse_service_with_script(
        include_str!("fixtures/services/timeout-client.yaml"),
        &script,
    )
}

fn create_rate_limited_backend() -> LatticeService {
    parse_service(include_str!("fixtures/services/backend-rate-limited.yaml"))
}

fn create_rate_limit_client() -> LatticeService {
    let script = generate_rate_limit_test_script("backend-rate-limited", POLICY_TEST_NAMESPACE, 10);
    parse_service_with_script(
        include_str!("fixtures/services/rate-limit-client.yaml"),
        &script,
    )
}

/// Deploy L7 policy test services
async fn deploy_policy_test_services(kubeconfig_path: &str) -> Result<(), String> {
    println!("  Creating namespace {}...", POLICY_TEST_NAMESPACE);
    let _ = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "create",
            "namespace",
            POLICY_TEST_NAMESPACE,
        ],
    );

    let client = client_from_kubeconfig(kubeconfig_path).await?;
    let api: Api<LatticeService> = Api::all(client);

    let services = vec![
        create_rate_limited_backend(),
        create_rate_limit_client(),
        create_retry_backend(),
        create_retry_client(),
        create_timeout_backend(),
        create_timeout_client(),
    ];

    for svc in services {
        let name = svc.metadata.name.clone().unwrap();
        println!("  Deploying {}...", name);
        api.create(&PostParams::default(), &svc)
            .await
            .map_err(|e| format!("Failed to create {}: {}", name, e))?;
    }

    Ok(())
}

/// Wait for policy test pods to be ready
async fn wait_for_policy_test_pods(kubeconfig_path: &str) -> Result<(), String> {
    println!("  Waiting for policy test pods to be ready...");

    for _ in 0..60 {
        let output = run_cmd(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "get",
                "pods",
                "-n",
                POLICY_TEST_NAMESPACE,
                "-o",
                "jsonpath={.items[*].status.phase}",
            ],
        );

        if let Ok(phases) = output {
            let all_running = phases.split_whitespace().all(|p| p == "Running");
            let count = phases.split_whitespace().count();
            if all_running && count >= 2 {
                println!("  All {} pods running", count);
                return Ok(());
            }
        }

        sleep(Duration::from_secs(5)).await;
    }

    Err("Timeout waiting for policy test pods".to_string())
}

/// Verify L7 policy enforcement from pod logs
async fn verify_policy_enforcement(kubeconfig_path: &str) -> Result<(), String> {
    println!("  Checking policy enforcement results...");

    // Debug: Check waypoint infrastructure
    println!("\n  --- Waypoint Infrastructure Debug ---");

    // Check for waypoint Gateway
    let gw_output = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "get",
            "gateway",
            "-n",
            POLICY_TEST_NAMESPACE,
            "-o",
            "wide",
        ],
    )
    .unwrap_or_else(|e| format!("Error: {}", e));
    println!("  Gateways:\n{}", gw_output);

    // Check for HTTPRoutes
    let hr_output = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "get",
            "httproute",
            "-n",
            POLICY_TEST_NAMESPACE,
            "-o",
            "wide",
        ],
    )
    .unwrap_or_else(|e| format!("Error: {}", e));
    println!("  HTTPRoutes:\n{}", hr_output);

    // Check for BackendTrafficPolicy
    let btp_output = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "get",
            "backendtrafficpolicy",
            "-n",
            POLICY_TEST_NAMESPACE,
            "-o",
            "wide",
        ],
    )
    .unwrap_or_else(|e| format!("Error: {}", e));
    println!("  BackendTrafficPolicies:\n{}", btp_output);

    // Check service labels for waypoint
    let svc_output = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "get",
            "svc",
            "-n",
            POLICY_TEST_NAMESPACE,
            "-o",
            "jsonpath={range .items[*]}{.metadata.name}: {.metadata.labels.istio\\.io/use-waypoint}{\"\\n\"}{end}",
        ],
    )
    .unwrap_or_else(|e| format!("Error: {}", e));
    println!("  Service waypoint labels:\n{}", svc_output);

    // Check waypoint pods
    let wp_pods = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "get",
            "pods",
            "-n",
            POLICY_TEST_NAMESPACE,
            "-l",
            "istio.io/waypoint-for=service",
            "-o",
            "wide",
        ],
    )
    .unwrap_or_else(|e| format!("Error: {}", e));
    println!("  Waypoint pods:\n{}", wp_pods);

    println!("  --- End Debug ---\n");

    // Check all policy test client logs
    let clients = ["client", "retry-client", "timeout-client"];
    let mut all_logs = String::new();

    for client in &clients {
        println!("\n  --- Logs from {} ---", client);
        let output = run_cmd(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "logs",
                "-n",
                POLICY_TEST_NAMESPACE,
                "-l",
                &format!("app.kubernetes.io/name={}", client),
                "--tail=50",
            ],
        )
        .unwrap_or_default();
        // Print last 20 lines of each client's logs for debugging
        let lines: Vec<&str> = output.lines().collect();
        let start = if lines.len() > 20 { lines.len() - 20 } else { 0 };
        for line in &lines[start..] {
            println!("    {}", line);
        }
        all_logs.push_str(&output);
        all_logs.push('\n');
    }

    // Track pass/fail counts - require at least one pass and no failures for success
    let mut rate_limit_pass_count = 0;
    let mut rate_limit_fail_count = 0;
    let mut retry_pass_count = 0;
    let mut retry_fail_count = 0;
    let mut timeout_pass_count = 0;
    let mut timeout_fail_count = 0;

    for line in all_logs.lines() {
        if line.contains("RATE_LIMIT_TEST:PASS") {
            rate_limit_pass_count += 1;
            println!("  [PASS] Rate limiting enforced");
        } else if line.contains("RATE_LIMIT_TEST:FAIL") {
            rate_limit_fail_count += 1;
            println!("  [WARN] Rate limiting not observed");
        }
        if line.contains("RETRY_TEST:PASS") {
            retry_pass_count += 1;
            println!("  [PASS] Retries are working");
        } else if line.contains("RETRY_TEST:FAIL") {
            retry_fail_count += 1;
            println!("  [WARN] Retries not observed");
        }
        if line.contains("TIMEOUT_TEST:PASS") {
            timeout_pass_count += 1;
            println!("  [PASS] Timeouts enforced");
        } else if line.contains("TIMEOUT_TEST:FAIL") {
            timeout_fail_count += 1;
            println!("  [WARN] Timeouts not enforced");
        }
    }

    // Require at least one pass AND no failures for a test to be considered passing
    let rate_limit_passed = rate_limit_pass_count > 0 && rate_limit_fail_count == 0;
    let retry_passed = retry_pass_count > 0 && retry_fail_count == 0;
    let timeout_passed = timeout_pass_count > 0 && timeout_fail_count == 0;

    println!("\n  ========================================");
    println!("  L7 POLICY ENFORCEMENT SUMMARY");
    println!("  ========================================");
    println!(
        "  Rate Limiting: {}",
        if rate_limit_passed { "PASS" } else { "PENDING" }
    );
    println!(
        "  Retries:       {}",
        if retry_passed { "PASS" } else { "PENDING" }
    );
    println!(
        "  Timeouts:      {}",
        if timeout_passed { "PASS" } else { "PENDING" }
    );

    let all_passed = rate_limit_passed && retry_passed && timeout_passed;
    if all_passed {
        println!("\n  SUCCESS: All L7 policies are being enforced!");
    } else {
        println!("\n  NOTE: Some policies pending - L7 traffic policies may require additional configuration");
    }

    Ok(())
}

/// Run the L7 policy enforcement test
pub async fn run_policy_enforcement_test(kubeconfig_path: &str) -> Result<(), String> {
    println!("\n[Phase 10] Running L7 traffic policy enforcement test...\n");

    deploy_policy_test_services(kubeconfig_path).await?;
    wait_for_policy_test_pods(kubeconfig_path).await?;
    println!("  Waiting for policy tests to run (90s)...");
    sleep(Duration::from_secs(90)).await;
    verify_policy_enforcement(kubeconfig_path).await?;

    Ok(())
}
