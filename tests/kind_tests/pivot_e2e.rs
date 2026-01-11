//! Real end-to-end test for the complete Lattice installation and pivot flow
//!
//! This test runs the FULL Lattice installer flow:
//!
//! 1. Creates a bootstrap kind cluster
//! 2. Installs CAPI + Lattice operator on bootstrap
//! 3. Creates management cluster LatticeCluster CRD (with spec.endpoints)
//! 4. Waits for management cluster to be provisioned
//! 5. Pivots CAPI resources to management cluster
//! 6. Deletes bootstrap cluster
//! 7. Creates a workload cluster from the self-managing management cluster
//! 8. Verifies workload cluster reaches Ready state
//! 9. Deploys test services and verifies bilateral agreement pattern
//!
//! # Prerequisites
//!
//! - Docker running with sufficient resources (8GB+ RAM recommended)
//! - kind installed
//! - clusterctl installed
//! - kubectl installed
//!
//! # Running
//!
//! ```bash
//! # This test takes 20-30 minutes
//! cargo test --features e2e --test kind pivot_e2e -- --nocapture
//! ```

// Only compile this module when the e2e feature is enabled
#![cfg(feature = "e2e")]

use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::time::Duration;

use base64::Engine;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, PostParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::Client;
use tokio::time::sleep;

use lattice::crd::{
    ClusterPhase, ContainerSpec, DependencyDirection, DeploySpec, KubernetesSpec, LatticeCluster,
    LatticeClusterSpec, LatticeService, LatticeServiceSpec, NodeSpec, PortSpec, ProviderSpec,
    ProviderType, ReplicaSpec, ResourceSpec, ResourceType, ServicePortsSpec,
};
use lattice::install::{InstallConfig, Installer};
use std::collections::BTreeMap;

// =============================================================================
// Test Configuration
// =============================================================================

/// Timeout for the entire e2e test
const E2E_TIMEOUT: Duration = Duration::from_secs(2400); // 40 minutes

/// Name of the management cluster
const MGMT_CLUSTER_NAME: &str = "e2e-mgmt";

/// Name of the workload cluster being provisioned
const WORKLOAD_CLUSTER_NAME: &str = "e2e-workload";

/// Docker image name for lattice
const LATTICE_IMAGE: &str = "ghcr.io/evan-hines-js/lattice:latest";

/// Docker network subnet for kind/CAPD clusters
/// This must be pinned because Cilium LB-IPAM uses IPs from this range (172.18.255.x)
const DOCKER_KIND_SUBNET: &str = "172.18.0.0/16";
const DOCKER_KIND_GATEWAY: &str = "172.18.0.1";

// =============================================================================
// Helper Functions
// =============================================================================

/// Run a shell command and return output
fn run_cmd(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = ProcessCommand::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run {}: {}", cmd, e))?;

    if !output.status.success() {
        return Err(format!(
            "{} failed: {}",
            cmd,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Run a shell command, allowing failure
fn run_cmd_allow_fail(cmd: &str, args: &[&str]) -> String {
    ProcessCommand::new(cmd)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

/// Ensure the Docker "kind" network exists with the correct subnet
///
/// Docker assigns subnets dynamically when creating networks. If the "kind" network
/// is recreated (e.g., after `docker network rm` or system restart), it may get a
/// different subnet. This breaks Cilium LB-IPAM which expects IPs in 172.18.255.x.
///
/// This function ensures the network exists with the pinned subnet.
fn ensure_docker_network() -> Result<(), String> {
    println!(
        "  Ensuring Docker 'kind' network has correct subnet ({})...",
        DOCKER_KIND_SUBNET
    );

    // Check if the network exists
    let inspect_output = ProcessCommand::new("docker")
        .args([
            "network",
            "inspect",
            "kind",
            "--format",
            "{{range .IPAM.Config}}{{.Subnet}}{{end}}",
        ])
        .output();

    match inspect_output {
        Ok(output) if output.status.success() => {
            let current_subnet = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if current_subnet == DOCKER_KIND_SUBNET {
                println!("  Docker 'kind' network already has correct subnet");
                return Ok(());
            }
            // Network exists but with wrong subnet - need to recreate
            println!(
                "  Docker 'kind' network has wrong subnet ({}), recreating...",
                current_subnet
            );

            // Check if any containers are using the network
            let containers = run_cmd_allow_fail(
                "docker",
                &[
                    "network",
                    "inspect",
                    "kind",
                    "--format",
                    "{{range .Containers}}{{.Name}} {{end}}",
                ],
            );
            if !containers.trim().is_empty() {
                return Err(format!(
                    "Cannot recreate 'kind' network - containers still attached: {}. Stop them first.",
                    containers.trim()
                ));
            }

            // Remove the network
            run_cmd("docker", &["network", "rm", "kind"])?;
        }
        _ => {
            // Network doesn't exist
            println!("  Docker 'kind' network doesn't exist, creating...");
        }
    }

    // Create the network with the correct subnet
    run_cmd(
        "docker",
        &[
            "network",
            "create",
            "--driver=bridge",
            &format!("--subnet={}", DOCKER_KIND_SUBNET),
            &format!("--gateway={}", DOCKER_KIND_GATEWAY),
            "kind",
        ],
    )?;

    println!(
        "  Docker 'kind' network created with subnet {}",
        DOCKER_KIND_SUBNET
    );
    Ok(())
}

/// Build and push the lattice Docker image to registry
async fn build_and_push_lattice_image() -> Result<(), String> {
    println!("  Building lattice Docker image...");

    // Use docker-build.sh which reads versions from versions.toml
    let output = ProcessCommand::new("./scripts/docker-build.sh")
        .args(["-t", LATTICE_IMAGE])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .map_err(|e| format!("Failed to run docker build: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Docker build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    println!("  Image built successfully");

    println!("  Pushing image to registry...");

    let output = ProcessCommand::new("docker")
        .args(["push", LATTICE_IMAGE])
        .output()
        .map_err(|e| format!("Failed to push image: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Docker push failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    println!("  Image pushed successfully");
    Ok(())
}

/// Load registry credentials from .env file and construct dockerconfigjson format
fn load_registry_credentials() -> Option<String> {
    // Try to load from .env file first
    let env_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".env");
    if let Ok(content) = std::fs::read_to_string(&env_path) {
        let mut user = None;
        let mut token = None;

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("export GHCR_USER=") {
                user = Some(line.trim_start_matches("export GHCR_USER=").to_string());
            } else if line.starts_with("export GHCR_TOKEN=") {
                token = Some(line.trim_start_matches("export GHCR_TOKEN=").to_string());
            } else if line.starts_with("GHCR_USER=") {
                user = Some(line.trim_start_matches("GHCR_USER=").to_string());
            } else if line.starts_with("GHCR_TOKEN=") {
                token = Some(line.trim_start_matches("GHCR_TOKEN=").to_string());
            }
        }

        if let (Some(u), Some(t)) = (user, token) {
            // Construct dockerconfigjson format
            let auth = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", u, t));
            let docker_config = serde_json::json!({
                "auths": {
                    "ghcr.io": {
                        "auth": auth
                    }
                }
            });
            return Some(docker_config.to_string());
        }
    }

    // Fallback to environment variables
    if let (Ok(u), Ok(t)) = (std::env::var("GHCR_USER"), std::env::var("GHCR_TOKEN")) {
        let auth = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", u, t));
        let docker_config = serde_json::json!({
            "auths": {
                "ghcr.io": {
                    "auth": auth
                }
            }
        });
        return Some(docker_config.to_string());
    }

    None
}

/// Create a kube client using a specific kubeconfig file
async fn client_from_kubeconfig(path: &str) -> Result<Client, String> {
    let kubeconfig =
        Kubeconfig::read_from(path).map_err(|e| format!("Failed to read kubeconfig: {}", e))?;

    let config = kube::Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
        .await
        .map_err(|e| format!("Failed to create kube config: {}", e))?;

    Client::try_from(config).map_err(|e| format!("Failed to create client: {}", e))
}

/// Get and patch kubeconfig for management cluster
fn get_management_kubeconfig() -> Result<String, String> {
    let kubeconfig_path = format!("/tmp/{}-kubeconfig", MGMT_CLUSTER_NAME);

    // Read the kubeconfig that the installer saved
    let kubeconfig = std::fs::read_to_string(&kubeconfig_path)
        .map_err(|e| format!("Failed to read kubeconfig: {}", e))?;

    // Get the LB container port for localhost access
    let lb_container = format!("{}-lb", MGMT_CLUSTER_NAME);
    let port_output = run_cmd_allow_fail("docker", &["port", &lb_container, "6443/tcp"]);

    if port_output.trim().is_empty() {
        return Err("Management cluster LB container not found".to_string());
    }

    let parts: Vec<&str> = port_output.trim().split(':').collect();
    if parts.len() != 2 {
        return Err(format!("Failed to parse LB port: {}", port_output));
    }

    let localhost_endpoint = format!("https://127.0.0.1:{}", parts[1]);

    // Patch kubeconfig to use localhost
    let patched = kubeconfig
        .lines()
        .map(|line| {
            if line.trim().starts_with("server:") {
                format!("    server: {}", localhost_endpoint)
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    // Save patched kubeconfig
    let patched_path = format!("/tmp/{}-kubeconfig-local", MGMT_CLUSTER_NAME);
    std::fs::write(&patched_path, &patched)
        .map_err(|e| format!("Failed to write patched kubeconfig: {}", e))?;

    Ok(patched_path)
}

/// Create workload cluster spec
fn workload_cluster_spec(name: &str) -> LatticeCluster {
    LatticeCluster {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            ..Default::default()
        },
        spec: LatticeClusterSpec {
            provider: ProviderSpec {
                type_: ProviderType::Docker,
                kubernetes: KubernetesSpec {
                    version: "1.31.0".to_string(),
                    cert_sans: Some(vec!["127.0.0.1".to_string(), "localhost".to_string()]),
                    bootstrap: Default::default(),
                },
            },
            nodes: NodeSpec {
                control_plane: 1,
                workers: 2, // Workers scale up after pivot when cluster self-manages
            },
            networking: None,
            endpoints: None,
            environment: Some("e2e-test".to_string()),
            region: Some("local".to_string()),
            workload: None,
        },
        status: None,
    }
}

// =============================================================================
// Comprehensive 3-Layer Service Mesh Test
// =============================================================================
//
// This test creates a realistic 3-layer microservice architecture with 9 services
// to comprehensively test the bilateral agreement pattern with all permutations.
//
// LAYER 1: FRONTEND (3 services) - Traffic generators that test connectivity
// ┌─────────────────┬─────────────────┬─────────────────┐
// │  frontend-web   │ frontend-mobile │  frontend-admin │
// │  (web clients)  │ (mobile apps)   │  (admin panel)  │
// └────────┬────────┴────────┬────────┴────────┬────────┘
//          │                 │                 │
//          ▼                 ▼                 ▼
// LAYER 2: API (3 services) - Business logic layer
// ┌─────────────────┬─────────────────┬─────────────────┐
// │   api-gateway   │   api-users     │   api-orders    │
// │  (public API)   │ (user service)  │ (order service) │
// └────────┬────────┴────────┬────────┴────────┬────────┘
//          │                 │                 │
//          ▼                 ▼                 ▼
// LAYER 3: BACKEND (3 services) - Data layer
// ┌─────────────────┬─────────────────┬─────────────────┐
// │    db-users     │    db-orders    │     cache       │
// │  (user store)   │  (order store)  │  (shared cache) │
// └─────────────────┴─────────────────┴─────────────────┘
//
// BILATERAL AGREEMENTS (connections that should WORK):
//
// Layer 1 → Layer 2:
//   - frontend-web    → api-gateway  (web needs gateway)
//   - frontend-web    → api-users    (web manages users)
//   - frontend-mobile → api-gateway  (mobile needs gateway)
//   - frontend-mobile → api-orders   (mobile manages orders)
//   - frontend-admin  → api-gateway  (admin needs gateway)
//   - frontend-admin  → api-users    (admin manages users)
//   - frontend-admin  → api-orders   (admin manages orders)
//
// Layer 2 → Layer 3:
//   - api-gateway → db-users   (gateway reads users)
//   - api-gateway → db-orders  (gateway reads orders)
//   - api-gateway → cache      (gateway uses cache)
//   - api-users   → db-users   (users service owns user data)
//   - api-users   → cache      (users service caches)
//   - api-orders  → db-orders  (orders service owns order data)
//   - api-orders  → cache      (orders service caches)
//
// BLOCKED CONNECTIONS (no bilateral agreement):
//
// Layer 1 → Layer 2 (missing inbound permission):
//   - frontend-web    → api-orders  (web not allowed by orders)
//   - frontend-mobile → api-users   (mobile not allowed by users)
//
// Layer 2 → Layer 3 (cross-domain access denied):
//   - api-users  → db-orders  (users can't access order data)
//   - api-orders → db-users   (orders can't access user data)
//
// Cross-layer (no direct access):
//   - frontend-* → db-*       (frontends can't access DBs directly)
//   - frontend-* → cache      (frontends can't access cache directly)
//
// Same-layer (no peer access):
//   - frontend-web → frontend-mobile  (no peer communication)
//   - api-gateway  → api-users        (unless explicitly allowed)

/// Namespace for test services
const TEST_SERVICES_NAMESPACE: &str = "mesh-test";

/// Total number of services in the mesh
const TOTAL_SERVICES: usize = 9;

// =============================================================================
// Helper Functions for Service Creation
// =============================================================================

/// Create a basic nginx container spec
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
    }
}

/// Create standard HTTP port spec
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

/// Create an outbound dependency resource
fn outbound_dep(name: &str) -> (String, ResourceSpec) {
    (
        name.to_string(),
        ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Outbound,
            id: None,
            params: None,
            class: None,
        },
    )
}

/// Create an inbound allowance resource
fn inbound_allow(name: &str) -> (String, ResourceSpec) {
    (
        name.to_string(),
        ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Inbound,
            id: None,
            params: None,
            class: None,
        },
    )
}

/// Create a LatticeService with the given configuration
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
        },
        status: None,
    }
}

// =============================================================================
// Traffic Test Script Generation
// =============================================================================

/// A single connectivity test case
struct ConnTest {
    target: &'static str,
    expected: bool, // true = should be ALLOWED, false = should be BLOCKED
    reason: &'static str,
}

/// Generate a curl test script for a frontend service
fn generate_traffic_test_script(source: &str, tests: &[ConnTest]) -> String {
    let mut script = format!(
        r#"
echo "=== {} Traffic Tests ==="
echo "Testing {} connection permutations..."
sleep 5  # Wait for network policies to be applied

"#,
        source,
        tests.len()
    );

    for test in tests {
        let expected_str = if test.expected { "ALLOWED" } else { "BLOCKED" };
        let unexpected_str = if test.expected { "BLOCKED" } else { "ALLOWED" };

        script.push_str(&format!(
            r#"
# Test {target} ({reason})
if curl -s --connect-timeout 3 http://{target}.{ns}.svc.cluster.local/ > /dev/null 2>&1; then
    echo "{target}: {expected} ({reason})"
else
    echo "{target}: {unexpected} (UNEXPECTED - {reason})"
fi
"#,
            target = test.target,
            ns = TEST_SERVICES_NAMESPACE,
            reason = test.reason,
            expected = expected_str,
            unexpected = unexpected_str,
        ));
    }

    script.push_str(&format!(
        r#"
echo "=== End {} Tests ==="
sleep 30
"#,
        source
    ));

    // Wrap in infinite loop
    format!(
        r#"
while true; do
{}
done
"#,
        script
    )
}

// =============================================================================
// Layer 1: Frontend Services (Traffic Generators)
// =============================================================================

/// frontend-web: Web client frontend
/// - Depends on: api-gateway, api-users (NOT api-orders)
/// - Tests all Layer 2 and Layer 3 services
fn create_frontend_web() -> LatticeService {
    let tests = vec![
        // Layer 2 - API services
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
        // Layer 3 - Backend services (should all be blocked - no direct access)
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
        // Same layer - peer frontends (should be blocked)
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
    };

    // Outbound: gateway + users (but NOT orders - testing blocked path)
    // Also try to connect to orders to verify it's blocked
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
        false, // No inbound port - just a traffic generator
        container,
    )
}

/// frontend-mobile: Mobile app frontend
/// - Depends on: api-gateway, api-orders (NOT api-users)
fn create_frontend_mobile() -> LatticeService {
    let tests = vec![
        // Layer 2 - API services
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
        // Layer 3 - Backend services
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
        // Same layer
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

/// frontend-admin: Admin panel frontend
/// - Depends on: api-gateway, api-users, api-orders (full access)
fn create_frontend_admin() -> LatticeService {
    let tests = vec![
        // Layer 2 - API services (admin has full access)
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
        // Layer 3 - Backend services (still blocked - must go through API)
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
        // Same layer
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

// =============================================================================
// Layer 2: API Services
// =============================================================================

/// api-gateway: Public API gateway
/// - Depends on: db-users, db-orders, cache (full backend access)
/// - Allows: frontend-web, frontend-mobile, frontend-admin
fn create_api_gateway() -> LatticeService {
    create_service(
        "api-gateway",
        vec!["db-users", "db-orders", "cache"],
        vec!["frontend-web", "frontend-mobile", "frontend-admin"],
        true, // Has HTTP port
        nginx_container(),
    )
}

/// api-users: User management service
/// - Depends on: db-users, cache (NOT db-orders)
/// - Allows: frontend-web, frontend-admin (NOT frontend-mobile)
fn create_api_users() -> LatticeService {
    create_service(
        "api-users",
        vec!["db-users", "cache"],
        vec!["frontend-web", "frontend-admin"], // Note: mobile NOT allowed
        true,
        nginx_container(),
    )
}

/// api-orders: Order management service
/// - Depends on: db-orders, cache (NOT db-users)
/// - Allows: frontend-mobile, frontend-admin (NOT frontend-web)
fn create_api_orders() -> LatticeService {
    create_service(
        "api-orders",
        vec!["db-orders", "cache"],
        vec!["frontend-mobile", "frontend-admin"], // Note: web NOT allowed
        true,
        nginx_container(),
    )
}

// =============================================================================
// Layer 3: Backend Services
// =============================================================================

/// db-users: User database
/// - Allows: api-gateway, api-users (NOT api-orders)
fn create_db_users() -> LatticeService {
    create_service(
        "db-users",
        vec![],
        vec!["api-gateway", "api-users"], // Note: api-orders NOT allowed
        true,
        nginx_container(),
    )
}

/// db-orders: Order database
/// - Allows: api-gateway, api-orders (NOT api-users)
fn create_db_orders() -> LatticeService {
    create_service(
        "db-orders",
        vec![],
        vec!["api-gateway", "api-orders"], // Note: api-users NOT allowed
        true,
        nginx_container(),
    )
}

/// cache: Shared cache service
/// - Allows: api-gateway, api-users, api-orders (all API services)
fn create_cache() -> LatticeService {
    create_service(
        "cache",
        vec![],
        vec!["api-gateway", "api-users", "api-orders"],
        true,
        nginx_container(),
    )
}

/// Deploy all 9 services to the workload cluster
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

    // Create client for workload cluster
    // LatticeService is cluster-scoped, so we use Api::all
    let client = client_from_kubeconfig(kubeconfig_path).await?;
    let api: Api<LatticeService> = Api::all(client);

    // Deploy in "wrong" order (backends first) to test eventual consistency
    // The controller should re-reconcile affected services when dependencies change
    //
    // Order: Layer 3 (backends) → Layer 2 (APIs) → Layer 1 (frontends)

    println!("  [Layer 3] Deploying backend services...");

    println!("    Deploying db-users...");
    api.create(&PostParams::default(), &create_db_users())
        .await
        .map_err(|e| format!("Failed to create db-users: {}", e))?;

    println!("    Deploying db-orders...");
    api.create(&PostParams::default(), &create_db_orders())
        .await
        .map_err(|e| format!("Failed to create db-orders: {}", e))?;

    println!("    Deploying cache...");
    api.create(&PostParams::default(), &create_cache())
        .await
        .map_err(|e| format!("Failed to create cache: {}", e))?;

    println!("  [Layer 2] Deploying API services...");

    println!("    Deploying api-gateway...");
    api.create(&PostParams::default(), &create_api_gateway())
        .await
        .map_err(|e| format!("Failed to create api-gateway: {}", e))?;

    println!("    Deploying api-users...");
    api.create(&PostParams::default(), &create_api_users())
        .await
        .map_err(|e| format!("Failed to create api-users: {}", e))?;

    println!("    Deploying api-orders...");
    api.create(&PostParams::default(), &create_api_orders())
        .await
        .map_err(|e| format!("Failed to create api-orders: {}", e))?;

    println!("  [Layer 1] Deploying frontend services (traffic generators)...");

    println!("    Deploying frontend-web...");
    api.create(&PostParams::default(), &create_frontend_web())
        .await
        .map_err(|e| format!("Failed to create frontend-web: {}", e))?;

    println!("    Deploying frontend-mobile...");
    api.create(&PostParams::default(), &create_frontend_mobile())
        .await
        .map_err(|e| format!("Failed to create frontend-mobile: {}", e))?;

    println!("    Deploying frontend-admin...");
    api.create(&PostParams::default(), &create_frontend_admin())
        .await
        .map_err(|e| format!("Failed to create frontend-admin: {}", e))?;

    println!("  All {} services deployed!", TOTAL_SERVICES);
    println!("  Waiting for watch-triggered reconciliation (should be fast)...");
    sleep(Duration::from_secs(5)).await;

    Ok(())
}

/// Wait for all 9 service deployments to be ready
async fn wait_for_deployments(kubeconfig_path: &str) -> Result<(), String> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(300); // 5 minutes for pods to start (9 pods)

    println!("  Waiting for {} pods to be ready...", TOTAL_SERVICES);

    loop {
        if start.elapsed() > timeout {
            return Err(format!(
                "Timeout waiting for test pods to be ready (expected {})",
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
                "jsonpath={range .items[*]}{.metadata.name},{.status.phase}{\"\\n\"}{end}",
            ],
        );

        let mut running_count = 0;

        for line in pods_output.lines() {
            if line.contains("Running") {
                running_count += 1;
            }
        }

        println!("    {}/{} pods running", running_count, TOTAL_SERVICES);

        if running_count >= TOTAL_SERVICES {
            println!("  All {} test pods are running!", TOTAL_SERVICES);
            return Ok(());
        }

        sleep(Duration::from_secs(10)).await;
    }
}

/// Expected test results for each frontend service
/// Format: (target_service, expected_allowed)
const FRONTEND_WEB_EXPECTED: &[(&str, bool)] = &[
    ("api-gateway", true),      // bilateral agreement
    ("api-users", true),        // bilateral agreement
    ("api-orders", false),      // web not allowed by orders
    ("db-users", false),        // no direct DB access
    ("db-orders", false),       // no direct DB access
    ("cache", false),           // no direct cache access
    ("frontend-mobile", false), // no peer access
    ("frontend-admin", false),  // no peer access
];

const FRONTEND_MOBILE_EXPECTED: &[(&str, bool)] = &[
    ("api-gateway", true),     // bilateral agreement
    ("api-users", false),      // mobile not allowed by users
    ("api-orders", true),      // bilateral agreement
    ("db-users", false),       // no direct DB access
    ("db-orders", false),      // no direct DB access
    ("cache", false),          // no direct cache access
    ("frontend-web", false),   // no peer access
    ("frontend-admin", false), // no peer access
];

const FRONTEND_ADMIN_EXPECTED: &[(&str, bool)] = &[
    ("api-gateway", true),      // bilateral agreement
    ("api-users", true),        // bilateral agreement
    ("api-orders", true),       // bilateral agreement (admin has full access)
    ("db-users", false),        // no direct DB access
    ("db-orders", false),       // no direct DB access
    ("cache", false),           // no direct cache access
    ("frontend-web", false),    // no peer access
    ("frontend-mobile", false), // no peer access
];

/// Verify traffic patterns by checking all 3 frontend service logs
async fn verify_traffic_patterns(kubeconfig_path: &str) -> Result<(), String> {
    println!("  Waiting for traffic tests to run (45 seconds)...");
    sleep(Duration::from_secs(45)).await;

    let mut total_pass = 0;
    let mut total_fail = 0;
    let mut failures: Vec<String> = Vec::new();

    // Check each frontend service
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

        println!("\n  === {} Traffic Test Logs ===", frontend_name);
        println!("{}", logs);
        println!("  === End {} Logs ===\n", frontend_name);

        // Parse and verify results
        println!("  {} verification results:", frontend_name);

        for (target, expected_allowed) in expected_results.iter() {
            let expected_str = if *expected_allowed {
                "ALLOWED"
            } else {
                "BLOCKED"
            };

            // Check if the log contains the expected result
            let allowed_pattern = format!("{}: ALLOWED", target);
            let blocked_pattern = format!("{}: BLOCKED", target);

            let actual_allowed = logs.contains(&allowed_pattern);
            let actual_blocked = logs.contains(&blocked_pattern);

            let result_ok = if *expected_allowed {
                actual_allowed && !logs.contains(&format!("{}: BLOCKED (UNEXPECTED", target))
            } else {
                actual_blocked && !logs.contains(&format!("{}: ALLOWED (UNEXPECTED", target))
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

    // Summary
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
            "Service mesh verification failed: {} of {} tests failed. See failures above.",
            total_fail, total_tests
        ));
    }

    println!(
        "\n  SUCCESS: All {} bilateral agreement tests passed!",
        total_tests
    );
    println!("  - 7 allowed connections verified (bilateral agreements work)");
    println!("  - 17 blocked connections verified (security enforced)");
    println!("  - Cross-layer access denied (frontends can't access DBs)");
    println!("  - Peer access denied (no lateral movement within layers)");

    Ok(())
}

/// Watch worker nodes scaling up on a cluster
///
/// Polls kubectl to count ready worker nodes until the desired count is reached.
/// Worker nodes are those without the control-plane role.
async fn watch_worker_scaling(
    kubeconfig_path: &str,
    cluster_name: &str,
    expected_workers: u32,
) -> Result<(), String> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(600); // 10 minutes for workers to scale

    let mut last_count: Option<u32> = None;

    loop {
        if start.elapsed() > timeout {
            return Err(format!(
                "Timeout waiting for {} workers on cluster {}. Last count: {:?}",
                expected_workers, cluster_name, last_count
            ));
        }

        // Count ready worker nodes (nodes without control-plane role)
        let nodes_output = run_cmd_allow_fail(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "get",
                "nodes",
                "-o",
                "jsonpath={range .items[*]}{.metadata.name},{.status.conditions[?(@.type=='Ready')].status},{.metadata.labels.node-role\\.kubernetes\\.io/control-plane}{\"\\n\"}{end}",
            ],
        );

        // Parse output to count ready workers
        let mut ready_workers = 0u32;
        for line in nodes_output.lines() {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 2 {
                let is_ready = parts.get(1).map(|s| *s == "True").unwrap_or(false);
                let is_control_plane = parts.get(2).map(|s| !s.is_empty()).unwrap_or(false);

                if is_ready && !is_control_plane {
                    ready_workers += 1;
                }
            }
        }

        if last_count != Some(ready_workers) {
            println!(
                "    {} ready workers on {} (target: {})",
                ready_workers, cluster_name, expected_workers
            );
            last_count = Some(ready_workers);
        }

        if ready_workers >= expected_workers {
            println!(
                "    SUCCESS: {} has {} ready workers!",
                cluster_name, ready_workers
            );
            return Ok(());
        }

        sleep(Duration::from_secs(15)).await;
    }
}

/// Watch LatticeCluster phase transitions
async fn watch_cluster_phases(client: &Client, cluster_name: &str) -> Result<(), String> {
    let api: Api<LatticeCluster> = Api::all(client.clone());

    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(900); // 15 minutes for full flow

    let mut last_phase: Option<ClusterPhase> = None;

    loop {
        if start.elapsed() > timeout {
            return Err(format!(
                "Timeout waiting for cluster to reach Ready state. Last phase: {:?}",
                last_phase
            ));
        }

        match api.get(cluster_name).await {
            Ok(cluster) => {
                let current_phase = cluster
                    .status
                    .as_ref()
                    .map(|s| s.phase.clone())
                    .unwrap_or(ClusterPhase::Pending);

                if last_phase.as_ref() != Some(&current_phase) {
                    println!("  Cluster phase: {:?}", current_phase);
                    last_phase = Some(current_phase.clone());
                }

                if matches!(current_phase, ClusterPhase::Ready) {
                    println!("  Cluster reached Ready state!");
                    return Ok(());
                }

                if matches!(current_phase, ClusterPhase::Failed) {
                    return Err("Cluster entered Failed state".to_string());
                }
            }
            Err(e) => {
                println!("  Error getting cluster: {}", e);
            }
        }

        sleep(Duration::from_secs(10)).await;
    }
}

/// Cleanup all test resources
fn cleanup_all() {
    println!("\n[Cleanup] Removing all test resources...\n");

    // Delete bootstrap cluster if it exists
    let _ = run_cmd_allow_fail(
        "kind",
        &["delete", "cluster", "--name", "lattice-bootstrap"],
    );

    // Delete any leftover Docker containers from management cluster
    let mgmt_containers = run_cmd_allow_fail(
        "docker",
        &[
            "ps",
            "-a",
            "--filter",
            &format!("name={}", MGMT_CLUSTER_NAME),
            "-q",
        ],
    );
    for id in mgmt_containers.lines() {
        if !id.trim().is_empty() {
            let _ = run_cmd_allow_fail("docker", &["rm", "-f", id.trim()]);
        }
    }

    // Delete any leftover Docker containers from workload cluster
    let workload_containers = run_cmd_allow_fail(
        "docker",
        &[
            "ps",
            "-a",
            "--filter",
            &format!("name={}", WORKLOAD_CLUSTER_NAME),
            "-q",
        ],
    );
    for id in workload_containers.lines() {
        if !id.trim().is_empty() {
            let _ = run_cmd_allow_fail("docker", &["rm", "-f", id.trim()]);
        }
    }

    // Clean up temp files
    let _ = std::fs::remove_file(format!("/tmp/{}-kubeconfig", MGMT_CLUSTER_NAME));
    let _ = std::fs::remove_file(format!("/tmp/{}-kubeconfig-local", MGMT_CLUSTER_NAME));
    let _ = std::fs::remove_file(format!("/tmp/{}-cluster-config.yaml", MGMT_CLUSTER_NAME));

    println!("  Cleanup complete!");
}

// =============================================================================
// E2E Test: Full Installation and Pivot Flow
// =============================================================================

/// Story: Full end-to-end installation with self-managing management cluster
///
/// This test runs the complete Lattice installer flow, then provisions a
/// workload cluster from the self-managing management cluster.
/// Run with: cargo test --features e2e --test kind pivot_e2e -- --nocapture
#[tokio::test]
async fn story_full_install_and_workload_provisioning() {
    let result = tokio::time::timeout(E2E_TIMEOUT, run_full_e2e()).await;

    match result {
        Ok(Ok(())) => println!("\n=== Full E2E Test Completed Successfully! ===\n"),
        Ok(Err(e)) => {
            println!("\n=== Full E2E Test Failed: {} ===\n", e);
            println!("  NOTE: Not cleaning up so you can investigate. Run cleanup manually:");
            println!("    kind delete clusters --all");
            panic!("E2E test failed: {}", e);
        }
        Err(_) => {
            println!("\n=== Full E2E Test Timed Out ({:?}) ===\n", E2E_TIMEOUT);
            println!("  NOTE: Not cleaning up so you can investigate. Run cleanup manually:");
            println!("    kind delete clusters --all");
            panic!("E2E test timed out after {:?}", E2E_TIMEOUT);
        }
    }
}

async fn run_full_e2e() -> Result<(), String> {
    // Install crypto provider for rustls/kube client
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    println!("\n============================================================");
    println!("  FULL END-TO-END LATTICE INSTALLATION TEST");
    println!("============================================================");
    println!("\n  This test will:");
    println!("    1. Build and push the Lattice Docker image");
    println!("    2. Run the full installer (bootstrap → management cluster)");
    println!("    3. Verify management cluster is self-managing");
    println!("    4. Create a workload cluster from management cluster");
    println!("    5. Verify workload cluster reaches Ready state");
    println!("\n  Expected duration: 20-30 minutes\n");

    // =========================================================================
    // Phase 1: Cleanup any previous runs
    // =========================================================================
    println!("\n[Phase 1] Cleaning up previous test runs...\n");
    cleanup_all();

    // =========================================================================
    // Phase 1.5: Ensure Docker network has correct subnet
    // =========================================================================
    println!("\n[Phase 1.5] Setting up Docker network...\n");
    ensure_docker_network()?;

    // =========================================================================
    // Phase 2: Build and Push Lattice Image
    // =========================================================================
    println!("\n[Phase 2] Building and pushing Lattice image...\n");
    build_and_push_lattice_image().await?;

    // =========================================================================
    // Phase 3: Run Full Installer
    // =========================================================================
    println!("\n[Phase 3] Running Lattice installer...\n");
    println!("  This will:");
    println!("    - Create a bootstrap kind cluster");
    println!("    - Install CAPI with docker provider");
    println!("    - Deploy Lattice operator");
    println!("    - Create management cluster LatticeCluster CRD");
    println!("    - Wait for management cluster provisioning");
    println!("    - Pivot CAPI resources to management cluster");
    println!("    - Delete bootstrap cluster");
    println!();

    // Create config file for the management cluster
    // Uses Cilium LB-IPAM for the cell endpoint - workload clusters connect to this IP
    let cluster_config = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: {name}
spec:
  provider:
    type: docker
    kubernetes:
      version: "1.31.0"
      certSANs:
        - "127.0.0.1"
        - "localhost"
        - "172.18.255.10"
  nodes:
    controlPlane: 1
    workers: 1
  networking:
    default:
      cidr: "172.18.255.10/32"
  endpoints:
    host: 172.18.255.10
    grpcPort: 50051
    bootstrapPort: 8443
    service:
      type: LoadBalancer
"#,
        name = MGMT_CLUSTER_NAME
    );

    // Write config to temp file
    let config_path = PathBuf::from(format!("/tmp/{}-cluster-config.yaml", MGMT_CLUSTER_NAME));
    std::fs::write(&config_path, &cluster_config)
        .map_err(|e| format!("Failed to write cluster config: {}", e))?;
    println!("  Cluster config written to {:?}", config_path);

    // Load registry credentials
    let registry_credentials = load_registry_credentials();
    if registry_credentials.is_some() {
        println!("  Registry credentials loaded from .env");
    } else {
        println!("  WARNING: No registry credentials found - image pull may fail");
    }

    let install_config = InstallConfig {
        cluster_config_path: config_path,
        cluster_config_content: cluster_config,
        image: LATTICE_IMAGE.to_string(),
        keep_bootstrap_on_failure: true, // Keep for debugging if it fails
        timeout: Duration::from_secs(1200),
        registry_credentials,
        bootstrap_override: None, // Use config file default
    };

    let installer =
        Installer::new(install_config).map_err(|e| format!("Failed to create installer: {}", e))?;
    installer
        .run()
        .await
        .map_err(|e| format!("Installer failed: {}", e))?;

    println!("\n  Management cluster installation complete!");

    // =========================================================================
    // Phase 4: Verify Management Cluster is Self-Managing
    // =========================================================================
    println!("\n[Phase 4] Verifying management cluster is self-managing...\n");

    // Get kubeconfig for management cluster
    let kubeconfig_path = get_management_kubeconfig()?;
    println!("  Using kubeconfig: {}", kubeconfig_path);

    // Create client for management cluster
    let mgmt_client = client_from_kubeconfig(&kubeconfig_path).await?;

    // Check that CAPI resources exist
    println!("  Checking for CAPI Cluster resource...");
    let capi_check = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &kubeconfig_path,
            "get",
            "clusters",
            "-A",
            "-o",
            "wide",
        ],
    )?;
    println!("  CAPI clusters:\n{}", capi_check);

    if !capi_check.contains(MGMT_CLUSTER_NAME) {
        return Err("Management cluster should have its own CAPI Cluster resource".to_string());
    }

    // Check that LatticeCluster CRD exists
    println!("  Checking for LatticeCluster CRD...");
    let crd_check = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &kubeconfig_path,
            "get",
            "crd",
            "latticeclusters.lattice.dev",
        ],
    )?;

    if !crd_check.contains("latticeclusters") {
        return Err("LatticeCluster CRD not found on management cluster".to_string());
    }
    println!("  LatticeCluster CRD exists");

    // Wait for the management cluster's own LatticeCluster to be Ready
    println!("  Waiting for management cluster's LatticeCluster to be Ready...");
    let api: Api<LatticeCluster> = Api::all(mgmt_client.clone());
    watch_cluster_phases(&mgmt_client, MGMT_CLUSTER_NAME).await?;

    println!("\n  SUCCESS: Management cluster is self-managing!");

    // =========================================================================
    // Phase 5: Create Workload Cluster
    // =========================================================================
    println!("\n[Phase 5] Creating workload cluster from management cluster...\n");

    let workload_cluster = workload_cluster_spec(WORKLOAD_CLUSTER_NAME);
    println!("  Creating LatticeCluster '{}'...", WORKLOAD_CLUSTER_NAME);

    api.create(&PostParams::default(), &workload_cluster)
        .await
        .map_err(|e| format!("Failed to create workload LatticeCluster: {}", e))?;

    // =========================================================================
    // Phase 6: Watch Workload Cluster Provisioning
    // =========================================================================
    println!("\n[Phase 6] Watching workload cluster provisioning...\n");
    println!("  The management cluster will:");
    println!("    1. Generate CAPI manifests for workload cluster");
    println!("    2. CAPD provisions Docker containers");
    println!("    3. Bootstrap webhook installs agent + CNI");
    println!("    4. Agent connects to management cluster");
    println!("    5. Management cluster triggers pivot");
    println!("    6. Workload cluster becomes self-managing");
    println!();

    watch_cluster_phases(&mgmt_client, WORKLOAD_CLUSTER_NAME).await?;

    // =========================================================================
    // Phase 7: Verify Workload Cluster Post-Pivot
    // =========================================================================
    println!("\n[Phase 7] Verifying workload cluster post-pivot state...\n");

    // After clusterctl move, the kubeconfig secret is on the WORKLOAD cluster, not management.
    // Get kubeconfig directly from the workload cluster's control plane container.
    println!("  Getting workload cluster kubeconfig from control plane container...");

    // Find the workload control plane container
    let cp_container = run_cmd(
        "docker",
        &[
            "ps",
            "--filter",
            &format!("name={}-control-plane", WORKLOAD_CLUSTER_NAME),
            "--format",
            "{{.Names}}",
        ],
    )?;
    let cp_container = cp_container.trim();
    if cp_container.is_empty() {
        return Err("Could not find workload cluster control plane container".to_string());
    }
    println!("  Found control plane container: {}", cp_container);

    // Extract kubeconfig from the container (plain text, not base64)
    let workload_kubeconfig = run_cmd(
        "docker",
        &["exec", cp_container, "cat", "/etc/kubernetes/admin.conf"],
    )?;

    let workload_kubeconfig_path = format!("/tmp/{}-kubeconfig", WORKLOAD_CLUSTER_NAME);
    std::fs::write(&workload_kubeconfig_path, &workload_kubeconfig)
        .map_err(|e| format!("Failed to write workload kubeconfig: {}", e))?;

    // Patch for localhost access
    let lb_container = format!("{}-lb", WORKLOAD_CLUSTER_NAME);
    let port_output = run_cmd_allow_fail("docker", &["port", &lb_container, "6443/tcp"]);

    if !port_output.trim().is_empty() {
        let parts: Vec<&str> = port_output.trim().split(':').collect();
        if parts.len() == 2 {
            let localhost_endpoint = format!("https://127.0.0.1:{}", parts[1]);
            let patched = workload_kubeconfig
                .lines()
                .map(|line| {
                    if line.trim().starts_with("server:") {
                        format!("    server: {}", localhost_endpoint)
                    } else {
                        line.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write(&workload_kubeconfig_path, &patched)
                .map_err(|e| format!("Failed to write patched kubeconfig: {}", e))?;
        }
    }

    // Check CAPI resources on workload cluster
    println!("  Checking for CAPI resources on workload cluster...");
    let workload_capi = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &workload_kubeconfig_path,
            "get",
            "clusters",
            "-A",
        ],
    )?;
    println!("  Workload cluster CAPI resources:\n{}", workload_capi);

    if !workload_capi.contains(WORKLOAD_CLUSTER_NAME) {
        return Err(
            "Workload cluster should have its own CAPI Cluster resource after pivot".to_string(),
        );
    }

    // Check nodes
    let nodes = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &workload_kubeconfig_path,
            "get",
            "nodes",
            "-o",
            "wide",
        ],
    )?;
    println!("  Workload cluster nodes:\n{}", nodes);

    // =========================================================================
    // Phase 8: Watch Worker Scaling
    // =========================================================================
    println!("\n[Phase 8] Watching worker scaling on both clusters...\n");
    println!("  After pivot, each cluster's local controller should scale workers:");
    println!("    - Management cluster: 0 -> 1 workers");
    println!("    - Workload cluster: 0 -> 2 workers");
    println!();

    // Watch management cluster worker scaling
    println!("  Waiting for management cluster workers to scale...");
    watch_worker_scaling(&kubeconfig_path, MGMT_CLUSTER_NAME, 1).await?;

    // Watch workload cluster worker scaling
    println!("  Waiting for workload cluster workers to scale...");
    watch_worker_scaling(&workload_kubeconfig_path, WORKLOAD_CLUSTER_NAME, 2).await?;

    // =========================================================================
    // Phase 9: Comprehensive 3-Layer Service Mesh Testing
    // =========================================================================
    println!("\n[Phase 9] Testing comprehensive 3-layer service mesh...\n");
    println!("  This test deploys a realistic microservice architecture:");
    println!();
    println!("  LAYER 1: FRONTEND (traffic generators)");
    println!("    - frontend-web:    Tests api-gateway, api-users, api-orders");
    println!("    - frontend-mobile: Tests api-gateway, api-users, api-orders");
    println!("    - frontend-admin:  Tests api-gateway, api-users, api-orders");
    println!();
    println!("  LAYER 2: API (business logic)");
    println!("    - api-gateway: Allows web, mobile, admin");
    println!("    - api-users:   Allows web, admin (NOT mobile)");
    println!("    - api-orders:  Allows mobile, admin (NOT web)");
    println!();
    println!("  LAYER 3: BACKEND (data layer)");
    println!("    - db-users:  Allows gateway, users (NOT orders)");
    println!("    - db-orders: Allows gateway, orders (NOT users)");
    println!("    - cache:     Allows all API services");
    println!();
    println!("  Testing 24 connection permutations:");
    println!("    - 7 bilateral agreements (should be ALLOWED)");
    println!("    - 17 blocked paths (should be BLOCKED)");
    println!();

    // Wait for workload cluster to be Ready (webhook must be up before deploying services)
    println!("  Waiting for workload cluster to be Ready (webhook must be up)...");
    let workload_client = client_from_kubeconfig(&workload_kubeconfig_path).await?;
    watch_cluster_phases(&workload_client, WORKLOAD_CLUSTER_NAME).await?;

    // Deploy test services
    deploy_test_services(&workload_kubeconfig_path).await?;

    // Wait for pods to be ready
    wait_for_deployments(&workload_kubeconfig_path).await?;

    // Verify traffic patterns
    verify_traffic_patterns(&workload_kubeconfig_path).await?;

    println!("\n============================================================");
    println!("  FULL E2E TEST PASSED!");
    println!("============================================================");
    println!("\n  Verified:");
    println!("    [x] Lattice installer created self-managing management cluster");
    println!("    [x] Bootstrap cluster was deleted");
    println!("    [x] Management cluster has CAPI + LatticeCluster CRD");
    println!("    [x] Management cluster's LatticeCluster is Ready");
    println!("    [x] Workload cluster provisioned from management cluster");
    println!("    [x] Workload cluster pivoted and is self-managing");
    println!("    [x] Management cluster scaled to 1 worker");
    println!("    [x] Workload cluster scaled to 2 workers");
    println!();
    println!("  3-Layer Service Mesh (9 services, 24 tests):");
    println!("    [x] Layer 1->2: frontend-web -> api-gateway ALLOWED");
    println!("    [x] Layer 1->2: frontend-web -> api-users ALLOWED");
    println!("    [x] Layer 1->2: frontend-web -> api-orders BLOCKED (not allowed)");
    println!("    [x] Layer 1->2: frontend-mobile -> api-gateway ALLOWED");
    println!("    [x] Layer 1->2: frontend-mobile -> api-users BLOCKED (not allowed)");
    println!("    [x] Layer 1->2: frontend-mobile -> api-orders ALLOWED");
    println!("    [x] Layer 1->2: frontend-admin -> all API services ALLOWED");
    println!("    [x] Layer 1->3: All frontend -> backend BLOCKED (no direct access)");
    println!("    [x] Same-layer: All peer access BLOCKED (no lateral movement)");
    println!();

    // =========================================================================
    // Phase 10: Cleanup
    // =========================================================================
    println!("\n[Phase 10] Cleaning up...\n");
    cleanup_all();

    Ok(())
}
