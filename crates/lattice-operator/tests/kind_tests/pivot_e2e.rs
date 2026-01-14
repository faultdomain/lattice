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

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::time::Duration;

use base64::Engine;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, PostParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::Client;
use rand::prelude::*;
use tokio::time::sleep;

use lattice_operator::crd::{
    BootstrapProvider, ClusterPhase, ContainerSpec, DependencyDirection, DeploySpec,
    KubernetesSpec, LatticeCluster, LatticeClusterSpec, LatticeExternalService,
    LatticeExternalServiceSpec, LatticeService, LatticeServiceSpec, NodeSpec, PortSpec,
    ProviderSpec, ProviderType, ReplicaSpec, Resolution, ResourceSpec, ResourceType,
    ServicePortsSpec,
};
use lattice_operator::install::{InstallConfig, Installer};
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

/// Get the workspace root directory (two levels up from CARGO_MANIFEST_DIR)
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

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
        .current_dir(workspace_root())
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
    let env_path = workspace_root().join(".env");
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

/// Create workload cluster spec with specified bootstrap provider
fn workload_cluster_spec(name: &str, bootstrap: BootstrapProvider) -> LatticeCluster {
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
                    bootstrap,
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

/// Get the kubeconfig path inside the control plane container based on bootstrap provider
fn get_kubeconfig_path_for_bootstrap(bootstrap: &BootstrapProvider) -> &'static str {
    match bootstrap {
        BootstrapProvider::Kubeadm => "/etc/kubernetes/admin.conf",
        BootstrapProvider::Rke2 => "/etc/rancher/rke2/rke2.yaml",
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
        startup_probe: None,
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
            class: None,
            metadata: None,
            params: None,
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
            class: None,
            metadata: None,
            params: None,
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
        // When curl succeeds (exit 0), connection was ALLOWED
        // When curl fails (exit non-0), connection was BLOCKED
        let (success_msg, fail_msg) = if test.expected {
            // Expected ALLOWED: success is expected, failure is unexpected
            (
                format!("{}: ALLOWED ({})", test.target, test.reason),
                format!("{}: BLOCKED (UNEXPECTED - {})", test.target, test.reason),
            )
        } else {
            // Expected BLOCKED: failure is expected, success is unexpected
            (
                format!("{}: ALLOWED (UNEXPECTED - {})", test.target, test.reason),
                format!("{}: BLOCKED ({})", test.target, test.reason),
            )
        };

        script.push_str(&format!(
            r#"
# Test {target} ({reason})
if curl -s --connect-timeout 3 http://{target}.{ns}.svc.cluster.local/ > /dev/null 2>&1; then
    echo "{success_msg}"
else
    echo "{fail_msg}"
fi
"#,
            target = test.target,
            ns = TEST_SERVICES_NAMESPACE,
            reason = test.reason,
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
        startup_probe: None,
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
/// Note: Caller must wait for traffic tests to run before calling this
async fn verify_traffic_patterns(kubeconfig_path: &str) -> Result<(), String> {
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

            // For expected ALLOWED: pass if ALLOWED appeared (ignores early BLOCKEDs before policy propagation)
            // For expected BLOCKED: fail if ALLOWED ever appeared (policy should never allow)
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

        // Count ready worker nodes using label selector to exclude control-plane
        let nodes_output = run_cmd_allow_fail(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "get",
                "nodes",
                "-l",
                "!node-role.kubernetes.io/control-plane",
                "-o",
                "jsonpath={range .items[*]}{.status.conditions[?(@.type=='Ready')].status}{\"\\n\"}{end}",
            ],
        );

        // Count ready workers (only worker nodes returned due to label selector)
        let ready_workers = nodes_output.lines().filter(|line| *line == "True").count() as u32;

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

/// Verify control-plane taints are restored on a cluster
///
/// Checks that control-plane nodes have the NoSchedule taint and
/// etcd nodes have the NoExecute taint (for RKE2 clusters).
async fn verify_control_plane_taints(
    kubeconfig_path: &str,
    bootstrap: &BootstrapProvider,
) -> Result<(), String> {
    println!("  Verifying control-plane taints are restored...");

    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(45);

    loop {
        // Get control-plane nodes and their taints (iterate per-taint for correct pairing)
        let cp_taints = run_cmd_allow_fail(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "get",
                "nodes",
                "-l",
                "node-role.kubernetes.io/control-plane",
                "-o",
                "jsonpath={range .items[*]}{.metadata.name}: {range .spec.taints[*]}{.key}={.effect} {end}{\"\\n\"}{end}",
            ],
        );

        // Check control-plane NoSchedule taint
        let has_cp_taint = cp_taints.contains("node-role.kubernetes.io/control-plane=NoSchedule");

        // For RKE2, also check etcd taint
        let has_etcd_taint = if matches!(bootstrap, BootstrapProvider::Rke2) {
            let etcd_taints = run_cmd_allow_fail(
                "kubectl",
                &[
                    "--kubeconfig",
                    kubeconfig_path,
                    "get",
                    "nodes",
                    "-l",
                    "node-role.kubernetes.io/etcd",
                    "-o",
                    "jsonpath={range .items[*]}{.metadata.name}: {range .spec.taints[*]}{.key}={.effect} {end}{\"\\n\"}{end}",
                ],
            );
            etcd_taints.contains("node-role.kubernetes.io/etcd=NoExecute")
        } else {
            true
        };

        if has_cp_taint && has_etcd_taint {
            println!("    Control-plane node taints:\n{}", cp_taints);
            println!("    [x] Control-plane NoSchedule taint present");
            if matches!(bootstrap, BootstrapProvider::Rke2) {
                println!("    [x] Etcd NoExecute taint present (RKE2)");
            }
            return Ok(());
        }

        if start.elapsed() > timeout {
            println!("    Control-plane node taints:\n{}", cp_taints);
            return Err(format!(
                "Control-plane nodes missing required taints after {}s",
                timeout.as_secs()
            ));
        }

        sleep(Duration::from_secs(5)).await;
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

/// Cleanup clusters and containers only (preserves images for reuse between test runs)
fn cleanup_clusters() {
    println!("\n[Cleanup] Removing clusters and containers...\n");

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

    println!("  Cluster cleanup complete!");
}

/// Cleanup Docker images and build cache (call once at the end of all tests)
fn cleanup_images() {
    println!("\n[Cleanup] Removing Docker images and build cache...\n");

    // Remove the lattice image we built
    let _ = run_cmd_allow_fail("docker", &["rmi", "-f", LATTICE_IMAGE]);

    // Prune dangling images (intermediate build stages)
    let _ = run_cmd_allow_fail("docker", &["image", "prune", "-f"]);

    // Prune build cache (can be quite large from multi-stage builds)
    let _ = run_cmd_allow_fail("docker", &["builder", "prune", "-f"]);

    println!("  Image cleanup complete!");
}

/// Cleanup all test resources (clusters + images)
fn cleanup_all() {
    cleanup_clusters();
    cleanup_images();
}

// =============================================================================
// E2E Test: Full Installation and Pivot Flow
// =============================================================================

/// Story: Full end-to-end installation with self-managing management cluster
///
/// This test runs the complete Lattice installer flow TWICE to test cross-bootstrap
/// provisioning in both directions:
///   1. First run: RKE2 management cluster → kubeadm workload cluster
///   2. Second run: kubeadm management cluster → RKE2 workload cluster
///
/// Run with: cargo test --features e2e --test kind pivot_e2e -- --nocapture
#[tokio::test]
async fn story_full_install_and_workload_provisioning() {
    // Install crypto provider for rustls/kube client (do this once at the start)
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // =========================================================================
    // Setup: Build image once for all test runs
    // =========================================================================
    println!("\n################################################################");
    println!("#  SETUP: Building Lattice image (once for all tests)");
    println!("################################################################\n");

    // Clean up any previous test artifacts (clusters only, preserve cached images)
    cleanup_clusters();

    // Ensure Docker network has correct subnet
    if let Err(e) = ensure_docker_network() {
        panic!("Failed to setup Docker network: {}", e);
    }

    // Build and push the image once
    if let Err(e) = build_and_push_lattice_image().await {
        cleanup_all(); // Clean up on failure
        panic!("Failed to build Lattice image: {}", e);
    }

    // =========================================================================
    // Test combination 1: RKE2 management → kubeadm workload
    // =========================================================================
    println!("\n################################################################");
    println!("#  TEST RUN 1: RKE2 management → kubeadm workload");
    println!("################################################################\n");

    let result1 = tokio::time::timeout(
        E2E_TIMEOUT,
        run_full_e2e(BootstrapProvider::Rke2, BootstrapProvider::Kubeadm),
    )
    .await;

    match result1 {
        Ok(Ok(())) => {
            println!("\n=== Run 1 (RKE2→kubeadm) Completed Successfully! ===\n");
        }
        Ok(Err(e)) => {
            println!("\n=== Run 1 (RKE2→kubeadm) Failed: {} ===\n", e);
            println!("  NOTE: Not cleaning up so you can investigate. Run cleanup manually:");
            println!("    kind delete clusters --all && docker system prune -af");
            panic!("E2E test run 1 failed: {}", e);
        }
        Err(_) => {
            println!(
                "\n=== Run 1 (RKE2→kubeadm) Timed Out ({:?}) ===\n",
                E2E_TIMEOUT
            );
            println!("  NOTE: Not cleaning up so you can investigate. Run cleanup manually:");
            println!("    kind delete clusters --all && docker system prune -af");
            panic!("E2E test run 1 timed out after {:?}", E2E_TIMEOUT);
        }
    }

    // Clean up clusters between runs (preserve image for reuse)
    cleanup_clusters();

    // =========================================================================
    // Test combination 2: kubeadm management → RKE2 workload
    // =========================================================================
    println!("\n################################################################");
    println!("#  TEST RUN 2: kubeadm management → RKE2 workload");
    println!("################################################################\n");

    let result2 = tokio::time::timeout(
        E2E_TIMEOUT,
        run_full_e2e(BootstrapProvider::Kubeadm, BootstrapProvider::Rke2),
    )
    .await;

    match result2 {
        Ok(Ok(())) => {
            println!("\n=== Run 2 (kubeadm→RKE2) Completed Successfully! ===\n");
            println!("\n################################################################");
            println!("#  ALL CROSS-BOOTSTRAP TESTS PASSED!");
            println!("################################################################\n");
        }
        Ok(Err(e)) => {
            println!("\n=== Run 2 (kubeadm→RKE2) Failed: {} ===\n", e);
            println!("  NOTE: Not cleaning up so you can investigate. Run cleanup manually:");
            println!("    kind delete clusters --all && docker system prune -af");
            panic!("E2E test run 2 failed: {}", e);
        }
        Err(_) => {
            println!(
                "\n=== Run 2 (kubeadm→RKE2) Timed Out ({:?}) ===\n",
                E2E_TIMEOUT
            );
            println!("  NOTE: Not cleaning up so you can investigate. Run cleanup manually:");
            println!("    kind delete clusters --all && docker system prune -af");
            panic!("E2E test run 2 timed out after {:?}", E2E_TIMEOUT);
        }
    }

    // =========================================================================
    // Final cleanup: Remove all resources including images
    // =========================================================================
    println!("\n################################################################");
    println!("#  CLEANUP: Removing all test resources");
    println!("################################################################\n");
    cleanup_all();
}

async fn run_full_e2e(
    mgmt_bootstrap: BootstrapProvider,
    workload_bootstrap: BootstrapProvider,
) -> Result<(), String> {
    println!("\n============================================================");
    println!("  FULL END-TO-END LATTICE INSTALLATION TEST");
    println!("  (Cross-Bootstrap Provider Testing)");
    println!("============================================================");
    println!("\n  This test validates cross-bootstrap provisioning:");
    println!(
        "    - Management cluster: {} ({:?}ControlPlane)",
        mgmt_bootstrap, mgmt_bootstrap
    );
    println!(
        "    - Workload cluster:   {} ({:?}ControlPlane)",
        workload_bootstrap, workload_bootstrap
    );
    println!("\n  Test phases:");
    println!(
        "    1. Run the full installer (bootstrap → {} management cluster)",
        mgmt_bootstrap
    );
    println!("    2. Verify management cluster is self-managing");
    println!(
        "    3. Create {} workload cluster from {} management cluster",
        workload_bootstrap, mgmt_bootstrap
    );
    println!("    4. Verify workload cluster reaches Ready state");
    println!("\n  Expected duration: 15-25 minutes\n");

    // Note: Image build and network setup are done once in the main test function

    // =========================================================================
    // Phase 1: Run Full Installer
    // =========================================================================
    println!("\n[Phase 1] Running Lattice installer...\n");
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
      bootstrap: {bootstrap}
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
        name = MGMT_CLUSTER_NAME,
        bootstrap = mgmt_bootstrap,
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
    // Phase 2: Verify Management Cluster is Self-Managing
    // =========================================================================
    println!("\n[Phase 2] Verifying management cluster is self-managing...\n");

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
    // Phase 3: Create Workload Cluster
    // =========================================================================
    println!("\n[Phase 3] Creating workload cluster from management cluster...\n");

    let workload_cluster = workload_cluster_spec(WORKLOAD_CLUSTER_NAME, workload_bootstrap.clone());
    println!(
        "  Creating LatticeCluster '{}' with {} bootstrap...",
        WORKLOAD_CLUSTER_NAME, workload_bootstrap
    );

    api.create(&PostParams::default(), &workload_cluster)
        .await
        .map_err(|e| format!("Failed to create workload LatticeCluster: {}", e))?;

    // =========================================================================
    // Phase 4: Watch Workload Cluster Provisioning
    // =========================================================================
    println!("\n[Phase 4] Watching workload cluster provisioning...\n");
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
    // Phase 5: Verify Workload Cluster Post-Pivot
    // =========================================================================
    println!("\n[Phase 5] Verifying workload cluster post-pivot state...\n");

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
    // Path differs by bootstrap provider: kubeadm uses /etc/kubernetes/admin.conf, RKE2 uses /etc/rancher/rke2/rke2.yaml
    let kubeconfig_container_path = get_kubeconfig_path_for_bootstrap(&workload_bootstrap);
    println!("  Extracting kubeconfig from {}", kubeconfig_container_path);
    let workload_kubeconfig = run_cmd(
        "docker",
        &["exec", cp_container, "cat", kubeconfig_container_path],
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
    // Phase 6: Watch Worker Scaling
    // =========================================================================
    println!("\n[Phase 6] Watching worker scaling on both clusters...\n");
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
    // Phase 7: Comprehensive 3-Layer Service Mesh Testing
    // =========================================================================
    println!("\n[Phase 7] Testing comprehensive 3-layer service mesh...\n");
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

    // =========================================================================
    // Deploy BOTH mesh tests in parallel for efficiency
    // Both use different namespaces so they don't conflict
    // =========================================================================

    // Generate randomized mesh first (so we can print the manifest early)
    println!("\n  Generating randomized mesh (50-100 services)...");
    let random_mesh = RandomMesh::generate(&RandomMeshConfig::default());
    let random_stats = random_mesh.stats();
    println!("{}", random_stats);
    println!("\n  Expected connection manifest (EXACT MATCH REQUIRED):");
    random_mesh.print_manifest();

    // Deploy deterministic test services (9 services in mesh-test namespace)
    println!("\n  Deploying deterministic mesh (9 services)...");
    deploy_test_services(&workload_kubeconfig_path).await?;

    // Deploy randomized mesh services (50-100 services in random-mesh namespace)
    println!("\n  Deploying randomized mesh...");
    deploy_random_mesh(&random_mesh, &workload_kubeconfig_path).await?;

    // Wait for ALL pods from BOTH meshes
    println!("\n  Waiting for deterministic mesh pods...");
    wait_for_deployments(&workload_kubeconfig_path).await?;
    println!("\n  Waiting for randomized mesh pods...");
    wait_for_random_mesh_pods(&random_mesh, &workload_kubeconfig_path).await?;

    // Single wait for policy propagation (90 seconds covers both)
    println!("\n  Waiting for traffic tests to run (90 seconds for both meshes)...");
    sleep(Duration::from_secs(90)).await;

    // Verify BOTH meshes
    println!("\n  Verifying deterministic mesh traffic patterns...");
    verify_traffic_patterns(&workload_kubeconfig_path).await?;

    println!("\n  Verifying randomized mesh traffic patterns...");
    verify_random_mesh_traffic(&random_mesh, &workload_kubeconfig_path).await?;

    println!("\n============================================================");
    println!("  FULL E2E TEST PASSED!");
    println!("  (Cross-Bootstrap Provider Testing Verified)");
    println!("============================================================");
    println!("\n  Cross-Bootstrap Provisioning:");
    println!("    [x] Management cluster: kubeadm (KubeadmControlPlane)");
    println!("    [x] Workload cluster:   RKE2 (RKE2ControlPlane)");
    println!("\n  Verified:");
    println!("    [x] Lattice installer created self-managing kubeadm management cluster");
    println!("    [x] Bootstrap cluster was deleted");
    println!("    [x] Management cluster has CAPI + LatticeCluster CRD");
    println!("    [x] Management cluster's LatticeCluster is Ready");
    println!("    [x] RKE2 workload cluster provisioned from kubeadm management cluster");
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
    println!(
        "  Randomized Mesh ({} services, {} tests):",
        random_mesh.services.len(),
        random_mesh.expected_connections.len()
    );
    println!("    [x] All bilateral agreements verified");
    println!("    [x] All blocked paths verified");
    println!();

    // =========================================================================
    // Phase 8: Prove Workload Cluster Independence
    // =========================================================================
    println!("\n[Phase 8] Proving workload cluster is truly self-managing...\n");
    println!("  This phase will:");
    println!("    1. Delete the management cluster entirely");
    println!("    2. Update workload cluster's LatticeCluster spec (scale workers 2 -> 3)");
    println!("    3. Verify workload cluster self-heals and scales without management cluster");
    println!();

    // Step 1: Delete management cluster
    println!("  [Step 1] Deleting management cluster...");
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
    println!("    Management cluster deleted!");

    // Verify management cluster is gone
    let mgmt_check = run_cmd_allow_fail(
        "docker",
        &[
            "ps",
            "--filter",
            &format!("name={}", MGMT_CLUSTER_NAME),
            "-q",
        ],
    );
    if !mgmt_check.trim().is_empty() {
        return Err("Failed to delete management cluster".to_string());
    }
    println!("    Verified: management cluster containers no longer exist");

    // Step 2: Update workload cluster spec to scale workers
    println!("\n  [Step 2] Scaling workload cluster workers 2 -> 3...");
    let patch_result = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &workload_kubeconfig_path,
            "patch",
            "latticecluster",
            WORKLOAD_CLUSTER_NAME,
            "--type=merge",
            "-p",
            r#"{"spec":{"nodes":{"workers":3}}}"#,
        ],
    )?;
    println!("    Patch applied: {}", patch_result.trim());

    // Step 3: Watch for the new worker to come up
    println!("\n  [Step 3] Waiting for workload cluster to self-heal and scale to 3 workers...");
    println!("    (Management cluster is GONE - workload cluster must do this itself)");
    watch_worker_scaling(&workload_kubeconfig_path, WORKLOAD_CLUSTER_NAME, 3).await?;

    println!(
        "\n  SUCCESS: Workload cluster scaled from 2 to 3 workers WITHOUT management cluster!"
    );
    println!("  This proves:");
    println!("    [x] Workload cluster is truly self-managing after pivot");
    println!("    [x] No dependency on parent cluster for ongoing operations");
    println!("    [x] CAPI reconciliation works locally");
    println!();

    // Step 4: Verify control-plane taints were restored
    println!("  [Step 4] Verifying control-plane taints were restored...");
    verify_control_plane_taints(&workload_kubeconfig_path, &workload_bootstrap).await?;
    println!("    [x] Control-plane taints restored by controller");

    // Note: Cleanup is handled by the main test function (preserves images between runs)
    println!("\n[Phase 10] Test run complete!\n");

    Ok(())
}

// =============================================================================
// Randomized Service Mesh Testing Module
// =============================================================================
//
// This module generates a randomized service mesh with 50-100 services to stress
// test the bilateral agreement pattern at scale with unpredictable topologies.

/// Configuration for randomized mesh generation
#[derive(Debug, Clone)]
struct RandomMeshConfig {
    /// Minimum number of services (inclusive)
    min_services: usize,
    /// Maximum number of services (inclusive)
    max_services: usize,
    /// Number of layers in the service graph (e.g., 5 for frontend->api->backend->db->cache)
    num_layers: usize,
    /// Probability that a service depends on another service in a lower layer (0.0-1.0)
    outbound_probability: f64,
    /// Probability that a callee allows an inbound caller when caller declares dependency (0.0-1.0)
    /// This controls how many bilateral agreements form vs blocked paths
    bilateral_probability: f64,
    /// Random seed for reproducibility (None = random)
    seed: Option<u64>,
    /// Number of external services to create
    num_external_services: usize,
    /// Probability that a traffic generator depends on an external service (0.0-1.0)
    external_outbound_probability: f64,
    /// Probability that an external service allows a requesting service (0.0-1.0)
    external_allow_probability: f64,
}

impl Default for RandomMeshConfig {
    fn default() -> Self {
        Self {
            min_services: 50,
            max_services: 100,
            num_layers: 5,
            outbound_probability: 0.3, // ~20% chance of connecting to each lower-layer service
            bilateral_probability: 0.6, // ~60% of declared outbounds get bilateral agreement
            seed: None,
            num_external_services: 10, // Create 5 external services
            external_outbound_probability: 0.3, // 30% chance of depending on each external service
            external_allow_probability: 0.6, // 60% of external deps get allowed
        }
    }
}

/// An external service in the randomized mesh
#[derive(Debug, Clone)]
struct RandomExternalService {
    /// Unique name for this external service
    #[allow(dead_code)]
    name: String,
    /// URL endpoint to test connectivity
    url: String,
    /// Services allowed to access this external service
    allowed_requesters: HashSet<String>,
    /// Resolution strategy (DNS or Static for IP-based endpoints)
    resolution: Resolution,
}

/// A service in the randomized mesh
#[derive(Debug, Clone)]
struct RandomService {
    /// Unique service name
    name: String,
    /// Layer index (0 = top/frontend, higher = lower layers)
    #[allow(dead_code)]
    layer: usize,
    /// Services this service wants to connect to (outbound dependencies)
    outbound: HashSet<String>,
    /// External services this service wants to connect to
    external_outbound: HashSet<String>,
    /// Services this service allows inbound connections from
    inbound: HashSet<String>,
    /// Is this a traffic generator (top layer services)
    is_traffic_generator: bool,
}

/// A randomized service mesh graph
#[derive(Debug)]
struct RandomMesh {
    /// All services indexed by name
    services: BTreeMap<String, RandomService>,
    /// Services organized by layer
    layers: Vec<Vec<String>>,
    /// External services
    external_services: BTreeMap<String, RandomExternalService>,
    /// Expected test results: (source, target, should_be_allowed, is_external)
    expected_connections: Vec<(String, String, bool, bool)>,
}

impl RandomMesh {
    /// Generate a new randomized service mesh
    fn generate(config: &RandomMeshConfig) -> Self {
        let mut rng = match config.seed {
            Some(seed) => StdRng::seed_from_u64(seed),
            None => StdRng::from_entropy(),
        };

        // Determine number of services
        let num_services = rng.gen_range(config.min_services..=config.max_services);
        println!(
            "  Generating {} services across {} layers...",
            num_services, config.num_layers
        );

        // Distribute services across layers (more services in middle layers)
        let mut layer_sizes = Vec::with_capacity(config.num_layers);
        let base_size = num_services / config.num_layers;
        let mut remaining = num_services;

        for i in 0..config.num_layers {
            let size = if i == config.num_layers - 1 {
                remaining // Last layer gets all remaining
            } else {
                // Middle layers get more services
                let variance = if i == 0 || i == config.num_layers - 1 {
                    base_size / 2 // Fewer at edges
                } else {
                    base_size / 3
                };
                let size = base_size + rng.gen_range(0..=variance);
                remaining -= size;
                size
            };
            layer_sizes.push(size);
        }

        // Generate service names for each layer
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
                        is_traffic_generator: layer_idx == 0, // Top layer generates traffic
                    },
                );
            }
            layers.push(layer_services);
        }

        // Generate random dependencies (top layers depend on lower layers)
        let mut expected_connections = Vec::new();

        for layer_idx in 0..config.num_layers.saturating_sub(1) {
            for source_name in &layers[layer_idx] {
                // This service can connect to services in ALL lower layers
                for target_layer_idx in (layer_idx + 1)..config.num_layers {
                    for target_name in &layers[target_layer_idx] {
                        // Random chance to create outbound dependency
                        if rng.gen::<f64>() < config.outbound_probability {
                            // Source declares outbound dependency
                            services
                                .get_mut(source_name)
                                .unwrap()
                                .outbound
                                .insert(target_name.clone());

                            // Random chance for bilateral agreement
                            let is_bilateral = rng.gen::<f64>() < config.bilateral_probability;
                            if is_bilateral {
                                // Target allows inbound from source
                                services
                                    .get_mut(target_name)
                                    .unwrap()
                                    .inbound
                                    .insert(source_name.clone());
                            }

                            // Track expected result for traffic generators
                            if services[source_name].is_traffic_generator {
                                expected_connections.push((
                                    source_name.clone(),
                                    target_name.clone(),
                                    is_bilateral,
                                    false, // not external
                                ));
                            }
                        }
                    }
                }

                // Also test some connections that should ALWAYS be blocked
                // (services this source didn't declare as dependencies)
                if services[source_name].is_traffic_generator {
                    // Pick a few random services from lower layers that we DON'T depend on
                    for target_layer_idx in (layer_idx + 1)..config.num_layers {
                        let not_dependent: Vec<_> = layers[target_layer_idx]
                            .iter()
                            .filter(|t| !services[source_name].outbound.contains(*t))
                            .collect();

                        // Test up to 3 random non-dependencies per layer
                        let sample_size = not_dependent.len().min(3);
                        let sampled: Vec<_> = not_dependent
                            .choose_multiple(&mut rng, sample_size)
                            .collect();

                        for target_name in sampled {
                            expected_connections.push((
                                source_name.clone(),
                                (*target_name).clone(),
                                false, // Should always be blocked (no outbound declared)
                                false, // not external
                            ));
                        }
                    }
                }
            }
        }

        // Also test same-layer connections (should all be blocked)
        for layer in &layers {
            if layer.len() < 2 {
                continue;
            }
            let traffic_generators: Vec<_> = layer
                .iter()
                .filter(|s| services[*s].is_traffic_generator)
                .collect();

            for source in &traffic_generators {
                // Pick a random peer in the same layer
                let peers: Vec<_> = layer.iter().filter(|s| *s != *source).collect();
                if let Some(peer) = peers.choose(&mut rng) {
                    expected_connections.push(((*source).clone(), (*peer).clone(), false, false));
                }
            }
        }

        // Generate external services with real, reachable URLs
        let external_urls = [
            ("httpbin", "https://httpbin.org/status/200"),
            ("example", "https://example.com"),
            ("google", "https://www.google.com"),
            ("cloudflare", "https://1.1.1.1"),
            ("github", "https://github.com"),
        ];

        let mut external_services = BTreeMap::new();
        let num_external = config.num_external_services.min(external_urls.len());

        for i in 0..num_external {
            let (name, url) = external_urls[i];
            // Detect IP-based URLs and set resolution accordingly
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

        // Generate external service dependencies for traffic generators
        let traffic_generators: Vec<String> = services
            .values()
            .filter(|s| s.is_traffic_generator)
            .map(|s| s.name.clone())
            .collect();

        let ext_names: Vec<String> = external_services.keys().cloned().collect();

        for source_name in &traffic_generators {
            for ext_name in &ext_names {
                // Random chance to depend on this external service
                if rng.gen::<f64>() < config.external_outbound_probability {
                    // Source declares outbound dependency on external service
                    services
                        .get_mut(source_name)
                        .unwrap()
                        .external_outbound
                        .insert(ext_name.clone());

                    // Random chance for external service to allow this requester
                    let is_allowed = rng.gen::<f64>() < config.external_allow_probability;
                    if is_allowed {
                        external_services
                            .get_mut(ext_name)
                            .unwrap()
                            .allowed_requesters
                            .insert(source_name.clone());
                    }

                    // Track expected result
                    expected_connections.push((
                        source_name.clone(),
                        ext_name.clone(),
                        is_allowed,
                        true, // is external
                    ));
                }
            }

            // Also test some external services that the source didn't declare as dependencies
            let not_dependent: Vec<_> = ext_names
                .iter()
                .filter(|e| !services[source_name].external_outbound.contains(*e))
                .cloned()
                .collect();

            // Test up to 2 random non-dependencies
            let sample_size = not_dependent.len().min(2);
            let sampled: Vec<_> = not_dependent
                .choose_multiple(&mut rng, sample_size)
                .cloned()
                .collect();

            for ext_name in sampled {
                expected_connections.push((
                    source_name.clone(),
                    ext_name,
                    false, // Should always be blocked (no outbound declared)
                    true,  // is external
                ));
            }
        }

        Self {
            services,
            layers,
            external_services,
            expected_connections,
        }
    }

    /// Check if a URL contains an IP address (IPv4 or IPv6) instead of a hostname
    fn is_ip_based_url(url: &str) -> bool {
        use std::net::IpAddr;

        // Extract host from URL (skip protocol)
        let host = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .or_else(|| url.strip_prefix("tcp://"))
            .or_else(|| url.strip_prefix("grpc://"))
            .unwrap_or(url);

        // Remove port and path
        let host = host.split(':').next().unwrap_or(host);
        let host = host.split('/').next().unwrap_or(host);

        // Handle IPv6 bracket notation [::1]
        let host = host.trim_start_matches('[').trim_end_matches(']');

        host.parse::<IpAddr>().is_ok()
    }

    /// Get summary statistics
    fn stats(&self) -> MeshStats {
        let total_services = self.services.len();
        let total_tests = self.expected_connections.len();
        let expected_allowed = self
            .expected_connections
            .iter()
            .filter(|(_, _, allowed, _)| *allowed)
            .count();
        let expected_blocked = total_tests - expected_allowed;

        let total_outbound: usize = self.services.values().map(|s| s.outbound.len()).sum();
        let total_inbound: usize = self.services.values().map(|s| s.inbound.len()).sum();
        let total_external_outbound: usize = self
            .services
            .values()
            .map(|s| s.external_outbound.len())
            .sum();
        let total_external_tests = self
            .expected_connections
            .iter()
            .filter(|(_, _, _, is_external)| *is_external)
            .count();

        MeshStats {
            total_services,
            services_per_layer: self.layers.iter().map(|l| l.len()).collect(),
            total_outbound_deps: total_outbound,
            total_inbound_allows: total_inbound,
            total_tests,
            expected_allowed,
            expected_blocked,
            total_external_services: self.external_services.len(),
            total_external_outbound_deps: total_external_outbound,
            total_external_tests,
        }
    }

    /// Print the full expected connection manifest
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
        for (src, tgt, _, is_external) in &allowed {
            let marker = if *is_external { " [EXT]" } else { "" };
            println!("    {} -> {}{}", src, tgt, marker);
        }

        println!("\n  === EXPECTED BLOCKED ({}) ===", blocked.len());
        for (src, tgt, _, is_external) in &blocked {
            let marker = if *is_external { " [EXT]" } else { "" };
            println!("    {} -> {}{}", src, tgt, marker);
        }
        println!();
    }

    /// Create a LatticeService for a service in the mesh
    fn create_lattice_service(&self, name: &str, namespace: &str) -> LatticeService {
        let svc = &self.services[name];

        let mut containers = BTreeMap::new();
        let mut resources: BTreeMap<String, ResourceSpec> = BTreeMap::new();

        // Add outbound dependencies
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
                },
            );
        }

        // Add inbound allowances
        // Key is service name (no conflicts since outbound goes to lower layers only)
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
                },
            );
        }

        // Add external service dependencies
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
                },
            );
        }

        if svc.is_traffic_generator {
            // Traffic generator: runs curl tests
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
            // Backend service: runs nginx
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
                    // Backend services need HTTP ports
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
            },
            status: None,
        }
    }

    /// Create a LatticeExternalService CRD for an external service in the mesh
    fn create_external_service(&self, name: &str, namespace: &str) -> LatticeExternalService {
        let ext_svc = &self.external_services[name];

        let mut endpoints = BTreeMap::new();
        endpoints.insert("default".to_string(), ext_svc.url.clone());

        LatticeExternalService {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                // LatticeExternalService is cluster-scoped, no namespace
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

    /// Generate test script for a traffic generator service
    fn generate_test_script(&self, source_name: &str, namespace: &str) -> String {
        let mut script = format!(
            r#"
echo "=== {} Traffic Tests ==="
sleep 5  # Brief wait for AuthorizationPolicies

"#,
            source_name
        );

        // Get all expected connections for this source
        let tests: Vec<_> = self
            .expected_connections
            .iter()
            .filter(|(src, _, _, _)| src == source_name)
            .collect();

        for (_, target, expected_allowed, is_external) in &tests {
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
                // External service - use the actual URL
                let url = &self.external_services[target].url;
                script.push_str(&format!(
                    r#"if curl -s --connect-timeout 5 {url} >/dev/null 2>&1; then
  echo "{success_msg}"
else
  echo "{fail_msg}"
fi
"#,
                    url = url,
                    success_msg = success_msg,
                    fail_msg = fail_msg,
                ));
            } else {
                // Internal service - use cluster DNS
                script.push_str(&format!(
                    r#"if curl -s --connect-timeout 2 http://{target}.{ns}.svc.cluster.local/ >/dev/null 2>&1; then
  echo "{success_msg}"
else
  echo "{fail_msg}"
fi
"#,
                    target = target,
                    ns = namespace,
                    success_msg = success_msg,
                    fail_msg = fail_msg,
                ));
            }
        }

        script.push_str(&format!(
            r#"
echo "=== End {} Tests ==="
sleep 10
"#,
            source_name
        ));

        // Wrap in loop
        format!("while true; do\n{}\ndone\n", script)
    }
}

/// Statistics about a generated mesh
#[derive(Debug)]
struct MeshStats {
    total_services: usize,
    services_per_layer: Vec<usize>,
    total_outbound_deps: usize,
    total_inbound_allows: usize,
    total_tests: usize,
    expected_allowed: usize,
    expected_blocked: usize,
    total_external_services: usize,
    total_external_outbound_deps: usize,
    total_external_tests: usize,
}

impl std::fmt::Display for MeshStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "  Total services: {}", self.total_services)?;
        writeln!(f, "  Services per layer: {:?}", self.services_per_layer)?;
        writeln!(
            f,
            "  Total outbound dependencies: {}",
            self.total_outbound_deps
        )?;
        writeln!(
            f,
            "  Total inbound allowances: {}",
            self.total_inbound_allows
        )?;
        writeln!(f, "  External services: {}", self.total_external_services)?;
        writeln!(
            f,
            "  External outbound dependencies: {}",
            self.total_external_outbound_deps
        )?;
        writeln!(
            f,
            "  Total connection tests: {} ({} internal, {} external)",
            self.total_tests,
            self.total_tests - self.total_external_tests,
            self.total_external_tests
        )?;
        writeln!(
            f,
            "  Expected ALLOWED: {} ({:.1}%)",
            self.expected_allowed,
            (self.expected_allowed as f64 / self.total_tests as f64) * 100.0
        )?;
        writeln!(
            f,
            "  Expected BLOCKED: {} ({:.1}%)",
            self.expected_blocked,
            (self.expected_blocked as f64 / self.total_tests as f64) * 100.0
        )
    }
}

/// Namespace for randomized mesh test
const RANDOM_MESH_NAMESPACE: &str = "random-mesh";

/// Deploy all services in the randomized mesh
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

    // Deploy external services first (cluster-scoped)
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

    // Deploy from bottom layer up (backends first, then APIs, then frontends)
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

        // Small delay between layers
        sleep(Duration::from_secs(2)).await;
    }

    println!(
        "  All {} services + {} external services deployed!",
        mesh.services.len(),
        mesh.external_services.len()
    );
    Ok(())
}

/// Wait for all pods in the random mesh to be ready
async fn wait_for_random_mesh_pods(mesh: &RandomMesh, kubeconfig_path: &str) -> Result<(), String> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(600); // 10 minutes for many pods
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

/// Verify traffic patterns for the randomized mesh - EXACT MATCH REQUIRED
/// Note: Caller must wait for traffic tests to run before calling this
async fn verify_random_mesh_traffic(
    mesh: &RandomMesh,
    kubeconfig_path: &str,
) -> Result<(), String> {
    // Build a map of expected results for exact matching
    // Key: (source, target), Value: (expected_allowed, is_external, actual_result)
    let mut results: BTreeMap<(String, String), (bool, bool, Option<bool>)> = BTreeMap::new();
    for (src, tgt, expected, is_external) in &mesh.expected_connections {
        results.insert((src.clone(), tgt.clone()), (*expected, *is_external, None));
    }

    // Get all traffic generator names
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

    // Collect actual results from logs
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

        // Check each expected connection from this source
        for ((src, tgt), (_, _, actual)) in results.iter_mut() {
            if src != source {
                continue;
            }

            // Look for result patterns
            let allowed_pattern = format!("{}->{}:ALLOWED", src, tgt);
            let blocked_pattern = format!("{}->{}:BLOCKED", src, tgt);

            let saw_allowed = logs.contains(&allowed_pattern);
            let saw_blocked = logs.contains(&blocked_pattern);

            if saw_allowed {
                *actual = Some(true);
            } else if saw_blocked {
                *actual = Some(false);
            }
            // For expected ALLOWED: seeing ALLOWED anywhere = success (ignores early BLOCKEDs from policy delay)
            // For expected BLOCKED: seeing ALLOWED = failure (policy shouldn't allow this)
        }
    }

    // Compare expected vs actual - EXACT MATCH REQUIRED
    let mut mismatches: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();

    for ((src, tgt), (expected, is_external, actual)) in &results {
        let marker = if *is_external { " [EXT]" } else { "" };
        match actual {
            None => {
                missing.push(format!("{} -> {}{}", src, tgt, marker));
            }
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

    // Print results
    let total = results.len();
    let passed = total - mismatches.len() - missing.len();

    println!("\n  ========================================");
    println!("  EXACT MATCH VERIFICATION");
    println!("  ========================================");
    println!("  Total expected: {}", total);
    println!("  Matched exactly: {}", passed);
    println!("  Mismatches: {}", mismatches.len());
    println!("  Missing results: {}", missing.len());

    if !mismatches.is_empty() || !missing.is_empty() {
        if !mismatches.is_empty() {
            println!("\n  MISMATCHES:");
            for m in &mismatches {
                println!("    {}", m);
            }
        }
        if !missing.is_empty() {
            println!("\n  MISSING (no result in logs):");
            for m in missing.iter().take(20) {
                println!("    {}", m);
            }
            if missing.len() > 20 {
                println!("    ... and {} more", missing.len() - 20);
            }
        }
        return Err(format!(
            "EXACT MATCH FAILED: {} mismatches, {} missing out of {} tests",
            mismatches.len(),
            missing.len(),
            total
        ));
    }

    println!("\n  SUCCESS: All {} tests matched exactly!", total);
    Ok(())
}
