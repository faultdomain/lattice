//! Provider-configurable end-to-end test for Lattice installation, pivot, and unpivot flow
//!
//! This test validates the full Lattice lifecycle including:
//! - Management cluster installation and self-management
//! - Workload cluster provisioning and pivot
//! - Deep cluster hierarchy (workload1 -> workload2)
//! - Independence (workload survives parent deletion)
//! - Unpivot (CAPI resources return to parent on delete)
//!
//! # Test Phases
//!
//! 1. Install management cluster
//! 2. Verify management cluster is self-managing
//! 3. Create workload cluster 1 off management cluster
//! 4. Watch workload1 provisioning and pivot
//! 5. Verify workload1 has CAPI resources
//! 6. Worker scaling verification
//! 7. Independence test - delete management, scale workload1
//! 8-9. Run in parallel:
//!      - Hierarchy test (workload2 create/verify/delete)
//!      - Service mesh tests (bilateral + randomized)
//!
//! # Design Philosophy
//!
//! All cluster configuration is defined in LatticeCluster CRD files. This ensures:
//! - Complete, self-contained cluster definitions
//! - Proper handling of secrets via secretRef
//! - Same CRD can be deployed to any cluster
//! - Consistent approach regardless of provider
//!
//! # Environment Variables
//!
//! ## Cluster Configuration (optional - defaults to Docker fixtures)
//! - LATTICE_MGMT_CLUSTER_CONFIG: Path to LatticeCluster YAML for management cluster
//! - LATTICE_WORKLOAD_CLUSTER_CONFIG: Path to LatticeCluster YAML for workload cluster
//! - LATTICE_WORKLOAD2_CLUSTER_CONFIG: Path to LatticeCluster YAML for second workload cluster
//!
//! ## Optional Test Phases (all default to true)
//! - LATTICE_ENABLE_INDEPENDENCE_TEST=false: Disable Phase 7 (delete mgmt, verify workload self-manages)
//! - LATTICE_ENABLE_HIERARCHY_TEST=false: Disable Phase 8-11 (deep hierarchy and unpivot)
//! - LATTICE_ENABLE_MESH_TEST=true: Enable Phase 12-13 (service mesh validation tests)
//!
//! # Running
//!
//! ```bash
//! # Docker clusters (uses default fixtures)
//! cargo test --features provider-e2e --test e2e pivot_e2e -- --nocapture
//!
//! # Proxmox clusters (custom configs)
//! LATTICE_MGMT_CLUSTER_CONFIG=crates/lattice-cli/tests/e2e/fixtures/clusters/proxmox-mgmt.yaml \
//!   LATTICE_WORKLOAD_CLUSTER_CONFIG=crates/lattice-cli/tests/e2e/fixtures/clusters/proxmox-workload.yaml \
//!   LATTICE_WORKLOAD2_CLUSTER_CONFIG=crates/lattice-cli/tests/e2e/fixtures/clusters/proxmox-workload2.yaml \
//!   cargo test --features provider-e2e --test e2e pivot_e2e -- --nocapture
//! ```
//!
//! # Example CRD Files
//!
//! See `crates/lattice-cli/tests/e2e/fixtures/clusters/` for LatticeCluster CRD files.

#![cfg(feature = "provider-e2e")]

use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::time::Duration;

use base64::Engine;
use kube::api::{Api, PostParams};

use lattice_cli::commands::install::Installer;
use lattice_operator::crd::LatticeCluster;

use super::helpers::{
    client_from_kubeconfig, ensure_docker_network, extract_docker_cluster_kubeconfig, run_cmd,
    run_cmd_allow_fail, verify_control_plane_taints, watch_cluster_phases,
    watch_cluster_phases_with_kubeconfig, watch_worker_scaling,
};
use super::mesh_tests::{mesh_test_enabled, run_mesh_test, run_random_mesh_test};
use super::providers::InfraProvider;

// =============================================================================
// Test Configuration
// =============================================================================

const E2E_TIMEOUT: Duration = Duration::from_secs(3600);
const MGMT_CLUSTER_NAME: &str = "e2e-mgmt";
const WORKLOAD_CLUSTER_NAME: &str = "e2e-workload";
const WORKLOAD2_CLUSTER_NAME: &str = "e2e-workload2";
const LATTICE_IMAGE: &str = "ghcr.io/evan-hines-js/lattice:latest";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("lattice-cli crate should have a parent directory")
        .parent()
        .expect("crates directory should have a parent (workspace root)")
        .to_path_buf()
}

// =============================================================================
// Helper Functions
// =============================================================================

async fn build_and_push_lattice_image() -> Result<(), String> {
    println!("  Building lattice Docker image...");

    let output = ProcessCommand::new("./scripts/docker-build.sh")
        .args(["-t", LATTICE_IMAGE])
        .env("DOCKER_BUILDKIT", "1")
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

fn load_registry_credentials() -> Option<String> {
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
            let auth = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", u, t));
            let docker_config = serde_json::json!({
                "auths": { "ghcr.io": { "auth": auth } }
            });
            return Some(docker_config.to_string());
        }
    }

    if let (Ok(u), Ok(t)) = (std::env::var("GHCR_USER"), std::env::var("GHCR_TOKEN")) {
        let auth = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", u, t));
        let docker_config = serde_json::json!({
            "auths": { "ghcr.io": { "auth": auth } }
        });
        return Some(docker_config.to_string());
    }

    None
}

/// Default fixture paths for cluster configs
fn default_cluster_config_path(env_var: &str) -> Option<PathBuf> {
    let fixtures_dir = workspace_root().join("crates/lattice-cli/tests/e2e/fixtures/clusters");
    match env_var {
        "LATTICE_MGMT_CLUSTER_CONFIG" => Some(fixtures_dir.join("docker-mgmt.yaml")),
        "LATTICE_WORKLOAD_CLUSTER_CONFIG" => Some(fixtures_dir.join("docker-workload.yaml")),
        "LATTICE_WORKLOAD2_CLUSTER_CONFIG" => Some(fixtures_dir.join("docker-workload2.yaml")),
        _ => None,
    }
}

/// Load cluster configuration from a CRD file.
///
/// Uses env var if set, otherwise falls back to default Docker fixture path.
///
/// # Arguments
/// * `env_var` - Environment variable name containing path to the CRD file
///
/// # Returns
/// Tuple of (config_content, parsed_cluster)
fn load_cluster_config(env_var: &str) -> Result<(String, LatticeCluster), String> {
    let path = match std::env::var(env_var) {
        Ok(p) => PathBuf::from(p),
        Err(_) => default_cluster_config_path(env_var)
            .ok_or_else(|| format!("No cluster config provided and no default for {}", env_var))?,
    };

    if !path.exists() {
        return Err(format!("Cluster config file not found: {}", path.display()));
    }

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read cluster config {}: {}", path.display(), e))?;

    let cluster: LatticeCluster = serde_yaml::from_str(&content)
        .map_err(|e| format!("Invalid LatticeCluster YAML in {}: {}", path.display(), e))?;

    println!("  Loaded cluster config from: {}", path.display());
    Ok((content, cluster))
}

fn get_management_kubeconfig(provider: InfraProvider) -> Result<String, String> {
    let kubeconfig_path = format!("/tmp/{}-kubeconfig", MGMT_CLUSTER_NAME);
    let kubeconfig = std::fs::read_to_string(&kubeconfig_path)
        .map_err(|e| format!("Failed to read kubeconfig: {}", e))?;

    if provider == InfraProvider::Docker {
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

        let patched_path = format!("/tmp/{}-kubeconfig-local", MGMT_CLUSTER_NAME);
        std::fs::write(&patched_path, &patched)
            .map_err(|e| format!("Failed to write patched kubeconfig: {}", e))?;

        return Ok(patched_path);
    }

    Ok(kubeconfig_path)
}

// =============================================================================
// Cleanup Functions
// =============================================================================

fn cleanup_clusters() {
    println!("  Cleaning up all kind clusters...");
    let _ = run_cmd_allow_fail("kind", &["delete", "clusters", "--all"]);
}

fn cleanup_all() {
    println!("  Full cleanup...");
    cleanup_clusters();
}

// =============================================================================
// Main Test
// =============================================================================

#[tokio::test]
async fn test_configurable_provider_pivot() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Initialize tracing for log output
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    println!("\n################################################################");
    println!("#  CONFIGURABLE PROVIDER E2E TEST");
    println!("################################################################\n");

    cleanup_clusters();

    if let Err(e) = build_and_push_lattice_image().await {
        cleanup_all();
        panic!("Failed to build Lattice image: {}", e);
    }

    let result = tokio::time::timeout(E2E_TIMEOUT, run_provider_e2e()).await;

    match result {
        Ok(Ok(())) => {
            println!("\n################################################################");
            println!("#  TEST PASSED");
            println!("################################################################\n");
        }
        Ok(Err(e)) => {
            println!("\n=== TEST FAILED: {} ===\n", e);
            panic!("E2E test failed: {}", e);
        }
        Err(_) => {
            println!("\n=== TEST TIMED OUT ({:?}) ===\n", E2E_TIMEOUT);
            panic!("E2E test timed out after {:?}", E2E_TIMEOUT);
        }
    }

    cleanup_all();
}

async fn run_provider_e2e() -> Result<(), String> {
    // =========================================================================
    // Load all cluster configs upfront (fail early if missing)
    // =========================================================================
    println!("Loading cluster configurations...\n");

    let (mgmt_config_content, mgmt_cluster) = load_cluster_config("LATTICE_MGMT_CLUSTER_CONFIG")?;
    let mgmt_provider: InfraProvider = mgmt_cluster.spec.provider.provider_type().into();
    let mgmt_bootstrap = mgmt_cluster.spec.provider.kubernetes.bootstrap.clone();

    let (workload_config_content, workload_cluster) =
        load_cluster_config("LATTICE_WORKLOAD_CLUSTER_CONFIG")?;
    let workload_provider: InfraProvider = workload_cluster.spec.provider.provider_type().into();
    let workload_bootstrap = workload_cluster.spec.provider.kubernetes.bootstrap.clone();

    let workload2_config = if hierarchy_test_enabled() {
        Some(load_cluster_config("LATTICE_WORKLOAD2_CLUSTER_CONFIG")?)
    } else {
        None
    };

    println!("Configuration:");
    println!("  Management:  {} + {:?}", mgmt_provider, mgmt_bootstrap);
    println!(
        "  Workload:    {} + {:?}",
        workload_provider, workload_bootstrap
    );
    if let Some((_, ref wl2)) = workload2_config {
        let wl2_bootstrap = &wl2.spec.provider.kubernetes.bootstrap;
        println!("  Workload2:   {} + {:?}", workload_provider, wl2_bootstrap);
    }
    println!();

    // Setup Docker network if needed
    if mgmt_provider == InfraProvider::Docker {
        if let Err(e) = ensure_docker_network() {
            return Err(format!("Failed to setup Docker network: {}", e));
        }
    }

    // =========================================================================
    // Phase 1: Install Management Cluster
    // =========================================================================
    println!(
        "\n[Phase 1] Installing management cluster ({} + {:?})...\n",
        mgmt_provider, mgmt_bootstrap
    );
    println!("  Cluster config:\n{}", mgmt_config_content);

    let registry_credentials = load_registry_credentials();
    if registry_credentials.is_some() {
        println!("  Registry credentials loaded");
    }

    let installer = Installer::new(
        mgmt_config_content,
        LATTICE_IMAGE.to_string(),
        true, // keep_bootstrap_on_failure
        registry_credentials,
        None, // bootstrap_override
    )
    .map_err(|e| format!("Failed to create installer: {}", e))?;
    installer
        .run()
        .await
        .map_err(|e| format!("Installer failed: {}", e))?;

    println!("\n  Management cluster installation complete!");

    // =========================================================================
    // Phase 2: Verify Management Cluster is Self-Managing
    // =========================================================================
    println!("\n[Phase 2] Verifying management cluster is self-managing...\n");

    let kubeconfig_path = get_management_kubeconfig(mgmt_provider)?;
    println!("  Using kubeconfig: {}", kubeconfig_path);

    let mgmt_client = client_from_kubeconfig(&kubeconfig_path).await?;

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

    println!("  Waiting for management cluster's LatticeCluster to be Ready...");
    watch_cluster_phases(&mgmt_client, MGMT_CLUSTER_NAME, None).await?;

    println!("\n  SUCCESS: Management cluster is self-managing!");

    // =========================================================================
    // Phase 3: Create Workload Cluster
    // =========================================================================
    println!(
        "\n[Phase 3] Creating workload cluster ({} + {:?})...\n",
        workload_provider, workload_bootstrap
    );
    println!("  Workload cluster config:\n{}", workload_config_content);

    let api: Api<LatticeCluster> = Api::all(mgmt_client.clone());
    api.create(&PostParams::default(), &workload_cluster)
        .await
        .map_err(|e| format!("Failed to create workload LatticeCluster: {}", e))?;

    println!("  Workload LatticeCluster created");

    // =========================================================================
    // Phase 4: Watch Workload Cluster Provisioning
    // =========================================================================
    println!("\n[Phase 4] Watching workload cluster provisioning...\n");

    let workload_kubeconfig_path = format!("/tmp/{}-kubeconfig", WORKLOAD_CLUSTER_NAME);

    // For non-Docker providers, extract kubeconfig DURING provisioning (before pivot moves it)
    if workload_provider == InfraProvider::Docker {
        watch_cluster_phases(&mgmt_client, WORKLOAD_CLUSTER_NAME, None).await?;
    } else {
        watch_cluster_phases_with_kubeconfig(
            &kubeconfig_path,
            WORKLOAD_CLUSTER_NAME,
            None,
            &workload_kubeconfig_path,
        )
        .await?;
    }

    println!("\n  SUCCESS: Workload cluster is Ready!");

    // =========================================================================
    // Phase 5: Extract Workload Cluster Kubeconfig and Verify
    // =========================================================================
    println!("\n[Phase 5] Verifying workload cluster...\n");

    // For Docker, extract kubeconfig now (it's not pivoted away like CAPI secrets)
    if workload_provider == InfraProvider::Docker {
        println!("  Extracting workload cluster kubeconfig...");
        extract_docker_cluster_kubeconfig(
            WORKLOAD_CLUSTER_NAME,
            &workload_bootstrap,
            &workload_kubeconfig_path,
        )?;
        println!("  Kubeconfig extracted successfully");
    } else {
        println!("  Using kubeconfig extracted during provisioning");
    }

    let nodes_output = run_cmd(
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
    println!("  Workload cluster nodes:\n{}", nodes_output);

    println!("  Checking for CAPI resources on workload cluster...");
    match run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &workload_kubeconfig_path,
            "get",
            "clusters",
            "-A",
        ],
    ) {
        Ok(output) => {
            println!("  Workload cluster CAPI resources:\n{}", output);
            if !output.contains(WORKLOAD_CLUSTER_NAME) {
                return Err(
                    "Workload cluster should have its own CAPI Cluster resource after pivot"
                        .to_string(),
                );
            }
        }
        Err(e) => println!("  Warning: Could not check CAPI resources: {}", e),
    }

    // =========================================================================
    // Phase 6: Worker Scaling Verification
    // =========================================================================
    println!("\n[Phase 6] Watching worker scaling...\n");
    watch_worker_scaling(&workload_kubeconfig_path, WORKLOAD_CLUSTER_NAME, 1).await?;

    // =========================================================================
    // Phase 7: Independence Verification
    // =========================================================================
    if independence_test_enabled() {
        println!("\n[Phase 7] Proving workload cluster is truly self-managing...\n");

        println!("  [Step 1] Deleting management cluster...");
        if workload_provider == InfraProvider::Docker {
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
        } else {
            // Cloud provider: delete via kubectl
            let _ = run_cmd_allow_fail(
                "kubectl",
                &[
                    "--kubeconfig",
                    &kubeconfig_path,
                    "delete",
                    "latticecluster",
                    MGMT_CLUSTER_NAME,
                    "--timeout=300s",
                ],
            );
        }
        println!("    Management cluster deleted!");

        println!("\n  [Step 2] Scaling workload cluster workers 1 -> 2...");
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
                r#"{"spec":{"nodes":{"workers":2}}}"#,
            ],
        )?;
        println!("    Patch applied: {}", patch_result.trim());

        println!(
            "\n  [Step 3] Waiting for workload cluster to self-heal and scale to 2 workers..."
        );
        watch_worker_scaling(&workload_kubeconfig_path, WORKLOAD_CLUSTER_NAME, 2).await?;

        println!(
            "\n  SUCCESS: Workload cluster scaled from 1 to 2 workers WITHOUT management cluster!"
        );

        println!("\n  [Step 4] Verifying control-plane taints were restored...");
        verify_control_plane_taints(&workload_kubeconfig_path).await?;
        println!("    [x] Control-plane taints restored by controller");
    } else {
        println!("\n[Phase 7] Skipping independence test (set LATTICE_ENABLE_INDEPENDENCE_TEST=true to enable)\n");
    }

    // =========================================================================
    // Phase 8-9: Run hierarchy test and mesh tests in parallel
    // =========================================================================
    let run_hierarchy = workload2_config.is_some();
    let run_mesh = mesh_test_enabled();

    if run_hierarchy || run_mesh {
        println!("\n[Phase 8-9] Running tests in parallel...\n");
        if run_hierarchy {
            println!("  - Hierarchy test (workload2 provisioning)");
        }
        if run_mesh {
            println!("  - Service mesh bilateral agreement test");
            println!("  - Service mesh randomized large-scale test");
        }
        println!();

        // Spawn hierarchy test if enabled
        let hierarchy_handle =
            if let Some((workload2_config_content, workload2_cluster)) = workload2_config {
                let kubeconfig = workload_kubeconfig_path.clone();
                let provider = workload_provider;
                Some(tokio::spawn(async move {
                    run_hierarchy_test(
                        workload2_config_content,
                        workload2_cluster,
                        &kubeconfig,
                        provider,
                    )
                    .await
                }))
            } else {
                None
            };

        // Spawn mesh tests if enabled
        let mesh_handle = if run_mesh {
            let kubeconfig = workload_kubeconfig_path.clone();
            Some(tokio::spawn(async move {
                let kubeconfig2 = kubeconfig.clone();
                let (result1, result2) = tokio::join!(
                    run_mesh_test(&kubeconfig),
                    run_random_mesh_test(&kubeconfig2)
                );
                result1?;
                result2
            }))
        } else {
            None
        };

        // Wait for both to complete
        if let Some(handle) = hierarchy_handle {
            handle
                .await
                .map_err(|e| format!("Hierarchy test task failed: {}", e))??;
        }
        if let Some(handle) = mesh_handle {
            handle
                .await
                .map_err(|e| format!("Mesh test task failed: {}", e))??;
        }
    } else {
        println!("\n[Phase 8-9] Skipping optional tests\n");
        println!("  Set LATTICE_ENABLE_HIERARCHY_TEST=true for hierarchy test");
        println!("  Set LATTICE_ENABLE_MESH_TEST=true for mesh tests");
    }

    println!("\n################################################################");
    println!("#  E2E TEST COMPLETE");
    println!("#  Management: {} + {:?}", mgmt_provider, mgmt_bootstrap);
    println!(
        "#  Workload:   {} + {:?}",
        workload_provider, workload_bootstrap
    );
    if run_hierarchy {
        println!("#  Hierarchy + unpivot: TESTED (parallel)");
    }
    if run_mesh {
        println!("#  Service mesh: TESTED (parallel)");
    }
    println!("################################################################\n");

    Ok(())
}

/// Run hierarchy test: create workload2 off workload1, verify, then delete (unpivot)
async fn run_hierarchy_test(
    workload2_config_content: String,
    workload2_cluster: LatticeCluster,
    workload_kubeconfig_path: &str,
    workload_provider: InfraProvider,
) -> Result<(), String> {
    println!("[Hierarchy] Creating second workload cluster (deep hierarchy)...\n");
    println!("  This tests creating a cluster off workload1 (which just lost its parent)");

    let workload2_bootstrap = workload2_cluster.spec.provider.kubernetes.bootstrap.clone();
    println!("  Workload2 cluster config:\n{}", workload2_config_content);
    println!("  Workload2 bootstrap provider: {:?}", workload2_bootstrap);

    // Connect to workload1 cluster and create workload2
    let workload_client = client_from_kubeconfig(workload_kubeconfig_path).await?;
    let api: Api<LatticeCluster> = Api::all(workload_client.clone());
    api.create(&PostParams::default(), &workload2_cluster)
        .await
        .map_err(|e| format!("Failed to create workload2 LatticeCluster: {}", e))?;

    println!("  Workload2 LatticeCluster created on workload1");

    println!("\n[Hierarchy] Watching workload2 cluster provisioning...\n");

    let workload2_kubeconfig_path = format!("/tmp/{}-kubeconfig", WORKLOAD2_CLUSTER_NAME);

    if workload_provider == InfraProvider::Docker {
        watch_cluster_phases(&workload_client, WORKLOAD2_CLUSTER_NAME, None).await?;
    } else {
        watch_cluster_phases_with_kubeconfig(
            workload_kubeconfig_path,
            WORKLOAD2_CLUSTER_NAME,
            None,
            &workload2_kubeconfig_path,
        )
        .await?;
    }

    println!("\n  SUCCESS: Workload2 cluster is Ready!");

    println!("\n[Hierarchy] Verifying workload2 cluster...\n");

    if workload_provider == InfraProvider::Docker {
        println!("  Extracting workload2 cluster kubeconfig...");
        extract_docker_cluster_kubeconfig(
            WORKLOAD2_CLUSTER_NAME,
            &workload2_bootstrap,
            &workload2_kubeconfig_path,
        )?;
        println!("  Kubeconfig extracted successfully");
    }

    let nodes_output = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &workload2_kubeconfig_path,
            "get",
            "nodes",
            "-o",
            "wide",
        ],
    )?;
    println!("  Workload2 cluster nodes:\n{}", nodes_output);

    println!("  Checking for CAPI resources on workload2 cluster...");
    match run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &workload2_kubeconfig_path,
            "get",
            "clusters",
            "-A",
        ],
    ) {
        Ok(output) => {
            println!("  Workload2 cluster CAPI resources:\n{}", output);
            if !output.contains(WORKLOAD2_CLUSTER_NAME) {
                return Err(
                    "Workload2 cluster should have its own CAPI Cluster resource after pivot"
                        .to_string(),
                );
            }
        }
        Err(e) => println!("  Warning: Could not check CAPI resources: {}", e),
    }

    println!("\n  SUCCESS: Deep hierarchy verified (mgmt -> workload1 -> workload2)!");

    println!("\n[Hierarchy] Deleting workload2 cluster (testing unpivot)...\n");
    println!("  This tests the unpivot flow: CAPI resources should move back to workload1");

    let _ = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &workload2_kubeconfig_path,
            "delete",
            "latticecluster",
            WORKLOAD2_CLUSTER_NAME,
            "--timeout=300s",
        ],
    )?;
    println!("  Workload2 LatticeCluster deletion initiated");

    println!("  Waiting for workload2 cluster to be fully deleted...");
    let mut attempts = 0;
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        attempts += 1;

        let check = run_cmd_allow_fail(
            "kubectl",
            &[
                "--kubeconfig",
                workload_kubeconfig_path,
                "get",
                "latticecluster",
                WORKLOAD2_CLUSTER_NAME,
                "-o",
                "name",
            ],
        );

        if check.trim().is_empty() || check.contains("not found") {
            println!("  Workload2 LatticeCluster deleted from workload1");
            break;
        }

        if attempts > 30 {
            return Err("Timeout waiting for workload2 deletion".to_string());
        }

        println!(
            "    Still waiting for deletion... (attempt {}/30)",
            attempts
        );
    }

    if workload_provider == InfraProvider::Docker {
        println!("  Waiting for workload2 Docker containers to be cleaned up...");
        let mut container_attempts = 0;
        loop {
            container_attempts += 1;
            tokio::time::sleep(Duration::from_secs(5)).await;

            let workload2_containers = run_cmd_allow_fail(
                "docker",
                &[
                    "ps",
                    "-a",
                    "--filter",
                    &format!("name={}", WORKLOAD2_CLUSTER_NAME),
                    "-q",
                ],
            );

            if workload2_containers.trim().is_empty() {
                println!("  SUCCESS: Workload2 Docker containers cleaned up by CAPI");
                break;
            }

            if container_attempts > 30 {
                return Err(format!(
                    "Timeout waiting for workload2 containers to be deleted. Still running: {}",
                    workload2_containers.trim()
                ));
            }

            println!(
                "    Still waiting for container cleanup... (attempt {}/30)",
                container_attempts
            );
        }
    }

    println!("\n[Hierarchy] SUCCESS: Unpivot test complete!");
    Ok(())
}

fn independence_test_enabled() -> bool {
    std::env::var("LATTICE_ENABLE_INDEPENDENCE_TEST")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true) // Default to true now since it's part of the flow
}

fn hierarchy_test_enabled() -> bool {
    std::env::var("LATTICE_ENABLE_HIERARCHY_TEST")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true) // Default to true now since it's part of the flow
}
