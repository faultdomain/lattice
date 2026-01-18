//! Provider-configurable end-to-end test for Lattice installation and pivot flow
//!
//! This test validates the full Lattice lifecycle using LatticeCluster CRD files.
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
//! ## Cluster Configuration (required)
//! - LATTICE_MGMT_CLUSTER_CONFIG: Path to LatticeCluster YAML for management cluster
//! - LATTICE_WORKLOAD_CLUSTER_CONFIG: Path to LatticeCluster YAML for workload cluster
//!
//! ## Provider Hints (for test behavior, extracted from CRD)
//! - LATTICE_MGMT_PROVIDER: Provider hint for test phases (docker|aws|openstack|proxmox)
//! - LATTICE_WORKLOAD_PROVIDER: Provider hint for test phases (docker|aws|openstack|proxmox)
//!
//! ## Optional Test Phases
//! - LATTICE_ENABLE_INDEPENDENCE_TEST=true: Enable Phase 7 (delete mgmt, verify workload self-manages)
//! - LATTICE_ENABLE_MESH_TEST=true: Enable Phase 8-9 (service mesh validation tests)
//!
//! # Running
//!
//! ```bash
//! # Docker clusters
//! LATTICE_MGMT_CLUSTER_CONFIG=crates/lattice-cli/tests/e2e/fixtures/clusters/docker-mgmt.yaml \
//!   LATTICE_WORKLOAD_CLUSTER_CONFIG=crates/lattice-cli/tests/e2e/fixtures/clusters/docker-workload.yaml \
//!   LATTICE_MGMT_PROVIDER=docker \
//!   LATTICE_WORKLOAD_PROVIDER=docker \
//!   cargo test --features provider-e2e --test e2e pivot_e2e -- --nocapture
//!
//! # Proxmox clusters
//! LATTICE_MGMT_CLUSTER_CONFIG=crates/lattice-cli/tests/e2e/fixtures/clusters/proxmox-mgmt.yaml \
//!   LATTICE_WORKLOAD_CLUSTER_CONFIG=crates/lattice-cli/tests/e2e/fixtures/clusters/proxmox-workload.yaml \
//!   LATTICE_MGMT_PROVIDER=proxmox \
//!   LATTICE_WORKLOAD_PROVIDER=proxmox \
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

use lattice_cli::commands::install::{InstallConfig, Installer};
use lattice_operator::crd::{BootstrapProvider, LatticeCluster};

use super::helpers::{
    client_from_kubeconfig, ensure_docker_network, extract_capi_kubeconfig,
    extract_docker_cluster_kubeconfig, run_cmd, run_cmd_allow_fail, verify_control_plane_taints,
    watch_cluster_phases, watch_worker_scaling,
};
use super::mesh_tests::{mesh_test_enabled, run_mesh_test, run_random_mesh_test};
use super::providers::InfraProvider;

// =============================================================================
// Test Configuration
// =============================================================================

const E2E_TIMEOUT: Duration = Duration::from_secs(3600);
const MGMT_CLUSTER_NAME: &str = "e2e-mgmt";
const WORKLOAD_CLUSTER_NAME: &str = "e2e-workload";
const LATTICE_IMAGE: &str = "ghcr.io/evan-hines-js/lattice:latest";

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

/// Load cluster configuration from a CRD file.
///
/// All cluster configuration is defined in LatticeCluster CRD files. This ensures:
/// - Complete, self-contained cluster definitions
/// - Proper handling of secrets via secretRef
/// - Same CRD can be deployed to any cluster
/// - Consistent approach regardless of provider
///
/// # Arguments
/// * `env_var` - Environment variable name containing path to the CRD file
///
/// # Returns
/// Tuple of (config_path, config_content)
fn load_cluster_config(env_var: &str) -> Result<(PathBuf, String), String> {
    let config_path = std::env::var(env_var).map_err(|_| {
        format!(
            "No cluster config provided. Set {} to a LatticeCluster YAML file.\n\
             Example CRD files are in crates/lattice-cli/tests/e2e/fixtures/clusters/",
            env_var
        )
    })?;

    let path = PathBuf::from(&config_path);
    if !path.exists() {
        return Err(format!(
            "Cluster config file not found: {} (specified via {})",
            config_path, env_var
        ));
    }

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read cluster config {}: {}", config_path, e))?;

    // Validate the YAML parses as a LatticeCluster
    let _: LatticeCluster = serde_yaml::from_str(&content)
        .map_err(|e| format!("Invalid LatticeCluster YAML in {}: {}", config_path, e))?;

    println!("  Loaded cluster config from: {}", config_path);
    Ok((path, content))
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

    let mgmt_provider = InfraProvider::from_env("LATTICE_MGMT_PROVIDER", InfraProvider::Docker);
    let workload_provider =
        InfraProvider::from_env("LATTICE_WORKLOAD_PROVIDER", InfraProvider::Docker);

    let mgmt_bootstrap = match std::env::var("LATTICE_MGMT_BOOTSTRAP").as_deref() {
        Ok("kubeadm") => BootstrapProvider::Kubeadm,
        _ => BootstrapProvider::Rke2,
    };

    let workload_bootstrap = match std::env::var("LATTICE_WORKLOAD_BOOTSTRAP").as_deref() {
        Ok("rke2") => BootstrapProvider::Rke2,
        _ => BootstrapProvider::Kubeadm,
    };

    println!("\n################################################################");
    println!("#  CONFIGURABLE PROVIDER E2E TEST");
    println!("################################################################");
    println!("\nConfiguration:");
    println!(
        "  Management cluster:  {} + {:?}",
        mgmt_provider, mgmt_bootstrap
    );
    println!(
        "  Workload cluster:    {} + {:?}",
        workload_provider, workload_bootstrap
    );
    println!();

    cleanup_clusters();

    if mgmt_provider == InfraProvider::Docker || workload_provider == InfraProvider::Docker {
        if let Err(e) = ensure_docker_network() {
            panic!("Failed to setup Docker network: {}", e);
        }
    }

    if let Err(e) = build_and_push_lattice_image().await {
        cleanup_all();
        panic!("Failed to build Lattice image: {}", e);
    }

    let result = tokio::time::timeout(
        E2E_TIMEOUT,
        run_provider_e2e(
            mgmt_provider,
            mgmt_bootstrap,
            workload_provider,
            workload_bootstrap,
        ),
    )
    .await;

    match result {
        Ok(Ok(())) => {
            println!("\n################################################################");
            println!("#  TEST PASSED: {} → {}", mgmt_provider, workload_provider);
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

async fn run_provider_e2e(
    mgmt_provider: InfraProvider,
    mgmt_bootstrap: BootstrapProvider,
    workload_provider: InfraProvider,
    workload_bootstrap: BootstrapProvider,
) -> Result<(), String> {
    // =========================================================================
    // Phase 1: Install Management Cluster
    // =========================================================================
    println!(
        "\n[Phase 1] Installing management cluster ({} + {:?})...\n",
        mgmt_provider, mgmt_bootstrap
    );

    // Load cluster config from CRD file
    let (config_path, cluster_config) = load_cluster_config("LATTICE_MGMT_CLUSTER_CONFIG")?;
    println!("  Cluster config:\n{}", cluster_config);

    let registry_credentials = load_registry_credentials();
    if registry_credentials.is_some() {
        println!("  Registry credentials loaded");
    }

    let install_config = InstallConfig {
        cluster_config_path: config_path,
        cluster_config_content: cluster_config,
        image: LATTICE_IMAGE.to_string(),
        keep_bootstrap_on_failure: true,
        timeout: Duration::from_secs(2400),
        registry_credentials,
        bootstrap_override: None,
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

    // Load workload cluster config from CRD file
    let (_workload_config_path, workload_config) =
        load_cluster_config("LATTICE_WORKLOAD_CLUSTER_CONFIG")?;
    println!("  Workload cluster config:\n{}", workload_config);

    let workload_cluster: LatticeCluster = serde_yaml::from_str(&workload_config)
        .map_err(|e| format!("Failed to parse workload cluster config: {}", e))?;

    let api: Api<LatticeCluster> = Api::all(mgmt_client.clone());
    api.create(&PostParams::default(), &workload_cluster)
        .await
        .map_err(|e| format!("Failed to create workload LatticeCluster: {}", e))?;

    println!("  Workload LatticeCluster created");

    // =========================================================================
    // Phase 4: Watch Workload Cluster Provisioning
    // =========================================================================
    println!("\n[Phase 4] Watching workload cluster provisioning...\n");

    watch_cluster_phases(&mgmt_client, WORKLOAD_CLUSTER_NAME, None).await?;

    println!("\n  SUCCESS: Workload cluster is Ready!");

    // =========================================================================
    // Phase 5: Extract Workload Cluster Kubeconfig and Verify
    // =========================================================================
    println!("\n[Phase 5] Verifying workload cluster...\n");

    let workload_kubeconfig_path = format!("/tmp/{}-kubeconfig", WORKLOAD_CLUSTER_NAME);

    println!("  Extracting workload cluster kubeconfig...");
    if workload_provider == InfraProvider::Docker {
        extract_docker_cluster_kubeconfig(
            WORKLOAD_CLUSTER_NAME,
            &workload_bootstrap,
            &workload_kubeconfig_path,
        )?;
    } else {
        extract_capi_kubeconfig(
            &kubeconfig_path,
            WORKLOAD_CLUSTER_NAME,
            &workload_kubeconfig_path,
        )
        .await?;
    }
    println!("  Kubeconfig extracted successfully");

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
    watch_worker_scaling(&workload_kubeconfig_path, WORKLOAD_CLUSTER_NAME, 2).await?;

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

        println!(
            "\n  [Step 3] Waiting for workload cluster to self-heal and scale to 3 workers..."
        );
        watch_worker_scaling(&workload_kubeconfig_path, WORKLOAD_CLUSTER_NAME, 3).await?;

        println!(
            "\n  SUCCESS: Workload cluster scaled from 2 to 3 workers WITHOUT management cluster!"
        );

        println!("\n  [Step 4] Verifying control-plane taints were restored...");
        verify_control_plane_taints(&workload_kubeconfig_path).await?;
        println!("    [x] Control-plane taints restored by controller");
    } else {
        println!("\n[Phase 7] Skipping independence test (set LATTICE_ENABLE_INDEPENDENCE_TEST=true to enable)\n");
    }

    // =========================================================================
    // Phase 8-9: Service Mesh Tests (Optional, run in parallel)
    // =========================================================================
    if mesh_test_enabled() {
        println!("\n[Phase 8-9] Running mesh tests in parallel...\n");
        let kubeconfig = workload_kubeconfig_path.clone();
        let kubeconfig2 = workload_kubeconfig_path.clone();

        let (result1, result2) = tokio::join!(
            run_mesh_test(&kubeconfig),
            run_random_mesh_test(&kubeconfig2)
        );

        result1?;
        result2?;
    } else {
        println!(
            "\n[Phase 8-9] Skipping mesh tests (set LATTICE_ENABLE_MESH_TEST=true to enable)\n"
        );
    }

    println!("\n################################################################");
    println!("#  E2E TEST COMPLETE");
    println!("#  Management: {} + {:?}", mgmt_provider, mgmt_bootstrap);
    println!(
        "#  Workload:   {} + {:?}",
        workload_provider, workload_bootstrap
    );
    println!("################################################################\n");

    Ok(())
}

fn independence_test_enabled() -> bool {
    std::env::var("LATTICE_ENABLE_INDEPENDENCE_TEST")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}
