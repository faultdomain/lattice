//! Provider-configurable end-to-end test for Lattice installation and pivot flow
//!
//! This test allows configuring different infrastructure providers for management
//! and workload clusters independently.
//!
//! # Environment Variables
//!
//! ## Provider Selection
//! - LATTICE_MGMT_PROVIDER: Provider for management cluster (aws|openstack|proxmox|docker)
//! - LATTICE_WORKLOAD_PROVIDER: Provider for workload cluster (aws|openstack|proxmox|docker)
//! - LATTICE_MGMT_BOOTSTRAP: Bootstrap provider for mgmt (kubeadm|rke2, default: rke2)
//! - LATTICE_WORKLOAD_BOOTSTRAP: Bootstrap provider for workload (kubeadm|rke2, default: kubeadm)
//!
//! ## Optional Test Phases
//! - LATTICE_ENABLE_INDEPENDENCE_TEST=true: Enable Phase 7 (delete mgmt, verify workload self-manages)
//! - LATTICE_ENABLE_MESH_TEST=true: Enable Phase 8-9 (9-service + 50-100 service mesh tests, run in parallel)
//!
//! ## AWS Configuration (when using aws provider)
//! - AWS_REGION: AWS region (default: us-west-2)
//! - AWS_SSH_KEY_NAME: EC2 key pair name (optional)
//! - AWS_VPC_ID: VPC ID (optional, uses default VPC if not set)
//! - AWS_AMI_ID: Custom AMI ID (optional)
//!
//! ## OpenStack Configuration (when using openstack provider)
//! - OS_CLOUD_NAME: Cloud name from clouds.yaml (default: openstack)
//! - OS_EXTERNAL_NETWORK: External network for floating IPs (default: Ext-Net)
//! - OS_IMAGE_NAME: Image name (default: Ubuntu 22.04)
//! - OS_CP_FLAVOR: Control plane flavor (default: m1.large)
//! - OS_WORKER_FLAVOR: Worker flavor (default: m1.large)
//! - OS_SSH_KEY_NAME: SSH key name (optional)
//!
//! ## Proxmox Configuration (when using proxmox provider)
//! - PROXMOX_URL: Proxmox API URL
//! - PROXMOX_TOKEN_ID: API token ID
//! - PROXMOX_TOKEN_SECRET: API token secret
//! - PROXMOX_NODE: Target node name
//! - PROXMOX_TEMPLATE_ID: VM template ID
//! - PROXMOX_STORAGE: Storage name (default: local-lvm)
//!
//! # Running
//!
//! ```bash
//! # Docker mgmt → Docker workload
//! LATTICE_MGMT_PROVIDER=docker LATTICE_WORKLOAD_PROVIDER=docker \
//!   cargo test --features provider-e2e --test kind pivot_e2e -- --nocapture
//!
//! # Docker mgmt → AWS workload
//! LATTICE_MGMT_PROVIDER=docker LATTICE_WORKLOAD_PROVIDER=aws \
//!   cargo test --features provider-e2e --test kind pivot_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::time::Duration;

use base64::Engine;
use kube::api::{Api, PostParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::Client;

use lattice_cli::commands::install::{InstallConfig, Installer};
use lattice_operator::crd::{BootstrapProvider, LatticeCluster};

use super::helpers::{
    create_capmox_credentials_secret, ensure_docker_network, extract_docker_cluster_kubeconfig,
    run_cmd, run_cmd_allow_fail, verify_control_plane_taints, watch_cluster_phases,
    watch_worker_scaling,
};
use super::mesh_tests::{mesh_test_enabled, run_mesh_test, run_random_mesh_test};
use super::providers::{generate_cluster_config, InfraProvider};

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

async fn client_from_kubeconfig(path: &str) -> Result<Client, String> {
    let kubeconfig =
        Kubeconfig::read_from(path).map_err(|e| format!("Failed to read kubeconfig: {}", e))?;

    let config = kube::Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
        .await
        .map_err(|e| format!("Failed to create kube config: {}", e))?;

    Client::try_from(config).map_err(|e| format!("Failed to create client: {}", e))
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
    // Only clean up clusters created by THIS test instance, not all kind clusters.
    // This allows concurrent E2E test runs with unique cluster names.
    println!("  Cleaning up test clusters...");

    // Delete known test cluster names (not --all to avoid killing concurrent tests)
    for name in &[MGMT_CLUSTER_NAME, WORKLOAD_CLUSTER_NAME] {
        let _ = run_cmd_allow_fail("kind", &["delete", "cluster", "--name", name]);

        let _ = run_cmd_allow_fail(
            "docker",
            &["ps", "-a", "--filter", &format!("name={}", name), "-q"],
        );
    }
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

    let cluster_config = generate_cluster_config(
        MGMT_CLUSTER_NAME,
        mgmt_provider,
        mgmt_bootstrap.clone(),
        true,
    );
    println!("  Cluster config:\n{}", cluster_config);

    let config_path = PathBuf::from(format!("/tmp/{}-cluster-config.yaml", MGMT_CLUSTER_NAME));
    std::fs::write(&config_path, &cluster_config)
        .map_err(|e| format!("Failed to write cluster config: {}", e))?;

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

    // Create provider-specific credentials if needed
    if workload_provider == InfraProvider::Proxmox {
        println!("\n  Setting up Proxmox credentials for workload cluster provisioning...");
        create_capmox_credentials_secret(&mgmt_client).await?;
    }

    // =========================================================================
    // Phase 3: Create Workload Cluster
    // =========================================================================
    println!(
        "\n[Phase 3] Creating workload cluster ({} + {:?})...\n",
        workload_provider, workload_bootstrap
    );

    let workload_config = generate_cluster_config(
        WORKLOAD_CLUSTER_NAME,
        workload_provider,
        workload_bootstrap.clone(),
        false,
    );

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
    // Phase 5: Verify Workload Cluster Independence
    // =========================================================================
    println!("\n[Phase 5] Verifying workload cluster...\n");

    let workload_kubeconfig_path = format!("/tmp/{}-kubeconfig", WORKLOAD_CLUSTER_NAME);

    if workload_provider == InfraProvider::Docker {
        println!("  Extracting workload cluster kubeconfig from control plane container...");

        match extract_docker_cluster_kubeconfig(
            WORKLOAD_CLUSTER_NAME,
            &workload_bootstrap,
            &workload_kubeconfig_path,
        ) {
            Ok(()) => {
                println!("  Kubeconfig extracted successfully");

                let nodes_check = run_cmd(
                    "kubectl",
                    &[
                        "--kubeconfig",
                        &workload_kubeconfig_path,
                        "get",
                        "nodes",
                        "-o",
                        "wide",
                    ],
                );

                match nodes_check {
                    Ok(output) => println!("  Workload cluster nodes:\n{}", output),
                    Err(e) => {
                        return Err(format!(
                            "Docker workload cluster should be accessible but failed: {}",
                            e
                        ))
                    }
                }

                println!("  Checking for CAPI resources on workload cluster...");
                let capi_check = run_cmd(
                    "kubectl",
                    &[
                        "--kubeconfig",
                        &workload_kubeconfig_path,
                        "get",
                        "clusters",
                        "-A",
                    ],
                );

                match capi_check {
                    Ok(output) => {
                        println!("  Workload cluster CAPI resources:\n{}", output);
                        if !output.contains(WORKLOAD_CLUSTER_NAME) {
                            return Err("Workload cluster should have its own CAPI Cluster resource after pivot".to_string());
                        }
                    }
                    Err(e) => println!("  Warning: Could not check CAPI resources: {}", e),
                }
            }
            Err(e) => {
                return Err(format!(
                    "Failed to extract kubeconfig for Docker workload cluster: {}",
                    e
                ))
            }
        }
    } else {
        println!(
            "  Skipping direct verification for cloud provider ({:?})",
            workload_provider
        );
    }

    // =========================================================================
    // Phase 6: Worker Scaling Verification (Docker only)
    // =========================================================================
    if workload_provider == InfraProvider::Docker {
        println!("\n[Phase 6] Watching worker scaling...\n");
        watch_worker_scaling(&workload_kubeconfig_path, WORKLOAD_CLUSTER_NAME, 2).await?;
    } else {
        println!("\n[Phase 6] Skipping worker scaling verification for cloud provider\n");
    }

    // =========================================================================
    // Phase 7: Independence Verification (Docker only)
    // =========================================================================
    if workload_provider == InfraProvider::Docker && independence_test_enabled() {
        println!("\n[Phase 7] Proving workload cluster is truly self-managing...\n");

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
        verify_control_plane_taints(&workload_kubeconfig_path, &workload_bootstrap).await?;
        println!("    [x] Control-plane taints restored by controller");
    } else if workload_provider == InfraProvider::Docker {
        println!("\n[Phase 7] Skipping independence test (set LATTICE_ENABLE_INDEPENDENCE_TEST=true to enable)\n");
    } else {
        println!("\n[Phase 7] Skipping independence test for cloud provider\n");
    }

    // =========================================================================
    // Phase 8-9: Service Mesh Tests (Optional, run in parallel)
    // =========================================================================
    if workload_provider == InfraProvider::Docker && mesh_test_enabled() {
        println!("\n[Phase 8-9] Running mesh tests in parallel...\n");
        let kubeconfig = workload_kubeconfig_path.clone();
        let kubeconfig2 = workload_kubeconfig_path.clone();

        let (result1, result2) = tokio::join!(
            run_mesh_test(&kubeconfig),
            run_random_mesh_test(&kubeconfig2)
        );

        result1?;
        result2?;
    } else if workload_provider == InfraProvider::Docker {
        println!(
            "\n[Phase 8-9] Skipping mesh tests (set LATTICE_ENABLE_MESH_TEST=true to enable)\n"
        );
    } else {
        println!("\n[Phase 8-9] Skipping mesh tests for cloud provider\n");
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
