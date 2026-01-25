//! Provider-configurable end-to-end test for Lattice installation, pivot, and unpivot flow
//!
//! This test validates the full Lattice lifecycle including:
//! - Management cluster installation and self-management
//! - Workload cluster provisioning and pivot
//! - Deep cluster hierarchy (workload1 -> workload2)
//! - Proper unpivot flow (CAPI resources return to parent on delete)
//! - Proper uninstall flow (management cluster cleanup)
//!
//! # Test Phases
//!
//! 1. Install management cluster
//! 2. Verify management cluster is self-managing
//! 3. Create workload cluster off management cluster
//! 4. Watch workload cluster provisioning and pivot
//! 5. Verify workload cluster has CAPI resources + worker scaling
//! 6. Create workload2 + run mesh tests (in parallel)
//! 7. Delete workload2 (unpivot to workload)
//! 8. Delete workload (unpivot to mgmt)
//! 9. Uninstall management cluster
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
//! ## Optional Test Phases
//! - LATTICE_ENABLE_MESH_TEST=true: Enable service mesh validation tests (default: true)
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
use std::time::Duration;

use kube::api::{Api, PostParams};
use tracing::info;

use lattice_cli::commands::install::Installer;
use lattice_cli::commands::uninstall::{UninstallArgs, Uninstaller};
use lattice_operator::crd::LatticeCluster;

use super::helpers::{
    build_and_push_lattice_image, client_from_kubeconfig, ensure_docker_network,
    extract_docker_cluster_kubeconfig, get_docker_kubeconfig, load_cluster_config,
    load_registry_credentials, run_cmd, run_cmd_allow_fail, watch_cluster_phases,
    watch_cluster_phases_with_kubeconfig, watch_worker_scaling,
};
// Media server test disabled pending investigation
#[allow(unused_imports)]
use super::media_server_e2e::{cleanup_media_server_test, run_media_server_test};
use super::mesh_tests::{run_mesh_test, run_random_mesh_test};
use super::providers::InfraProvider;

// =============================================================================
// Test Configuration
// =============================================================================

const E2E_TIMEOUT: Duration = Duration::from_secs(3600);
const MGMT_CLUSTER_NAME: &str = "e2e-mgmt";
const WORKLOAD_CLUSTER_NAME: &str = "e2e-workload";
const WORKLOAD2_CLUSTER_NAME: &str = "e2e-workload2";
const LATTICE_IMAGE: &str = "ghcr.io/evan-hines-js/lattice:latest";

fn get_kubeconfig(cluster_name: &str, provider: InfraProvider) -> Result<String, String> {
    if provider == InfraProvider::Docker {
        get_docker_kubeconfig(cluster_name)
    } else {
        Ok(format!("/tmp/{}-kubeconfig", cluster_name))
    }
}

// =============================================================================
// Cleanup Functions
// =============================================================================

/// Clean up kind bootstrap clusters only (lattice-install, lattice-uninstall)
/// These are temporary clusters used during install/uninstall and safe to force-delete
fn cleanup_bootstrap_clusters() {
    info!("  Cleaning up kind bootstrap clusters...");
    let _ = run_cmd_allow_fail("kind", &["delete", "cluster", "--name", "lattice-install"]);
    let _ = run_cmd_allow_fail(
        "kind",
        &["delete", "cluster", "--name", "lattice-uninstall"],
    );
}

// =============================================================================
// Main Test
// =============================================================================

#[tokio::test]
async fn test_configurable_provider_pivot() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    info!("\n################################################################");
    info!("#  LATTICE E2E TEST - Full Lifecycle");
    info!("################################################################\n");

    // Clean up any leftover bootstrap clusters from previous runs
    cleanup_bootstrap_clusters();

    if let Err(e) = build_and_push_lattice_image(LATTICE_IMAGE).await {
        panic!("Failed to build Lattice image: {}", e);
    }

    let result = tokio::time::timeout(E2E_TIMEOUT, run_provider_e2e()).await;

    match result {
        Ok(Ok(())) => {
            info!("\n################################################################");
            info!("#  TEST PASSED - All resources cleaned up properly");
            info!("################################################################\n");
        }
        Ok(Err(e)) => {
            cleanup_bootstrap_clusters();
            info!("\n=== TEST FAILED: {} ===", e);
            info!("=== Manual cleanup may be required for test clusters ===\n");
            panic!("E2E test failed: {}", e);
        }
        Err(_) => {
            cleanup_bootstrap_clusters();
            info!("\n=== TEST TIMED OUT ({:?}) ===", E2E_TIMEOUT);
            info!("=== Manual cleanup required for test clusters ===\n");
            panic!("E2E test timed out after {:?}", E2E_TIMEOUT);
        }
    }
}

async fn run_provider_e2e() -> Result<(), String> {
    // =========================================================================
    // Load all cluster configs upfront (fail early if missing)
    // =========================================================================
    info!("Loading cluster configurations...\n");

    let (mgmt_config_content, mgmt_cluster) =
        load_cluster_config("LATTICE_MGMT_CLUSTER_CONFIG", "docker-mgmt.yaml")?;
    let mgmt_provider: InfraProvider = mgmt_cluster.spec.provider.provider_type().into();
    let mgmt_bootstrap = mgmt_cluster.spec.provider.kubernetes.bootstrap.clone();

    let (_, workload_cluster) =
        load_cluster_config("LATTICE_WORKLOAD_CLUSTER_CONFIG", "docker-workload.yaml")?;
    let workload_provider: InfraProvider = workload_cluster.spec.provider.provider_type().into();
    let workload_bootstrap = workload_cluster.spec.provider.kubernetes.bootstrap.clone();

    let (_, workload2_cluster) =
        load_cluster_config("LATTICE_WORKLOAD2_CLUSTER_CONFIG", "docker-workload2.yaml")?;
    let workload2_bootstrap = workload2_cluster.spec.provider.kubernetes.bootstrap.clone();

    info!("Configuration:");
    info!("  Management:  {} + {:?}", mgmt_provider, mgmt_bootstrap);
    info!(
        "  Workload:    {} + {:?}",
        workload_provider, workload_bootstrap
    );
    info!(
        "  Workload2:   {} + {:?}",
        workload_provider, workload2_bootstrap
    );
    info!();

    // Setup Docker network if needed
    if mgmt_provider == InfraProvider::Docker {
        ensure_docker_network().map_err(|e| format!("Failed to setup Docker network: {}", e))?;
    }

    // =========================================================================
    // Phase 1: Install Management Cluster
    // =========================================================================
    info!(
        "\n[Phase 1] Installing management cluster ({} + {:?})...\n",
        mgmt_provider, mgmt_bootstrap
    );

    let registry_credentials = load_registry_credentials();
    if registry_credentials.is_some() {
        info!("  Registry credentials loaded");
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

    info!("\n  Management cluster installation complete!");

    // =========================================================================
    // Phase 2: Verify Management Cluster is Self-Managing
    // =========================================================================
    info!("\n[Phase 2] Verifying management cluster is self-managing...\n");

    let mgmt_kubeconfig_path = get_kubeconfig(MGMT_CLUSTER_NAME, mgmt_provider)?;
    info!("  Using kubeconfig: {}", mgmt_kubeconfig_path);

    let mgmt_client = client_from_kubeconfig(&mgmt_kubeconfig_path).await?;

    info!("  Checking for CAPI Cluster resource...");
    let capi_check = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &mgmt_kubeconfig_path,
            "get",
            "clusters",
            "-A",
            "-o",
            "wide",
        ],
    )?;
    info!("  CAPI clusters:\n{}", capi_check);

    if !capi_check.contains(MGMT_CLUSTER_NAME) {
        return Err("Management cluster should have its own CAPI Cluster resource".to_string());
    }

    info!("  Waiting for management cluster's LatticeCluster to be Ready...");
    watch_cluster_phases(&mgmt_client, MGMT_CLUSTER_NAME, None).await?;

    info!("\n  SUCCESS: Management cluster is self-managing!");

    // =========================================================================
    // Phase 3: Create Workload Cluster
    // =========================================================================
    info!(
        "\n[Phase 3] Creating workload cluster ({} + {:?})...\n",
        workload_provider, workload_bootstrap
    );

    let api: Api<LatticeCluster> = Api::all(mgmt_client.clone());
    api.create(&PostParams::default(), &workload_cluster)
        .await
        .map_err(|e| format!("Failed to create workload LatticeCluster: {}", e))?;

    info!("  Workload LatticeCluster created");

    // =========================================================================
    // Phase 4: Watch Workload Cluster Provisioning
    // =========================================================================
    info!("\n[Phase 4] Watching workload cluster provisioning...\n");

    let workload_kubeconfig_path = format!("/tmp/{}-kubeconfig", WORKLOAD_CLUSTER_NAME);

    if workload_provider == InfraProvider::Docker {
        watch_cluster_phases(&mgmt_client, WORKLOAD_CLUSTER_NAME, None).await?;
    } else {
        watch_cluster_phases_with_kubeconfig(
            &mgmt_kubeconfig_path,
            WORKLOAD_CLUSTER_NAME,
            None,
            &workload_kubeconfig_path,
        )
        .await?;
    }

    info!("\n  SUCCESS: Workload cluster is Ready!");

    // =========================================================================
    // Phase 5: Verify Workload Cluster
    // =========================================================================
    info!("\n[Phase 5] Verifying workload cluster...\n");

    if workload_provider == InfraProvider::Docker {
        info!("  Extracting workload cluster kubeconfig...");
        extract_docker_cluster_kubeconfig(
            WORKLOAD_CLUSTER_NAME,
            &workload_bootstrap,
            &workload_kubeconfig_path,
        )?;
    }

    verify_cluster_capi_resources(&workload_kubeconfig_path, WORKLOAD_CLUSTER_NAME).await?;
    watch_worker_scaling(&workload_kubeconfig_path, WORKLOAD_CLUSTER_NAME, 1).await?;

    // =========================================================================
    // Phase 6: Create Workload2 + Run Mesh Tests (in parallel)
    // =========================================================================
    info!("\n[Phase 6] Creating workload2 cluster + running mesh tests in parallel...\n");

    let workload_client = client_from_kubeconfig(&workload_kubeconfig_path).await?;

    // Spawn workload2 creation
    let workload2_kubeconfig_path = format!("/tmp/{}-kubeconfig", WORKLOAD2_CLUSTER_NAME);
    let workload2_handle = {
        let workload_client = workload_client.clone();
        let workload_kubeconfig = workload_kubeconfig_path.clone();
        let workload2_kubeconfig = workload2_kubeconfig_path.clone();
        let workload2 = workload2_cluster.clone();
        let bootstrap = workload2_bootstrap.clone();
        let provider = workload_provider;

        tokio::spawn(async move {
            let workload_api: Api<LatticeCluster> = Api::all(workload_client.clone());
            workload_api
                .create(&PostParams::default(), &workload2)
                .await
                .map_err(|e| format!("Failed to create workload2: {}", e))?;

            info!("  [Workload2] LatticeCluster created on workload cluster");

            if provider == InfraProvider::Docker {
                watch_cluster_phases(&workload_client, WORKLOAD2_CLUSTER_NAME, None).await?;
            } else {
                watch_cluster_phases_with_kubeconfig(
                    &workload_kubeconfig,
                    WORKLOAD2_CLUSTER_NAME,
                    None,
                    &workload2_kubeconfig,
                )
                .await?;
            }

            info!("  [Workload2] Cluster is Ready!");

            if provider == InfraProvider::Docker {
                extract_docker_cluster_kubeconfig(
                    WORKLOAD2_CLUSTER_NAME,
                    &bootstrap,
                    &workload2_kubeconfig,
                )?;
            }

            verify_cluster_capi_resources(&workload2_kubeconfig, WORKLOAD2_CLUSTER_NAME).await?;
            info!("  [Workload2] Deep hierarchy verified!");

            Ok::<_, String>(())
        })
    };

    // Spawn mesh tests if enabled
    let mesh_handle = if mesh_test_enabled() {
        let kubeconfig = workload_kubeconfig_path.clone();
        Some(tokio::spawn(async move {
            info!("  [Mesh] Running service mesh tests...");
            let kubeconfig2 = kubeconfig.clone();

            // Run mesh tests in parallel:
            // - Fixed 9-service bilateral agreement test
            // - Randomized large-scale mesh test
            // NOTE: Media server test disabled pending investigation
            let (r1, r2) = tokio::join!(
                run_mesh_test(&kubeconfig),
                run_random_mesh_test(&kubeconfig2)
            );

            r1?;
            r2?;
            info!("  [Mesh] All tests complete!");
            Ok::<_, String>(())
        }))
    } else {
        None
    };

    // Wait for both to complete
    workload2_handle
        .await
        .map_err(|e| format!("Workload2 task panicked: {}", e))??;

    if let Some(handle) = mesh_handle {
        handle
            .await
            .map_err(|e| format!("Mesh test task panicked: {}", e))??;
    }

    info!("\n  SUCCESS: Workload2 + mesh tests complete!");

    // =========================================================================
    // Phase 7: Delete Workload2 (unpivot to workload)
    // =========================================================================
    info!("\n[Phase 7] Deleting workload2 cluster (unpivot flow)...\n");
    info!("  CAPI resources will move back to workload cluster");

    delete_cluster_and_wait(
        &workload2_kubeconfig_path,
        &workload_kubeconfig_path,
        WORKLOAD2_CLUSTER_NAME,
        workload_provider,
    )
    .await?;

    info!("\n  SUCCESS: Workload2 deleted and unpivoted!");

    // =========================================================================
    // Phase 8: Delete Workload (unpivot to mgmt)
    // =========================================================================
    info!("\n[Phase 8] Deleting workload cluster (unpivot flow)...\n");
    info!("  CAPI resources will move back to management cluster");

    delete_cluster_and_wait(
        &workload_kubeconfig_path,
        &mgmt_kubeconfig_path,
        WORKLOAD_CLUSTER_NAME,
        workload_provider,
    )
    .await?;

    info!("\n  SUCCESS: Workload deleted and unpivoted!");

    // =========================================================================
    // Phase 9: Uninstall Management Cluster
    // =========================================================================
    info!("\n[Phase 9] Uninstalling management cluster...\n");
    info!("  This uses the proper uninstall flow (reverse pivot to temporary kind cluster)");

    let uninstall_args = UninstallArgs {
        kubeconfig: PathBuf::from(&mgmt_kubeconfig_path),
        name: Some(MGMT_CLUSTER_NAME.to_string()),
        yes: true,
        keep_bootstrap_on_failure: false,
    };

    let uninstaller = Uninstaller::new(&uninstall_args)
        .await
        .map_err(|e| format!("Failed to create uninstaller: {}", e))?;

    uninstaller
        .run()
        .await
        .map_err(|e| format!("Uninstall failed: {}", e))?;

    info!("\n  SUCCESS: Management cluster uninstalled!");

    info!("\n################################################################");
    info!("#  E2E TEST COMPLETE - Full Lifecycle Verified");
    info!("#  ");
    info!("#  Tested:");
    info!("#  - Management cluster install + self-management");
    info!("#  - Workload cluster provisioning + pivot");
    info!("#  - Deep hierarchy (mgmt -> workload -> workload2)");
    info!("#  - Workload2 deletion + unpivot");
    info!("#  - Workload deletion + unpivot");
    info!("#  - Management cluster uninstall");
    if mesh_test_enabled() {
        info!("#  - Service mesh bilateral agreements");
    }
    info!("################################################################\n");

    Ok(())
}

/// Verify a cluster has its own CAPI resources after pivot
async fn verify_cluster_capi_resources(kubeconfig: &str, cluster_name: &str) -> Result<(), String> {
    let nodes_output = run_cmd(
        "kubectl",
        &["--kubeconfig", kubeconfig, "get", "nodes", "-o", "wide"],
    )?;
    info!("  Cluster nodes:\n{}", nodes_output);

    info!("  Checking for CAPI resources...");
    let capi_output = run_cmd(
        "kubectl",
        &["--kubeconfig", kubeconfig, "get", "clusters", "-A"],
    )?;
    info!("  CAPI clusters:\n{}", capi_output);

    if !capi_output.contains(cluster_name) {
        return Err(format!(
            "Cluster {} should have its own CAPI Cluster resource after pivot",
            cluster_name
        ));
    }

    Ok(())
}

/// Delete a cluster via kubectl and wait for cleanup
async fn delete_cluster_and_wait(
    cluster_kubeconfig: &str,
    parent_kubeconfig: &str,
    cluster_name: &str,
    provider: InfraProvider,
) -> Result<(), String> {
    // Initiate deletion on the cluster itself
    run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            cluster_kubeconfig,
            "delete",
            "latticecluster",
            cluster_name,
            "--timeout=300s",
        ],
    )?;
    info!("  LatticeCluster deletion initiated");

    // Wait for the LatticeCluster to be fully deleted from parent
    info!("  Waiting for LatticeCluster to be deleted from parent...");
    for attempt in 1..=60 {
        tokio::time::sleep(Duration::from_secs(10)).await;

        let check = run_cmd_allow_fail(
            "kubectl",
            &[
                "--kubeconfig",
                parent_kubeconfig,
                "get",
                "latticecluster",
                cluster_name,
                "-o",
                "name",
            ],
        );

        if check.trim().is_empty() || check.contains("not found") {
            info!("  LatticeCluster deleted from parent");
            break;
        }

        if attempt == 60 {
            return Err(format!(
                "Timeout waiting for {} deletion after 10 minutes",
                cluster_name
            ));
        }

        info!("    Still waiting... (attempt {}/60)", attempt);
    }

    // For Docker, verify containers are cleaned up
    if provider == InfraProvider::Docker {
        info!("  Waiting for Docker containers to be cleaned up...");
        for attempt in 1..=30 {
            tokio::time::sleep(Duration::from_secs(5)).await;

            let containers = run_cmd_allow_fail(
                "docker",
                &[
                    "ps",
                    "-a",
                    "--filter",
                    &format!("name={}", cluster_name),
                    "-q",
                ],
            );

            if containers.trim().is_empty() {
                info!("  Docker containers cleaned up by CAPI");
                break;
            }

            if attempt == 30 {
                return Err(format!(
                    "Timeout waiting for {} containers to be deleted. Still running: {}",
                    cluster_name,
                    containers.trim()
                ));
            }

            info!(
                "    Still waiting for container cleanup... (attempt {}/30)",
                attempt
            );
        }
    }

    Ok(())
}

fn mesh_test_enabled() -> bool {
    std::env::var("LATTICE_ENABLE_MESH_TEST")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true)
}
