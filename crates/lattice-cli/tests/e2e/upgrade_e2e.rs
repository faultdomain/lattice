//! Kubernetes upgrade resilience E2E test
//!
//! This test validates that service mesh policies remain enforced during
//! a full Kubernetes cluster upgrade (control plane + workers).
//!
//! # Security Invariant
//!
//! During upgrade chaos (nodes draining, pods rescheduling, waypoints restarting):
//! - Dropped/failed traffic: ACCEPTABLE (expected during disruption)
//! - Incorrectly allowed traffic: NEVER ACCEPTABLE (security violation)
//!
//! The mesh should never degrade to "allow all" even when components restart.
//!
//! # Test Flow
//!
//! 1. Install management cluster
//! 2. Create workload cluster at Kubernetes v1.31
//! 3. Deploy mesh services and start traffic generators
//! 4. Trigger upgrade to Kubernetes v1.32
//! 5. Periodically check for policy gaps during upgrade
//! 6. Wait for upgrade to complete (all nodes Ready)
//! 7. Final verification - no incorrectly allowed traffic
//!
//! # Environment Variables
//!
//! - LATTICE_UPGRADE_FROM_VERSION: Starting K8s version (default: 1.31.0)
//! - LATTICE_UPGRADE_TO_VERSION: Target K8s version (default: 1.32.0)
//! - LATTICE_UPGRADE_MGMT_CONFIG: Management cluster config (default: docker-mgmt.yaml)
//! - LATTICE_UPGRADE_WORKLOAD_CONFIG: Workload cluster config (default: docker-workload.yaml)

#![cfg(feature = "provider-e2e")]

use std::path::PathBuf;
use std::time::Duration;

use kube::api::{Api, Patch, PatchParams, PostParams};
use kube::ResourceExt;
use serde_json::json;
use tracing::info;

use lattice_cli::commands::install::Installer;
use lattice_cli::commands::uninstall::{UninstallArgs, Uninstaller};
use lattice_operator::crd::LatticeCluster;

use super::helpers::{
    build_and_push_lattice_image, client_from_kubeconfig, ensure_docker_network,
    extract_docker_cluster_kubeconfig, get_docker_kubeconfig, load_cluster_config,
    load_registry_credentials, run_cmd, run_cmd_allow_fail, watch_cluster_phases,
};
use super::mesh_tests::start_mesh_test;
use super::providers::InfraProvider;

// =============================================================================
// Test Configuration
// =============================================================================

const E2E_TIMEOUT: Duration = Duration::from_secs(5400); // 90 minutes for upgrade
const LATTICE_IMAGE: &str = "ghcr.io/evan-hines-js/lattice:latest";

fn get_upgrade_from_version() -> String {
    std::env::var("LATTICE_UPGRADE_FROM_VERSION").unwrap_or_else(|_| "1.31.0".to_string())
}

fn get_upgrade_to_version() -> String {
    std::env::var("LATTICE_UPGRADE_TO_VERSION").unwrap_or_else(|_| "1.32.0".to_string())
}

fn get_kubeconfig(cluster_name: &str, provider: InfraProvider) -> Result<String, String> {
    if provider == InfraProvider::Docker {
        get_docker_kubeconfig(cluster_name)
    } else {
        Ok(format!("/tmp/{}-kubeconfig", cluster_name))
    }
}

// =============================================================================
// Cleanup
// =============================================================================

fn cleanup_bootstrap_clusters() {
    info!("Cleaning up kind bootstrap clusters...");
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
async fn test_upgrade_with_mesh_traffic() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let from_version = get_upgrade_from_version();
    let to_version = get_upgrade_to_version();

    info!(from = %from_version, to = %to_version, "Starting upgrade resilience test");

    cleanup_bootstrap_clusters();

    if let Err(e) = build_and_push_lattice_image(LATTICE_IMAGE).await {
        panic!("Failed to build Lattice image: {}", e);
    }

    let result = tokio::time::timeout(E2E_TIMEOUT, run_upgrade_e2e()).await;

    match result {
        Ok(Ok(())) => {
            info!("TEST PASSED");
        }
        Ok(Err(e)) => {
            cleanup_bootstrap_clusters();
            panic!("Upgrade E2E test failed: {}", e);
        }
        Err(_) => {
            cleanup_bootstrap_clusters();
            panic!("Upgrade E2E test timed out after {:?}", E2E_TIMEOUT);
        }
    }
}

async fn run_upgrade_e2e() -> Result<(), String> {
    let from_version = get_upgrade_from_version();
    let to_version = get_upgrade_to_version();

    // =========================================================================
    // Load cluster configs
    // =========================================================================
    info!("Loading cluster configurations...");

    let (mgmt_config_content, mgmt_cluster) =
        load_cluster_config("LATTICE_UPGRADE_MGMT_CONFIG", "docker-mgmt.yaml")?;
    let mgmt_provider: InfraProvider = mgmt_cluster.spec.provider.provider_type().into();
    let mgmt_bootstrap = mgmt_cluster.spec.provider.kubernetes.bootstrap.clone();
    let mgmt_cluster_name = mgmt_cluster.name_any();

    let (_, mut workload_cluster) =
        load_cluster_config("LATTICE_UPGRADE_WORKLOAD_CONFIG", "docker-workload.yaml")?;
    let workload_provider: InfraProvider = workload_cluster.spec.provider.provider_type().into();
    let workload_bootstrap = workload_cluster.spec.provider.kubernetes.bootstrap.clone();
    let workload_cluster_name = workload_cluster.name_any();

    // Override workload cluster version to start at from_version
    workload_cluster.spec.provider.kubernetes.version = from_version.clone();

    info!("Configuration:");
    info!(
        "Management:  {} ({} + {:?})",
        mgmt_cluster_name, mgmt_provider, mgmt_bootstrap
    );
    info!(
        "Workload:    {} ({} + {:?}, starting at v{})",
        workload_cluster_name, workload_provider, workload_bootstrap, from_version
    );
    info!("Upgrade to:  v{}", to_version);
    info!("");

    if mgmt_provider == InfraProvider::Docker {
        ensure_docker_network().map_err(|e| format!("Failed to setup Docker network: {}", e))?;
    }

    // =========================================================================
    // Phase 1: Install Management Cluster
    // =========================================================================
    info!("[Phase 1] Installing management cluster...");

    let registry_credentials = load_registry_credentials();
    let installer = Installer::new(
        mgmt_config_content,
        LATTICE_IMAGE.to_string(),
        true,
        registry_credentials,
        None,
    )
    .map_err(|e| format!("Failed to create installer: {}", e))?;

    installer
        .run()
        .await
        .map_err(|e| format!("Installer failed: {}", e))?;

    info!("\n  Management cluster installation complete!");

    // =========================================================================
    // Phase 2: Create Workload Cluster at v{from_version}
    // =========================================================================
    info!(
        "[Phase 2] Creating workload cluster at v{}...\n",
        from_version
    );

    let mgmt_kubeconfig_path = get_kubeconfig(&mgmt_cluster_name, mgmt_provider)?;
    let mgmt_client = client_from_kubeconfig(&mgmt_kubeconfig_path).await?;

    let api: Api<LatticeCluster> = Api::all(mgmt_client.clone());
    api.create(&PostParams::default(), &workload_cluster)
        .await
        .map_err(|e| format!("Failed to create workload LatticeCluster: {}", e))?;

    info!("Workload LatticeCluster created");

    watch_cluster_phases(&mgmt_client, &workload_cluster_name, None).await?;
    info!("\n  Workload cluster Ready at v{}!", from_version);

    // Extract kubeconfig
    let workload_kubeconfig_path = format!("/tmp/{}-kubeconfig", workload_cluster_name);
    if workload_provider == InfraProvider::Docker {
        extract_docker_cluster_kubeconfig(
            &workload_cluster_name,
            &workload_bootstrap,
            &workload_kubeconfig_path,
        )?;
    }

    // Verify starting version
    let version_output = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &workload_kubeconfig_path,
            "version",
            "-o",
            "json",
        ],
    )?;
    info!("Cluster version info:\n{}", version_output);

    // =========================================================================
    // Phase 3: Deploy Mesh and Start Traffic
    // =========================================================================
    info!("[Phase 3] Deploying mesh services and starting traffic...");

    let mesh_handle = start_mesh_test(&workload_kubeconfig_path).await?;

    // Initial verification before upgrade
    info!("Running initial policy verification...");
    tokio::time::sleep(Duration::from_secs(60)).await;
    mesh_handle.check_no_policy_gaps().await?;
    info!("Initial verification passed - policies are enforced");

    // =========================================================================
    // Phase 4: Trigger Kubernetes Upgrade
    // =========================================================================
    info!(
        "[Phase 4] Triggering upgrade from v{} to v{}...\n",
        from_version, to_version
    );

    // Patch the LatticeCluster to trigger upgrade
    let patch = json!({
        "spec": {
            "provider": {
                "kubernetes": {
                    "version": to_version
                }
            }
        }
    });

    let workload_client = client_from_kubeconfig(&workload_kubeconfig_path).await?;
    let workload_api: Api<LatticeCluster> = Api::all(workload_client.clone());

    workload_api
        .patch(
            &workload_cluster_name,
            &PatchParams::apply("lattice-e2e-test"),
            &Patch::Merge(&patch),
        )
        .await
        .map_err(|e| format!("Failed to patch cluster version: {}", e))?;

    info!("Upgrade initiated!");

    // =========================================================================
    // Phase 5: Monitor for Policy Gaps During Upgrade
    // =========================================================================
    info!("[Phase 5] Monitoring for policy gaps during upgrade...");
    info!("Security invariant: traffic that should be BLOCKED must NEVER be ALLOWED");
    info!("(Dropped/failed allowed traffic is acceptable during node disruption)\n");

    let upgrade_start = std::time::Instant::now();
    let upgrade_timeout = Duration::from_secs(1800); // 30 minutes for upgrade
    let check_interval = Duration::from_secs(30);

    loop {
        if upgrade_start.elapsed() > upgrade_timeout {
            return Err("Upgrade timed out after 30 minutes".to_string());
        }

        // Check for policy gaps
        if let Err(e) = mesh_handle.check_no_policy_gaps().await {
            return Err(format!("SECURITY VIOLATION during upgrade: {}", e));
        }

        // Check upgrade progress
        let nodes_output = run_cmd_allow_fail(
            "kubectl",
            &[
                "--kubeconfig",
                &workload_kubeconfig_path,
                "get",
                "nodes",
                "-o",
                "jsonpath={range .items[*]}{.status.nodeInfo.kubeletVersion} {.status.conditions[?(@.type=='Ready')].status}{\"\\n\"}{end}",
            ],
        );

        let mut all_upgraded = true;
        let mut all_ready = true;
        let mut node_count = 0;

        for line in nodes_output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                node_count += 1;
                let version = parts[0];
                let ready = parts[1];

                if !version.contains(&to_version) {
                    all_upgraded = false;
                }
                if ready != "True" {
                    all_ready = false;
                }
            }
        }

        let elapsed = upgrade_start.elapsed().as_secs();
        info!(
            "[{:3}s] Nodes: {}, All upgraded: {}, All ready: {}",
            elapsed, node_count, all_upgraded, all_ready
        );

        if all_upgraded && all_ready && node_count > 0 {
            info!(
                "\n  Upgrade complete! All nodes at v{} and Ready",
                to_version
            );
            break;
        }

        tokio::time::sleep(check_interval).await;
    }

    // =========================================================================
    // Phase 6: Final Verification
    // =========================================================================
    info!("[Phase 6] Final policy verification after upgrade...");

    // Wait for mesh to stabilize after upgrade
    info!("Waiting for mesh to stabilize (120)...");
    tokio::time::sleep(Duration::from_secs(120)).await;

    // Final policy gap check
    mesh_handle.check_no_policy_gaps().await?;
    info!("No policy gaps detected!");

    // Full verification
    info!("Running full bilateral agreement verification...");
    mesh_handle.stop_and_verify().await?;

    // Verify final version
    let version_output = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &workload_kubeconfig_path,
            "version",
            "-o",
            "json",
        ],
    )?;
    info!("Final cluster version:\n{}", version_output);

    // =========================================================================
    // Cleanup
    // =========================================================================
    info!("\n[Cleanup] Deleting test clusters...");

    // Delete workload cluster
    run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &workload_kubeconfig_path,
            "delete",
            "latticecluster",
            &workload_cluster_name,
            "--timeout=300s",
        ],
    )?;

    // Wait for deletion
    for _ in 1..=60 {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let check = run_cmd_allow_fail(
            "kubectl",
            &[
                "--kubeconfig",
                &mgmt_kubeconfig_path,
                "get",
                "latticecluster",
                &workload_cluster_name,
                "-o",
                "name",
            ],
        );
        if check.trim().is_empty() || check.contains("not found") {
            break;
        }
    }

    // Uninstall management cluster
    let uninstall_args = UninstallArgs {
        kubeconfig: PathBuf::from(&mgmt_kubeconfig_path),
        name: Some(mgmt_cluster_name.clone()),
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

    info!(from = %from_version, to = %to_version, "Upgrade resilience test complete");

    Ok(())
}
