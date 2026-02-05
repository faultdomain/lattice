//! Kubernetes upgrade resilience E2E test
//!
//! Validates that service mesh policies remain enforced during a full
//! Kubernetes cluster upgrade (control plane + workers).
//!
//! # Security Invariant
//!
//! During upgrade chaos (nodes draining, pods rescheduling, waypoints restarting):
//! - Dropped/failed traffic: ACCEPTABLE (expected during disruption)
//! - Incorrectly allowed traffic: NEVER ACCEPTABLE (security violation)
//!
//! # Test Flow
//!
//! 1. Install management cluster
//! 2. Create workload cluster at starting version
//! 3. Deploy mesh services and start traffic generators
//! 4. Enable chaos monkey
//! 5. Trigger upgrade to target version
//! 6. Monitor for policy gaps during upgrade
//! 7. Final verification
//!
//! # Running
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e upgrade_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::sync::Arc;
use std::time::{Duration, Instant};

use kube::api::{Api, DeleteParams, Patch, PatchParams, PostParams};
use serde_json::json;
use tracing::{error, info};

use lattice_cli::commands::install::Installer;
use lattice_operator::crd::LatticeCluster;

use super::chaos::{ChaosConfig, ChaosMonkey, ChaosTargets};
use super::context::init_e2e_test;
use super::helpers::{
    build_and_push_lattice_image, client_from_kubeconfig, ensure_docker_network,
    extract_docker_cluster_kubeconfig, get_docker_kubeconfig, kubeconfig_path, load_cluster_config,
    load_registry_credentials, run_cmd, run_id, watch_cluster_phases, DEFAULT_LATTICE_IMAGE,
    MGMT_CLUSTER_NAME,
};
use super::integration::setup;
use super::mesh_tests::{start_mesh_test, wait_for_mesh_test_cycles};
use super::providers::InfraProvider;

/// Different from standard e2e-workload - tests Kubernetes version upgrades
const UPGRADE_WORKLOAD_CLUSTER_NAME: &str = "e2e-upgrade";
const TEST_TIMEOUT: Duration = Duration::from_secs(90 * 60); // 90 minutes
const UPGRADE_TIMEOUT: Duration = Duration::from_secs(30 * 60); // 30 minutes for upgrade

fn get_upgrade_versions() -> (String, String) {
    let from =
        std::env::var("LATTICE_UPGRADE_FROM_VERSION").unwrap_or_else(|_| "1.31.0".to_string());
    let to = std::env::var("LATTICE_UPGRADE_TO_VERSION").unwrap_or_else(|_| "1.32.0".to_string());
    (from, to)
}

#[tokio::test]
async fn test_upgrade_with_mesh_traffic() {
    init_e2e_test();

    let (from_version, to_version) = get_upgrade_versions();

    info!("=========================================================");
    info!(
        "UPGRADE RESILIENCE TEST: v{} -> v{}",
        from_version, to_version
    );
    info!("=========================================================");

    // Opt-in cleanup of orphaned clusters from previous failed runs
    setup::cleanup_orphan_bootstrap_clusters();

    if let Err(e) = build_and_push_lattice_image(DEFAULT_LATTICE_IMAGE).await {
        panic!("Failed to build Lattice image: {}", e);
    }

    match tokio::time::timeout(TEST_TIMEOUT, run_upgrade_test()).await {
        Ok(Ok(())) => {
            info!("=========================================================");
            info!("UPGRADE TEST PASSED");
            info!("=========================================================");
        }
        Ok(Err(e)) => {
            error!("=========================================================");
            error!("UPGRADE TEST FAILED: {}", e);
            error!("=========================================================");
            setup::cleanup_bootstrap_cluster(run_id());
            panic!("Upgrade test failed: {}", e);
        }
        Err(_) => {
            error!("=========================================================");
            error!("UPGRADE TEST TIMED OUT");
            error!("=========================================================");
            setup::cleanup_bootstrap_cluster(run_id());
            panic!("Upgrade test timed out after {:?}", TEST_TIMEOUT);
        }
    }
}

async fn run_upgrade_test() -> Result<(), String> {
    let (from_version, to_version) = get_upgrade_versions();

    // Load configurations
    let (mgmt_config_content, _) =
        load_cluster_config("LATTICE_MGMT_CLUSTER_CONFIG", "docker-mgmt.yaml")?;

    let (_, mut workload_cluster) =
        load_cluster_config("LATTICE_WORKLOAD_CLUSTER_CONFIG", "docker-workload.yaml")?;

    let workload_provider: InfraProvider = workload_cluster.spec.provider.provider_type().into();
    let workload_bootstrap = workload_cluster.spec.provider.kubernetes.bootstrap.clone();

    // Override to start at from_version
    workload_cluster.spec.provider.kubernetes.version = from_version.clone();
    workload_cluster.metadata.name = Some(UPGRADE_WORKLOAD_CLUSTER_NAME.to_string());

    ensure_docker_network().map_err(|e| format!("Failed to setup Docker network: {}", e))?;

    // Install management cluster
    info!("[Phase 1] Installing management cluster...");
    let registry_credentials = load_registry_credentials();

    let installer = Installer::new(
        mgmt_config_content,
        DEFAULT_LATTICE_IMAGE.to_string(),
        true,
        registry_credentials,
        None,
        Some(super::helpers::run_id().to_string()),
    )
    .map_err(|e| format!("Failed to create installer: {}", e))?;

    installer
        .run()
        .await
        .map_err(|e| format!("Installer failed: {}", e))?;

    let mgmt_kubeconfig = get_docker_kubeconfig(MGMT_CLUSTER_NAME)?;
    let mgmt_client = client_from_kubeconfig(&mgmt_kubeconfig).await?;

    // Create workload cluster at from_version
    info!(
        "[Phase 2] Creating workload cluster at v{}...",
        from_version
    );

    let api: Api<LatticeCluster> = Api::all(mgmt_client.clone());
    api.create(&PostParams::default(), &workload_cluster)
        .await
        .map_err(|e| format!("Failed to create workload cluster: {}", e))?;

    // Wait for cluster to be ready
    watch_cluster_phases(&mgmt_client, UPGRADE_WORKLOAD_CLUSTER_NAME, Some(600)).await?;
    info!("Workload cluster ready at v{}!", from_version);

    // Extract kubeconfig
    let workload_kubeconfig_path = kubeconfig_path(UPGRADE_WORKLOAD_CLUSTER_NAME);
    if workload_provider == InfraProvider::Docker {
        extract_docker_cluster_kubeconfig(
            UPGRADE_WORKLOAD_CLUSTER_NAME,
            &workload_bootstrap,
            &workload_kubeconfig_path,
        )
        .await?;
    }

    // Deploy mesh services
    info!("[Phase 3] Deploying mesh services...");
    let mesh_handle = start_mesh_test(&workload_kubeconfig_path).await?;

    // Initial verification - wait for 1 complete test cycle
    wait_for_mesh_test_cycles(&workload_kubeconfig_path, 1).await?;
    mesh_handle.check_no_policy_gaps().await?;
    info!("Initial policy verification passed");

    // Start chaos with coordinated attacks for upgrade stress testing
    info!("[Phase 4] Starting coordinated chaos monkey...");
    let chaos_targets = Arc::new(ChaosTargets::new(run_id()));
    chaos_targets.add(MGMT_CLUSTER_NAME, &mgmt_kubeconfig, None);
    chaos_targets.add(
        UPGRADE_WORKLOAD_CLUSTER_NAME,
        &workload_kubeconfig_path,
        Some(&mgmt_kubeconfig),
    );

    let chaos_config = ChaosConfig::for_provider(workload_provider).with_coordinated(0.5);
    let _chaos = ChaosMonkey::start_with_config(chaos_targets, chaos_config);

    // Trigger upgrade
    info!("[Phase 5] Triggering upgrade to v{}...", to_version);

    let workload_client = client_from_kubeconfig(&workload_kubeconfig_path).await?;
    let workload_api: Api<LatticeCluster> = Api::all(workload_client.clone());

    let patch = json!({
        "spec": {
            "provider": {
                "kubernetes": {
                    "version": to_version
                }
            }
        }
    });

    workload_api
        .patch(
            UPGRADE_WORKLOAD_CLUSTER_NAME,
            &PatchParams::apply("lattice-e2e"),
            &Patch::Merge(&patch),
        )
        .await
        .map_err(|e| format!("Failed to trigger upgrade: {}", e))?;

    // Monitor upgrade with policy checks
    info!("[Phase 6] Monitoring upgrade (chaos active)...");
    monitor_upgrade(&workload_kubeconfig_path, &to_version, &mesh_handle).await?;

    // Final verification - wait for 1 complete test cycle after upgrade
    info!("[Phase 7] Final verification...");
    wait_for_mesh_test_cycles(&workload_kubeconfig_path, 1).await?;
    mesh_handle.check_no_policy_gaps().await?;
    mesh_handle.stop_and_verify().await?;

    // Cleanup
    info!("[Cleanup] Deleting workload cluster...");
    let _ = workload_api
        .delete(UPGRADE_WORKLOAD_CLUSTER_NAME, &DeleteParams::default())
        .await;
    wait_for_cluster_deleted(&mgmt_kubeconfig, UPGRADE_WORKLOAD_CLUSTER_NAME).await?;

    // Force cleanup Docker containers
    let _ = run_cmd(
        "docker",
        &[
            "rm",
            "-f",
            &format!("{}-control-plane", UPGRADE_WORKLOAD_CLUSTER_NAME),
        ],
    );
    let _ = run_cmd(
        "docker",
        &[
            "rm",
            "-f",
            &format!("{}-worker", UPGRADE_WORKLOAD_CLUSTER_NAME),
        ],
    );

    info!(
        "Upgrade test complete: v{} -> v{}",
        from_version, to_version
    );
    Ok(())
}

async fn wait_for_cluster_deleted(kubeconfig: &str, name: &str) -> Result<(), String> {
    use super::helpers::wait_for_condition;

    // Use a generous timeout - cluster deletion can take a while with CAPI cleanup
    wait_for_condition(
        &format!("cluster {} to be deleted", name),
        Duration::from_secs(600),
        Duration::from_secs(5),
        || async move {
            match run_cmd(
                "kubectl",
                &[
                    "--kubeconfig",
                    kubeconfig,
                    "get",
                    "latticecluster",
                    name,
                    "-o",
                    "name",
                ],
            ) {
                Err(e) if e.contains("not found") || e.contains("NotFound") => Ok(true),
                Err(e) => {
                    info!("[Upgrade] Error checking cluster deletion: {}", e);
                    Ok(false)
                }
                Ok(_) => Ok(false),
            }
        },
    )
    .await
}

async fn monitor_upgrade(
    kubeconfig_path: &str,
    target_version: &str,
    mesh_handle: &super::mesh_tests::MeshTestHandle,
) -> Result<(), String> {
    let start = Instant::now();

    loop {
        if start.elapsed() > UPGRADE_TIMEOUT {
            return Err("Upgrade timed out".to_string());
        }

        // Check for policy gaps
        if let Err(e) = mesh_handle.check_no_policy_gaps().await {
            return Err(format!("SECURITY VIOLATION during upgrade: {}", e));
        }

        // Check node versions
        let output = run_cmd(
            "kubectl",
            &[
                "--kubeconfig", kubeconfig_path,
                "get", "nodes",
                "-o", "jsonpath={range .items[*]}{.status.nodeInfo.kubeletVersion} {.status.conditions[?(@.type=='Ready')].status}{\"\\n\"}{end}",
            ],
        ).unwrap_or_default();

        let mut all_upgraded = true;
        let mut all_ready = true;
        let mut node_count = 0;

        for line in output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                node_count += 1;
                if !parts[0].contains(target_version) {
                    all_upgraded = false;
                }
                if parts[1] != "True" {
                    all_ready = false;
                }
            }
        }

        let elapsed = start.elapsed().as_secs();
        info!(
            "[{:3}s] Nodes: {}, upgraded: {}, ready: {}",
            elapsed, node_count, all_upgraded, all_ready
        );

        if all_upgraded && all_ready && node_count > 0 {
            info!("Upgrade complete - all nodes at v{}", target_version);
            return Ok(());
        }

        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}
