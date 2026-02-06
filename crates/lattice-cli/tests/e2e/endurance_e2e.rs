//! Endurance test for Lattice - runs forever creating/deleting clusters
//!
//! # Design
//!
//! Runs forever until failure. Each batch:
//! 1. Create 1 cluster
//! 2. Wait for all to reach Running
//! 3. Delete all clusters (chaos active during unpivot)
//! 4. Repeat
//!
//! # Failure Conditions
//!
//! - Any batch exceeds 10 minute timeout = FAILURE
//! - Any cluster failing to provision = FAILURE
//! - Any cluster failing to delete = FAILURE
//!
//! # Running
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e endurance_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::try_join_all;
use kube::api::{Api, PostParams};
use kube::Client;
use tracing::{error, info};

use lattice_cli::commands::install::Installer;
use lattice_operator::crd::LatticeCluster;

use super::chaos::{ChaosConfig, ChaosMonkey, ChaosTargets};
use super::context::init_e2e_test;
use super::helpers::{
    build_and_push_lattice_image, client_from_kubeconfig, delete_cluster_and_wait,
    ensure_docker_network, extract_docker_cluster_kubeconfig, force_delete_docker_cluster,
    get_docker_kubeconfig, kubeconfig_path, load_cluster_config, load_registry_credentials, run_id,
    watch_cluster_phases, DEFAULT_LATTICE_IMAGE, MGMT_CLUSTER_NAME,
};
use super::integration::setup;
use super::providers::InfraProvider;

const BATCH_TIMEOUT: Duration = Duration::from_secs(10 * 60); // 10 minutes per batch

/// Delete all endurance test Docker clusters (mgmt + endurance-*)
fn delete_endurance_docker_clusters() {
    force_delete_docker_cluster(MGMT_CLUSTER_NAME);
    force_delete_docker_cluster("endurance-");
}

/// Clean up this run's resources
fn cleanup_all_clusters() {
    info!("Cleaning up all test resources...");
    setup::cleanup_bootstrap_cluster(run_id());
    delete_endurance_docker_clusters();
    info!("Cleanup complete");
}

/// Clean up orphans and all resources (opt-in via LATTICE_CLEANUP_ORPHANS)
fn cleanup_orphans_and_all_clusters() {
    info!("Cleaning up orphaned and all test resources...");
    setup::cleanup_orphan_bootstrap_clusters();
    delete_endurance_docker_clusters();
    info!("Cleanup complete");
}

#[tokio::test]
async fn test_endurance_loop() {
    init_e2e_test();

    info!("=========================================================");
    info!("ENDURANCE TEST - RUNS FOREVER (10 min timeout per batch)");
    info!("=========================================================");

    // Clean up any leftover resources from previous runs (opt-in via LATTICE_CLEANUP_ORPHANS)
    cleanup_orphans_and_all_clusters();

    if let Err(e) = build_and_push_lattice_image(DEFAULT_LATTICE_IMAGE).await {
        cleanup_all_clusters();
        panic!("Failed to build Lattice image: {}", e);
    }

    // This runs forever until failure
    let result = run_endurance_test().await;

    match result {
        Ok(()) => {
            // Only clean up on success
            cleanup_all_clusters();
            info!("TEST PASSED");
        }
        Err(e) => {
            error!("=========================================================");
            error!("ENDURANCE TEST FAILED: {}", e);
            error!("Clusters left running for debugging. Run cleanup manually.");
            error!("=========================================================");
            panic!("Endurance test failed: {}", e);
        }
    }
}

async fn run_endurance_test() -> Result<(), String> {
    // Load configurations
    let (mgmt_config_content, _) =
        load_cluster_config("LATTICE_MGMT_CLUSTER_CONFIG", "docker-mgmt.yaml")?;

    // Load workload cluster configs (we'll create multiple instances with unique names)
    let (_, workload_template) =
        load_cluster_config("LATTICE_WORKLOAD_CLUSTER_CONFIG", "docker-workload.yaml")?;
    let workload_bootstrap = workload_template.spec.provider.kubernetes.bootstrap.clone();

    ensure_docker_network().map_err(|e| format!("Failed to setup Docker network: {}", e))?;

    // Install management cluster once
    info!("[SETUP] Installing management cluster...");
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

    // get_docker_kubeconfig returns the path to the patched kubeconfig (for localhost access)
    let mgmt_kubeconfig_path = get_docker_kubeconfig(MGMT_CLUSTER_NAME)?;
    let mgmt_client = client_from_kubeconfig(&mgmt_kubeconfig_path).await?;

    // Verify management cluster
    watch_cluster_phases(&mgmt_client, MGMT_CLUSTER_NAME, Some(600)).await?;
    info!("[SETUP] Management cluster ready!");

    // Start coordinated chaos monkey on mgmt cluster
    let chaos_targets = Arc::new(ChaosTargets::new(run_id()));
    chaos_targets.add(MGMT_CLUSTER_NAME, &mgmt_kubeconfig_path, None);

    info!("[CHAOS] Starting coordinated chaos monkey...");
    let chaos_config = ChaosConfig::for_provider(InfraProvider::Docker).with_coordinated(0.5);
    let _chaos = ChaosMonkey::start_with_config(chaos_targets.clone(), chaos_config);

    let mut iteration = 0u64;
    let test_start = Instant::now();

    info!("Starting batch iterations (1 cluster per batch, runs forever, 10 min timeout per batch)...");

    // Loop forever until failure
    loop {
        iteration += 1;
        let batch_start = Instant::now();
        info!(
            "[ITERATION {}] Starting batch (total runtime: {:?})",
            iteration,
            test_start.elapsed()
        );

        // Create cluster configs with unique names and IPs for this iteration
        let clusters: Vec<LatticeCluster> = (0..1)
            .map(|i| {
                let name = format!("endurance-{}-{}", iteration, i);
                // Each cluster needs a unique IP: 172.18.255.{100 + offset}
                let ip_offset = ((iteration - 1) + i) % 100 + 100;
                let ip = format!("172.18.255.{}", ip_offset);

                let mut cluster = workload_template.clone();
                cluster.metadata.name = Some(name);

                // Update networking CIDR
                if let Some(ref mut networking) = cluster.spec.networking {
                    if let Some(ref mut default) = networking.default {
                        default.cidr = format!("{}/32", ip);
                    }
                }

                // Update parent_config host
                if let Some(ref mut parent_config) = cluster.spec.parent_config {
                    parent_config.host = Some(ip.clone());
                }

                // Update cert SANs
                cluster.spec.provider.kubernetes.cert_sans =
                    Some(vec!["127.0.0.1".to_string(), "localhost".to_string(), ip]);

                cluster
            })
            .collect();

        let cluster_names: Vec<String> = clusters
            .iter()
            .filter_map(|c| c.metadata.name.clone())
            .collect();

        // Run batch with timeout
        let batch_result = tokio::time::timeout(BATCH_TIMEOUT, async {
            // Create all clusters in parallel
            info!(
                "[ITERATION {}] Creating {} clusters...",
                iteration,
                clusters.len()
            );
            create_clusters_parallel(&mgmt_client, &clusters).await?;

            // Wait for all to reach Running
            info!(
                "[ITERATION {}] Waiting for all clusters to reach Running...",
                iteration
            );
            wait_all_running(&mgmt_client, &cluster_names).await?;
            info!("[ITERATION {}] All clusters running!", iteration);

            // Add workload clusters to chaos targets (parent: mgmt)
            // These clusters were created by mgmt, so kubeconfig must be extracted from Docker
            for name in &cluster_names {
                let cluster_kc_path = kubeconfig_path(name);
                if extract_docker_cluster_kubeconfig(name, &workload_bootstrap, &cluster_kc_path)
                    .await
                    .is_ok()
                {
                    chaos_targets.add(name, &cluster_kc_path, Some(&mgmt_kubeconfig_path));
                }
            }

            // Delete all clusters (must delete from child cluster to trigger unpivot)
            info!("[ITERATION {}] Deleting all clusters...", iteration);
            for name in &cluster_names {
                // Use the kubeconfig path that was extracted above
                let cluster_kc_path = kubeconfig_path(name);
                delete_cluster_and_wait(
                    &cluster_kc_path,
                    &mgmt_kubeconfig_path,
                    name,
                    InfraProvider::Docker,
                )
                .await?;
                info!("[ITERATION {}] Cluster {} deleted!", iteration, name);
            }

            Ok::<(), String>(())
        })
        .await;

        // Remove clusters from chaos targets (whether success or failure)
        for name in &cluster_names {
            chaos_targets.remove(name);
        }

        // Check batch result
        match batch_result {
            Ok(Ok(())) => {
                info!(
                    "[ITERATION {}] Complete in {:?}!",
                    iteration,
                    batch_start.elapsed()
                );
            }
            Ok(Err(e)) => {
                return Err(format!("Batch {} failed: {}", iteration, e));
            }
            Err(_) => {
                return Err(format!(
                    "Batch {} timed out after {:?}",
                    iteration, BATCH_TIMEOUT
                ));
            }
        }
    }
}

async fn create_clusters_parallel(
    client: &Client,
    clusters: &[LatticeCluster],
) -> Result<(), String> {
    let api: Api<LatticeCluster> = Api::all(client.clone());

    let futures: Vec<_> = clusters
        .iter()
        .map(|cluster| {
            let api = api.clone();
            let cluster = cluster.clone();
            async move {
                api.create(&PostParams::default(), &cluster)
                    .await
                    .map_err(|e| {
                        format!(
                            "Failed to create {}: {}",
                            cluster.metadata.name.as_deref().unwrap_or("unknown"),
                            e
                        )
                    })
            }
        })
        .collect();

    try_join_all(futures).await?;
    Ok(())
}

async fn wait_all_running(client: &Client, cluster_names: &[String]) -> Result<(), String> {
    let futures: Vec<_> = cluster_names
        .iter()
        .map(|name| {
            let client = client.clone();
            let name = name.clone();
            async move { watch_cluster_phases(&client, &name, Some(600)).await }
        })
        .collect();

    try_join_all(futures).await?;
    Ok(())
}
