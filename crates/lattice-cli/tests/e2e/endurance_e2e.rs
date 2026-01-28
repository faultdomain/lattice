//! Endurance test for Lattice - runs forever creating/deleting clusters
//!
//! # Design
//!
//! Runs forever until failure. Each batch:
//! 1. Create 4 clusters simultaneously
//! 2. Wait for all to reach Running
//! 3. Wait 20 seconds (chaos active)
//! 4. Delete all clusters (chaos active during unpivot)
//! 5. Repeat
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
use kube::api::{Api, DeleteParams, PostParams};
use kube::Client;
use tracing::{error, info};

use lattice_cli::commands::install::Installer;
use lattice_operator::crd::LatticeCluster;

use super::chaos::{ChaosConfig, ChaosMonkey, ChaosTargets};
use super::helpers::{
    build_and_push_lattice_image, client_from_kubeconfig, ensure_docker_network,
    get_docker_kubeconfig, load_cluster_config, load_registry_credentials, run_cmd_allow_fail,
    watch_cluster_phases,
};

const MGMT_CLUSTER_NAME: &str = "e2e-mgmt";
const LATTICE_IMAGE: &str = "ghcr.io/evan-hines-js/lattice:latest";
const BATCH_TIMEOUT: Duration = Duration::from_secs(10 * 60); // 10 minutes per batch
const SETTLE_DELAY: Duration = Duration::from_secs(20);

fn cleanup_bootstrap_clusters() {
    info!("Cleaning up kind bootstrap cluster...");
    let _ = run_cmd_allow_fail(
        "kind",
        &["delete", "cluster", "--name", "lattice-bootstrap"],
    );
}

#[tokio::test]
async fn test_endurance_loop() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    info!("=========================================================");
    info!("ENDURANCE TEST - RUNS FOREVER (10 min timeout per batch)");
    info!("=========================================================");

    cleanup_bootstrap_clusters();

    if let Err(e) = build_and_push_lattice_image(LATTICE_IMAGE).await {
        panic!("Failed to build Lattice image: {}", e);
    }

    // This runs forever until failure
    if let Err(e) = run_endurance_test().await {
        error!("=========================================================");
        error!("ENDURANCE TEST FAILED: {}", e);
        error!("=========================================================");
        cleanup_bootstrap_clusters();
        panic!("Endurance test failed: {}", e);
    }
}

async fn run_endurance_test() -> Result<(), String> {
    // Load configurations
    let (mgmt_config_content, _) =
        load_cluster_config("LATTICE_MGMT_CLUSTER_CONFIG", "docker-mgmt.yaml")?;

    // Load workload cluster configs (we'll create multiple instances with unique names)
    let (_, workload_template) =
        load_cluster_config("LATTICE_WORKLOAD_CLUSTER_CONFIG", "docker-workload.yaml")?;

    ensure_docker_network().map_err(|e| format!("Failed to setup Docker network: {}", e))?;

    // Install management cluster once
    info!("[SETUP] Installing management cluster...");
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

    let mgmt_kubeconfig = get_docker_kubeconfig(MGMT_CLUSTER_NAME)?;
    let mgmt_client = client_from_kubeconfig(&mgmt_kubeconfig).await?;

    // Verify management cluster
    watch_cluster_phases(&mgmt_client, MGMT_CLUSTER_NAME, Some(600)).await?;
    info!("[SETUP] Management cluster ready!");

    // Start aggressive chaos monkey on mgmt cluster
    let chaos_targets = Arc::new(ChaosTargets::new());
    chaos_targets.add(MGMT_CLUSTER_NAME, &mgmt_kubeconfig);

    info!("[CHAOS] Starting aggressive chaos monkey...");
    let _chaos = ChaosMonkey::start_with_config(chaos_targets.clone(), ChaosConfig::aggressive());

    let mut iteration = 0u64;
    let test_start = Instant::now();

    info!("Starting batch iterations (runs forever, 10 min timeout per batch)...");

    // Loop forever until failure
    loop {
        iteration += 1;
        let batch_start = Instant::now();
        info!(
            "[ITERATION {}] Starting batch (total runtime: {:?})",
            iteration, test_start.elapsed()
        );

        // Create cluster configs with unique names for this iteration
        let cluster_names: Vec<String> = (0..4)
            .map(|i| format!("endurance-{}-{}", iteration, i))
            .collect();

        let clusters: Vec<LatticeCluster> = cluster_names
            .iter()
            .map(|name| {
                let mut cluster = workload_template.clone();
                cluster.metadata.name = Some(name.clone());
                cluster
            })
            .collect();

        // Run batch with timeout
        let batch_result = tokio::time::timeout(BATCH_TIMEOUT, async {
            // Create all clusters in parallel
            info!("[ITERATION {}] Creating {} clusters...", iteration, clusters.len());
            create_clusters_parallel(&mgmt_client, &clusters).await?;

            // Wait for all to reach Running
            info!("[ITERATION {}] Waiting for all clusters to reach Running...", iteration);
            wait_all_running(&mgmt_client, &cluster_names).await?;
            info!("[ITERATION {}] All clusters running!", iteration);

            // Add workload clusters to chaos targets
            for name in &cluster_names {
                let kubeconfig_path = format!("/tmp/{}-kubeconfig", name);
                if let Ok(kc) = get_docker_kubeconfig(name) {
                    if std::fs::write(&kubeconfig_path, &kc).is_ok() {
                        chaos_targets.add(name, &kubeconfig_path);
                    }
                }
            }

            // Wait 20 seconds with chaos running against all clusters
            info!("[ITERATION {}] Waiting {} seconds (chaos active)...", iteration, SETTLE_DELAY.as_secs());
            tokio::time::sleep(SETTLE_DELAY).await;

            // Delete all clusters in parallel (chaos continues during unpivot)
            info!("[ITERATION {}] Deleting all clusters...", iteration);
            delete_clusters_parallel(&mgmt_client, &cluster_names).await?;

            // Wait for all to be fully deleted
            info!("[ITERATION {}] Waiting for deletion to complete...", iteration);
            wait_all_deleted(&mgmt_client, &cluster_names).await?;
            info!("[ITERATION {}] All clusters deleted!", iteration);

            Ok::<(), String>(())
        })
        .await;

        // Remove clusters from chaos targets (whether success or failure)
        for name in &cluster_names {
            chaos_targets.remove(name);
        }

        // Force cleanup Docker containers
        for name in &cluster_names {
            let _ = run_cmd_allow_fail("docker", &["rm", "-f", &format!("{}-control-plane", name)]);
            let _ = run_cmd_allow_fail("docker", &["rm", "-f", &format!("{}-worker", name)]);
        }

        // Check batch result
        match batch_result {
            Ok(Ok(())) => {
                info!("[ITERATION {}] Complete in {:?}!", iteration, batch_start.elapsed());
            }
            Ok(Err(e)) => {
                return Err(format!("Batch {} failed: {}", iteration, e));
            }
            Err(_) => {
                return Err(format!("Batch {} timed out after {:?}", iteration, BATCH_TIMEOUT));
            }
        }
    }
}

async fn create_clusters_parallel(client: &Client, clusters: &[LatticeCluster]) -> Result<(), String> {
    let api: Api<LatticeCluster> = Api::all(client.clone());

    let futures: Vec<_> = clusters
        .iter()
        .map(|cluster| {
            let api = api.clone();
            let cluster = cluster.clone();
            async move {
                api.create(&PostParams::default(), &cluster)
                    .await
                    .map_err(|e| format!("Failed to create {}: {}", cluster.metadata.name.as_deref().unwrap_or("unknown"), e))
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
            async move {
                watch_cluster_phases(&client, &name, Some(600)).await
            }
        })
        .collect();

    try_join_all(futures).await?;
    Ok(())
}

async fn delete_clusters_parallel(client: &Client, cluster_names: &[String]) -> Result<(), String> {
    let api: Api<LatticeCluster> = Api::all(client.clone());

    let futures: Vec<_> = cluster_names
        .iter()
        .map(|name| {
            let api = api.clone();
            let name = name.clone();
            async move {
                // Delete the LatticeCluster - this triggers CAPI cleanup
                match api.delete(&name, &DeleteParams::default()).await {
                    Ok(_) => Ok(()),
                    Err(kube::Error::Api(ref e)) if e.code == 404 => Ok(()), // Already gone
                    Err(e) => Err(format!("Failed to delete {}: {}", name, e)),
                }
            }
        })
        .collect();

    try_join_all(futures).await?;
    Ok(())
}

async fn wait_all_deleted(client: &Client, cluster_names: &[String]) -> Result<(), String> {
    let api: Api<LatticeCluster> = Api::all(client.clone());

    for name in cluster_names {
        // Poll until the resource is gone
        loop {
            match api.get(name).await {
                Ok(_) => {
                    // Still exists, wait and retry
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                Err(kube::Error::Api(ref e)) if e.code == 404 => {
                    // Gone, move to next
                    break;
                }
                Err(e) => {
                    return Err(format!("Error checking deletion of {}: {}", name, e));
                }
            }
        }
    }
    Ok(())
}
