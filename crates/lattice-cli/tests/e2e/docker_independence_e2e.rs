//! Docker-specific E2E test for cluster independence verification
//!
//! This test validates that a workload cluster remains fully operational after its
//! parent management cluster is deleted. This proves the pivoting architecture works
//! correctly - each cluster is truly self-managing.
//!
//! # Test Flow
//!
//! 1. Install management cluster
//! 2. Create workload cluster off management cluster
//! 3. Verify workload cluster is self-managing (has own CAPI resources)
//! 4. Delete management cluster (force delete via Docker)
//! 5. Scale workload cluster workers 1 -> 2
//! 6. Verify workload cluster scaled successfully without parent
//! 7. Cleanup workload cluster (force delete via Docker)
//!
//! # Why Docker-Only
//!
//! This test uses force-deletion (docker rm -f) which is only safe for Docker provider.
//! For cloud providers, force-deleting would orphan cloud resources. The main E2E test
//! uses proper unpivot/uninstall flows that work for all providers.
//!
//! # Running
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e docker_independence -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use kube::api::{Api, PostParams};
use tracing::info;

use lattice_cli::commands::install::Installer;
use lattice_operator::crd::LatticeCluster;

use super::context::init_e2e_test;
use super::helpers::{
    build_and_push_lattice_image, client_from_kubeconfig, docker_containers_deleted,
    ensure_docker_network, extract_docker_cluster_kubeconfig, force_delete_docker_cluster,
    get_docker_kubeconfig, kubeconfig_path, load_cluster_config, load_registry_credentials,
    run_cmd, watch_cluster_phases, watch_worker_scaling, DEFAULT_LATTICE_IMAGE, MGMT_CLUSTER_NAME,
    WORKLOAD_CLUSTER_NAME,
};
use super::integration::setup::cleanup_bootstrap_clusters;

const E2E_TIMEOUT: Duration = Duration::from_secs(1800);

fn cleanup_clusters(mgmt_name: &str, workload_name: &str) {
    info!("Cleaning up all test resources...");
    cleanup_bootstrap_clusters();
    force_delete_docker_cluster(mgmt_name);
    force_delete_docker_cluster(workload_name);
}

#[tokio::test]
async fn test_docker_independence() {
    init_e2e_test();
    info!("Starting independence test: workload clusters survive parent deletion");

    let (_, mgmt_cluster) =
        load_cluster_config("LATTICE_INDEP_MGMT_CONFIG", "docker-mgmt.yaml").unwrap();
    let (_, workload_cluster) =
        load_cluster_config("LATTICE_INDEP_WORKLOAD_CONFIG", "docker-workload.yaml").unwrap();
    let mgmt_name = mgmt_cluster
        .metadata
        .name
        .as_deref()
        .unwrap_or(MGMT_CLUSTER_NAME);
    let workload_name = workload_cluster
        .metadata
        .name
        .as_deref()
        .unwrap_or(WORKLOAD_CLUSTER_NAME);

    cleanup_clusters(mgmt_name, workload_name);

    if let Err(e) = build_and_push_lattice_image(DEFAULT_LATTICE_IMAGE).await {
        cleanup_clusters(mgmt_name, workload_name);
        panic!("Failed to build image: {}", e);
    }

    let result = tokio::time::timeout(
        E2E_TIMEOUT,
        run_independence_test(mgmt_name.to_string(), workload_name.to_string()),
    )
    .await;

    cleanup_clusters(mgmt_name, workload_name);

    match result {
        Ok(Ok(())) => {
            info!("TEST PASSED");
        }
        Ok(Err(e)) => {
            panic!("Independence test failed: {}", e);
        }
        Err(_) => {
            panic!("Test timed out after {:?}", E2E_TIMEOUT);
        }
    }
}

async fn run_independence_test(
    mgmt_cluster_name: String,
    workload_cluster_name: String,
) -> Result<(), String> {
    ensure_docker_network().map_err(|e| format!("Failed to setup Docker network: {}", e))?;

    let (mgmt_config, _) = load_cluster_config("LATTICE_INDEP_MGMT_CONFIG", "docker-mgmt.yaml")?;
    let (_, workload_cluster) =
        load_cluster_config("LATTICE_INDEP_WORKLOAD_CONFIG", "docker-workload.yaml")?;
    let workload_bootstrap = workload_cluster.spec.provider.kubernetes.bootstrap.clone();

    // =========================================================================
    // Phase 1: Install Management Cluster
    // =========================================================================
    info!("[Phase 1] Installing management cluster...");

    let installer = Installer::new(
        mgmt_config,
        DEFAULT_LATTICE_IMAGE.to_string(),
        true,
        load_registry_credentials(),
        None,
        Some(super::helpers::run_id().to_string()),
    )
    .map_err(|e| format!("Failed to create installer: {}", e))?;

    installer
        .run()
        .await
        .map_err(|e| format!("Install failed: {}", e))?;

    info!("Management cluster installed!");

    // =========================================================================
    // Phase 2: Create Workload Cluster
    // =========================================================================
    info!("[Phase 2] Creating workload cluster...");

    let mgmt_kubeconfig = get_docker_kubeconfig(&mgmt_cluster_name)?;
    let mgmt_client = client_from_kubeconfig(&mgmt_kubeconfig).await?;

    let api: Api<LatticeCluster> = Api::all(mgmt_client.clone());
    api.create(&PostParams::default(), &workload_cluster)
        .await
        .map_err(|e| format!("Failed to create workload cluster: {}", e))?;

    info!("Waiting for workload cluster to be ready...");
    watch_cluster_phases(&mgmt_client, &workload_cluster_name, None).await?;

    info!("Workload cluster ready!");

    // =========================================================================
    // Phase 3: Verify Workload Has CAPI Resources
    // =========================================================================
    info!("[Phase 3] Verifying workload cluster is self-managing...");

    let workload_kubeconfig = kubeconfig_path(&workload_cluster_name);
    extract_docker_cluster_kubeconfig(
        &workload_cluster_name,
        &workload_bootstrap,
        &workload_kubeconfig,
    )?;

    let capi_check = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &workload_kubeconfig,
            "get",
            "clusters",
            "-A",
        ],
    )?;

    if !capi_check.contains(&workload_cluster_name) {
        return Err("Workload cluster missing CAPI resources after pivot".to_string());
    }

    info!("Workload cluster has its own CAPI resources!");

    watch_worker_scaling(&workload_kubeconfig, &workload_cluster_name, 1).await?;

    // =========================================================================
    // Phase 4: Delete Management Cluster
    // =========================================================================
    info!("[Phase 4] Deleting management cluster (force delete)...");
    info!("This simulates parent failure - workload should survive");

    force_delete_docker_cluster(&mgmt_cluster_name);

    if !docker_containers_deleted(&mgmt_cluster_name) {
        return Err("Failed to delete management cluster containers".to_string());
    }

    info!("Management cluster deleted!");

    // =========================================================================
    // Phase 5: Scale Workload Cluster
    // =========================================================================
    info!("[Phase 5] Scaling workload cluster workers 1 -> 2...");
    info!("If this works, the cluster is truly self-managing");

    run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &workload_kubeconfig,
            "patch",
            "latticecluster",
            &workload_cluster_name,
            "--type=merge",
            "-p",
            r#"{"spec":{"nodes":{"workerPools":{"default":{"replicas":2}}}}}"#,
        ],
    )?;

    info!("Patch applied, waiting for scale-up...");

    // =========================================================================
    // Phase 6: Verify Scaling Succeeded
    // =========================================================================
    info!("[Phase 6] Verifying workload cluster scaled to 2 workers...");

    watch_worker_scaling(&workload_kubeconfig, &workload_cluster_name, 2).await?;

    info!("SUCCESS: Workload cluster scaled from 1 to 2 workers");
    info!("SUCCESS: Cluster is fully operational without parent!");

    Ok(())
}
