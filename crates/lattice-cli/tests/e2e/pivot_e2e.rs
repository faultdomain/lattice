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
//! 6. Create workload2 + start mesh tests (mesh runs in background)
//! 7. Delete workload2 immediately after verification (unpivot to workload)
//! 7b. Wait for mesh tests to complete
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
use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, PostParams};
use tracing::info;

use lattice_cli::commands::install::Installer;
use lattice_cli::commands::uninstall::{UninstallArgs, Uninstaller};
use lattice_operator::crd::LatticeCluster;

use super::chaos::{ChaosMonkey, ChaosTargets};
use super::helpers::{
    build_and_push_lattice_image, client_from_kubeconfig, delete_cluster_and_wait,
    ensure_docker_network, extract_docker_cluster_kubeconfig, get_docker_kubeconfig,
    load_cluster_config, load_registry_credentials, run_cmd, run_cmd_allow_fail,
    verify_cluster_capi_resources, watch_cluster_phases, watch_cluster_phases_with_kubeconfig,
    watch_worker_scaling,
};
// Media server test disabled pending investigation
#[allow(unused_imports)]
use super::media_server_e2e::{cleanup_media_server_test, run_media_server_test};
use super::mesh_tests::{
    cleanup_all_mesh_tests, run_cedar_authz_test, run_mesh_test, run_random_mesh_test,
};
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

/// Clean up kind bootstrap cluster used during install
fn cleanup_bootstrap_clusters() {
    info!("Cleaning up kind bootstrap cluster...");
    let _ = run_cmd_allow_fail(
        "kind",
        &["delete", "cluster", "--name", "lattice-bootstrap"],
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

    info!("Starting E2E test: Full Lifecycle");

    cleanup_bootstrap_clusters();

    if let Err(e) = build_and_push_lattice_image(LATTICE_IMAGE).await {
        panic!("Failed to build Lattice image: {}", e);
    }

    let result = tokio::time::timeout(E2E_TIMEOUT, run_provider_e2e()).await;

    match result {
        Ok(Ok(())) => {
            info!("TEST PASSED");
        }
        Ok(Err(e)) => {
            cleanup_bootstrap_clusters();
            panic!("E2E test failed: {} (manual cleanup may be required)", e);
        }
        Err(_) => {
            cleanup_bootstrap_clusters();
            panic!(
                "E2E test timed out after {:?} (manual cleanup required)",
                E2E_TIMEOUT
            );
        }
    }
}

async fn run_provider_e2e() -> Result<(), String> {
    let chaos_targets = Arc::new(ChaosTargets::new());
    let chaos = ChaosMonkey::start(chaos_targets.clone());

    let result = run_provider_e2e_inner(chaos_targets).await;

    chaos.stop().await;
    result
}

async fn run_provider_e2e_inner(chaos_targets: Arc<ChaosTargets>) -> Result<(), String> {
    // =========================================================================
    // Load all cluster configs upfront (fail early if missing)
    // =========================================================================
    info!("Loading cluster configurations...");

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
    info!("Management:  {} + {:?}", mgmt_provider, mgmt_bootstrap);
    info!(
        "Workload:    {} + {:?}",
        workload_provider, workload_bootstrap
    );
    info!(
        "Workload2:   {} + {:?}",
        workload_provider, workload2_bootstrap
    );

    // Setup Docker network if needed
    if mgmt_provider == InfraProvider::Docker {
        ensure_docker_network().map_err(|e| format!("Failed to setup Docker network: {}", e))?;
    }

    // =========================================================================
    // Phase 1: Install Management Cluster
    // =========================================================================
    info!(
        "[Phase 1] Installing management cluster ({} + {:?})...\n",
        mgmt_provider, mgmt_bootstrap
    );

    let registry_credentials = load_registry_credentials();
    if registry_credentials.is_some() {
        info!("Registry credentials loaded");
    }

    let installer = Installer::new(
        mgmt_config_content,
        LATTICE_IMAGE.to_string(),
        true, // keep_bootstrap_on_failure
        registry_credentials,
        None, // bootstrap_override
        true, // enable_cedar_authz
    )
    .map_err(|e| format!("Failed to create installer: {}", e))?;
    installer
        .run()
        .await
        .map_err(|e| format!("Installer failed: {}", e))?;

    info!("Management cluster installation complete!");

    // =========================================================================
    // Phase 2: Verify Management Cluster is Self-Managing
    // =========================================================================
    info!("[Phase 2] Verifying management cluster is self-managing...");

    let mgmt_kubeconfig_path = get_kubeconfig(MGMT_CLUSTER_NAME, mgmt_provider)?;
    info!("Using kubeconfig: {}", mgmt_kubeconfig_path);

    let mgmt_client = client_from_kubeconfig(&mgmt_kubeconfig_path).await?;

    info!("Checking for CAPI Cluster resource...");
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
    info!("CAPI clusters:\n{}", capi_check);

    if !capi_check.contains(MGMT_CLUSTER_NAME) {
        return Err("Management cluster should have its own CAPI Cluster resource".to_string());
    }

    info!("Waiting for management cluster's LatticeCluster to be Ready...");
    watch_cluster_phases(&mgmt_client, MGMT_CLUSTER_NAME, None).await?;

    info!("SUCCESS: Management cluster is self-managing!");

    // Add mgmt to chaos targets now that it's ready
    chaos_targets.add(MGMT_CLUSTER_NAME, &mgmt_kubeconfig_path);

    // =========================================================================
    // Phase 3: Create Workload Cluster
    // =========================================================================
    info!(
        "[Phase 3] Creating workload cluster ({} + {:?})...\n",
        workload_provider, workload_bootstrap
    );

    let api: Api<LatticeCluster> = Api::all(mgmt_client.clone());
    api.create(&PostParams::default(), &workload_cluster)
        .await
        .map_err(|e| format!("Failed to create workload LatticeCluster: {}", e))?;

    info!("Workload LatticeCluster created");

    // =========================================================================
    // Phase 4: Watch Workload Cluster Provisioning
    // =========================================================================
    info!("[Phase 4] Watching workload cluster provisioning...");

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

    info!("SUCCESS: Workload cluster is Ready!");

    // =========================================================================
    // Phase 5: Verify Workload Cluster
    // =========================================================================
    info!("[Phase 5] Verifying workload cluster...");

    if workload_provider == InfraProvider::Docker {
        info!("Extracting workload cluster kubeconfig...");
        extract_docker_cluster_kubeconfig(
            WORKLOAD_CLUSTER_NAME,
            &workload_bootstrap,
            &workload_kubeconfig_path,
        )?;
    }

    verify_cluster_capi_resources(&workload_kubeconfig_path, WORKLOAD_CLUSTER_NAME).await?;
    watch_worker_scaling(&workload_kubeconfig_path, WORKLOAD_CLUSTER_NAME, 1).await?;

    // Run Cedar ExtAuth test BEFORE chaos starts - it requires operator availability
    // Cedar authorization depends on the operator's ExtAuth server being reachable
    if mesh_test_enabled() {
        info!("[Cedar] Running Cedar ExtAuth test (before chaos)...");
        run_cedar_authz_test(&workload_kubeconfig_path).await?;
        info!("[Cedar] Cedar ExtAuth test passed!");
    }

    // Add workload to chaos targets now that Cedar test is complete
    chaos_targets.add(WORKLOAD_CLUSTER_NAME, &workload_kubeconfig_path);

    // =========================================================================
    // Phase 6: Create Workload2 + Start Mesh Tests
    // =========================================================================
    info!("[Phase 6] Creating workload2 cluster + starting mesh tests...");

    let workload_client = client_from_kubeconfig(&workload_kubeconfig_path).await?;

    // Start mesh tests in background (runs on workload cluster, doesn't need workload2)
    // Note: Cedar test already ran above (requires operator, can't run under chaos)
    let mesh_handle = if mesh_test_enabled() {
        let kubeconfig = workload_kubeconfig_path.clone();
        Some(tokio::spawn(async move {
            info!("[Mesh] Running service mesh tests...");
            let kubeconfig2 = kubeconfig.clone();

            // Run mesh tests in parallel (these test policy enforcement, not operator availability):
            // - Fixed 10-service bilateral agreement test (includes wildcard)
            // - Randomized large-scale mesh test
            let (r1, r2) = tokio::join!(
                run_mesh_test(&kubeconfig),
                run_random_mesh_test(&kubeconfig2)
            );

            r1?;
            r2?;
            info!("[Mesh] All tests complete!");
            Ok::<_, String>(())
        }))
    } else {
        None
    };

    // Create and verify workload2 (deep hierarchy test)
    let workload2_kubeconfig_path = format!("/tmp/{}-kubeconfig", WORKLOAD2_CLUSTER_NAME);
    {
        let workload_api: Api<LatticeCluster> = Api::all(workload_client.clone());
        workload_api
            .create(&PostParams::default(), &workload2_cluster)
            .await
            .map_err(|e| format!("Failed to create workload2: {}", e))?;

        info!("[Workload2] LatticeCluster created on workload cluster");

        if workload_provider == InfraProvider::Docker {
            watch_cluster_phases(&workload_client, WORKLOAD2_CLUSTER_NAME, None).await?;
        } else {
            watch_cluster_phases_with_kubeconfig(
                &workload_kubeconfig_path,
                WORKLOAD2_CLUSTER_NAME,
                None,
                &workload2_kubeconfig_path,
            )
            .await?;
        }

        info!("[Workload2] Cluster is Ready!");

        if workload_provider == InfraProvider::Docker {
            extract_docker_cluster_kubeconfig(
                WORKLOAD2_CLUSTER_NAME,
                &workload2_bootstrap,
                &workload2_kubeconfig_path,
            )?;
        }

        verify_cluster_capi_resources(&workload2_kubeconfig_path, WORKLOAD2_CLUSTER_NAME).await?;
        info!("[Workload2] Deep hierarchy verified!");
    }

    // =========================================================================
    // Phase 7: Start workload2 deletion + wait for mesh tests (parallel)
    // =========================================================================
    info!("[Phase 7] Starting workload2 deletion (unpivot flow)...");
    info!("CAPI resources will move back to workload cluster");

    // Start delete in background
    let workload2_kc = workload2_kubeconfig_path.clone();
    let workload_kc = workload_kubeconfig_path.clone();
    let delete_handle = tokio::spawn(async move {
        delete_cluster_and_wait(
            &workload2_kc,
            &workload_kc,
            WORKLOAD2_CLUSTER_NAME,
            workload_provider,
        )
        .await
    });

    // Wait for mesh tests and cleanup immediately (don't wait for delete)
    if let Some(handle) = mesh_handle {
        info!("[Phase 7] Waiting for mesh tests to complete...");
        handle
            .await
            .map_err(|e| format!("Mesh test task panicked: {}", e))??;

        info!("[Phase 7] Cleaning up mesh test services...");
        cleanup_all_mesh_tests(&workload_kubeconfig_path);
        info!("SUCCESS: Mesh tests complete and cleaned up!");
    }

    // Now wait for delete to complete
    info!("[Phase 7] Waiting for workload2 deletion to complete...");
    delete_handle
        .await
        .map_err(|e| format!("Delete task panicked: {}", e))??;

    info!("SUCCESS: Workload2 deleted and unpivoted!");

    // =========================================================================
    // Phase 8: Delete Workload (unpivot to mgmt)
    // =========================================================================
    info!("[Phase 8] Deleting workload cluster (unpivot flow)...");
    info!("CAPI resources will move back to management cluster");
    info!("(Chaos monkey continues during unpivot to test resilience)");

    delete_cluster_and_wait(
        &workload_kubeconfig_path,
        &mgmt_kubeconfig_path,
        WORKLOAD_CLUSTER_NAME,
        workload_provider,
    )
    .await?;

    info!("SUCCESS: Workload deleted and unpivoted!");

    // =========================================================================
    // Phase 9: Uninstall Management Cluster
    // =========================================================================
    info!("[Phase 9] Uninstalling management cluster...");
    info!("This uses the proper uninstall flow (reverse pivot to temporary kind cluster)");
    info!("(Chaos monkey continues during uninstall to test resilience)");

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

    info!("SUCCESS: Management cluster uninstalled!");

    info!("E2E test complete: full lifecycle verified");

    Ok(())
}

fn mesh_test_enabled() -> bool {
    std::env::var("LATTICE_ENABLE_MESH_TEST")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true)
}
