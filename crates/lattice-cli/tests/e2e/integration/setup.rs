//! Infrastructure setup for integration and E2E tests
//!
//! This module provides functions to set up cluster infrastructure that can be
//! reused across different test scenarios. The setup functions create clusters
//! and return an `InfraContext` with the kubeconfig paths.
//!
//! # Cleanup Strategy
//!
//! Each test run uses a unique `run_id` suffix for its bootstrap cluster, allowing
//! parallel test execution without conflicts. Cleanup functions:
//!
//! - `cleanup_bootstrap_cluster(run_id)` - Clean up this run's bootstrap cluster (targeted)
//! - `cleanup_orphan_bootstrap_clusters()` - Clean up ALL orphaned bootstrap clusters (opt-in)
//!
//! The orphan cleanup only runs when `LATTICE_CLEANUP_ORPHANS=1` is set, to avoid
//! accidentally deleting clusters from parallel test runs.
//!
//! # Running Setup Only
//!
//! ```bash
//! # Build full 3-cluster hierarchy, leave running for integration tests
//! cargo test --features provider-e2e --test e2e test_setup_hierarchy_only -- --ignored --nocapture
//!
//! # Then run integration tests against the existing clusters
//! LATTICE_WORKLOAD_KUBECONFIG=/tmp/e2e-workload-kubeconfig-xxx \
//! cargo test --features provider-e2e --test e2e test_mesh_standalone -- --ignored --nocapture
//! ```
//!
//! # Cleaning Up Orphaned Clusters
//!
//! If you have orphaned clusters from failed runs, use:
//!
//! ```bash
//! LATTICE_CLEANUP_ORPHANS=1 cargo test --features provider-e2e --test e2e test_setup_hierarchy_only -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::sync::Arc;

use kube::api::{Api, PostParams};
use tracing::info;

use lattice_cli::commands::install::Installer;
use lattice_operator::crd::LatticeCluster;

use super::super::chaos::{ChaosConfig, ChaosMonkey, ChaosTargets};
use super::super::context::InfraContext;
use super::super::helpers::{
    build_and_push_lattice_image, client_from_kubeconfig, ensure_docker_network,
    extract_docker_cluster_kubeconfig, get_docker_kubeconfig, kubeconfig_path, load_cluster_config,
    load_registry_credentials, rebuild_and_restart_operators, run_cmd_allow_fail,
    watch_cluster_phases, watch_cluster_phases_with_kubeconfig, ProxySession,
};
use super::super::providers::InfraProvider;
use super::{capi, pivot, scaling};

// =============================================================================
// Configuration
// =============================================================================

use super::super::helpers::{
    DEFAULT_LATTICE_IMAGE, MGMT_CLUSTER_NAME, WORKLOAD2_CLUSTER_NAME, WORKLOAD_CLUSTER_NAME,
};

/// Configuration for infrastructure setup
#[derive(Clone)]
pub struct SetupConfig {
    /// Lattice container image to use
    pub lattice_image: String,
    /// Whether to enable chaos monkey during setup
    pub enable_chaos: bool,
    /// Whether to build and push the lattice image before setup
    pub build_image: bool,
}

impl Default for SetupConfig {
    fn default() -> Self {
        Self {
            lattice_image: DEFAULT_LATTICE_IMAGE.to_string(),
            enable_chaos: false,
            build_image: true,
        }
    }
}

impl SetupConfig {
    /// Create config that skips image build (for faster iteration)
    pub fn skip_build() -> Self {
        Self {
            build_image: false,
            ..Default::default()
        }
    }

    /// Create config with chaos monkey enabled
    pub fn with_chaos() -> Self {
        Self {
            enable_chaos: true,
            ..Default::default()
        }
    }
}

/// Result of infrastructure setup containing context and optional chaos handle
pub struct SetupResult {
    /// Infrastructure context with kubeconfig paths (proxy-based for child clusters)
    pub ctx: InfraContext,
    /// Chaos monkey handle (if enabled)
    pub chaos: Option<ChaosMonkey>,
    /// Chaos targets (if enabled)
    pub chaos_targets: Option<Arc<ChaosTargets>>,
    /// Proxy session to mgmt cluster (keeps port-forward alive for workload access)
    pub mgmt_proxy: Option<ProxySession>,
    /// Proxy session to workload cluster (keeps port-forward alive for workload2 access)
    pub workload_proxy: Option<ProxySession>,
}

impl SetupResult {
    /// Stop chaos monkey if running
    pub async fn stop_chaos(&mut self) {
        if let Some(chaos) = self.chaos.take() {
            chaos.stop().await;
        }
    }
}

// =============================================================================
// Setup Functions
// =============================================================================

fn get_kubeconfig(cluster_name: &str, provider: InfraProvider) -> Result<String, String> {
    if provider == InfraProvider::Docker {
        get_docker_kubeconfig(cluster_name)
    } else {
        Ok(kubeconfig_path(cluster_name))
    }
}

/// Clean up the bootstrap cluster for a specific run_id
///
/// This should be called at the end of a test run (success or failure) to clean up
/// the bootstrap cluster created by this specific run.
pub fn cleanup_bootstrap_cluster(run_id: &str) {
    let cluster_name = format!("lattice-bootstrap-{}", run_id);
    info!("Cleaning up bootstrap cluster '{}'...", cluster_name);
    let _ = run_cmd_allow_fail("kind", &["delete", "cluster", "--name", &cluster_name]);
}

/// Clean up ALL orphaned bootstrap clusters (opt-in)
///
/// Cleans up all `lattice-bootstrap-*` clusters when `LATTICE_CLEANUP_ORPHANS=1` is set.
/// Use this when you need to clean up stale clusters from previous failed runs.
///
/// **Warning**: This will delete bootstrap clusters from OTHER parallel test runs.
/// Only use when you're sure no other tests are running.
pub fn cleanup_orphan_bootstrap_clusters() {
    if std::env::var("LATTICE_CLEANUP_ORPHANS").is_ok() {
        info!("LATTICE_CLEANUP_ORPHANS is set - cleaning up ALL orphaned bootstrap clusters...");
        let clusters = run_cmd_allow_fail("kind", &["get", "clusters"]);
        for cluster in clusters.lines() {
            let cluster = cluster.trim();
            if cluster.starts_with("lattice-bootstrap-") {
                info!("Deleting orphaned bootstrap cluster: {}", cluster);
                let _ = run_cmd_allow_fail("kind", &["delete", "cluster", "--name", cluster]);
            }
        }
    }
}

/// Set up the full 3-cluster hierarchy (mgmt -> workload -> workload2)
///
/// This function:
/// 1. Builds and pushes the Lattice image (if configured)
/// 2. Installs the management cluster
/// 3. Verifies mgmt is self-managing
/// 4. Creates and verifies workload cluster
/// 5. Creates and verifies workload2 cluster
///
/// Returns an `InfraContext` with all kubeconfig paths populated.
///
/// # Example
///
/// ```rust,ignore
/// let result = setup_full_hierarchy(&SetupConfig::default()).await?;
/// println!("Management: {}", result.ctx.mgmt_kubeconfig);
/// println!("Workload: {:?}", result.ctx.workload_kubeconfig);
/// println!("Workload2: {:?}", result.ctx.workload2_kubeconfig);
/// ```
pub async fn setup_full_hierarchy(config: &SetupConfig) -> Result<SetupResult, String> {
    // Opt-in cleanup of orphaned clusters from previous failed runs
    cleanup_orphan_bootstrap_clusters();

    // Build image if configured
    if config.build_image {
        info!("[Setup] Building and pushing Lattice image...");
        build_and_push_lattice_image(&config.lattice_image).await?;
    }

    // Load cluster configurations
    info!("[Setup] Loading cluster configurations...");

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

    info!("[Setup] Configuration:");
    info!("  Management:  {} + {:?}", mgmt_provider, mgmt_bootstrap);
    info!(
        "  Workload:    {} + {:?}",
        workload_provider, workload_bootstrap
    );
    info!(
        "  Workload2:   {} + {:?}",
        workload_provider, workload2_bootstrap
    );

    // Setup Docker network if needed
    if mgmt_provider == InfraProvider::Docker {
        ensure_docker_network().map_err(|e| format!("Failed to setup Docker network: {}", e))?;
    }

    // Start chaos monkey if configured (uses provider-appropriate intervals)
    let (chaos, chaos_targets) = if config.enable_chaos {
        let targets = Arc::new(ChaosTargets::new());
        let config = ChaosConfig::for_provider(mgmt_provider);
        let monkey = ChaosMonkey::start_with_config(targets.clone(), config);
        (Some(monkey), Some(targets))
    } else {
        (None, None)
    };

    // =========================================================================
    // Phase 1: Install Management Cluster
    // =========================================================================
    info!("[Setup/Phase 1] Installing management cluster...");

    let registry_credentials = load_registry_credentials();
    if registry_credentials.is_some() {
        info!("[Setup] Registry credentials loaded");
    }

    let installer = Installer::new(
        mgmt_config_content,
        config.lattice_image.clone(),
        true, // keep_bootstrap_on_failure
        registry_credentials,
        None,
        Some(super::super::helpers::run_id().to_string()),
    )
    .map_err(|e| format!("Failed to create installer: {}", e))?;

    installer
        .run()
        .await
        .map_err(|e| format!("Installer failed: {}", e))?;

    info!("[Setup] Management cluster installation complete!");

    // =========================================================================
    // Phase 2: Verify Management Cluster
    // =========================================================================
    info!("[Setup/Phase 2] Verifying management cluster is self-managing...");

    let mgmt_kubeconfig_path = get_kubeconfig(MGMT_CLUSTER_NAME, mgmt_provider)?;
    info!("[Setup] Management kubeconfig: {}", mgmt_kubeconfig_path);

    let mgmt_client = client_from_kubeconfig(&mgmt_kubeconfig_path).await?;

    let ctx = InfraContext::mgmt_only(mgmt_kubeconfig_path.clone(), mgmt_provider);
    capi::verify_mgmt_capi_resources(&ctx, MGMT_CLUSTER_NAME).await?;

    info!("[Setup] Waiting for management LatticeCluster to be Ready...");
    pivot::wait_for_cluster_ready(&mgmt_client, MGMT_CLUSTER_NAME, None).await?;

    info!("[Setup] SUCCESS: Management cluster is self-managing!");

    // Add mgmt to chaos targets (no parent)
    if let Some(ref targets) = chaos_targets {
        targets.add(MGMT_CLUSTER_NAME, &mgmt_kubeconfig_path, None);
    }

    // =========================================================================
    // Phase 3: Create Workload Cluster
    // =========================================================================
    info!("[Setup/Phase 3] Creating workload cluster...");

    let api: Api<LatticeCluster> = Api::all(mgmt_client.clone());
    api.create(&PostParams::default(), &workload_cluster)
        .await
        .map_err(|e| format!("Failed to create workload LatticeCluster: {}", e))?;

    info!("[Setup] Workload LatticeCluster created, waiting for Ready...");

    let workload_kubeconfig_path = kubeconfig_path(WORKLOAD_CLUSTER_NAME);

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

    info!("[Setup] SUCCESS: Workload cluster is Ready!");

    // =========================================================================
    // Phase 4: Verify Workload Cluster
    // =========================================================================
    info!("[Setup/Phase 4] Verifying workload cluster...");

    if workload_provider == InfraProvider::Docker {
        extract_docker_cluster_kubeconfig(
            WORKLOAD_CLUSTER_NAME,
            &workload_bootstrap,
            &workload_kubeconfig_path,
        )?;
    }
    info!("[Setup] Workload kubeconfig: {}", workload_kubeconfig_path);

    let ctx = ctx.with_workload(workload_kubeconfig_path.clone());

    capi::verify_workload_capi_resources(&ctx, WORKLOAD_CLUSTER_NAME).await?;

    info!("[Setup] SUCCESS: Workload cluster pivot verified!");

    // Add workload to chaos targets (parent: mgmt)
    if let Some(ref targets) = chaos_targets {
        targets.add(
            WORKLOAD_CLUSTER_NAME,
            &workload_kubeconfig_path,
            Some(&mgmt_kubeconfig_path),
        );
    }

    // =========================================================================
    // Phase 5: Create Workload2 Cluster (parallel with workload worker join)
    // =========================================================================
    info!("[Setup/Phase 5] Creating workload2 cluster (deep hierarchy)...");

    let workload_client = client_from_kubeconfig(&workload_kubeconfig_path).await?;
    let workload_api: Api<LatticeCluster> = Api::all(workload_client.clone());

    workload_api
        .create(&PostParams::default(), &workload2_cluster)
        .await
        .map_err(|e| format!("Failed to create workload2: {}", e))?;

    info!("[Setup] Workload2 LatticeCluster created, waiting for Ready (workers joining in parallel)...");

    let workload2_kubeconfig_path = kubeconfig_path(WORKLOAD2_CLUSTER_NAME);

    // Run workload worker verification in parallel with workload2 provisioning
    let (worker_result, phase_result) = tokio::join!(
        scaling::verify_workers(&ctx, WORKLOAD_CLUSTER_NAME, 1),
        async {
            if workload_provider == InfraProvider::Docker {
                watch_cluster_phases(&workload_client, WORKLOAD2_CLUSTER_NAME, None).await
            } else {
                watch_cluster_phases_with_kubeconfig(
                    &workload_kubeconfig_path,
                    WORKLOAD2_CLUSTER_NAME,
                    None,
                    &workload2_kubeconfig_path,
                )
                .await
            }
        }
    );
    worker_result?;
    phase_result?;

    info!("[Setup] SUCCESS: Workload2 cluster is Ready!");

    // =========================================================================
    // Phase 6: Verify Workload2 Cluster
    // =========================================================================
    info!("[Setup/Phase 6] Verifying workload2 cluster...");

    if workload_provider == InfraProvider::Docker {
        extract_docker_cluster_kubeconfig(
            WORKLOAD2_CLUSTER_NAME,
            &workload2_bootstrap,
            &workload2_kubeconfig_path,
        )?;
    }
    info!(
        "[Setup] Workload2 kubeconfig: {}",
        workload2_kubeconfig_path
    );

    let ctx = ctx.with_workload2(workload2_kubeconfig_path.clone());

    capi::verify_workload2_capi_resources(&ctx, WORKLOAD2_CLUSTER_NAME).await?;

    info!("[Setup] SUCCESS: Workload2 cluster verified!");

    // Add workload2 to chaos targets (parent: workload)
    if let Some(ref targets) = chaos_targets {
        targets.add(
            WORKLOAD2_CLUSTER_NAME,
            &workload2_kubeconfig_path,
            Some(&workload_kubeconfig_path),
        );
    }

    // =========================================================================
    // Phase 7: Generate Proxy Kubeconfigs
    // =========================================================================
    info!("[Setup/Phase 7] Generating proxy kubeconfigs...");

    // Start proxy session to mgmt for accessing workload
    let mgmt_proxy = ProxySession::start(&mgmt_kubeconfig_path)?;
    let workload_proxy_kc = mgmt_proxy.kubeconfig_for(WORKLOAD_CLUSTER_NAME)?;

    // Start proxy session to workload for accessing workload2
    // Note: We use the direct workload kubeconfig here since we need to access workload directly
    let workload_proxy = ProxySession::start(&workload_kubeconfig_path)?;
    let workload2_proxy_kc = workload_proxy.kubeconfig_for(WORKLOAD2_CLUSTER_NAME)?;

    // Build final context with proxy kubeconfigs
    let ctx = InfraContext::new(
        mgmt_kubeconfig_path.clone(),
        Some(workload_proxy_kc.clone()),
        Some(workload2_proxy_kc.clone()),
        mgmt_provider,
    );

    // =========================================================================
    // Setup Complete
    // =========================================================================
    info!("");
    info!("========================================");
    info!("INFRASTRUCTURE SETUP COMPLETE");
    info!("========================================");
    info!("");
    info!("Cluster hierarchy: mgmt -> workload -> workload2");
    info!("");
    info!("Kubeconfig paths (proxy-based for child clusters):");
    info!("  LATTICE_MGMT_KUBECONFIG={}", ctx.mgmt_kubeconfig);
    info!("  LATTICE_WORKLOAD_KUBECONFIG={}", workload_proxy_kc);
    info!("  LATTICE_WORKLOAD2_KUBECONFIG={}", workload2_proxy_kc);
    info!("");
    info!("Run integration tests with:");
    info!("  LATTICE_MGMT_KUBECONFIG={} \\", ctx.mgmt_kubeconfig);
    info!("  LATTICE_WORKLOAD_KUBECONFIG={} \\", workload_proxy_kc);
    info!("  LATTICE_WORKLOAD2_KUBECONFIG={} \\", workload2_proxy_kc);
    info!("  cargo test --features provider-e2e --test e2e <test_name> -- --ignored --nocapture");
    info!("");

    Ok(SetupResult {
        ctx,
        chaos,
        chaos_targets,
        mgmt_proxy: Some(mgmt_proxy),
        workload_proxy: Some(workload_proxy),
    })
}

/// Set up management cluster only
///
/// Useful when you only need a single self-managing cluster.
pub async fn setup_mgmt_only(config: &SetupConfig) -> Result<SetupResult, String> {
    // Opt-in cleanup of orphaned clusters from previous failed runs
    cleanup_orphan_bootstrap_clusters();

    if config.build_image {
        info!("[Setup] Building and pushing Lattice image...");
        build_and_push_lattice_image(&config.lattice_image).await?;
    }

    let (mgmt_config_content, mgmt_cluster) =
        load_cluster_config("LATTICE_MGMT_CLUSTER_CONFIG", "docker-mgmt.yaml")?;
    let mgmt_provider: InfraProvider = mgmt_cluster.spec.provider.provider_type().into();

    if mgmt_provider == InfraProvider::Docker {
        ensure_docker_network().map_err(|e| format!("Failed to setup Docker network: {}", e))?;
    }

    // Start chaos monkey if configured (uses provider-appropriate intervals)
    let (chaos, chaos_targets) = if config.enable_chaos {
        let targets = Arc::new(ChaosTargets::new());
        let config = ChaosConfig::for_provider(mgmt_provider);
        let monkey = ChaosMonkey::start_with_config(targets.clone(), config);
        (Some(monkey), Some(targets))
    } else {
        (None, None)
    };

    info!("[Setup] Installing management cluster...");

    let registry_credentials = load_registry_credentials();
    let installer = Installer::new(
        mgmt_config_content,
        config.lattice_image.clone(),
        true,
        registry_credentials,
        None,
        Some(super::super::helpers::run_id().to_string()),
    )
    .map_err(|e| format!("Failed to create installer: {}", e))?;

    installer
        .run()
        .await
        .map_err(|e| format!("Installer failed: {}", e))?;

    let mgmt_kubeconfig_path = get_kubeconfig(MGMT_CLUSTER_NAME, mgmt_provider)?;
    let mgmt_client = client_from_kubeconfig(&mgmt_kubeconfig_path).await?;

    let ctx = InfraContext::mgmt_only(mgmt_kubeconfig_path.clone(), mgmt_provider);
    capi::verify_mgmt_capi_resources(&ctx, MGMT_CLUSTER_NAME).await?;
    pivot::wait_for_cluster_ready(&mgmt_client, MGMT_CLUSTER_NAME, None).await?;

    if let Some(ref targets) = chaos_targets {
        targets.add(MGMT_CLUSTER_NAME, &mgmt_kubeconfig_path, None);
    }

    info!("");
    info!("========================================");
    info!("MANAGEMENT CLUSTER SETUP COMPLETE");
    info!("========================================");
    info!("  LATTICE_MGMT_KUBECONFIG={}", ctx.mgmt_kubeconfig);
    info!("");

    Ok(SetupResult {
        ctx,
        chaos,
        chaos_targets,
        mgmt_proxy: None,
        workload_proxy: None,
    })
}

/// Set up management + single workload cluster
pub async fn setup_mgmt_and_workload(config: &SetupConfig) -> Result<SetupResult, String> {
    // Start with mgmt setup
    let mut result = setup_mgmt_only(config).await?;

    let (_, workload_cluster) =
        load_cluster_config("LATTICE_WORKLOAD_CLUSTER_CONFIG", "docker-workload.yaml")?;
    let workload_provider: InfraProvider = workload_cluster.spec.provider.provider_type().into();
    let workload_bootstrap = workload_cluster.spec.provider.kubernetes.bootstrap.clone();

    info!("[Setup] Creating workload cluster...");

    let mgmt_client = client_from_kubeconfig(&result.ctx.mgmt_kubeconfig).await?;
    let api: Api<LatticeCluster> = Api::all(mgmt_client.clone());

    api.create(&PostParams::default(), &workload_cluster)
        .await
        .map_err(|e| format!("Failed to create workload LatticeCluster: {}", e))?;

    let workload_kubeconfig_path = kubeconfig_path(WORKLOAD_CLUSTER_NAME);

    if workload_provider == InfraProvider::Docker {
        watch_cluster_phases(&mgmt_client, WORKLOAD_CLUSTER_NAME, None).await?;
        extract_docker_cluster_kubeconfig(
            WORKLOAD_CLUSTER_NAME,
            &workload_bootstrap,
            &workload_kubeconfig_path,
        )?;
    } else {
        watch_cluster_phases_with_kubeconfig(
            &result.ctx.mgmt_kubeconfig,
            WORKLOAD_CLUSTER_NAME,
            None,
            &workload_kubeconfig_path,
        )
        .await?;
    }

    result.ctx = result.ctx.with_workload(workload_kubeconfig_path.clone());

    capi::verify_workload_capi_resources(&result.ctx, WORKLOAD_CLUSTER_NAME).await?;
    scaling::verify_workers(&result.ctx, WORKLOAD_CLUSTER_NAME, 1).await?;

    if let Some(ref targets) = result.chaos_targets {
        targets.add(
            WORKLOAD_CLUSTER_NAME,
            &workload_kubeconfig_path,
            Some(&result.ctx.mgmt_kubeconfig),
        );
    }

    // Generate proxy kubeconfig for workload
    info!("[Setup] Generating proxy kubeconfig for workload...");
    let mgmt_proxy = ProxySession::start(&result.ctx.mgmt_kubeconfig)?;
    let workload_proxy_kc = mgmt_proxy.kubeconfig_for(WORKLOAD_CLUSTER_NAME)?;

    // Update context with proxy kubeconfig
    result.ctx = InfraContext::new(
        result.ctx.mgmt_kubeconfig.clone(),
        Some(workload_proxy_kc.clone()),
        None,
        result.ctx.provider,
    );
    result.mgmt_proxy = Some(mgmt_proxy);

    info!("");
    info!("========================================");
    info!("MGMT + WORKLOAD SETUP COMPLETE");
    info!("========================================");
    info!("  LATTICE_MGMT_KUBECONFIG={}", result.ctx.mgmt_kubeconfig);
    info!("  LATTICE_WORKLOAD_KUBECONFIG={}", workload_proxy_kc);
    info!("");

    Ok(result)
}

// =============================================================================
// Standalone Tests
// =============================================================================

use super::super::context::init_e2e_test;

/// Setup full 3-cluster hierarchy and exit (leave clusters running)
///
/// Use this to set up infrastructure once, then run integration tests repeatedly.
///
/// ```bash
/// cargo test --features provider-e2e --test e2e test_setup_hierarchy_only -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore]
async fn test_setup_hierarchy_only() {
    init_e2e_test();

    info!("========================================");
    info!("SETUP ONLY MODE");
    info!("========================================");
    info!("This will create the full cluster hierarchy and exit.");
    info!("Clusters will be left running for integration tests.");
    info!("");

    let config = SetupConfig::default();
    let result = setup_full_hierarchy(&config).await.unwrap();
    drop(result);

    info!("Setup complete. Clusters are running.");
}

/// Setup management cluster only and exit
#[tokio::test]
#[ignore]
async fn test_setup_mgmt_only() {
    init_e2e_test();
    let config = SetupConfig::default();
    let result = setup_mgmt_only(&config).await.unwrap();
    drop(result);
    info!("Management cluster setup complete.");
}

/// Setup mgmt + workload and exit
#[tokio::test]
#[ignore]
async fn test_setup_mgmt_and_workload_only() {
    init_e2e_test();
    let config = SetupConfig::default();
    let result = setup_mgmt_and_workload(&config).await.unwrap();
    drop(result);
    info!("Management + workload cluster setup complete.");
}

/// Rebuild image and restart operators on all existing clusters
///
/// Use this to update operators after making code changes without full teardown.
/// Requires `LATTICE_MGMT_KUBECONFIG` and optionally `LATTICE_WORKLOAD_KUBECONFIG`
/// and `LATTICE_WORKLOAD2_KUBECONFIG`.
///
/// ```bash
/// LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
/// LATTICE_WORKLOAD_KUBECONFIG=/path/to/workload-kubeconfig \
/// cargo test --features provider-e2e --test e2e test_rebuild_operators -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore]
async fn test_rebuild_operators() {
    use super::super::context::init_test_env;

    let ctx = init_test_env("Set LATTICE_MGMT_KUBECONFIG to rebuild operators");

    info!("========================================");
    info!("REBUILD AND RESTART OPERATORS");
    info!("========================================");

    let kubeconfigs = ctx.all_kubeconfigs();
    info!("Found {} cluster(s):", kubeconfigs.len());
    for (name, path) in &kubeconfigs {
        info!("  {}: {}", name, path);
    }

    rebuild_and_restart_operators(DEFAULT_LATTICE_IMAGE, &kubeconfigs)
        .await
        .unwrap();

    info!("");
    info!("========================================");
    info!("OPERATORS REBUILT AND RESTARTED");
    info!("========================================");
}
