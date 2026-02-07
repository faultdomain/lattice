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
use lattice_common::crd::LatticeCluster;

use super::super::chaos::{ChaosConfig, ChaosMonkey, ChaosTargets};
use super::super::context::{ClusterLevel, InfraContext};
use super::super::helpers::{
    build_and_push_lattice_image, client_from_kubeconfig, ensure_docker_network,
    get_docker_kubeconfig, kubeconfig_path, load_cluster_config, load_registry_credentials,
    run_cmd, wait_for_operator_ready, watch_cluster_phases, ProxySession,
};
use super::super::providers::InfraProvider;
use super::{capi, cedar, scaling};

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
    /// Whether to skip workload2 creation (faster iteration)
    pub skip_workload2: bool,
}

impl Default for SetupConfig {
    fn default() -> Self {
        Self {
            lattice_image: DEFAULT_LATTICE_IMAGE.to_string(),
            enable_chaos: false,
            build_image: true,
            // Skip workload2 by default for faster iteration
            // Set LATTICE_ENABLE_WORKLOAD2=1 or LATTICE_ENABLE_WORKLOAD2=true to enable
            skip_workload2: !matches!(
                std::env::var("LATTICE_ENABLE_WORKLOAD2")
                    .unwrap_or_default()
                    .to_lowercase()
                    .as_str(),
                "1" | "true" | "yes"
            ),
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

    /// Create config with workload2 enabled (full 3-cluster hierarchy)
    pub fn with_workload2(mut self) -> Self {
        self.skip_workload2 = false;
        self
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
    /// Proxy session to mgmt cluster (all child access routes through mgmt's proxy)
    pub mgmt_proxy: Option<ProxySession>,
}

impl SetupResult {
    /// Stop chaos monkey if running
    pub async fn stop_chaos(&mut self) {
        if let Some(chaos) = self.chaos.take() {
            chaos.stop().await;
        }
    }

    /// Restart chaos monkey (if targets are available)
    pub fn restart_chaos(&mut self) {
        if self.chaos.is_some() {
            return; // Already running
        }
        if let Some(ref targets) = self.chaos_targets {
            self.chaos = Some(ChaosMonkey::start(targets.clone()));
        }
    }

    /// Verify the mgmt proxy session is healthy (watchdog handles restarts automatically)
    pub async fn ensure_proxies_alive(&mut self) -> Result<(), String> {
        if let Some(ref mut proxy) = self.mgmt_proxy {
            proxy.ensure_alive().await?;
        }
        Ok(())
    }

    /// Pause chaos on a specific cluster by removing it from targets.
    /// Use resume_chaos_on_cluster to re-add it later.
    pub fn pause_chaos_on_cluster(&self, cluster_name: &str) {
        if let Some(ref targets) = self.chaos_targets {
            targets.remove(cluster_name);
        }
    }

    /// Resume chaos on a specific cluster by adding it back to targets.
    pub fn resume_chaos_on_cluster(
        &self,
        cluster_name: &str,
        kubeconfig: &str,
        parent_kubeconfig: Option<&str>,
    ) {
        if let Some(ref targets) = self.chaos_targets {
            targets.add(cluster_name, kubeconfig, parent_kubeconfig);
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
    let _ = run_cmd("kind", &["delete", "cluster", "--name", &cluster_name]);
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
        if let Ok(clusters) = run_cmd("kind", &["get", "clusters"]) {
            for cluster in clusters.lines() {
                let cluster = cluster.trim();
                if cluster.starts_with("lattice-bootstrap-") {
                    info!("Deleting orphaned bootstrap cluster: {}", cluster);
                    let _ = run_cmd("kind", &["delete", "cluster", "--name", cluster]);
                }
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

    let (workload2_cluster, workload2_bootstrap) = if config.skip_workload2 {
        (None, None)
    } else {
        let (_, cluster) =
            load_cluster_config("LATTICE_WORKLOAD2_CLUSTER_CONFIG", "docker-workload2.yaml")?;
        let bootstrap = cluster.spec.provider.kubernetes.bootstrap.clone();
        (Some(cluster), Some(bootstrap))
    };

    info!("[Setup] Configuration:");
    info!("  Management:  {} + {:?}", mgmt_provider, mgmt_bootstrap);
    info!(
        "  Workload:    {} + {:?}",
        workload_provider, workload_bootstrap
    );
    if !config.skip_workload2 {
        info!(
            "  Workload2:   {} + {:?}",
            workload_provider, workload2_bootstrap
        );
    } else {
        info!("  Workload2:   SKIPPED (set LATTICE_ENABLE_WORKLOAD2=1 to enable)");
    }

    // Setup Docker network if needed
    if mgmt_provider == InfraProvider::Docker {
        ensure_docker_network().map_err(|e| format!("Failed to setup Docker network: {}", e))?;
    }

    // Start chaos monkey if configured (uses provider-appropriate intervals)
    let (chaos, chaos_targets) = if config.enable_chaos {
        let targets = Arc::new(ChaosTargets::new(super::super::helpers::run_id()));
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
    capi::verify_capi_resources(&ctx, MGMT_CLUSTER_NAME, ClusterLevel::Mgmt).await?;

    info!("[Setup] Waiting for management LatticeCluster to be Ready...");
    watch_cluster_phases(&mgmt_client, MGMT_CLUSTER_NAME, None).await?;

    info!("[Setup] SUCCESS: Management cluster is self-managing!");

    // Add mgmt to chaos targets - tests agent connections during workload provisioning
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

    // Watch for Ready state, then set up proxy access
    watch_cluster_phases(&mgmt_client, WORKLOAD_CLUSTER_NAME, None).await?;

    info!("[Setup] SUCCESS: Workload cluster is Ready!");

    // =========================================================================
    // Phase 4: Set up proxy access to workload cluster
    // =========================================================================
    // All providers use proxy for workload cluster access.
    // Remove mgmt from chaos - port-forward needs stability for the rest of setup.
    // mgmt stays out of chaos until deletion phase.
    info!("[Setup/Phase 4] Setting up proxy access to workload cluster...");

    if let Some(ref targets) = chaos_targets {
        info!("[Setup] Removing mgmt from chaos (port-forward needs stability)...");
        targets.remove(MGMT_CLUSTER_NAME);
    }

    wait_for_operator_ready(MGMT_CLUSTER_NAME, &mgmt_kubeconfig_path, Some(120)).await?;
    cedar::apply_e2e_default_policy(&mgmt_kubeconfig_path).await?;

    let mgmt_proxy = ProxySession::start_for_provider(&mgmt_kubeconfig_path, mgmt_provider).await?;
    let workload_proxy_kc = mgmt_proxy.kubeconfig_for(WORKLOAD_CLUSTER_NAME).await?;

    info!(
        "[Setup] Workload kubeconfig (via proxy): {}",
        workload_proxy_kc
    );

    let ctx = ctx.with_workload(workload_proxy_kc.clone());

    // =========================================================================
    // Phase 4.5: Verify Workload Cluster
    // =========================================================================
    info!("[Setup/Phase 4.5] Verifying workload cluster...");

    capi::verify_capi_resources(&ctx, WORKLOAD_CLUSTER_NAME, ClusterLevel::Workload).await?;

    info!("[Setup] SUCCESS: Workload cluster pivot verified!");

    // Add workload to chaos targets (mgmt stays out - port-forward stability)
    if let Some(ref targets) = chaos_targets {
        targets.add(
            WORKLOAD_CLUSTER_NAME,
            &workload_proxy_kc,
            Some(&mgmt_kubeconfig_path),
        );
    }

    // =========================================================================
    // Phase 5: Create Workload2 Cluster (parallel with workload worker join)
    // =========================================================================
    let ctx = if let Some(workload2_cluster) = workload2_cluster {
        info!("[Setup/Phase 5] Creating workload2 cluster (deep hierarchy)...");

        let workload_client = client_from_kubeconfig(&workload_proxy_kc).await?;
        let workload_api: Api<LatticeCluster> = Api::all(workload_client.clone());

        workload_api
            .create(&PostParams::default(), &workload2_cluster)
            .await
            .map_err(|e| format!("Failed to create workload2: {}", e))?;

        info!("[Setup] Workload2 LatticeCluster created, waiting for Ready (workers joining in parallel)...");

        // Run workload worker verification in parallel with workload2 provisioning
        let (worker_result, phase_result) = tokio::join!(
            scaling::verify_cluster_workers(&ctx, WORKLOAD_CLUSTER_NAME, 1, ClusterLevel::Workload),
            watch_cluster_phases(&workload_client, WORKLOAD2_CLUSTER_NAME, None)
        );
        worker_result?;
        phase_result?;

        info!("[Setup] SUCCESS: Workload2 cluster is Ready!");

        // =========================================================================
        // Phase 6: Set up proxy access to workload2 and verify
        // =========================================================================
        // mgmt is already out of chaos (removed in Phase 4), workload chaos continues
        info!("[Setup/Phase 6] Setting up proxy access to workload2...");

        // Wait for workload operator to be ready (so workload2's agent can connect)
        wait_for_operator_ready(WORKLOAD_CLUSTER_NAME, &workload_proxy_kc, Some(120)).await?;

        // Apply Cedar policy on workload to allow proxy access to workload2
        cedar::apply_e2e_default_policy(&workload_proxy_kc).await?;

        // Get workload2 kubeconfig from mgmt proxy - it sees workload2 in its subtree
        // The route is: mgmt proxy -> workload agent -> workload proxy -> workload2 agent
        let workload2_proxy_kc = mgmt_proxy.kubeconfig_for(WORKLOAD2_CLUSTER_NAME).await?;

        info!(
            "[Setup] Workload2 kubeconfig (via proxy): {}",
            workload2_proxy_kc
        );

        let ctx = ctx.with_workload2(workload2_proxy_kc.clone());

        info!("[Setup/Phase 6.5] Verifying workload2 cluster...");
        capi::verify_capi_resources(&ctx, WORKLOAD2_CLUSTER_NAME, ClusterLevel::Workload2).await?;

        info!("[Setup] SUCCESS: Workload2 cluster verified!");

        // Add workload2 to chaos targets
        if let Some(ref targets) = chaos_targets {
            targets.add(
                WORKLOAD2_CLUSTER_NAME,
                &workload2_proxy_kc,
                Some(&workload_proxy_kc),
            );
        }

        ctx
    } else {
        info!("[Setup/Phase 5] Skipping workload2 cluster (disabled)");

        // Just verify workload workers without parallel workload2 provisioning
        scaling::verify_cluster_workers(&ctx, WORKLOAD_CLUSTER_NAME, 1, ClusterLevel::Workload)
            .await?;

        ctx
    };

    // =========================================================================
    // Phase 7: Finalize Context with Proxy URL
    // =========================================================================
    info!("[Setup/Phase 7] Finalizing context...");

    let final_ctx = InfraContext::new(
        mgmt_kubeconfig_path.clone(),
        ctx.workload_kubeconfig.clone(),
        ctx.workload2_kubeconfig.clone(),
        mgmt_provider,
    )
    .with_mgmt_proxy_url(mgmt_proxy.url.clone());

    // =========================================================================
    // Setup Complete - Print copy-pasteable output
    // =========================================================================
    println!();
    println!("========================================");
    println!("INFRASTRUCTURE SETUP COMPLETE");
    println!("========================================");
    println!();
    if final_ctx.has_workload2() {
        println!("Cluster hierarchy: mgmt -> workload -> workload2");
    } else {
        println!("Cluster hierarchy: mgmt -> workload");
    }
    println!();
    println!("Kubeconfig paths (proxy-based for child clusters):");
    println!("  LATTICE_MGMT_KUBECONFIG={}", final_ctx.mgmt_kubeconfig);
    if let Some(ref wk) = final_ctx.workload_kubeconfig {
        println!("  LATTICE_WORKLOAD_KUBECONFIG={}", wk);
    }
    if let Some(ref w2k) = final_ctx.workload2_kubeconfig {
        println!("  LATTICE_WORKLOAD2_KUBECONFIG={}", w2k);
    }
    println!();
    println!("Run integration tests with:");
    println!("  LATTICE_MGMT_KUBECONFIG={} \\", final_ctx.mgmt_kubeconfig);
    if let Some(ref wk) = final_ctx.workload_kubeconfig {
        println!("  LATTICE_WORKLOAD_KUBECONFIG={} \\", wk);
    }
    if let Some(ref w2k) = final_ctx.workload2_kubeconfig {
        println!("  LATTICE_WORKLOAD2_KUBECONFIG={} \\", w2k);
    }
    println!(
        "  cargo test --features provider-e2e --test e2e <test_name> -- --ignored --nocapture"
    );
    println!();

    Ok(SetupResult {
        ctx: final_ctx,
        chaos,
        chaos_targets,
        mgmt_proxy: Some(mgmt_proxy),
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
        let targets = Arc::new(ChaosTargets::new(super::super::helpers::run_id()));
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
    capi::verify_capi_resources(&ctx, MGMT_CLUSTER_NAME, ClusterLevel::Mgmt).await?;
    watch_cluster_phases(&mgmt_client, MGMT_CLUSTER_NAME, None).await?;

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
    })
}

/// Set up management + single workload cluster
pub async fn setup_mgmt_and_workload(config: &SetupConfig) -> Result<SetupResult, String> {
    // Start with mgmt setup
    let mut result = setup_mgmt_only(config).await?;

    let (_, workload_cluster) =
        load_cluster_config("LATTICE_WORKLOAD_CLUSTER_CONFIG", "docker-workload.yaml")?;

    info!("[Setup] Creating workload cluster...");

    let mgmt_client = client_from_kubeconfig(&result.ctx.mgmt_kubeconfig).await?;
    let api: Api<LatticeCluster> = Api::all(mgmt_client.clone());

    api.create(&PostParams::default(), &workload_cluster)
        .await
        .map_err(|e| format!("Failed to create workload LatticeCluster: {}", e))?;

    // Watch for Ready state
    watch_cluster_phases(&mgmt_client, WORKLOAD_CLUSTER_NAME, None).await?;

    // Set up proxy access to workload cluster (all providers use proxy)
    info!("[Setup] Setting up proxy access to workload...");
    wait_for_operator_ready(MGMT_CLUSTER_NAME, &result.ctx.mgmt_kubeconfig, Some(120)).await?;
    cedar::apply_e2e_default_policy(&result.ctx.mgmt_kubeconfig).await?;
    let mgmt_proxy =
        ProxySession::start_for_provider(&result.ctx.mgmt_kubeconfig, result.ctx.provider).await?;
    let workload_proxy_kc = mgmt_proxy.kubeconfig_for(WORKLOAD_CLUSTER_NAME).await?;

    // Update context with proxy kubeconfig
    result.ctx = result.ctx.with_workload(workload_proxy_kc.clone());

    // Verify cluster is operational
    capi::verify_capi_resources(&result.ctx, WORKLOAD_CLUSTER_NAME, ClusterLevel::Workload).await?;
    scaling::verify_cluster_workers(
        &result.ctx,
        WORKLOAD_CLUSTER_NAME,
        1,
        ClusterLevel::Workload,
    )
    .await?;

    // Add to chaos targets
    if let Some(ref targets) = result.chaos_targets {
        targets.add(
            WORKLOAD_CLUSTER_NAME,
            &workload_proxy_kc,
            Some(&result.ctx.mgmt_kubeconfig),
        );
    }

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
/// Standalone test - rebuild and restart operators on all clusters
///
/// Uses TestSession for consistent test initialization.
/// After rebuild, port-forwards are automatically restarted since the
/// operator pods (which include lattice-cell) are replaced.
#[tokio::test]
#[ignore]
async fn test_rebuild_operators() {
    use super::super::context::TestSession;

    let mut session = TestSession::from_env("Set LATTICE_MGMT_KUBECONFIG to rebuild operators")
        .await
        .unwrap();

    info!("========================================");
    info!("REBUILD AND RESTART OPERATORS");
    info!("========================================");

    let kubeconfigs = session.ctx.all_kubeconfigs();
    info!("Found {} cluster(s):", kubeconfigs.len());
    for (name, path) in &kubeconfigs {
        info!("  {}: {}", name, path);
    }

    session
        .rebuild_operators(DEFAULT_LATTICE_IMAGE)
        .await
        .unwrap();

    info!("");
    info!("========================================");
    info!("OPERATORS REBUILT AND RESTARTED");
    info!("========================================");
    info!("Port-forwards have been automatically restarted.");
}
