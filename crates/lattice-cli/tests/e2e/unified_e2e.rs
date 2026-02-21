//! Unified E2E test for Lattice: full lifecycle with all integration tests
//!
//! This test validates the complete Lattice lifecycle by running ALL integration
//! tests in sequence against a 2-cluster hierarchy (mgmt -> workload). Use this
//! when you want comprehensive coverage in a single run.
//!
//! For the 3-cluster hierarchy (workload2), see `workload2_e2e.rs`.
//! For isolated, per-integration E2E tests, see the individual `*_e2e.rs` files.
//!
//! # Phases
//!
//! 1. Set up cluster hierarchy (mgmt -> workload)
//! 2. Kubeconfig + proxy verification
//! 3. Cedar cluster-access policy enforcement
//! 4. Mesh + secrets + Cedar secret + autoscaling tests (parallel)
//! 5. Workload deletion (unpivot to mgmt)
//! 6. Management cluster uninstall
//!
//! # Running
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_configurable_provider_pivot -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tracing::info;

use super::context::init_e2e_test;
use super::helpers::{
    run_id, teardown_mgmt_cluster, TestHarness, MGMT_CLUSTER_NAME, WORKLOAD2_CLUSTER_NAME,
    WORKLOAD_CLUSTER_NAME,
};
use super::integration::{self, setup};
use super::providers::InfraProvider;

const E2E_TIMEOUT: Duration = Duration::from_secs(3600);

#[tokio::test]
async fn test_configurable_provider_pivot() {
    init_e2e_test();
    info!("Starting E2E test: Full Lifecycle");

    let result = tokio::time::timeout(E2E_TIMEOUT, run_full_e2e()).await;

    match result {
        Ok(Ok(())) => {
            info!("TEST PASSED");
        }
        Ok(Err(e)) => {
            setup::cleanup_bootstrap_cluster(run_id()).await;
            panic!("E2E test failed: {} (manual cleanup may be required)", e);
        }
        Err(_) => {
            setup::cleanup_bootstrap_cluster(run_id()).await;
            panic!(
                "E2E test timed out after {:?} (manual cleanup required)",
                E2E_TIMEOUT
            );
        }
    }
}

async fn run_full_e2e() -> Result<(), String> {
    // =========================================================================
    // Phase 1-6: Set up full hierarchy using integration module
    // =========================================================================
    // Allow disabling chaos via environment variable for debugging
    let config = if std::env::var("LATTICE_DISABLE_CHAOS").is_ok() {
        info!("[E2E] Chaos monkey disabled via LATTICE_DISABLE_CHAOS");
        setup::SetupConfig::default()
    } else {
        setup::SetupConfig::with_chaos()
    };
    let mut setup_result = integration::setup::setup_full_hierarchy(&config).await?;
    let ctx = setup_result.ctx.clone();

    // Chaos continues running from setup (paused/resumed per-cluster as needed).
    // Ensure port-forwards are alive before continuing.
    setup_result.ensure_proxies_alive().await?;

    // =========================================================================
    // Phase 6.5: Verify kubeconfig patching + test proxy access
    // =========================================================================
    info!("[Phase 6.5] Verifying kubeconfig patching and proxy access...");

    // Verify kubeconfigs are patched for proxy
    integration::kubeconfig::run_kubeconfig_verification(&ctx, WORKLOAD_CLUSTER_NAME, None).await?;

    // Test proxy access through the hierarchy
    integration::proxy::run_proxy_tests(&ctx, WORKLOAD_CLUSTER_NAME, None).await?;

    info!("SUCCESS: Kubeconfig and proxy verification complete!");

    // =========================================================================
    // Phase 6.6: Test Cedar policy enforcement for proxy access
    // =========================================================================
    // Pause chaos on mgmt cluster only - we want to test resilience to workload
    // operator restarts. The retry logic should handle "cluster not found" errors
    // when the agent temporarily disconnects.
    setup_result.pause_chaos_on_cluster(MGMT_CLUSTER_NAME);
    info!("[Phase 6.6] Testing Cedar policy enforcement (chaos paused on mgmt)...");

    // Test Cedar policies for access from mgmt -> workload
    integration::cedar::run_cedar_hierarchy_tests(&ctx, WORKLOAD_CLUSTER_NAME).await?;

    info!("SUCCESS: Cedar policy enforcement verified!");

    // =========================================================================
    // Phase 7: Run mesh + secrets + Cedar secret + autoscaling tests (pool)
    // =========================================================================
    info!("[Phase 7] Running mesh/secrets/cedar/autoscaling tests (pool=3)...");

    // Limit concurrent proxy load — at most 3 tasks run simultaneously
    // (some tasks may spawn internal concurrency, e.g. secrets runs up to 3 sub-tests)
    let pool = Arc::new(Semaphore::new(3));
    let mut handles: Vec<(&str, tokio::task::JoinHandle<Result<(), String>>)> = Vec::new();

    // Mesh: fixed test
    if integration::mesh::mesh_tests_enabled() {
        let kc = ctx.require_workload()?.to_string();
        let sem = pool.clone();
        handles.push((
            "Fixed mesh",
            tokio::spawn(async move {
                let _permit = sem.acquire().await.map_err(|e| e.to_string())?;
                super::mesh_tests::run_mesh_test(&kc).await
            }),
        ));
    }

    // Mesh: random test
    if integration::mesh::mesh_tests_enabled() {
        let kc = ctx.require_workload()?.to_string();
        let sem = pool.clone();
        handles.push((
            "Random mesh",
            tokio::spawn(async move {
                let _permit = sem.acquire().await.map_err(|e| e.to_string())?;
                super::mesh_random::run_random_mesh_test(&kc).await
            }),
        ));
    }

    // Mesh: media server test (Docker only)
    if integration::mesh::mesh_tests_enabled() && ctx.provider == InfraProvider::Docker {
        let kc = ctx.require_workload()?.to_string();
        let sem = pool.clone();
        handles.push((
            "Media server",
            tokio::spawn(async move {
                let _permit = sem.acquire().await.map_err(|e| e.to_string())?;
                super::media_server_e2e::run_media_server_test(&kc).await
            }),
        ));
    }

    // Secrets tests
    {
        let ctx2 = ctx.clone();
        let sem = pool.clone();
        handles.push((
            "Secrets",
            tokio::spawn(async move {
                let _permit = sem.acquire().await.map_err(|e| e.to_string())?;
                integration::secrets::run_secrets_tests(&ctx2).await
            }),
        ));
    }

    // Cedar secret authorization tests
    {
        let ctx2 = ctx.clone();
        let sem = pool.clone();
        handles.push((
            "Cedar secrets",
            tokio::spawn(async move {
                let _permit = sem.acquire().await.map_err(|e| e.to_string())?;
                integration::cedar_secrets::run_cedar_secret_tests(&ctx2).await
            }),
        ));
    }

    // Tetragon runtime enforcement
    {
        let ctx2 = ctx.clone();
        let sem = pool.clone();
        handles.push((
            "Tetragon",
            tokio::spawn(async move {
                let _permit = sem.acquire().await.map_err(|e| e.to_string())?;
                integration::tetragon::run_tetragon_tests(&ctx2).await
            }),
        ));
    }

    // Autoscaling: KEDA pod scale-up
    {
        let ctx2 = ctx.clone();
        let sem = pool.clone();
        handles.push((
            "Autoscaling",
            tokio::spawn(async move {
                let _permit = sem.acquire().await.map_err(|e| e.to_string())?;
                integration::autoscaling::run_autoscaling_tests(&ctx2).await
            }),
        ));
    }

    // Job: Volcano gang scheduling
    {
        let ctx2 = ctx.clone();
        let sem = pool.clone();
        handles.push((
            "Job",
            tokio::spawn(async move {
                let _permit = sem.acquire().await.map_err(|e| e.to_string())?;
                integration::job::run_job_tests(&ctx2).await
            }),
        ));
    }

    // Workload2 deletion (if exists) — pause chaos first to avoid log spam
    if ctx.has_workload2() {
        setup_result.pause_chaos_on_cluster(WORKLOAD2_CLUSTER_NAME);
        let child_kc = ctx.require_workload2()?.to_string();
        let parent_kc = ctx.require_workload()?.to_string();
        let provider = ctx.provider;
        let sem = pool.clone();
        handles.push((
            "Workload2 deletion",
            tokio::spawn(async move {
                let _permit = sem.acquire().await.map_err(|e| e.to_string())?;
                integration::pivot::delete_and_verify_unpivot(
                    &child_kc,
                    &parent_kc,
                    WORKLOAD2_CLUSTER_NAME,
                    provider,
                )
                .await
            }),
        ));
    }

    // Wait for all tasks and collect results
    let harness = TestHarness::new("E2E Phase 7");
    for (name, handle) in handles {
        let start = std::time::Instant::now();
        let result = handle.await;
        let duration = start.elapsed();
        match result {
            Ok(Ok(())) => harness.record(name, true, duration, None),
            Ok(Err(e)) => harness.record(name, false, duration, Some(e)),
            Err(e) => harness.record(name, false, duration, Some(format!("PANIC: {e}"))),
        }
    }
    harness.finish()?;

    // =========================================================================
    // Phase 8: Delete workload (unpivot to mgmt)
    // =========================================================================
    // Resume chaos on mgmt cluster for deletion/unpivot testing
    setup_result.resume_chaos_on_cluster(MGMT_CLUSTER_NAME, &ctx.mgmt_kubeconfig, None);
    setup_result.restart_chaos();

    info!("[Phase 8] Deleting workload cluster (unpivot to mgmt)...");

    // Pause chaos on workload cluster BEFORE deletion to avoid log spam from
    // chaos trying to apply jobs to a cluster that no longer exists.
    setup_result.pause_chaos_on_cluster(WORKLOAD_CLUSTER_NAME);

    integration::pivot::delete_and_verify_unpivot(
        ctx.require_workload()?,
        &ctx.mgmt_kubeconfig,
        WORKLOAD_CLUSTER_NAME,
        ctx.provider,
    )
    .await?;

    info!("SUCCESS: Workload deleted and unpivoted!");

    // =========================================================================
    // Phase 9: Uninstall management cluster
    // =========================================================================
    // Stop chaos entirely before teardown to avoid retries against disappearing clusters
    setup_result.stop_chaos().await;
    info!("[Phase 9] Uninstalling management cluster...");

    teardown_mgmt_cluster(&ctx.mgmt_kubeconfig, MGMT_CLUSTER_NAME).await?;

    info!("E2E test complete: full lifecycle verified");

    Ok(())
}
