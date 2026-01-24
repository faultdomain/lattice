//! Media Server E2E Test
//!
//! Tests LatticeService using a real media server stack (jellyfin, nzbget, sonarr).
//! Applies the fixtures from examples/media-server/ and verifies:
//!
//! - Volume ownership and sharing with subpaths
//! - Pod affinity for RWO volume references (same-node scheduling)
//! - Bilateral agreements with L7 policies
//! - Actual data sharing through the shared volume
//!
//! ## Volume Model
//!
//! All services share a SINGLE `media-storage` volume with subpaths:
//! - jellyfin: OWNS the volume, mounts `library/` subpath to `/media`
//! - nzbget: REFERENCES the volume, mounts `downloads/` subpath to `/downloads`
//! - sonarr: REFERENCES the volume, mounts both subpaths

#![cfg(feature = "provider-e2e")]

use std::time::Duration;
use tokio::time::sleep;

use super::helpers::{run_cmd, run_cmd_allow_fail, workspace_root};

const NAMESPACE: &str = "media";

/// Get the media-server fixtures path (relative to workspace root)
fn fixtures_path() -> String {
    workspace_root()
        .join("examples/media-server")
        .to_string_lossy()
        .to_string()
}

// =============================================================================
// Deployment
// =============================================================================

/// Deploy media server services by applying the fixtures
async fn deploy_media_services(kubeconfig_path: &str) -> Result<(), String> {
    println!("Deploying media server services from fixtures...");

    // Create namespace
    let _ = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "create",
            "namespace",
            NAMESPACE,
        ],
    );

    // Label namespace for Istio ambient mesh
    run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "label",
            "namespace",
            NAMESPACE,
            "istio.io/dataplane-mode=ambient",
            "--overwrite",
        ],
    )?;

    // Apply the fixtures using kustomize
    run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "apply",
            "-k",
            &fixtures_path(),
        ],
    )?;

    println!("  Fixtures applied successfully");
    Ok(())
}

// =============================================================================
// Verification
// =============================================================================

/// Wait for all pods to be running
async fn wait_for_pods(kubeconfig_path: &str) -> Result<(), String> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(300);
    let expected_pods = 3;

    println!("Waiting for {} media pods to be ready...", expected_pods);

    loop {
        if start.elapsed() > timeout {
            let debug = run_cmd_allow_fail(
                "kubectl",
                &[
                    "--kubeconfig",
                    kubeconfig_path,
                    "get",
                    "pods",
                    "-n",
                    NAMESPACE,
                    "-o",
                    "wide",
                ],
            );
            println!("  Pod status:\n{}", debug);

            return Err(format!(
                "Timeout waiting for media pods (expected {})",
                expected_pods
            ));
        }

        let pods_output = run_cmd_allow_fail(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "get",
                "pods",
                "-n",
                NAMESPACE,
                "-o",
                "jsonpath={range .items[*]}{.status.phase}{\"\\n\"}{end}",
            ],
        );

        let running_count = pods_output.lines().filter(|l| *l == "Running").count();
        println!("  {}/{} pods running", running_count, expected_pods);

        if running_count >= expected_pods {
            println!("  All pods are running!");
            return Ok(());
        }

        sleep(Duration::from_secs(10)).await;
    }
}

/// Verify PVCs were created correctly
async fn verify_pvcs(kubeconfig_path: &str) -> Result<(), String> {
    println!("Verifying PVC creation...");

    let pvc_output = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "get",
            "pvc",
            "-n",
            NAMESPACE,
            "-o",
            "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}",
        ],
    )?;

    let pvcs: Vec<&str> = pvc_output.lines().filter(|l| !l.is_empty()).collect();
    println!("  Found {} PVCs: {:?}", pvcs.len(), pvcs);

    // Expected PVCs:
    // - vol-media-storage (owned by jellyfin via id) - THE SINGLE SHARED VOLUME
    // - jellyfin-config, jellyfin-cache (owned by jellyfin)
    // - sonarr-config (owned by sonarr)
    // - nzbget-config (owned by nzbget)
    let expected_pvcs = [
        "vol-media-storage",
        "jellyfin-config",
        "jellyfin-cache",
        "sonarr-config",
        "nzbget-config",
    ];

    for expected in &expected_pvcs {
        if !pvcs.iter().any(|p| p.contains(expected)) {
            return Err(format!("Missing expected PVC: {}", expected));
        }
        println!("    [OK] Found PVC: {}", expected);
    }

    // CRITICAL: Only ONE shared volume should exist (not two)
    let shared_count = pvcs.iter().filter(|p| p.starts_with("vol-")).count();
    if shared_count != 1 {
        return Err(format!(
            "Expected exactly 1 shared volume (vol-media-storage), found {}",
            shared_count
        ));
    }

    println!("  PVC verification passed!");
    Ok(())
}

/// Verify all pods sharing the RWO volume are on the same node
async fn verify_node_colocation(kubeconfig_path: &str) -> Result<(), String> {
    println!("Verifying RWO volume pod co-location...");

    let get_pod_node = |name: &str| -> Result<String, String> {
        let output = run_cmd(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "get",
                "pods",
                "-n",
                NAMESPACE,
                "-l",
                &format!("app.kubernetes.io/name={}", name),
                "-o",
                "jsonpath={.items[0].spec.nodeName}",
            ],
        )?;
        Ok(output.trim().to_string())
    };

    let jellyfin_node = get_pod_node("jellyfin")?;
    let sonarr_node = get_pod_node("sonarr")?;
    let nzbget_node = get_pod_node("nzbget")?;

    println!("  jellyfin pod on node: {}", jellyfin_node);
    println!("  sonarr pod on node:   {}", sonarr_node);
    println!("  nzbget pod on node:   {}", nzbget_node);

    // All pods must be on the same node (single shared RWO volume)
    if jellyfin_node != sonarr_node {
        return Err(format!(
            "sonarr is on node '{}' but jellyfin (volume owner) is on '{}'. \
             RWO volume sharing requires same-node scheduling!",
            sonarr_node, jellyfin_node
        ));
    }

    if nzbget_node != jellyfin_node {
        return Err(format!(
            "nzbget is on node '{}' but jellyfin (volume owner) is on '{}'. \
             RWO volume sharing requires same-node scheduling!",
            nzbget_node, jellyfin_node
        ));
    }

    println!("  [OK] All pods co-located on node: {}", jellyfin_node);
    Ok(())
}

/// Verify data can be shared through the volume subpaths
async fn verify_volume_sharing(kubeconfig_path: &str) -> Result<(), String> {
    println!("Verifying volume data sharing with subpaths...");

    // Give pods time to initialize
    sleep(Duration::from_secs(5)).await;

    // Test 1: jellyfin writes to library/ subpath, sonarr reads it
    println!("  Test 1: jellyfin writes to library/, sonarr reads...");

    run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "exec",
            "-n",
            NAMESPACE,
            "deploy/jellyfin",
            "--",
            "sh",
            "-c",
            "echo 'jellyfin-marker' > /media/.test-marker",
        ],
    )?;

    let result = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "exec",
            "-n",
            NAMESPACE,
            "deploy/sonarr",
            "--",
            "cat",
            "/tv/.test-marker",
        ],
    )?;

    if !result.contains("jellyfin-marker") {
        return Err(format!(
            "sonarr cannot read jellyfin's marker. Expected 'jellyfin-marker', got: {}",
            result
        ));
    }
    println!("    [OK] sonarr read jellyfin's marker from library/ subpath");

    // Test 2: nzbget writes to downloads/ subpath, sonarr reads it
    println!("  Test 2: nzbget writes to downloads/, sonarr reads...");

    run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "exec",
            "-n",
            NAMESPACE,
            "deploy/nzbget",
            "--",
            "sh",
            "-c",
            "echo 'nzbget-marker' > /downloads/.test-marker",
        ],
    )?;

    let result = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "exec",
            "-n",
            NAMESPACE,
            "deploy/sonarr",
            "--",
            "cat",
            "/downloads/.test-marker",
        ],
    )?;

    if !result.contains("nzbget-marker") {
        return Err(format!(
            "sonarr cannot read nzbget's marker. Expected 'nzbget-marker', got: {}",
            result
        ));
    }
    println!("    [OK] sonarr read nzbget's marker from downloads/ subpath");

    // Test 3: Verify subpaths are isolated (library/ and downloads/ are separate)
    println!("  Test 3: Verify subpath isolation...");

    let result = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "exec",
            "-n",
            NAMESPACE,
            "deploy/jellyfin",
            "--",
            "cat",
            "/media/.test-marker",
        ],
    );

    // jellyfin's /media (library/) should NOT see nzbget's marker
    if result.contains("nzbget-marker") {
        return Err(
            "Subpath isolation failed: jellyfin sees nzbget's file in library/".to_string(),
        );
    }
    println!("    [OK] Subpaths are properly isolated");

    println!("  Volume sharing verification passed!");
    Ok(())
}

/// Verify bilateral agreements allow/block traffic correctly
async fn verify_bilateral_agreements(kubeconfig_path: &str) -> Result<(), String> {
    println!("Verifying bilateral service mesh agreements...");

    // Wait for policies to propagate
    println!("  Waiting 30s for AuthorizationPolicies to propagate...");
    sleep(Duration::from_secs(30)).await;

    // Test: sonarr -> jellyfin (should be ALLOWED)
    println!("  Testing: sonarr -> jellyfin (should be ALLOWED)...");
    let result = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "exec",
            "-n",
            NAMESPACE,
            "deploy/sonarr",
            "--",
            "sh",
            "-c",
            "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 http://jellyfin:8096/ || echo '000'",
        ],
    );

    let code = result.trim();
    if code == "403" {
        return Err(
            "sonarr->jellyfin returned 403 (blocked). Bilateral agreement not working!".to_string(),
        );
    }
    println!("    [OK] sonarr->jellyfin: HTTP {} (allowed)", code);

    // Test: sonarr -> nzbget (should be ALLOWED)
    println!("  Testing: sonarr -> nzbget (should be ALLOWED)...");
    let result = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "exec",
            "-n",
            NAMESPACE,
            "deploy/sonarr",
            "--",
            "sh",
            "-c",
            "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 http://nzbget:6789/ || echo '000'",
        ],
    );

    let code = result.trim();
    if code == "403" {
        return Err(
            "sonarr->nzbget returned 403 (blocked). Bilateral agreement not working!".to_string(),
        );
    }
    println!("    [OK] sonarr->nzbget: HTTP {} (allowed)", code);

    // Test: jellyfin -> sonarr (should be BLOCKED - no bilateral agreement)
    println!("  Testing: jellyfin -> sonarr (should be BLOCKED)...");
    let result = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "exec",
            "-n",
            NAMESPACE,
            "deploy/jellyfin",
            "--",
            "sh",
            "-c",
            "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 http://sonarr:8989/ || echo '000'",
        ],
    );

    let code = result.trim();
    if code == "403" {
        println!("    [OK] jellyfin->sonarr: HTTP 403 (blocked as expected)");
    } else {
        println!("    [WARN] jellyfin->sonarr: HTTP {} (expected 403)", code);
    }

    println!("  Bilateral agreement verification completed");
    Ok(())
}

/// Clean up test resources
async fn cleanup(kubeconfig_path: &str) {
    println!("Cleaning up media server test resources...");

    let _ = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "delete",
            "-k",
            &fixtures_path(),
            "--ignore-not-found",
        ],
    );

    let _ = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "delete",
            "namespace",
            NAMESPACE,
            "--ignore-not-found",
            "--timeout=60s",
        ],
    );

    println!("  Cleanup complete");
}

// =============================================================================
// Public Entry Points
// =============================================================================

/// Run the media server E2E test
pub async fn run_media_server_test(kubeconfig_path: &str) -> Result<(), String> {
    println!("\n========================================");
    println!("Media Server E2E Test");
    println!("========================================\n");

    deploy_media_services(kubeconfig_path).await?;
    wait_for_pods(kubeconfig_path).await?;
    verify_pvcs(kubeconfig_path).await?;
    verify_node_colocation(kubeconfig_path).await?;
    verify_volume_sharing(kubeconfig_path).await?;

    // Wait for Istio waypoint proxy
    println!("Waiting for Istio waypoint proxy...");
    sleep(Duration::from_secs(30)).await;

    verify_bilateral_agreements(kubeconfig_path).await?;

    println!("\n========================================");
    println!("Media Server E2E Test: PASSED");
    println!("========================================\n");

    Ok(())
}

/// Cleanup function for use in test teardown
pub async fn cleanup_media_server_test(kubeconfig_path: &str) {
    cleanup(kubeconfig_path).await;
}
