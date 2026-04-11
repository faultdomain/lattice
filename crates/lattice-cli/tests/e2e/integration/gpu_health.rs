//! GPU health monitoring integration tests
//!
//! Tests the operator's end-to-end response to GPU health annotations on real
//! nodes. No real GPUs are needed — tests patch node annotations directly and
//! verify that the operator's `reconcile_gpu_health` path cordons and
//! uncordons nodes correctly.
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_gpu_health_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use chrono::Utc;
use tracing::info;

use lattice_common::gpu::{
    ANNOTATION_GPU_HEALTH, ANNOTATION_GPU_LOSS, ANNOTATION_HEARTBEAT, HEARTBEAT_STALENESS_SECS,
};

use super::super::helpers::{
    run_kubectl, wait_for_condition, with_diagnostics, DiagnosticContext, POLL_INTERVAL,
};

// =============================================================================
// Helpers
// =============================================================================

/// Find the first non-control-plane worker node. Returns `None` if no workers exist.
async fn get_first_worker_node(kubeconfig: &str) -> Result<Option<String>, String> {
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "nodes",
        "-l",
        "!node-role.kubernetes.io/control-plane",
        "-o",
        "jsonpath={.items[0].metadata.name}",
    ])
    .await?;

    let name = output.trim().to_string();
    if name.is_empty() {
        Ok(None)
    } else {
        Ok(Some(name))
    }
}

/// Patch GPU-related annotations on a node (overwrite existing).
async fn patch_gpu_annotations(
    kubeconfig: &str,
    node: &str,
    annotations: &[(&str, &str)],
) -> Result<(), String> {
    let mut args = vec![
        "--kubeconfig",
        kubeconfig,
        "annotate",
        "node",
        node,
        "--overwrite",
    ];
    let formatted: Vec<String> = annotations
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let refs: Vec<&str> = formatted.iter().map(|s| s.as_str()).collect();
    args.extend_from_slice(&refs);

    run_kubectl(&args).await?;
    Ok(())
}

/// Patch fake GPU capacity onto a node's `status.allocatable` so the operator
/// recognises it as a GPU node. Uses the status subresource via strategic merge
/// patch.
async fn add_fake_gpu_capacity(kubeconfig: &str, node: &str) -> Result<(), String> {
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "patch",
        "node",
        node,
        "--subresource=status",
        "--type=merge",
        "-p",
        r#"{"status":{"allocatable":{"nvidia.com/gpu":"8"},"capacity":{"nvidia.com/gpu":"8"}}}"#,
    ])
    .await?;
    Ok(())
}

/// Remove fake GPU capacity from a node's `status.allocatable` and
/// `status.capacity`. Uses a JSON patch to delete the keys.
async fn remove_fake_gpu_capacity(kubeconfig: &str, node: &str) -> Result<(), String> {
    // JSON patch to remove the nvidia.com/gpu keys. The ~1 is the JSON Pointer
    // encoding of `/`.
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "patch",
        "node",
        node,
        "--subresource=status",
        "--type=json",
        "-p",
        r#"[{"op":"remove","path":"/status/allocatable/nvidia.com~1gpu"},{"op":"remove","path":"/status/capacity/nvidia.com~1gpu"}]"#,
    ])
    .await;
    Ok(())
}

/// Remove all `lattice.dev/gpu-*` annotations from a node.
async fn clear_gpu_annotations(kubeconfig: &str, node: &str) -> Result<(), String> {
    let keys = [
        ANNOTATION_GPU_HEALTH,
        ANNOTATION_GPU_LOSS,
        ANNOTATION_HEARTBEAT,
        lattice_common::gpu::ANNOTATION_ANOMALY_SCORE,
    ];

    let mut args = vec![
        "--kubeconfig".to_string(),
        kubeconfig.to_string(),
        "annotate".to_string(),
        "node".to_string(),
        node.to_string(),
    ];
    for key in &keys {
        args.push(format!("{key}-"));
    }
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    // Ignore errors — some annotations may not exist.
    let _ = run_kubectl(&refs).await;
    Ok(())
}

/// Check whether `spec.unschedulable` is true on a node.
async fn is_node_cordoned(kubeconfig: &str, node: &str) -> Result<bool, String> {
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "node",
        node,
        "-o",
        "jsonpath={.spec.unschedulable}",
    ])
    .await?;

    Ok(output.trim() == "true")
}

/// Poll until a node reaches the expected cordon state or timeout expires.
async fn wait_for_cordon(
    kubeconfig: &str,
    node: &str,
    expected_cordoned: bool,
    timeout: Duration,
) -> Result<(), String> {
    let desc = if expected_cordoned {
        format!("node {node} to become cordoned")
    } else {
        format!("node {node} to become schedulable")
    };
    let kc = kubeconfig.to_string();
    let n = node.to_string();

    wait_for_condition(&desc, timeout, POLL_INTERVAL, || {
        let kc = kc.clone();
        let n = n.clone();
        async move {
            let cordoned = is_node_cordoned(&kc, &n).await?;
            Ok(cordoned == expected_cordoned)
        }
    })
    .await
}

/// Uncordon a node.
async fn uncordon_node(kubeconfig: &str, node: &str) -> Result<(), String> {
    run_kubectl(&["--kubeconfig", kubeconfig, "uncordon", node]).await?;
    Ok(())
}

/// Fresh RFC 3339 timestamp for "now".
fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

/// RFC 3339 timestamp for N seconds ago.
fn seconds_ago_rfc3339(secs: i64) -> String {
    (Utc::now() - chrono::Duration::seconds(secs)).to_rfc3339()
}

/// Ensure node is clean and schedulable before / after each test case.
async fn reset_node(kubeconfig: &str, node: &str) -> Result<(), String> {
    clear_gpu_annotations(kubeconfig, node).await?;
    uncordon_node(kubeconfig, node).await?;
    Ok(())
}

const RECONCILE_TIMEOUT: Duration = super::super::helpers::DEFAULT_TIMEOUT;

// =============================================================================
// Test cases
// =============================================================================

/// Test 1: Normal annotations with a fresh heartbeat do not cordon the node.
async fn test_normal_no_cordon(kubeconfig: &str, node: &str) -> Result<(), String> {
    info!("[Integration/GPUHealth] Test: normal annotations → no cordon");

    patch_gpu_annotations(
        kubeconfig,
        node,
        &[
            (ANNOTATION_GPU_HEALTH, "normal"),
            (ANNOTATION_HEARTBEAT, &now_rfc3339()),
        ],
    )
    .await?;

    // Verify the node stays schedulable across multiple checks (operator should not cordon it).
    let kc = kubeconfig.to_string();
    let n = node.to_string();
    let checks = 6; // 6 checks x 5s = 30s of stability verification
    for i in 1..=checks {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let cordoned = is_node_cordoned(&kc, &n).await?;
        if cordoned {
            return Err(format!(
                "Node was cordoned despite normal GPU health (detected on check {i}/{checks})"
            ));
        }
    }

    info!("[Integration/GPUHealth] PASSED: normal annotations → node stayed schedulable");
    Ok(())
}

/// Test 2: Warning/unhealthy health triggers cordon.
async fn test_unhealthy_triggers_cordon(kubeconfig: &str, node: &str) -> Result<(), String> {
    info!("[Integration/GPUHealth] Test: unhealthy annotation → cordon");

    patch_gpu_annotations(
        kubeconfig,
        node,
        &[
            (ANNOTATION_GPU_HEALTH, "warning"),
            (ANNOTATION_HEARTBEAT, &now_rfc3339()),
        ],
    )
    .await?;

    wait_for_cordon(kubeconfig, node, true, RECONCILE_TIMEOUT).await?;

    info!("[Integration/GPUHealth] PASSED: warning health → node cordoned");
    Ok(())
}

/// Test 3: GPU loss flapping — operator cordons on loss and uncordons on recovery.
///
/// Simulates: loss → verify cordon → recovery → verify uncordon.
async fn test_gpu_loss_flap(kubeconfig: &str, node: &str) -> Result<(), String> {
    info!("[Integration/GPUHealth] Test: GPU loss flap — cordon on loss, uncordon on recovery");

    let now = now_rfc3339();
    patch_gpu_annotations(
        kubeconfig,
        node,
        &[
            (ANNOTATION_GPU_HEALTH, "unhealthy"),
            (ANNOTATION_GPU_LOSS, "true"),
            (ANNOTATION_HEARTBEAT, &now),
        ],
    )
    .await?;

    wait_for_cordon(kubeconfig, node, true, RECONCILE_TIMEOUT).await?;
    info!("[Integration/GPUHealth] Loss detected, node cordoned");

    // Recovery: GPUs come back — set health back to normal and clear loss.
    patch_gpu_annotations(
        kubeconfig,
        node,
        &[
            (ANNOTATION_GPU_HEALTH, "normal"),
            (ANNOTATION_GPU_LOSS, "false"),
            (ANNOTATION_HEARTBEAT, &now_rfc3339()),
        ],
    )
    .await?;

    wait_for_cordon(kubeconfig, node, false, RECONCILE_TIMEOUT).await?;
    info!("[Integration/GPUHealth] PASSED: GPU loss flap — cordon on loss, uncordon on recovery");
    Ok(())
}

/// Test 5: Stale heartbeat — unhealthy annotation is ignored.
async fn test_stale_heartbeat_ignored(kubeconfig: &str, node: &str) -> Result<(), String> {
    info!("[Integration/GPUHealth] Test: stale heartbeat → no cordon");

    let stale = seconds_ago_rfc3339(HEARTBEAT_STALENESS_SECS + 60);
    patch_gpu_annotations(
        kubeconfig,
        node,
        &[
            (ANNOTATION_GPU_HEALTH, "unhealthy"),
            (ANNOTATION_HEARTBEAT, &stale),
        ],
    )
    .await?;

    // Verify the node stays schedulable across multiple checks (operator should ignore stale data).
    let kc = kubeconfig.to_string();
    let n = node.to_string();
    let checks = 6; // 6 checks x 5s = 30s of stability verification
    for i in 1..=checks {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let cordoned = is_node_cordoned(&kc, &n).await?;
        if cordoned {
            return Err(format!(
                "Node was cordoned despite stale heartbeat — operator should ignore stale data \
                 (detected on check {i}/{checks})"
            ));
        }
    }

    info!("[Integration/GPUHealth] PASSED: stale heartbeat → node stayed schedulable");
    Ok(())
}

// =============================================================================
// Public entry point
// =============================================================================

/// Run all GPU health integration tests against a cluster.
pub async fn run_gpu_health_tests(kubeconfig: &str) -> Result<(), String> {
    info!("\n========================================");
    info!("GPU Health Monitoring Tests");
    info!("========================================\n");

    let diag = DiagnosticContext::new(kubeconfig, lattice_core::LATTICE_SYSTEM_NAMESPACE);
    with_diagnostics(&diag, "GPU Health", || async {
        let node = match get_first_worker_node(kubeconfig).await? {
            Some(n) => n,
            None => {
                info!("[Integration/GPUHealth] No worker nodes found — skipping GPU health tests");
                return Ok(());
            }
        };
        info!("[Integration/GPUHealth] Using worker node: {node}");

        reset_node(kubeconfig, &node).await?;
        add_fake_gpu_capacity(kubeconfig, &node).await?;

        let result = async {
            test_normal_no_cordon(kubeconfig, &node).await?;

            reset_node(kubeconfig, &node).await?;
            test_unhealthy_triggers_cordon(kubeconfig, &node).await?;

            reset_node(kubeconfig, &node).await?;
            test_gpu_loss_flap(kubeconfig, &node).await?;

            reset_node(kubeconfig, &node).await?;
            test_stale_heartbeat_ignored(kubeconfig, &node).await
        }
        .await;

        reset_node(kubeconfig, &node).await?;
        remove_fake_gpu_capacity(kubeconfig, &node).await?;

        result?;

        info!("\n========================================");
        info!("GPU Health Monitoring Tests: PASSED");
        info!("========================================\n");

        Ok(())
    })
    .await
}

// =============================================================================
// Standalone test
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_gpu_health_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_gpu_health_tests(&resolved.kubeconfig).await.unwrap();
}
