//! GPU health monitoring integration tests
//!
//! Tests the operator's end-to-end response to GPU health annotations on real
//! nodes. No real GPUs are needed — tests patch node annotations directly and
//! verify that the operator's `reconcile_gpu_health` path cordons, drains, and
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
    ANNOTATION_GPU_HEALTH, ANNOTATION_GPU_LOSS, ANNOTATION_GPU_LOSS_AT, ANNOTATION_HEARTBEAT,
    GPU_LOSS_DRAIN_DELAY_SECS, HEARTBEAT_STALENESS_SECS,
};

use super::super::helpers::{apply_yaml, run_kubectl, wait_for_condition};

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

/// Remove all `lattice.dev/gpu-*` annotations from a node.
async fn clear_gpu_annotations(kubeconfig: &str, node: &str) -> Result<(), String> {
    let keys = [
        ANNOTATION_GPU_HEALTH,
        ANNOTATION_GPU_LOSS,
        ANNOTATION_GPU_LOSS_AT,
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

    wait_for_condition(&desc, timeout, Duration::from_secs(5), || {
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

const RECONCILE_TIMEOUT: Duration = Duration::from_secs(120);

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

    // Give the operator two reconcile cycles, then assert still schedulable.
    tokio::time::sleep(Duration::from_secs(30)).await;

    let cordoned = is_node_cordoned(kubeconfig, node).await?;
    if cordoned {
        return Err("Node was cordoned despite normal GPU health".into());
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

/// Test 3: GPU loss with drain delay — cordon immediately, drain after delay.
async fn test_gpu_loss_drain_delay(kubeconfig: &str, node: &str) -> Result<(), String> {
    info!("[Integration/GPUHealth] Test: GPU loss drain delay");

    // Phase A: GPU loss just detected — should cordon but NOT drain yet.
    let now = now_rfc3339();
    patch_gpu_annotations(
        kubeconfig,
        node,
        &[
            (ANNOTATION_GPU_HEALTH, "unhealthy"),
            (ANNOTATION_GPU_LOSS, "true"),
            (ANNOTATION_GPU_LOSS_AT, &now),
            (ANNOTATION_HEARTBEAT, &now),
        ],
    )
    .await?;

    wait_for_cordon(kubeconfig, node, true, RECONCILE_TIMEOUT).await?;
    info!("[Integration/GPUHealth] Phase A: node cordoned (drain delay not yet elapsed)");

    // Phase B: Move gpu-loss-detected-at to >60s ago so drain triggers.
    let past = seconds_ago_rfc3339(GPU_LOSS_DRAIN_DELAY_SECS + 10);
    patch_gpu_annotations(
        kubeconfig,
        node,
        &[
            (ANNOTATION_GPU_LOSS_AT, &past),
            (ANNOTATION_HEARTBEAT, &now_rfc3339()),
        ],
    )
    .await?;

    // Deploy a pod that requests nvidia.com/gpu to verify it gets evicted.
    // The pod will be Pending (no real GPUs), which is fine — drain evicts by
    // pod spec, not pod phase. We use a unique namespace to avoid conflicts.
    let ns = "gpu-health-drain-test";
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "create",
        "namespace",
        ns,
    ])
    .await;

    // Create a pod that is node-selected to our test node requesting GPU.
    let pod_yaml = format!(
        r#"apiVersion: v1
kind: Pod
metadata:
  name: gpu-drain-canary
  namespace: {ns}
spec:
  nodeName: {node}
  terminationGracePeriodSeconds: 0
  containers:
  - name: sleep
    image: busybox:1.36
    command: ["sleep", "3600"]
    resources:
      limits:
        nvidia.com/gpu: "1"
  tolerations:
  - operator: Exists"#
    );

    // Apply the canary pod via stdin-piped kubectl.
    apply_yaml(kubeconfig, &pod_yaml).await?;

    // Wait for the pod to be evicted/deleted (operator drains GPU pods).
    let kc = kubeconfig.to_string();
    let ns_owned = ns.to_string();
    let evicted = wait_for_condition(
        "GPU-requesting pod evicted",
        RECONCILE_TIMEOUT,
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            let ns_owned = ns_owned.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "pod",
                    "gpu-drain-canary",
                    "-n",
                    &ns_owned,
                    "-o",
                    "jsonpath={.status.phase}",
                ])
                .await;
                match output {
                    // Pod gone or in failed/evicted state → drain worked
                    Err(_) => Ok(true),
                    Ok(phase) => Ok(phase.trim() == "Failed" || phase.trim() == "Succeeded"),
                }
            }
        },
    )
    .await;

    // Clean up namespace regardless of result.
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "namespace",
        ns,
        "--ignore-not-found",
    ])
    .await;

    evicted?;

    info!("[Integration/GPUHealth] PASSED: GPU loss → cordon + drain after delay");
    Ok(())
}

/// Test 4: Stale heartbeat — unhealthy annotation is ignored.
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

    // Give the operator two reconcile cycles, then assert still schedulable.
    tokio::time::sleep(Duration::from_secs(30)).await;

    let cordoned = is_node_cordoned(kubeconfig, node).await?;
    if cordoned {
        return Err("Node was cordoned despite stale heartbeat — operator should ignore stale data".into());
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

    let node = match get_first_worker_node(kubeconfig).await? {
        Some(n) => n,
        None => {
            info!("[Integration/GPUHealth] No worker nodes found — skipping GPU health tests");
            return Ok(());
        }
    };
    info!("[Integration/GPUHealth] Using worker node: {node}");

    // Ensure clean state before starting.
    reset_node(kubeconfig, &node).await?;

    // Run each test case sequentially, cleaning up between them.
    // On failure, clean up and return the error.
    let result = async {
        reset_node(kubeconfig, &node).await?;
        test_normal_no_cordon(kubeconfig, &node).await?;

        reset_node(kubeconfig, &node).await?;
        test_unhealthy_triggers_cordon(kubeconfig, &node).await?;

        reset_node(kubeconfig, &node).await?;
        test_gpu_loss_drain_delay(kubeconfig, &node).await?;

        reset_node(kubeconfig, &node).await?;
        test_stale_heartbeat_ignored(kubeconfig, &node).await
    }
    .await;

    // Always clean up, even on failure.
    reset_node(kubeconfig, &node).await?;

    result?;

    info!("\n========================================");
    info!("GPU Health Monitoring Tests: PASSED");
    info!("========================================\n");

    Ok(())
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
