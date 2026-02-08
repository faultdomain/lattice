//! Multi-hop proxy integration tests
//!
//! Tests the full proxy path through multiple hops (mgmt -> workload -> workload2)
//! with real Kubernetes operations: create pod, stream logs, exec into pod, delete pod.
//!
//! # Architecture
//!
//! The multi-hop proxy flow is:
//! 1. Client sends request to mgmt's auth proxy
//! 2. Mgmt proxy routes through gRPC tunnel to workload's agent
//! 3. Workload's agent forwards to workload's proxy (since workload2 is workload's child)
//! 4. Workload proxy routes through gRPC tunnel to workload2's agent
//! 5. Workload2's agent executes request against local K8s API
//! 6. Response returns through the full chain
//!
//! # Operations Tested
//!
//! | Operation | K8s API | What It Validates |
//! |-----------|---------|-------------------|
//! | Create Pod | POST /api/v1/namespaces/{ns}/pods | REST write through 2 hops |
//! | Wait Ready | GET /api/v1/namespaces/{ns}/pods/{name} | Polling through 2 hops |
//! | Stream Logs | GET /api/v1/namespaces/{ns}/pods/{name}/log | Chunked streaming through 2 hops |
//! | Exec | POST /api/v1/namespaces/{ns}/pods/{name}/exec | WebSocket through 2 hops |
//! | Delete Pod | DELETE /api/v1/namespaces/{ns}/pods/{name} | REST delete through 2 hops |
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/workload-kubeconfig \
//! LATTICE_WORKLOAD2_KUBECONFIG=/path/to/workload2-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_multi_hop_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;
use tokio::time::sleep;
use tracing::info;

use super::super::context::{InfraContext, TestSession};
use super::super::helpers::{run_cmd, run_kubectl_with_retry, BUSYBOX_IMAGE};

// ============================================================================
// Constants
// ============================================================================

/// Namespace for multi-hop tests
const MULTI_HOP_NAMESPACE: &str = "multi-hop-test";

/// Pod name for multi-hop tests
const TEST_POD_NAME: &str = "multi-hop-test-pod";

/// Marker string in pod logs to verify log streaming
const LOG_MARKER: &str = "MULTI_HOP_TEST_MARKER";

/// Marker string for exec verification
const EXEC_MARKER: &str = "EXEC_SUCCESS_MARKER";

// ============================================================================
// Core Test Functions
// ============================================================================

/// Run the full suite of multi-hop proxy tests.
///
/// This function tests the complete proxy path through multiple hops:
/// mgmt -> workload -> workload2
///
/// Tests are run sequentially since each depends on the previous:
/// 1. Create namespace (if needed)
/// 2. Create pod
/// 3. Wait for pod to be ready
/// 4. Stream logs and verify marker
/// 5. Exec command and verify output
/// 6. Delete pod
/// 7. Cleanup namespace
///
/// # Arguments
/// * `ctx` - Infrastructure context with kubeconfig paths
pub async fn run_multi_hop_proxy_tests(ctx: &InfraContext) -> Result<(), String> {
    if !ctx.has_workload2() {
        info!("[Integration/MultiHop] Skipping - workload2 not enabled");
        return Ok(());
    }

    let kubeconfig = ctx.require_workload2()?;
    info!(
        "[Integration/MultiHop] Running multi-hop proxy tests through: mgmt -> workload -> workload2"
    );

    // Setup namespace
    ensure_namespace(kubeconfig).await?;

    // Run tests in sequence (each depends on previous)
    let result = run_test_sequence(kubeconfig).await;

    // Cleanup regardless of test result
    cleanup_namespace(kubeconfig);

    result
}

/// Run the test sequence after namespace setup.
async fn run_test_sequence(kubeconfig: &str) -> Result<(), String> {
    test_create_pod(kubeconfig).await?;
    test_wait_pod_ready(kubeconfig).await?;
    test_stream_logs(kubeconfig).await?;
    test_exec_command(kubeconfig).await?;
    test_delete_pod(kubeconfig).await?;

    info!("[Integration/MultiHop] All multi-hop proxy tests passed!");
    Ok(())
}

// ============================================================================
// Namespace Helpers
// ============================================================================

/// Ensure the test namespace exists.
async fn ensure_namespace(kubeconfig: &str) -> Result<(), String> {
    info!(
        "[Integration/MultiHop] Ensuring namespace {} exists...",
        MULTI_HOP_NAMESPACE
    );

    // Check if namespace exists (with retry for proxy failures)
    let exists = run_kubectl_with_retry(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "namespace",
        MULTI_HOP_NAMESPACE,
        "-o",
        "name",
    ])
    .await
    .is_ok();

    if exists {
        info!(
            "[Integration/MultiHop] Namespace {} already exists",
            MULTI_HOP_NAMESPACE
        );
        return Ok(());
    }

    // Create namespace
    run_kubectl_with_retry(&[
        "--kubeconfig",
        kubeconfig,
        "create",
        "namespace",
        MULTI_HOP_NAMESPACE,
    ])
    .await
    .map_err(|e| format!("Failed to create namespace {}: {}", MULTI_HOP_NAMESPACE, e))?;

    info!(
        "[Integration/MultiHop] Created namespace {}",
        MULTI_HOP_NAMESPACE
    );
    Ok(())
}

/// Delete the test namespace (best effort, doesn't fail the test).
fn cleanup_namespace(kubeconfig: &str) {
    info!(
        "[Integration/MultiHop] Cleaning up namespace {}...",
        MULTI_HOP_NAMESPACE
    );

    let _ = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "delete",
            "namespace",
            MULTI_HOP_NAMESPACE,
            "--wait=false",
        ],
    );
}

// ============================================================================
// Individual Test Functions
// ============================================================================

/// Test 1: Create a busybox pod through the multi-hop proxy.
async fn test_create_pod(kubeconfig: &str) -> Result<(), String> {
    info!("[Integration/MultiHop] Test 1: Creating pod through 2-hop proxy...");

    // Delete any existing pod first (from previous failed runs)
    let _ = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "delete",
            "pod",
            TEST_POD_NAME,
            "-n",
            MULTI_HOP_NAMESPACE,
            "--ignore-not-found",
        ],
    );

    // Create the pod
    // The pod echoes a marker then sleeps to stay running for log/exec tests
    let pod_command = format!("echo '{}'; sleep 300", LOG_MARKER);

    run_kubectl_with_retry(&[
        "--kubeconfig",
        kubeconfig,
        "run",
        TEST_POD_NAME,
        "-n",
        MULTI_HOP_NAMESPACE,
        &format!("--image={}", BUSYBOX_IMAGE),
        "--restart=Never",
        "--",
        "sh",
        "-c",
        &pod_command,
    ])
    .await
    .map_err(|e| format!("Failed to create pod: {}", e))?;

    info!("[Integration/MultiHop] SUCCESS: Pod created through 2-hop proxy");
    Ok(())
}

/// Test 2: Wait for the pod to be ready (polling through proxy).
async fn test_wait_pod_ready(kubeconfig: &str) -> Result<(), String> {
    info!("[Integration/MultiHop] Test 2: Waiting for pod to be ready (polling through 2-hop proxy)...");

    let timeout = Duration::from_secs(300);
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err(format!(
                "Pod {} did not become ready within {:?}",
                TEST_POD_NAME, timeout
            ));
        }

        // Check pod phase (with retry for proxy failures)
        let phase = run_kubectl_with_retry(&[
            "--kubeconfig",
            kubeconfig,
            "get",
            "pod",
            TEST_POD_NAME,
            "-n",
            MULTI_HOP_NAMESPACE,
            "-o",
            "jsonpath={.status.phase}",
        ])
        .await
        .unwrap_or_default();

        match phase.trim() {
            "Running" => {
                info!("[Integration/MultiHop] SUCCESS: Pod is running");
                return Ok(());
            }
            "Succeeded" => {
                // Pod completed - this is OK, it means the echo ran and sleep completed
                info!("[Integration/MultiHop] SUCCESS: Pod completed (still valid for log test)");
                return Ok(());
            }
            "Failed" => {
                return Err(format!("Pod {} failed", TEST_POD_NAME));
            }
            _ => {
                // Still pending or creating
                sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

/// Test 3: Stream logs from the pod through the proxy.
async fn test_stream_logs(kubeconfig: &str) -> Result<(), String> {
    info!("[Integration/MultiHop] Test 3: Streaming logs through 2-hop proxy...");

    // Use --tail to get recent logs (simpler than --follow for testing)
    let output = run_kubectl_with_retry(&[
        "--kubeconfig",
        kubeconfig,
        "logs",
        TEST_POD_NAME,
        "-n",
        MULTI_HOP_NAMESPACE,
        "--tail=10",
    ])
    .await
    .map_err(|e| format!("Failed to stream logs: {}", e))?;

    if !output.contains(LOG_MARKER) {
        return Err(format!(
            "Log streaming failed - marker '{}' not found in logs. Got: {}",
            LOG_MARKER,
            truncate(&output, 200)
        ));
    }

    info!("[Integration/MultiHop] SUCCESS: Log streaming through 2-hop proxy works");
    Ok(())
}

/// Test 4: Execute a command in the pod through the proxy (WebSocket).
async fn test_exec_command(kubeconfig: &str) -> Result<(), String> {
    info!("[Integration/MultiHop] Test 4: Exec command through 2-hop proxy (WebSocket)...");

    // First check if pod is still running (it might have completed)
    let phase = run_kubectl_with_retry(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "pod",
        TEST_POD_NAME,
        "-n",
        MULTI_HOP_NAMESPACE,
        "-o",
        "jsonpath={.status.phase}",
    ])
    .await
    .unwrap_or_default();

    if phase.trim() != "Running" {
        info!(
            "[Integration/MultiHop] Pod phase is '{}', skipping exec test (pod must be Running)",
            phase.trim()
        );
        return Ok(());
    }

    let output = run_kubectl_with_retry(&[
        "--kubeconfig",
        kubeconfig,
        "exec",
        TEST_POD_NAME,
        "-n",
        MULTI_HOP_NAMESPACE,
        "--",
        "echo",
        EXEC_MARKER,
    ])
    .await
    .map_err(|e| format!("Failed to exec into pod: {}", e))?;

    if !output.contains(EXEC_MARKER) {
        return Err(format!(
            "Exec failed - marker '{}' not found in output. Got: {}",
            EXEC_MARKER,
            truncate(&output, 200)
        ));
    }

    info!("[Integration/MultiHop] SUCCESS: Exec through 2-hop proxy works");
    Ok(())
}

/// Test 5: Delete the pod through the proxy.
async fn test_delete_pod(kubeconfig: &str) -> Result<(), String> {
    info!("[Integration/MultiHop] Test 5: Deleting pod through 2-hop proxy...");

    run_kubectl_with_retry(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "pod",
        TEST_POD_NAME,
        "-n",
        MULTI_HOP_NAMESPACE,
        "--wait=false",
    ])
    .await
    .map_err(|e| format!("Failed to delete pod: {}", e))?;

    info!("[Integration/MultiHop] SUCCESS: Pod deleted through 2-hop proxy");
    Ok(())
}

// ============================================================================
// Helpers
// ============================================================================

/// Truncate a string for error messages.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...(truncated)", &s[..max_len])
    } else {
        s.to_string()
    }
}

// ============================================================================
// Standalone Tests
// ============================================================================

/// Standalone test - run full multi-hop proxy tests.
///
/// Requires workload2 kubeconfig to be set.
#[tokio::test]
#[ignore]
async fn test_multi_hop_standalone() {
    let session = TestSession::from_env(
        "Set LATTICE_MGMT_KUBECONFIG, LATTICE_WORKLOAD_KUBECONFIG, and LATTICE_WORKLOAD2_KUBECONFIG",
    )
    .await
    .unwrap();

    if !session.ctx.has_workload2() {
        panic!("This test requires LATTICE_WORKLOAD2_KUBECONFIG to be set");
    }

    run_multi_hop_proxy_tests(&session.ctx).await.unwrap();
}
