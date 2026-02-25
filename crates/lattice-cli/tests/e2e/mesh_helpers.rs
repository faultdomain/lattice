//! Test utilities for mesh bilateral agreement tests
//!
//! Contains test target types, log parsing, traffic script generation,
//! cycle-based waiting, and verification functions.

#![cfg(feature = "provider-e2e")]

use std::future::Future;
use std::time::{Duration, Instant};

use tokio::time::sleep;
use tracing::{info, warn};

use kube::api::{Api, Patch, PatchParams};

use lattice_common::crd::LatticeService;

use super::helpers::{
    client_from_kubeconfig, patch_with_retry, run_kubectl, wait_for_condition, DEFAULT_TIMEOUT,
};

// =============================================================================
// Constants
// =============================================================================

const CYCLE_START_MARKER: &str = "===CYCLE_START===";
const CYCLE_END_MARKER: &str = "===CYCLE_END===";

// =============================================================================
// Test Target
// =============================================================================

pub struct TestTarget {
    pub url: String,
    pub expected_allowed: bool,
    pub success_msg: String,
    pub fail_msg: String,
}

impl TestTarget {
    /// Create a test target for an internal service (fixed mesh log format)
    pub fn internal(name: &str, namespace: &str, expected: bool, reason: &str) -> Self {
        let (success_msg, fail_msg) = if expected {
            (
                format!("{}: ALLOWED ({})", name, reason),
                format!("{}: BLOCKED (UNEXPECTED - {})", name, reason),
            )
        } else {
            (
                format!("{}: ALLOWED (UNEXPECTED - {})", name, reason),
                format!("{}: BLOCKED ({})", name, reason),
            )
        };
        Self {
            url: format!("http://{}.{}.svc.cluster.local/", name, namespace),
            expected_allowed: expected,
            success_msg,
            fail_msg,
        }
    }

    /// Create a test target with a custom URL (random mesh log format)
    pub fn with_url(source: &str, target: &str, url: &str, expected: bool) -> Self {
        let (success_msg, fail_msg) = if expected {
            (
                format!("{}->{}:ALLOWED", source, target),
                format!("{}->{}:BLOCKED(UNEXPECTED)", source, target),
            )
        } else {
            (
                format!("{}->{}:ALLOWED(UNEXPECTED)", source, target),
                format!("{}->{}:BLOCKED", source, target),
            )
        };
        Self {
            url: url.to_string(),
            expected_allowed: expected,
            success_msg,
            fail_msg,
        }
    }
}

// =============================================================================
// Log Result Parsing
// =============================================================================

/// Parse traffic test result from logs.
///
/// Returns the most recent result when both ALLOWED and BLOCKED patterns exist.
pub fn parse_traffic_result(
    logs: &str,
    allowed_pattern: &str,
    blocked_pattern: &str,
) -> Option<bool> {
    let has_allowed = logs.contains(allowed_pattern);
    let has_blocked = logs.contains(blocked_pattern);

    match (has_allowed, has_blocked) {
        (true, true) => {
            let last_allowed = logs.rfind(allowed_pattern).unwrap();
            let last_blocked = logs.rfind(blocked_pattern).unwrap();
            Some(last_allowed > last_blocked)
        }
        (true, false) => Some(true),
        (false, true) => Some(false),
        (false, false) => None,
    }
}

// =============================================================================
// Traffic Script Generation
// =============================================================================

/// Generate a traffic test script that waits for policies and tests connections.
pub fn generate_test_script(source_name: &str, targets: Vec<TestTarget>) -> String {
    let blocked_targets: Vec<&TestTarget> =
        targets.iter().filter(|t| !t.expected_allowed).collect();

    let endpoint_checks: String = blocked_targets
        .iter()
        .enumerate()
        .map(|(i, t)| {
            format!(
                r#"
    R{i}=$(curl -sk -o /dev/null -w "%{{http_code}}" --connect-timeout 1 --max-time 2 {url} 2>/dev/null; true)"#,
                i = i,
                url = t.url,
            )
        })
        .collect();

    let all_blocked_check: String = if blocked_targets.is_empty() {
        "true".to_string()
    } else {
        blocked_targets
            .iter()
            .enumerate()
            .map(|(i, _)| {
                format!(
                    "\"$R{}\" != \"200\" ] && [ \"$R{}\" != \"201\" ] && [ \"$R{}\" != \"204\"",
                    i, i, i
                )
            })
            .collect::<Vec<_>>()
            .join(" ] && [ ")
    };

    let mut script = format!(
        r#"
echo "{cycle_start}"
echo "=== {source} Traffic Tests ==="
echo "Testing {num_targets} endpoints..."

# Wait for blocked endpoints to NOT return 2xx (policy active or service not ready)
# Increase timeout to 3 minutes (90 retries * 2 seconds) to handle slow policy propagation
echo "Waiting for policies on {num_blocked} blocked endpoints..."
MAX_RETRIES=90
RETRY=0
while [ $RETRY -lt $MAX_RETRIES ]; do{endpoint_checks}
    if [ {all_blocked_check} ]; then
        echo "Blocked endpoints not returning 2xx - policies active"
        sleep 2
        break
    fi
    RETRY=$((RETRY + 1))
    if [ $((RETRY % 15)) -eq 0 ]; then
        echo "Waiting for policies... (attempt $RETRY/$MAX_RETRIES)"
    fi
    sleep 2
done

if [ $RETRY -eq $MAX_RETRIES ]; then
    echo "ERROR: Policy propagation wait timed out after 3 minutes"
    echo "Blocked endpoints are still returning 2xx - policies not enforced"
    exit 1
fi

"#,
        cycle_start = CYCLE_START_MARKER,
        source = source_name,
        num_targets = targets.len(),
        num_blocked = blocked_targets.len(),
        endpoint_checks = endpoint_checks,
        all_blocked_check = all_blocked_check,
    );

    for target in &targets {
        script.push_str(&format!(
            r#"
# Test {url} - retry transient failures, accept 403 as definitive block
MAX_ATTEMPTS=3
ATTEMPT=0
RESULT="UNKNOWN"
while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    HTTP_CODE=$(curl -sk -o /dev/null -w "%{{http_code}}" --connect-timeout 1 --max-time 2 {url} 2>/dev/null; true)
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "204" ] || [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ]; then
        RESULT="ALLOWED"
        break
    elif [ "$HTTP_CODE" = "403" ]; then
        # Policy block - definitive, no retry needed
        RESULT="BLOCKED"
        break
    else
        # Transient failure (000=connection error, 5xx=server error) - retry
        ATTEMPT=$((ATTEMPT + 1))
        if [ $ATTEMPT -lt $MAX_ATTEMPTS ]; then
            sleep 1
        fi
    fi
done
if [ "$RESULT" = "ALLOWED" ]; then
    echo "{success_msg}"
elif [ "$RESULT" = "BLOCKED" ]; then
    echo "{fail_msg}"
else
    # All attempts failed with connection errors - blocked at network layer (Cilium)
    echo "{fail_msg} (timeout)"
fi
"#,
            url = target.url,
            success_msg = target.success_msg,
            fail_msg = target.fail_msg,
        ));
    }

    script.push_str(&format!(
        r#"
echo "=== End {source} Tests ==="
echo "{cycle_end}"
sleep 5
"#,
        source = source_name,
        cycle_end = CYCLE_END_MARKER,
    ));

    // Loop forever
    script.insert_str(0, "while true; do\n");
    script.push_str("done\n");

    script
}

// =============================================================================
// Cycle-Based Waiting
// =============================================================================

/// Wait for N complete test cycles across specified traffic generator pods.
pub async fn wait_for_cycles(
    kubeconfig_path: &str,
    namespace: &str,
    service_names: &[&str],
    min_cycles: usize,
    label: &str,
) -> Result<(), String> {
    info!(
        "[{}] Waiting for {} complete test cycles on {} traffic generators...",
        label,
        min_cycles,
        service_names.len()
    );

    wait_for_condition(
        &format!("{} test cycles in {}", min_cycles, label),
        Duration::from_secs(600),
        Duration::from_secs(10),
        || async move {
            let label_escaped = lattice_common::LABEL_NAME.replace('.', r"\.");
            let jsonpath = format!(
                "{{range .items[*]}}{{.metadata.name}}:{{.metadata.labels.{}}}{{\"\\n\"}}{{end}}",
                label_escaped
            );
            let pods_output = run_kubectl(&[
                "--kubeconfig",
                kubeconfig_path,
                "get",
                "pods",
                "-n",
                namespace,
                "-o",
                &format!("jsonpath={}", jsonpath),
            ])
            .await
            .unwrap_or_default();

            let pods: Vec<&str> = pods_output
                .lines()
                .filter_map(|line: &str| {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() == 2 {
                        let pod_name = parts[0].trim();
                        let label_value = parts[1].trim();
                        if service_names.contains(&label_value) {
                            return Some(pod_name);
                        }
                    }
                    None
                })
                .collect();

            if pods.len() < service_names.len() {
                info!(
                    "[{}] Found {}/{} traffic generator pods, waiting...",
                    label,
                    pods.len(),
                    service_names.len()
                );
                return Ok(false);
            }

            let mut all_pods_ready = true;
            let mut min_cycles_found = usize::MAX;

            for pod in &pods {
                let logs = match run_kubectl(&[
                    "--kubeconfig",
                    kubeconfig_path,
                    "logs",
                    "-n",
                    namespace,
                    pod,
                    "--tail",
                    "2000",
                ])
                .await
                {
                    Ok(output) => output,
                    Err(e) => {
                        warn!("[{}] Failed to get logs for pod {}: {}", label, pod, e);
                        String::new()
                    }
                };

                let cycle_count = logs.matches(CYCLE_END_MARKER).count();
                min_cycles_found = min_cycles_found.min(cycle_count);

                if cycle_count < min_cycles {
                    all_pods_ready = false;
                }
            }

            if min_cycles_found == usize::MAX {
                min_cycles_found = 0;
            }

            info!(
                "[{}] Cycle progress: {}/{} cycles complete (across {} pods)",
                label,
                min_cycles_found,
                min_cycles,
                pods.len()
            );

            if all_pods_ready {
                info!(
                    "[{}] All {} pods have completed {} cycles!",
                    label,
                    pods.len(),
                    min_cycles
                );
            }

            Ok(all_pods_ready)
        },
    )
    .await
}

/// Wait for the expected number of pods to be running in a namespace.
pub async fn wait_for_pods_running(
    kubeconfig_path: &str,
    namespace: &str,
    expected_pods: usize,
    label: &str,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<(), String> {
    info!("[{}] Waiting for {} pods...", label, expected_pods);

    wait_for_condition(
        &format!("{} pods in {}", expected_pods, label),
        timeout,
        poll_interval,
        || async move {
            let running_count = match run_kubectl(&[
                "--kubeconfig",
                kubeconfig_path,
                "get",
                "pods",
                "-n",
                namespace,
                "-o",
                "jsonpath={range .items[*]}{.status.phase}{\"\\n\"}{end}",
            ])
            .await
            {
                Ok(output) => output
                    .lines()
                    .filter(|l: &&str| l.trim() == "Running")
                    .count(),
                Err(_) => 0,
            };

            info!(
                "[{}] {}/{} pods running",
                label, running_count, expected_pods
            );

            if running_count >= expected_pods {
                info!("[{}] All {} pods running", label, expected_pods);
                return Ok(true);
            }

            Ok(false)
        },
    )
    .await
}

/// Wait for all LatticeServices in a namespace to be Ready.
pub async fn wait_for_services_ready(
    kubeconfig_path: &str,
    namespace: &str,
    expected_count: usize,
) -> Result<(), String> {
    info!(
        "[{}] Waiting for {} LatticeServices to be Ready...",
        namespace, expected_count
    );

    wait_for_condition(
        &format!(
            "{} LatticeServices in {} to be Ready",
            expected_count, namespace
        ),
        DEFAULT_TIMEOUT,
        Duration::from_secs(2),
        || async move {
            let output = run_kubectl(&[
                "--kubeconfig",
                kubeconfig_path,
                "get",
                "latticeservices",
                "-n",
                namespace,
                "-o",
                "jsonpath={range .items[*]}{.metadata.name}:{.status.phase}{\"\\n\"}{end}",
            ])
            .await
            .unwrap_or_default();

            let services: Vec<(&str, &str)> = output
                .lines()
                .filter_map(|line| {
                    let parts: Vec<&str> = line.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        Some((parts[0].trim(), parts[1].trim()))
                    } else {
                        None
                    }
                })
                .collect();

            let total = services.len();
            let ready_count = services
                .iter()
                .filter(|(_, phase)| *phase == "Ready")
                .count();

            info!(
                "[{}] {}/{} LatticeServices ready (total: {})",
                namespace, ready_count, expected_count, total
            );

            if ready_count >= expected_count {
                info!(
                    "[{}] All {} LatticeServices are Ready!",
                    namespace, expected_count
                );
                return Ok(true);
            }

            let not_ready: Vec<String> = services
                .iter()
                .filter(|(_, phase)| *phase != "Ready")
                .map(|(name, phase)| format!("{}:{}", name, phase))
                .collect();

            if !not_ready.is_empty() && not_ready.len() <= 5 {
                info!("[{}]   Not ready: {}", namespace, not_ready.join(", "));
            }

            Ok(false)
        },
    )
    .await
}

// =============================================================================
// Verification
// =============================================================================

/// Retry a verification function every 15s for up to 5 minutes.
///
/// Used by both fixed and random mesh tests to handle slow policy propagation.
pub async fn retry_verification<F, Fut>(label: &str, verify: F) -> Result<(), String>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let timeout = DEFAULT_TIMEOUT;
    let start = Instant::now();
    let mut attempt = 0u32;
    let mut last_err;

    loop {
        attempt += 1;
        info!(
            "[{}] Verification attempt {} (elapsed: {:.0}s)",
            label,
            attempt,
            start.elapsed().as_secs_f64()
        );

        match verify().await {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = e;
                if start.elapsed() >= timeout {
                    break;
                }
                info!("[{}] Verification failed, retrying in 8s...", label);
                sleep(Duration::from_secs(8)).await;
            }
        }
    }

    Err(format!(
        "[{}] Timed out after {} attempts ({:.0}s): {}",
        label,
        attempt,
        start.elapsed().as_secs_f64(),
        last_err
    ))
}

// =============================================================================
// Edge Removal Test Helpers
// =============================================================================

/// An edge that was removed and whose denial we need to verify.
pub struct RemovedEdge {
    /// Traffic generator service name (used as pod label selector)
    pub source: String,
    /// Pattern that appears when the connection is allowed
    pub allowed_pattern: String,
    /// Pattern that appears when the connection is blocked
    pub blocked_pattern: String,
}

/// Remove an inbound resource from a LatticeService via JSON merge patch.
///
/// This breaks a bilateral agreement by removing the target's inbound allow
/// for the given source, causing the connection to be denied.
pub async fn remove_inbound_edge(
    kubeconfig_path: &str,
    namespace: &str,
    target_service: &str,
    inbound_key: &str,
) -> Result<(), String> {
    let client = client_from_kubeconfig(kubeconfig_path).await?;
    let api: Api<LatticeService> = Api::namespaced(client, namespace);

    let mut resources_map = serde_json::Map::new();
    resources_map.insert(inbound_key.to_string(), serde_json::Value::Null);

    let patch = serde_json::json!({
        "spec": {
            "workload": {
                "resources": serde_json::Value::Object(resources_map)
            }
        }
    });

    patch_with_retry(
        &api,
        target_service,
        &PatchParams::default(),
        &Patch::Merge(patch),
    )
    .await?;

    info!(
        "[Edge Removal] Removed inbound '{}' from '{}'",
        inbound_key, target_service
    );
    Ok(())
}

/// Wait for removed edges to become denied in traffic generator logs.
///
/// Polls traffic generator logs every 8s for up to 5 minutes. An edge is
/// considered denied when `parse_traffic_result` returns `Some(false)`.
pub async fn wait_for_edges_denied(
    kubeconfig_path: &str,
    namespace: &str,
    edges: &[RemovedEdge],
    label: &str,
) -> Result<(), String> {
    info!(
        "[{}] Waiting for {} removed edges to become denied (up to 5 min)...",
        label,
        edges.len()
    );

    let timeout = DEFAULT_TIMEOUT;
    let start = Instant::now();

    loop {
        let mut all_denied = true;
        let mut pending = Vec::new();

        for edge in edges {
            let logs = run_kubectl(&[
                "--kubeconfig",
                kubeconfig_path,
                "logs",
                "-n",
                namespace,
                "-l",
                &format!("{}={}", lattice_common::LABEL_NAME, edge.source),
                "--tail",
                "200",
            ])
            .await
            .unwrap_or_default();

            match parse_traffic_result(&logs, &edge.allowed_pattern, &edge.blocked_pattern) {
                Some(false) => {
                    // Most recent result is BLOCKED — edge is denied
                }
                result => {
                    all_denied = false;
                    let status = match result {
                        Some(true) => "still ALLOWED",
                        None => "no result yet",
                        _ => unreachable!(),
                    };
                    pending.push(format!(
                        "{} -> {}: {}",
                        edge.source, edge.blocked_pattern, status
                    ));
                }
            }
        }

        if all_denied {
            info!(
                "[{}] All {} removed edges are now denied!",
                label,
                edges.len()
            );
            return Ok(());
        }

        if start.elapsed() >= timeout {
            return Err(format!(
                "[{}] Timed out after {:.0}s waiting for edges to become denied. Still pending: {}",
                label,
                start.elapsed().as_secs_f64(),
                pending.join("; ")
            ));
        }

        info!(
            "[{}] {}/{} edges denied (elapsed: {:.0}s), waiting...",
            label,
            edges.len() - pending.len(),
            edges.len(),
            start.elapsed().as_secs_f64()
        );

        sleep(Duration::from_secs(8)).await;
    }
}

/// Check that no traffic was incorrectly allowed (security violation check).
pub async fn check_no_incorrectly_allowed(
    kubeconfig_path: &str,
    namespace: &str,
) -> Result<(), String> {
    let mut violations: Vec<String> = Vec::new();

    let pods_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig_path,
        "get",
        "pods",
        "-n",
        namespace,
        "-o",
        "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}",
    ])
    .await?;

    for pod in pods_output.lines() {
        let pod = pod.trim();
        if pod.is_empty() {
            continue;
        }

        let logs = run_kubectl(&[
            "--kubeconfig",
            kubeconfig_path,
            "logs",
            "-n",
            namespace,
            pod,
            "--tail",
            "500",
        ])
        .await
        .unwrap_or_default();

        for line in logs.lines() {
            if line.contains("ALLOWED(UNEXPECTED)") || line.contains("ALLOWED (UNEXPECTED") {
                violations.push(format!("{}: {}", pod, line.trim()));
            }
        }
    }

    if !violations.is_empty() {
        info!("SECURITY VIOLATIONS DETECTED:");
        for v in &violations {
            info!("{}", v);
        }
        return Err(format!(
            "Policy gaps detected: {} instances of incorrectly allowed traffic",
            violations.len()
        ));
    }

    Ok(())
}
