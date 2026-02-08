//! Test utilities for mesh bilateral agreement tests
//!
//! Contains test target types, log parsing, traffic script generation,
//! cycle-based waiting, and verification functions.

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::{info, warn};

use super::helpers::{run_kubectl, wait_for_condition};

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

    /// Create a test target for an external service (random mesh log format)
    pub fn external(source: &str, target: &str, url: &str, expected: bool) -> Self {
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

    /// Create a test target for an internal service (random mesh log format)
    pub fn internal_random(source: &str, target: &str, namespace: &str, expected: bool) -> Self {
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
            url: format!("http://{}.{}.svc.cluster.local/", target, namespace),
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
    R{i}=$(curl -s -o /dev/null -w "%{{http_code}}" --connect-timeout 3 --max-time 5 {url} 2>/dev/null || echo "000")"#,
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
    HTTP_CODE=$(curl -s -o /dev/null -w "%{{http_code}}" --connect-timeout 2 --max-time 3 {url} 2>/dev/null || echo "000")
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

/// Wait for pods to be running in a namespace.
///
/// Waits until `num_services + 1` pods are running (+1 for the Istio waypoint proxy).
pub async fn wait_for_pods_running(
    kubeconfig_path: &str,
    namespace: &str,
    num_services: usize,
    label: &str,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<(), String> {
    let expected_pods = num_services + 1;

    info!(
        "[{}] Waiting for {} pods ({} services + 1 waypoint)...",
        label, expected_pods, num_services
    );

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
                info!(
                    "[{}] All {} pods running ({} services + 1 waypoint)",
                    label, expected_pods, num_services
                );
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
        Duration::from_secs(300),
        Duration::from_secs(5),
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
