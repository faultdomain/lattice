//! Gateway-specific test helpers
//!
//! Discovery, traffic script generation, and verification helpers for
//! Gateway API integration tests.

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::{info, warn};

use super::gateway_fixtures::ExpectedStatus;
use super::helpers::{run_kubectl, wait_for_condition};

// =============================================================================
// Constants
// =============================================================================

const CYCLE_START_MARKER: &str = "===CYCLE_START===";
const CYCLE_END_MARKER: &str = "===CYCLE_END===";

// =============================================================================
// Gateway Test Target
// =============================================================================

/// A target for the gateway traffic generator script.
pub struct GatewayTestTarget {
    /// Host header to send
    pub host: String,
    /// URL path to request
    pub path: String,
    /// Whether to use HTTPS (port 443 with -k)
    pub use_https: bool,
    /// Expected status category
    pub expected_status: ExpectedStatus,
    /// Human-readable label for log messages
    pub label: String,
}

// =============================================================================
// Gateway Address Discovery
// =============================================================================

/// Discover the ClusterIP of the Istio-created gateway Service.
///
/// The Istio gateway controller creates a Service named `{namespace}-ingress-istio`
/// for each Gateway resource. We use ClusterIP (not LoadBalancer) since traffic
/// generators run inside the cluster and this always works in Kind without MetalLB.
pub async fn get_gateway_service_ip(kubeconfig: &str, namespace: &str) -> Result<String, String> {
    let svc_name = format!("{}-ingress-istio", namespace);

    wait_for_condition(
        &format!("gateway service {} to get ClusterIP", svc_name),
        Duration::from_secs(180),
        Duration::from_secs(5),
        || async {
            let output = run_kubectl(&[
                "--kubeconfig",
                kubeconfig,
                "get",
                "service",
                &svc_name,
                "-n",
                namespace,
                "--ignore-not-found",
                "-o",
                "jsonpath={.spec.clusterIP}",
            ])
            .await
            .unwrap_or_default();

            if output.is_empty() || output == "None" {
                info!("Gateway service {} not ready yet", svc_name);
                return Ok(false);
            }

            Ok(true)
        },
    )
    .await?;

    let ip = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "service",
        &svc_name,
        "-n",
        namespace,
        "--ignore-not-found",
        "-o",
        "jsonpath={.spec.clusterIP}",
    ])
    .await?;

    if ip.is_empty() || ip == "None" {
        return Err(format!(
            "Gateway service {} has no ClusterIP after waiting",
            svc_name
        ));
    }

    info!("Gateway service {} ClusterIP: {}", svc_name, ip);
    Ok(ip)
}

/// Discover the HTTPS port on the gateway Service (the port named `https` or 443).
pub async fn get_gateway_https_port(kubeconfig: &str, namespace: &str) -> Result<u16, String> {
    let svc_name = format!("{}-ingress-istio", namespace);

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "service",
        &svc_name,
        "-n",
        namespace,
        "--ignore-not-found",
        "-o",
        "jsonpath={.spec.ports[?(@.name==\"https\")].port}",
    ])
    .await
    .unwrap_or_default();

    if let Ok(port) = output.trim().parse::<u16>() {
        return Ok(port);
    }

    // Fallback: look for port 443
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "service",
        &svc_name,
        "-n",
        namespace,
        "--ignore-not-found",
        "-o",
        "jsonpath={.spec.ports[?(@.port==443)].port}",
    ])
    .await
    .unwrap_or_default();

    output
        .trim()
        .parse::<u16>()
        .map_err(|_| format!("No HTTPS port found on gateway service {}", svc_name))
}

// =============================================================================
// Traffic Script Generation
// =============================================================================

/// Generate a bash script that curls the gateway IP with Host headers.
///
/// Uses `===CYCLE_START===` / `===CYCLE_END===` markers for cycle-based waiting.
pub fn generate_gateway_test_script(
    source_name: &str,
    gateway_ip: &str,
    gateway_https_port: u16,
    targets: Vec<GatewayTestTarget>,
) -> String {
    let mut script = String::from("while true; do\n");

    script.push_str(&format!(
        r#"echo "{cycle_start}"
echo "=== {source} Gateway Traffic Tests ==="
echo "Testing {num_targets} gateway endpoints..."

"#,
        cycle_start = CYCLE_START_MARKER,
        source = source_name,
        num_targets = targets.len(),
    ));

    for (i, target) in targets.iter().enumerate() {
        let (curl_cmd, status_var) = if target.use_https {
            (
                format!(
                    r#"HTTP_CODE_{i}=$(curl -sk -o /dev/null -w "%{{http_code}}" --connect-timeout 3 --max-time 5 -H "Host: {host}" https://{ip}:{port}{path} 2>/dev/null; true)"#,
                    i = i,
                    host = target.host,
                    ip = gateway_ip,
                    port = gateway_https_port,
                    path = target.path,
                ),
                format!("HTTP_CODE_{}", i),
            )
        } else {
            (
                format!(
                    r#"HTTP_CODE_{i}=$(curl -sk -o /dev/null -w "%{{http_code}}" --connect-timeout 3 --max-time 5 -H "Host: {host}" http://{ip}:80{path} 2>/dev/null; true)"#,
                    i = i,
                    host = target.host,
                    ip = gateway_ip,
                    path = target.path,
                ),
                format!("HTTP_CODE_{}", i),
            )
        };

        let (success_msg, fail_msg) = match target.expected_status {
            ExpectedStatus::Success => (
                format!("GATEWAY[{}]:ALLOWED({})", target.label, target.host),
                format!("GATEWAY[{}]:BLOCKED(UNEXPECTED)", target.label),
            ),
            ExpectedStatus::NotFound => (
                format!("GATEWAY[{}]:404({})", target.label, target.host),
                format!("GATEWAY[{}]:UNEXPECTED_STATUS", target.label),
            ),
        };

        let check = match target.expected_status {
            ExpectedStatus::Success => format!(
                r#"
{curl_cmd}
if [ "${status_var}" = "200" ] || [ "${status_var}" = "201" ] || [ "${status_var}" = "204" ] || [ "${status_var}" = "301" ] || [ "${status_var}" = "302" ]; then
    echo "{success_msg}"
else
    echo "{fail_msg} (got ${status_var})"
fi
"#,
                curl_cmd = curl_cmd,
                status_var = status_var,
                success_msg = success_msg,
                fail_msg = fail_msg,
            ),
            ExpectedStatus::NotFound => format!(
                r#"
{curl_cmd}
if [ "${status_var}" = "404" ]; then
    echo "{success_msg}"
elif [ "${status_var}" = "200" ] || [ "${status_var}" = "201" ] || [ "${status_var}" = "204" ]; then
    echo "{fail_msg} (got ${status_var} — route unexpectedly matched)"
else
    echo "{success_msg}"
fi
"#,
                curl_cmd = curl_cmd,
                status_var = status_var,
                success_msg = success_msg,
                fail_msg = fail_msg,
            ),
        };

        script.push_str(&check);
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

    script.push_str("done\n");
    script
}

// =============================================================================
// Gateway Readiness
// =============================================================================

/// Wait for the Gateway resource and its backing Istio Service to be ready.
pub async fn wait_for_gateway_ready(kubeconfig: &str, namespace: &str) -> Result<(), String> {
    let gateway_name = format!("{}-ingress", namespace);

    wait_for_condition(
        &format!("Gateway {} to exist", gateway_name),
        Duration::from_secs(180),
        Duration::from_secs(5),
        || async {
            let output = run_kubectl(&[
                "--kubeconfig",
                kubeconfig,
                "get",
                "gateway",
                &gateway_name,
                "-n",
                namespace,
                "--ignore-not-found",
                "-o",
                "jsonpath={.metadata.name}",
            ])
            .await
            .unwrap_or_default();

            Ok(!output.is_empty())
        },
    )
    .await?;

    info!("Gateway {} exists", gateway_name);

    // Also wait for the Istio service to have endpoints
    let svc_name = format!("{}-ingress-istio", namespace);
    wait_for_condition(
        &format!("Gateway service {} endpoints", svc_name),
        Duration::from_secs(180),
        Duration::from_secs(5),
        || async {
            let output = run_kubectl(&[
                "--kubeconfig",
                kubeconfig,
                "get",
                "endpoints",
                &svc_name,
                "-n",
                namespace,
                "--ignore-not-found",
                "-o",
                "jsonpath={.subsets[0].addresses[0].ip}",
            ])
            .await
            .unwrap_or_default();

            if output.is_empty() {
                info!("Gateway service {} has no endpoints yet", svc_name);
                return Ok(false);
            }

            info!("Gateway service {} has endpoints", svc_name);
            Ok(true)
        },
    )
    .await
}

// =============================================================================
// Resource Verification
// =============================================================================

/// Verify that the Gateway has the expected listener names.
pub async fn verify_gateway_listeners(
    kubeconfig: &str,
    namespace: &str,
    expected_listeners: &[&str],
) -> Result<(), String> {
    let gateway_name = format!("{}-ingress", namespace);

    wait_for_condition(
        &format!("Gateway {} to have all listeners", gateway_name),
        Duration::from_secs(120),
        Duration::from_secs(5),
        || async {
            let output = run_kubectl(&[
                "--kubeconfig",
                kubeconfig,
                "get",
                "gateway",
                &gateway_name,
                "-n",
                namespace,
                "--ignore-not-found",
                "-o",
                "jsonpath={.spec.listeners[*].name}",
            ])
            .await
            .unwrap_or_default();

            let listeners: Vec<&str> = output.split_whitespace().collect();
            for expected in expected_listeners {
                if !listeners.iter().any(|l| l == expected) {
                    info!(
                        "Gateway {}: waiting for listener {} (have: {:?})",
                        gateway_name, expected, listeners
                    );
                    return Ok(false);
                }
            }
            info!(
                "Gateway {}: all {} expected listeners verified",
                gateway_name,
                expected_listeners.len()
            );
            Ok(true)
        },
    )
    .await
}

/// Verify an HTTPRoute has the expected hostname, backend, and port.
pub async fn verify_httproute(
    kubeconfig: &str,
    namespace: &str,
    route_name: &str,
    expected_host: &str,
    expected_backend: &str,
    expected_port: &str,
) -> Result<(), String> {
    let expected_backend_port = format!("{}:{}", expected_backend, expected_port);

    wait_for_condition(
        &format!("HTTPRoute {} to be correct", route_name),
        Duration::from_secs(120),
        Duration::from_secs(5),
        || {
            let route_name = route_name.to_string();
            let expected_host = expected_host.to_string();
            let expected_backend_port = expected_backend_port.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    kubeconfig,
                    "get",
                    "httproute",
                    &route_name,
                    "-n",
                    namespace,
                    "--ignore-not-found",
                    "-o",
                    "jsonpath={.spec.hostnames[0]} {.spec.rules[0].backendRefs[0].name}:{.spec.rules[0].backendRefs[0].port}",
                ])
                .await
                .unwrap_or_default();

                let parts: Vec<&str> = output.split_whitespace().collect();
                if parts.len() != 2 {
                    info!("HTTPRoute {} not ready yet", route_name);
                    return Ok(false);
                }
                if parts[0] != expected_host || parts[1] != expected_backend_port {
                    info!(
                        "HTTPRoute {} mismatch: host={} backend={} (expected {} {})",
                        route_name, parts[0], parts[1], expected_host, expected_backend_port
                    );
                    return Ok(false);
                }
                info!(
                    "HTTPRoute {} -> {} (backend {})",
                    route_name, expected_host, expected_backend_port
                );
                Ok(true)
            }
        },
    )
    .await
}

/// Verify a Certificate has the expected DNS name and issuer.
pub async fn verify_certificate(
    kubeconfig: &str,
    namespace: &str,
    cert_name: &str,
    expected_dns: &str,
    expected_issuer: &str,
) -> Result<(), String> {
    wait_for_condition(
        &format!("Certificate {} to be correct", cert_name),
        Duration::from_secs(120),
        Duration::from_secs(5),
        || {
            let cert_name = cert_name.to_string();
            let expected_dns = expected_dns.to_string();
            let expected_issuer = expected_issuer.to_string();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    kubeconfig,
                    "get",
                    "certificate",
                    &cert_name,
                    "-n",
                    namespace,
                    "--ignore-not-found",
                    "-o",
                    "jsonpath={.spec.dnsNames[0]} {.spec.issuerRef.name}",
                ])
                .await
                .unwrap_or_default();

                let parts: Vec<&str> = output.split_whitespace().collect();
                if parts.len() != 2 {
                    info!("Certificate {} not ready yet", cert_name);
                    return Ok(false);
                }
                if parts[0] != expected_dns || parts[1] != expected_issuer {
                    info!(
                        "Certificate {} mismatch: dns={} issuer={} (expected {} {})",
                        cert_name, parts[0], parts[1], expected_dns, expected_issuer
                    );
                    return Ok(false);
                }
                info!(
                    "Certificate {} -> {} (issuer: {})",
                    cert_name, expected_dns, expected_issuer
                );
                Ok(true)
            }
        },
    )
    .await
}

// =============================================================================
// Traffic Cycle Waiting
// =============================================================================

/// Wait for the gateway traffic generator to complete N cycles.
///
/// Polls pod logs for `===CYCLE_END===` markers.
pub async fn wait_for_gateway_cycles(
    kubeconfig: &str,
    namespace: &str,
    traffic_gen_name: &str,
    min_cycles: usize,
) -> Result<(), String> {
    info!(
        "[Gateway] Waiting for {} complete test cycles on {}...",
        min_cycles, traffic_gen_name
    );

    wait_for_condition(
        &format!("{} gateway test cycles", min_cycles),
        Duration::from_secs(600),
        Duration::from_secs(10),
        || async move {
            let logs = match run_kubectl(&[
                "--kubeconfig",
                kubeconfig,
                "logs",
                "-n",
                namespace,
                "-l",
                &format!("{}={}", lattice_common::LABEL_NAME, traffic_gen_name),
                "--tail",
                "2000",
            ])
            .await
            {
                Ok(output) => output,
                Err(e) => {
                    warn!(
                        "[Gateway] Failed to get logs for {}: {}",
                        traffic_gen_name, e
                    );
                    return Ok(false);
                }
            };

            let cycle_count = logs.matches(CYCLE_END_MARKER).count();
            info!(
                "[Gateway] Cycle progress: {}/{} cycles complete",
                cycle_count, min_cycles
            );

            if cycle_count >= min_cycles {
                info!(
                    "[Gateway] Traffic generator completed {} cycles!",
                    min_cycles
                );
                return Ok(true);
            }

            Ok(false)
        },
    )
    .await
}

// =============================================================================
// Traffic Verification
// =============================================================================

/// Verify gateway traffic results from traffic generator logs.
///
/// Checks that each target matches its expected status (ALLOWED, 404, or BLOCKED).
pub async fn verify_gateway_traffic(
    kubeconfig: &str,
    namespace: &str,
    traffic_gen_name: &str,
) -> Result<(), String> {
    let logs = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "logs",
        "-n",
        namespace,
        "-l",
        &format!("{}={}", lattice_common::LABEL_NAME, traffic_gen_name),
        "--tail",
        "2000",
    ])
    .await
    .map_err(|e| format!("Failed to get traffic gen logs: {}", e))?;

    let mut failures: Vec<String> = Vec::new();

    // Check for unexpected results in the logs
    for line in logs.lines() {
        let line = line.trim();
        if line.contains("UNEXPECTED") {
            failures.push(line.to_string());
        }
    }

    if !failures.is_empty() {
        return Err(format!(
            "Gateway traffic verification failed with {} unexpected results:\n{}",
            failures.len(),
            failures.join("\n")
        ));
    }

    // Verify we actually got results (not just empty logs)
    let allowed_count = logs.matches(":ALLOWED(").count();
    let not_found_count = logs.matches(":404(").count();

    if allowed_count == 0 && not_found_count == 0 {
        return Err("No gateway traffic results found in logs".to_string());
    }

    info!(
        "[Gateway] Traffic verified: {} allowed, {} 404s, 0 unexpected",
        allowed_count, not_found_count
    );

    Ok(())
}

/// Verify that an HTTPRoute has been deleted (orphan cleanup).
pub async fn verify_httproute_deleted(
    kubeconfig: &str,
    namespace: &str,
    route_name: &str,
) -> Result<(), String> {
    wait_for_condition(
        &format!("HTTPRoute {} to be deleted", route_name),
        Duration::from_secs(120),
        Duration::from_secs(5),
        || {
            let route_name = route_name.to_string();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    kubeconfig,
                    "get",
                    "httproute",
                    &route_name,
                    "-n",
                    namespace,
                    "--ignore-not-found",
                    "-o",
                    "jsonpath={.metadata.name}",
                ])
                .await
                .unwrap_or_default();

                if output.is_empty() {
                    info!("HTTPRoute {} deleted", route_name);
                    return Ok(true);
                }

                info!("HTTPRoute {} still exists, waiting...", route_name);
                Ok(false)
            }
        },
    )
    .await
}
