//! Diagnostic dump for E2E test failures.
//!
//! Captures cluster state (pods, policies, logs, operator graph) to a file
//! on disk for post-mortem analysis. All output is also pushed to stdout
//! via `tracing::info!` so CI logs capture the full dump.
#![cfg(feature = "provider-e2e")]

use std::any::Any;
use std::future::Future;
use std::io::Write;
use std::panic::AssertUnwindSafe;

use futures::FutureExt;
use tracing::{info, warn};

use super::docker::run_kubectl;
use lattice_common::LATTICE_SYSTEM_NAMESPACE;

/// Extract a human-readable message from a panic payload.
pub fn panic_message(payload: &dyn Any) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

/// Context for capturing diagnostic dumps on test failure.
///
/// Construct with `new()` (no service names) or `with_services()` to include
/// per-service traffic generator logs in the dump.
pub struct DiagnosticContext {
    pub kubeconfig: String,
    pub namespace: String,
    pub service_names: Vec<String>,
}

impl DiagnosticContext {
    /// Create a diagnostic context (no per-service traffic logs).
    pub fn new(kubeconfig: &str, namespace: &str) -> Self {
        Self {
            kubeconfig: kubeconfig.to_string(),
            namespace: namespace.to_string(),
            service_names: Vec::new(),
        }
    }

    /// Create a diagnostic context with per-service traffic generator log capture.
    pub fn with_services(kubeconfig: &str, namespace: &str, service_names: Vec<String>) -> Self {
        Self {
            kubeconfig: kubeconfig.to_string(),
            namespace: namespace.to_string(),
            service_names,
        }
    }

    /// Capture cluster diagnostics to a file on disk AND stdout.
    ///
    /// Captures pod status, mesh policies, operator/ztunnel logs, the in-memory
    /// service graph (via port-forward to the operator's `/debug/graph` endpoint),
    /// unhealthy pod details, and per-service traffic generator logs.
    ///
    /// Each section is best-effort: failures are logged inline so partial dumps
    /// survive panics (file is opened in append mode).
    ///
    /// Returns the path to the dump file.
    pub async fn dump(&self, label: &str) -> String {
        let slug: String = label
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '-' })
            .collect();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let path = format!("/tmp/lattice-diag-{}-{}.log", slug, ts);

        info!(
            "[Diagnostics] ====== FAILURE DIAGNOSTIC DUMP: {} ======",
            label
        );
        info!("[Diagnostics] Writing to {}", path);

        let mut file = match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) => {
                warn!("[Diagnostics] Failed to open dump file {}: {}", path, e);
                return path;
            }
        };

        let kubeconfig = &self.kubeconfig;
        let namespace = &self.namespace;

        // In-memory service graph
        emit_section(&mut file, "In-memory Service Graph", async {
            fetch_operator_graph(kubeconfig).await
        })
        .await;

        // kubectl resource dumps
        let sections: &[(&str, Vec<&str>)] = &[
            (
                "Pod Status",
                vec!["get", "pods", "-n", namespace, "-o", "wide"],
            ),
            (
                "LatticeMeshMembers",
                vec!["get", "latticemeshmembers", "-n", namespace, "-o", "yaml"],
            ),
            (
                "AuthorizationPolicies",
                vec![
                    "get",
                    "authorizationpolicies",
                    "-n",
                    namespace,
                    "-o",
                    "yaml",
                ],
            ),
            (
                "CiliumNetworkPolicies",
                vec![
                    "get",
                    "ciliumnetworkpolicies",
                    "-n",
                    namespace,
                    "-o",
                    "yaml",
                ],
            ),
            (
                "LatticeServices",
                vec!["get", "latticeservices", "-n", namespace, "-o", "yaml"],
            ),
            (
                "ExternalSecrets",
                vec!["get", "externalsecrets", "-n", namespace, "-o", "yaml"],
            ),
            (
                "Ztunnel Logs",
                vec![
                    "logs",
                    "-n",
                    "istio-system",
                    "-l",
                    "app=ztunnel",
                    "--tail=200",
                ],
            ),
            (
                "Operator Logs",
                vec![
                    "logs",
                    "-n",
                    LATTICE_SYSTEM_NAMESPACE,
                    "-l",
                    "app=lattice-operator",
                    "--tail=200",
                ],
            ),
            (
                "CiliumEndpoints",
                vec!["get", "ciliumendpoints", "-n", namespace, "-o", "yaml"],
            ),
            (
                "Events",
                vec!["get", "events", "-n", namespace, "--sort-by=.lastTimestamp"],
            ),
        ];

        for (name, args) in sections {
            let mut full_args = vec!["--kubeconfig", kubeconfig];
            full_args.extend_from_slice(args);
            emit_section(&mut file, name, async { run_kubectl(&full_args).await }).await;
        }

        // Describe unhealthy pods: pods that are not Running, or Running but have
        // containers that are not ready (catches CrashLoopBackOff, OOM, image pull errors).
        emit_section(&mut file, "Unhealthy Pod Details", async {
            describe_unhealthy_pods(kubeconfig, namespace).await
        })
        .await;

        // Per-service traffic generator logs
        for svc in &self.service_names {
            let label = &format!("{}={}", lattice_common::LABEL_NAME, svc);
            emit_section(&mut file, &format!("Traffic: {}", svc), async {
                run_kubectl(&[
                    "--kubeconfig",
                    kubeconfig,
                    "logs",
                    "-n",
                    namespace,
                    "-l",
                    label,
                    "--tail=500",
                    "--since=10m",
                ])
                .await
            })
            .await;
        }

        info!("[Diagnostics] ====== END DIAGNOSTIC DUMP ======");
        path
    }
}

/// Run an async test body with automatic diagnostic dump on failure.
///
/// Dumps diagnostics on both `Err` returns and panics, so callers don't need
/// to wire up separate dump logic for each failure mode.
pub async fn with_diagnostics<F, Fut>(
    ctx: &DiagnosticContext,
    label: &str,
    f: F,
) -> Result<(), String>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let result = AssertUnwindSafe(f()).catch_unwind().await;
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            warn!("[{}] FAILED: {}", label, e);
            let path = ctx.dump(label).await;
            warn!("[{}] Diagnostic dump (error): {}", label, path);
            Err(e)
        }
        Err(panic_payload) => {
            warn!(
                "[{}] PANIC caught: {}",
                label,
                panic_message(&*panic_payload)
            );
            let path = ctx.dump(label).await;
            warn!("[{}] Diagnostic dump (panic): {}", label, path);
            std::panic::resume_unwind(panic_payload);
        }
    }
}

/// Emit a single diagnostic section to both file and stdout.
async fn emit_section<F: std::future::Future<Output = Result<String, String>>>(
    file: &mut std::fs::File,
    name: &str,
    fut: F,
) {
    write_banner(file, name);
    info!("[Diagnostics] --- {} ---", name);

    match fut.await {
        Ok(output) => {
            let _ = writeln!(file, "{}", output);
            for line in output.lines() {
                info!("[Diagnostics] {}", line);
            }
        }
        Err(e) => {
            let msg = format!("ERROR: {}", e);
            let _ = writeln!(file, "{}", msg);
            info!("[Diagnostics] {}", msg);
        }
    }
}

fn write_banner(file: &mut std::fs::File, name: &str) {
    let _ = writeln!(file, "\n{}", "=".repeat(72));
    let _ = writeln!(file, "--- {} ---", name);
    let _ = writeln!(file, "{}\n", "=".repeat(72));
}

/// Find pods that are not Running/Succeeded or have non-ready containers,
/// and return `kubectl describe` output for each.
async fn describe_unhealthy_pods(kubeconfig: &str, namespace: &str) -> Result<String, String> {
    let pod_info = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "pods",
        "-n",
        namespace,
        "-o",
        "jsonpath={range .items[*]}{.metadata.name} {.status.phase} {range .status.containerStatuses[*]}{.ready}{end}{\"\\n\"}{end}",
    ])
    .await?;

    let mut unhealthy = Vec::new();
    for line in pod_info.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let name = parts[0];
        let phase = parts.get(1).copied().unwrap_or("Unknown");
        let has_not_ready = parts[2..].contains(&"false");
        if (phase != "Running" && phase != "Succeeded") || has_not_ready {
            unhealthy.push(name.to_string());
        }
    }

    if unhealthy.is_empty() {
        return Ok("All pods healthy".to_string());
    }

    let mut output = String::new();
    for pod in &unhealthy {
        match run_kubectl(&[
            "--kubeconfig",
            kubeconfig,
            "describe",
            "pod",
            pod,
            "-n",
            namespace,
        ])
        .await
        {
            Ok(desc) => output.push_str(&format!("--- {} ---\n{}\n\n", pod, desc)),
            Err(e) => output.push_str(&format!("--- {} ---\nERROR: {}\n\n", pod, e)),
        }
    }
    Ok(output)
}

/// Fetch the in-memory service graph from the operator via port-forward.
///
/// Spawns a `kubectl port-forward` to the operator deployment, makes an HTTP
/// GET to `/debug/graph`, and returns the JSON body. The operator image has no
/// curl, so we use reqwest from the test process.
async fn fetch_operator_graph(kubeconfig: &str) -> Result<String, String> {
    use std::process::Stdio;
    use tokio::io::AsyncBufReadExt;

    // Let kubectl pick the local port (0:8080) and parse it from stdout.
    // This avoids a race between dropping a pre-bound listener and kubectl
    // binding the same port.
    let mut child = tokio::process::Command::new("kubectl")
        .args([
            "--kubeconfig",
            kubeconfig,
            "port-forward",
            "-n",
            LATTICE_SYSTEM_NAMESPACE,
            "deploy/lattice-operator",
            "0:8080",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("spawn port-forward: {e}"))?;

    // Wait for "Forwarding from 127.0.0.1:PORT" and extract the port.
    // We read both stdout (for the port) and stderr (for error details).
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let mut stdout_reader = tokio::io::BufReader::new(stdout).lines();
    let mut stderr_reader = tokio::io::BufReader::new(stderr);

    let local_port = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while let Ok(Some(line)) = stdout_reader.next_line().await {
            // kubectl prints "Forwarding from 127.0.0.1:PORT -> 8080"
            if let Some(rest) = line.strip_prefix("Forwarding from 127.0.0.1:") {
                if let Some(port_str) = rest.split_whitespace().next() {
                    if let Ok(port) = port_str.parse::<u16>() {
                        return Ok(port);
                    }
                }
            }
        }
        // stdout ended without the "Forwarding from" line — read stderr for the reason
        let mut stderr_buf = String::new();
        let _ = tokio::io::AsyncReadExt::read_to_string(&mut stderr_reader, &mut stderr_buf).await;
        let detail = stderr_buf.trim();
        if detail.is_empty() {
            Err("port-forward stdout ended before ready (no stderr)".to_string())
        } else {
            Err(format!("port-forward failed: {detail}"))
        }
    })
    .await
    .map_err(|_| "port-forward timed out waiting for ready".to_string())?
    .map_err(|e| e.to_string())?;

    let url = format!("http://127.0.0.1:{}/debug/graph", local_port);
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), reqwest::get(&url))
        .await
        .map_err(|_| "HTTP GET /debug/graph timed out".to_string())?
        .map_err(|e| format!("HTTP GET /debug/graph: {e}"))?;

    let body = result
        .text()
        .await
        .map_err(|e| format!("read response body: {e}"))?;

    // child is killed on drop
    Ok(body)
}
