//! Diagnostic dump for E2E test failures.
//!
//! Captures cluster state (pods, policies, logs, operator graph) to a file
//! on disk for post-mortem analysis. All output is also pushed to stdout
//! via `tracing::info!` so CI logs capture the full dump.
#![cfg(feature = "provider-e2e")]

use std::io::Write;

use tracing::{info, warn};

use super::docker::run_kubectl;
use lattice_common::LATTICE_SYSTEM_NAMESPACE;

/// Dump cluster diagnostics to a file on disk AND stdout.
///
/// Captures pod status, mesh policies, operator/ztunnel logs, the in-memory
/// service graph (via port-forward to the operator's `/debug/graph` endpoint),
/// and per-service traffic generator logs.
///
/// Each section is best-effort: failures are logged inline so partial dumps
/// survive panics (file is opened in append mode).
///
/// Returns the path to the dump file.
pub async fn dump_failure_diagnostics(
    kubeconfig: &str,
    namespace: &str,
    label: &str,
    service_names: &[String],
) -> String {
    let slug: String = label
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let path = format!("/tmp/lattice-diag-{}-{}.log", slug, ts);

    info!("[Diagnostics] ====== FAILURE DIAGNOSTIC DUMP: {} ======", label);
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

    // Section 1: In-memory service graph
    emit_section(&mut file, "In-memory Service Graph", async {
        fetch_operator_graph(kubeconfig).await
    })
    .await;

    // Sections 2-9: kubectl resource dumps
    let sections: &[(&str, &[&str])] = &[
        (
            "Pod Status",
            &["get", "pods", "-n", namespace, "-o", "wide"],
        ),
        (
            "LatticeMeshMembers",
            &[
                "get",
                "latticemeshmembers",
                "-n",
                namespace,
                "-o",
                "yaml",
            ],
        ),
        (
            "AuthorizationPolicies",
            &[
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
            &[
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
            &["get", "latticeservices", "-n", namespace, "-o", "yaml"],
        ),
        (
            "ExternalSecrets",
            &["get", "externalsecrets", "-n", namespace, "-o", "yaml"],
        ),
        (
            "Ztunnel Logs",
            &[
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
            &[
                "logs",
                "-n",
                LATTICE_SYSTEM_NAMESPACE,
                "-l",
                "app=lattice-operator",
                "--tail=200",
            ],
        ),
        (
            "Events",
            &[
                "get",
                "events",
                "-n",
                namespace,
                "--sort-by=.lastTimestamp",
            ],
        ),
    ];

    for (name, args) in sections {
        let mut full_args = vec!["--kubeconfig", kubeconfig];
        full_args.extend_from_slice(args);
        emit_section(&mut file, name, async {
            run_kubectl(&full_args).await
        })
        .await;
    }

    // Section 10: Per-service traffic generator logs
    write_banner(&mut file, "Traffic Generator Logs");
    info!("[Diagnostics] --- Traffic Generator Logs ---");
    for svc in service_names {
        let header = format!("  [{}]", svc);
        match run_kubectl(&[
            "--kubeconfig",
            kubeconfig,
            "logs",
            "-n",
            namespace,
            "-l",
            &format!("{}={}", lattice_common::LABEL_NAME, svc),
            "--tail=50",
        ])
        .await
        {
            Ok(output) => {
                let _ = writeln!(file, "--- {} ---\n{}", svc, output);
                info!("{}\n{}", header, output);
            }
            Err(e) => {
                let msg = format!("ERROR: {}", e);
                let _ = writeln!(file, "--- {} ---\n{}", svc, msg);
                info!("{} {}", header, msg);
            }
        }
    }

    info!("[Diagnostics] ====== END DIAGNOSTIC DUMP ======");
    path
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
            // Print each line to stdout so it shows in CI logs
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

/// Fetch the in-memory service graph from the operator via port-forward.
///
/// Spawns a `kubectl port-forward` to the operator deployment, makes an HTTP
/// GET to `/debug/graph`, and returns the JSON body. The operator image has no
/// curl, so we use reqwest from the test process.
async fn fetch_operator_graph(kubeconfig: &str) -> Result<String, String> {
    use std::process::Stdio;
    use tokio::io::AsyncBufReadExt;

    // Pick an ephemeral local port
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("bind ephemeral port: {e}"))?;
    let local_port = listener.local_addr().unwrap().port();
    drop(listener);

    let mut child = tokio::process::Command::new("kubectl")
        .args([
            "--kubeconfig",
            kubeconfig,
            "port-forward",
            "-n",
            LATTICE_SYSTEM_NAMESPACE,
            "deploy/lattice-operator",
            &format!("{}:8080", local_port),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("spawn port-forward: {e}"))?;

    // Wait for "Forwarding from" line to confirm the tunnel is up
    let stdout = child.stdout.take().unwrap();
    let mut reader = tokio::io::BufReader::new(stdout).lines();
    let ready = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while let Ok(Some(line)) = reader.next_line().await {
            if line.contains("Forwarding from") {
                return Ok(());
            }
        }
        Err("port-forward stdout ended before ready".to_string())
    })
    .await
    .map_err(|_| "port-forward timed out waiting for ready".to_string())?;
    ready?;

    let url = format!("http://127.0.0.1:{}/debug/graph", local_port);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        reqwest::get(&url),
    )
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
