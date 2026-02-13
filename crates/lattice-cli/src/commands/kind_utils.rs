//! Shared utilities for kind cluster operations

use std::path::Path;
use std::time::Duration;

use tokio::process::Command;
use tracing::info;

use lattice_common::kube_utils;

use super::CommandErrorExt;
use crate::{Error, Result};

/// Kind cluster config with Docker socket mount for CAPD (Cluster API Provider Docker)
/// and FIPS-compliant TLS cipher suites on the API server.
pub const KIND_CONFIG_WITH_DOCKER: &str = r#"kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: /var/run/docker.sock
    containerPath: /var/run/docker.sock
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        tls-cipher-suites: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        tls-min-version: "VersionTLS12"
"#;

/// Create a kind cluster and export its kubeconfig
pub async fn create_kind_cluster(name: &str, kubeconfig_path: &Path) -> Result<()> {
    info!("Creating kind cluster: {}", name);

    // Delete any existing cluster with the same name (ignore errors)
    let _ = Command::new("kind")
        .args(["delete", "cluster", "--name", name])
        .output()
        .await;

    let mut child = Command::new("kind")
        .args(["create", "cluster", "--name", name, "--config", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(KIND_CONFIG_WITH_DOCKER.as_bytes()).await?;
    }

    let output = child.wait_with_output().await?;
    if !output.status.success() {
        return Err(Error::command_failed(format!(
            "kind create cluster failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Export kubeconfig
    let kubeconfig_str = kubeconfig_path
        .to_str()
        .ok_or_else(|| Error::command_failed("kubeconfig path contains invalid UTF-8"))?;

    let export_output = Command::new("kind")
        .args([
            "export",
            "kubeconfig",
            "--name",
            name,
            "--kubeconfig",
            kubeconfig_str,
        ])
        .output()
        .await?;

    if !export_output.status.success() {
        return Err(Error::command_failed(format!(
            "kind export kubeconfig failed: {}",
            String::from_utf8_lossy(&export_output.stderr)
        )));
    }

    // Wait for nodes to be ready
    let client = kube_utils::create_client(Some(kubeconfig_path))
        .await
        .map_err(|e| Error::command_failed(format!("Failed to create client: {}", e)))?;

    kube_utils::wait_for_nodes_ready(&client, Duration::from_secs(120))
        .await
        .cmd_err()?;

    Ok(())
}

/// Delete a kind cluster
pub async fn delete_kind_cluster(name: &str) -> Result<()> {
    let output = Command::new("kind")
        .args(["delete", "cluster", "--name", name])
        .output()
        .await?;

    if !output.status.success() {
        return Err(Error::command_failed(format!(
            "kind delete cluster failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}
