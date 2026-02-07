//! GPU stack manifest generation
//!
//! Generates NVIDIA GPU Operator and HAMi manifests for GPU-enabled clusters.
//! The GPU Operator bundles NFD, the NVIDIA device plugin, and DCGM exporter.
//! HAMi enables fractional GPU sharing via its scheduler.

use std::sync::Arc;

use tokio::sync::OnceCell;
use tracing::info;

use super::{charts_dir, namespace_yaml, run_helm_template};

/// Cached GPU stack manifests to avoid repeated helm template calls.
static GPU_MANIFESTS: OnceCell<Result<Arc<Vec<String>>, String>> = OnceCell::const_new();

/// NVIDIA GPU Operator version (pinned at build time)
pub fn gpu_operator_version() -> &'static str {
    env!("GPU_OPERATOR_VERSION")
}

/// HAMi version (pinned at build time)
pub fn hami_version() -> &'static str {
    env!("HAMI_VERSION")
}

/// Generate GPU stack manifests (GPU Operator + HAMi) using helm template
///
/// Renders via `helm template` on-demand with caching. The first call executes helm
/// and caches the result; subsequent calls return the cached manifests.
pub async fn generate_gpu_stack() -> Result<Arc<Vec<String>>, String> {
    GPU_MANIFESTS
        .get_or_init(|| async { render_gpu_helm().await.map(Arc::new) })
        .await
        .clone()
}

/// Internal function to render GPU Operator + HAMi manifests via helm template
async fn render_gpu_helm() -> Result<Vec<String>, String> {
    let charts = charts_dir();
    let mut manifests = Vec::new();

    // 1. NVIDIA GPU Operator (bundles NFD + device plugin + DCGM)
    let gpu_op_version = gpu_operator_version();
    let gpu_op_chart = format!("{}/gpu-operator-v{}.tgz", charts, gpu_op_version);

    info!(version = gpu_op_version, "Rendering GPU Operator chart");

    let gpu_op_manifests = run_helm_template(
        "gpu-operator",
        &gpu_op_chart,
        "gpu-operator",
        &[
            "--set",
            "driver.enabled=false",
            "--set",
            "toolkit.enabled=true",
            "--set",
            "devicePlugin.enabled=true",
            "--set",
            "nfd.enabled=true",
            "--set",
            "dcgmExporter.enabled=true",
            "--set",
            "migManager.enabled=false",
            "--set",
            "gfd.enabled=true",
        ],
    )
    .await?;

    manifests.push(namespace_yaml("gpu-operator"));
    manifests.extend(gpu_op_manifests);

    // 2. HAMi (fractional GPU sharing)
    let hami_ver = hami_version();
    let hami_chart = format!("{}/hami-{}.tgz", charts, hami_ver);

    info!(version = hami_ver, "Rendering HAMi chart");

    let hami_manifests = run_helm_template(
        "hami",
        &hami_chart,
        "hami-system",
        &["--set", "scheduler.enabled=true"],
    )
    .await?;

    manifests.push(namespace_yaml("hami-system"));
    manifests.extend(hami_manifests);

    info!(count = manifests.len(), "Rendered GPU stack manifests");
    Ok(manifests)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_operator_version_is_set() {
        let version = gpu_operator_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn hami_version_is_set() {
        let version = hami_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn gpu_namespaces_are_correct() {
        let ns = namespace_yaml("gpu-operator");
        assert!(ns.contains("kind: Namespace"));
        assert!(ns.contains("name: gpu-operator"));

        let ns = namespace_yaml("hami-system");
        assert!(ns.contains("kind: Namespace"));
        assert!(ns.contains("name: hami-system"));
    }
}
