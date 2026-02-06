//! Velero manifest generation
//!
//! Generates Velero manifests for backup and restore capabilities.
//! Deployed during cluster provisioning via Helm chart with node-agent
//! DaemonSet for file-level backup and CSI plugin for volume snapshots.

use std::sync::Arc;

use tokio::sync::OnceCell;
use tracing::info;

use super::{charts_dir, namespace_yaml, run_helm_template};

/// Cached Velero manifests to avoid repeated helm template calls.
static VELERO_MANIFESTS: OnceCell<Result<Arc<Vec<String>>, String>> = OnceCell::const_new();

/// Velero version (pinned at build time)
pub fn velero_version() -> &'static str {
    env!("VELERO_VERSION")
}

/// Generate Velero manifests using helm template
///
/// Renders via `helm template` on-demand with caching. The first call executes helm
/// and caches the result; subsequent calls return the cached manifests.
pub async fn generate_velero() -> Result<Arc<Vec<String>>, String> {
    VELERO_MANIFESTS
        .get_or_init(|| async { render_velero_helm().await.map(Arc::new) })
        .await
        .clone()
}

/// Internal function to render Velero manifests via helm template
async fn render_velero_helm() -> Result<Vec<String>, String> {
    let version = velero_version();
    let charts = charts_dir();
    let chart_path = format!("{}/velero-{}.tgz", charts, version);

    info!(version, "Rendering Velero chart");

    let helm_manifests = run_helm_template(
        "velero",
        &chart_path,
        "velero",
        &[
            "--set",
            "deployNodeAgent=true",
            "--set",
            "snapshotsEnabled=true",
            "--set",
            "initContainers=null",
        ],
    )
    .await?;

    let mut manifests = vec![namespace_yaml("velero")];
    manifests.extend(helm_manifests);

    info!(count = manifests.len(), "Rendered Velero manifests");
    Ok(manifests)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        let version = velero_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn test_namespace_is_correct() {
        let ns = namespace_yaml("velero");
        assert!(ns.contains("kind: Namespace"));
        assert!(ns.contains("name: velero"));
    }
}
