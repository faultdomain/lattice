//! VictoriaMetrics K8s Stack manifest generation
//!
//! Generates VictoriaMetrics K8s Stack manifests for HA metrics collection.
//! Deploys VMCluster mode (vmselect/vminsert/vmstorage with 2 replicas each)
//! providing a Prometheus-compatible backend for HPA custom metrics,
//! canary analysis, and observability.

use std::sync::Arc;

use tokio::sync::OnceCell;
use tracing::info;

use super::{charts_dir, namespace_yaml, run_helm_template};

/// Well-known service name for the VMCluster components.
/// Used as `fullnameOverride` so all downstream consumers (prometheus-adapter,
/// canary controller, HPA, etc.) reference a stable integration point.
pub const VMCLUSTER_NAME: &str = "lattice-metrics";

/// Namespace for monitoring components.
pub const MONITORING_NAMESPACE: &str = "monitoring";

/// VMSelect query port (Prometheus-compatible read path).
pub const VMSELECT_PORT: u16 = 8481;

/// VMSelect URL path prefix for Prometheus-compatible queries.
pub const VMSELECT_PATH: &str = "/select/0/prometheus";

/// Build the VMSelect service URL from well-known constants.
/// Returns e.g. `http://lattice-metrics-vmselect.monitoring.svc`
pub fn vmselect_url() -> String {
    format!(
        "http://{}-vmselect.{}.svc",
        VMCLUSTER_NAME, MONITORING_NAMESPACE
    )
}

/// Cached VictoriaMetrics manifests to avoid repeated helm template calls.
static PROMETHEUS_MANIFESTS: OnceCell<Result<Arc<Vec<String>>, String>> = OnceCell::const_new();

/// VictoriaMetrics K8s Stack version (pinned at build time)
pub fn victoria_metrics_version() -> &'static str {
    env!("VICTORIA_METRICS_VERSION")
}

/// Generate VictoriaMetrics K8s Stack manifests using helm template
///
/// Renders via `helm template` on-demand with caching. The first call executes helm
/// and caches the result; subsequent calls return the cached manifests.
pub async fn generate_prometheus() -> Result<Arc<Vec<String>>, String> {
    PROMETHEUS_MANIFESTS
        .get_or_init(|| async { render_prometheus_helm().await.map(Arc::new) })
        .await
        .clone()
}

/// Internal function to render VictoriaMetrics K8s Stack manifests via helm template
async fn render_prometheus_helm() -> Result<Vec<String>, String> {
    let version = victoria_metrics_version();
    let charts = charts_dir();
    let chart_path = format!("{}/victoria-metrics-k8s-stack-{}.tgz", charts, version);

    info!(version, "Rendering VictoriaMetrics K8s Stack chart");

    let fullname_override = format!("fullnameOverride={}", VMCLUSTER_NAME);

    let helm_manifests = run_helm_template(
        "vm",
        &chart_path,
        MONITORING_NAMESPACE,
        &[
            // Static service name for stable integration point
            "--set",
            &fullname_override,
            // VMCluster HA mode
            "--set",
            "vmcluster.enabled=true",
            "--set",
            "vmcluster.spec.retentionPeriod=24h",
            "--set",
            "vmcluster.spec.vmstorage.replicaCount=2",
            "--set",
            "vmcluster.spec.vmselect.replicaCount=2",
            "--set",
            "vmcluster.spec.vminsert.replicaCount=2",
            "--set",
            "vmcluster.spec.replicationFactor=2",
            // Disable VMSingle (using VMCluster instead)
            "--set",
            "vmsingle.enabled=false",
            // Disable unused components
            "--set",
            "grafana.enabled=false",
            "--set",
            "alertmanager.enabled=false",
        ],
    )
    .await?;

    let mut manifests = vec![namespace_yaml(MONITORING_NAMESPACE)];
    manifests.extend(helm_manifests);

    info!(
        count = manifests.len(),
        "Rendered VictoriaMetrics K8s Stack manifests"
    );
    Ok(manifests)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        let version = victoria_metrics_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn test_namespace_is_correct() {
        let ns = namespace_yaml("monitoring");
        assert!(ns.contains("kind: Namespace"));
        assert!(ns.contains("name: monitoring"));
    }
}
