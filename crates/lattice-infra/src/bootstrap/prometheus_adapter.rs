//! Prometheus Adapter manifest generation
//!
//! Generates Prometheus Adapter manifests for custom metrics HPA.
//! Bridges Prometheus metrics to the Kubernetes custom metrics API,
//! enabling HPA to scale on application-specific signals (e.g. vLLM queue depth).

use std::sync::Arc;

use tokio::sync::OnceCell;
use tracing::info;

use super::prometheus::{vmselect_url, MONITORING_NAMESPACE, VMSELECT_PATH, VMSELECT_PORT};
use super::{charts_dir, namespace_yaml, run_helm_template};

/// Cached Prometheus Adapter manifests to avoid repeated helm template calls.
static PROMETHEUS_ADAPTER_MANIFESTS: OnceCell<Result<Arc<Vec<String>>, String>> =
    OnceCell::const_new();

/// Prometheus Adapter version (pinned at build time)
pub fn prometheus_adapter_version() -> &'static str {
    env!("PROMETHEUS_ADAPTER_VERSION")
}

/// Generate Prometheus Adapter manifests using helm template
///
/// Renders via `helm template` on-demand with caching. The first call executes helm
/// and caches the result; subsequent calls return the cached manifests.
pub async fn generate_prometheus_adapter() -> Result<Arc<Vec<String>>, String> {
    PROMETHEUS_ADAPTER_MANIFESTS
        .get_or_init(|| async { render_prometheus_adapter_helm().await.map(Arc::new) })
        .await
        .clone()
}

/// Internal function to render Prometheus Adapter manifests via helm template
async fn render_prometheus_adapter_helm() -> Result<Vec<String>, String> {
    let version = prometheus_adapter_version();
    let charts = charts_dir();
    let chart_path = format!("{}/prometheus-adapter-{}.tgz", charts, version);

    info!(version, "Rendering Prometheus Adapter chart");

    let prom_url = format!("prometheus.url={}", vmselect_url());
    let prom_port = format!("prometheus.port={}", VMSELECT_PORT);
    let prom_path = format!("prometheus.path={}", VMSELECT_PATH);

    let helm_manifests = run_helm_template(
        "prometheus-adapter",
        &chart_path,
        MONITORING_NAMESPACE,
        &[
            "--set",
            &prom_url,
            "--set",
            &prom_port,
            "--set",
            &prom_path,
            "--set",
            "rules.default=false",
            "--set",
            "rules.custom[0].seriesQuery=vllm:num_requests_waiting",
            "--set",
            "rules.custom[0].resources.overrides.namespace.resource=namespace",
            "--set",
            "rules.custom[0].resources.overrides.pod.resource=pod",
            "--set",
            "rules.custom[0].name.matches=^(.*)",
            "--set",
            "rules.custom[0].name.as=${1}",
            "--set",
            "rules.custom[0].metricsQuery=sum(rate(${1}{<<.LabelMatchers>>}[2m])) by (<<.GroupBy>>)",
            "--set",
            "rules.custom[1].seriesQuery=tgi_queue_size",
            "--set",
            "rules.custom[1].resources.overrides.namespace.resource=namespace",
            "--set",
            "rules.custom[1].resources.overrides.pod.resource=pod",
            "--set",
            "rules.custom[1].name.matches=^(.*)",
            "--set",
            "rules.custom[1].name.as=${1}",
            "--set",
            "rules.custom[1].metricsQuery=sum(rate(${1}{<<.LabelMatchers>>}[2m])) by (<<.GroupBy>>)",
        ],
    )
    .await?;

    let mut manifests = vec![namespace_yaml(MONITORING_NAMESPACE)];
    manifests.extend(helm_manifests);

    info!(
        count = manifests.len(),
        "Rendered Prometheus Adapter manifests"
    );
    Ok(manifests)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        let version = prometheus_adapter_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn test_namespace_is_correct() {
        let ns = namespace_yaml("monitoring");
        assert!(ns.contains("kind: Namespace"));
        assert!(ns.contains("name: monitoring"));
    }
}
