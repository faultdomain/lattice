//! VictoriaMetrics K8s Stack manifest generation
//!
//! Embeds pre-rendered VictoriaMetrics manifests from build time.

use std::sync::LazyLock;

use super::{namespace_yaml, split_yaml_documents};

/// Well-known service name for the VMCluster components.
/// Used as `fullnameOverride` so all downstream consumers (KEDA,
/// canary controller, KEDA, etc.) reference a stable integration point.
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

/// Pre-rendered VictoriaMetrics manifests with namespace prepended.
static PROMETHEUS_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml(MONITORING_NAMESPACE)];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/victoria-metrics.yaml"
    ))));
    manifests
});

/// VictoriaMetrics K8s Stack version (pinned at build time)
pub fn victoria_metrics_version() -> &'static str {
    env!("VICTORIA_METRICS_VERSION")
}

/// Generate VictoriaMetrics K8s Stack manifests
///
/// Returns pre-rendered manifests embedded at build time.
pub fn generate_prometheus() -> &'static [String] {
    &PROMETHEUS_MANIFESTS
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

    #[test]
    fn manifests_are_embedded() {
        let manifests = generate_prometheus();
        assert!(!manifests.is_empty());
        assert!(manifests[0].contains("kind: Namespace"));
    }
}
