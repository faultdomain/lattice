//! KEDA manifest generation
//!
//! Embeds pre-rendered KEDA manifests from build time.
//! KEDA provides event-driven autoscaling via ScaledObject triggers.

use std::sync::LazyLock;

use super::{namespace_yaml_ambient, split_yaml_documents};

/// Namespace for KEDA components.
pub const KEDA_NAMESPACE: &str = "keda";

/// KEDA operator service account name (derived from chart defaults).
/// Used to construct SPIFFE identity for AuthorizationPolicy.
pub const KEDA_SERVICE_ACCOUNT: &str = "keda-operator";

/// KEDA metrics server service account name.
/// The metrics-apiserver calls keda-operator on port 9666 (gRPC) to fetch metrics.
pub const KEDA_METRICS_SERVICE_ACCOUNT: &str = "keda-operator-metrics-apiserver";

static KEDA_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml_ambient(KEDA_NAMESPACE)];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/keda.yaml"
    ))));
    manifests
});

pub fn keda_version() -> &'static str {
    env!("KEDA_VERSION")
}

pub fn generate_keda() -> &'static [String] {
    &KEDA_MANIFESTS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!keda_version().is_empty());
    }

    #[test]
    fn manifests_are_embedded() {
        let manifests = generate_keda();
        assert!(!manifests.is_empty());
        assert!(manifests[0].contains("kind: Namespace"));
        assert!(
            manifests[0].contains("istio.io/dataplane-mode: ambient"),
            "KEDA namespace must be enrolled in ambient mesh for mTLS identity"
        );
    }
}
