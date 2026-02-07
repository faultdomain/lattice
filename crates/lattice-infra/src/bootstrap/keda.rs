//! KEDA manifest generation
//!
//! Embeds pre-rendered KEDA manifests from build time.
//! KEDA provides event-driven autoscaling, replacing prometheus-adapter
//! for custom metrics HPA support.

use std::sync::LazyLock;

use super::{namespace_yaml, split_yaml_documents};

/// Namespace for KEDA components.
pub const KEDA_NAMESPACE: &str = "keda";

/// Pre-rendered KEDA manifests with namespace prepended.
static KEDA_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml(KEDA_NAMESPACE)];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/keda.yaml"
    ))));
    manifests
});

/// KEDA version (pinned at build time)
pub fn keda_version() -> &'static str {
    env!("KEDA_VERSION")
}

/// Generate KEDA manifests
///
/// Returns pre-rendered manifests embedded at build time.
pub fn generate_keda() -> &'static [String] {
    &KEDA_MANIFESTS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        let version = keda_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn manifests_are_embedded() {
        let manifests = generate_keda();
        assert!(!manifests.is_empty());
        assert!(manifests[0].contains("kind: Namespace"));
    }
}
