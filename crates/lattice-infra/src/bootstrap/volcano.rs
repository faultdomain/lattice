//! Volcano Helm chart embedding for gang scheduling
//!
//! Provides pre-rendered Volcano manifests for batch workload scheduling.
//! Volcano is always installed as core infrastructure.
//! Includes the Volcano vGPU device plugin for GPU workloads.
//!
//! The Volcano admission webhook is configured to skip `lattice-system`
//! (via `webhooks_namespace_selector_expressions` in the Helm values)
//! so the operator can start before Volcano is ready.

use std::sync::LazyLock;

use super::{namespace_yaml, split_yaml_documents};

static VOLCANO_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml("volcano-system")];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/volcano.yaml"
    ))));

    // Volcano vGPU device plugin (runs alongside Volcano for GPU scheduling)
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/volcano-vgpu-device-plugin.yaml"
    ))));

    manifests
});

pub fn volcano_version() -> &'static str {
    env!("VOLCANO_VERSION")
}

/// Pre-rendered Volcano Helm chart manifests (including vGPU device plugin)
pub fn generate_volcano() -> &'static [String] {
    &VOLCANO_MANIFESTS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!volcano_version().is_empty());
    }

    #[test]
    fn manifests_are_embedded() {
        let m = generate_volcano();
        assert!(!m.is_empty());
    }

    #[test]
    fn namespace_is_first_manifest() {
        let m = generate_volcano();
        assert!(
            m[0].contains("volcano-system"),
            "First manifest should create the volcano-system namespace"
        );
    }

    #[test]
    fn webhook_excludes_lattice_system() {
        let m = generate_volcano();
        let webhook_manifests: Vec<&String> = m
            .iter()
            .filter(|doc| doc.contains("MutatingWebhookConfiguration"))
            .collect();

        // If Volcano has webhook configs, they should exclude lattice-system
        for wh in &webhook_manifests {
            assert!(
                wh.contains("lattice-system"),
                "MutatingWebhookConfiguration should exclude lattice-system namespace"
            );
        }
    }
}
