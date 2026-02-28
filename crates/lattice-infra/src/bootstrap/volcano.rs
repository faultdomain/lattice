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

use lattice_common::crd::{NetworkTopologyConfig, ProviderType, TopologyDiscoverySpec};

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

/// Generate a topology discovery ConfigMap for the Volcano controller.
///
/// Returns `None` for manual mode (discovery is `None` — user creates HyperNode CRDs directly).
/// For UFM or Label discovery, generates a ConfigMap in `volcano-system` with the
/// discovery configuration that the `network-topology-aware` plugin reads.
pub fn generate_topology_discovery_configmap(
    config: &NetworkTopologyConfig,
    provider: ProviderType,
) -> Option<String> {
    let discovery = config.discovery.as_ref()?;

    let config_yaml = match discovery {
        TopologyDiscoverySpec::Ufm(ufm) => {
            let interval = ufm.interval.as_deref().unwrap_or("10m");
            let skip_verify = if ufm.insecure_skip_verify {
                "\n    insecureSkipVerify: true"
            } else {
                ""
            };
            format!(
                r#"source: ufm
ufm:
    endpoint: "{}"
    credentialSecretRef: "{}"{}
    interval: "{}""#,
                ufm.endpoint, ufm.credential_secret_ref, skip_verify, interval
            )
        }
        TopologyDiscoverySpec::Label(label) => {
            let interval = label.interval.as_deref().unwrap_or("10m");
            let tiers = if label.tiers.is_empty() {
                auto_label_tiers(provider)
            } else {
                label
                    .tiers
                    .iter()
                    .map(|t| format!("    - nodeLabel: \"{}\"", t.node_label))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            format!(
                r#"source: label
label:
    interval: "{}"
    tiers:
{}"#,
                interval, tiers
            )
        }
        _ => return None,
    };

    Some(format!(
        r#"---
apiVersion: v1
kind: ConfigMap
metadata:
  name: volcano-topology-discovery
  namespace: volcano-system
data:
  config.yaml: |
    {}"#,
        config_yaml.replace('\n', "\n    ")
    ))
}

/// Auto-configure label tiers from the cloud provider.
///
/// Cloud providers (AWS, GCP, Azure, OpenStack) get zone + hostname tiers.
/// Local providers (Docker, Proxmox) get hostname only.
/// No region tier — K8s clusters are almost never multi-region.
fn auto_label_tiers(provider: ProviderType) -> String {
    match provider {
        ProviderType::Aws | ProviderType::Gcp | ProviderType::Azure | ProviderType::OpenStack => [
            "    - nodeLabel: \"topology.kubernetes.io/zone\"",
            "    - nodeLabel: \"kubernetes.io/hostname\"",
        ]
        .join("\n"),
        _ => "    - nodeLabel: \"kubernetes.io/hostname\"".to_string(),
    }
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
