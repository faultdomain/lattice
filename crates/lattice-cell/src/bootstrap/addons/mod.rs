//! Provider-specific addon manifests
//!
//! Generates infrastructure addons based on provider type:
//! - **AWS**: Cloud Controller Manager + EBS CSI Driver
//! - **local-path-provisioner**: PVC support for providers without a CSI driver
//! - **Autoscaler**: CAPI cluster-autoscaler for scaling-enabled pools

pub mod autoscaler;
mod aws;
mod local_path_provisioner;

use lattice_common::capi_namespace;
use lattice_common::crd::ProviderType;

/// Generate provider-specific addon manifests for a cluster.
///
/// This is the single entry point for provider addons. Callers should use this
/// function rather than calling individual addon generators directly.
///
/// # Arguments
/// * `provider` - Infrastructure provider type
/// * `k8s_version` - Kubernetes version (e.g., "1.32.0") for version-matched addons
/// * `cluster_name` - Cluster name for CAPI namespace derivation
/// * `autoscaling_enabled` - Whether any worker pool has autoscaling enabled
///
/// # Returns
/// Vec of JSON manifest strings for the provider's addons
pub fn generate_for_provider(
    provider: ProviderType,
    k8s_version: &str,
    cluster_name: &str,
    autoscaling_enabled: bool,
) -> Vec<String> {
    let mut manifests = match provider {
        ProviderType::Aws => aws::generate_aws_addon_manifests(k8s_version),
        // Providers without a built-in CSI driver need local-path-provisioner
        _ => local_path_provisioner::generate_local_path_provisioner_manifests(),
    };

    // Add cluster-autoscaler when any pool has autoscaling enabled
    if autoscaling_enabled {
        let capi_ns = capi_namespace(cluster_name);
        manifests.push(autoscaler::generate_autoscaler_manifests(&capi_ns));
    }

    manifests
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_provider_generates_ccm_and_csi() {
        let manifests = generate_for_provider(ProviderType::Aws, "1.32.0", "test", false);
        let combined = manifests.join("\n");

        assert!(combined.contains("cloud-controller-manager"));
        assert!(combined.contains("ebs.csi.aws.com"));
    }

    #[test]
    fn non_aws_providers_generate_local_path_provisioner() {
        for provider in [
            ProviderType::Docker,
            ProviderType::Proxmox,
            ProviderType::OpenStack,
        ] {
            let manifests = generate_for_provider(provider, "1.32.0", "test", false);
            let combined = manifests.join("\n");
            assert!(
                combined.contains("local-path-provisioner"),
                "{provider:?} should include local-path-provisioner"
            );
        }
    }

    #[test]
    fn autoscaling_adds_cluster_autoscaler() {
        let manifests = generate_for_provider(ProviderType::Aws, "1.32.0", "my-cluster", true);
        let combined = manifests.join("\n");

        assert!(combined.contains("cluster-autoscaler"));
        assert!(combined.contains("capi-my-cluster"));
    }
}
