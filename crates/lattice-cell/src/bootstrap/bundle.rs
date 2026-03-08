//! Bootstrap bundle generation
//!
//! The `generate_bootstrap_bundle()` function is the single source of truth
//! for bootstrap manifests. Both the install command (management cluster) and
//! bootstrap webhook (child clusters) call this function.

use kube::CustomResourceExt;
use lattice_common::crd::LatticeCluster;

use super::addons;
use super::errors::BootstrapError;
use super::types::{BootstrapBundleConfig, ManifestGenerator};

/// Generate a complete bootstrap bundle for a cluster
///
/// This is the single source of truth for bootstrap manifests. Both the install command
/// (management cluster) and bootstrap webhook (child clusters) MUST call this function.
/// See [`BootstrapBundleConfig`] for what's included vs deferred.
///
/// Does NOT include parent connection config - that's webhook-specific.
pub async fn generate_bootstrap_bundle<G: ManifestGenerator>(
    generator: &G,
    config: &BootstrapBundleConfig<'_>,
) -> Result<Vec<String>, BootstrapError> {
    // Generate operator + CNI manifests
    let mut manifests = generator
        .generate(
            config.image,
            config.registry_credentials,
            Some(config.cluster_name),
            Some(config.provider),
        )
        .await?;

    // Add Cilium LB-IPAM resources (on-prem providers only)
    if let Some(cidr) = config.lb_cidr {
        let lb_resources = crate::cilium::generate_lb_resources(cidr).map_err(|e| {
            BootstrapError::Internal(format!("failed to generate Cilium LB resources: {}", e))
        })?;
        manifests.extend(lb_resources);
    }

    // Add provider-specific addons (CCM, CSI, storage, autoscaler)
    manifests.extend(addons::generate_for_provider(
        config.provider,
        config.k8s_version,
        config.cluster_name,
        config.autoscaling_enabled,
    ));

    // Add LatticeCluster CRD definition
    let crd_definition = serde_json::to_string(&LatticeCluster::crd()).map_err(|e| {
        BootstrapError::Internal(format!("failed to serialize LatticeCluster CRD: {}", e))
    })?;
    manifests.push(crd_definition);

    // Add LatticeCluster instance
    manifests.push(config.cluster_manifest.to_string());

    Ok(manifests)
}
