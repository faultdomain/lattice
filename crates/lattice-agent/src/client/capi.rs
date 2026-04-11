//! CAPI installation on the agent cluster.
//!
//! Reads provider type from LatticeCluster CRD, copies credentials,
//! and installs cert-manager + CAPI providers from bundled manifests.

use tracing::{debug, info};

use kube::ResourceExt;
use lattice_capi::installer::{CapiInstaller, CapiProviderConfig, NativeInstaller};
use lattice_common::crd::{InfraProvider, LatticeCluster, ProviderType};
use lattice_core::LATTICE_SYSTEM_NAMESPACE;

use super::config::CAPI_CRD_POLL_INTERVAL;
use super::AgentClient;

impl AgentClient {
    /// Install CAPI and infrastructure provider
    ///
    /// Reads provider type from LatticeCluster CRD, then:
    /// - Copies provider credentials from lattice-system to provider namespace
    /// - Installs cert-manager + CAPI providers from bundled manifests
    pub(super) async fn install_capi(&self) -> Result<String, std::io::Error> {
        use kube::api::ListParams;

        let client = self
            .create_client()
            .await
            .map_err(|e| std::io::Error::other(format!("failed to create K8s client: {}", e)))?;

        let clusters: kube::Api<LatticeCluster> = kube::Api::all(client.clone());
        let list = clusters
            .list(&ListParams::default())
            .await
            .map_err(|e| std::io::Error::other(format!("failed to list LatticeCluster: {}", e)))?;

        let cluster = list
            .items
            .first()
            .ok_or_else(|| std::io::Error::other("no LatticeCluster found"))?;

        let infrastructure = cluster.spec.provider.provider_type();
        let provider_str = infrastructure.to_string();

        info!(infrastructure = %provider_str, "Installing CAPI providers");

        // Create ESO ExternalSecret in the CAPI provider namespace
        if infrastructure != ProviderType::Docker {
            let cloud_providers: kube::Api<InfraProvider> =
                kube::Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
            let cp = cloud_providers
                .get(&cluster.spec.provider_ref)
                .await
                .map_err(|e| {
                    std::io::Error::other(format!(
                        "InfraProvider '{}' not found: {}",
                        cluster.spec.provider_ref, e
                    ))
                })?;

            if let Some(ref credentials) = cp.spec.credentials {
                if let Some(ns) = lattice_capi::installer::infra_provider_namespace(infrastructure)
                {
                    lattice_secret_provider::credentials::ensure_credentials(
                        &client,
                        &cp.name_any(),
                        credentials,
                        cp.spec.credential_data.as_ref(),
                        ns,
                        "lattice-agent",
                    )
                    .await
                    .map_err(|e| {
                        std::io::Error::other(format!("failed to sync credentials to {ns}: {e}"))
                    })?;
                }
            }
        }

        let config = CapiProviderConfig::new(infrastructure)
            .map_err(|e| std::io::Error::other(format!("Failed to create CAPI config: {}", e)))?;
        NativeInstaller::new()
            .ensure(&config)
            .await
            .map_err(|e| std::io::Error::other(format!("CAPI installation failed: {}", e)))?;

        info!(infrastructure = %provider_str, "CAPI providers installed successfully");
        Ok(provider_str)
    }

    /// Wait for CAPI CRDs to be available
    ///
    /// Uses kube-rs to check if the clusters.cluster.x-k8s.io CRD exists.
    /// Returns true if CRD becomes available within timeout_secs.
    pub(super) async fn wait_for_capi_crds(&self, timeout_secs: u64) -> bool {
        use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
        use kube::api::Api;
        use tokio::time::{sleep, Duration};

        let Some(client) = self.create_client_logged("CRD check").await else {
            return false;
        };

        let crds: Api<CustomResourceDefinition> = Api::all(client);

        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout {
            match crds.get("clusters.cluster.x-k8s.io").await {
                Ok(_) => return true,
                Err(_) => {
                    debug!("CAPI CRDs not yet available, waiting...");
                    // 5s base + up to 3s jitter to avoid thundering herd
                    let jitter_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.subsec_millis() as u64 % 3000)
                        .unwrap_or(0);
                    sleep(CAPI_CRD_POLL_INTERVAL + Duration::from_millis(jitter_ms)).await;
                }
            }
        }

        false
    }
}
