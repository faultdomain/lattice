//! Resource distribution for child clusters (cell-side)
//!
//! This module handles fetching resources from the parent cluster
//! to distribute to child clusters.

use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ListParams};
use kube::Client;
use thiserror::Error;
use tracing::debug;

use lattice_common::crd::{CloudProvider, SecretsProvider};
pub use lattice_common::DistributableResources;
use lattice_common::LATTICE_SYSTEM_NAMESPACE;

/// Error type for resource distribution
#[derive(Debug, Error)]
pub enum ResourceError {
    /// Internal error during resource fetching
    #[error("internal error: {0}")]
    Internal(String),
}

/// Fetch all resources to distribute to child clusters.
pub async fn fetch_distributable_resources(
    client: &Client,
) -> Result<DistributableResources, ResourceError> {
    use std::collections::HashSet;

    let lp = ListParams::default();
    let mut secret_names: HashSet<String> = HashSet::new();

    // Fetch CloudProvider CRDs
    let cp_api: Api<CloudProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let cp_list = cp_api
        .list(&lp)
        .await
        .map_err(|e| ResourceError::Internal(format!("failed to list CloudProviders: {}", e)))?;

    let mut cloud_providers = Vec::new();
    for cp in &cp_list.items {
        let yaml = serialize_for_distribution(cp)?;
        cloud_providers.push(yaml);
        if let Some(ref secret_ref) = cp.spec.credentials_secret_ref {
            secret_names.insert(secret_ref.name.clone());
        }
    }

    // Fetch SecretsProvider CRDs
    let sp_api: Api<SecretsProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let sp_list = sp_api
        .list(&lp)
        .await
        .map_err(|e| ResourceError::Internal(format!("failed to list SecretsProviders: {}", e)))?;

    let mut secrets_providers = Vec::new();
    for sp in &sp_list.items {
        let yaml = serialize_for_distribution(sp)?;
        secrets_providers.push(yaml);
        if let Some(ref secret_ref) = sp.spec.credentials_secret_ref {
            secret_names.insert(secret_ref.name.clone());
        }
    }

    // Fetch referenced secrets
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let mut secrets = Vec::new();
    for name in &secret_names {
        match secret_api.get(name).await {
            Ok(secret) => {
                let yaml = serialize_for_distribution(&secret)?;
                secrets.push(yaml);
            }
            Err(kube::Error::Api(e)) if e.code == 404 => {
                debug!(secret = %name, "Referenced secret not found, skipping");
            }
            Err(e) => {
                return Err(ResourceError::Internal(format!(
                    "failed to get secret {}: {}",
                    name, e
                )));
            }
        }
    }

    debug!(
        cloud_providers = cloud_providers.len(),
        secrets_providers = secrets_providers.len(),
        secrets = secrets.len(),
        "fetched distributable resources"
    );

    Ok(DistributableResources {
        cloud_providers,
        secrets_providers,
        secrets,
    })
}

/// Serialize a Kubernetes resource for distribution, stripping cluster-specific metadata
fn serialize_for_distribution<T: serde::Serialize + Clone + kube::ResourceExt>(
    resource: &T,
) -> Result<Vec<u8>, ResourceError> {
    let mut clean = resource.clone();
    lattice_common::kube_utils::strip_export_metadata(clean.meta_mut());

    serde_json::to_string(&clean)
        .map(|s| s.into_bytes())
        .map_err(|e| ResourceError::Internal(format!("failed to serialize resource: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{CloudProviderSpec, CloudProviderType, SecretRef};
    use lattice_common::CAPA_NAMESPACE;

    // =========================================================================
    // serialize_for_distribution Tests
    // =========================================================================

    fn sample_cloud_provider() -> CloudProvider {
        let mut cp = CloudProvider::new(
            "test-provider",
            CloudProviderSpec {
                provider_type: CloudProviderType::Docker,
                region: None,
                credentials_secret_ref: None,
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        );
        // Add metadata that should be stripped
        cp.metadata.namespace = Some(LATTICE_SYSTEM_NAMESPACE.to_string());
        cp.metadata.uid = Some("test-uid-12345".to_string());
        cp.metadata.resource_version = Some("123456".to_string());
        cp.metadata.creation_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
                    .unwrap()
                    .into(),
            ));
        cp
    }

    #[test]
    fn test_serialize_for_distribution_produces_json() {
        let cp = sample_cloud_provider();
        let result = serialize_for_distribution(&cp);
        assert!(result.is_ok());

        let json = String::from_utf8(result.unwrap()).unwrap();
        assert!(json.contains("test-provider"));
        // CloudProviderType uses rename_all = "lowercase", so Docker -> docker
        assert!(json.contains("docker"));
    }

    #[test]
    fn test_serialize_for_distribution_strips_uid() {
        let cp = sample_cloud_provider();
        let result = serialize_for_distribution(&cp).unwrap();
        let json = String::from_utf8(result).unwrap();

        // UID should be stripped
        assert!(!json.contains("test-uid-12345"));
    }

    #[test]
    fn test_serialize_for_distribution_strips_resource_version() {
        let cp = sample_cloud_provider();
        let result = serialize_for_distribution(&cp).unwrap();
        let json = String::from_utf8(result).unwrap();

        // resourceVersion should be stripped
        assert!(!json.contains("resourceVersion"));
    }

    #[test]
    fn test_serialize_for_distribution_with_credentials_ref() {
        let mut cp = sample_cloud_provider();
        cp.spec.credentials_secret_ref = Some(SecretRef {
            name: "my-secret".to_string(),
            namespace: CAPA_NAMESPACE.to_string(),
        });

        let result = serialize_for_distribution(&cp).unwrap();
        let json = String::from_utf8(result).unwrap();

        // Credentials ref should be preserved
        assert!(json.contains("my-secret"));
        assert!(json.contains(CAPA_NAMESPACE));
    }

    #[test]
    fn test_serialize_for_distribution_with_secret() {
        use k8s_openapi::api::core::v1::Secret;
        use std::collections::BTreeMap;

        let mut secret = Secret::default();
        secret.metadata.name = Some("test-secret".to_string());
        secret.metadata.namespace = Some(LATTICE_SYSTEM_NAMESPACE.to_string());
        secret.metadata.uid = Some("secret-uid".to_string());
        secret.metadata.resource_version = Some("999".to_string());

        let mut data = BTreeMap::new();
        data.insert(
            "key".to_string(),
            k8s_openapi::ByteString("value".as_bytes().to_vec()),
        );
        secret.data = Some(data);

        let result = serialize_for_distribution(&secret).unwrap();
        let json = String::from_utf8(result).unwrap();

        // Name should be preserved
        assert!(json.contains("test-secret"));
        // UID and resourceVersion should be stripped
        assert!(!json.contains("secret-uid"));
    }

    // =========================================================================
    // ResourceError Tests
    // =========================================================================

    #[test]
    fn test_resource_error_internal() {
        let err = ResourceError::Internal("test error".to_string());
        assert!(err.to_string().contains("internal error"));
        assert!(err.to_string().contains("test error"));
    }

    // =========================================================================
    // DistributableResources Tests (re-exports from lattice_common)
    // =========================================================================

    #[test]
    fn test_distributable_resources_is_empty() {
        let empty = DistributableResources::default();
        assert!(empty.is_empty());

        let with_cp = DistributableResources {
            cloud_providers: vec![vec![1, 2, 3]],
            ..Default::default()
        };
        assert!(!with_cp.is_empty());
    }

    #[test]
    fn test_distributable_resources_with_secrets_providers() {
        let resources = DistributableResources {
            cloud_providers: vec![],
            secrets_providers: vec![vec![1]],
            secrets: vec![],
        };
        assert!(!resources.is_empty());
    }

    #[test]
    fn test_distributable_resources_with_secrets() {
        let resources = DistributableResources {
            cloud_providers: vec![],
            secrets_providers: vec![],
            secrets: vec![vec![1]],
        };
        assert!(!resources.is_empty());
    }
}
