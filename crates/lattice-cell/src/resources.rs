//! Resource distribution for child clusters (cell-side)
//!
//! This module handles fetching resources from the parent cluster
//! to distribute to child clusters. Resources are prefixed with the
//! origin cluster name for inherited policies/providers.

use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ListParams, ObjectList};
use kube::{Client, Resource};
use serde::de::DeserializeOwned;
use thiserror::Error;
use tracing::debug;

use lattice_common::crd::{CedarPolicy, CloudProvider, OIDCProvider, SecretsProvider};
pub use lattice_common::DistributableResources;
use lattice_common::{
    INHERITED_LABEL, LATTICE_SYSTEM_NAMESPACE, ORIGINAL_NAME_LABEL, ORIGIN_CLUSTER_LABEL,
};

/// Error type for resource distribution
#[derive(Debug, Error)]
pub enum ResourceError {
    /// Internal error during resource fetching
    #[error("internal error: {0}")]
    Internal(String),
}

/// List CRD resources with graceful 404 handling.
/// Returns None if the CRD is not installed (common on bootstrap clusters).
async fn list_crd_optional<T>(
    api: &Api<T>,
    lp: &ListParams,
    crd_name: &str,
) -> Result<Option<ObjectList<T>>, ResourceError>
where
    T: Clone + DeserializeOwned + std::fmt::Debug,
{
    match api.list(lp).await {
        Ok(list) => Ok(Some(list)),
        Err(kube::Error::Api(e)) if e.code == 404 => {
            debug!("{} CRD not installed, skipping", crd_name);
            Ok(None)
        }
        Err(e) => Err(ResourceError::Internal(format!(
            "failed to list {}s: {}",
            crd_name, e
        ))),
    }
}

/// Fetch all resources to distribute to child clusters.
///
/// # Arguments
/// * `client` - Kubernetes client
/// * `cluster_name` - Name of the current cluster (used for prefixing inherited resources)
pub async fn fetch_distributable_resources(
    client: &Client,
    cluster_name: &str,
) -> Result<DistributableResources, ResourceError> {
    use std::collections::HashSet;

    let lp = ListParams::default();
    let mut secret_names: HashSet<String> = HashSet::new();

    // Fetch CloudProvider CRDs
    let cp_api: Api<CloudProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let mut cloud_providers = Vec::new();
    if let Some(cp_list) = list_crd_optional(&cp_api, &lp, "CloudProvider").await? {
        for cp in &cp_list.items {
            cloud_providers.push(serialize_for_distribution(cp)?);
            if let Some(ref secret_ref) = cp.spec.credentials_secret_ref {
                secret_names.insert(secret_ref.name.clone());
            }
        }
    }

    // Fetch SecretsProvider CRDs
    let sp_api: Api<SecretsProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let mut secrets_providers = Vec::new();
    if let Some(sp_list) = list_crd_optional(&sp_api, &lp, "SecretsProvider").await? {
        for sp in &sp_list.items {
            secrets_providers.push(serialize_for_distribution(sp)?);
            if let Some(ref secret_ref) = sp.spec.credentials_secret_ref {
                secret_names.insert(secret_ref.name.clone());
            }
        }
    }

    // Fetch CedarPolicy CRDs (skip disabled or non-propagating)
    let cedar_api: Api<CedarPolicy> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let mut cedar_policies = Vec::new();
    if let Some(cedar_list) = list_crd_optional(&cedar_api, &lp, "CedarPolicy").await? {
        for policy in cedar_list
            .items
            .iter()
            .filter(|p| p.spec.enabled && p.spec.propagate)
        {
            cedar_policies.push(serialize_inherited_resource(policy, cluster_name)?);
        }
    }

    // Fetch OIDCProvider CRDs (skip non-propagating)
    let oidc_api: Api<OIDCProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let mut oidc_providers = Vec::new();
    if let Some(oidc_list) = list_crd_optional(&oidc_api, &lp, "OIDCProvider").await? {
        for provider in oidc_list.items.iter().filter(|p| p.spec.propagate) {
            oidc_providers.push(serialize_inherited_resource(provider, cluster_name)?);
            if let Some(ref secret_ref) = provider.spec.client_secret {
                secret_names.insert(secret_ref.name.clone());
            }
        }
    }

    // Fetch referenced secrets
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let mut secrets = Vec::new();
    for name in &secret_names {
        match secret_api.get(name).await {
            Ok(secret) => secrets.push(serialize_for_distribution(&secret)?),
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
        cedar_policies = cedar_policies.len(),
        oidc_providers = oidc_providers.len(),
        secrets = secrets.len(),
        "fetched distributable resources"
    );

    Ok(DistributableResources {
        cloud_providers,
        secrets_providers,
        secrets,
        cedar_policies,
        oidc_providers,
    })
}

/// Core serialization logic shared by both distribution functions.
/// Strips metadata and serializes to JSON bytes.
fn serialize_resource_core<T>(resource: &T, resource_name: &str) -> Result<Vec<u8>, ResourceError>
where
    T: serde::Serialize,
{
    serde_json::to_string(resource)
        .map(|s| s.into_bytes())
        .map_err(|e| {
            ResourceError::Internal(format!("failed to serialize {}: {}", resource_name, e))
        })
}

/// Serialize a Kubernetes resource for distribution, stripping cluster-specific metadata
fn serialize_for_distribution<T>(resource: &T) -> Result<Vec<u8>, ResourceError>
where
    T: serde::Serialize + Clone + Resource<DynamicType = ()>,
{
    let mut clean = resource.clone();
    let resource_name = clean
        .meta()
        .name
        .clone()
        .unwrap_or_else(|| "<unnamed>".to_string());
    lattice_common::kube_utils::strip_export_metadata(clean.meta_mut());

    serialize_resource_core(&clean, &resource_name)
}

/// Serialize a resource for distribution with origin cluster prefix and labels.
/// Used for inherited CedarPolicy and OIDCProvider resources.
fn serialize_inherited_resource<T>(
    resource: &T,
    cluster_name: &str,
) -> Result<Vec<u8>, ResourceError>
where
    T: serde::Serialize + Clone + Resource<DynamicType = ()>,
{
    let mut clean = resource.clone();
    let original_name = clean.meta().name.clone().unwrap_or_default();

    // Prefix name with origin cluster: "global-root--admin-access"
    let prefixed_name = format!("{}--{}", cluster_name, original_name);
    clean.meta_mut().name = Some(prefixed_name.clone());

    // Strip cluster-specific metadata
    lattice_common::kube_utils::strip_export_metadata(clean.meta_mut());

    // Add origin labels
    let labels = clean.meta_mut().labels.get_or_insert_with(Default::default);
    labels.insert(ORIGIN_CLUSTER_LABEL.to_string(), cluster_name.to_string());
    labels.insert(ORIGINAL_NAME_LABEL.to_string(), original_name);
    labels.insert(INHERITED_LABEL.to_string(), "true".to_string());

    serialize_resource_core(&clean, &prefixed_name)
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
            secrets_providers: vec![vec![1]],
            ..Default::default()
        };
        assert!(!resources.is_empty());
    }

    #[test]
    fn test_distributable_resources_with_secrets() {
        let resources = DistributableResources {
            secrets: vec![vec![1]],
            ..Default::default()
        };
        assert!(!resources.is_empty());
    }

    #[test]
    fn test_distributable_resources_with_cedar_policies() {
        let resources = DistributableResources {
            cedar_policies: vec![vec![1]],
            ..Default::default()
        };
        assert!(!resources.is_empty());
    }

    #[test]
    fn test_distributable_resources_with_oidc_providers() {
        let resources = DistributableResources {
            oidc_providers: vec![vec![1]],
            ..Default::default()
        };
        assert!(!resources.is_empty());
    }

    // =========================================================================
    // Inherited Resource Serialization Tests
    // =========================================================================

    fn sample_cedar_policy() -> CedarPolicy {
        use lattice_common::crd::CedarPolicySpec;

        let mut policy = CedarPolicy::new(
            "admin-access",
            CedarPolicySpec {
                description: Some("Allow admins".to_string()),
                policies: "permit(principal, action, resource);".to_string(),
                priority: 0,
                enabled: true,
                propagate: true,
            },
        );
        policy.metadata.namespace = Some(LATTICE_SYSTEM_NAMESPACE.to_string());
        policy.metadata.uid = Some("policy-uid-12345".to_string());
        policy
    }

    fn sample_oidc_provider() -> OIDCProvider {
        use lattice_common::crd::OIDCProviderSpec;

        let mut provider = OIDCProvider::new(
            "corporate-idp",
            OIDCProviderSpec {
                issuer_url: "https://idp.example.com".to_string(),
                client_id: "lattice".to_string(),
                client_secret: None,
                username_claim: "sub".to_string(),
                groups_claim: "groups".to_string(),
                username_prefix: None,
                groups_prefix: None,
                audiences: vec![],
                required_claims: vec![],
                ca_bundle: None,
                jwks_refresh_interval_seconds: 3600,
                propagate: true,
                allow_child_override: false,
            },
        );
        provider.metadata.namespace = Some(LATTICE_SYSTEM_NAMESPACE.to_string());
        provider.metadata.uid = Some("provider-uid-12345".to_string());
        provider
    }

    #[test]
    fn test_serialize_inherited_resource_prefixes_name() {
        let policy = sample_cedar_policy();
        let result = serialize_inherited_resource(&policy, "global-root").unwrap();
        let json = String::from_utf8(result).unwrap();

        assert!(json.contains("global-root--admin-access"));
        assert!(!json.contains(r#""name":"admin-access""#));
    }

    #[test]
    fn test_serialize_inherited_resource_adds_origin_labels() {
        let policy = sample_cedar_policy();
        let result = serialize_inherited_resource(&policy, "global-root").unwrap();
        let json = String::from_utf8(result).unwrap();

        assert!(json.contains(ORIGIN_CLUSTER_LABEL));
        assert!(json.contains("global-root"));
        assert!(json.contains(ORIGINAL_NAME_LABEL));
        assert!(json.contains(INHERITED_LABEL));
        assert!(json.contains("\"true\""));
    }

    #[test]
    fn test_serialize_inherited_resource_strips_metadata() {
        let policy = sample_cedar_policy();
        let result = serialize_inherited_resource(&policy, "global-root").unwrap();
        let json = String::from_utf8(result).unwrap();

        assert!(!json.contains("policy-uid-12345"));
    }

    #[test]
    fn test_serialize_inherited_resource_works_for_oidc_provider() {
        let provider = sample_oidc_provider();
        let result = serialize_inherited_resource(&provider, "global-root").unwrap();
        let json = String::from_utf8(result).unwrap();

        assert!(json.contains("global-root--corporate-idp"));
        assert!(json.contains(ORIGIN_CLUSTER_LABEL));
        assert!(json.contains(INHERITED_LABEL));
        assert!(!json.contains("provider-uid-12345"));
    }
}
