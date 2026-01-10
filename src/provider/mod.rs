//! Infrastructure provider abstraction layer
//!
//! This module provides a trait-based abstraction for infrastructure providers
//! that generate CAPI (Cluster API) manifests. Each provider implements the
//! [`Provider`] trait to generate the appropriate manifests for its infrastructure.
//!
//! # Supported Providers
//!
//! - [`DockerProvider`] - Docker/Kind provider for local development
//!
//! # Example
//!
//! ```ignore
//! use lattice::provider::{Provider, DockerProvider};
//! use lattice::crd::LatticeCluster;
//!
//! let provider = DockerProvider::new();
//! let cluster: LatticeCluster = /* ... */;
//! let manifests = provider.generate_capi_manifests(&cluster).await?;
//! ```

mod docker;

pub use docker::DockerProvider;

use async_trait::async_trait;

use crate::crd::{LatticeCluster, ProviderSpec};
use crate::Result;

/// A CAPI manifest represented as an untyped Kubernetes resource
///
/// This struct holds a generic Kubernetes manifest with its API version,
/// kind, metadata, and spec. It can be serialized to YAML for applying
/// to a cluster.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CAPIManifest {
    /// API version (e.g., "cluster.x-k8s.io/v1beta1")
    pub api_version: String,
    /// Kind of resource (e.g., "Cluster", "MachineDeployment")
    pub kind: String,
    /// Resource metadata
    pub metadata: ManifestMetadata,
    /// Resource spec (untyped)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<serde_json::Value>,
}

impl CAPIManifest {
    /// Create a new CAPI manifest
    pub fn new(
        api_version: impl Into<String>,
        kind: impl Into<String>,
        name: impl Into<String>,
        namespace: impl Into<String>,
    ) -> Self {
        Self {
            api_version: api_version.into(),
            kind: kind.into(),
            metadata: ManifestMetadata {
                name: name.into(),
                namespace: Some(namespace.into()),
                labels: None,
                annotations: None,
            },
            spec: None,
        }
    }

    /// Set the spec for this manifest
    pub fn with_spec(mut self, spec: serde_json::Value) -> Self {
        self.spec = Some(spec);
        self
    }

    /// Add labels to the manifest
    pub fn with_labels(mut self, labels: std::collections::BTreeMap<String, String>) -> Self {
        self.metadata.labels = Some(labels);
        self
    }

    /// Serialize the manifest to YAML
    pub fn to_yaml(&self) -> Result<String> {
        serde_yaml::to_string(self).map_err(|e| crate::Error::serialization(e.to_string()))
    }
}

/// Bootstrap information for workload clusters
///
/// This struct contains the information needed for a workload cluster to
/// bootstrap and connect to its parent cell.
#[derive(Clone, Debug, Default)]
pub struct BootstrapInfo {
    /// The parent cell's bootstrap endpoint URL (HTTPS)
    pub bootstrap_endpoint: Option<String>,
    /// One-time bootstrap token for authentication
    pub bootstrap_token: Option<String>,
    /// CA certificate PEM for verifying the cell's TLS certificate
    pub ca_cert_pem: Option<String>,
}

impl BootstrapInfo {
    /// Create new bootstrap info for a workload cluster
    pub fn new(bootstrap_endpoint: String, token: String, ca_cert_pem: String) -> Self {
        Self {
            bootstrap_endpoint: Some(bootstrap_endpoint),
            bootstrap_token: Some(token),
            ca_cert_pem: Some(ca_cert_pem),
        }
    }

    /// Check if bootstrap info is present
    pub fn is_some(&self) -> bool {
        self.bootstrap_token.is_some()
    }
}

/// Metadata for a CAPI manifest
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ManifestMetadata {
    /// Name of the resource
    pub name: String,
    /// Namespace (optional for cluster-scoped resources)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Labels
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<std::collections::BTreeMap<String, String>>,
    /// Annotations
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<std::collections::BTreeMap<String, String>>,
}

/// Infrastructure provider trait for generating CAPI manifests
///
/// Implementations of this trait generate Cluster API manifests for their
/// specific infrastructure provider (Docker, AWS, GCP, Azure, etc.).
///
/// # Example Implementation
///
/// ```ignore
/// use async_trait::async_trait;
/// use lattice::provider::{Provider, CAPIManifest, BootstrapInfo};
/// use lattice::crd::{LatticeCluster, ProviderSpec};
/// use lattice::Result;
///
/// struct MyProvider;
///
/// #[async_trait]
/// impl Provider for MyProvider {
///     async fn generate_capi_manifests(
///         &self,
///         cluster: &LatticeCluster,
///         bootstrap: &BootstrapInfo,
///     ) -> Result<Vec<CAPIManifest>> {
///         // Generate manifests for your infrastructure
///         todo!()
///     }
///
///     async fn validate_spec(&self, spec: &ProviderSpec) -> Result<()> {
///         // Validate provider-specific configuration
///         todo!()
///     }
/// }
/// ```
#[async_trait]
pub trait Provider: Send + Sync {
    /// Generate CAPI manifests for the given cluster
    ///
    /// This method should generate all necessary Cluster API resources to
    /// provision the cluster, including:
    /// - Cluster resource
    /// - Infrastructure-specific cluster resource (e.g., DockerCluster)
    /// - KubeadmControlPlane
    /// - Infrastructure-specific machine templates
    /// - MachineDeployment for workers
    /// - KubeadmConfigTemplate for workers
    ///
    /// # Arguments
    ///
    /// * `cluster` - The LatticeCluster CRD to generate manifests for
    /// * `bootstrap` - Bootstrap information for workload clusters (endpoint, token, etc.)
    ///
    /// # Returns
    ///
    /// A vector of CAPI manifests that can be applied to provision the cluster
    async fn generate_capi_manifests(
        &self,
        cluster: &LatticeCluster,
        bootstrap: &BootstrapInfo,
    ) -> Result<Vec<CAPIManifest>>;

    /// Validate the provider specification
    ///
    /// This method validates that the provider-specific configuration is valid
    /// for this provider type. For example, a Docker provider might validate
    /// that no cloud-specific fields are set.
    ///
    /// # Arguments
    ///
    /// * `spec` - The provider specification to validate
    ///
    /// # Returns
    ///
    /// `Ok(())` if the spec is valid, or an error describing what's wrong
    async fn validate_spec(&self, spec: &ProviderSpec) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    mod capi_manifest {
        use super::*;

        #[test]
        fn test_new_creates_manifest_with_metadata() {
            let manifest = CAPIManifest::new(
                "cluster.x-k8s.io/v1beta1",
                "Cluster",
                "test-cluster",
                "default",
            );

            assert_eq!(manifest.api_version, "cluster.x-k8s.io/v1beta1");
            assert_eq!(manifest.kind, "Cluster");
            assert_eq!(manifest.metadata.name, "test-cluster");
            assert_eq!(manifest.metadata.namespace, Some("default".to_string()));
            assert!(manifest.spec.is_none());
        }

        #[test]
        fn test_with_spec_adds_spec() {
            let spec = serde_json::json!({
                "clusterNetwork": {
                    "pods": { "cidrBlocks": ["192.168.0.0/16"] }
                }
            });

            let manifest = CAPIManifest::new(
                "cluster.x-k8s.io/v1beta1",
                "Cluster",
                "test-cluster",
                "default",
            )
            .with_spec(spec.clone());

            assert_eq!(manifest.spec, Some(spec));
        }

        #[test]
        fn test_with_labels_adds_labels() {
            let mut labels = std::collections::BTreeMap::new();
            labels.insert("app".to_string(), "lattice".to_string());

            let manifest = CAPIManifest::new(
                "cluster.x-k8s.io/v1beta1",
                "Cluster",
                "test-cluster",
                "default",
            )
            .with_labels(labels.clone());

            assert_eq!(manifest.metadata.labels, Some(labels));
        }

        #[test]
        fn test_to_yaml_produces_valid_yaml() {
            let manifest = CAPIManifest::new(
                "cluster.x-k8s.io/v1beta1",
                "Cluster",
                "test-cluster",
                "default",
            )
            .with_spec(serde_json::json!({
                "clusterNetwork": {
                    "pods": { "cidrBlocks": ["192.168.0.0/16"] }
                }
            }));

            let yaml = manifest.to_yaml().expect("should serialize to YAML");
            assert!(yaml.contains("apiVersion: cluster.x-k8s.io/v1beta1"));
            assert!(yaml.contains("kind: Cluster"));
            assert!(yaml.contains("name: test-cluster"));
            assert!(yaml.contains("namespace: default"));
        }

        #[test]
        fn test_manifest_serialization_roundtrip() {
            let manifest = CAPIManifest::new(
                "cluster.x-k8s.io/v1beta1",
                "Cluster",
                "test-cluster",
                "default",
            )
            .with_spec(serde_json::json!({
                "controlPlaneRef": {
                    "apiVersion": "controlplane.cluster.x-k8s.io/v1beta1",
                    "kind": "KubeadmControlPlane",
                    "name": "test-cluster-control-plane"
                }
            }));

            let yaml = manifest.to_yaml().expect("should serialize");
            let parsed: CAPIManifest = serde_yaml::from_str(&yaml).expect("should deserialize");

            assert_eq!(manifest, parsed);
        }
    }
}
