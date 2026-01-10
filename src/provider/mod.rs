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
//! ```text
//! let provider = DockerProvider::new();
//! let cluster: LatticeCluster = ...;
//! let manifests = provider.generate_capi_manifests(&cluster).await?;
//! ```

mod docker;

pub use docker::DockerProvider;

use async_trait::async_trait;

use crate::crd::{LatticeCluster, ProviderSpec, ProviderType};
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

/// CAPI Cluster API version (shared across all providers)
/// Updated to v1beta2 as of CAPI v1.11+ (August 2025)
pub const CAPI_CLUSTER_API_VERSION: &str = "cluster.x-k8s.io/v1beta2";
/// CAPI Bootstrap API version for KubeadmConfigTemplate (shared across all providers)
pub const CAPI_BOOTSTRAP_API_VERSION: &str = "bootstrap.cluster.x-k8s.io/v1beta2";
/// CAPI Control Plane API version for KubeadmControlPlane (shared across all providers)
pub const CAPI_CONTROLPLANE_API_VERSION: &str = "controlplane.cluster.x-k8s.io/v1beta2";

/// Common cluster configuration for CAPI manifest generation
#[derive(Clone, Debug)]
pub struct ClusterConfig<'a> {
    /// Cluster name
    pub name: &'a str,
    /// Kubernetes namespace for CAPI resources
    pub namespace: &'a str,
    /// Kubernetes version (e.g., "1.31.0")
    pub k8s_version: &'a str,
    /// Labels to apply to all resources
    pub labels: std::collections::BTreeMap<String, String>,
}

/// Infrastructure provider reference configuration
#[derive(Clone, Debug)]
pub struct InfrastructureRef<'a> {
    /// API group for infrastructure resources (e.g., "infrastructure.cluster.x-k8s.io")
    pub api_group: &'a str,
    /// Kind for the infrastructure cluster (e.g., "DockerCluster")
    pub cluster_kind: &'a str,
    /// Kind for machine templates (e.g., "DockerMachineTemplate")
    pub machine_template_kind: &'a str,
}

/// Control plane specific configuration
#[derive(Clone, Debug)]
pub struct ControlPlaneConfig {
    /// Number of control plane replicas
    pub replicas: u32,
    /// Additional SANs for the API server certificate
    pub cert_sans: Vec<String>,
    /// Commands to run after kubeadm completes
    pub post_kubeadm_commands: Vec<String>,
}

/// Generate a MachineDeployment manifest
///
/// This is shared across ALL providers. MachineDeployment is always created with
/// replicas=0 during initial provisioning. After pivot, the cluster's local
/// controller scales up to match spec.nodes.workers.
pub fn generate_machine_deployment(
    config: &ClusterConfig,
    infra: &InfrastructureRef,
) -> CAPIManifest {
    let deployment_name = format!("{}-md-0", config.name);
    let spec = serde_json::json!({
        "clusterName": config.name,
        "replicas": 0,  // ALWAYS 0 - scaling happens after pivot
        "selector": {
            "matchLabels": {}
        },
        "template": {
            "spec": {
                "clusterName": config.name,
                "version": format!("v{}", config.k8s_version.trim_start_matches('v')),
                "bootstrap": {
                    "configRef": {
                        "apiGroup": "bootstrap.cluster.x-k8s.io",
                        "kind": "KubeadmConfigTemplate",
                        "name": format!("{}-md-0", config.name)
                    }
                },
                "infrastructureRef": {
                    "apiGroup": infra.api_group,
                    "kind": infra.machine_template_kind,
                    "name": format!("{}-md-0", config.name)
                }
            }
        }
    });

    CAPIManifest::new(
        CAPI_CLUSTER_API_VERSION,
        "MachineDeployment",
        &deployment_name,
        config.namespace,
    )
    .with_labels(config.labels.clone())
    .with_spec(spec)
}

/// Generate a KubeadmConfigTemplate manifest for workers
///
/// This is shared across ALL providers since worker kubeadm config is provider-agnostic.
pub fn generate_kubeadm_config_template(config: &ClusterConfig) -> CAPIManifest {
    let template_name = format!("{}-md-0", config.name);

    // In CAPI v1beta2, kubeletExtraArgs is a list of {name, value} objects
    let spec = serde_json::json!({
        "template": {
            "spec": {
                "joinConfiguration": {
                    "nodeRegistration": {
                        "criSocket": "/var/run/containerd/containerd.sock",
                        "kubeletExtraArgs": [
                            {"name": "eviction-hard", "value": "nodefs.available<0%,imagefs.available<0%"}
                        ]
                    }
                }
            }
        }
    });

    CAPIManifest::new(
        CAPI_BOOTSTRAP_API_VERSION,
        "KubeadmConfigTemplate",
        &template_name,
        config.namespace,
    )
    .with_labels(config.labels.clone())
    .with_spec(spec)
}

/// Generate the main CAPI Cluster resource
///
/// This is shared across ALL providers. The only provider-specific part is the
/// infrastructureRef which points to the provider's infrastructure cluster resource
/// (DockerCluster, AWSCluster, etc.)
pub fn generate_cluster(config: &ClusterConfig, infra: &InfrastructureRef) -> CAPIManifest {
    // In CAPI v1beta2, refs use apiGroup (not apiVersion) and no namespace
    let spec = serde_json::json!({
        "clusterNetwork": {
            "pods": {
                "cidrBlocks": ["192.168.0.0/16"]
            },
            "services": {
                "cidrBlocks": ["10.128.0.0/12"]
            }
        },
        "controlPlaneRef": {
            "apiGroup": "controlplane.cluster.x-k8s.io",
            "kind": "KubeadmControlPlane",
            "name": format!("{}-control-plane", config.name)
        },
        "infrastructureRef": {
            "apiGroup": infra.api_group,
            "kind": infra.cluster_kind,
            "name": config.name
        }
    });

    CAPIManifest::new(
        CAPI_CLUSTER_API_VERSION,
        "Cluster",
        config.name,
        config.namespace,
    )
    .with_labels(config.labels.clone())
    .with_spec(spec)
}

/// Generate the KubeadmControlPlane resource
///
/// This is shared across ALL providers. The only provider-specific part is the
/// machineTemplate.infrastructureRef which points to the provider's machine template
/// (DockerMachineTemplate, AWSMachineTemplate, etc.)
pub fn generate_control_plane(
    config: &ClusterConfig,
    infra: &InfrastructureRef,
    cp_config: &ControlPlaneConfig,
) -> CAPIManifest {
    let cp_name = format!("{}-control-plane", config.name);

    // In CAPI v1beta2, extraArgs changed from map to list of {name, value} objects
    let mut kubeadm_config_spec = serde_json::json!({
        "clusterConfiguration": {
            "apiServer": {
                "certSANs": cp_config.cert_sans
            },
            "controllerManager": {
                "extraArgs": [
                    {"name": "bind-address", "value": "0.0.0.0"}
                ]
            },
            "scheduler": {
                "extraArgs": [
                    {"name": "bind-address", "value": "0.0.0.0"}
                ]
            }
        },
        "initConfiguration": {
            "nodeRegistration": {
                "criSocket": "/var/run/containerd/containerd.sock",
                "kubeletExtraArgs": [
                    {"name": "eviction-hard", "value": "nodefs.available<0%,imagefs.available<0%"}
                ]
            }
        },
        "joinConfiguration": {
            "nodeRegistration": {
                "criSocket": "/var/run/containerd/containerd.sock",
                "kubeletExtraArgs": [
                    {"name": "eviction-hard", "value": "nodefs.available<0%,imagefs.available<0%"}
                ]
            }
        }
    });

    if !cp_config.post_kubeadm_commands.is_empty() {
        kubeadm_config_spec["postKubeadmCommands"] =
            serde_json::json!(cp_config.post_kubeadm_commands);
    }

    // In CAPI v1beta2, infrastructureRef is nested under machineTemplate.spec
    let spec = serde_json::json!({
        "replicas": cp_config.replicas,
        "version": format!("v{}", config.k8s_version.trim_start_matches('v')),
        "machineTemplate": {
            "spec": {
                "infrastructureRef": {
                    "apiGroup": infra.api_group,
                    "kind": infra.machine_template_kind,
                    "name": format!("{}-control-plane", config.name)
                }
            }
        },
        "kubeadmConfigSpec": kubeadm_config_spec
    });

    CAPIManifest::new(
        CAPI_CONTROLPLANE_API_VERSION,
        "KubeadmControlPlane",
        &cp_name,
        config.namespace,
    )
    .with_labels(config.labels.clone())
    .with_spec(spec)
}

/// Build postKubeadmCommands for agent bootstrap
///
/// This is shared across ALL providers. These are the shell commands that run
/// after kubeadm completes on each control plane node.
pub fn build_post_kubeadm_commands(cluster_name: &str, bootstrap: &BootstrapInfo) -> Vec<String> {
    let mut commands = Vec::new();

    // Untaint control plane so pods can schedule (all clusters need this)
    commands.push(
        r#"kubectl --kubeconfig=/etc/kubernetes/admin.conf taint nodes --all node-role.kubernetes.io/control-plane:NoSchedule-"#
            .to_string(),
    );

    // If cluster has bootstrap info, fetch and apply manifests from parent
    if let (Some(ref endpoint), Some(ref token), Some(ref ca_cert)) = (
        &bootstrap.bootstrap_endpoint,
        &bootstrap.bootstrap_token,
        &bootstrap.ca_cert_pem,
    ) {
        commands.push(format!(
            r#"echo "Bootstrapping cluster {cluster_name} from {endpoint}""#
        ));

        // Write CA cert to verify TLS connection to parent
        commands.push(format!(
            r#"cat > /tmp/cell-ca.crt << 'CACERT'
{ca_cert}
CACERT"#
        ));

        // Retry fetching manifests until success (with backoff)
        commands.push(format!(
            r#"echo "Fetching bootstrap manifests from parent..."
MANIFEST_FILE=/tmp/bootstrap-manifests.yaml
RETRY_DELAY=5
while true; do
  if curl -sf --cacert /tmp/cell-ca.crt "{endpoint}/api/clusters/{cluster_name}/manifests" \
    -H "Authorization: Bearer {token}" \
    -o "$MANIFEST_FILE"; then
    echo "Successfully fetched bootstrap manifests"
    break
  fi
  echo "Failed to fetch manifests, retrying in ${{RETRY_DELAY}}s..."
  sleep $RETRY_DELAY
  RETRY_DELAY=$((RETRY_DELAY < 60 ? RETRY_DELAY * 2 : 60))
done"#,
        ));

        // Apply manifests with retry
        commands.push(
            r#"echo "Applying bootstrap manifests..."
RETRY_DELAY=5
while true; do
  if kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f /tmp/bootstrap-manifests.yaml; then
    echo "Successfully applied bootstrap manifests"
    break
  fi
  echo "Failed to apply manifests, retrying in ${RETRY_DELAY}s..."
  sleep $RETRY_DELAY
  RETRY_DELAY=$((RETRY_DELAY < 60 ? RETRY_DELAY * 2 : 60))
done"#
                .to_string(),
        );

        // Clean up temp files
        commands.push(r#"rm -f /tmp/cell-ca.crt /tmp/bootstrap-manifests.yaml"#.to_string());
    }

    commands
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

/// Create a provider instance for the given provider type
///
/// This factory function returns the appropriate provider implementation
/// based on the cluster's provider type. The provider is configured with
/// the given namespace for CAPI resources.
///
/// # Arguments
///
/// * `provider_type` - The type of infrastructure provider (Docker, AWS, etc.)
/// * `namespace` - The Kubernetes namespace for CAPI resources
///
/// # Returns
///
/// A boxed provider instance, or an error if the provider type is not supported
pub fn create_provider(provider_type: ProviderType, namespace: &str) -> Result<Box<dyn Provider>> {
    match provider_type {
        ProviderType::Docker => Ok(Box::new(DockerProvider::with_namespace(namespace))),
        ProviderType::Aws => Err(crate::Error::provider(
            "AWS provider not yet implemented".to_string(),
        )),
        ProviderType::Gcp => Err(crate::Error::provider(
            "GCP provider not yet implemented".to_string(),
        )),
        ProviderType::Azure => Err(crate::Error::provider(
            "Azure provider not yet implemented".to_string(),
        )),
    }
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
