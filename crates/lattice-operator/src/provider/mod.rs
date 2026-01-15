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

mod aws;
mod docker;
mod openstack;
mod proxmox;

pub use aws::AwsProvider;
pub use docker::DockerProvider;
pub use openstack::OpenstackProvider;
pub use proxmox::ProxmoxProvider;

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
    /// Resource spec (untyped) - used for most Kubernetes resources
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<serde_json::Value>,
    /// Resource data - used for ConfigMaps and Secrets
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
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
            data: None,
        }
    }

    /// Set the spec for this manifest
    pub fn with_spec(mut self, spec: serde_json::Value) -> Self {
        self.spec = Some(spec);
        self
    }

    /// Set the data for this manifest (for ConfigMaps/Secrets)
    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
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
/// CAPI Bootstrap API version for KubeadmConfigTemplate
pub const CAPI_BOOTSTRAP_API_VERSION: &str = "bootstrap.cluster.x-k8s.io/v1beta2";
/// CAPI Control Plane API version for KubeadmControlPlane
pub const CAPI_CONTROLPLANE_API_VERSION: &str = "controlplane.cluster.x-k8s.io/v1beta2";
/// RKE2 Bootstrap API version for RKE2ConfigTemplate
pub const RKE2_BOOTSTRAP_API_VERSION: &str = "bootstrap.cluster.x-k8s.io/v1beta1";
/// RKE2 Control Plane API version for RKE2ControlPlane
pub const RKE2_CONTROLPLANE_API_VERSION: &str = "controlplane.cluster.x-k8s.io/v1beta1";

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
    /// Bootstrap mechanism (kubeadm or rke2)
    pub bootstrap: crate::crd::BootstrapProvider,
}

/// Infrastructure provider reference configuration
#[derive(Clone, Debug)]
pub struct InfrastructureRef<'a> {
    /// API group for infrastructure resources (e.g., "infrastructure.cluster.x-k8s.io")
    pub api_group: &'a str,
    /// Full API version (e.g., "infrastructure.cluster.x-k8s.io/v1beta1")
    pub api_version: &'a str,
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
    use crate::crd::BootstrapProvider;

    let deployment_name = format!("{}-md-0", config.name);

    // Bootstrap config template kind and version suffix depend on bootstrap provider
    let (bootstrap_config_kind, version) = match config.bootstrap {
        BootstrapProvider::Kubeadm => (
            "KubeadmConfigTemplate",
            format!("v{}", config.k8s_version.trim_start_matches('v')),
        ),
        BootstrapProvider::Rke2 => (
            "RKE2ConfigTemplate",
            format!("v{}+rke2r1", config.k8s_version.trim_start_matches('v')),
        ),
    };

    let spec = serde_json::json!({
        "clusterName": config.name,
        "replicas": 0,  // ALWAYS 0 - scaling happens after pivot
        "selector": {
            "matchLabels": {}
        },
        "template": {
            "spec": {
                "clusterName": config.name,
                "version": version,
                "bootstrap": {
                    "configRef": {
                        "apiGroup": "bootstrap.cluster.x-k8s.io",
                        "kind": bootstrap_config_kind,
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

/// Generate bootstrap config template for workers (KubeadmConfigTemplate or RKE2ConfigTemplate)
///
/// This dispatches to the appropriate config template generator based on the
/// bootstrap provider configured in the ClusterConfig.
pub fn generate_bootstrap_config_template(config: &ClusterConfig) -> CAPIManifest {
    use crate::crd::BootstrapProvider;

    match config.bootstrap {
        BootstrapProvider::Kubeadm => generate_kubeadm_config_template_impl(config),
        BootstrapProvider::Rke2 => generate_rke2_config_template(config),
    }
}

/// Alias for backwards compatibility
pub fn generate_kubeadm_config_template(config: &ClusterConfig) -> CAPIManifest {
    generate_kubeadm_config_template_impl(config)
}

/// Generate KubeadmConfigTemplate manifest for workers
fn generate_kubeadm_config_template_impl(config: &ClusterConfig) -> CAPIManifest {
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

/// Generate RKE2ConfigTemplate manifest for workers
fn generate_rke2_config_template(config: &ClusterConfig) -> CAPIManifest {
    let template_name = format!("{}-md-0", config.name);

    let spec = serde_json::json!({
        "template": {
            "spec": {
                "agentConfig": {
                    "kubelet": {
                        "extraArgs": [
                            "eviction-hard=nodefs.available<0%,imagefs.available<0%"
                        ]
                    }
                }
            }
        }
    });

    CAPIManifest::new(
        RKE2_BOOTSTRAP_API_VERSION,
        "RKE2ConfigTemplate",
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
    use crate::crd::BootstrapProvider;

    // Control plane kind depends on bootstrap provider
    let cp_kind = match config.bootstrap {
        BootstrapProvider::Kubeadm => "KubeadmControlPlane",
        BootstrapProvider::Rke2 => "RKE2ControlPlane",
    };

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
            "kind": cp_kind,
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

/// Generate control plane resource (KubeadmControlPlane or RKE2ControlPlane)
///
/// This dispatches to the appropriate control plane generator based on the
/// bootstrap provider configured in the ClusterConfig.
pub fn generate_control_plane(
    config: &ClusterConfig,
    infra: &InfrastructureRef,
    cp_config: &ControlPlaneConfig,
) -> CAPIManifest {
    use crate::crd::BootstrapProvider;

    match config.bootstrap {
        BootstrapProvider::Kubeadm => generate_kubeadm_control_plane(config, infra, cp_config),
        BootstrapProvider::Rke2 => generate_rke2_control_plane(config, infra, cp_config),
    }
}

/// Generate KubeadmControlPlane resource
fn generate_kubeadm_control_plane(
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

/// Generate RKE2ControlPlane resource
///
/// RKE2 is FIPS-compliant out of the box and uses a different configuration
/// structure than kubeadm.
fn generate_rke2_control_plane(
    config: &ClusterConfig,
    infra: &InfrastructureRef,
    cp_config: &ControlPlaneConfig,
) -> CAPIManifest {
    let cp_name = format!("{}-control-plane", config.name);

    // RKE2 agent configuration (kubelet settings)
    let agent_config = serde_json::json!({
        "kubelet": {
            "extraArgs": [
                "eviction-hard=nodefs.available<0%,imagefs.available<0%"
            ]
        }
    });

    // Build spec - postRKE2Commands is at the TOP level, not inside agentConfig
    let mut spec = serde_json::json!({
        "replicas": cp_config.replicas,
        "version": format!("v{}+rke2r1", config.k8s_version.trim_start_matches('v')),
        // Use control-plane-endpoint for node registration (via CAPD load balancer)
        "registrationMethod": "control-plane-endpoint",
        // Use machineTemplate.infrastructureRef (the non-deprecated path)
        "machineTemplate": {
            "infrastructureRef": {
                "apiVersion": infra.api_version,
                "kind": infra.machine_template_kind,
                "name": format!("{}-control-plane", config.name)
            }
        },
        "agentConfig": agent_config,
        "serverConfig": {
            "tlsSan": cp_config.cert_sans,
            "cni": "none",  // We use Cilium, not built-in CNI
            // Disable cloud controller - we don't use a cloud provider with CAPD
            "disableComponents": {
                "kubernetesComponents": ["cloudController"]
            },
            // Force FIPS-compliant TLS ciphers - RKE2's BoringCrypto allows X25519
            // but our GOFIPS140 kubectl rejects it
            // Enable anonymous auth so HAProxy can health-check /healthz without credentials
            "kubeAPIServer": {
                "extraArgs": [
                    "anonymous-auth=true",
                    "tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
                ]
            }
        },
        // Required by RKE2ControlPlane CRD - matches the default
        "rolloutStrategy": {
            "type": "RollingUpdate",
            "rollingUpdate": {
                "maxSurge": 1
            }
        }
    });

    // Add postRKE2Commands at the spec level if provided
    if !cp_config.post_kubeadm_commands.is_empty() {
        spec["postRKE2Commands"] = serde_json::json!(cp_config.post_kubeadm_commands);
    }

    CAPIManifest::new(
        RKE2_CONTROLPLANE_API_VERSION,
        "RKE2ControlPlane",
        &cp_name,
        config.namespace,
    )
    .with_labels(config.labels.clone())
    .with_spec(spec)
}

/// Default scripts directory (set by LATTICE_SCRIPTS_DIR env var in container)
const DEFAULT_SCRIPTS_DIR: &str = "/scripts";

/// Get scripts directory - checks runtime env var first, then compile-time, then default
fn get_scripts_dir() -> String {
    if let Ok(dir) = std::env::var("LATTICE_SCRIPTS_DIR") {
        return dir;
    }
    if let Some(dir) = option_env!("LATTICE_SCRIPTS_DIR") {
        return dir.to_string();
    }
    DEFAULT_SCRIPTS_DIR.to_string()
}

/// Load and render the bootstrap script template using minijinja
fn render_bootstrap_script(
    endpoint: &str,
    cluster_name: &str,
    token: &str,
    ca_cert_path: &str,
) -> String {
    let scripts_dir = get_scripts_dir();
    let script_path = format!("{}/bootstrap-cluster.sh", scripts_dir);
    let template = std::fs::read_to_string(&script_path).unwrap_or_else(|e| {
        panic!(
            "Failed to load bootstrap script from {}: {}. Set LATTICE_SCRIPTS_DIR env var.",
            script_path, e
        )
    });

    let mut env = minijinja::Environment::new();
    env.add_template("bootstrap", &template)
        .expect("Invalid bootstrap template");

    let ctx = minijinja::context! {
        endpoint => endpoint,
        cluster_name => cluster_name,
        token => token,
        ca_cert_path => ca_cert_path,
    };

    env.get_template("bootstrap")
        .expect("Template not found")
        .render(ctx)
        .expect("Failed to render bootstrap template")
}

/// Build postKubeadmCommands for agent bootstrap
///
/// This is shared across ALL providers. These are the shell commands that run
/// after kubeadm completes on each control plane node.
///
/// For RKE2, the same commands are used in postRKE2Commands.
/// The commands handle "token already used" errors gracefully by continuing.
pub fn build_post_kubeadm_commands(cluster_name: &str, bootstrap: &BootstrapInfo) -> Vec<String> {
    let mut commands = Vec::new();

    // If cluster has bootstrap info, embed the bootstrap script with substituted variables
    if let (Some(ref endpoint), Some(ref token), Some(ref ca_cert)) = (
        &bootstrap.bootstrap_endpoint,
        &bootstrap.bootstrap_token,
        &bootstrap.ca_cert_pem,
    ) {
        // Write CA cert to temp file
        commands.push(format!(
            r#"cat > /tmp/cell-ca.crt << 'CACERT'
{ca_cert}
CACERT"#
        ));

        // Render script template with variables
        let script = render_bootstrap_script(endpoint, cluster_name, token, "/tmp/cell-ca.crt");

        // Embed the script as a heredoc and execute it
        commands.push(format!(
            r#"bash << 'BOOTSTRAP_SCRIPT'
{script}
BOOTSTRAP_SCRIPT"#
        ));

        // Cleanup CA cert
        commands.push(r#"rm -f /tmp/cell-ca.crt"#.to_string());
    } else {
        // No bootstrap info - just untaint control plane
        commands.push(
            r#"kubectl --kubeconfig=/etc/kubernetes/admin.conf taint nodes --all node-role.kubernetes.io/control-plane:NoSchedule- || true"#
                .to_string(),
        );
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
/// use lattice_operator::provider::{Provider, CAPIManifest, BootstrapInfo};
/// use lattice_operator::crd::{LatticeCluster, ProviderSpec};
/// use lattice_operator::Result;
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
        ProviderType::Proxmox => Ok(Box::new(ProxmoxProvider::with_namespace(namespace))),
        ProviderType::OpenStack => Ok(Box::new(OpenstackProvider::with_namespace(namespace))),
        ProviderType::Aws => Ok(Box::new(AwsProvider::with_namespace(namespace))),
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

    mod bootstrap_provider_manifests {
        use super::*;
        use crate::crd::BootstrapProvider;

        fn test_config(bootstrap: BootstrapProvider) -> ClusterConfig<'static> {
            ClusterConfig {
                name: "test-cluster",
                namespace: "default",
                k8s_version: "1.31.0",
                labels: std::collections::BTreeMap::new(),
                bootstrap,
            }
        }

        fn test_infra() -> InfrastructureRef<'static> {
            InfrastructureRef {
                api_group: "infrastructure.cluster.x-k8s.io",
                api_version: "infrastructure.cluster.x-k8s.io/v1beta1",
                cluster_kind: "DockerCluster",
                machine_template_kind: "DockerMachineTemplate",
            }
        }

        #[test]
        fn kubeadm_generates_kubeadm_control_plane() {
            let config = test_config(BootstrapProvider::Kubeadm);
            let infra = test_infra();
            let cp_config = ControlPlaneConfig {
                replicas: 1,
                cert_sans: vec!["localhost".to_string()],
                post_kubeadm_commands: vec![],
            };

            let manifest = generate_control_plane(&config, &infra, &cp_config);

            assert_eq!(manifest.kind, "KubeadmControlPlane");
            assert_eq!(manifest.api_version, CAPI_CONTROLPLANE_API_VERSION);
        }

        #[test]
        fn rke2_generates_rke2_control_plane() {
            let config = test_config(BootstrapProvider::Rke2);
            let infra = test_infra();
            let cp_config = ControlPlaneConfig {
                replicas: 1,
                cert_sans: vec!["localhost".to_string()],
                post_kubeadm_commands: vec![],
            };

            let manifest = generate_control_plane(&config, &infra, &cp_config);

            assert_eq!(manifest.kind, "RKE2ControlPlane");
            assert_eq!(manifest.api_version, RKE2_CONTROLPLANE_API_VERSION);
        }

        #[test]
        fn kubeadm_generates_kubeadm_config_template() {
            let config = test_config(BootstrapProvider::Kubeadm);

            let manifest = generate_bootstrap_config_template(&config);

            assert_eq!(manifest.kind, "KubeadmConfigTemplate");
            assert_eq!(manifest.api_version, CAPI_BOOTSTRAP_API_VERSION);
        }

        #[test]
        fn rke2_generates_rke2_config_template() {
            let config = test_config(BootstrapProvider::Rke2);

            let manifest = generate_bootstrap_config_template(&config);

            assert_eq!(manifest.kind, "RKE2ConfigTemplate");
            assert_eq!(manifest.api_version, RKE2_BOOTSTRAP_API_VERSION);
        }

        #[test]
        fn kubeadm_cluster_references_kubeadm_control_plane() {
            let config = test_config(BootstrapProvider::Kubeadm);
            let infra = test_infra();

            let manifest = generate_cluster(&config, &infra);
            let spec = manifest.spec.expect("should have spec");

            let cp_kind = spec
                .pointer("/controlPlaneRef/kind")
                .and_then(|v| v.as_str())
                .expect("should have controlPlaneRef.kind");

            assert_eq!(cp_kind, "KubeadmControlPlane");
        }

        #[test]
        fn rke2_cluster_references_rke2_control_plane() {
            let config = test_config(BootstrapProvider::Rke2);
            let infra = test_infra();

            let manifest = generate_cluster(&config, &infra);
            let spec = manifest.spec.expect("should have spec");

            let cp_kind = spec
                .pointer("/controlPlaneRef/kind")
                .and_then(|v| v.as_str())
                .expect("should have controlPlaneRef.kind");

            assert_eq!(cp_kind, "RKE2ControlPlane");
        }

        #[test]
        fn kubeadm_machine_deployment_references_kubeadm_config() {
            let config = test_config(BootstrapProvider::Kubeadm);
            let infra = test_infra();

            let manifest = generate_machine_deployment(&config, &infra);
            let spec = manifest.spec.expect("should have spec");

            let bootstrap_kind = spec
                .pointer("/template/spec/bootstrap/configRef/kind")
                .and_then(|v| v.as_str())
                .expect("should have bootstrap.configRef.kind");

            assert_eq!(bootstrap_kind, "KubeadmConfigTemplate");
        }

        #[test]
        fn rke2_machine_deployment_references_rke2_config() {
            let config = test_config(BootstrapProvider::Rke2);
            let infra = test_infra();

            let manifest = generate_machine_deployment(&config, &infra);
            let spec = manifest.spec.expect("should have spec");

            let bootstrap_kind = spec
                .pointer("/template/spec/bootstrap/configRef/kind")
                .and_then(|v| v.as_str())
                .expect("should have bootstrap.configRef.kind");

            assert_eq!(bootstrap_kind, "RKE2ConfigTemplate");
        }

        #[test]
        fn rke2_control_plane_has_correct_version_suffix() {
            let config = test_config(BootstrapProvider::Rke2);
            let infra = test_infra();
            let cp_config = ControlPlaneConfig {
                replicas: 1,
                cert_sans: vec![],
                post_kubeadm_commands: vec![],
            };

            let manifest = generate_control_plane(&config, &infra, &cp_config);
            let spec = manifest.spec.expect("should have spec");

            let version = spec
                .get("version")
                .and_then(|v| v.as_str())
                .expect("should have version");

            assert!(
                version.ends_with("+rke2r1"),
                "RKE2 version should end with +rke2r1"
            );
            assert!(
                version.starts_with("v1.31.0"),
                "version should start with v1.31.0"
            );
        }

        #[test]
        fn rke2_control_plane_has_cni_none() {
            let config = test_config(BootstrapProvider::Rke2);
            let infra = test_infra();
            let cp_config = ControlPlaneConfig {
                replicas: 1,
                cert_sans: vec![],
                post_kubeadm_commands: vec![],
            };

            let manifest = generate_control_plane(&config, &infra, &cp_config);
            let spec = manifest.spec.expect("should have spec");

            let cni = spec
                .pointer("/serverConfig/cni")
                .and_then(|v| v.as_str())
                .expect("should have serverConfig.cni");

            assert_eq!(cni, "none", "RKE2 should have cni=none (we use Cilium)");
        }
    }
}
