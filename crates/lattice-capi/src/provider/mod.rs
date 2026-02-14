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
pub use openstack::OpenStackProvider;
pub use proxmox::ProxmoxProvider;

use async_trait::async_trait;

use lattice_common::crd::{LatticeCluster, ProviderSpec, ProviderType};
use lattice_common::{Error, Result};

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

    /// Add annotations to the manifest
    pub fn with_annotations(
        mut self,
        annotations: std::collections::BTreeMap<String, String>,
    ) -> Self {
        self.metadata.annotations = Some(annotations);
        self
    }

    /// Add a single annotation to the manifest
    pub fn with_annotation(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let annotations = self
            .metadata
            .annotations
            .get_or_insert_with(Default::default);
        annotations.insert(key.into(), value.into());
        self
    }

    /// Serialize the manifest to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| Error::serialization(e.to_string()))
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

// ============================================================================
// Shared Helper Functions
// ============================================================================

/// Create standard labels for CAPI resources
///
/// All CAPI resources should have these labels for proper resource tracking
/// and cluster association.
pub fn create_cluster_labels(name: &str) -> std::collections::BTreeMap<String, String> {
    let mut labels = std::collections::BTreeMap::new();
    labels.insert(
        "cluster.x-k8s.io/cluster-name".to_string(),
        name.to_string(),
    );
    labels.insert("lattice.dev/cluster".to_string(), name.to_string());
    labels.insert(
        lattice_common::LABEL_MANAGED_BY.to_string(),
        lattice_common::LABEL_MANAGED_BY_LATTICE.to_string(),
    );
    labels
}

/// Validate Kubernetes version format
///
/// Accepts versions in format "1.x.x" or "v1.x.x".
pub fn validate_k8s_version(version: &str) -> Result<()> {
    if !version.starts_with("1.") && !version.starts_with("v1.") {
        return Err(Error::validation(format!(
            "invalid kubernetes version: {version}, expected format: 1.x.x or v1.x.x"
        )));
    }
    Ok(())
}

/// Build certSANs list from cluster spec
///
/// Returns user-provided SANs. Cell LB IP is added at runtime by
/// `get_cell_server_sans()` auto-discovery.
pub fn build_cert_sans(cluster: &LatticeCluster) -> Vec<String> {
    cluster
        .spec
        .provider
        .kubernetes
        .cert_sans
        .clone()
        .unwrap_or_default()
}

/// Extract cluster name from metadata or return validation error
pub fn get_cluster_name(cluster: &LatticeCluster) -> Result<&str> {
    cluster
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| Error::validation("cluster name required"))
}

/// Get required secrets for a provider, using cluster's credentials_secret_ref or defaults
///
/// Returns a vec of (secret_name, namespace) tuples.
pub fn get_provider_secrets(
    cluster: &LatticeCluster,
    default_name: &str,
    default_namespace: &str,
) -> Vec<(String, String)> {
    let secret_ref = cluster.spec.provider.credentials_secret_ref.as_ref();
    vec![(
        secret_ref
            .map(|s| s.name.clone())
            .unwrap_or_else(|| default_name.to_string()),
        secret_ref
            .map(|s| s.namespace.clone())
            .unwrap_or_else(|| default_namespace.to_string()),
    )]
}

// ============================================================================
// Configuration Structs
// ============================================================================

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
    pub bootstrap: lattice_common::crd::BootstrapProvider,
    /// Infrastructure provider type (Docker, Proxmox, etc.)
    pub provider_type: ProviderType,
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
    /// VIP configuration for kube-vip (required for bare-metal/Proxmox)
    pub vip: Option<VipConfig>,
    /// SSH authorized keys for node access
    pub ssh_authorized_keys: Vec<String>,
}

/// Virtual IP configuration for kube-vip
#[derive(Clone, Debug)]
pub struct VipConfig {
    /// VIP address (e.g., "10.0.0.100")
    pub address: String,
    /// Network interface (e.g., "eth0")
    pub interface: String,
    /// kube-vip image (e.g., "ghcr.io/kube-vip/kube-vip:v0.8.0")
    pub image: String,
}

use crate::constants::{
    DEFAULT_KUBE_VIP_IMAGE, DEFAULT_NETWORK_INTERFACE, KUBERNETES_API_SERVER_PORT,
};

impl VipConfig {
    /// Create a new VipConfig with defaults
    pub fn new(address: String, interface: Option<String>, image: Option<String>) -> Self {
        Self {
            address,
            interface: interface.unwrap_or_else(|| DEFAULT_NETWORK_INTERFACE.to_string()),
            image: image.unwrap_or_else(|| DEFAULT_KUBE_VIP_IMAGE.to_string()),
        }
    }
}

/// Generate kube-vip static pod manifest
fn generate_kube_vip_manifest(
    vip: &VipConfig,
    bootstrap: &lattice_common::crd::BootstrapProvider,
) -> Result<String> {
    use k8s_openapi::api::core::v1::{
        Capabilities, Container, EnvVar, HostAlias, HostPathVolumeSource, Pod, PodSpec,
        SecurityContext, Volume, VolumeMount,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use lattice_common::crd::BootstrapProvider;

    let kubeconfig_path = match bootstrap {
        BootstrapProvider::Rke2 => "/etc/rancher/rke2/rke2.yaml",
        BootstrapProvider::Kubeadm => "/etc/kubernetes/super-admin.conf",
    };

    let pod = Pod {
        metadata: ObjectMeta {
            name: Some("kube-vip".to_string()),
            namespace: Some("kube-system".to_string()),
            ..Default::default()
        },
        spec: Some(PodSpec {
            host_network: Some(true),
            host_aliases: Some(vec![HostAlias {
                hostnames: Some(vec!["kubernetes".to_string()]),
                ip: "127.0.0.1".to_string(),
            }]),
            containers: vec![Container {
                name: "kube-vip".to_string(),
                image: Some(vip.image.clone()),
                image_pull_policy: Some("IfNotPresent".to_string()),
                args: Some(vec!["manager".to_string()]),
                env: Some(vec![
                    EnvVar {
                        name: "cp_enable".to_string(),
                        value: Some("true".to_string()),
                        ..Default::default()
                    },
                    EnvVar {
                        name: "vip_interface".to_string(),
                        value: Some(vip.interface.clone()),
                        ..Default::default()
                    },
                    EnvVar {
                        name: "address".to_string(),
                        value: Some(vip.address.clone()),
                        ..Default::default()
                    },
                    EnvVar {
                        name: "port".to_string(),
                        value: Some(KUBERNETES_API_SERVER_PORT.to_string()),
                        ..Default::default()
                    },
                    EnvVar {
                        name: "vip_arp".to_string(),
                        value: Some("true".to_string()),
                        ..Default::default()
                    },
                    EnvVar {
                        name: "vip_leaderelection".to_string(),
                        value: Some("true".to_string()),
                        ..Default::default()
                    },
                    EnvVar {
                        name: "vip_leaseduration".to_string(),
                        value: Some("60".to_string()),
                        ..Default::default()
                    },
                    EnvVar {
                        name: "vip_renewdeadline".to_string(),
                        value: Some("40".to_string()),
                        ..Default::default()
                    },
                    EnvVar {
                        name: "vip_retryperiod".to_string(),
                        value: Some("5".to_string()),
                        ..Default::default()
                    },
                ]),
                security_context: Some(SecurityContext {
                    capabilities: Some(Capabilities {
                        add: Some(vec!["NET_ADMIN".to_string(), "NET_RAW".to_string()]),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                volume_mounts: Some(vec![VolumeMount {
                    name: "kubeconfig".to_string(),
                    mount_path: "/etc/kubernetes/admin.conf".to_string(),
                    ..Default::default()
                }]),
                ..Default::default()
            }],
            volumes: Some(vec![Volume {
                name: "kubeconfig".to_string(),
                host_path: Some(HostPathVolumeSource {
                    path: kubeconfig_path.to_string(),
                    type_: Some("FileOrCreate".to_string()),
                }),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    };

    serde_json::to_string(&pod).map_err(|e| Error::serialization(format!("kube-vip pod: {}", e)))
}

/// Configuration for a worker pool
#[derive(Clone, Debug)]
pub struct WorkerPoolConfig<'a> {
    /// Pool identifier (e.g., "general", "gpu")
    pub pool_id: &'a str,
    /// Worker pool specification
    pub spec: &'a lattice_common::crd::WorkerPoolSpec,
}

/// Get the resource suffix for a pool
///
/// This generates the suffix used for MachineDeployment, ConfigTemplate, and MachineTemplate names.
pub fn pool_resource_suffix(pool_id: &str) -> String {
    format!("pool-{}", pool_id)
}

/// Get the control plane resource name for a cluster
///
/// This is used for KubeadmControlPlane, RKE2ControlPlane, and related resources.
pub fn control_plane_name(cluster_name: &str) -> String {
    format!("{}-control-plane", cluster_name)
}

/// Autoscaler annotation keys
const AUTOSCALER_MIN_SIZE: &str = "cluster.x-k8s.io/cluster-api-autoscaler-node-group-min-size";
const AUTOSCALER_MAX_SIZE: &str = "cluster.x-k8s.io/cluster-api-autoscaler-node-group-max-size";

/// Generate a MachineDeployment manifest for a worker pool
///
/// MachineDeployment is created with replicas=0 during initial provisioning.
/// After pivot, the cluster's local controller scales up (or autoscaler manages it).
pub fn generate_machine_deployment_for_pool(
    config: &ClusterConfig,
    infra: &InfrastructureRef,
    pool: &WorkerPoolConfig,
) -> CAPIManifest {
    use lattice_common::crd::BootstrapProvider;

    let suffix = pool_resource_suffix(pool.pool_id);
    let deployment_name = format!("{}-{}", config.name, suffix);

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
        "replicas": 0,  // Always 0 initially - scaling happens after pivot
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
                        "name": format!("{}-{}", config.name, suffix)
                    }
                },
                "infrastructureRef": {
                    "apiGroup": infra.api_group,
                    "kind": infra.machine_template_kind,
                    "name": format!("{}-{}", config.name, suffix)
                }
            }
        }
    });

    // Build annotations for autoscaler if min/max are set
    let mut annotations = std::collections::BTreeMap::new();
    if let (Some(min), Some(max)) = (pool.spec.min, pool.spec.max) {
        annotations.insert(AUTOSCALER_MIN_SIZE.to_string(), min.to_string());
        annotations.insert(AUTOSCALER_MAX_SIZE.to_string(), max.to_string());
    }

    let mut manifest = CAPIManifest::new(
        CAPI_CLUSTER_API_VERSION,
        "MachineDeployment",
        &deployment_name,
        config.namespace,
    )
    .with_labels(config.labels.clone())
    .with_spec(spec);

    if !annotations.is_empty() {
        manifest.metadata.annotations = Some(annotations);
    }

    manifest
}

/// Generate bootstrap config template for a worker pool
///
/// This dispatches to the appropriate config template generator based on the
/// bootstrap provider configured in the ClusterConfig.
pub fn generate_bootstrap_config_template_for_pool(
    config: &ClusterConfig,
    pool: &WorkerPoolConfig,
) -> CAPIManifest {
    use lattice_common::crd::BootstrapProvider;

    match config.bootstrap {
        BootstrapProvider::Kubeadm => generate_kubeadm_config_template_for_pool(config, pool),
        BootstrapProvider::Rke2 => generate_rke2_config_template_for_pool(config, pool),
    }
}

/// Build kubelet extra args for kubeadm based on provider type
///
/// All providers include the eviction-hard arg to disable aggressive eviction in test.
/// - AWS: Uses cloud-provider=external (AWS CCM sets providerID with correct format)
/// - Other cloud providers: Manual provider-id via cloud-init templating
fn build_kubelet_extra_args(provider_type: ProviderType) -> Vec<serde_json::Value> {
    let mut args = vec![serde_json::json!({
        "name": "eviction-hard",
        "value": "nodefs.available<0%,imagefs.available<0%"
    })];

    if uses_external_cloud_provider(provider_type) {
        args.push(serde_json::json!({
            "name": "cloud-provider",
            "value": "external"
        }));
    } else if needs_manual_provider_id(provider_type) {
        args.push(serde_json::json!({
            "name": "provider-id",
            "value": format!("{}://{{{{ ds.meta_data.instance_id }}}}", provider_type)
        }));
    }

    args
}

/// Build kubelet extra args for RKE2 based on provider type
///
/// RKE2 uses a different format: list of "key=value" strings instead of {name, value} objects.
/// - AWS: Uses cloud-provider=external (AWS CCM sets providerID with correct format)
/// - Other cloud providers: Manual provider-id via cloud-init templating
fn build_rke2_kubelet_extra_args(provider_type: ProviderType) -> Vec<String> {
    let mut args = vec!["eviction-hard=nodefs.available<0%,imagefs.available<0%".to_string()];

    if uses_external_cloud_provider(provider_type) {
        args.push("cloud-provider=external".to_string());
    } else if needs_manual_provider_id(provider_type) {
        args.push(format!(
            "provider-id={}://{{{{ ds.meta_data.instance_id }}}}",
            provider_type
        ));
    }

    args
}

/// Build API server extra args for RKE2 based on provider type
///
/// RKE2 uses a different format: list of "key=value" strings instead of {name, value} objects.
fn build_rke2_api_server_extra_args(provider_type: ProviderType) -> Vec<String> {
    let mut args = vec![
        "anonymous-auth=true".to_string(),
        format!("tls-cipher-suites={FIPS_TLS_CIPHER_SUITES}"),
        format!("tls-min-version={FIPS_TLS_MIN_VERSION}"),
    ];

    if uses_external_cloud_provider(provider_type) {
        args.push("cloud-provider=external".to_string());
    }

    args
}

/// Build controller manager extra args for RKE2 based on provider type
///
/// RKE2 uses a different format: list of "key=value" strings instead of {name, value} objects.
fn build_rke2_controller_manager_extra_args(provider_type: ProviderType) -> Vec<String> {
    let mut args = vec![];

    if uses_external_cloud_provider(provider_type) {
        args.push("cloud-provider=external".to_string());
    }

    args
}

/// Check if a provider uses external cloud controller manager
///
/// Providers that use external CCM need `cloud-provider: external` in:
/// - kubelet args
/// - API server extra args
/// - Controller manager extra args
fn uses_external_cloud_provider(provider_type: ProviderType) -> bool {
    matches!(provider_type, ProviderType::Aws)
}

/// Check if a provider needs manual provider-id via cloud-init templating
///
/// Providers without external CCM need manual provider-id to be set via cloud-init.
/// Docker doesn't need this since there's no cloud provider involved.
fn needs_manual_provider_id(provider_type: ProviderType) -> bool {
    !matches!(provider_type, ProviderType::Docker | ProviderType::Aws)
}

use lattice_common::fips::{FIPS_TLS_CIPHER_SUITES, FIPS_TLS_MIN_VERSION};

/// Build API server extra args based on provider type
fn build_api_server_extra_args(provider_type: ProviderType) -> Vec<serde_json::Value> {
    let mut args = vec![
        serde_json::json!({"name": "bind-address", "value": "0.0.0.0"}),
        serde_json::json!({"name": "tls-cipher-suites", "value": FIPS_TLS_CIPHER_SUITES}),
        serde_json::json!({"name": "tls-min-version", "value": FIPS_TLS_MIN_VERSION}),
    ];

    if uses_external_cloud_provider(provider_type) {
        args.push(serde_json::json!({"name": "cloud-provider", "value": "external"}));
    }

    args
}

/// Build controller manager extra args based on provider type
fn build_controller_manager_extra_args(provider_type: ProviderType) -> Vec<serde_json::Value> {
    let mut args = vec![serde_json::json!({"name": "bind-address", "value": "0.0.0.0"})];

    if uses_external_cloud_provider(provider_type) {
        args.push(serde_json::json!({"name": "cloud-provider", "value": "external"}));
    }

    args
}

/// Get the node name template for kubeadm nodeRegistration
///
/// For AWS, this uses cloud-init datasource to get the EC2 local hostname,
/// which the AWS CCM needs to look up the instance and set the correct providerID.
fn get_node_name_template(provider_type: ProviderType) -> Option<&'static str> {
    match provider_type {
        ProviderType::Aws => Some("{{ ds.meta_data.local_hostname }}"),
        _ => None,
    }
}

/// Build kubeadm nodeRegistration JSON with optional name template for cloud providers.
fn build_node_registration(
    kubelet_extra_args: &[serde_json::Value],
    provider_type: ProviderType,
) -> serde_json::Value {
    let mut reg = serde_json::json!({
        "criSocket": "/var/run/containerd/containerd.sock",
        "kubeletExtraArgs": kubelet_extra_args
    });
    if let Some(name_template) = get_node_name_template(provider_type) {
        reg["name"] = serde_json::json!(name_template);
    }
    reg
}

/// Generate KubeadmConfigTemplate manifest for a worker pool
fn generate_kubeadm_config_template_for_pool(
    config: &ClusterConfig,
    pool: &WorkerPoolConfig,
) -> CAPIManifest {
    let suffix = pool_resource_suffix(pool.pool_id);
    let template_name = format!("{}-{}", config.name, suffix);

    // Build kubelet extra args using the shared function - keep as mutable Vec
    let mut kubelet_extra_args = build_kubelet_extra_args(config.provider_type);

    // Add pool labels to kubelet args
    let mut node_labels = pool.spec.labels.clone();
    node_labels.insert("lattice.dev/pool".to_string(), pool.pool_id.to_string());
    if !node_labels.is_empty() {
        let labels_str: Vec<String> = node_labels
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        kubelet_extra_args
            .push(serde_json::json!({"name": "node-labels", "value": labels_str.join(",")}));
    }

    // Add pool taints to kubelet args
    if !pool.spec.taints.is_empty() {
        let taints_str: Vec<String> = pool
            .spec
            .taints
            .iter()
            .map(|t| {
                if let Some(ref v) = t.value {
                    format!("{}={}:{}", t.key, v, t.effect)
                } else {
                    format!("{}:{}", t.key, t.effect)
                }
            })
            .collect();
        kubelet_extra_args.push(
            serde_json::json!({"name": "register-with-taints", "value": taints_str.join(",")}),
        );
    }

    // Build nodeRegistration with optional name field for cloud providers
    let mut node_registration = serde_json::json!({
        "criSocket": "/var/run/containerd/containerd.sock",
        "kubeletExtraArgs": kubelet_extra_args
    });
    if let Some(name_template) = get_node_name_template(config.provider_type) {
        node_registration["name"] = serde_json::json!(name_template);
    }

    let spec = serde_json::json!({
        "template": {
            "spec": {
                "joinConfiguration": {
                    "nodeRegistration": node_registration
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

/// Generate RKE2ConfigTemplate manifest for a worker pool
fn generate_rke2_config_template_for_pool(
    config: &ClusterConfig,
    pool: &WorkerPoolConfig,
) -> CAPIManifest {
    let suffix = pool_resource_suffix(pool.pool_id);
    let template_name = format!("{}-{}", config.name, suffix);

    // Build kubelet extra args using the shared function
    let mut kubelet_extra_args = build_rke2_kubelet_extra_args(config.provider_type);

    // Add pool labels
    let mut node_labels = pool.spec.labels.clone();
    node_labels.insert("lattice.dev/pool".to_string(), pool.pool_id.to_string());
    if !node_labels.is_empty() {
        let labels_str: Vec<String> = node_labels
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        kubelet_extra_args.push(format!("node-labels={}", labels_str.join(",")));
    }

    // Add pool taints
    if !pool.spec.taints.is_empty() {
        let taints_str: Vec<String> = pool
            .spec
            .taints
            .iter()
            .map(|t| {
                if let Some(ref v) = t.value {
                    format!("{}={}:{}", t.key, v, t.effect)
                } else {
                    format!("{}:{}", t.key, t.effect)
                }
            })
            .collect();
        kubelet_extra_args.push(format!("register-with-taints={}", taints_str.join(",")));
    }

    let spec = serde_json::json!({
        "template": {
            "spec": {
                "agentConfig": {
                    "kubelet": {
                        "extraArgs": kubelet_extra_args
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
    use lattice_common::crd::BootstrapProvider;

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
            "name": control_plane_name(config.name)
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
) -> Result<CAPIManifest> {
    use lattice_common::crd::BootstrapProvider;

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
) -> Result<CAPIManifest> {
    let cp_name = control_plane_name(config.name);

    // Build extra args based on provider type
    let kubelet_extra_args = build_kubelet_extra_args(config.provider_type);
    let api_server_extra_args = build_api_server_extra_args(config.provider_type);
    let controller_manager_extra_args = build_controller_manager_extra_args(config.provider_type);

    // Build nodeRegistration with optional name field for cloud providers
    let node_registration = build_node_registration(&kubelet_extra_args, config.provider_type);

    let mut kubeadm_config_spec = serde_json::json!({
        "clusterConfiguration": {
            "apiServer": {
                "certSANs": cp_config.cert_sans,
                "extraArgs": api_server_extra_args
            },
            "controllerManager": {
                "extraArgs": controller_manager_extra_args
            },
            "scheduler": {
                "extraArgs": [
                    {"name": "bind-address", "value": "0.0.0.0"}
                ]
            }
        },
        "initConfiguration": {
            "nodeRegistration": node_registration.clone()
        },
        "joinConfiguration": {
            "nodeRegistration": node_registration
        }
    });

    if !cp_config.post_kubeadm_commands.is_empty() {
        kubeadm_config_spec["postKubeadmCommands"] =
            serde_json::json!(cp_config.post_kubeadm_commands);
    }

    // Add kube-vip static pod if VIP is configured
    if let Some(ref vip) = cp_config.vip {
        let kube_vip_content = generate_kube_vip_manifest(vip, &config.bootstrap)?;
        kubeadm_config_spec["files"] = serde_json::json!([
            {
                "content": kube_vip_content,
                "owner": "root:root",
                "path": "/etc/kubernetes/manifests/kube-vip.yaml",
                "permissions": "0644"
            }
        ]);

        // Set node-ip before kubeadm starts to prevent VIP registration issue
        // See: https://github.com/kube-vip/kube-vip/issues/741
        let interface = &vip.interface;
        kubeadm_config_spec["preKubeadmCommands"] = serde_json::json!([format!(
            r#"NODE_IP=$(ip -4 -o addr show {iface} | awk '{{print $4}}' | cut -d/ -f1 | head -1) && echo "KUBELET_EXTRA_ARGS=\"--node-ip=$NODE_IP\"" > /etc/default/kubelet"#,
            iface = interface
        )]);
    }

    // Add SSH authorized keys if configured
    if !cp_config.ssh_authorized_keys.is_empty() {
        kubeadm_config_spec["users"] = serde_json::json!([
            {
                "name": "root",
                "sshAuthorizedKeys": cp_config.ssh_authorized_keys
            }
        ]);
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
                    "name": control_plane_name(config.name)
                }
            }
        },
        "kubeadmConfigSpec": kubeadm_config_spec
    });

    Ok(CAPIManifest::new(
        CAPI_CONTROLPLANE_API_VERSION,
        "KubeadmControlPlane",
        &cp_name,
        config.namespace,
    )
    .with_labels(config.labels.clone())
    .with_spec(spec))
}

/// Generate RKE2ControlPlane resource
///
/// RKE2 is FIPS-compliant out of the box and uses a different configuration
/// structure than kubeadm.
fn generate_rke2_control_plane(
    config: &ClusterConfig,
    infra: &InfrastructureRef,
    cp_config: &ControlPlaneConfig,
) -> Result<CAPIManifest> {
    let cp_name = control_plane_name(config.name);

    // Build files array for static pods and SSH keys
    let mut files: Vec<serde_json::Value> = Vec::new();

    // Add kube-vip static pod if VIP is configured
    if let Some(ref vip) = cp_config.vip {
        let kube_vip_content = generate_kube_vip_manifest(vip, &config.bootstrap)?;
        files.push(serde_json::json!({
            "content": kube_vip_content,
            "owner": "root:root",
            "path": "/var/lib/rancher/rke2/agent/pod-manifests/kube-vip.yaml",
            "permissions": "0644"
        }));
    }

    // Add SSH authorized keys via files (RKE2 doesn't have native user support)
    if !cp_config.ssh_authorized_keys.is_empty() {
        files.push(serde_json::json!({
            "content": cp_config.ssh_authorized_keys.join("\n"),
            "owner": "root:root",
            "path": "/root/.ssh/authorized_keys",
            "permissions": "0600"
        }));
    }

    // Build preRKE2Commands to set node-ip before kube-vip adds the VIP
    // This prevents kubelet from registering with the VIP instead of the actual node IP
    // See: https://github.com/kube-vip/kube-vip/issues/741
    let mut pre_rke2_commands: Vec<String> = vec![];
    if let Some(ref vip) = cp_config.vip {
        let interface = &vip.interface;
        // Get the node's actual IP (not the VIP) and write to RKE2 config
        // This runs BEFORE RKE2 starts, so kube-vip hasn't added the VIP yet
        pre_rke2_commands.push(format!(
            r#"NODE_IP=$(ip -4 -o addr show {iface} | awk '{{print $4}}' | cut -d/ -f1 | head -1) && mkdir -p /etc/rancher/rke2 && echo "node-ip: $NODE_IP" >> /etc/rancher/rke2/config.yaml"#,
            iface = interface
        ));
    }

    // Build extra args using the shared functions
    let kubelet_extra_args = build_rke2_kubelet_extra_args(config.provider_type);
    let api_server_extra_args = build_rke2_api_server_extra_args(config.provider_type);
    let controller_manager_extra_args =
        build_rke2_controller_manager_extra_args(config.provider_type);

    let mut spec = serde_json::json!({
        "replicas": cp_config.replicas,
        "version": format!("v{}+rke2r1", config.k8s_version.trim_start_matches('v')),
        "registrationMethod": "control-plane-endpoint",
        "machineTemplate": {
            "infrastructureRef": {
                "apiVersion": infra.api_version,
                "kind": infra.machine_template_kind,
                "name": control_plane_name(config.name)
            }
        },
        "agentConfig": {
            "kubelet": {
                "extraArgs": kubelet_extra_args
            }
        },
        "serverConfig": {
            "tlsSan": cp_config.cert_sans,
            "cni": "none",
            "disableComponents": {
                "kubernetesComponents": ["cloudController"]
            },
            "kubeAPIServer": {
                "extraArgs": api_server_extra_args
            }
        },
        "rolloutStrategy": {
            "type": "RollingUpdate",
            "rollingUpdate": { "maxSurge": 1 }
        }
    });

    // Add controller manager extra args if any (e.g., cloud-provider=external for AWS)
    if !controller_manager_extra_args.is_empty() {
        spec["serverConfig"]["kubeControllerManager"] = serde_json::json!({
            "extraArgs": controller_manager_extra_args
        });
    }

    if !pre_rke2_commands.is_empty() {
        spec["preRKE2Commands"] = serde_json::json!(pre_rke2_commands);
    }

    if !cp_config.post_kubeadm_commands.is_empty() {
        spec["postRKE2Commands"] = serde_json::json!(cp_config.post_kubeadm_commands);
    }

    if !files.is_empty() {
        spec["files"] = serde_json::json!(files);
    }

    Ok(CAPIManifest::new(
        RKE2_CONTROLPLANE_API_VERSION,
        "RKE2ControlPlane",
        &cp_name,
        config.namespace,
    )
    .with_labels(config.labels.clone())
    .with_spec(spec))
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
) -> Result<String> {
    let scripts_dir = get_scripts_dir();
    let script_path = format!("{}/bootstrap-cluster.sh", scripts_dir);
    let template = std::fs::read_to_string(&script_path).map_err(|e| {
        Error::bootstrap(format!(
            "Failed to load bootstrap script from {}: {}. Set LATTICE_SCRIPTS_DIR env var.",
            script_path, e
        ))
    })?;

    let mut env = minijinja::Environment::new();
    env.add_template("bootstrap", &template)
        .map_err(|e| Error::bootstrap(format!("Invalid bootstrap template: {}", e)))?;

    let ctx = minijinja::context! {
        endpoint => endpoint,
        cluster_name => cluster_name,
        token => token,
        ca_cert_path => ca_cert_path,
    };

    env.get_template("bootstrap")
        .map_err(|e| Error::bootstrap(format!("Template not found: {}", e)))?
        .render(ctx)
        .map_err(|e| Error::bootstrap(format!("Failed to render bootstrap template: {}", e)))
}

/// Build postKubeadmCommands for agent bootstrap
///
/// This is shared across ALL providers. These are the shell commands that run
/// after kubeadm completes on each control plane node.
///
/// For RKE2, the same commands are used in postRKE2Commands.
/// The commands handle "token already used" errors gracefully by continuing.
pub fn build_post_kubeadm_commands(
    cluster_name: &str,
    bootstrap: &BootstrapInfo,
) -> Result<Vec<String>> {
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
        let script = render_bootstrap_script(endpoint, cluster_name, token, "/tmp/cell-ca.crt")?;

        // Embed the script as a heredoc and execute it
        commands.push(format!(
            r#"bash << 'BOOTSTRAP_SCRIPT'
{script}
BOOTSTRAP_SCRIPT"#
        ));

        // Cleanup CA cert
        commands.push(r#"rm -f /tmp/cell-ca.crt"#.to_string());
    }

    Ok(commands)
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
/// use lattice_capi::provider::{Provider, CAPIManifest, BootstrapInfo};
/// use lattice_common::crd::{LatticeCluster, ProviderSpec};
/// use lattice_common::Result;
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

    /// Get secrets required by this provider in the cluster's namespace
    ///
    /// Some providers (like Proxmox, OpenStack, AWS) require credential secrets
    /// in the cluster's CAPI namespace. Returns secrets to copy from source
    /// namespace to the cluster namespace before generating CAPI manifests.
    ///
    /// # Returns
    ///
    /// A vector of (secret_name, source_namespace) tuples
    fn required_secrets(&self, _cluster: &LatticeCluster) -> Vec<(String, String)> {
        Vec::new()
    }
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
        ProviderType::Aws => Ok(Box::new(AwsProvider::with_namespace(namespace))),
        ProviderType::Docker => Ok(Box::new(DockerProvider::with_namespace(namespace))),
        ProviderType::OpenStack => Ok(Box::new(OpenStackProvider::with_namespace(namespace))),
        ProviderType::Proxmox => Ok(Box::new(ProxmoxProvider::with_namespace(namespace))),
        ProviderType::Gcp => Err(Error::provider(
            "GCP provider not yet implemented".to_string(),
        )),
        ProviderType::Azure => Err(Error::provider(
            "Azure provider not yet implemented".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::INFRASTRUCTURE_API_GROUP;

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

            let json = manifest.to_json().expect("should serialize");
            let parsed: CAPIManifest = serde_json::from_str(&json).expect("should deserialize");

            assert_eq!(manifest, parsed);
        }
    }

    mod bootstrap_provider_manifests {
        use super::*;
        use lattice_common::crd::BootstrapProvider;

        fn test_config(bootstrap: BootstrapProvider) -> ClusterConfig<'static> {
            ClusterConfig {
                name: "test-cluster",
                namespace: "default",
                k8s_version: "1.32.0",
                labels: std::collections::BTreeMap::new(),
                bootstrap,
                provider_type: ProviderType::Docker,
            }
        }

        fn test_infra() -> InfrastructureRef<'static> {
            InfrastructureRef {
                api_group: INFRASTRUCTURE_API_GROUP,
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
                vip: None,
                ssh_authorized_keys: vec![],
            };

            let manifest = generate_control_plane(&config, &infra, &cp_config)
                .expect("should generate control plane");

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
                vip: None,
                ssh_authorized_keys: vec![],
            };

            let manifest = generate_control_plane(&config, &infra, &cp_config)
                .expect("should generate control plane");

            assert_eq!(manifest.kind, "RKE2ControlPlane");
            assert_eq!(manifest.api_version, RKE2_CONTROLPLANE_API_VERSION);
        }

        fn test_pool() -> WorkerPoolConfig<'static> {
            use lattice_common::crd::WorkerPoolSpec;
            // Leak a Box to get a 'static reference for test purposes
            let spec = Box::leak(Box::new(WorkerPoolSpec {
                replicas: 2,
                ..Default::default()
            }));
            WorkerPoolConfig {
                pool_id: "default",
                spec,
            }
        }

        #[test]
        fn kubeadm_generates_kubeadm_config_template() {
            let config = test_config(BootstrapProvider::Kubeadm);
            let pool = test_pool();

            let manifest = generate_bootstrap_config_template_for_pool(&config, &pool);

            assert_eq!(manifest.kind, "KubeadmConfigTemplate");
            assert_eq!(manifest.api_version, CAPI_BOOTSTRAP_API_VERSION);
            assert_eq!(manifest.metadata.name, "test-cluster-pool-default");
        }

        #[test]
        fn rke2_generates_rke2_config_template() {
            let config = test_config(BootstrapProvider::Rke2);
            let pool = test_pool();

            let manifest = generate_bootstrap_config_template_for_pool(&config, &pool);

            assert_eq!(manifest.kind, "RKE2ConfigTemplate");
            assert_eq!(manifest.api_version, RKE2_BOOTSTRAP_API_VERSION);
            assert_eq!(manifest.metadata.name, "test-cluster-pool-default");
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
            let pool = test_pool();

            let manifest = generate_machine_deployment_for_pool(&config, &infra, &pool);
            let spec = manifest.spec.expect("should have spec");

            let bootstrap_kind = spec
                .pointer("/template/spec/bootstrap/configRef/kind")
                .and_then(|v| v.as_str())
                .expect("should have bootstrap.configRef.kind");

            assert_eq!(bootstrap_kind, "KubeadmConfigTemplate");
            assert_eq!(manifest.metadata.name, "test-cluster-pool-default");
        }

        #[test]
        fn rke2_machine_deployment_references_rke2_config() {
            let config = test_config(BootstrapProvider::Rke2);
            let infra = test_infra();
            let pool = test_pool();

            let manifest = generate_machine_deployment_for_pool(&config, &infra, &pool);
            let spec = manifest.spec.expect("should have spec");

            let bootstrap_kind = spec
                .pointer("/template/spec/bootstrap/configRef/kind")
                .and_then(|v| v.as_str())
                .expect("should have bootstrap.configRef.kind");

            assert_eq!(bootstrap_kind, "RKE2ConfigTemplate");
            assert_eq!(manifest.metadata.name, "test-cluster-pool-default");
        }

        #[test]
        fn machine_deployment_has_autoscaler_annotations_when_min_max_set() {
            use lattice_common::crd::WorkerPoolSpec;

            let config = test_config(BootstrapProvider::Kubeadm);
            let infra = test_infra();
            let spec = Box::leak(Box::new(WorkerPoolSpec {
                replicas: 3,
                min: Some(1),
                max: Some(10),
                ..Default::default()
            }));
            let pool = WorkerPoolConfig {
                pool_id: "autoscaled",
                spec,
            };

            let manifest = generate_machine_deployment_for_pool(&config, &infra, &pool);

            let annotations = manifest
                .metadata
                .annotations
                .expect("should have annotations when autoscaling enabled");
            assert_eq!(annotations.get(AUTOSCALER_MIN_SIZE), Some(&"1".to_string()));
            assert_eq!(
                annotations.get(AUTOSCALER_MAX_SIZE),
                Some(&"10".to_string())
            );
        }

        #[test]
        fn machine_deployment_no_autoscaler_annotations_without_min_max() {
            let config = test_config(BootstrapProvider::Kubeadm);
            let infra = test_infra();
            let pool = test_pool(); // No min/max set

            let manifest = generate_machine_deployment_for_pool(&config, &infra, &pool);

            assert!(
                manifest.metadata.annotations.is_none(),
                "should not have annotations when autoscaling disabled"
            );
        }

        #[test]
        fn rke2_control_plane_has_correct_version_suffix() {
            let config = test_config(BootstrapProvider::Rke2);
            let infra = test_infra();
            let cp_config = ControlPlaneConfig {
                replicas: 1,
                cert_sans: vec![],
                post_kubeadm_commands: vec![],
                vip: None,
                ssh_authorized_keys: vec![],
            };

            let manifest = generate_control_plane(&config, &infra, &cp_config)
                .expect("should generate control plane");
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
                version.starts_with("v1.32.0"),
                "version should start with v1.32.0"
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
                vip: None,
                ssh_authorized_keys: vec![],
            };

            let manifest = generate_control_plane(&config, &infra, &cp_config)
                .expect("should generate control plane");
            let spec = manifest.spec.expect("should have spec");

            let cni = spec
                .pointer("/serverConfig/cni")
                .and_then(|v| v.as_str())
                .expect("should have serverConfig.cni");

            assert_eq!(cni, "none", "RKE2 should have cni=none (we use Cilium)");
        }

        #[test]
        fn kubeadm_control_plane_includes_kube_vip_when_vip_configured() {
            let config = test_config(BootstrapProvider::Kubeadm);
            let infra = test_infra();
            let cp_config = ControlPlaneConfig {
                replicas: 3,
                cert_sans: vec!["10.0.0.100".to_string()],
                post_kubeadm_commands: vec![],
                vip: Some(VipConfig::new("10.0.0.100".to_string(), None, None)),
                ssh_authorized_keys: vec![],
            };

            let manifest = generate_control_plane(&config, &infra, &cp_config)
                .expect("should generate control plane");
            let spec = manifest.spec.expect("should have spec");

            let files = spec
                .pointer("/kubeadmConfigSpec/files")
                .expect("should have files when VIP configured");

            let file = files
                .as_array()
                .expect("files should be array")
                .first()
                .expect("files should not be empty");
            let path = file
                .get("path")
                .expect("file should have path")
                .as_str()
                .expect("path should be a string");
            let content = file
                .get("content")
                .expect("file should have content")
                .as_str()
                .expect("content should be a string");

            assert_eq!(path, "/etc/kubernetes/manifests/kube-vip.yaml");
            assert!(content.contains("kube-vip"));
            assert!(content.contains("10.0.0.100"));
            assert!(content.contains("eth0"));
            assert!(content.contains(DEFAULT_KUBE_VIP_IMAGE));
            // Kubeadm uses super-admin.conf kubeconfig
            assert!(
                content.contains("/etc/kubernetes/super-admin.conf"),
                "Kubeadm kube-vip should use kubeadm kubeconfig path"
            );

            // Verify preKubeadmCommands sets node-ip to prevent VIP registration issue
            // See: https://github.com/kube-vip/kube-vip/issues/741
            let pre_commands = spec
                .pointer("/kubeadmConfigSpec/preKubeadmCommands")
                .expect("should have preKubeadmCommands when VIP configured");
            let pre_commands_arr = pre_commands
                .as_array()
                .expect("preKubeadmCommands should be array");
            assert!(
                !pre_commands_arr.is_empty(),
                "preKubeadmCommands should have commands"
            );
            let cmd = pre_commands_arr[0]
                .as_str()
                .expect("command should be a string");
            assert!(cmd.contains("node-ip"), "should set node-ip for kubelet");
            assert!(
                cmd.contains("eth0"),
                "should use VIP interface for IP detection"
            );
        }

        #[test]
        fn kubeadm_control_plane_no_files_without_vip() {
            let config = test_config(BootstrapProvider::Kubeadm);
            let infra = test_infra();
            let cp_config = ControlPlaneConfig {
                replicas: 1,
                cert_sans: vec![],
                post_kubeadm_commands: vec![],
                vip: None,
                ssh_authorized_keys: vec![],
            };

            let manifest = generate_control_plane(&config, &infra, &cp_config)
                .expect("should generate control plane");
            let spec = manifest.spec.expect("should have spec");

            assert!(
                spec.pointer("/kubeadmConfigSpec/files").is_none(),
                "should not have files when VIP not configured"
            );
            assert!(
                spec.pointer("/kubeadmConfigSpec/preKubeadmCommands")
                    .is_none(),
                "should not have preKubeadmCommands when VIP not configured"
            );
        }

        #[test]
        fn rke2_control_plane_includes_kube_vip_when_vip_configured() {
            let config = test_config(BootstrapProvider::Rke2);
            let infra = test_infra();
            let cp_config = ControlPlaneConfig {
                replicas: 3,
                cert_sans: vec!["10.0.0.100".to_string()],
                post_kubeadm_commands: vec![],
                vip: Some(VipConfig::new("10.0.0.100".to_string(), None, None)),
                ssh_authorized_keys: vec![],
            };

            let manifest = generate_control_plane(&config, &infra, &cp_config)
                .expect("should generate control plane");
            let spec = manifest.spec.expect("should have spec");

            let files = spec
                .pointer("/files")
                .expect("should have files when VIP configured");

            let file = files
                .as_array()
                .expect("files should be array")
                .first()
                .expect("files should not be empty");
            let path = file
                .get("path")
                .expect("file should have path")
                .as_str()
                .expect("path should be a string");
            let content = file
                .get("content")
                .expect("file should have content")
                .as_str()
                .expect("content should be a string");

            // RKE2 uses different path than kubeadm
            assert_eq!(
                path,
                "/var/lib/rancher/rke2/agent/pod-manifests/kube-vip.yaml"
            );
            assert!(content.contains("kube-vip"));
            assert!(content.contains("10.0.0.100"));
            // RKE2 uses different kubeconfig path than kubeadm
            assert!(
                content.contains("/etc/rancher/rke2/rke2.yaml"),
                "RKE2 kube-vip should use RKE2 kubeconfig path"
            );
            assert!(
                !content.contains("/etc/kubernetes/super-admin.conf"),
                "RKE2 kube-vip should not use kubeadm kubeconfig path"
            );

            // Verify preRKE2Commands sets node-ip to prevent VIP registration issue
            // See: https://github.com/kube-vip/kube-vip/issues/741
            let pre_commands = spec
                .pointer("/preRKE2Commands")
                .expect("should have preRKE2Commands when VIP configured");
            let pre_commands_arr = pre_commands
                .as_array()
                .expect("preRKE2Commands should be array");
            assert!(
                !pre_commands_arr.is_empty(),
                "preRKE2Commands should have commands"
            );
            let cmd = pre_commands_arr[0]
                .as_str()
                .expect("command should be a string");
            assert!(cmd.contains("node-ip"), "should set node-ip in RKE2 config");
            assert!(
                cmd.contains("eth0"),
                "should use VIP interface for IP detection"
            );
        }

        #[test]
        fn rke2_control_plane_no_files_without_vip_or_ssh() {
            let config = test_config(BootstrapProvider::Rke2);
            let infra = test_infra();
            let cp_config = ControlPlaneConfig {
                replicas: 1,
                cert_sans: vec![],
                post_kubeadm_commands: vec![],
                vip: None,
                ssh_authorized_keys: vec![],
            };

            let manifest = generate_control_plane(&config, &infra, &cp_config)
                .expect("should generate control plane");
            let spec = manifest.spec.expect("should have spec");

            assert!(
                spec.pointer("/files").is_none(),
                "should not have files when neither VIP nor SSH configured"
            );
            assert!(
                spec.pointer("/preRKE2Commands").is_none(),
                "should not have preRKE2Commands when VIP not configured"
            );
        }

        #[test]
        fn rke2_control_plane_includes_ssh_keys_in_files() {
            let config = test_config(BootstrapProvider::Rke2);
            let infra = test_infra();
            let cp_config = ControlPlaneConfig {
                replicas: 1,
                cert_sans: vec![],
                post_kubeadm_commands: vec![],
                vip: None,
                ssh_authorized_keys: vec![
                    "ssh-ed25519 AAAAC3... user@host".to_string(),
                    "ssh-rsa AAAAB3... other@host".to_string(),
                ],
            };

            let manifest = generate_control_plane(&config, &infra, &cp_config)
                .expect("should generate control plane");
            let spec = manifest.spec.expect("should have spec");

            let files = spec
                .pointer("/files")
                .expect("should have files when SSH keys configured");
            let file = files
                .as_array()
                .expect("files should be an array")
                .first()
                .expect("files should not be empty");

            assert_eq!(file["path"], "/root/.ssh/authorized_keys");
            assert_eq!(file["permissions"], "0600");
            assert_eq!(file["owner"], "root:root");
            assert!(file["content"]
                .as_str()
                .expect("content should be a string")
                .contains("ssh-ed25519"));
            assert!(file["content"]
                .as_str()
                .expect("content should be a string")
                .contains("ssh-rsa"));
        }

        #[test]
        fn rke2_control_plane_combines_vip_and_ssh_files() {
            let config = test_config(BootstrapProvider::Rke2);
            let infra = test_infra();
            let cp_config = ControlPlaneConfig {
                replicas: 1,
                cert_sans: vec!["10.0.0.100".to_string()],
                post_kubeadm_commands: vec![],
                vip: Some(VipConfig::new("10.0.0.100".to_string(), None, None)),
                ssh_authorized_keys: vec!["ssh-ed25519 AAAAC3... user@host".to_string()],
            };

            let manifest = generate_control_plane(&config, &infra, &cp_config)
                .expect("should generate control plane");
            let spec = manifest.spec.expect("should have spec");

            let files = spec.pointer("/files").expect("should have files");
            let files_arr = files.as_array().expect("files should be an array");

            assert_eq!(
                files_arr.len(),
                2,
                "should have both kube-vip and SSH files"
            );

            let paths: Vec<&str> = files_arr
                .iter()
                .map(|f| f["path"].as_str().expect("path should be a string"))
                .collect();
            assert!(paths.contains(&"/var/lib/rancher/rke2/agent/pod-manifests/kube-vip.yaml"));
            assert!(paths.contains(&"/root/.ssh/authorized_keys"));
        }
    }

    mod shared_helpers {
        use super::*;

        #[test]
        fn test_create_cluster_labels() {
            let labels = create_cluster_labels("my-cluster");

            assert_eq!(labels.len(), 3);
            assert_eq!(
                labels.get("cluster.x-k8s.io/cluster-name"),
                Some(&"my-cluster".to_string())
            );
            assert_eq!(
                labels.get("lattice.dev/cluster"),
                Some(&"my-cluster".to_string())
            );
            assert_eq!(
                labels.get(lattice_common::LABEL_MANAGED_BY),
                Some(&lattice_common::LABEL_MANAGED_BY_LATTICE.to_string())
            );
        }

        #[test]
        fn test_validate_k8s_version_valid() {
            assert!(validate_k8s_version("1.32.0").is_ok());
            assert!(validate_k8s_version("1.31.1").is_ok());
            assert!(validate_k8s_version("v1.32.0").is_ok());
            assert!(validate_k8s_version("v1.28.5").is_ok());
        }

        #[test]
        fn test_validate_k8s_version_invalid() {
            assert!(validate_k8s_version("2.0.0").is_err());
            assert!(validate_k8s_version("invalid").is_err());
            assert!(validate_k8s_version("").is_err());
            assert!(validate_k8s_version("0.1.0").is_err());
        }

        #[test]
        fn test_pool_resource_suffix() {
            assert_eq!(pool_resource_suffix("default"), "pool-default");
            assert_eq!(pool_resource_suffix("gpu"), "pool-gpu");
            assert_eq!(
                pool_resource_suffix("memory-optimized"),
                "pool-memory-optimized"
            );
        }

        #[test]
        fn test_uses_external_cloud_provider() {
            assert!(uses_external_cloud_provider(ProviderType::Aws));
            assert!(!uses_external_cloud_provider(ProviderType::Docker));
            assert!(!uses_external_cloud_provider(ProviderType::Proxmox));
            assert!(!uses_external_cloud_provider(ProviderType::OpenStack));
        }

        #[test]
        fn test_needs_manual_provider_id() {
            // Docker and AWS don't need manual provider-id
            assert!(!needs_manual_provider_id(ProviderType::Docker));
            assert!(!needs_manual_provider_id(ProviderType::Aws));
            // Other providers do
            assert!(needs_manual_provider_id(ProviderType::Proxmox));
            assert!(needs_manual_provider_id(ProviderType::OpenStack));
        }

        #[test]
        fn test_get_node_name_template() {
            // AWS uses cloud-init template for node name
            assert_eq!(
                get_node_name_template(ProviderType::Aws),
                Some("{{ ds.meta_data.local_hostname }}")
            );
            // Other providers don't
            assert_eq!(get_node_name_template(ProviderType::Docker), None);
            assert_eq!(get_node_name_template(ProviderType::Proxmox), None);
            assert_eq!(get_node_name_template(ProviderType::OpenStack), None);
        }

        #[test]
        fn test_build_kubelet_extra_args_docker() {
            let args = build_kubelet_extra_args(ProviderType::Docker);
            // Docker only has eviction-hard
            assert_eq!(args.len(), 1);
            assert!(args[0]["name"].as_str().unwrap().contains("eviction-hard"));
        }

        #[test]
        fn test_build_kubelet_extra_args_aws() {
            let args = build_kubelet_extra_args(ProviderType::Aws);
            // AWS has eviction-hard + cloud-provider=external
            assert_eq!(args.len(), 2);
            let cloud_provider_arg = args
                .iter()
                .find(|a| a["name"].as_str() == Some("cloud-provider"));
            assert!(cloud_provider_arg.is_some());
            assert_eq!(
                cloud_provider_arg.unwrap()["value"].as_str(),
                Some("external")
            );
        }

        #[test]
        fn test_build_kubelet_extra_args_proxmox() {
            let args = build_kubelet_extra_args(ProviderType::Proxmox);
            // Proxmox has eviction-hard + provider-id template
            assert_eq!(args.len(), 2);
            let provider_id_arg = args
                .iter()
                .find(|a| a["name"].as_str() == Some("provider-id"));
            assert!(provider_id_arg.is_some());
            assert!(provider_id_arg.unwrap()["value"]
                .as_str()
                .unwrap()
                .contains("proxmox://"));
        }

        #[test]
        fn test_build_rke2_kubelet_extra_args_docker() {
            let args = build_rke2_kubelet_extra_args(ProviderType::Docker);
            assert_eq!(args.len(), 1);
            assert!(args[0].contains("eviction-hard"));
        }

        #[test]
        fn test_build_rke2_kubelet_extra_args_aws() {
            let args = build_rke2_kubelet_extra_args(ProviderType::Aws);
            assert_eq!(args.len(), 2);
            assert!(args.iter().any(|a| a == "cloud-provider=external"));
        }

        #[test]
        fn test_build_api_server_extra_args_docker() {
            let args = build_api_server_extra_args(ProviderType::Docker);
            assert_eq!(args.len(), 3);
            assert!(args
                .iter()
                .any(|a| a["name"].as_str() == Some("bind-address")));
            assert!(args
                .iter()
                .any(|a| a["name"].as_str() == Some("tls-cipher-suites")));
            assert!(args
                .iter()
                .any(|a| a["name"].as_str() == Some("tls-min-version")));
        }

        #[test]
        fn test_build_api_server_extra_args_aws() {
            let args = build_api_server_extra_args(ProviderType::Aws);
            assert_eq!(args.len(), 4);
            assert!(args
                .iter()
                .any(|a| a["name"].as_str() == Some("cloud-provider")));
            assert!(args
                .iter()
                .any(|a| a["name"].as_str() == Some("tls-cipher-suites")));
            assert!(args
                .iter()
                .any(|a| a["name"].as_str() == Some("tls-min-version")));
        }

        #[test]
        fn kubeadm_api_server_has_fips_tls_config() {
            let args = build_api_server_extra_args(ProviderType::Docker);
            let cipher_arg = args
                .iter()
                .find(|a| a["name"].as_str() == Some("tls-cipher-suites"))
                .expect(
                    "kubeadm API server args must include tls-cipher-suites for FIPS compliance",
                );
            let value = cipher_arg["value"].as_str().unwrap();
            assert!(value.contains("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"));
            assert!(value.contains("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"));

            let min_version = args
                .iter()
                .find(|a| a["name"].as_str() == Some("tls-min-version"))
                .expect("kubeadm API server args must include tls-min-version for FIPS compliance");
            assert_eq!(min_version["value"].as_str(), Some("VersionTLS12"));
        }

        #[test]
        fn test_build_controller_manager_extra_args_docker() {
            let args = build_controller_manager_extra_args(ProviderType::Docker);
            assert_eq!(args.len(), 1);
            assert!(args[0]["name"].as_str() == Some("bind-address"));
        }

        #[test]
        fn test_build_controller_manager_extra_args_aws() {
            let args = build_controller_manager_extra_args(ProviderType::Aws);
            assert_eq!(args.len(), 2);
            assert!(args
                .iter()
                .any(|a| a["name"].as_str() == Some("cloud-provider")));
        }

        #[test]
        fn test_build_rke2_api_server_extra_args_docker() {
            let args = build_rke2_api_server_extra_args(ProviderType::Docker);
            assert_eq!(args.len(), 3);
            assert!(args.iter().any(|a| a.contains("anonymous-auth=true")));
            assert!(args.iter().any(|a| a.contains("tls-cipher-suites")));
            assert!(args.iter().any(|a| a.contains("tls-min-version")));
        }

        #[test]
        fn test_build_rke2_api_server_extra_args_aws() {
            let args = build_rke2_api_server_extra_args(ProviderType::Aws);
            assert_eq!(args.len(), 4);
            assert!(args.iter().any(|a| a == "cloud-provider=external"));
        }

        #[test]
        fn test_build_rke2_controller_manager_extra_args_docker() {
            let args = build_rke2_controller_manager_extra_args(ProviderType::Docker);
            assert!(args.is_empty());
        }

        #[test]
        fn test_build_rke2_controller_manager_extra_args_aws() {
            let args = build_rke2_controller_manager_extra_args(ProviderType::Aws);
            assert_eq!(args.len(), 1);
            assert!(args.iter().any(|a| a == "cloud-provider=external"));
        }

        #[test]
        fn test_vip_config_new_with_defaults() {
            let vip = VipConfig::new("10.0.0.100".to_string(), None, None);
            assert_eq!(vip.address, "10.0.0.100");
            assert_eq!(vip.interface, "eth0");
            assert_eq!(vip.image, DEFAULT_KUBE_VIP_IMAGE);
        }

        #[test]
        fn test_vip_config_new_with_custom_values() {
            let vip = VipConfig::new(
                "192.168.1.100".to_string(),
                Some("ens192".to_string()),
                Some("custom-image:v1".to_string()),
            );
            assert_eq!(vip.address, "192.168.1.100");
            assert_eq!(vip.interface, "ens192");
            assert_eq!(vip.image, "custom-image:v1");
        }

        #[test]
        fn test_bootstrap_info_is_some() {
            let empty = BootstrapInfo::default();
            assert!(!empty.is_some());

            let with_token = BootstrapInfo {
                bootstrap_token: Some("token".to_string()),
                ..Default::default()
            };
            assert!(with_token.is_some());
        }

        #[test]
        fn test_bootstrap_info_new() {
            let info = BootstrapInfo::new(
                "https://cell:8080".to_string(),
                "token123".to_string(),
                "-----BEGIN CERTIFICATE-----".to_string(),
            );
            assert_eq!(
                info.bootstrap_endpoint,
                Some("https://cell:8080".to_string())
            );
            assert_eq!(info.bootstrap_token, Some("token123".to_string()));
            assert_eq!(
                info.ca_cert_pem,
                Some("-----BEGIN CERTIFICATE-----".to_string())
            );
            assert!(info.is_some());
        }

        #[test]
        fn test_capi_manifest_with_data() {
            let data = serde_json::json!({"key": "value"});
            let manifest =
                CAPIManifest::new("v1", "Secret", "my-secret", "default").with_data(data.clone());

            assert_eq!(manifest.data, Some(data));
            assert!(manifest.spec.is_none());
        }
    }

    mod create_provider {
        use super::*;

        #[test]
        fn test_create_provider_aws() {
            let provider = create_provider(ProviderType::Aws, "capi-system");
            assert!(provider.is_ok());
        }

        #[test]
        fn test_create_provider_docker() {
            let provider = create_provider(ProviderType::Docker, "capi-system");
            assert!(provider.is_ok());
        }

        #[test]
        fn test_create_provider_openstack() {
            let provider = create_provider(ProviderType::OpenStack, "capi-system");
            assert!(provider.is_ok());
        }

        #[test]
        fn test_create_provider_proxmox() {
            let provider = create_provider(ProviderType::Proxmox, "capi-system");
            assert!(provider.is_ok());
        }

        #[test]
        fn test_create_provider_gcp_not_implemented() {
            let result = create_provider(ProviderType::Gcp, "capi-system");
            match result {
                Ok(_) => panic!("expected error"),
                Err(e) => assert!(e.to_string().contains("GCP")),
            }
        }

        #[test]
        fn test_create_provider_azure_not_implemented() {
            let result = create_provider(ProviderType::Azure, "capi-system");
            match result {
                Ok(_) => panic!("expected error"),
                Err(e) => assert!(e.to_string().contains("Azure")),
            }
        }
    }
}
