//! Workload types for Lattice services
//!
//! This module defines Kubernetes workload resource types used by the ServiceCompiler:
//! - Deployment: Container orchestration
//! - Service: Network exposure
//! - ServiceAccount: SPIFFE identity for mTLS
//! - HorizontalPodAutoscaler: Auto-scaling
//! - ConfigMap/Secret: Configuration and secrets
//!
//! For workload generation, use [`crate::compiler::ServiceCompiler`].

pub mod env;
pub mod error;
pub mod files;

pub use error::CompilationError;

use std::collections::BTreeMap;

use aws_lc_rs::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};

/// Compute a config hash from ConfigMap and Secret data
///
/// This hash is added as a pod annotation to trigger rollouts when config changes.
/// Uses SHA-256 for FIPS compliance.
pub fn compute_config_hash(
    config_map: Option<&ConfigMap>,
    secret: Option<&Secret>,
    files_cm: Option<&ConfigMap>,
    files_secret: Option<&Secret>,
) -> String {
    let mut data = String::new();

    // Hash ConfigMap data
    if let Some(cm) = config_map {
        for (k, v) in &cm.data {
            data.push_str(k);
            data.push('=');
            data.push_str(v);
            data.push('\n');
        }
    }

    // Hash Secret data
    if let Some(s) = secret {
        for (k, v) in &s.string_data {
            data.push_str(k);
            data.push('=');
            data.push_str(v);
            data.push('\n');
        }
    }

    // Hash files ConfigMap
    if let Some(cm) = files_cm {
        for (k, v) in &cm.data {
            data.push_str("file:");
            data.push_str(k);
            data.push('=');
            data.push_str(v);
            data.push('\n');
        }
    }

    // Hash files Secret
    if let Some(s) = files_secret {
        for (k, v) in &s.string_data {
            data.push_str("file:");
            data.push_str(k);
            data.push('=');
            data.push_str(v);
            data.push('\n');
        }
    }

    // Compute SHA-256 hash
    let hash = digest(&SHA256, data.as_bytes());
    // Return first 16 hex chars (64 bits) for readability
    hash.as_ref()
        .iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect()
}

// =============================================================================
// Kubernetes Resource Types
// =============================================================================

/// Standard Kubernetes ObjectMeta
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ObjectMeta {
    /// Resource name
    pub name: String,
    /// Resource namespace
    pub namespace: String,
    /// Labels
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Annotations
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

impl ObjectMeta {
    /// Create new metadata with standard Lattice labels
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        let name = name.into();
        let mut labels = BTreeMap::new();
        labels.insert("app.kubernetes.io/name".to_string(), name.clone());
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            "lattice".to_string(),
        );
        Self {
            name,
            namespace: namespace.into(),
            labels,
            annotations: BTreeMap::new(),
        }
    }

    /// Add a label
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Add an annotation
    pub fn with_annotation(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.annotations.insert(key.into(), value.into());
        self
    }
}

// =============================================================================
// ConfigMap and Secret
// =============================================================================

/// Kubernetes ConfigMap for non-sensitive configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigMap {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// String data
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, String>,
}

impl ConfigMap {
    /// Create a new ConfigMap
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            api_version: "v1".to_string(),
            kind: "ConfigMap".to_string(),
            metadata: ObjectMeta::new(name, namespace),
            data: BTreeMap::new(),
        }
    }

    /// Add a data entry
    pub fn with_data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), value.into());
        self
    }
}

/// Kubernetes Secret for sensitive configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Secret {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// String data (auto-encoded to base64 by K8s)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub string_data: BTreeMap<String, String>,
    /// Secret type
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

impl Secret {
    /// Create a new Secret
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            api_version: "v1".to_string(),
            kind: "Secret".to_string(),
            metadata: ObjectMeta::new(name, namespace),
            string_data: BTreeMap::new(),
            type_: Some("Opaque".to_string()),
        }
    }

    /// Add a data entry
    pub fn with_data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.string_data.insert(key.into(), value.into());
        self
    }
}

// =============================================================================
// EnvFrom sources for referencing ConfigMap/Secret in containers
// =============================================================================

/// Reference to a ConfigMap or Secret for loading env vars
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvFromSource {
    /// ConfigMap reference
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_map_ref: Option<ConfigMapEnvSource>,
    /// Secret reference
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<SecretEnvSource>,
}

/// Reference to a ConfigMap for env vars
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ConfigMapEnvSource {
    /// ConfigMap name
    pub name: String,
}

/// Reference to a Secret for env vars
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SecretEnvSource {
    /// Secret name
    pub name: String,
}

// =============================================================================
// Deployment
// =============================================================================

/// Kubernetes Deployment
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Deployment {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Spec
    pub spec: DeploymentSpec,
}

/// Deployment spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentSpec {
    /// Number of replicas
    pub replicas: u32,
    /// Label selector
    pub selector: LabelSelector,
    /// Pod template
    pub template: PodTemplateSpec,
    /// Deployment strategy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<DeploymentStrategy>,
}

/// Label selector
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    /// Match labels
    pub match_labels: BTreeMap<String, String>,
}

/// Deployment strategy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentStrategy {
    /// Strategy type: RollingUpdate or Recreate
    #[serde(rename = "type")]
    pub type_: String,
    /// Rolling update config
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolling_update: Option<RollingUpdateConfig>,
}

/// Rolling update configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RollingUpdateConfig {
    /// Max unavailable pods
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_unavailable: Option<String>,
    /// Max surge pods
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_surge: Option<String>,
}

/// Pod template spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodTemplateSpec {
    /// Pod metadata
    pub metadata: PodMeta,
    /// Pod spec
    pub spec: PodSpec,
}

/// Pod metadata (subset of ObjectMeta)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodMeta {
    /// Labels
    pub labels: BTreeMap<String, String>,
    /// Annotations
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// Pod spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodSpec {
    /// Service account name
    pub service_account_name: String,
    /// Containers
    pub containers: Vec<Container>,
    /// Volumes
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<Volume>,
}

/// Container spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Container {
    /// Container name
    pub name: String,
    /// Image
    pub image: String,
    /// Command
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    /// Args
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    /// Environment variables
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvVar>,
    /// Environment from ConfigMap/Secret references
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_from: Vec<EnvFromSource>,
    /// Ports
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<ContainerPort>,
    /// Resource requirements
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,
    /// Liveness probe
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness_probe: Option<ProbeSpec>,
    /// Readiness probe
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_probe: Option<ProbeSpec>,
    /// Volume mounts
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volume_mounts: Vec<VolumeMount>,
}

/// Environment variable
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvVar {
    /// Variable name
    pub name: String,
    /// Variable value
    pub value: String,
}

/// Container port
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ContainerPort {
    /// Port name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Port number
    pub container_port: u16,
    /// Protocol
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

/// Resource requirements
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceRequirements {
    /// Requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<ResourceQuantity>,
    /// Limits
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<ResourceQuantity>,
}

/// Resource quantity
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceQuantity {
    /// CPU
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,
    /// Memory
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
}

/// Probe specification
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProbeSpec {
    /// HTTP GET probe
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_get: Option<HttpGetAction>,
    /// Exec probe
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecAction>,
    /// Initial delay seconds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_delay_seconds: Option<u32>,
    /// Period seconds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period_seconds: Option<u32>,
}

/// HTTP GET action for probe
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpGetAction {
    /// Path
    pub path: String,
    /// Port
    pub port: u16,
    /// Scheme
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
}

/// Exec action for probe
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExecAction {
    /// Command
    pub command: Vec<String>,
}

/// Volume
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Volume {
    /// Volume name
    pub name: String,
    /// ConfigMap source
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_map: Option<ConfigMapVolumeSource>,
    /// Secret source
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretVolumeSource>,
    /// EmptyDir source
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty_dir: Option<EmptyDirVolumeSource>,
}

/// ConfigMap volume source
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigMapVolumeSource {
    /// ConfigMap name
    pub name: String,
}

/// Secret volume source
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecretVolumeSource {
    /// Secret name
    pub secret_name: String,
}

/// EmptyDir volume source
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EmptyDirVolumeSource {}

/// Volume mount
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VolumeMount {
    /// Volume name
    pub name: String,
    /// Mount path
    pub mount_path: String,
    /// Sub path within the volume
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_path: Option<String>,
    /// Read only
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
}

// =============================================================================
// Service
// =============================================================================

/// Kubernetes Service
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Spec
    pub spec: ServiceSpec,
}

/// Service spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSpec {
    /// Selector
    pub selector: BTreeMap<String, String>,
    /// Ports
    pub ports: Vec<ServicePort>,
    /// Service type
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

/// Service port
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServicePort {
    /// Port name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Port number
    pub port: u16,
    /// Target port
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_port: Option<u16>,
    /// Protocol
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

// =============================================================================
// ServiceAccount
// =============================================================================

/// Kubernetes ServiceAccount
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccount {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
}

// =============================================================================
// HorizontalPodAutoscaler
// =============================================================================

/// Kubernetes HorizontalPodAutoscaler (v2)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HorizontalPodAutoscaler {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Spec
    pub spec: HpaSpec,
}

/// HPA spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HpaSpec {
    /// Scale target ref
    pub scale_target_ref: ScaleTargetRef,
    /// Min replicas
    pub min_replicas: u32,
    /// Max replicas
    pub max_replicas: u32,
    /// Metrics
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metrics: Vec<MetricSpec>,
}

/// Scale target reference
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScaleTargetRef {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Name
    pub name: String,
}

/// Metric specification
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MetricSpec {
    /// Metric type
    #[serde(rename = "type")]
    pub type_: String,
    /// Resource metric
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceMetricSource>,
}

/// Resource metric source
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceMetricSource {
    /// Resource name (cpu, memory)
    pub name: String,
    /// Target
    pub target: MetricTarget,
}

/// Metric target
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MetricTarget {
    /// Target type
    #[serde(rename = "type")]
    pub type_: String,
    /// Average utilization percentage
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub average_utilization: Option<u32>,
}

// =============================================================================
// Generated Workloads Container
// =============================================================================

/// Collection of all workload resources generated for a service
#[derive(Clone, Debug, Default)]
pub struct GeneratedWorkloads {
    /// Kubernetes Deployment
    pub deployment: Option<Deployment>,
    /// Kubernetes Service
    pub service: Option<Service>,
    /// Kubernetes ServiceAccount
    pub service_account: Option<ServiceAccount>,
    /// Kubernetes HorizontalPodAutoscaler
    pub hpa: Option<HorizontalPodAutoscaler>,
    /// ConfigMap for non-sensitive env vars
    pub env_config_map: Option<ConfigMap>,
    /// Secret for sensitive env vars
    pub env_secret: Option<Secret>,
    /// ConfigMap for file mounts (text content)
    pub files_config_map: Option<ConfigMap>,
    /// Secret for file mounts (binary content)
    pub files_secret: Option<Secret>,
}

impl GeneratedWorkloads {
    /// Create empty workload collection
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if any workloads were generated
    pub fn is_empty(&self) -> bool {
        self.deployment.is_none()
            && self.service.is_none()
            && self.service_account.is_none()
            && self.hpa.is_none()
            && self.env_config_map.is_none()
            && self.env_secret.is_none()
            && self.files_config_map.is_none()
            && self.files_secret.is_none()
    }
}

// =============================================================================
// Compiled Pod Spec (for webhook injection)
// =============================================================================

/// Compiled pod specification for webhook injection
///
/// This contains just the parts of a pod spec that the webhook needs
/// to inject into a Deployment. Used by the mutating admission webhook.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CompiledPodSpec {
    /// Containers to inject
    pub containers: Vec<Container>,
    /// Volumes to inject
    pub volumes: Vec<Volume>,
    /// Deployment strategy
    pub strategy: Option<DeploymentStrategy>,
}

impl CompiledPodSpec {
    /// Create a new empty compiled pod spec
    pub fn new() -> Self {
        Self {
            containers: vec![],
            volumes: vec![],
            strategy: None,
        }
    }
}

impl Default for CompiledPodSpec {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Workload Compiler
// =============================================================================

use crate::crd::{DeployStrategy, LatticeService, LatticeServiceSpec};

/// Compiler for generating Kubernetes workload resources from LatticeService
///
/// This compiler generates:
/// - ServiceAccount: For SPIFFE identity (always)
/// - Deployment: Container orchestration (always)
/// - Service: Network exposure (if ports defined)
/// - HPA: Auto-scaling (if max replicas set)
///
/// For webhook-based injection, use [`compile_pod_spec`] to get just the
/// container and volume specifications.
pub struct WorkloadCompiler;

impl WorkloadCompiler {
    /// Compile a LatticeService into workload resources
    ///
    /// # Arguments
    /// * `service` - The LatticeService to compile
    /// * `namespace` - Target namespace (from environment label, since LatticeService is cluster-scoped)
    pub fn compile(service: &LatticeService, namespace: &str) -> GeneratedWorkloads {
        let name = service.metadata.name.as_deref().unwrap_or("unknown");

        let mut output = GeneratedWorkloads::new();

        // Always generate ServiceAccount for SPIFFE identity
        output.service_account = Some(Self::compile_service_account(name, namespace));

        // Always generate Deployment
        output.deployment = Some(Self::compile_deployment(name, namespace, &service.spec));

        // Generate Service if ports are defined
        if service.spec.service.is_some() {
            output.service = Some(Self::compile_service(name, namespace, &service.spec));
        }

        // Generate HPA if max replicas is set
        if service.spec.replicas.max.is_some() {
            output.hpa = Some(Self::compile_hpa(name, namespace, &service.spec));
        }

        output
    }

    /// Compile a LatticeService with pre-rendered containers
    ///
    /// This is the full compilation path that:
    /// 1. Routes env vars to ConfigMap (non-sensitive) or Secret (sensitive)
    /// 2. Routes file mounts to ConfigMap (text) or Secret (binary)
    /// 3. Wires up envFrom and volumeMounts in containers
    ///
    /// # Arguments
    /// * `service` - The LatticeService to compile
    /// * `namespace` - Target namespace
    /// * `rendered` - Pre-rendered containers from TemplateRenderer
    pub fn compile_rendered(
        service: &LatticeService,
        namespace: &str,
        rendered: &std::collections::BTreeMap<String, crate::template::RenderedContainer>,
    ) -> GeneratedWorkloads {
        let name = service.metadata.name.as_deref().unwrap_or("unknown");

        let mut output = GeneratedWorkloads::new();

        // Always generate ServiceAccount for SPIFFE identity
        output.service_account = Some(Self::compile_service_account(name, namespace));

        // Compile env vars and files for each container, aggregate into single ConfigMap/Secret
        let mut all_env_vars = std::collections::BTreeMap::new();
        let mut all_files = std::collections::BTreeMap::new();

        for (container_name, container) in rendered {
            // Prefix env vars with container name to avoid collisions
            for (key, var) in &container.variables {
                let prefixed_key = if rendered.len() > 1 {
                    format!(
                        "{}_{}",
                        container_name.to_uppercase().replace('-', "_"),
                        key
                    )
                } else {
                    key.clone()
                };
                all_env_vars.insert(prefixed_key, var.clone());
            }

            // Aggregate files (paths are unique across containers)
            for (path, file) in &container.files {
                all_files.insert(path.clone(), file.clone());
            }
        }

        // Compile env vars to ConfigMap/Secret
        let compiled_env = env::compile(name, namespace, &all_env_vars);
        output.env_config_map = compiled_env.config_map;
        output.env_secret = compiled_env.secret;

        // Compile files to ConfigMap/Secret
        let compiled_files = files::compile(name, namespace, &all_files);
        output.files_config_map = compiled_files.config_map;
        output.files_secret = compiled_files.secret;

        // Compute config hash for rollout triggers
        let config_hash = compute_config_hash(
            output.env_config_map.as_ref(),
            output.env_secret.as_ref(),
            output.files_config_map.as_ref(),
            output.files_secret.as_ref(),
        );

        // Build containers with envFrom and volumeMounts
        let containers: Vec<Container> = rendered
            .iter()
            .map(|(container_name, rc)| {
                let container_spec = service.spec.containers.get(container_name);

                // Build ports from service spec
                let ports: Vec<ContainerPort> = if let Some(svc) = &service.spec.service {
                    svc.ports
                        .iter()
                        .map(|(port_name, port_spec)| ContainerPort {
                            name: Some(port_name.clone()),
                            container_port: port_spec.target_port.unwrap_or(port_spec.port),
                            protocol: port_spec.protocol.clone(),
                        })
                        .collect()
                } else {
                    vec![]
                };

                // Build resource requirements
                let resources = container_spec
                    .and_then(|cs| cs.resources.as_ref())
                    .map(|r| ResourceRequirements {
                        requests: r.requests.as_ref().map(|req| ResourceQuantity {
                            cpu: req.cpu.clone(),
                            memory: req.memory.clone(),
                        }),
                        limits: r.limits.as_ref().map(|lim| ResourceQuantity {
                            cpu: lim.cpu.clone(),
                            memory: lim.memory.clone(),
                        }),
                    });

                Container {
                    name: container_name.clone(),
                    image: rc.image.clone(),
                    command: rc.command.clone(),
                    args: rc.args.clone(),
                    env: vec![], // Using envFrom instead
                    env_from: compiled_env.env_from.clone(),
                    ports,
                    resources,
                    liveness_probe: None,  // TODO: from container_spec
                    readiness_probe: None, // TODO: from container_spec
                    volume_mounts: compiled_files.volume_mounts.clone(),
                }
            })
            .collect();

        // Build deployment with compiled containers
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("app.kubernetes.io/name".to_string(), name.to_string());

        // Add config hash as pod annotation to trigger rollouts on config changes
        let mut annotations = std::collections::BTreeMap::new();
        annotations.insert("lattice.dev/config-hash".to_string(), config_hash);

        let strategy = Self::compile_strategy(&service.spec);

        let replicas = if service.spec.replicas.min == 0 {
            1
        } else {
            service.spec.replicas.min
        };

        output.deployment = Some(Deployment {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
            metadata: ObjectMeta::new(name, namespace),
            spec: DeploymentSpec {
                replicas,
                selector: LabelSelector {
                    match_labels: labels.clone(),
                },
                template: PodTemplateSpec {
                    metadata: PodMeta {
                        labels,
                        annotations,
                    },
                    spec: PodSpec {
                        service_account_name: name.to_string(),
                        containers,
                        volumes: compiled_files.volumes,
                    },
                },
                strategy,
            },
        });

        // Generate Service if ports are defined
        if service.spec.service.is_some() {
            output.service = Some(Self::compile_service(name, namespace, &service.spec));
        }

        // Generate HPA if max replicas is set
        if service.spec.replicas.max.is_some() {
            output.hpa = Some(Self::compile_hpa(name, namespace, &service.spec));
        }

        output
    }

    /// Compile just the pod spec for webhook injection
    ///
    /// This returns the containers, volumes, and strategy that the webhook
    /// will inject into an existing Deployment skeleton.
    pub fn compile_pod_spec(service: &LatticeService) -> CompiledPodSpec {
        let containers = Self::compile_containers(&service.spec);
        let strategy = Self::compile_strategy(&service.spec);

        CompiledPodSpec {
            containers,
            volumes: vec![], // TODO: Add volume support from file mounts
            strategy,
        }
    }

    /// Compile containers from a LatticeServiceSpec
    fn compile_containers(spec: &LatticeServiceSpec) -> Vec<Container> {
        spec.containers
            .iter()
            .map(|(container_name, container_spec)| {
                // NOTE: Template rendering happens before this stage.
                // At compile time, variables still contain unrendered templates.
                // The workload compiler should render these before generating K8s resources.
                let env: Vec<EnvVar> = container_spec
                    .variables
                    .iter()
                    .map(|(k, v)| EnvVar {
                        name: k.clone(),
                        value: v.to_string(),
                    })
                    .collect();

                // Get ports from service spec
                let ports: Vec<ContainerPort> = spec
                    .service
                    .as_ref()
                    .map(|svc| {
                        svc.ports
                            .iter()
                            .map(|(port_name, port_spec)| ContainerPort {
                                name: Some(port_name.clone()),
                                container_port: port_spec.target_port.unwrap_or(port_spec.port),
                                protocol: port_spec.protocol.clone(),
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                // Convert resources
                let resources = container_spec
                    .resources
                    .as_ref()
                    .map(|r| ResourceRequirements {
                        requests: r.requests.as_ref().map(|req| ResourceQuantity {
                            cpu: req.cpu.clone(),
                            memory: req.memory.clone(),
                        }),
                        limits: r.limits.as_ref().map(|lim| ResourceQuantity {
                            cpu: lim.cpu.clone(),
                            memory: lim.memory.clone(),
                        }),
                    });

                // Convert probes
                let liveness_probe = container_spec.liveness_probe.as_ref().map(|p| ProbeSpec {
                    http_get: p.http_get.as_ref().map(|h| HttpGetAction {
                        path: h.path.clone(),
                        port: h.port,
                        scheme: h.scheme.clone(),
                    }),
                    exec: p.exec.as_ref().map(|e| ExecAction {
                        command: e.command.clone(),
                    }),
                    initial_delay_seconds: None,
                    period_seconds: None,
                });

                let readiness_probe = container_spec.readiness_probe.as_ref().map(|p| ProbeSpec {
                    http_get: p.http_get.as_ref().map(|h| HttpGetAction {
                        path: h.path.clone(),
                        port: h.port,
                        scheme: h.scheme.clone(),
                    }),
                    exec: p.exec.as_ref().map(|e| ExecAction {
                        command: e.command.clone(),
                    }),
                    initial_delay_seconds: None,
                    period_seconds: None,
                });

                Container {
                    name: container_name.clone(),
                    image: container_spec.image.clone(),
                    command: container_spec.command.clone(),
                    args: container_spec.args.clone(),
                    env,
                    env_from: vec![],
                    ports,
                    resources,
                    liveness_probe,
                    readiness_probe,
                    volume_mounts: vec![],
                }
            })
            .collect()
    }

    /// Compile deployment strategy
    fn compile_strategy(spec: &LatticeServiceSpec) -> Option<DeploymentStrategy> {
        match spec.deploy.strategy {
            DeployStrategy::Rolling => Some(DeploymentStrategy {
                type_: "RollingUpdate".to_string(),
                rolling_update: Some(RollingUpdateConfig {
                    max_unavailable: Some("25%".to_string()),
                    max_surge: Some("25%".to_string()),
                }),
            }),
            DeployStrategy::Canary => Some(DeploymentStrategy {
                type_: "RollingUpdate".to_string(),
                rolling_update: Some(RollingUpdateConfig {
                    max_unavailable: Some("0".to_string()),
                    max_surge: Some("100%".to_string()),
                }),
            }),
        }
    }

    fn compile_service_account(name: &str, namespace: &str) -> ServiceAccount {
        ServiceAccount {
            api_version: "v1".to_string(),
            kind: "ServiceAccount".to_string(),
            metadata: ObjectMeta::new(name, namespace),
        }
    }

    /// Compile a skeleton Deployment for webhook mutation.
    ///
    /// Creates a Deployment with minimal spec - the mutating webhook will
    /// inject the actual container spec from the LatticeService.
    /// The `lattice.dev/service` label links this Deployment to its LatticeService.
    fn compile_deployment(name: &str, namespace: &str, spec: &LatticeServiceSpec) -> Deployment {
        use crate::webhook::deployment::LATTICE_SERVICE_LABEL;

        let mut labels = BTreeMap::new();
        labels.insert("app.kubernetes.io/name".to_string(), name.to_string());
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            "lattice".to_string(),
        );
        // Label for webhook to find the LatticeService
        labels.insert(LATTICE_SERVICE_LABEL.to_string(), name.to_string());

        // Strategy is set at Deployment level, not patched by webhook
        let strategy = Self::compile_strategy(spec);

        Deployment {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
            // Deployment metadata must have lattice.dev/service label for webhook objectSelector
            metadata: ObjectMeta::new(name, namespace).with_label(LATTICE_SERVICE_LABEL, name),
            spec: DeploymentSpec {
                replicas: spec.replicas.min,
                selector: LabelSelector {
                    match_labels: {
                        let mut selector = BTreeMap::new();
                        selector.insert("app.kubernetes.io/name".to_string(), name.to_string());
                        selector
                    },
                },
                template: PodTemplateSpec {
                    metadata: PodMeta {
                        labels,
                        annotations: BTreeMap::new(),
                    },
                    spec: PodSpec {
                        // Webhook patches serviceAccountName and containers
                        service_account_name: String::new(),
                        containers: vec![],
                        volumes: vec![],
                    },
                },
                strategy,
            },
        }
    }

    fn compile_service(name: &str, namespace: &str, spec: &LatticeServiceSpec) -> Service {
        let mut selector = BTreeMap::new();
        selector.insert("app.kubernetes.io/name".to_string(), name.to_string());

        let ports: Vec<ServicePort> = spec
            .service
            .as_ref()
            .map(|svc| {
                svc.ports
                    .iter()
                    .map(|(port_name, port_spec)| ServicePort {
                        name: Some(port_name.clone()),
                        port: port_spec.port,
                        target_port: port_spec.target_port,
                        protocol: port_spec.protocol.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        Service {
            api_version: "v1".to_string(),
            kind: "Service".to_string(),
            metadata: ObjectMeta::new(name, namespace),
            spec: ServiceSpec {
                selector,
                ports,
                type_: None,
            },
        }
    }

    fn compile_hpa(
        name: &str,
        namespace: &str,
        spec: &LatticeServiceSpec,
    ) -> HorizontalPodAutoscaler {
        HorizontalPodAutoscaler {
            api_version: "autoscaling/v2".to_string(),
            kind: "HorizontalPodAutoscaler".to_string(),
            metadata: ObjectMeta::new(name, namespace),
            spec: HpaSpec {
                scale_target_ref: ScaleTargetRef {
                    api_version: "apps/v1".to_string(),
                    kind: "Deployment".to_string(),
                    name: name.to_string(),
                },
                min_replicas: spec.replicas.min,
                max_replicas: spec.replicas.max.unwrap_or(spec.replicas.min),
                metrics: vec![MetricSpec {
                    type_: "Resource".to_string(),
                    resource: Some(ResourceMetricSource {
                        name: "cpu".to_string(),
                        target: MetricTarget {
                            type_: "Utilization".to_string(),
                            average_utilization: Some(80),
                        },
                    }),
                }],
            },
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{ContainerSpec, DeploySpec, PortSpec, ReplicaSpec, ServicePortsSpec};
    use crate::template::TemplateString;

    fn make_service(name: &str, namespace: &str) -> LatticeService {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "nginx:latest".to_string(),
                command: None,
                args: None,
                variables: BTreeMap::new(),
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
            },
        );

        let mut ports = BTreeMap::new();
        ports.insert(
            "http".to_string(),
            PortSpec {
                port: 80,
                target_port: None,
                protocol: None,
            },
        );

        LatticeService {
            metadata: kube::api::ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: crate::crd::LatticeServiceSpec {
                environment: namespace.to_string(),
                containers,
                resources: BTreeMap::new(),
                service: Some(ServicePortsSpec { ports }),
                replicas: ReplicaSpec { min: 1, max: None },
                deploy: DeploySpec::default(),
            },
            status: None,
        }
    }

    // =========================================================================
    // Story: Always Generate ServiceAccount
    // =========================================================================

    #[test]
    fn story_always_generates_service_account() {
        let service = make_service("my-app", "default");
        let output = WorkloadCompiler::compile(&service, &service.spec.environment);

        let sa = output.service_account.expect("should have service account");
        assert_eq!(sa.metadata.name, "my-app");
        assert_eq!(sa.metadata.namespace, "default");
        assert_eq!(sa.api_version, "v1");
        assert_eq!(sa.kind, "ServiceAccount");
    }

    // =========================================================================
    // Story: Always Generate Deployment
    // =========================================================================

    #[test]
    fn story_always_generates_deployment() {
        let service = make_service("my-app", "prod");
        let output = WorkloadCompiler::compile(&service, &service.spec.environment);

        let deployment = output.deployment.expect("should have deployment");
        assert_eq!(deployment.metadata.name, "my-app");
        assert_eq!(deployment.metadata.namespace, "prod");
        assert_eq!(deployment.api_version, "apps/v1");
        assert_eq!(deployment.kind, "Deployment");
        assert_eq!(deployment.spec.replicas, 1);
    }

    #[test]
    fn story_deployment_has_correct_labels() {
        let service = make_service("my-app", "default");
        let output = WorkloadCompiler::compile(&service, &service.spec.environment);

        let deployment = output.deployment.unwrap();
        assert_eq!(
            deployment
                .spec
                .selector
                .match_labels
                .get("app.kubernetes.io/name"),
            Some(&"my-app".to_string())
        );
        assert_eq!(
            deployment
                .spec
                .template
                .metadata
                .labels
                .get("app.kubernetes.io/managed-by"),
            Some(&"lattice".to_string())
        );
    }

    #[test]
    fn story_deployment_is_skeleton() {
        use crate::webhook::deployment::LATTICE_SERVICE_LABEL;

        let service = make_service("my-app", "default");
        let output = WorkloadCompiler::compile(&service, &service.spec.environment);

        let deployment = output.deployment.unwrap();

        // Skeleton deployment has empty containers (webhook fills these)
        assert!(deployment.spec.template.spec.containers.is_empty());

        // Skeleton deployment has empty service account (webhook fills this)
        assert!(deployment
            .spec
            .template
            .spec
            .service_account_name
            .is_empty());

        // Has the lattice.dev/service label for webhook to find LatticeService
        let labels = &deployment.spec.template.metadata.labels;
        assert_eq!(
            labels.get(LATTICE_SERVICE_LABEL),
            Some(&"my-app".to_string())
        );
    }

    // =========================================================================
    // Story: Generate Service When Ports Defined
    // =========================================================================

    #[test]
    fn story_generates_service_with_ports() {
        let service = make_service("my-app", "default");
        let output = WorkloadCompiler::compile(&service, &service.spec.environment);

        let svc = output.service.expect("should have service");
        assert_eq!(svc.metadata.name, "my-app");
        assert_eq!(svc.api_version, "v1");
        assert_eq!(svc.kind, "Service");
        assert!(!svc.spec.ports.is_empty());
    }

    #[test]
    fn story_no_service_without_ports() {
        let mut service = make_service("my-app", "default");
        service.spec.service = None;

        let output = WorkloadCompiler::compile(&service, &service.spec.environment);
        assert!(output.service.is_none());
    }

    // =========================================================================
    // Story: Generate HPA When Max Replicas Set
    // =========================================================================

    #[test]
    fn story_generates_hpa_with_max_replicas() {
        let mut service = make_service("my-app", "default");
        service.spec.replicas = ReplicaSpec {
            min: 2,
            max: Some(10),
        };

        let output = WorkloadCompiler::compile(&service, &service.spec.environment);

        let hpa = output.hpa.expect("should have HPA");
        assert_eq!(hpa.metadata.name, "my-app");
        assert_eq!(hpa.api_version, "autoscaling/v2");
        assert_eq!(hpa.spec.min_replicas, 2);
        assert_eq!(hpa.spec.max_replicas, 10);
        assert_eq!(hpa.spec.scale_target_ref.name, "my-app");
        assert_eq!(hpa.spec.scale_target_ref.kind, "Deployment");
    }

    #[test]
    fn story_no_hpa_without_max_replicas() {
        let service = make_service("my-app", "default");
        let output = WorkloadCompiler::compile(&service, &service.spec.environment);
        assert!(output.hpa.is_none());
    }

    // =========================================================================
    // Story: Deployment Strategy
    // =========================================================================

    #[test]
    fn story_rolling_strategy() {
        let service = make_service("my-app", "default");
        let output = WorkloadCompiler::compile(&service, &service.spec.environment);

        let strategy = output.deployment.unwrap().spec.strategy.unwrap();
        assert_eq!(strategy.type_, "RollingUpdate");
        let rolling = strategy.rolling_update.unwrap();
        assert_eq!(rolling.max_unavailable, Some("25%".to_string()));
        assert_eq!(rolling.max_surge, Some("25%".to_string()));
    }

    #[test]
    fn story_canary_strategy() {
        let mut service = make_service("my-app", "default");
        service.spec.deploy.strategy = DeployStrategy::Canary;

        let output = WorkloadCompiler::compile(&service, &service.spec.environment);

        let strategy = output.deployment.unwrap().spec.strategy.unwrap();
        assert_eq!(strategy.type_, "RollingUpdate");
        let rolling = strategy.rolling_update.unwrap();
        assert_eq!(rolling.max_unavailable, Some("0".to_string()));
        assert_eq!(rolling.max_surge, Some("100%".to_string()));
    }

    // =========================================================================
    // Story: Container Configuration
    // =========================================================================

    #[test]
    fn story_container_environment_variables() {
        let mut service = make_service("my-app", "default");
        let container = service.spec.containers.get_mut("main").unwrap();
        container
            .variables
            .insert("LOG_LEVEL".to_string(), TemplateString::from("debug"));

        // Use compile_pod_spec which generates container specs for webhook
        let pod_spec = WorkloadCompiler::compile_pod_spec(&service);

        let env = &pod_spec
            .containers
            .iter()
            .find(|c| c.name == "main")
            .unwrap()
            .env;
        assert!(env
            .iter()
            .any(|e| e.name == "LOG_LEVEL" && e.value == "debug"));
    }

    #[test]
    fn story_container_ports_from_service() {
        let service = make_service("my-app", "default");

        // Use compile_pod_spec which generates container specs for webhook
        let pod_spec = WorkloadCompiler::compile_pod_spec(&service);

        let ports = &pod_spec
            .containers
            .iter()
            .find(|c| c.name == "main")
            .unwrap()
            .ports;
        assert!(ports.iter().any(|p| p.container_port == 80));
    }

    // =========================================================================
    // Story: GeneratedWorkloads Utility Methods
    // =========================================================================

    #[test]
    fn story_is_empty() {
        let empty = GeneratedWorkloads::new();
        assert!(empty.is_empty());

        let service = make_service("my-app", "default");
        let output = WorkloadCompiler::compile(&service, &service.spec.environment);
        assert!(!output.is_empty());
    }

    // =========================================================================
    // Story: Config Hash for Rollouts
    // =========================================================================

    #[test]
    fn test_config_hash_empty() {
        let hash = compute_config_hash(None, None, None, None);
        // Empty data still produces a hash
        assert_eq!(hash.len(), 16); // 8 bytes = 16 hex chars
    }

    #[test]
    fn test_config_hash_with_configmap() {
        let mut cm = ConfigMap::new("test", "default");
        cm.data.insert("KEY".to_string(), "value".to_string());

        let hash1 = compute_config_hash(Some(&cm), None, None, None);
        assert_eq!(hash1.len(), 16);

        // Different value produces different hash
        cm.data.insert("KEY".to_string(), "different".to_string());
        let hash2 = compute_config_hash(Some(&cm), None, None, None);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_config_hash_with_secret() {
        let mut secret = Secret::new("test", "default");
        secret
            .string_data
            .insert("PASSWORD".to_string(), "secret123".to_string());

        let hash = compute_config_hash(None, Some(&secret), None, None);
        assert_eq!(hash.len(), 16);
    }

    #[test]
    fn test_config_hash_deterministic() {
        let mut cm = ConfigMap::new("test", "default");
        cm.data.insert("KEY".to_string(), "value".to_string());

        // Same input produces same hash
        let hash1 = compute_config_hash(Some(&cm), None, None, None);
        let hash2 = compute_config_hash(Some(&cm), None, None, None);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_config_hash_combines_all_sources() {
        let mut env_cm = ConfigMap::new("env", "default");
        env_cm
            .data
            .insert("HOST".to_string(), "localhost".to_string());

        let mut env_secret = Secret::new("env", "default");
        env_secret
            .string_data
            .insert("PASSWORD".to_string(), "secret".to_string());

        let mut files_cm = ConfigMap::new("files", "default");
        files_cm
            .data
            .insert("config-yaml".to_string(), "key: value".to_string());

        let mut files_secret = Secret::new("files", "default");
        files_secret
            .string_data
            .insert("cert-pem".to_string(), "binary".to_string());

        // All four produce a combined hash
        let hash_all = compute_config_hash(
            Some(&env_cm),
            Some(&env_secret),
            Some(&files_cm),
            Some(&files_secret),
        );

        // Subset produces different hash
        let hash_partial = compute_config_hash(Some(&env_cm), Some(&env_secret), None, None);

        assert_ne!(hash_all, hash_partial);
    }

    // =========================================================================
    // Story: Full Compilation Pipeline (compile_rendered)
    // =========================================================================

    #[test]
    fn test_compile_rendered_routes_env_to_configmap() {
        use crate::template::{RenderedContainer, RenderedVariable};

        let service = make_service("api", "prod");

        let mut rendered = BTreeMap::new();
        let mut vars = BTreeMap::new();
        vars.insert("HOST".to_string(), RenderedVariable::plain("localhost"));
        vars.insert("PORT".to_string(), RenderedVariable::plain("8080"));

        rendered.insert(
            "main".to_string(),
            RenderedContainer {
                name: "main".to_string(),
                image: "nginx:latest".to_string(),
                command: None,
                args: None,
                variables: vars,
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
            },
        );

        let output = WorkloadCompiler::compile_rendered(&service, "prod", &rendered);

        // Should create ConfigMap for non-sensitive vars
        let cm = output.env_config_map.expect("should have env ConfigMap");
        assert_eq!(cm.metadata.name, "api-env");
        assert_eq!(cm.data.get("HOST"), Some(&"localhost".to_string()));
        assert_eq!(cm.data.get("PORT"), Some(&"8080".to_string()));

        // Should NOT create Secret (no sensitive vars)
        assert!(output.env_secret.is_none());
    }

    #[test]
    fn test_compile_rendered_routes_sensitive_to_secret() {
        use crate::template::{RenderedContainer, RenderedVariable};

        let service = make_service("api", "prod");

        let mut rendered = BTreeMap::new();
        let mut vars = BTreeMap::new();
        vars.insert("HOST".to_string(), RenderedVariable::plain("localhost"));
        vars.insert(
            "DB_PASSWORD".to_string(),
            RenderedVariable::secret("supersecret"),
        );

        rendered.insert(
            "main".to_string(),
            RenderedContainer {
                name: "main".to_string(),
                image: "nginx:latest".to_string(),
                command: None,
                args: None,
                variables: vars,
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
            },
        );

        let output = WorkloadCompiler::compile_rendered(&service, "prod", &rendered);

        // Non-sensitive goes to ConfigMap
        let cm = output.env_config_map.expect("should have env ConfigMap");
        assert_eq!(cm.data.get("HOST"), Some(&"localhost".to_string()));
        assert!(cm.data.get("DB_PASSWORD").is_none());

        // Sensitive goes to Secret
        let secret = output.env_secret.expect("should have env Secret");
        assert_eq!(
            secret.string_data.get("DB_PASSWORD"),
            Some(&"supersecret".to_string())
        );
        assert!(secret.string_data.get("HOST").is_none());
    }

    #[test]
    fn test_compile_rendered_adds_config_hash_annotation() {
        use crate::template::{RenderedContainer, RenderedVariable};

        let service = make_service("api", "prod");

        let mut rendered = BTreeMap::new();
        let mut vars = BTreeMap::new();
        vars.insert("KEY".to_string(), RenderedVariable::plain("value"));

        rendered.insert(
            "main".to_string(),
            RenderedContainer {
                name: "main".to_string(),
                image: "nginx:latest".to_string(),
                command: None,
                args: None,
                variables: vars,
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
            },
        );

        let output = WorkloadCompiler::compile_rendered(&service, "prod", &rendered);

        let deployment = output.deployment.expect("should have deployment");
        let annotations = &deployment.spec.template.metadata.annotations;

        // Should have config hash annotation
        let hash = annotations
            .get("lattice.dev/config-hash")
            .expect("should have config hash");
        assert_eq!(hash.len(), 16); // 8 bytes = 16 hex chars
    }

    #[test]
    fn test_compile_rendered_config_hash_changes_with_data() {
        use crate::template::{RenderedContainer, RenderedVariable};

        let service = make_service("api", "prod");

        // First compilation
        let mut rendered1 = BTreeMap::new();
        let mut vars1 = BTreeMap::new();
        vars1.insert("KEY".to_string(), RenderedVariable::plain("value1"));
        rendered1.insert(
            "main".to_string(),
            RenderedContainer {
                name: "main".to_string(),
                image: "nginx:latest".to_string(),
                command: None,
                args: None,
                variables: vars1,
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
            },
        );

        let output1 = WorkloadCompiler::compile_rendered(&service, "prod", &rendered1);
        let hash1 = output1
            .deployment
            .unwrap()
            .spec
            .template
            .metadata
            .annotations
            .get("lattice.dev/config-hash")
            .unwrap()
            .clone();

        // Second compilation with different value
        let mut rendered2 = BTreeMap::new();
        let mut vars2 = BTreeMap::new();
        vars2.insert("KEY".to_string(), RenderedVariable::plain("value2"));
        rendered2.insert(
            "main".to_string(),
            RenderedContainer {
                name: "main".to_string(),
                image: "nginx:latest".to_string(),
                command: None,
                args: None,
                variables: vars2,
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
            },
        );

        let output2 = WorkloadCompiler::compile_rendered(&service, "prod", &rendered2);
        let hash2 = output2
            .deployment
            .unwrap()
            .spec
            .template
            .metadata
            .annotations
            .get("lattice.dev/config-hash")
            .unwrap()
            .clone();

        // Hashes should differ when config changes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compile_rendered_wires_envfrom() {
        use crate::template::{RenderedContainer, RenderedVariable};

        let service = make_service("api", "prod");

        let mut rendered = BTreeMap::new();
        let mut vars = BTreeMap::new();
        vars.insert("HOST".to_string(), RenderedVariable::plain("localhost"));
        vars.insert("PASSWORD".to_string(), RenderedVariable::secret("secret"));

        rendered.insert(
            "main".to_string(),
            RenderedContainer {
                name: "main".to_string(),
                image: "nginx:latest".to_string(),
                command: None,
                args: None,
                variables: vars,
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
            },
        );

        let output = WorkloadCompiler::compile_rendered(&service, "prod", &rendered);

        let deployment = output.deployment.expect("should have deployment");
        let container = &deployment.spec.template.spec.containers[0];

        // Should have envFrom references
        assert_eq!(container.env_from.len(), 2);

        // One for ConfigMap
        assert!(container
            .env_from
            .iter()
            .any(|ef| ef.config_map_ref.is_some()));

        // One for Secret
        assert!(container.env_from.iter().any(|ef| ef.secret_ref.is_some()));
    }

    #[test]
    fn test_compile_rendered_with_files() {
        use crate::template::{RenderedContainer, RenderedFile};

        let service = make_service("api", "prod");

        let mut rendered = BTreeMap::new();
        let mut files = BTreeMap::new();
        files.insert(
            "/etc/app/config.yaml".to_string(),
            RenderedFile {
                content: Some("key: value".to_string()),
                binary_content: None,
                source: None,
                mode: Some("0644".to_string()),
            },
        );

        rendered.insert(
            "main".to_string(),
            RenderedContainer {
                name: "main".to_string(),
                image: "nginx:latest".to_string(),
                command: None,
                args: None,
                variables: BTreeMap::new(),
                files,
                volumes: BTreeMap::new(),
            },
        );

        let output = WorkloadCompiler::compile_rendered(&service, "prod", &rendered);

        // Should create files ConfigMap
        let files_cm = output
            .files_config_map
            .expect("should have files ConfigMap");
        assert_eq!(files_cm.metadata.name, "api-files");
        assert!(!files_cm.data.is_empty());

        // Deployment should have volume
        let deployment = output.deployment.expect("should have deployment");
        assert!(!deployment.spec.template.spec.volumes.is_empty());

        // Container should have volume mount
        let container = &deployment.spec.template.spec.containers[0];
        assert!(!container.volume_mounts.is_empty());
        assert!(container
            .volume_mounts
            .iter()
            .any(|vm| vm.mount_path == "/etc/app/config.yaml"));
    }
}
