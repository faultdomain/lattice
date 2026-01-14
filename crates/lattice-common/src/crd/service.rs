//! LatticeService Custom Resource Definition
//!
//! The LatticeService CRD represents a workload deployed by Lattice.
//! Services declare their dependencies and allowed callers for automatic
//! network policy generation.
//!
//! ## Score-Compatible Templating
//!
//! The following fields support `${...}` placeholder syntax per the Score spec:
//! - `containers.*.variables.*` - Environment variable values
//! - `containers.*.files.*.content` - Inline file content
//! - `containers.*.files.*.source` - File source path
//! - `containers.*.volumes.*.source` - Volume source reference
//! - `resources.*.params.*` - Resource parameters
//!
//! Use `$${...}` to escape and produce literal `${...}` in output.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::types::Condition;
use crate::template::TemplateString;

/// Generate a schema for arbitrary JSON objects
///
/// This is used for fields like `params` that can contain any JSON structure.
/// Kubernetes requires a type to be specified, so we use "object" with
/// x-kubernetes-preserve-unknown-fields to allow arbitrary content.
fn arbitrary_json_object(_gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
    schemars::schema::Schema::Object(schemars::schema::SchemaObject {
        instance_type: Some(schemars::schema::InstanceType::Object.into()),
        extensions: [(
            "x-kubernetes-preserve-unknown-fields".to_string(),
            true.into(),
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    })
}

/// Direction of a service dependency
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DependencyDirection {
    /// This service calls the target (outbound traffic)
    #[default]
    Outbound,
    /// The target calls this service (inbound traffic)
    Inbound,
    /// Bidirectional communication
    Both,
}

impl DependencyDirection {
    /// Returns true if this direction includes outbound traffic
    pub fn is_outbound(&self) -> bool {
        matches!(self, Self::Outbound | Self::Both)
    }

    /// Returns true if this direction includes inbound traffic
    pub fn is_inbound(&self) -> bool {
        matches!(self, Self::Inbound | Self::Both)
    }
}

/// Type of resource dependency
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]

pub enum ResourceType {
    /// Internal service (another LatticeService)
    #[default]
    Service,
    /// External service (LatticeExternalService)
    ExternalService,
    /// HTTP route (future: for ingress)
    Route,
    /// PostgreSQL database
    Postgres,
    /// Redis cache
    Redis,
}

/// Resource metadata (Score-compatible)
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct ResourceMetadata {
    /// Annotations for the resource
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// Resource dependency specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceSpec {
    /// Type of resource
    #[serde(rename = "type")]
    pub type_: ResourceType,

    /// Direction of the dependency (Lattice extension)
    #[serde(default)]
    pub direction: DependencyDirection,

    /// Optional identifier for resource sharing
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Optional specialization class
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,

    /// Resource metadata (Score-compatible)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ResourceMetadata>,

    /// Resource-specific parameters (arbitrary JSON object)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "arbitrary_json_object")]
    pub params: Option<serde_json::Value>,
}

/// Container resource limits and requests
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct ResourceRequirements {
    /// Resource requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<ResourceQuantity>,

    /// Resource limits
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<ResourceQuantity>,
}

/// Resource quantity for CPU and memory
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct ResourceQuantity {
    /// CPU quantity (e.g., "100m", "1")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,

    /// Memory quantity (e.g., "128Mi", "1Gi")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
}

/// HTTP probe configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpGetProbe {
    /// Path to probe
    pub path: String,

    /// Port to probe
    pub port: u16,

    /// HTTP scheme (HTTP or HTTPS)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,

    /// Optional host header
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// Optional HTTP headers
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_headers: Option<Vec<HttpHeader>>,
}

/// HTTP header for probes
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct HttpHeader {
    /// Header name
    pub name: String,
    /// Header value
    pub value: String,
}

/// Exec probe configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct ExecProbe {
    /// Command to execute
    pub command: Vec<String>,
}

/// TCP socket probe configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TcpSocketProbe {
    /// Port to probe
    pub port: u16,

    /// Optional host (defaults to pod IP)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

/// gRPC probe configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GrpcProbe {
    /// Port to probe (must be a gRPC server with health checking enabled)
    pub port: u16,

    /// Service name to check (optional, defaults to "" which checks server health)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}

/// Probe configuration (liveness, readiness, or startup)
///
/// Maps 1:1 with Kubernetes probe specification. Supports HTTP GET, exec,
/// TCP socket, and gRPC probe types with full timing configuration.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Probe {
    /// HTTP GET probe - performs an HTTP GET request
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_get: Option<HttpGetProbe>,

    /// Exec probe - executes a command inside the container
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecProbe>,

    /// TCP socket probe - performs a TCP check against the container's IP
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_socket: Option<TcpSocketProbe>,

    /// gRPC probe - performs a gRPC health check (requires Kubernetes 1.24+)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc: Option<GrpcProbe>,

    /// Number of seconds after container starts before probes are initiated (default: 0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_delay_seconds: Option<u32>,

    /// How often (in seconds) to perform the probe (default: 10)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period_seconds: Option<u32>,

    /// Number of seconds after which the probe times out (default: 1)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u32>,

    /// Minimum consecutive successes for probe to be considered successful (default: 1)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub success_threshold: Option<u32>,

    /// Minimum consecutive failures for probe to be considered failed (default: 3)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_threshold: Option<u32>,

    /// Override pod's terminationGracePeriodSeconds when probe fails (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub termination_grace_period_seconds: Option<i64>,
}

/// File mount specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FileMount {
    /// Inline file content (UTF-8, supports `${...}` placeholders)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<TemplateString>,

    /// Base64-encoded binary content
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_content: Option<String>,

    /// Path to content file (supports `${...}` placeholders)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<TemplateString>,

    /// File mode in octal
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,

    /// Disable placeholder expansion
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_expand: Option<bool>,
}

/// Volume mount specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VolumeMount {
    /// External volume reference (supports `${...}` placeholders)
    pub source: TemplateString,

    /// Sub path in the volume
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Mount as read-only
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
}

/// Container specification (Score-compatible)
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ContainerSpec {
    /// Container image (use "." for runtime-supplied image via config)
    pub image: String,

    /// Override container entrypoint
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,

    /// Override container arguments
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,

    /// Environment variables (values support `${...}` placeholders)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub variables: BTreeMap<String, TemplateString>,

    /// Resource requirements
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,

    /// Files to mount in the container
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, FileMount>,

    /// Volumes to mount
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub volumes: BTreeMap<String, VolumeMount>,

    /// Liveness probe - restarts container when it fails
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness_probe: Option<Probe>,

    /// Readiness probe - removes container from service endpoints when it fails
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_probe: Option<Probe>,

    /// Startup probe - delays liveness/readiness checks until container is ready
    ///
    /// Useful for slow-starting containers. Liveness and readiness probes
    /// will not run until the startup probe succeeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup_probe: Option<Probe>,
}

/// Service port specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PortSpec {
    /// Service port
    pub port: u16,

    /// Target port (defaults to port)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_port: Option<u16>,

    /// Protocol (TCP or UDP)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

/// Service exposure specification
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct ServicePortsSpec {
    /// Named network ports
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ports: BTreeMap<String, PortSpec>,
}

/// Replica scaling specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct ReplicaSpec {
    /// Minimum replicas
    #[serde(default)]
    pub min: u32,

    /// Maximum replicas
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<u32>,
}

impl Default for ReplicaSpec {
    fn default() -> Self {
        Self { min: 1, max: None }
    }
}

/// Deployment strategy
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeployStrategy {
    /// Rolling update strategy
    #[default]
    Rolling,
    /// Canary deployment with progressive traffic shifting
    Canary,
}

/// Canary deployment configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CanarySpec {
    /// Interval between steps
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,

    /// Error threshold before rollback
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<u32>,

    /// Maximum traffic weight
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_weight: Option<u32>,

    /// Weight increment per step
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_weight: Option<u32>,
}

/// Deployment specification
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct DeploySpec {
    /// Deployment strategy
    #[serde(default)]
    pub strategy: DeployStrategy,

    /// Canary configuration (only if strategy is canary)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary: Option<CanarySpec>,
}

/// Service lifecycle phase
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]

pub enum ServicePhase {
    /// Service is waiting for configuration
    #[default]
    Pending,
    /// Service manifests are being compiled
    Compiling,
    /// Service is fully operational
    Ready,
    /// Service has encountered an error
    Failed,
}

impl std::fmt::Display for ServicePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Compiling => write!(f, "Compiling"),
            Self::Ready => write!(f, "Ready"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Specification for a LatticeService
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "LatticeService",
    plural = "latticeservices",
    shortname = "ls",
    status = "LatticeServiceStatus",
    namespaced = false,
    printcolumn = r#"{"name":"Strategy","type":"string","jsonPath":".spec.deploy.strategy"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LatticeServiceSpec {
    /// Environment name - determines the namespace where workloads deploy
    ///
    /// This is required since LatticeService is cluster-scoped. The environment
    /// maps to a Kubernetes namespace where the Deployment, Service, etc. are created.
    pub environment: String,

    /// Named container specifications (Score-compatible)
    pub containers: BTreeMap<String, ContainerSpec>,

    /// External dependencies (service, route, postgres, redis, etc.)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resources: BTreeMap<String, ResourceSpec>,

    /// Service port configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<ServicePortsSpec>,

    /// Replica scaling configuration
    #[serde(default)]
    pub replicas: ReplicaSpec,

    /// Deployment strategy configuration
    #[serde(default)]
    pub deploy: DeploySpec,
}

impl LatticeServiceSpec {
    /// Extract service names that this service depends on (outbound)
    pub fn dependencies(&self) -> Vec<&str> {
        self.resources
            .iter()
            .filter(|(_, spec)| {
                spec.direction.is_outbound()
                    && matches!(
                        spec.type_,
                        ResourceType::Service | ResourceType::ExternalService
                    )
            })
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Extract service names that are allowed to call this service (inbound)
    pub fn allowed_callers(&self) -> Vec<&str> {
        self.resources
            .iter()
            .filter(|(_, spec)| {
                spec.direction.is_inbound() && matches!(spec.type_, ResourceType::Service)
            })
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Extract external service dependencies
    pub fn external_dependencies(&self) -> Vec<&str> {
        self.resources
            .iter()
            .filter(|(_, spec)| {
                spec.direction.is_outbound() && matches!(spec.type_, ResourceType::ExternalService)
            })
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Extract internal service dependencies
    pub fn internal_dependencies(&self) -> Vec<&str> {
        self.resources
            .iter()
            .filter(|(_, spec)| {
                spec.direction.is_outbound() && matches!(spec.type_, ResourceType::Service)
            })
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Get the ports this service exposes
    pub fn ports(&self) -> BTreeMap<&str, u16> {
        self.service
            .as_ref()
            .map(|s| {
                s.ports
                    .iter()
                    .map(|(name, spec)| (name.as_str(), spec.port))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the primary container image
    pub fn primary_image(&self) -> Option<&str> {
        self.containers
            .get("main")
            .or_else(|| self.containers.values().next())
            .map(|c| c.image.as_str())
    }

    /// Validate the service specification
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.containers.is_empty() {
            return Err(crate::Error::validation(
                "service must have at least one container",
            ));
        }

        // Validate replica counts
        if let Some(max) = self.replicas.max {
            if self.replicas.min > max {
                return Err(crate::Error::validation(
                    "min replicas cannot exceed max replicas",
                ));
            }
        }

        // Validate containers
        for (name, container) in &self.containers {
            container.validate(name)?;
        }

        // Validate service ports
        if let Some(ref svc) = self.service {
            svc.validate()?;
        }

        Ok(())
    }
}

impl ContainerSpec {
    /// Validate container specification
    pub fn validate(&self, container_name: &str) -> Result<(), crate::Error> {
        // Validate image format
        validate_image(&self.image, container_name)?;

        // Validate resource quantities
        if let Some(ref resources) = self.resources {
            resources.validate(container_name)?;
        }

        // Validate file mount modes
        for (path, file_mount) in &self.files {
            file_mount.validate(container_name, path)?;
        }

        Ok(())
    }
}

impl ResourceRequirements {
    /// Validate resource requirements
    pub fn validate(&self, container_name: &str) -> Result<(), crate::Error> {
        if let Some(ref requests) = self.requests {
            requests.validate(container_name, "requests")?;
        }
        if let Some(ref limits) = self.limits {
            limits.validate(container_name, "limits")?;
        }
        Ok(())
    }
}

impl ResourceQuantity {
    /// Validate resource quantity values
    pub fn validate(&self, container_name: &str, field: &str) -> Result<(), crate::Error> {
        if let Some(ref cpu) = self.cpu {
            validate_cpu_quantity(cpu, container_name, field)?;
        }
        if let Some(ref memory) = self.memory {
            validate_memory_quantity(memory, container_name, field)?;
        }
        Ok(())
    }
}

impl FileMount {
    /// Validate file mount specification
    pub fn validate(&self, container_name: &str, path: &str) -> Result<(), crate::Error> {
        // Validate mode is valid octal
        if let Some(ref mode) = self.mode {
            validate_file_mode(mode, container_name, path)?;
        }

        // Ensure at least one content source is specified
        let has_content =
            self.content.is_some() || self.binary_content.is_some() || self.source.is_some();
        if !has_content {
            return Err(crate::Error::validation(format!(
                "container '{}' file '{}': must specify content, binary_content, or source",
                container_name, path
            )));
        }

        Ok(())
    }
}

impl ServicePortsSpec {
    /// Validate service port specification
    pub fn validate(&self) -> Result<(), crate::Error> {
        let mut seen_ports: std::collections::HashSet<u16> = std::collections::HashSet::new();

        for (name, port_spec) in &self.ports {
            // Validate port is not zero
            if port_spec.port == 0 {
                return Err(crate::Error::validation(format!(
                    "service port '{}': port cannot be 0",
                    name
                )));
            }

            // Validate target_port is not zero
            if let Some(target_port) = port_spec.target_port {
                if target_port == 0 {
                    return Err(crate::Error::validation(format!(
                        "service port '{}': target_port cannot be 0",
                        name
                    )));
                }
            }

            // Check for duplicate port numbers
            if !seen_ports.insert(port_spec.port) {
                return Err(crate::Error::validation(format!(
                    "duplicate service port number: {}",
                    port_spec.port
                )));
            }
        }

        Ok(())
    }
}

/// Validate container image format
///
/// Accepts:
/// - Standard image references: "nginx:latest", "gcr.io/project/image:v1"
/// - Runtime placeholder: "." (Score spec - image supplied via config at render time)
///
/// Note: Per Score spec, `${...}` placeholders are NOT supported in image field.
/// Use "." for runtime-supplied images instead.
fn validate_image(image: &str, container_name: &str) -> Result<(), crate::Error> {
    if image.is_empty() {
        return Err(crate::Error::validation(format!(
            "container '{}': image cannot be empty",
            container_name
        )));
    }

    // "." is the Score placeholder for runtime-supplied image
    if image == "." {
        return Ok(());
    }

    // Basic validation: image must not contain whitespace or control characters
    if image.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(crate::Error::validation(format!(
            "container '{}': image '{}' contains invalid characters",
            container_name, image
        )));
    }

    Ok(())
}

/// Validate CPU quantity format (e.g., "100m", "1", "0.5")
fn validate_cpu_quantity(qty: &str, container_name: &str, field: &str) -> Result<(), crate::Error> {
    // CPU can be: integer, decimal, or integer with 'm' suffix
    let is_valid = if let Some(stripped) = qty.strip_suffix('m') {
        // Millicores: must be integer
        stripped.parse::<u64>().is_ok()
    } else {
        // Cores: can be integer or decimal
        qty.parse::<f64>().is_ok()
    };

    if !is_valid {
        return Err(crate::Error::validation(format!(
            "container '{}' {}.cpu: invalid quantity '{}' (expected e.g., '100m', '1', '0.5')",
            container_name, field, qty
        )));
    }

    Ok(())
}

/// Validate memory quantity format (e.g., "128Mi", "1Gi", "1000000")
fn validate_memory_quantity(
    qty: &str,
    container_name: &str,
    field: &str,
) -> Result<(), crate::Error> {
    // Memory can have these suffixes: Ki, Mi, Gi, Ti, Pi, Ei, k, M, G, T, P, E
    let suffixes = [
        "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "k", "M", "G", "T", "P", "E",
    ];

    let is_valid = if let Some(suffix) = suffixes.iter().find(|s| qty.ends_with(*s)) {
        // Has suffix: prefix must be a number
        let prefix = &qty[..qty.len() - suffix.len()];
        prefix.parse::<u64>().is_ok() || prefix.parse::<f64>().is_ok()
    } else {
        // No suffix: must be integer (bytes)
        qty.parse::<u64>().is_ok()
    };

    if !is_valid {
        return Err(crate::Error::validation(format!(
            "container '{}' {}.memory: invalid quantity '{}' (expected e.g., '128Mi', '1Gi')",
            container_name, field, qty
        )));
    }

    Ok(())
}

/// Validate file mode is valid octal (e.g., "0644", "0755")
fn validate_file_mode(mode: &str, container_name: &str, path: &str) -> Result<(), crate::Error> {
    // Mode should be 3-4 octal digits, optionally prefixed with 0
    let mode_str = mode.strip_prefix('0').unwrap_or(mode);

    if mode_str.len() < 3 || mode_str.len() > 4 {
        return Err(crate::Error::validation(format!(
            "container '{}' file '{}': mode '{}' must be 3-4 octal digits (e.g., '0644')",
            container_name, path, mode
        )));
    }

    if !mode_str.chars().all(|c| ('0'..='7').contains(&c)) {
        return Err(crate::Error::validation(format!(
            "container '{}' file '{}': mode '{}' contains non-octal digits",
            container_name, path, mode
        )));
    }

    Ok(())
}

/// Status for a LatticeService
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatticeServiceStatus {
    /// Current phase of the service lifecycle
    #[serde(default)]
    pub phase: ServicePhase,

    /// Human-readable message about current state
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Conditions representing the service state
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    /// Last time manifests were compiled
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_compiled_at: Option<DateTime<Utc>>,

    /// Observed generation for optimistic concurrency
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    /// Resolved dependency URLs
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resolved_dependencies: BTreeMap<String, String>,
}

impl LatticeServiceStatus {
    /// Create a new status with the given phase
    pub fn with_phase(phase: ServicePhase) -> Self {
        Self {
            phase,
            ..Default::default()
        }
    }

    /// Set the phase and return self for chaining
    pub fn phase(mut self, phase: ServicePhase) -> Self {
        self.phase = phase;
        self
    }

    /// Set the message and return self for chaining
    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }

    /// Add a condition and return self for chaining
    pub fn condition(mut self, condition: Condition) -> Self {
        self.conditions.retain(|c| c.type_ != condition.type_);
        self.conditions.push(condition);
        self
    }

    /// Set the last compiled timestamp
    pub fn compiled_at(mut self, time: DateTime<Utc>) -> Self {
        self.last_compiled_at = Some(time);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::types::ConditionStatus;

    // =========================================================================
    // Test Fixtures
    // =========================================================================

    fn simple_container() -> ContainerSpec {
        ContainerSpec {
            image: "nginx:latest".to_string(),
            command: None,
            args: None,
            variables: BTreeMap::new(),
            resources: None,
            files: BTreeMap::new(),
            volumes: BTreeMap::new(),
            liveness_probe: None,
            readiness_probe: None,
            startup_probe: None,
        }
    }

    fn sample_service_spec() -> LatticeServiceSpec {
        let mut containers = BTreeMap::new();
        containers.insert("main".to_string(), simple_container());

        LatticeServiceSpec {
            environment: "test".to_string(),
            containers,
            resources: BTreeMap::new(),
            service: None,
            replicas: ReplicaSpec::default(),
            deploy: DeploySpec::default(),
        }
    }

    // =========================================================================
    // Dependency Direction Tests
    // =========================================================================

    #[test]
    fn test_dependency_direction_outbound() {
        let dir = DependencyDirection::Outbound;
        assert!(dir.is_outbound());
        assert!(!dir.is_inbound());
    }

    #[test]
    fn test_dependency_direction_inbound() {
        let dir = DependencyDirection::Inbound;
        assert!(!dir.is_outbound());
        assert!(dir.is_inbound());
    }

    #[test]
    fn test_dependency_direction_both() {
        let dir = DependencyDirection::Both;
        assert!(dir.is_outbound());
        assert!(dir.is_inbound());
    }

    // =========================================================================
    // Dependency Extraction Stories
    // =========================================================================

    /// Story: Service declares outbound dependencies on other services
    #[test]
    fn story_service_declares_outbound_dependencies() {
        let mut resources = BTreeMap::new();
        resources.insert(
            "redis".to_string(),
            ResourceSpec {
                type_: ResourceType::ExternalService,
                direction: DependencyDirection::Outbound,
                id: None,
                class: None,
                metadata: None,
                params: None,
            },
        );
        resources.insert(
            "api-gateway".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Outbound,
                id: None,
                class: None,
                metadata: None,
                params: None,
            },
        );

        let mut spec = sample_service_spec();
        spec.resources = resources;

        let deps = spec.dependencies();
        assert_eq!(deps.len(), 2);
        assert!(deps.contains(&"redis"));
        assert!(deps.contains(&"api-gateway"));
    }

    /// Story: Service declares which callers are allowed
    #[test]
    fn story_service_declares_allowed_callers() {
        let mut resources = BTreeMap::new();
        resources.insert(
            "curl-tester".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Inbound,
                id: None,
                class: None,
                metadata: None,
                params: None,
            },
        );
        resources.insert(
            "frontend".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Inbound,
                id: None,
                class: None,
                metadata: None,
                params: None,
            },
        );

        let mut spec = sample_service_spec();
        spec.resources = resources;

        let callers = spec.allowed_callers();
        assert_eq!(callers.len(), 2);
        assert!(callers.contains(&"curl-tester"));
        assert!(callers.contains(&"frontend"));
    }

    /// Story: Bidirectional relationships are counted in both directions
    #[test]
    fn story_bidirectional_relationships() {
        let mut resources = BTreeMap::new();
        resources.insert(
            "cache".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Both,
                id: None,
                class: None,
                metadata: None,
                params: None,
            },
        );

        let mut spec = sample_service_spec();
        spec.resources = resources;

        // Should appear in both dependencies and allowed_callers
        assert!(spec.dependencies().contains(&"cache"));
        assert!(spec.allowed_callers().contains(&"cache"));
    }

    /// Story: External services are separated from internal
    #[test]
    fn story_external_vs_internal_dependencies() {
        let mut resources = BTreeMap::new();
        resources.insert(
            "google".to_string(),
            ResourceSpec {
                type_: ResourceType::ExternalService,
                direction: DependencyDirection::Outbound,
                id: None,
                class: None,
                metadata: None,
                params: None,
            },
        );
        resources.insert(
            "backend".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Outbound,
                id: None,
                class: None,
                metadata: None,
                params: None,
            },
        );

        let mut spec = sample_service_spec();
        spec.resources = resources;

        let external = spec.external_dependencies();
        let internal = spec.internal_dependencies();

        assert_eq!(external, vec!["google"]);
        assert_eq!(internal, vec!["backend"]);
    }

    // =========================================================================
    // Validation Stories
    // =========================================================================

    /// Story: Valid service passes validation
    #[test]
    fn story_valid_service_passes_validation() {
        let spec = sample_service_spec();
        assert!(spec.validate().is_ok());
    }

    /// Story: Service without containers fails validation
    #[test]
    fn story_service_without_containers_fails() {
        let spec = LatticeServiceSpec {
            environment: "test".to_string(),
            containers: BTreeMap::new(),
            resources: BTreeMap::new(),
            service: None,
            replicas: ReplicaSpec::default(),
            deploy: DeploySpec::default(),
        };

        let result = spec.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at least one container"));
    }

    /// Story: Invalid replica configuration fails validation
    #[test]
    fn story_invalid_replicas_fails() {
        let mut spec = sample_service_spec();
        spec.replicas = ReplicaSpec {
            min: 5,
            max: Some(3),
        };

        let result = spec.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("min replicas"));
    }

    // =========================================================================
    // YAML Serialization Stories
    // =========================================================================

    /// Story: User defines simple nginx service
    #[test]
    fn story_yaml_simple_service() {
        let yaml = r#"
environment: test
containers:
  main:
    image: nginx:latest
service:
  ports:
    http:
      port: 80
replicas:
  min: 1
  max: 3
"#;
        let spec: LatticeServiceSpec = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(spec.containers.len(), 1);
        assert_eq!(spec.containers["main"].image, "nginx:latest");
        assert_eq!(spec.replicas.min, 1);
        assert_eq!(spec.replicas.max, Some(3));

        let ports = spec.ports();
        assert_eq!(ports.get("http"), Some(&80));
    }

    /// Story: User defines service with dependencies and callers
    #[test]
    fn story_yaml_service_with_dependencies() {
        let yaml = r#"
environment: test
containers:
  main:
    image: my-api:v1.0
    variables:
      LOG_LEVEL: info
resources:
  curl-tester:
    type: service
    direction: inbound
  google:
    type: external-service
    direction: outbound
  cache:
    type: service
    direction: both
service:
  ports:
    http:
      port: 8080
"#;
        let spec: LatticeServiceSpec = serde_yaml::from_str(yaml).unwrap();

        // Check dependencies
        let deps = spec.dependencies();
        assert!(deps.contains(&"google"));
        assert!(deps.contains(&"cache"));

        // Check allowed callers
        let callers = spec.allowed_callers();
        assert!(callers.contains(&"curl-tester"));
        assert!(callers.contains(&"cache"));

        // Check variables
        assert_eq!(
            spec.containers["main"]
                .variables
                .get("LOG_LEVEL")
                .map(|v| v.as_str()),
            Some("info")
        );
    }

    /// Story: Service with canary deployment
    #[test]
    fn story_yaml_canary_deployment() {
        let yaml = r#"
environment: test
containers:
  main:
    image: app:v2.0
deploy:
  strategy: canary
  canary:
    interval: "1m"
    threshold: 5
    maxWeight: 50
    stepWeight: 10
"#;
        let spec: LatticeServiceSpec = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(spec.deploy.strategy, DeployStrategy::Canary);
        let canary = spec.deploy.canary.unwrap();
        assert_eq!(canary.interval, Some("1m".to_string()));
        assert_eq!(canary.threshold, Some(5));
        assert_eq!(canary.max_weight, Some(50));
        assert_eq!(canary.step_weight, Some(10));
    }

    /// Story: Spec survives serialization roundtrip
    #[test]
    fn story_spec_survives_yaml_roundtrip() {
        let spec = sample_service_spec();
        let yaml = serde_yaml::to_string(&spec).unwrap();
        let parsed: LatticeServiceSpec = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(spec, parsed);
    }

    // =========================================================================
    // Status Builder Stories
    // =========================================================================

    /// Story: Controller builds status fluently
    #[test]
    fn story_controller_builds_status_fluently() {
        let condition = Condition::new(
            "Ready",
            ConditionStatus::True,
            "ServiceReady",
            "All replicas are healthy",
        );

        let status = LatticeServiceStatus::default()
            .phase(ServicePhase::Ready)
            .message("Service is operational")
            .condition(condition)
            .compiled_at(Utc::now());

        assert_eq!(status.phase, ServicePhase::Ready);
        assert_eq!(status.message.as_deref(), Some("Service is operational"));
        assert_eq!(status.conditions.len(), 1);
        assert!(status.last_compiled_at.is_some());
    }

    // =========================================================================
    // Helper Method Tests
    // =========================================================================

    #[test]
    fn test_primary_image() {
        let spec = sample_service_spec();
        assert_eq!(spec.primary_image(), Some("nginx:latest"));
    }

    #[test]
    fn test_primary_image_without_main() {
        let mut containers = BTreeMap::new();
        containers.insert("worker".to_string(), simple_container());

        let spec = LatticeServiceSpec {
            environment: "test".to_string(),
            containers,
            resources: BTreeMap::new(),
            service: None,
            replicas: ReplicaSpec::default(),
            deploy: DeploySpec::default(),
        };

        assert_eq!(spec.primary_image(), Some("nginx:latest"));
    }

    #[test]
    fn test_service_phase_display() {
        assert_eq!(ServicePhase::Pending.to_string(), "Pending");
        assert_eq!(ServicePhase::Compiling.to_string(), "Compiling");
        assert_eq!(ServicePhase::Ready.to_string(), "Ready");
        assert_eq!(ServicePhase::Failed.to_string(), "Failed");
    }

    // =========================================================================
    // Field Validation Tests
    // =========================================================================

    /// Story: Valid CPU quantities pass validation
    #[test]
    fn test_valid_cpu_quantities() {
        assert!(validate_cpu_quantity("100m", "main", "requests").is_ok());
        assert!(validate_cpu_quantity("1", "main", "limits").is_ok());
        assert!(validate_cpu_quantity("0.5", "main", "requests").is_ok());
        assert!(validate_cpu_quantity("2000m", "main", "limits").is_ok());
    }

    /// Story: Invalid CPU quantities fail validation
    #[test]
    fn test_invalid_cpu_quantities() {
        assert!(validate_cpu_quantity("", "main", "requests").is_err());
        assert!(validate_cpu_quantity("abc", "main", "limits").is_err());
        assert!(validate_cpu_quantity("100x", "main", "requests").is_err());
        assert!(validate_cpu_quantity("1.5m", "main", "limits").is_err()); // millicores must be int
    }

    /// Story: Valid memory quantities pass validation
    #[test]
    fn test_valid_memory_quantities() {
        assert!(validate_memory_quantity("128Mi", "main", "requests").is_ok());
        assert!(validate_memory_quantity("1Gi", "main", "limits").is_ok());
        assert!(validate_memory_quantity("1000000", "main", "requests").is_ok()); // bytes
        assert!(validate_memory_quantity("512Ki", "main", "limits").is_ok());
        assert!(validate_memory_quantity("1M", "main", "requests").is_ok());
    }

    /// Story: Invalid memory quantities fail validation
    #[test]
    fn test_invalid_memory_quantities() {
        assert!(validate_memory_quantity("", "main", "requests").is_err());
        assert!(validate_memory_quantity("abc", "main", "limits").is_err());
        assert!(validate_memory_quantity("128Xi", "main", "requests").is_err());
        // invalid suffix
    }

    /// Story: Valid file modes pass validation
    #[test]
    fn test_valid_file_modes() {
        assert!(validate_file_mode("0644", "main", "/etc/config").is_ok());
        assert!(validate_file_mode("0755", "main", "/usr/bin/script").is_ok());
        assert!(validate_file_mode("644", "main", "/etc/config").is_ok()); // without leading 0
        assert!(validate_file_mode("0777", "main", "/tmp/file").is_ok());
    }

    /// Story: Invalid file modes fail validation
    #[test]
    fn test_invalid_file_modes() {
        assert!(validate_file_mode("0999", "main", "/etc/config").is_err()); // 9 is not octal
        assert!(validate_file_mode("abc", "main", "/etc/config").is_err());
        assert!(validate_file_mode("12", "main", "/etc/config").is_err()); // too short
        assert!(validate_file_mode("12345", "main", "/etc/config").is_err()); // too long
    }

    /// Story: Empty image fails validation
    #[test]
    fn test_empty_image_fails() {
        assert!(validate_image("", "main").is_err());
    }

    /// Story: Image with whitespace fails validation
    #[test]
    fn test_image_with_whitespace_fails() {
        assert!(validate_image("nginx latest", "main").is_err());
        assert!(validate_image("nginx\tlatest", "main").is_err());
    }

    /// Story: Valid images pass validation
    #[test]
    fn test_valid_images() {
        assert!(validate_image("nginx:latest", "main").is_ok());
        assert!(validate_image("registry.example.com/app:v1.2.3", "main").is_ok());
        assert!(validate_image("gcr.io/project/image@sha256:abc123", "main").is_ok());
    }

    /// Story: Score "." image placeholder is valid
    #[test]
    fn test_dot_image_placeholder_valid() {
        assert!(validate_image(".", "main").is_ok());
    }

    /// Story: Duplicate service ports fail validation
    #[test]
    fn test_duplicate_service_ports_fail() {
        let mut ports = BTreeMap::new();
        ports.insert(
            "http".to_string(),
            PortSpec {
                port: 80,
                target_port: None,
                protocol: None,
            },
        );
        ports.insert(
            "http2".to_string(),
            PortSpec {
                port: 80, // duplicate!
                target_port: None,
                protocol: None,
            },
        );

        let svc = ServicePortsSpec { ports };
        assert!(svc.validate().is_err());
    }

    /// Story: Port zero fails validation
    #[test]
    fn test_port_zero_fails() {
        let mut ports = BTreeMap::new();
        ports.insert(
            "http".to_string(),
            PortSpec {
                port: 0,
                target_port: None,
                protocol: None,
            },
        );

        let svc = ServicePortsSpec { ports };
        assert!(svc.validate().is_err());
    }

    /// Story: File mount must have content source
    #[test]
    fn test_file_mount_requires_content() {
        let file = FileMount {
            content: None,
            binary_content: None,
            source: None,
            mode: None,
            no_expand: None,
        };
        assert!(file.validate("main", "/etc/config").is_err());

        // With content, it passes
        let file_with_content = FileMount {
            content: Some(TemplateString::from("data")),
            binary_content: None,
            source: None,
            mode: None,
            no_expand: None,
        };
        assert!(file_with_content.validate("main", "/etc/config").is_ok());
    }

    // =========================================================================
    // Template String Tests
    // =========================================================================

    /// Story: Environment variables support Score placeholders
    #[test]
    fn test_variables_support_templates() {
        let yaml = r#"
environment: test
containers:
  main:
    image: app:latest
    variables:
      DB_HOST: "${resources.postgres.host}"
      DB_PORT: "${resources.postgres.port}"
      STATIC: "plain-value"
"#;
        let spec: LatticeServiceSpec = serde_yaml::from_str(yaml).unwrap();
        let vars = &spec.containers["main"].variables;

        assert!(vars["DB_HOST"].has_placeholders());
        assert!(vars["DB_PORT"].has_placeholders());
        assert!(!vars["STATIC"].has_placeholders());
    }

    /// Story: File content supports Score placeholders
    #[test]
    fn test_file_content_supports_templates() {
        let yaml = r#"
environment: test
containers:
  main:
    image: app:latest
    files:
      /etc/config.yaml:
        content: |
          database:
            host: ${resources.db.host}
            port: ${resources.db.port}
"#;
        let spec: LatticeServiceSpec = serde_yaml::from_str(yaml).unwrap();
        let file = &spec.containers["main"].files["/etc/config.yaml"];

        assert!(file.content.as_ref().unwrap().has_placeholders());
    }

    /// Story: Volume source supports Score placeholders
    #[test]
    fn test_volume_source_supports_templates() {
        let yaml = r#"
environment: test
containers:
  main:
    image: app:latest
    volumes:
      /data:
        source: "${resources.volume.name}"
"#;
        let spec: LatticeServiceSpec = serde_yaml::from_str(yaml).unwrap();
        let volume = &spec.containers["main"].volumes["/data"];

        assert!(volume.source.has_placeholders());
    }

    // =========================================================================
    // Probe Tests (Score/K8s compatible)
    // =========================================================================

    /// Story: Full probe configuration with all timing parameters
    #[test]
    fn test_probe_with_timing_parameters() {
        let yaml = r#"
environment: test
containers:
  main:
    image: app:latest
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 30
      periodSeconds: 10
      timeoutSeconds: 5
      successThreshold: 1
      failureThreshold: 3
"#;
        let spec: LatticeServiceSpec = serde_yaml::from_str(yaml).unwrap();
        let probe = spec.containers["main"].liveness_probe.as_ref().unwrap();

        assert_eq!(probe.initial_delay_seconds, Some(30));
        assert_eq!(probe.period_seconds, Some(10));
        assert_eq!(probe.timeout_seconds, Some(5));
        assert_eq!(probe.success_threshold, Some(1));
        assert_eq!(probe.failure_threshold, Some(3));

        let http = probe.http_get.as_ref().unwrap();
        assert_eq!(http.path, "/healthz");
        assert_eq!(http.port, 8080);
    }

    /// Story: TCP socket probe
    #[test]
    fn test_tcp_socket_probe() {
        let yaml = r#"
environment: test
containers:
  main:
    image: redis:latest
    readinessProbe:
      tcpSocket:
        port: 6379
      periodSeconds: 5
"#;
        let spec: LatticeServiceSpec = serde_yaml::from_str(yaml).unwrap();
        let probe = spec.containers["main"].readiness_probe.as_ref().unwrap();

        let tcp = probe.tcp_socket.as_ref().unwrap();
        assert_eq!(tcp.port, 6379);
        assert_eq!(probe.period_seconds, Some(5));
    }

    /// Story: gRPC probe
    #[test]
    fn test_grpc_probe() {
        let yaml = r#"
environment: test
containers:
  main:
    image: grpc-server:latest
    livenessProbe:
      grpc:
        port: 50051
        service: my.health.Service
      initialDelaySeconds: 10
"#;
        let spec: LatticeServiceSpec = serde_yaml::from_str(yaml).unwrap();
        let probe = spec.containers["main"].liveness_probe.as_ref().unwrap();

        let grpc = probe.grpc.as_ref().unwrap();
        assert_eq!(grpc.port, 50051);
        assert_eq!(grpc.service, Some("my.health.Service".to_string()));
        assert_eq!(probe.initial_delay_seconds, Some(10));
    }

    /// Story: Startup probe for slow-starting containers
    #[test]
    fn test_startup_probe() {
        let yaml = r#"
environment: test
containers:
  main:
    image: slow-app:latest
    startupProbe:
      httpGet:
        path: /ready
        port: 8080
      failureThreshold: 30
      periodSeconds: 10
"#;
        let spec: LatticeServiceSpec = serde_yaml::from_str(yaml).unwrap();
        let probe = spec.containers["main"].startup_probe.as_ref().unwrap();

        let http = probe.http_get.as_ref().unwrap();
        assert_eq!(http.path, "/ready");
        assert_eq!(probe.failure_threshold, Some(30));
        assert_eq!(probe.period_seconds, Some(10));
    }

    /// Story: Exec probe with command
    #[test]
    fn test_exec_probe() {
        let yaml = r#"
environment: test
containers:
  main:
    image: app:latest
    livenessProbe:
      exec:
        command:
          - cat
          - /tmp/healthy
      periodSeconds: 5
"#;
        let spec: LatticeServiceSpec = serde_yaml::from_str(yaml).unwrap();
        let probe = spec.containers["main"].liveness_probe.as_ref().unwrap();

        let exec = probe.exec.as_ref().unwrap();
        assert_eq!(exec.command, vec!["cat", "/tmp/healthy"]);
    }

    /// Story: Image "." placeholder parses correctly
    #[test]
    fn test_image_dot_placeholder_yaml() {
        let yaml = r#"
environment: test
containers:
  main:
    image: "."
"#;
        let spec: LatticeServiceSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.containers["main"].image, ".");
        assert!(spec.validate().is_ok());
    }
}
