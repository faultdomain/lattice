//! LatticePackage Custom Resource Definition
//!
//! Declarative Helm chart lifecycle management with secret injection,
//! Cedar authorization, and optional mesh integration.
//!
//! Secrets are injected into Helm values via two modes:
//! - `$secret` directives: object in values tree replaced with K8s Secret name
//! - `${secret.X.Y}` inline refs: resolved from synced K8s Secret data
//!
//! Charts are rendered with `helm template` and applied via server-side apply.

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::mesh_member::EgressRule;
use super::types::{Condition, ConditionStatus, ServiceRef};
use super::ResourceSpec;

// =============================================================================
// Phase
// =============================================================================

/// Phase of a LatticePackage
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub enum PackagePhase {
    /// Initial state, not yet reconciled
    #[default]
    Pending,
    /// Helm release installed and healthy
    Ready,
    /// Chart pull, install, or authorization failed
    Failed,
}

impl std::fmt::Display for PackagePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Ready => write!(f, "Ready"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

// =============================================================================
// Spec
// =============================================================================

/// Specification for a LatticePackage
///
/// Defines a Helm chart to install with optional secret injection and mesh
/// integration. The controller renders the chart with `helm template` and
/// applies the output via server-side apply.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "LatticePackage",
    plural = "latticepackages",
    shortname = "lpkg",
    namespaced,
    status = "LatticePackageStatus",
    printcolumn = r#"{"name":"Chart","type":"string","jsonPath":".spec.chart.name"}"#,
    printcolumn = r#"{"name":"Version","type":"string","jsonPath":".spec.chart.version"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LatticePackageSpec {
    /// Helm chart reference
    pub chart: ChartRef,

    /// Helm values with secret injection support.
    ///
    /// `$secret` directives in the tree are replaced with K8s Secret names.
    /// Each directive maps target keys to resources via `${resource.key}`.
    /// Processed by `lattice_template::expand()`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::crd::preserve_unknown_fields")]
    pub values: Option<serde_json::Value>,

    /// Secret resources referenced by `$secret` directives in `values`.
    ///
    /// Same format as `LatticeService.spec.workload.resources`. Declares
    /// where secrets live (provider, remote key). Directives reference
    /// these by name via `${resource.key}` syntax.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resources: BTreeMap<String, ResourceSpec>,

    /// Optional mesh integration for chart workloads.
    ///
    /// When set, generates a `LatticeMeshMember` so chart pods participate
    /// in bilateral agreements and get Cilium/Istio policies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<PackageMeshConfig>,

    /// Namespace to render the chart into. Defaults to `metadata.namespace`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_namespace: Option<String>,

    /// Whether to create the target namespace if it doesn't exist.
    #[serde(default)]
    pub create_namespace: bool,

    /// Whether to skip CRD installation from the chart.
    #[serde(default)]
    pub skip_crds: bool,

    /// Helm template timeout (e.g., "5m", "10m"). Defaults to "5m".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,

    /// Whether this package should be distributed to child clusters.
    /// When true, the parent cell includes this package in `DistributableResources`
    /// sent during pivot and ongoing sync.
    #[serde(default)]
    pub propagate: bool,
}

/// Helm chart reference
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChartRef {
    /// Chart repository URL (OCI or HTTPS).
    /// Examples: `oci://registry.example.com/charts`, `https://charts.bitnami.com/bitnami`
    pub repository: String,

    /// Chart name within the repository
    pub name: String,

    /// Chart version (SemVer). Required — no floating versions.
    pub version: String,
}

/// Mesh configuration for package workloads
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PackageMeshConfig {
    /// Label selector for pods created by this chart.
    /// Applied to the generated MeshMember's target.
    pub selector: BTreeMap<String, String>,

    /// Ports exposed by the chart workloads
    #[serde(default)]
    pub ports: Vec<PackageMeshPort>,

    /// Services allowed to connect (inbound side of bilateral agreement)
    #[serde(default)]
    pub allowed_callers: Vec<ServiceRef>,

    /// Services this package depends on (outbound side)
    #[serde(default)]
    pub dependencies: Vec<ServiceRef>,

    /// Non-mesh egress rules (FQDN, CIDR, entity targets).
    /// For chart workloads that need to reach external endpoints.
    #[serde(default)]
    pub egress: Vec<EgressRule>,
}

/// A port exposed by the package for mesh policy generation
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PackageMeshPort {
    /// Port name (must be a valid DNS label)
    pub name: String,
    /// Port number
    pub port: u16,
    /// Protocol (defaults to TCP)
    #[serde(default = "default_tcp")]
    pub protocol: String,
}

fn default_tcp() -> String {
    "TCP".to_string()
}

// =============================================================================
// Status
// =============================================================================

/// Status of a LatticePackage
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatticePackageStatus {
    /// Current phase
    #[serde(default)]
    pub phase: PackagePhase,

    /// Applied chart version
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chart_version: Option<String>,

    /// Status conditions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    /// Human-readable message
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Observed generation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

// =============================================================================
// Validation
// =============================================================================

impl LatticePackageSpec {
    /// Validate the package spec
    pub fn validate(&self) -> Result<(), crate::ValidationError> {
        if self.chart.repository.is_empty() {
            return Err(crate::ValidationError::new("chart.repository is required"));
        }
        if self.chart.name.is_empty() {
            return Err(crate::ValidationError::new("chart.name is required"));
        }
        if self.chart.version.is_empty() {
            return Err(crate::ValidationError::new(
                "chart.version is required (no floating versions)",
            ));
        }

        if let Some(ref mesh) = self.mesh {
            if mesh.selector.is_empty() {
                return Err(crate::ValidationError::new(
                    "mesh.selector must have at least one label",
                ));
            }
        }

        Ok(())
    }
}

// =============================================================================
// Status helpers
// =============================================================================

impl LatticePackageStatus {
    /// Create a status update for a given phase
    pub fn with_phase(phase: PackagePhase) -> Self {
        Self {
            phase,
            ..Default::default()
        }
    }

    /// Set a condition on the status
    pub fn set_condition(
        &mut self,
        type_: &str,
        status: ConditionStatus,
        reason: &str,
        message: &str,
    ) {
        // Remove existing condition of the same type
        self.conditions.retain(|c| c.type_ != type_);
        self.conditions
            .push(Condition::new(type_, status, reason, message));
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_spec() -> LatticePackageSpec {
        LatticePackageSpec {
            chart: ChartRef {
                repository: "oci://registry.example.com/charts".to_string(),
                name: "redis".to_string(),
                version: "18.6.1".to_string(),
            },
            values: None,
            resources: BTreeMap::new(),
            mesh: None,
            target_namespace: None,
            create_namespace: false,
            skip_crds: false,
            timeout: None,
            propagate: false,
        }
    }

    #[test]
    fn valid_spec_passes() {
        assert!(valid_spec().validate().is_ok());
    }

    #[test]
    fn empty_repository_fails() {
        let mut spec = valid_spec();
        spec.chart.repository = String::new();
        assert!(spec.validate().is_err());
    }

    #[test]
    fn empty_chart_name_fails() {
        let mut spec = valid_spec();
        spec.chart.name = String::new();
        assert!(spec.validate().is_err());
    }

    #[test]
    fn empty_version_fails() {
        let mut spec = valid_spec();
        spec.chart.version = String::new();
        assert!(spec.validate().is_err());
    }

    #[test]
    fn empty_mesh_selector_fails() {
        let mut spec = valid_spec();
        spec.mesh = Some(PackageMeshConfig {
            selector: BTreeMap::new(),
            ports: vec![],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: vec![],
        });
        assert!(spec.validate().is_err());
    }

    #[test]
    fn mesh_with_selector_passes() {
        let mut spec = valid_spec();
        spec.mesh = Some(PackageMeshConfig {
            selector: BTreeMap::from([("app".to_string(), "redis".to_string())]),
            ports: vec![PackageMeshPort {
                name: "redis".to_string(),
                port: 6379,
                protocol: "TCP".to_string(),
            }],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: vec![],
        });
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn values_with_secret_directive_deserializes() {
        let yaml = r#"
chart:
  repository: oci://registry.example.com/charts
  name: redis
  version: "18.6.1"
resources:
  redis-creds:
    type: secret
    id: payments/redis/prod
    params:
      provider: vault-prod
      keys:
        - password
values:
  auth:
    existingSecret:
      $secret:
        redis-password: "${redis-creds.password}"
  master:
    resources:
      requests:
        cpu: "500m"
"#;
        let spec: LatticePackageSpec =
            serde_json::from_value(crate::yaml::parse_yaml(yaml).unwrap()).unwrap();

        assert_eq!(spec.chart.name, "redis");
        assert!(spec.resources.contains_key("redis-creds"));
        let values = spec.values.unwrap();
        assert!(values["auth"]["existingSecret"]["$secret"].is_object());
        assert_eq!(
            values["auth"]["existingSecret"]["$secret"]["redis-password"],
            serde_json::json!("${redis-creds.password}")
        );
        assert_eq!(
            values["master"]["resources"]["requests"]["cpu"],
            serde_json::json!("500m")
        );
    }

    #[test]
    fn phase_display() {
        assert_eq!(PackagePhase::Pending.to_string(), "Pending");
        assert_eq!(PackagePhase::Ready.to_string(), "Ready");
        assert_eq!(PackagePhase::Failed.to_string(), "Failed");
    }

    #[test]
    fn status_set_condition() {
        let mut status = LatticePackageStatus::default();
        status.set_condition(
            "SecretsReady",
            ConditionStatus::True,
            "Synced",
            "All secrets synced",
        );
        assert_eq!(status.conditions.len(), 1);

        // Setting same type replaces
        status.set_condition(
            "SecretsReady",
            ConditionStatus::False,
            "Failed",
            "Sync failed",
        );
        assert_eq!(status.conditions.len(), 1);
        assert_eq!(status.conditions[0].reason, "Failed");
    }
}
