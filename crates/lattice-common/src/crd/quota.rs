//! LatticeQuota CRD for per-principal resource limits
//!
//! A LatticeQuota defines resource consumption limits (CPU, memory, GPU) for a
//! Cedar principal (User, Group, or Service). The quota controller tracks usage
//! in status, and the workload compiler enforces soft limits at compile time.
//!
//! - **Soft limits** (required): burst ceiling. The compiler rejects workloads
//!   that would exceed these. Sum of soft quotas tells the autoscaler the
//!   maximum scale target.
//! - **Hard limits** (optional): guaranteed reserved capacity. The cluster keeps
//!   at least this much provisioned even when unused. Sum of hard quotas defines
//!   minimum cluster compute.
//!
//! Example:
//! ```yaml
//! apiVersion: lattice.dev/v1alpha1
//! kind: LatticeQuota
//! metadata:
//!   name: ml-team-gpu-budget
//!   namespace: lattice-system
//! spec:
//!   principal: 'Lattice::Group::"ml-team"'
//!   soft:
//!     cpu: "128"
//!     memory: "512Gi"
//!     nvidia.com/gpu: "16"
//!   hard:
//!     cpu: "64"
//!     memory: "256Gi"
//!     nvidia.com/gpu: "8"
//!   maxPerWorkload:
//!     nvidia.com/gpu: "8"
//! ```

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::resources::parse_resource_by_key;

/// LatticeQuota defines resource limits for a Cedar principal.
///
/// The `principal` field accepts any Cedar principal string:
/// - `Lattice::Service::"namespace/name"` — limits a single workload
/// - `Lattice::Group::"group-name"` — limits all workloads in namespaces labeled `lattice.dev/group: <name>`
/// - `Lattice::User::"email"` — limits all workloads annotated `lattice.dev/owner: <email>`
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "LatticeQuota",
    namespaced,
    status = "LatticeQuotaStatus",
    printcolumn = r#"{"name":"Principal","type":"string","jsonPath":".spec.principal"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LatticeQuotaSpec {
    /// Cedar principal string (e.g., `Lattice::Group::"ml-team"`)
    pub principal: String,

    /// Soft resource limits — burst ceiling for the principal.
    ///
    /// The compiler rejects workloads that would exceed these limits.
    /// The sum of all soft quotas tells the autoscaler the maximum it may
    /// need to scale to. This is the default and only required limit.
    ///
    /// Keys are resource names: `cpu` (cores), `memory` (bytes with suffix),
    /// `nvidia.com/gpu` (count). Values are Kubernetes quantity strings.
    pub soft: BTreeMap<String, String>,

    /// Hard resource limits — guaranteed reserved capacity for the principal.
    ///
    /// The cluster will keep at least this much capacity provisioned even when
    /// unused. The sum of all hard quotas defines the minimum compute the
    /// cluster must maintain. Optional — omit for best-effort (soft-only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard: Option<BTreeMap<String, String>>,

    /// Optional per-workload caps. Any single workload exceeding these is rejected
    /// regardless of total quota availability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_per_workload: Option<BTreeMap<String, String>>,

    /// Whether this quota is enabled. Disabled quotas are not enforced.
    #[serde(default = "super::default_true")]
    pub enabled: bool,
}

impl LatticeQuotaSpec {
    /// Validate the quota spec. Returns an error if any quantity string is unparseable
    /// or the principal format is invalid.
    pub fn validate(&self) -> Result<(), crate::Error> {
        QuotaPrincipal::parse(&self.principal)
            .map_err(|e| crate::Error::validation(e.to_string()))?;

        validate_resource_map(&self.soft, "soft")?;

        if let Some(ref hard) = self.hard {
            validate_resource_map(hard, "hard")?;

            // Hard limits must not exceed soft limits
            for (key, hard_val) in hard {
                if let Some(soft_val) = self.soft.get(key) {
                    let hard_parsed = parse_resource_by_key(key, hard_val)
                        .map_err(|_| crate::Error::validation(format!("hard.{key}: invalid")))?;
                    let soft_parsed = parse_resource_by_key(key, soft_val)
                        .map_err(|_| crate::Error::validation(format!("soft.{key}: invalid")))?;
                    if hard_parsed > soft_parsed {
                        return Err(crate::Error::validation(format!(
                            "hard.{key} ({hard_val}) exceeds soft.{key} ({soft_val})"
                        )));
                    }
                }
            }
        }

        if let Some(ref max) = self.max_per_workload {
            validate_resource_map(max, "maxPerWorkload")?;
        }

        Ok(())
    }
}

fn validate_resource_map(map: &BTreeMap<String, String>, field: &str) -> Result<(), crate::Error> {
    for (key, value) in map {
        parse_resource_by_key(key, value).map_err(|_| {
            crate::Error::validation(format!("{field}.{key}: invalid quantity '{value}'"))
        })?;
    }
    Ok(())
}

/// LatticeQuota status
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatticeQuotaStatus {
    /// Current phase
    #[serde(default)]
    pub phase: LatticeQuotaPhase,

    /// Current resource usage by the principal (same keys as `spec.soft`)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub used: BTreeMap<String, String>,

    /// Number of workloads contributing to usage
    #[serde(default)]
    pub workload_count: u32,

    /// Human-readable message
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Last observed metadata.generation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

/// LatticeQuota phase
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub enum LatticeQuotaPhase {
    /// Quota is being initialized
    #[default]
    Pending,
    /// Quota is active and usage is within limits
    Active,
    /// Usage exceeds hard limits
    Exceeded,
    /// Quota spec is invalid
    Invalid,
}

impl std::fmt::Display for LatticeQuotaPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Active => write!(f, "Active"),
            Self::Exceeded => write!(f, "Exceeded"),
            Self::Invalid => write!(f, "Invalid"),
        }
    }
}

// =============================================================================
// Principal matching
// =============================================================================

/// Label on namespaces that maps them to a group for quota purposes.
pub const QUOTA_GROUP_LABEL: &str = "lattice.dev/group";

/// Annotation on workloads that maps them to an owner for quota purposes.
pub const QUOTA_OWNER_ANNOTATION: &str = "lattice.dev/owner";

/// Parsed quota principal
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuotaPrincipal {
    /// Matches a single workload by namespace + name
    Service {
        /// Workload namespace
        namespace: String,
        /// Workload name
        name: String,
    },
    /// Matches all workloads in namespaces labeled `lattice.dev/group: <name>`
    Group {
        /// Group name
        name: String,
    },
    /// Matches all workloads annotated `lattice.dev/owner: <email>`
    User {
        /// User email
        email: String,
    },
}

impl QuotaPrincipal {
    /// Parse a Cedar principal string into a QuotaPrincipal.
    ///
    /// Accepted formats:
    /// - `Lattice::Service::"namespace/name"`
    /// - `Lattice::Group::"group-name"`
    /// - `Lattice::User::"user@example.com"`
    pub fn parse(principal: &str) -> Result<Self, QuotaPrincipalError> {
        let id = extract_cedar_id(principal, "Service");
        if let Some(id) = id {
            let (ns, name) = id.split_once('/').ok_or_else(|| {
                QuotaPrincipalError(format!(
                    "Service principal must be 'namespace/name', got '{id}'"
                ))
            })?;
            return Ok(Self::Service {
                namespace: ns.to_string(),
                name: name.to_string(),
            });
        }

        let id = extract_cedar_id(principal, "Group");
        if let Some(id) = id {
            return Ok(Self::Group {
                name: id.to_string(),
            });
        }

        let id = extract_cedar_id(principal, "User");
        if let Some(id) = id {
            return Ok(Self::User {
                email: id.to_string(),
            });
        }

        Err(QuotaPrincipalError(format!(
            "unsupported principal format: '{principal}' (expected Lattice::Service, Lattice::Group, or Lattice::User)"
        )))
    }

    /// Check if a workload matches this principal.
    pub fn matches_workload(
        &self,
        workload_namespace: &str,
        workload_name: &str,
        namespace_labels: &BTreeMap<String, String>,
        workload_annotations: &BTreeMap<String, String>,
    ) -> bool {
        match self {
            Self::Service { namespace, name } => {
                workload_namespace == namespace && workload_name == name
            }
            Self::Group { name } => namespace_labels
                .get(QUOTA_GROUP_LABEL)
                .map(|v| v == name)
                .unwrap_or(false),
            Self::User { email } => workload_annotations
                .get(QUOTA_OWNER_ANNOTATION)
                .map(|v| v == email)
                .unwrap_or(false),
        }
    }
}

/// Extract the quoted ID from a Cedar entity reference like `Lattice::Type::"id"`.
fn extract_cedar_id<'a>(principal: &'a str, type_name: &str) -> Option<&'a str> {
    let prefix = format!("Lattice::{}::\"", type_name);
    principal
        .strip_prefix(&prefix)
        .and_then(|rest| rest.strip_suffix('"'))
}

/// Error parsing a quota principal string.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct QuotaPrincipalError(pub String);

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_service_principal() {
        let p = QuotaPrincipal::parse("Lattice::Service::\"payments/checkout\"").unwrap();
        assert_eq!(
            p,
            QuotaPrincipal::Service {
                namespace: "payments".to_string(),
                name: "checkout".to_string(),
            }
        );
    }

    #[test]
    fn parse_group_principal() {
        let p = QuotaPrincipal::parse("Lattice::Group::\"ml-team\"").unwrap();
        assert_eq!(
            p,
            QuotaPrincipal::Group {
                name: "ml-team".to_string(),
            }
        );
    }

    #[test]
    fn parse_user_principal() {
        let p = QuotaPrincipal::parse("Lattice::User::\"alice@example.com\"").unwrap();
        assert_eq!(
            p,
            QuotaPrincipal::User {
                email: "alice@example.com".to_string(),
            }
        );
    }

    #[test]
    fn parse_invalid_principal() {
        assert!(QuotaPrincipal::parse("Lattice::Unknown::\"foo\"").is_err());
        assert!(QuotaPrincipal::parse("not-a-principal").is_err());
        assert!(QuotaPrincipal::parse("").is_err());
    }

    #[test]
    fn parse_service_principal_missing_slash() {
        assert!(QuotaPrincipal::parse("Lattice::Service::\"nonamespace\"").is_err());
    }

    #[test]
    fn matches_service() {
        let p = QuotaPrincipal::Service {
            namespace: "ns".to_string(),
            name: "svc".to_string(),
        };
        assert!(p.matches_workload("ns", "svc", &BTreeMap::new(), &BTreeMap::new()));
        assert!(!p.matches_workload("ns", "other", &BTreeMap::new(), &BTreeMap::new()));
        assert!(!p.matches_workload("other", "svc", &BTreeMap::new(), &BTreeMap::new()));
    }

    #[test]
    fn matches_group() {
        let p = QuotaPrincipal::Group {
            name: "ml-team".to_string(),
        };
        let labels = BTreeMap::from([("lattice.dev/group".to_string(), "ml-team".to_string())]);
        assert!(p.matches_workload("ns", "svc", &labels, &BTreeMap::new()));

        let wrong = BTreeMap::from([("lattice.dev/group".to_string(), "other".to_string())]);
        assert!(!p.matches_workload("ns", "svc", &wrong, &BTreeMap::new()));
        assert!(!p.matches_workload("ns", "svc", &BTreeMap::new(), &BTreeMap::new()));
    }

    #[test]
    fn matches_user() {
        let p = QuotaPrincipal::User {
            email: "alice@example.com".to_string(),
        };
        let anns = BTreeMap::from([(
            "lattice.dev/owner".to_string(),
            "alice@example.com".to_string(),
        )]);
        assert!(p.matches_workload("ns", "svc", &BTreeMap::new(), &anns));

        let wrong = BTreeMap::from([(
            "lattice.dev/owner".to_string(),
            "bob@example.com".to_string(),
        )]);
        assert!(!p.matches_workload("ns", "svc", &BTreeMap::new(), &wrong));
    }

    #[test]
    fn validate_valid_spec() {
        let spec = LatticeQuotaSpec {
            principal: "Lattice::Group::\"team\"".to_string(),
            soft: BTreeMap::from([
                ("cpu".to_string(), "100".to_string()),
                ("memory".to_string(), "512Gi".to_string()),
                ("nvidia.com/gpu".to_string(), "16".to_string()),
            ]),
            hard: None,
            max_per_workload: Some(BTreeMap::from([(
                "nvidia.com/gpu".to_string(),
                "8".to_string(),
            )])),
            enabled: true,
        };
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn validate_with_hard_within_soft() {
        let spec = LatticeQuotaSpec {
            principal: "Lattice::Group::\"team\"".to_string(),
            soft: BTreeMap::from([("cpu".to_string(), "100".to_string())]),
            hard: Some(BTreeMap::from([("cpu".to_string(), "64".to_string())])),
            max_per_workload: None,
            enabled: true,
        };
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn validate_hard_exceeds_soft() {
        let spec = LatticeQuotaSpec {
            principal: "Lattice::Group::\"team\"".to_string(),
            soft: BTreeMap::from([("cpu".to_string(), "64".to_string())]),
            hard: Some(BTreeMap::from([("cpu".to_string(), "100".to_string())])),
            max_per_workload: None,
            enabled: true,
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn validate_bad_principal() {
        let spec = LatticeQuotaSpec {
            principal: "not-valid".to_string(),
            soft: BTreeMap::new(),
            hard: None,
            max_per_workload: None,
            enabled: true,
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn validate_bad_cpu_quantity() {
        let spec = LatticeQuotaSpec {
            principal: "Lattice::Group::\"team\"".to_string(),
            soft: BTreeMap::from([("cpu".to_string(), "abc".to_string())]),
            hard: None,
            max_per_workload: None,
            enabled: true,
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn validate_bad_memory_quantity() {
        let spec = LatticeQuotaSpec {
            principal: "Lattice::Group::\"team\"".to_string(),
            soft: BTreeMap::from([("memory".to_string(), "notmemory".to_string())]),
            hard: None,
            max_per_workload: None,
            enabled: true,
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn validate_bad_gpu_quantity() {
        let spec = LatticeQuotaSpec {
            principal: "Lattice::Group::\"team\"".to_string(),
            soft: BTreeMap::from([("nvidia.com/gpu".to_string(), "not-a-number".to_string())]),
            hard: None,
            max_per_workload: None,
            enabled: true,
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn phase_display() {
        assert_eq!(LatticeQuotaPhase::Pending.to_string(), "Pending");
        assert_eq!(LatticeQuotaPhase::Active.to_string(), "Active");
        assert_eq!(LatticeQuotaPhase::Exceeded.to_string(), "Exceeded");
        assert_eq!(LatticeQuotaPhase::Invalid.to_string(), "Invalid");
    }

    #[test]
    fn basic_quota_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: LatticeQuota
metadata:
  name: ml-team-gpu-budget
spec:
  principal: 'Lattice::Group::"ml-team"'
  soft:
    cpu: "128"
    memory: "512Gi"
    nvidia.com/gpu: "16"
  hard:
    cpu: "64"
    memory: "256Gi"
    nvidia.com/gpu: "8"
  maxPerWorkload:
    nvidia.com/gpu: "8"
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let quota: LatticeQuota = serde_json::from_value(value).expect("deserialize");
        assert!(quota.spec.principal.contains("ml-team"));
        assert_eq!(quota.spec.soft.get("cpu").unwrap(), "128");
        assert_eq!(quota.spec.hard.as_ref().unwrap().get("cpu").unwrap(), "64");
        assert_eq!(
            quota
                .spec
                .max_per_workload
                .as_ref()
                .unwrap()
                .get("nvidia.com/gpu")
                .unwrap(),
            "8"
        );
        assert!(quota.spec.enabled);
        assert!(quota.spec.validate().is_ok());
    }

    #[test]
    fn soft_only_quota_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: LatticeQuota
metadata:
  name: dev-team-soft-only
spec:
  principal: 'Lattice::Group::"dev-team"'
  soft:
    cpu: "32"
    memory: "128Gi"
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let quota: LatticeQuota = serde_json::from_value(value).expect("deserialize");
        assert!(quota.spec.hard.is_none());
        assert_eq!(quota.spec.soft.get("cpu").unwrap(), "32");
        assert!(quota.spec.validate().is_ok());
    }
}
