//! CedarPolicy CRD for access control policies
//!
//! A CedarPolicy defines authorization rules using the Cedar policy language.
//! These policies control which users/groups can access which clusters.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// CedarPolicy defines access control policies for Lattice.
///
/// Policies are written in the Cedar policy language and evaluated by the
/// auth proxy to determine if a user can access a cluster.
///
/// Example:
/// ```yaml
/// apiVersion: lattice.dev/v1alpha1
/// kind: CedarPolicy
/// metadata:
///   name: frontend-team-access
///   namespace: lattice-system
/// spec:
///   description: Allow frontend team to access frontend clusters
///   policies: |
///     permit(
///       principal in Lattice::Group::"frontend-team",
///       action,
///       resource == Lattice::Cluster::"frontend-prod"
///     );
/// ```
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "CedarPolicy",
    namespaced,
    status = "CedarPolicyStatus",
    printcolumn = r#"{"name":"Description","type":"string","jsonPath":".spec.description"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct CedarPolicySpec {
    /// Human-readable description of what this policy does
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Cedar policy text
    ///
    /// This should contain one or more Cedar policy statements.
    /// Policies use the Lattice schema with these entity types:
    /// - Lattice::User - Individual users (principal)
    /// - Lattice::Group - User groups (principal)
    /// - Lattice::Cluster - Kubernetes clusters (resource)
    /// - Lattice::Action - K8s verbs: get, list, create, update, delete, etc.
    ///
    /// Example:
    /// ```cedar
    /// permit(
    ///   principal == Lattice::User::"alice@example.com",
    ///   action,
    ///   resource == Lattice::Cluster::"prod-frontend"
    /// );
    /// ```
    pub policies: String,

    /// Priority for policy evaluation (higher = evaluated first)
    /// Default: 0
    #[serde(default)]
    pub priority: i32,

    /// Whether this policy is enabled
    /// Disabled policies are not evaluated
    #[serde(default = "super::default_true")]
    pub enabled: bool,

    /// Whether to propagate this policy to child clusters
    /// When true, policy is distributed down the hierarchy
    #[serde(default = "super::default_true")]
    pub propagate: bool,
}

/// CedarPolicy status
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CedarPolicyStatus {
    /// Current phase
    #[serde(default)]
    pub phase: CedarPolicyPhase,

    /// Human-readable message
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Number of permit statements in the policy
    #[serde(default)]
    pub permit_count: u32,

    /// Number of forbid statements in the policy
    #[serde(default)]
    pub forbid_count: u32,

    /// Last time the policy was validated
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_validated: Option<String>,

    /// Validation errors (if any)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validation_errors: Vec<String>,
}

/// CedarPolicy phase
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum CedarPolicyPhase {
    /// Policy is being validated
    #[default]
    Pending,
    /// Policy parsed and validated successfully
    Valid,
    /// Policy has syntax or validation errors
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_cedar_policy_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: CedarPolicy
metadata:
  name: admin-access
spec:
  description: Allow admins full access
  policies: |
    permit(
      principal in Lattice::Group::"admins",
      action,
      resource
    );
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let policy: CedarPolicy = serde_json::from_value(value).expect("parse");
        assert_eq!(
            policy.spec.description,
            Some("Allow admins full access".to_string())
        );
        assert!(policy.spec.policies.contains("admins"));
        assert!(policy.spec.enabled);
        assert_eq!(policy.spec.priority, 0);
    }

    #[test]
    fn cedar_policy_with_priority_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: CedarPolicy
metadata:
  name: deny-production
spec:
  description: Deny access to production (evaluated first)
  priority: 100
  policies: |
    forbid(
      principal,
      action,
      resource == Lattice::Cluster::"production"
    ) unless {
      principal in Lattice::Group::"sre-team"
    };
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let policy: CedarPolicy = serde_json::from_value(value).expect("parse");
        assert_eq!(policy.spec.priority, 100);
        assert!(policy.spec.policies.contains("forbid"));
        assert!(policy.spec.policies.contains("sre-team"));
    }

    #[test]
    fn cedar_policy_disabled_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: CedarPolicy
metadata:
  name: legacy-policy
spec:
  enabled: false
  policies: |
    permit(principal, action, resource);
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let policy: CedarPolicy = serde_json::from_value(value).expect("parse");
        assert!(!policy.spec.enabled);
    }

    #[test]
    fn cedar_policy_multiple_statements() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: CedarPolicy
metadata:
  name: team-policies
spec:
  description: Team-specific access policies
  policies: |
    // Frontend team can access frontend clusters
    permit(
      principal in Lattice::Group::"frontend-team",
      action in [Lattice::Action::"get", Lattice::Action::"list"],
      resource == Lattice::Cluster::"frontend-prod"
    );

    // Backend team can access backend clusters
    permit(
      principal in Lattice::Group::"backend-team",
      action in [Lattice::Action::"get", Lattice::Action::"list"],
      resource == Lattice::Cluster::"backend-prod"
    );
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let policy: CedarPolicy = serde_json::from_value(value).expect("parse");
        assert!(policy.spec.policies.contains("frontend-team"));
        assert!(policy.spec.policies.contains("backend-team"));
    }

    #[test]
    fn cedar_policy_propagate_defaults_to_true() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: CedarPolicy
metadata:
  name: admin-access
spec:
  policies: |
    permit(principal, action, resource);
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let policy: CedarPolicy = serde_json::from_value(value).expect("parse");
        // propagate should default to true
        assert!(policy.spec.propagate);
    }

    #[test]
    fn cedar_policy_propagate_false() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: CedarPolicy
metadata:
  name: local-only-policy
spec:
  propagate: false
  policies: |
    permit(principal, action, resource);
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let policy: CedarPolicy = serde_json::from_value(value).expect("parse");
        assert!(!policy.spec.propagate);
    }
}
