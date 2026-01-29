//! LatticeServicePolicy Custom Resource Definition
//!
//! The LatticeServicePolicy CRD enables organization-wide Cedar authorization policies
//! that apply to services via label selectors. This creates a two-tier policy model:
//!
//! 1. **LatticeServicePolicy** (selector-based, ~5-20 policies per cluster)
//! 2. **LatticeService.authorization** (inline, service-specific)
//!
//! ## Evaluation Order
//!
//! 1. All matching LatticeServicePolicy `forbid` rules -> if ANY matches, DENY
//! 2. LatticeService embedded Cedar policy -> if permit matches, ALLOW
//! 3. All matching LatticeServicePolicy `permit` rules -> if ANY matches, ALLOW
//! 4. Default: DENY
//!
//! **Key principle:** `forbid` rules from any matching policy are "sticky" - they
//! cannot be overridden by service-level policies.

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::service::AuthorizationConfig;
use super::types::Condition;

/// Operator for label selector requirements
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum LabelSelectorOperator {
    /// Label value must be in the specified set
    In,
    /// Label value must not be in the specified set
    NotIn,
    /// Label must exist (value ignored)
    Exists,
    /// Label must not exist (value ignored)
    DoesNotExist,
}

impl LabelSelectorOperator {
    /// Check if a label value matches this requirement
    ///
    /// - `label_value`: The actual label value (None if label doesn't exist)
    /// - `values`: The values specified in the requirement
    pub fn matches(&self, label_value: Option<&str>, values: &[String]) -> bool {
        match self {
            Self::In => label_value.is_some_and(|v| values.iter().any(|req| req == v)),
            Self::NotIn => {
                label_value.is_none() || !values.iter().any(|req| Some(req.as_str()) == label_value)
            }
            Self::Exists => label_value.is_some(),
            Self::DoesNotExist => label_value.is_none(),
        }
    }
}

/// A label selector requirement (similar to Kubernetes LabelSelectorRequirement)
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelectorRequirement {
    /// The label key that the selector applies to
    pub key: String,

    /// Operator representing the relationship between label and values
    pub operator: LabelSelectorOperator,

    /// Array of string values
    ///
    /// - For `In` and `NotIn` operators: must be non-empty
    /// - For `Exists` and `DoesNotExist`: must be empty
    #[serde(default)]
    pub values: Vec<String>,
}

impl LabelSelectorRequirement {
    /// Check if a label set matches this requirement
    pub fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        let value = labels.get(&self.key).map(|s| s.as_str());
        self.operator.matches(value, &self.values)
    }
}

/// Namespace selector for targeting services in specific namespaces
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceSelector {
    /// Map of label key-value pairs for exact matching
    ///
    /// All labels must match for the namespace to be selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_labels: Option<BTreeMap<String, String>>,

    /// List of label selector requirements
    ///
    /// All requirements must be satisfied for the namespace to be selected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_expressions: Vec<LabelSelectorRequirement>,
}

impl NamespaceSelector {
    /// Check if namespace labels match this selector
    pub fn matches(&self, namespace_labels: &BTreeMap<String, String>) -> bool {
        // Check matchLabels (all must match)
        if let Some(match_labels) = &self.match_labels {
            for (key, value) in match_labels {
                if namespace_labels.get(key) != Some(value) {
                    return false;
                }
            }
        }

        // Check matchExpressions (all must match)
        for req in &self.match_expressions {
            if !req.matches(namespace_labels) {
                return false;
            }
        }

        true
    }

    /// Check if this selector is empty (matches everything)
    pub fn is_empty(&self) -> bool {
        self.match_labels.as_ref().is_none_or(|m| m.is_empty()) && self.match_expressions.is_empty()
    }
}

/// Service selector for targeting LatticeServices by labels
///
/// An empty selector `{}` matches ALL services.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSelector {
    /// Map of label key-value pairs for exact matching
    ///
    /// All labels must match for the service to be selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_labels: Option<BTreeMap<String, String>>,

    /// List of label selector requirements for complex queries
    ///
    /// All requirements must be satisfied for the service to be selected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_expressions: Vec<LabelSelectorRequirement>,

    /// Target services in specific namespaces
    ///
    /// If not specified, the policy only applies to services in the same namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_selector: Option<NamespaceSelector>,
}

impl ServiceSelector {
    /// Check if a service matches this selector
    ///
    /// # Arguments
    /// - `service_labels`: Labels on the LatticeService
    /// - `namespace_labels`: Labels on the namespace containing the service
    /// - `policy_namespace`: Namespace where the LatticeServicePolicy is defined
    /// - `service_namespace`: Namespace where the LatticeService is defined
    pub fn matches(
        &self,
        service_labels: &BTreeMap<String, String>,
        namespace_labels: &BTreeMap<String, String>,
        policy_namespace: &str,
        service_namespace: &str,
    ) -> bool {
        // Check namespace constraint
        match &self.namespace_selector {
            Some(ns_selector) => {
                // If namespace selector is specified, it must match
                if !ns_selector.matches(namespace_labels) {
                    return false;
                }
            }
            None => {
                // If no namespace selector, policy only applies to same namespace
                if policy_namespace != service_namespace {
                    return false;
                }
            }
        }

        // Check matchLabels (all must match)
        if let Some(match_labels) = &self.match_labels {
            for (key, value) in match_labels {
                if service_labels.get(key) != Some(value) {
                    return false;
                }
            }
        }

        // Check matchExpressions (all must match)
        for req in &self.match_expressions {
            if !req.matches(service_labels) {
                return false;
            }
        }

        true
    }

    /// Check if this selector is empty (matches all services in the namespace)
    pub fn is_empty(&self) -> bool {
        self.match_labels.as_ref().is_none_or(|m| m.is_empty())
            && self.match_expressions.is_empty()
            && self
                .namespace_selector
                .as_ref()
                .is_none_or(|ns| ns.is_empty())
    }
}

/// Phase of a LatticeServicePolicy
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum ServicePolicyPhase {
    /// Policy is pending processing
    #[default]
    Pending,
    /// Policy is being compiled
    Compiling,
    /// Policy is active and ready
    Active,
    /// Policy compilation or validation failed
    Failed,
}

impl std::fmt::Display for ServicePolicyPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Compiling => write!(f, "Compiling"),
            Self::Active => write!(f, "Active"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Status of a LatticeServicePolicy
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatticeServicePolicyStatus {
    /// Current phase of the policy
    #[serde(default)]
    pub phase: ServicePolicyPhase,

    /// Number of services currently matched by this policy's selector
    #[serde(default)]
    pub matched_services: u32,

    /// List of matched service references (namespace/name)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_service_refs: Vec<String>,

    /// Status conditions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    /// Human-readable message about current state
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Observed generation for status reconciliation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

/// Specification for a LatticeServicePolicy
///
/// LatticeServicePolicy applies Cedar authorization policies to services
/// matching its selector. This enables organization-wide authorization
/// baselines that combine with service-level policies.
///
/// ## Example
///
/// ```yaml
/// apiVersion: lattice.dev/v1alpha1
/// kind: LatticeServicePolicy
/// metadata:
///   name: pci-compliance
///   namespace: lattice-system
/// spec:
///   selector:
///     matchLabels:
///       environment: production
///     matchExpressions:
///       - key: data-tier
///         operator: In
///         values: [critical, sensitive]
///     namespaceSelector:
///       matchLabels:
///         compliance: pci
///   authorization:
///     cedar:
///       policies: |
///         forbid(principal, action, resource)
///         when { !context.authenticated };
///   description: "Require authentication for PCI-compliant production services"
/// ```
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "LatticeServicePolicy",
    plural = "latticeservicepolicies",
    shortname = "lsp",
    namespaced,
    status = "LatticeServicePolicyStatus",
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Matched","type":"integer","jsonPath":".status.matchedServices"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LatticeServicePolicySpec {
    /// Selector for matching LatticeServices
    ///
    /// An empty selector `{}` matches all services (within namespace constraints).
    #[serde(default)]
    pub selector: ServiceSelector,

    /// Authorization configuration (OIDC + Cedar policies)
    ///
    /// The Cedar policies in this configuration are applied to all matching services.
    /// `forbid` rules take precedence and cannot be overridden by service-level policies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<AuthorizationConfig>,

    /// Human-readable description of this policy's purpose
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Priority for policy ordering (higher = evaluated first)
    ///
    /// When multiple policies match a service, they are evaluated in priority order.
    /// Policies with equal priority are evaluated in alphabetical order by name.
    /// Default is 0.
    #[serde(default)]
    pub priority: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_selector_operator_in() {
        let op = LabelSelectorOperator::In;

        // Match when value is in the set
        assert!(op.matches(Some("prod"), &["dev".into(), "prod".into()]));

        // No match when value not in set
        assert!(!op.matches(Some("staging"), &["dev".into(), "prod".into()]));

        // No match when label doesn't exist
        assert!(!op.matches(None, &["dev".into(), "prod".into()]));
    }

    #[test]
    fn test_label_selector_operator_not_in() {
        let op = LabelSelectorOperator::NotIn;

        // Match when value is not in the set
        assert!(op.matches(Some("staging"), &["dev".into(), "prod".into()]));

        // Match when label doesn't exist
        assert!(op.matches(None, &["dev".into(), "prod".into()]));

        // No match when value is in set
        assert!(!op.matches(Some("prod"), &["dev".into(), "prod".into()]));
    }

    #[test]
    fn test_label_selector_operator_exists() {
        let op = LabelSelectorOperator::Exists;

        // Match when label exists
        assert!(op.matches(Some("any-value"), &[]));

        // No match when label doesn't exist
        assert!(!op.matches(None, &[]));
    }

    #[test]
    fn test_label_selector_operator_does_not_exist() {
        let op = LabelSelectorOperator::DoesNotExist;

        // Match when label doesn't exist
        assert!(op.matches(None, &[]));

        // No match when label exists
        assert!(!op.matches(Some("any-value"), &[]));
    }

    #[test]
    fn test_label_selector_requirement() {
        let req = LabelSelectorRequirement {
            key: "environment".to_string(),
            operator: LabelSelectorOperator::In,
            values: vec!["production".to_string(), "staging".to_string()],
        };

        let mut labels = BTreeMap::new();
        labels.insert("environment".to_string(), "production".to_string());
        assert!(req.matches(&labels));

        labels.insert("environment".to_string(), "development".to_string());
        assert!(!req.matches(&labels));
    }

    #[test]
    fn test_namespace_selector_empty() {
        let selector = NamespaceSelector::default();
        assert!(selector.is_empty());

        let labels = BTreeMap::new();
        assert!(selector.matches(&labels));
    }

    #[test]
    fn test_namespace_selector_match_labels() {
        let mut match_labels = BTreeMap::new();
        match_labels.insert("compliance".to_string(), "pci".to_string());

        let selector = NamespaceSelector {
            match_labels: Some(match_labels),
            match_expressions: vec![],
        };

        let mut ns_labels = BTreeMap::new();
        ns_labels.insert("compliance".to_string(), "pci".to_string());
        ns_labels.insert("team".to_string(), "platform".to_string());
        assert!(selector.matches(&ns_labels));

        ns_labels.insert("compliance".to_string(), "hipaa".to_string());
        assert!(!selector.matches(&ns_labels));
    }

    #[test]
    fn test_service_selector_same_namespace() {
        let selector = ServiceSelector::default();

        let service_labels = BTreeMap::new();
        let namespace_labels = BTreeMap::new();

        // Same namespace matches
        assert!(selector.matches(&service_labels, &namespace_labels, "default", "default"));

        // Different namespace doesn't match (no namespace selector)
        assert!(!selector.matches(&service_labels, &namespace_labels, "default", "other"));
    }

    #[test]
    fn test_service_selector_with_labels() {
        let mut match_labels = BTreeMap::new();
        match_labels.insert("environment".to_string(), "production".to_string());

        let selector = ServiceSelector {
            match_labels: Some(match_labels),
            match_expressions: vec![],
            namespace_selector: None,
        };

        let mut service_labels = BTreeMap::new();
        service_labels.insert("environment".to_string(), "production".to_string());
        let namespace_labels = BTreeMap::new();

        assert!(selector.matches(&service_labels, &namespace_labels, "default", "default"));

        service_labels.insert("environment".to_string(), "development".to_string());
        assert!(!selector.matches(&service_labels, &namespace_labels, "default", "default"));
    }

    #[test]
    fn test_service_selector_with_namespace_selector() {
        let mut ns_match_labels = BTreeMap::new();
        ns_match_labels.insert("compliance".to_string(), "pci".to_string());

        let selector = ServiceSelector {
            match_labels: None,
            match_expressions: vec![],
            namespace_selector: Some(NamespaceSelector {
                match_labels: Some(ns_match_labels),
                match_expressions: vec![],
            }),
        };

        let service_labels = BTreeMap::new();
        let mut namespace_labels = BTreeMap::new();
        namespace_labels.insert("compliance".to_string(), "pci".to_string());

        // Cross-namespace matching works when namespace selector matches
        assert!(selector.matches(
            &service_labels,
            &namespace_labels,
            "default",
            "pci-namespace"
        ));

        // Fails if namespace labels don't match
        namespace_labels.insert("compliance".to_string(), "hipaa".to_string());
        assert!(!selector.matches(
            &service_labels,
            &namespace_labels,
            "default",
            "pci-namespace"
        ));
    }

    #[test]
    fn test_service_selector_complex() {
        let mut match_labels = BTreeMap::new();
        match_labels.insert("app".to_string(), "api".to_string());

        let selector = ServiceSelector {
            match_labels: Some(match_labels),
            match_expressions: vec![
                LabelSelectorRequirement {
                    key: "tier".to_string(),
                    operator: LabelSelectorOperator::In,
                    values: vec!["frontend".to_string(), "backend".to_string()],
                },
                LabelSelectorRequirement {
                    key: "deprecated".to_string(),
                    operator: LabelSelectorOperator::DoesNotExist,
                    values: vec![],
                },
            ],
            namespace_selector: None,
        };

        let mut service_labels = BTreeMap::new();
        service_labels.insert("app".to_string(), "api".to_string());
        service_labels.insert("tier".to_string(), "backend".to_string());
        let namespace_labels = BTreeMap::new();

        // Matches: app=api, tier in (frontend, backend), no deprecated label
        assert!(selector.matches(&service_labels, &namespace_labels, "default", "default"));

        // Fails: wrong tier
        service_labels.insert("tier".to_string(), "database".to_string());
        assert!(!selector.matches(&service_labels, &namespace_labels, "default", "default"));

        // Fails: has deprecated label
        service_labels.insert("tier".to_string(), "backend".to_string());
        service_labels.insert("deprecated".to_string(), "true".to_string());
        assert!(!selector.matches(&service_labels, &namespace_labels, "default", "default"));
    }

    #[test]
    fn test_empty_selector_matches_all_in_namespace() {
        let selector = ServiceSelector::default();
        assert!(selector.is_empty());

        let service_labels = BTreeMap::new();
        let namespace_labels = BTreeMap::new();

        // Empty selector matches all services in the same namespace
        assert!(selector.matches(&service_labels, &namespace_labels, "default", "default"));
    }

    #[test]
    fn test_service_policy_phase_display() {
        assert_eq!(ServicePolicyPhase::Pending.to_string(), "Pending");
        assert_eq!(ServicePolicyPhase::Compiling.to_string(), "Compiling");
        assert_eq!(ServicePolicyPhase::Active.to_string(), "Active");
        assert_eq!(ServicePolicyPhase::Failed.to_string(), "Failed");
    }
}
