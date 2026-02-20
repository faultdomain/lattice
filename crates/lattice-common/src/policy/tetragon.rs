//! Tetragon TracingPolicy types for kernel-level runtime enforcement via eBPF kprobes on LSM hooks.
//!
//! Third layer of Lattice defense-in-depth: L4 Cilium → L7 Istio → kernel Tetragon.

use serde::{Deserialize, Serialize};

use crate::kube_utils::{HasApiResource, ObjectMeta};
use crate::policy::cilium::ClusterwideMetadata;

// =============================================================================
// TracingPolicy (cluster-scoped)
// =============================================================================

/// Tetragon TracingPolicy for cluster-wide runtime enforcement
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TracingPolicy {
    /// API version
    #[serde(default = "TracingPolicy::default_api_version")]
    pub api_version: String,
    /// Kind
    #[serde(default = "TracingPolicy::default_kind")]
    pub kind: String,
    /// Cluster-scoped metadata
    pub metadata: ClusterwideMetadata,
    /// Policy spec
    pub spec: TracingPolicySpec,
}

impl HasApiResource for TracingPolicy {
    const API_VERSION: &'static str = "cilium.io/v1alpha1";
    const KIND: &'static str = "TracingPolicy";
}

impl TracingPolicy {
    fn default_api_version() -> String {
        <Self as HasApiResource>::API_VERSION.to_string()
    }
    fn default_kind() -> String {
        <Self as HasApiResource>::KIND.to_string()
    }

    /// Create a new cluster-scoped TracingPolicy
    pub fn new(name: impl Into<String>, spec: TracingPolicySpec) -> Self {
        Self {
            api_version: Self::default_api_version(),
            kind: Self::default_kind(),
            metadata: ClusterwideMetadata::new(name),
            spec,
        }
    }
}

// =============================================================================
// TracingPolicyNamespaced (namespace-scoped)
// =============================================================================

/// Tetragon TracingPolicyNamespaced for per-service runtime enforcement
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TracingPolicyNamespaced {
    /// API version
    #[serde(default = "TracingPolicyNamespaced::default_api_version")]
    pub api_version: String,
    /// Kind
    #[serde(default = "TracingPolicyNamespaced::default_kind")]
    pub kind: String,
    /// Namespace-scoped metadata
    pub metadata: ObjectMeta,
    /// Policy spec
    pub spec: TracingPolicySpec,
}

impl HasApiResource for TracingPolicyNamespaced {
    const API_VERSION: &'static str = "cilium.io/v1alpha1";
    const KIND: &'static str = "TracingPolicyNamespaced";
}

impl TracingPolicyNamespaced {
    fn default_api_version() -> String {
        <Self as HasApiResource>::API_VERSION.to_string()
    }
    fn default_kind() -> String {
        <Self as HasApiResource>::KIND.to_string()
    }

    /// Create a new namespace-scoped TracingPolicyNamespaced
    pub fn new(
        name: impl Into<String>,
        namespace: impl Into<String>,
        spec: TracingPolicySpec,
    ) -> Self {
        let mut metadata = ObjectMeta::new(name, namespace);
        metadata.labels.insert(
            crate::LABEL_MANAGED_BY.to_string(),
            crate::LABEL_MANAGED_BY_LATTICE.to_string(),
        );
        Self {
            api_version: Self::default_api_version(),
            kind: Self::default_kind(),
            metadata,
            spec,
        }
    }
}

// =============================================================================
// Spec types
// =============================================================================

/// TracingPolicy spec containing kprobe hooks
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TracingPolicySpec {
    /// Pod selector to filter which pods this policy applies to
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_selector: Option<PodSelector>,
    /// Kprobe hooks to attach
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kprobes: Vec<KprobeSpec>,
}

/// Kprobe hook specification — attaches to kernel functions (LSM hooks), architecture-independent
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KprobeSpec {
    /// Kernel function to attach to (e.g., "security_bprm_check")
    pub call: String,
    /// Whether this is a syscall kprobe (CRD defaults to true, so always serialize)
    #[serde(default)]
    pub syscall: bool,
    /// Whether to also attach a return probe
    #[serde(default, rename = "return", skip_serializing_if = "is_false")]
    pub return_: bool,
    /// Return argument spec (when return_ is true)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_arg: Option<ReturnArg>,
    /// Arguments to extract from the kprobe
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<KprobeArg>,
    /// Selectors to filter which processes this applies to
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selectors: Vec<Selector>,
}

impl KprobeSpec {
    /// Create a kprobe with no argument extraction
    pub fn simple(call: impl Into<String>, selectors: Vec<Selector>) -> Self {
        Self {
            call: call.into(),
            syscall: false,
            return_: false,
            return_arg: None,
            args: vec![],
            selectors,
        }
    }

    /// Create a kprobe with argument extraction
    pub fn with_args(
        call: impl Into<String>,
        args: Vec<KprobeArg>,
        selectors: Vec<Selector>,
    ) -> Self {
        Self {
            call: call.into(),
            syscall: false,
            return_: false,
            return_arg: None,
            args,
            selectors,
        }
    }
}

fn is_false(v: &bool) -> bool {
    !v
}

/// Kprobe argument specification
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KprobeArg {
    /// Argument index
    pub index: u32,
    /// Argument type (e.g., "int", "file", "string")
    #[serde(rename = "type")]
    pub type_: String,
    /// Optional label
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Return argument specification for return probes
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReturnArg {
    /// Argument index
    pub index: u32,
    /// Argument type
    #[serde(rename = "type")]
    pub type_: String,
}

// =============================================================================
// Selector types
// =============================================================================

/// Selector for filtering kprobe events by namespace or argument
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Selector {
    /// Match by argument values
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_args: Vec<MatchArg>,
    /// Match by namespace inclusion/exclusion
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_namespaces: Vec<MatchNamespace>,
    /// Actions to take on match
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_actions: Vec<MatchAction>,
}

impl Selector {
    /// Selector that SIGKILLs matching processes
    pub fn sigkill() -> Self {
        Self {
            match_actions: vec![MatchAction {
                action: TracingAction::Sigkill,
            }],
            ..Default::default()
        }
    }
}

/// Argument matching for selectors
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MatchArg {
    /// Argument index to match
    pub index: u32,
    /// Operator: "Equal", "NotEqual", "Prefix", "Mask"
    pub operator: String,
    /// Values to match against
    pub values: Vec<String>,
}

/// Namespace matching for selectors
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MatchNamespace {
    /// Namespace type
    pub namespace: String,
    /// Operator: "In", "NotIn"
    pub operator: String,
    /// Namespace values
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
}

/// Pod selector for filtering which pods a TracingPolicy applies to
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodSelector {
    /// Match pods by labels
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub match_labels: std::collections::BTreeMap<String, String>,
}

impl PodSelector {
    /// Create a pod selector targeting a specific service by name label
    pub fn for_service(service_name: &str) -> Self {
        let mut labels = std::collections::BTreeMap::new();
        labels.insert(crate::LABEL_NAME.to_string(), service_name.to_string());
        Self {
            match_labels: labels,
        }
    }

    /// Create a pod selector targeting all Lattice-managed workload pods
    pub fn managed_by_lattice() -> Self {
        let mut labels = std::collections::BTreeMap::new();
        labels.insert(
            crate::LABEL_MANAGED_BY.to_string(),
            crate::LABEL_MANAGED_BY_LATTICE.to_string(),
        );
        Self {
            match_labels: labels,
        }
    }
}

/// Action to take when a selector matches
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MatchAction {
    /// Action type
    pub action: TracingAction,
}

/// Actions Tetragon can take on a matched event
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum TracingAction {
    /// Kill the process with SIGKILL
    Sigkill,
    /// Log the event (audit mode)
    Post,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracing_policy_serialization() {
        let policy = TracingPolicy::new(
            "block-ptrace",
            TracingPolicySpec {
                pod_selector: None,
                kprobes: vec![KprobeSpec::simple(
                    "security_ptrace_access_check",
                    vec![Selector {
                        match_actions: vec![MatchAction {
                            action: TracingAction::Sigkill,
                        }],
                        ..Default::default()
                    }],
                )],
            },
        );

        let json = serde_json::to_string_pretty(&policy).unwrap();
        assert!(json.contains("TracingPolicy"));
        assert!(json.contains("cilium.io/v1alpha1"));
        assert!(json.contains("security_ptrace_access_check"));
    }

    #[test]
    fn namespaced_policy_metadata() {
        let policy = TracingPolicyNamespaced::new(
            "block-shells-myapp",
            "prod",
            TracingPolicySpec {
                pod_selector: None,
                kprobes: vec![],
            },
        );
        assert_eq!(policy.metadata.namespace, "prod");
        assert_eq!(policy.kind, "TracingPolicyNamespaced");
    }

    #[test]
    fn roundtrip() {
        let policy = TracingPolicyNamespaced::new(
            "test",
            "default",
            TracingPolicySpec {
                pod_selector: Some(PodSelector::for_service("test-svc")),
                kprobes: vec![KprobeSpec::with_args(
                    "security_bprm_check",
                    vec![KprobeArg {
                        index: 0,
                        type_: "file".to_string(),
                        label: Some("filename".to_string()),
                    }],
                    vec![Selector {
                        match_args: vec![MatchArg {
                            index: 0,
                            operator: "Equal".to_string(),
                            values: vec!["/bin/sh".to_string()],
                        }],
                        match_actions: vec![MatchAction {
                            action: TracingAction::Sigkill,
                        }],
                        ..Default::default()
                    }],
                )],
            },
        );

        let json = serde_json::to_string(&policy).unwrap();
        let de: TracingPolicyNamespaced = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, de);
    }

    #[test]
    fn sigkill_selector() {
        let sel = Selector::sigkill();
        assert!(sel.match_args.is_empty());
        assert_eq!(sel.match_actions[0].action, TracingAction::Sigkill);
    }

    #[test]
    fn pod_selector_for_service() {
        let ps = PodSelector::for_service("my-app");
        assert_eq!(
            ps.match_labels.get("app.kubernetes.io/name").unwrap(),
            "my-app"
        );
    }
}
