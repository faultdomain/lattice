//! Tetragon Helm chart embedding and cluster-wide baseline TracingPolicy
//!
//! Generates a TracingPolicy that blocks dangerous kernel operations for
//! Lattice-managed workload pods using kprobes on LSM hooks. System pods are
//! excluded via podSelector (only pods with managed-by=lattice are targeted).

use std::sync::LazyLock;

use super::split_yaml_documents;
use lattice_common::policy::tetragon::{
    KprobeSpec, PodSelector, Selector, TracingPolicy, TracingPolicySpec,
};

static TETRAGON_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    split_yaml_documents(include_str!(concat!(env!("OUT_DIR"), "/tetragon.yaml")))
});

pub fn tetragon_version() -> &'static str {
    env!("TETRAGON_VERSION")
}

/// Pre-rendered Tetragon Helm chart manifests
pub fn generate_tetragon() -> &'static [String] {
    &TETRAGON_MANIFESTS
}

/// LSM hooks unconditionally blocked for workload pods
const BLOCKED_HOOKS: &[&str] = &[
    "security_ptrace_access_check",
    "security_kernel_module_request",
    "security_sb_mount",
    "security_sb_umount",
];

/// Cluster-wide baseline TracingPolicy blocking dangerous operations via LSM hooks
///
/// Uses podSelector to target only Lattice-managed workload pods, automatically
/// excluding system pods (kube-system, cilium-system, istio-system, etc.) which
/// don't carry the managed-by label.
pub fn generate_baseline_tracing_policy() -> TracingPolicy {
    let kprobes: Vec<KprobeSpec> = BLOCKED_HOOKS
        .iter()
        .map(|hook| KprobeSpec::simple(*hook, vec![Selector::sigkill()]))
        .collect();

    TracingPolicy::new(
        "lattice-baseline-runtime",
        TracingPolicySpec {
            pod_selector: Some(PodSelector::managed_by_lattice()),
            kprobes,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::policy::tetragon::TracingAction;

    #[test]
    fn version_is_set() {
        assert!(!tetragon_version().is_empty());
    }

    #[test]
    fn manifests_are_embedded() {
        let m = generate_tetragon();
        assert!(!m.is_empty());
        assert!(m.iter().any(|doc| doc.contains("DaemonSet")));
    }

    #[test]
    fn baseline_metadata() {
        let p = generate_baseline_tracing_policy();
        assert_eq!(p.metadata.name, "lattice-baseline-runtime");
        assert_eq!(p.api_version, "cilium.io/v1alpha1");
    }

    #[test]
    fn baseline_has_all_hooks() {
        let p = generate_baseline_tracing_policy();
        let calls: Vec<&str> = p.spec.kprobes.iter().map(|k| k.call.as_str()).collect();
        for hook in BLOCKED_HOOKS {
            assert!(calls.contains(hook), "missing {hook}");
        }
    }

    #[test]
    fn baseline_targets_lattice_managed_pods() {
        let p = generate_baseline_tracing_policy();
        let ps = p
            .spec
            .pod_selector
            .as_ref()
            .expect("podSelector must be set");
        assert_eq!(
            ps.match_labels.get("app.kubernetes.io/managed-by").unwrap(),
            "lattice"
        );
    }

    #[test]
    fn baseline_uses_sigkill() {
        let p = generate_baseline_tracing_policy();
        for kp in &p.spec.kprobes {
            for sel in &kp.selectors {
                assert!(sel
                    .match_actions
                    .iter()
                    .all(|a| a.action == TracingAction::Sigkill));
            }
        }
    }

    #[test]
    fn serialization_roundtrip() {
        let p = generate_baseline_tracing_policy();
        let json = serde_json::to_string(&p).unwrap();
        let de: TracingPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, de);
    }
}
