//! Tetragon Helm chart embedding and cluster-wide baseline TracingPolicy
//!
//! Generates a TracingPolicy that blocks dangerous kernel operations across
//! all workload namespaces using kprobes on LSM hooks. System namespaces excluded.

use std::sync::LazyLock;

use super::split_yaml_documents;
use lattice_common::policy::tetragon::{
    KprobeArg, KprobeSpec, MatchArg, MatchNamespace, Selector, TracingPolicy, TracingPolicySpec,
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

const EXCLUDED_NAMESPACES: &[&str] = &[
    "kube-system",
    "cilium-system",
    "istio-system",
    "lattice-system",
    "cert-manager",
];

/// LSM hooks unconditionally blocked for workload namespaces
const BLOCKED_HOOKS: &[&str] = &[
    "security_ptrace_access_check",
    "security_kernel_module_request",
    "security_sb_mount",
    "security_sb_umount",
];

const SENSITIVE_PATHS: &[&str] = &["/etc/shadow", "/etc/passwd", "/etc/sudoers"];

/// Cluster-wide baseline TracingPolicy blocking dangerous operations via LSM hooks
pub fn generate_baseline_tracing_policy() -> TracingPolicy {
    let ns_exclusions = namespace_exclusions();

    let mut kprobes: Vec<KprobeSpec> = BLOCKED_HOOKS
        .iter()
        .map(|hook| {
            KprobeSpec::simple(
                *hook,
                vec![Selector::sigkill_excluding_namespaces(&ns_exclusions)],
            )
        })
        .collect();

    // security_file_open needs path-based arg filtering
    kprobes.push(KprobeSpec::with_args(
        "security_file_open",
        vec![KprobeArg {
            index: 0,
            type_: "file".to_string(),
            label: Some("path".to_string()),
        }],
        vec![Selector {
            match_args: vec![MatchArg {
                index: 0,
                operator: "Equal".to_string(),
                values: SENSITIVE_PATHS.iter().map(|s| s.to_string()).collect(),
            }],
            ..Selector::sigkill_excluding_namespaces(&ns_exclusions)
        }],
    ));

    TracingPolicy::new(
        "lattice-baseline-runtime",
        TracingPolicySpec {
            pod_selector: None,
            kprobes,
        },
    )
}

fn namespace_exclusions() -> Vec<MatchNamespace> {
    EXCLUDED_NAMESPACES
        .iter()
        .map(|ns| MatchNamespace {
            namespace: "Namespace".to_string(),
            operator: "NotIn".to_string(),
            values: vec![ns.to_string()],
        })
        .collect()
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
        assert!(calls.contains(&"security_file_open"));
    }

    #[test]
    fn baseline_blocks_sensitive_files() {
        let p = generate_baseline_tracing_policy();
        let file_open = p
            .spec
            .kprobes
            .iter()
            .find(|k| k.call == "security_file_open")
            .unwrap();
        let values = &file_open.selectors[0].match_args[0].values;
        for path in SENSITIVE_PATHS {
            assert!(values.contains(&path.to_string()), "missing {path}");
        }
    }

    #[test]
    fn baseline_excludes_system_namespaces() {
        let p = generate_baseline_tracing_policy();
        let excluded: Vec<&str> = p.spec.kprobes[0].selectors[0]
            .match_namespaces
            .iter()
            .flat_map(|ns| ns.values.iter().map(|v| v.as_str()))
            .collect();
        for ns in EXCLUDED_NAMESPACES {
            assert!(excluded.contains(ns), "missing exclusion for {ns}");
        }
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
