//! Tetragon runtime policy compilation
//!
//! Generates per-service TracingPolicyNamespaced resources from workload and runtime specs.
//!
//! Policy tiers:
//! - Tier 1: Block shell execution (probe-aware exemptions)
//! - Tier 2: Enforce security context at kernel level (rootfs, setuid, capabilities)

use std::collections::HashSet;

use lattice_common::crd::{
    ContainerSpec, Probe, RuntimeSpec, SecurityContext, SidecarSpec, WorkloadSpec,
};
use lattice_common::policy::tetragon::{
    KprobeArg, KprobeSpec, MatchArg, Selector, TracingPolicyNamespaced, TracingPolicySpec,
};

/// Well-known shell paths to block by default
const SHELL_PATHS: &[&str] = &[
    "/bin/sh",
    "/bin/bash",
    "/bin/dash",
    "/bin/zsh",
    "/bin/csh",
    "/bin/ash",
    "/usr/bin/sh",
    "/usr/bin/bash",
    "/usr/bin/dash",
    "/usr/bin/zsh",
];

/// Compile TracingPolicyNamespaced resources for a workload.
///
/// Takes workload + runtime specs (not a specific CRD type) so it can be
/// called from LatticeService, LatticeJob, or LatticeModel controllers.
pub fn compile_tracing_policies(
    name: &str,
    namespace: &str,
    workload: &WorkloadSpec,
    runtime: &RuntimeSpec,
) -> Vec<TracingPolicyNamespaced> {
    let mut policies = Vec::new();

    // Tier 1: block shells not used by probes or container commands
    policies.push(compile_shell_policy(name, namespace, workload, runtime));

    // Tier 2: enforce declared security constraints at kernel level
    let security = aggregate_security_context(workload, runtime);

    if security.read_only_root_filesystem.unwrap_or(true) {
        policies.push(make_policy(
            "block-rootfs-write",
            name,
            namespace,
            KprobeSpec::with_args(
                "security_file_open",
                vec![KprobeArg {
                    index: 0,
                    type_: "file".to_string(),
                    label: Some("path".to_string()),
                }],
                vec![Selector::sigkill_for_service(name)],
            ),
        ));
    }

    if security.run_as_non_root.unwrap_or(true) {
        policies.push(make_policy(
            "block-setuid",
            name,
            namespace,
            KprobeSpec::simple(
                "security_task_fix_setuid",
                vec![Selector::sigkill_for_service(name)],
            ),
        ));
    }

    if security.capabilities.is_empty() {
        policies.push(make_policy(
            "block-capset",
            name,
            namespace,
            KprobeSpec::simple("security_capset", vec![Selector::sigkill_for_service(name)]),
        ));
    }

    policies
}

fn make_policy(
    prefix: &str,
    service_name: &str,
    namespace: &str,
    kprobe: KprobeSpec,
) -> TracingPolicyNamespaced {
    TracingPolicyNamespaced::new(
        format!("{prefix}-{service_name}"),
        namespace,
        TracingPolicySpec {
            kprobes: vec![kprobe],
        },
    )
}

/// Block shell execution unless a probe or container entrypoint needs it
fn compile_shell_policy(
    name: &str,
    namespace: &str,
    workload: &WorkloadSpec,
    runtime: &RuntimeSpec,
) -> TracingPolicyNamespaced {
    let allowed = extract_shell_paths(workload, runtime);

    let blocked: Vec<String> = SHELL_PATHS
        .iter()
        .filter(|s| !allowed.contains(**s))
        .map(|s| s.to_string())
        .collect();

    let selectors = if blocked.is_empty() {
        vec![]
    } else {
        let mut sel = Selector::sigkill_for_service(name);
        sel.match_args = vec![MatchArg {
            index: 0,
            operator: "Equal".to_string(),
            values: blocked,
        }];
        vec![sel]
    };

    make_policy(
        "block-shells",
        name,
        namespace,
        KprobeSpec::with_args(
            "security_bprm_check",
            vec![KprobeArg {
                index: 0,
                type_: "file".to_string(),
                label: Some("filename".to_string()),
            }],
            selectors,
        ),
    )
}

/// Scan containers and sidecars for shell paths in commands, args, and exec probes
fn extract_shell_paths(workload: &WorkloadSpec, runtime: &RuntimeSpec) -> HashSet<String> {
    let mut shells = HashSet::new();

    for container in workload.containers.values() {
        collect_from_container(container, &mut shells);
    }
    for sidecar in runtime.sidecars.values() {
        collect_from_sidecar(sidecar, &mut shells);
    }

    shells
}

fn collect_from_container(c: &ContainerSpec, shells: &mut HashSet<String>) {
    collect_from_strings(&c.command, shells);
    collect_from_strings(&c.args, shells);
    collect_from_probe(&c.liveness_probe, shells);
    collect_from_probe(&c.readiness_probe, shells);
    collect_from_probe(&c.startup_probe, shells);
}

fn collect_from_sidecar(s: &SidecarSpec, shells: &mut HashSet<String>) {
    collect_from_strings(&s.command, shells);
    collect_from_strings(&s.args, shells);
    collect_from_probe(&s.liveness_probe, shells);
    collect_from_probe(&s.readiness_probe, shells);
    collect_from_probe(&s.startup_probe, shells);
}

fn collect_from_strings(cmd: &Option<Vec<String>>, shells: &mut HashSet<String>) {
    if let Some(args) = cmd {
        for arg in args {
            if SHELL_PATHS.contains(&arg.as_str()) {
                shells.insert(arg.clone());
            }
        }
    }
}

fn collect_from_probe(probe: &Option<Probe>, shells: &mut HashSet<String>) {
    if let Some(probe) = probe {
        if let Some(exec) = &probe.exec {
            collect_from_strings(&Some(exec.command.clone()), shells);
        }
    }
}

/// Merge security contexts across all containers — most permissive wins
/// (if ANY container opts out of a restriction, we can't enforce it at kernel level)
fn aggregate_security_context(workload: &WorkloadSpec, runtime: &RuntimeSpec) -> SecurityContext {
    let mut result = SecurityContext::default();

    for container in workload.containers.values() {
        if let Some(sec) = &container.security {
            merge_security(&mut result, sec);
        }
    }
    for sidecar in runtime.sidecars.values() {
        if let Some(sec) = &sidecar.security {
            merge_security(&mut result, sec);
        }
    }

    result
}

fn merge_security(agg: &mut SecurityContext, sec: &SecurityContext) {
    if sec.read_only_root_filesystem == Some(false) {
        agg.read_only_root_filesystem = Some(false);
    }
    if sec.run_as_non_root == Some(false) {
        agg.run_as_non_root = Some(false);
    }
    for cap in &sec.capabilities {
        if !agg.capabilities.contains(cap) {
            agg.capabilities.push(cap.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lattice_common::crd::{
        ContainerSpec, ExecProbe, Probe, RuntimeSpec, SecurityContext, WorkloadSpec,
    };

    use super::*;

    fn default_workload(security: Option<SecurityContext>) -> (WorkloadSpec, RuntimeSpec) {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                security,
                ..Default::default()
            },
        );
        (
            WorkloadSpec {
                containers,
                ..Default::default()
            },
            RuntimeSpec::default(),
        )
    }

    fn compile(workload: &WorkloadSpec, runtime: &RuntimeSpec) -> Vec<TracingPolicyNamespaced> {
        compile_tracing_policies("my-app", "default", workload, runtime)
    }

    fn names(policies: &[TracingPolicyNamespaced]) -> Vec<&str> {
        policies.iter().map(|p| p.metadata.name.as_str()).collect()
    }

    #[test]
    fn default_security_generates_all_policies() {
        let (w, r) = default_workload(None);
        let policies = compile(&w, &r);
        let n = names(&policies);
        assert!(n.contains(&"block-shells-my-app"));
        assert!(n.contains(&"block-rootfs-write-my-app"));
        assert!(n.contains(&"block-setuid-my-app"));
        assert!(n.contains(&"block-capset-my-app"));
    }

    #[test]
    fn writable_rootfs_skips_file_open() {
        let (w, r) = default_workload(Some(SecurityContext {
            read_only_root_filesystem: Some(false),
            ..Default::default()
        }));
        let policies = compile(&w, &r);
        assert!(!names(&policies).contains(&"block-rootfs-write-my-app"));
    }

    #[test]
    fn root_allowed_skips_setuid() {
        let (w, r) = default_workload(Some(SecurityContext {
            run_as_non_root: Some(false),
            ..Default::default()
        }));
        let policies = compile(&w, &r);
        assert!(!names(&policies).contains(&"block-setuid-my-app"));
    }

    #[test]
    fn capabilities_requested_skips_capset() {
        let (w, r) = default_workload(Some(SecurityContext {
            capabilities: vec!["NET_ADMIN".to_string()],
            ..Default::default()
        }));
        let policies = compile(&w, &r);
        assert!(!names(&policies).contains(&"block-capset-my-app"));
    }

    #[test]
    fn probe_shell_exemption() {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                liveness_probe: Some(Probe {
                    http_get: None,
                    exec: Some(ExecProbe {
                        command: vec!["/bin/sh".to_string(), "-c".to_string(), "true".to_string()],
                    }),
                }),
                ..Default::default()
            },
        );
        let w = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let r = RuntimeSpec::default();

        let policies = compile(&w, &r);
        let shell_policy = policies
            .iter()
            .find(|p| p.metadata.name == "block-shells-my-app")
            .unwrap();
        let kp = &shell_policy.spec.kprobes[0];
        if !kp.selectors.is_empty() {
            let blocked = &kp.selectors[0].match_args[0].values;
            assert!(
                !blocked.contains(&"/bin/sh".to_string()),
                "/bin/sh should be exempted for probe"
            );
        }
    }

    #[test]
    fn container_command_shell_exemption() {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                command: Some(vec!["/bin/bash".to_string(), "-c".to_string()]),
                ..Default::default()
            },
        );
        let w = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let r = RuntimeSpec::default();

        let policies = compile(&w, &r);
        let kp = &policies
            .iter()
            .find(|p| p.metadata.name == "block-shells-my-app")
            .unwrap()
            .spec
            .kprobes[0];
        if !kp.selectors.is_empty() {
            let blocked = &kp.selectors[0].match_args[0].values;
            assert!(!blocked.contains(&"/bin/bash".to_string()));
        }
    }

    #[test]
    fn shell_policy_uses_bprm_check() {
        let (w, r) = default_workload(None);
        let policies = compile(&w, &r);
        let shell = policies
            .iter()
            .find(|p| p.metadata.name == "block-shells-my-app")
            .unwrap();
        assert_eq!(shell.spec.kprobes[0].call, "security_bprm_check");
    }
}
