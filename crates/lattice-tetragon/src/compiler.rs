//! Tetragon runtime policy compilation
//!
//! Generates per-service TracingPolicyNamespaced resources from workload and runtime specs.
//! The only policy is a binary execution whitelist: any binary not in the whitelist is
//! SIGKILL'd via the `security_bprm_check` kprobe. Security context enforcement
//! (readOnlyRootFilesystem, runAsNonRoot, capabilities) is handled by the kubelet.

use std::collections::HashSet;

use lattice_common::crd::{has_unknown_binary_entrypoint, Probe, RuntimeSpec, WorkloadSpec};
use lattice_common::policy::tetragon::{
    KprobeArg, KprobeSpec, MatchArg, PodSelector, Selector, TracingPolicyNamespaced,
    TracingPolicySpec,
};

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

    // Binary execution whitelist
    // Explicit allowedBinaries: ["*"] always disables restrictions, even when
    // entrypoints exist (command, probes).
    // If ANY container lacks both `command` and `allowedBinaries`, we can't know
    // its image ENTRYPOINT, so the whole pod gets implicit wildcard (Tetragon
    // policies are pod-scoped). Cedar must authorize this separately.
    let allowed_binaries = extract_allowed_binaries(workload, runtime);
    let entrypoints = extract_entrypoint_binaries(workload, runtime);
    let needs_wildcard =
        allowed_binaries.contains("*") || any_container_unknown_entrypoint(workload, runtime);
    if !needs_wildcard {
        policies.push(compile_allow_binaries_policy(
            name,
            namespace,
            &allowed_binaries,
            &entrypoints,
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
            pod_selector: Some(PodSelector::for_service(service_name)),
            kprobes: vec![kprobe],
        },
    )
}

/// Compile the allow-binaries policy: anything NOT in the whitelist gets SIGKILL'd.
///
/// The whitelist is the union of declared `allowedBinaries` plus entrypoint binaries
/// auto-detected from container/sidecar commands and exec probes.
fn compile_allow_binaries_policy(
    name: &str,
    namespace: &str,
    allowed_binaries: &HashSet<String>,
    entrypoints: &HashSet<String>,
) -> TracingPolicyNamespaced {
    let mut allowed = allowed_binaries.clone();
    allowed.extend(entrypoints.iter().cloned());

    let mut allowed_list: Vec<String> = allowed.into_iter().collect();
    allowed_list.sort();

    let selectors = if allowed_list.is_empty() {
        vec![Selector::sigkill()]
    } else {
        let mut sel = Selector::sigkill();
        sel.match_args = vec![MatchArg {
            index: 0,
            operator: "NotEqual".to_string(),
            values: allowed_list,
        }];
        vec![sel]
    };

    make_policy(
        "allow-binaries",
        name,
        namespace,
        KprobeSpec::with_args(
            "security_bprm_check",
            vec![KprobeArg {
                index: 0,
                type_: "linux_binprm".to_string(),
                label: Some("filename".to_string()),
            }],
            selectors,
        ),
    )
}

/// Returns true if any container/sidecar has an unknown binary entrypoint,
/// meaning binary restrictions must be disabled for the whole pod (Tetragon
/// policies are pod-scoped).
fn any_container_unknown_entrypoint(workload: &WorkloadSpec, runtime: &RuntimeSpec) -> bool {
    workload
        .containers
        .values()
        .any(|c| has_unknown_binary_entrypoint(&c.command, &c.security))
        || runtime
            .sidecars
            .values()
            .any(|s| has_unknown_binary_entrypoint(&s.command, &s.security))
}

/// Collect `allowed_binaries` from all containers and sidecars (union)
fn extract_allowed_binaries(workload: &WorkloadSpec, runtime: &RuntimeSpec) -> HashSet<String> {
    let mut binaries = HashSet::new();
    for container in workload.containers.values() {
        if let Some(sec) = &container.security {
            binaries.extend(sec.allowed_binaries.iter().cloned());
        }
    }
    for sidecar in runtime.sidecars.values() {
        if let Some(sec) = &sidecar.security {
            binaries.extend(sec.allowed_binaries.iter().cloned());
        }
    }
    binaries
}

/// Extract entrypoint binaries (command[0]) from containers, sidecars, and exec probes.
///
/// These are auto-allowed so that container entrypoints and health probes aren't
/// killed by the binary whitelist.
fn extract_entrypoint_binaries(workload: &WorkloadSpec, runtime: &RuntimeSpec) -> HashSet<String> {
    let mut binaries = HashSet::new();
    for c in workload.containers.values() {
        collect_entrypoints(
            &c.command,
            &[&c.liveness_probe, &c.readiness_probe, &c.startup_probe],
            &mut binaries,
        );
    }
    for s in runtime.sidecars.values() {
        collect_entrypoints(
            &s.command,
            &[&s.liveness_probe, &s.readiness_probe, &s.startup_probe],
            &mut binaries,
        );
    }
    binaries
}

/// Collect the first element of `command` and exec probe commands into `binaries`.
fn collect_entrypoints(
    command: &Option<Vec<String>>,
    probes: &[&Option<Probe>],
    binaries: &mut HashSet<String>,
) {
    if let Some(cmd) = command {
        if let Some(binary) = cmd.first() {
            binaries.insert(binary.clone());
        }
    }
    for p in probes.iter().filter_map(|probe| probe.as_ref()) {
        if let Some(exec) = &p.exec {
            if let Some(binary) = exec.command.first() {
                binaries.insert(binary.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lattice_common::crd::{
        ContainerSpec, ExecProbe, Probe, RuntimeSpec, SecurityContext, SidecarSpec, WorkloadSpec,
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

    fn allowed_values(policies: &[TracingPolicyNamespaced]) -> Vec<String> {
        let allow = policies
            .iter()
            .find(|p| p.metadata.name == "allow-binaries-my-app")
            .expect("allow-binaries policy should exist");
        let sel = &allow.spec.kprobes[0].selectors[0];
        if sel.match_args.is_empty() {
            vec![]
        } else {
            sel.match_args[0].values.clone()
        }
    }

    #[test]
    fn no_command_no_allowed_binaries_generates_no_policies() {
        let (w, r) = default_workload(None);
        let policies = compile(&w, &r);
        assert!(
            policies.is_empty(),
            "No command → implicit wildcard → no policies at all"
        );
    }

    #[test]
    fn no_command_with_probe_skips_binary_policy() {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                readiness_probe: Some(Probe {
                    exec: Some(ExecProbe {
                        command: vec!["nc".to_string(), "-z".to_string(), "127.0.0.1".to_string()],
                    }),
                    ..Default::default()
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
        let n = names(&policies);
        assert!(
            !n.contains(&"allow-binaries-my-app"),
            "Container without command → unknown entrypoint → implicit wildcard"
        );
    }

    #[test]
    fn probe_entrypoint_auto_allowed() {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                command: Some(vec!["/usr/bin/myapp".to_string()]),
                liveness_probe: Some(Probe {
                    exec: Some(ExecProbe {
                        command: vec!["/bin/sh".to_string(), "-c".to_string(), "true".to_string()],
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let w = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let r = RuntimeSpec::default();

        let values = allowed_values(&compile(&w, &r));
        assert!(
            values.contains(&"/bin/sh".to_string()),
            "/bin/sh should be auto-allowed as probe entrypoint"
        );
    }

    #[test]
    fn container_command_entrypoint_auto_allowed() {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                command: Some(vec!["/usr/bin/python".to_string(), "app.py".to_string()]),
                ..Default::default()
            },
        );
        let w = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let r = RuntimeSpec::default();

        let values = allowed_values(&compile(&w, &r));
        assert!(values.contains(&"/usr/bin/python".to_string()));
        assert!(
            !values.contains(&"app.py".to_string()),
            "Only command[0] should be auto-allowed, not arguments"
        );
    }

    #[test]
    fn sidecar_command_entrypoint_auto_allowed() {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                command: Some(vec!["/usr/bin/myapp".to_string()]),
                ..Default::default()
            },
        );
        let w = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let mut sidecars = BTreeMap::new();
        sidecars.insert(
            "log-shipper".to_string(),
            SidecarSpec {
                image: "fluent:latest".to_string(),
                command: Some(vec![
                    "/bin/ash".to_string(),
                    "-c".to_string(),
                    "tail -f /dev/null".to_string(),
                ]),
                ..Default::default()
            },
        );
        let r = RuntimeSpec {
            sidecars,
            ..Default::default()
        };

        let values = allowed_values(&compile(&w, &r));
        assert!(values.contains(&"/bin/ash".to_string()));
    }

    #[test]
    fn declared_binaries_included_in_whitelist() {
        let (w, r) = default_workload(Some(SecurityContext {
            allowed_binaries: vec!["/usr/bin/curl".to_string(), "/usr/bin/convert".to_string()],
            ..Default::default()
        }));
        let values = allowed_values(&compile(&w, &r));
        assert!(values.contains(&"/usr/bin/curl".to_string()));
        assert!(values.contains(&"/usr/bin/convert".to_string()));
    }

    #[test]
    fn declared_binaries_plus_probe_entrypoint() {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                security: Some(SecurityContext {
                    allowed_binaries: vec!["/usr/bin/curl".to_string()],
                    ..Default::default()
                }),
                liveness_probe: Some(Probe {
                    exec: Some(ExecProbe {
                        command: vec!["/bin/sh".to_string(), "-c".to_string(), "true".to_string()],
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let w = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let r = RuntimeSpec::default();

        let values = allowed_values(&compile(&w, &r));
        assert!(values.contains(&"/usr/bin/curl".to_string()));
        assert!(values.contains(&"/bin/sh".to_string()));
    }

    #[test]
    fn wildcard_disables_binary_policy() {
        let (w, r) = default_workload(Some(SecurityContext {
            allowed_binaries: vec!["*".to_string()],
            ..Default::default()
        }));
        let policies = compile(&w, &r);
        let n = names(&policies);
        assert!(!n.contains(&"allow-binaries-my-app"));
    }

    #[test]
    fn unlisted_binary_not_in_whitelist() {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                command: Some(vec!["/bin/sleep".to_string(), "infinity".to_string()]),
                security: Some(SecurityContext {
                    allowed_binaries: vec!["/usr/bin/curl".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let w = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let r = RuntimeSpec::default();

        let values = allowed_values(&compile(&w, &r));
        assert!(
            values.contains(&"/bin/sleep".to_string()),
            "command[0] auto-whitelisted"
        );
        assert!(
            values.contains(&"/usr/bin/curl".to_string()),
            "declared binary whitelisted"
        );
        assert!(
            !values.contains(&"sh".to_string()),
            "sh not declared and not an entrypoint — should be killed"
        );
    }

    #[test]
    fn allowed_binaries_uses_not_equal_operator() {
        let (w, r) = default_workload(Some(SecurityContext {
            allowed_binaries: vec!["/usr/bin/curl".to_string()],
            ..Default::default()
        }));
        let policies = compile(&w, &r);
        let allow = policies
            .iter()
            .find(|p| p.metadata.name == "allow-binaries-my-app")
            .unwrap();
        assert_eq!(
            allow.spec.kprobes[0].selectors[0].match_args[0].operator,
            "NotEqual"
        );
    }

    #[test]
    fn allow_binaries_uses_bprm_check() {
        let (w, r) = default_workload(Some(SecurityContext {
            allowed_binaries: vec!["/usr/bin/curl".to_string()],
            ..Default::default()
        }));
        let policies = compile(&w, &r);
        let allow = policies
            .iter()
            .find(|p| p.metadata.name == "allow-binaries-my-app")
            .unwrap();
        assert_eq!(allow.spec.kprobes[0].call, "security_bprm_check");
    }
}
