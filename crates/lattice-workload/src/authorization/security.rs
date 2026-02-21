//! Security override authorization via Cedar policies

use std::collections::HashSet;

use lattice_cedar::{PolicyEngine, SecurityAuthzRequest, SecurityOverrideRequest};
use lattice_common::crd::{
    has_unknown_binary_entrypoint, RuntimeSpec, SecurityContext, WorkloadSpec,
};

use crate::error::CompilationError;

/// Default Linux capabilities granted to containers by Docker/containerd.
///
/// These are the capabilities a container receives when no explicit `drop: [ALL]`
/// is applied. When `drop_capabilities` is set to something other than `["ALL"]`,
/// any capability in this set that is NOT in the drop list is implicitly retained
/// and must be authorized via Cedar policy.
///
/// Reference: <https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities>
const DEFAULT_CONTAINER_CAPABILITIES: &[&str] = &[
    "AUDIT_WRITE",
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "MKNOD",
    "NET_BIND_SERVICE",
    "NET_RAW",
    "SETFCAP",
    "SETGID",
    "SETPCAP",
    "SETUID",
    "SYS_CHROOT",
];

/// Authorize security overrides via Cedar policies (default-deny).
///
/// Scans the spec for any deviation from PSS restricted defaults, builds a
/// batch authorization request, and evaluates it.
pub(crate) async fn authorize_security_overrides(
    cedar: &PolicyEngine,
    name: &str,
    namespace: &str,
    workload: &WorkloadSpec,
    runtime: &RuntimeSpec,
) -> Result<(), CompilationError> {
    let overrides = collect_security_overrides(workload, runtime);

    if overrides.is_empty() {
        return Ok(());
    }

    let result = cedar
        .authorize_security_overrides(&SecurityAuthzRequest {
            service_name: name.to_string(),
            namespace: namespace.to_string(),
            overrides,
        })
        .await;

    if !result.is_allowed() {
        let details = result
            .denied
            .iter()
            .map(|d| {
                if let Some(ref c) = d.container {
                    format!("'{}' (container '{}'): {}", d.override_id, c, d.reason)
                } else {
                    format!("'{}': {}", d.override_id, d.reason)
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(CompilationError::security_override_denied(details));
    }

    Ok(())
}

/// Collect security overrides from WorkloadSpec + RuntimeSpec.
///
/// Scans pod-level and container-level fields for any deviation from the
/// PSS restricted profile defaults.
fn collect_security_overrides(
    workload: &WorkloadSpec,
    runtime: &RuntimeSpec,
) -> Vec<SecurityOverrideRequest> {
    let mut overrides = Vec::new();

    // Pod-level overrides (from RuntimeSpec)
    if runtime.host_network == Some(true) {
        overrides.push(SecurityOverrideRequest {
            override_id: "hostNetwork".into(),
            category: "pod".into(),
            container: None,
        });
    }
    if runtime.share_process_namespace == Some(true) {
        overrides.push(SecurityOverrideRequest {
            override_id: "shareProcessNamespace".into(),
            category: "pod".into(),
            container: None,
        });
    }

    // Container-level overrides
    for (name, container) in &workload.containers {
        collect_container_overrides(
            &mut overrides,
            name,
            container.security.as_ref(),
            &container.command,
        );
    }
    for (name, sidecar) in &runtime.sidecars {
        collect_container_overrides(
            &mut overrides,
            name,
            sidecar.security.as_ref(),
            &sidecar.command,
        );
    }

    overrides
}

/// Collect security overrides from a single container's SecurityContext.
///
/// When the container has an unknown binary entrypoint (no `command` and no
/// `allowedBinaries`), Tetragon infers an implicit wildcard. Cedar must
/// authorize it via an `allowedBinary:*` override.
fn collect_container_overrides(
    overrides: &mut Vec<SecurityOverrideRequest>,
    container_name: &str,
    security: Option<&SecurityContext>,
    command: &Option<Vec<String>>,
) {
    let cname = Some(container_name.to_string());

    // Unknown entrypoint → implicit wildcard requires Cedar authorization
    if has_unknown_binary_entrypoint(command, &security.cloned()) {
        overrides.push(SecurityOverrideRequest {
            override_id: "allowedBinary:*".into(),
            category: "binary".into(),
            container: cname.clone(),
        });
    }

    let Some(s) = security else { return };

    for cap in &s.capabilities {
        overrides.push(SecurityOverrideRequest {
            override_id: format!("capability:{cap}"),
            category: "capability".into(),
            container: cname.clone(),
        });
    }

    // If drop_capabilities relaxes the default "drop ALL", retained default
    // capabilities must also be authorized via Cedar.
    if s.privileged != Some(true) {
        if let Some(ref drops) = s.drop_capabilities {
            if !drops.iter().any(|d| d.eq_ignore_ascii_case("ALL")) {
                let explicitly_added: HashSet<String> = s
                    .capabilities
                    .iter()
                    .map(|c| c.to_ascii_uppercase())
                    .collect();
                let dropped: HashSet<String> =
                    drops.iter().map(|d| d.to_ascii_uppercase()).collect();

                for &default_cap in DEFAULT_CONTAINER_CAPABILITIES {
                    if dropped.contains(default_cap) || explicitly_added.contains(default_cap) {
                        continue;
                    }
                    overrides.push(SecurityOverrideRequest {
                        override_id: format!("capability:{default_cap}"),
                        category: "capability".into(),
                        container: cname.clone(),
                    });
                }
            }
        }
    }

    if s.privileged == Some(true) {
        overrides.push(SecurityOverrideRequest {
            override_id: "privileged".into(),
            category: "container".into(),
            container: cname.clone(),
        });
    }
    if s.run_as_user == Some(0) || s.run_as_non_root == Some(false) {
        overrides.push(SecurityOverrideRequest {
            override_id: "runAsRoot".into(),
            category: "container".into(),
            container: cname.clone(),
        });
    }
    if s.run_as_group == Some(0) {
        overrides.push(SecurityOverrideRequest {
            override_id: "runAsRootGroup".into(),
            category: "container".into(),
            container: cname.clone(),
        });
    }
    if s.read_only_root_filesystem == Some(false) {
        overrides.push(SecurityOverrideRequest {
            override_id: "readWriteRootFilesystem".into(),
            category: "container".into(),
            container: cname.clone(),
        });
    }
    if s.allow_privilege_escalation == Some(true) {
        overrides.push(SecurityOverrideRequest {
            override_id: "allowPrivilegeEscalation".into(),
            category: "container".into(),
            container: cname.clone(),
        });
    }
    if s.seccomp_profile.as_deref() == Some("Unconfined") {
        overrides.push(SecurityOverrideRequest {
            override_id: "unconfined:seccomp".into(),
            category: "profile".into(),
            container: cname.clone(),
        });
    }
    if s.seccomp_profile.as_deref() == Some("Localhost") {
        overrides.push(SecurityOverrideRequest {
            override_id: "localhost:seccomp".into(),
            category: "profile".into(),
            container: cname.clone(),
        });
    }
    if s.apparmor_profile.as_deref() == Some("Unconfined") {
        overrides.push(SecurityOverrideRequest {
            override_id: "unconfined:apparmor".into(),
            category: "profile".into(),
            container: cname.clone(),
        });
    }
    if s.apparmor_profile.as_deref() == Some("Localhost") {
        overrides.push(SecurityOverrideRequest {
            override_id: "localhost:apparmor".into(),
            category: "profile".into(),
            container: cname.clone(),
        });
    }

    for binary in &s.allowed_binaries {
        overrides.push(SecurityOverrideRequest {
            override_id: format!("allowedBinary:{binary}"),
            category: "binary".into(),
            container: cname.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lattice_common::crd::{ContainerSpec, RuntimeSpec, SecurityContext, WorkloadSpec};

    use super::*;

    #[test]
    fn allowed_binaries_generate_overrides() {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                security: Some(SecurityContext {
                    allowed_binaries: vec![
                        "/usr/bin/curl".to_string(),
                        "/usr/bin/convert".to_string(),
                    ],
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let workload = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let runtime = RuntimeSpec::default();

        let overrides = collect_security_overrides(&workload, &runtime);
        let binary_overrides: Vec<_> = overrides
            .iter()
            .filter(|o| o.category == "binary")
            .collect();
        assert_eq!(binary_overrides.len(), 2);
        assert!(binary_overrides
            .iter()
            .any(|o| o.override_id == "allowedBinary:/usr/bin/curl"));
        assert!(binary_overrides
            .iter()
            .any(|o| o.override_id == "allowedBinary:/usr/bin/convert"));
        assert!(binary_overrides
            .iter()
            .all(|o| o.container.as_deref() == Some("main")));
    }

    #[test]
    fn wildcard_allowed_binary_generates_override() {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                security: Some(SecurityContext {
                    allowed_binaries: vec!["*".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let workload = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let runtime = RuntimeSpec::default();

        let overrides = collect_security_overrides(&workload, &runtime);
        let binary_overrides: Vec<_> = overrides
            .iter()
            .filter(|o| o.category == "binary")
            .collect();
        assert_eq!(binary_overrides.len(), 1);
        assert_eq!(binary_overrides[0].override_id, "allowedBinary:*");
    }

    #[test]
    fn no_command_no_allowed_binaries_generates_implicit_wildcard() {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                ..Default::default()
            },
        );
        let workload = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let runtime = RuntimeSpec::default();

        let overrides = collect_security_overrides(&workload, &runtime);
        let binary_overrides: Vec<_> = overrides
            .iter()
            .filter(|o| o.category == "binary")
            .collect();
        assert_eq!(binary_overrides.len(), 1);
        assert_eq!(binary_overrides[0].override_id, "allowedBinary:*");
    }

    #[test]
    fn has_command_no_allowed_binaries_no_binary_overrides() {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                command: Some(vec!["/usr/bin/myapp".to_string()]),
                ..Default::default()
            },
        );
        let workload = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let runtime = RuntimeSpec::default();

        let overrides = collect_security_overrides(&workload, &runtime);
        assert!(overrides.iter().all(|o| o.category != "binary"));
    }

    #[test]
    fn run_as_root_group_generates_override() {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                command: Some(vec!["/app".to_string()]),
                security: Some(SecurityContext {
                    run_as_group: Some(0),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let workload = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let runtime = RuntimeSpec::default();

        let overrides = collect_security_overrides(&workload, &runtime);
        assert!(overrides
            .iter()
            .any(|o| o.override_id == "runAsRootGroup" && o.container.as_deref() == Some("main")));
    }

    #[test]
    fn non_zero_run_as_group_no_override() {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                command: Some(vec!["/app".to_string()]),
                security: Some(SecurityContext {
                    run_as_group: Some(1000),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let workload = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let runtime = RuntimeSpec::default();

        let overrides = collect_security_overrides(&workload, &runtime);
        assert!(!overrides.iter().any(|o| o.override_id == "runAsRootGroup"));
    }

    #[test]
    fn localhost_seccomp_generates_override() {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                command: Some(vec!["/app".to_string()]),
                security: Some(SecurityContext {
                    seccomp_profile: Some("Localhost".to_string()),
                    seccomp_localhost_profile: Some("profiles/custom.json".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let workload = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let runtime = RuntimeSpec::default();

        let overrides = collect_security_overrides(&workload, &runtime);
        assert!(overrides
            .iter()
            .any(|o| o.override_id == "localhost:seccomp" && o.category == "profile"));
    }

    #[test]
    fn localhost_apparmor_generates_override() {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                command: Some(vec!["/app".to_string()]),
                security: Some(SecurityContext {
                    apparmor_profile: Some("Localhost".to_string()),
                    apparmor_localhost_profile: Some("custom-profile".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let workload = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let runtime = RuntimeSpec::default();

        let overrides = collect_security_overrides(&workload, &runtime);
        assert!(overrides
            .iter()
            .any(|o| o.override_id == "localhost:apparmor" && o.category == "profile"));
    }

    #[test]
    fn runtime_default_profiles_no_override() {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                command: Some(vec!["/app".to_string()]),
                security: Some(SecurityContext {
                    seccomp_profile: Some("RuntimeDefault".to_string()),
                    apparmor_profile: Some("RuntimeDefault".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let workload = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let runtime = RuntimeSpec::default();

        let overrides = collect_security_overrides(&workload, &runtime);
        assert!(!overrides.iter().any(|o| o.category == "profile"));
    }
}
