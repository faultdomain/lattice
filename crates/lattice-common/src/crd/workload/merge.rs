//! Strategic merge patch for workload types.
//!
//! Implements a `Merge` trait that applies defaults-with-overlays semantics:
//! - **Maps**: deep merge by key (task-level keys override or extend defaults)
//! - **Scalars**: task-level value wins if present, default value used otherwise
//! - **Lists**: task-level replaces entire list (atomic — no append)
//! - **Option<T>**: `Some` at task level overrides, `None` means "use default"
//!
//! Merge is called at compile time, not CRD admission. The stored spec stays
//! exactly as the user wrote it.

use std::collections::BTreeMap;

use super::container::{ContainerSpec, SecurityContext};
use super::resources::{ResourceQuantity, ResourceRequirements};
use super::spec::{RuntimeSpec, WorkloadSpec};
use crate::crd::job::JobTaskSpec;
use crate::crd::model_serving::ModelRoleSpec;

/// Strategic merge patch: populate `self` with values from `defaults` where
/// `self` has no value set. Already-set fields on `self` are never overwritten.
pub trait Merge {
    /// Merge default values into `self`. Fields already set on `self` are preserved.
    fn merge_from(&mut self, defaults: &Self);
}

// =============================================================================
// Scalar/Option helpers
// =============================================================================

/// Merge an `Option<T: Clone>`: if self is `None`, use default's value.
fn merge_option<T: Clone>(target: &mut Option<T>, default: &Option<T>) {
    if target.is_none() {
        *target = default.clone();
    }
}

/// Merge an `Option<T: Merge + Clone>`: if self is `None`, clone default.
/// If both are `Some`, deep merge self from default.
fn merge_option_deep<T: Merge + Clone>(target: &mut Option<T>, default: &Option<T>) {
    match (target.as_mut(), default) {
        (Some(t), Some(d)) => t.merge_from(d),
        (None, Some(d)) => *target = Some(d.clone()),
        _ => {}
    }
}

/// Merge a `BTreeMap`: default keys are inserted only if absent in target.
/// When both sides have the same key, the target value wins (no deep merge
/// on map values unless the value type itself implements `Merge`).
fn merge_map<K: Ord + Clone, V: Clone>(target: &mut BTreeMap<K, V>, defaults: &BTreeMap<K, V>) {
    for (k, v) in defaults {
        target.entry(k.clone()).or_insert_with(|| v.clone());
    }
}

/// Merge a `BTreeMap` with deep merge on values that implement `Merge`.
fn merge_map_deep<K: Ord + Clone, V: Merge + Clone>(
    target: &mut BTreeMap<K, V>,
    defaults: &BTreeMap<K, V>,
) {
    for (k, v) in defaults {
        target
            .entry(k.clone())
            .and_modify(|existing| existing.merge_from(v))
            .or_insert_with(|| v.clone());
    }
}

/// Merge a `Vec`: lists are atomic — if target is non-empty, keep it.
/// If target is empty, use default.
fn merge_vec<T: Clone>(target: &mut Vec<T>, defaults: &[T]) {
    if target.is_empty() {
        *target = defaults.to_vec();
    }
}

/// Merge a string: if target is empty, use default.
fn merge_string(target: &mut String, default: &str) {
    if target.is_empty() {
        *target = default.to_string();
    }
}

// =============================================================================
// WorkloadSpec
// =============================================================================

impl Merge for WorkloadSpec {
    fn merge_from(&mut self, defaults: &Self) {
        // containers: deep merge by name
        merge_map_deep(&mut self.containers, &defaults.containers);
        // resources: shallow merge by name (ResourceSpec is opaque)
        merge_map(&mut self.resources, &defaults.resources);
        // service: option merge (no deep merge — service ports are atomic)
        merge_option(&mut self.service, &defaults.service);
    }
}

// =============================================================================
// RuntimeSpec
// =============================================================================

impl Merge for RuntimeSpec {
    fn merge_from(&mut self, defaults: &Self) {
        // sidecars: shallow merge by name
        merge_map(&mut self.sidecars, &defaults.sidecars);
        // sysctls: shallow merge by key
        merge_map(&mut self.sysctls, &defaults.sysctls);
        // scalars
        merge_option(&mut self.host_network, &defaults.host_network);
        merge_option(
            &mut self.share_process_namespace,
            &defaults.share_process_namespace,
        );
        // lists (atomic replace)
        merge_vec(&mut self.image_pull_secrets, &defaults.image_pull_secrets);
    }
}

// =============================================================================
// ContainerSpec
// =============================================================================

impl Merge for ContainerSpec {
    fn merge_from(&mut self, defaults: &Self) {
        // image: non-empty wins
        merge_string(&mut self.image, &defaults.image);
        // command/args: Option<Vec> — atomic list override
        merge_option(&mut self.command, &defaults.command);
        merge_option(&mut self.args, &defaults.args);
        // working_dir
        merge_option(&mut self.working_dir, &defaults.working_dir);
        // variables: map merge by key
        merge_map(&mut self.variables, &defaults.variables);
        // resources: deep merge
        merge_option_deep(&mut self.resources, &defaults.resources);
        // files: shallow merge by path
        merge_map(&mut self.files, &defaults.files);
        // volumes: shallow merge by path
        merge_map(&mut self.volumes, &defaults.volumes);
        // probes
        merge_option(&mut self.liveness_probe, &defaults.liveness_probe);
        merge_option(&mut self.readiness_probe, &defaults.readiness_probe);
        merge_option(&mut self.startup_probe, &defaults.startup_probe);
        // env_from: atomic list
        merge_vec(&mut self.env_from, &defaults.env_from);
        // security: deep merge
        merge_option_deep(&mut self.security, &defaults.security);
    }
}

// =============================================================================
// SecurityContext
// =============================================================================

impl Merge for SecurityContext {
    fn merge_from(&mut self, defaults: &Self) {
        merge_vec(&mut self.capabilities, &defaults.capabilities);
        merge_option(&mut self.drop_capabilities, &defaults.drop_capabilities);
        merge_option(&mut self.privileged, &defaults.privileged);
        merge_option(
            &mut self.read_only_root_filesystem,
            &defaults.read_only_root_filesystem,
        );
        merge_option(&mut self.run_as_non_root, &defaults.run_as_non_root);
        merge_option(&mut self.run_as_user, &defaults.run_as_user);
        merge_option(&mut self.run_as_group, &defaults.run_as_group);
        merge_option(
            &mut self.allow_privilege_escalation,
            &defaults.allow_privilege_escalation,
        );
        merge_option(&mut self.seccomp_profile, &defaults.seccomp_profile);
        merge_option(
            &mut self.seccomp_localhost_profile,
            &defaults.seccomp_localhost_profile,
        );
        merge_option(&mut self.apparmor_profile, &defaults.apparmor_profile);
        merge_option(
            &mut self.apparmor_localhost_profile,
            &defaults.apparmor_localhost_profile,
        );
        merge_vec(&mut self.allowed_binaries, &defaults.allowed_binaries);
    }
}

// =============================================================================
// ResourceRequirements / ResourceQuantity
// =============================================================================

impl Merge for ResourceRequirements {
    fn merge_from(&mut self, defaults: &Self) {
        merge_option_deep(&mut self.requests, &defaults.requests);
        merge_option_deep(&mut self.limits, &defaults.limits);
    }
}

impl Merge for ResourceQuantity {
    fn merge_from(&mut self, defaults: &Self) {
        merge_option(&mut self.cpu, &defaults.cpu);
        merge_option(&mut self.memory, &defaults.memory);
    }
}

// =============================================================================
// JobTaskSpec
// =============================================================================

impl Merge for JobTaskSpec {
    fn merge_from(&mut self, defaults: &Self) {
        merge_option(&mut self.replicas, &defaults.replicas);
        self.workload.merge_from(&defaults.workload);
        self.runtime.merge_from(&defaults.runtime);
        merge_option(&mut self.restart_policy, &defaults.restart_policy);
        merge_option(&mut self.policies, &defaults.policies);
    }
}

// =============================================================================
// ModelRoleSpec
// =============================================================================

impl Merge for ModelRoleSpec {
    fn merge_from(&mut self, defaults: &Self) {
        merge_option(&mut self.replicas, &defaults.replicas);
        self.entry_workload.merge_from(&defaults.entry_workload);
        self.entry_runtime.merge_from(&defaults.entry_runtime);
        merge_option(&mut self.worker_replicas, &defaults.worker_replicas);
        merge_option_deep(&mut self.worker_workload, &defaults.worker_workload);
        merge_option_deep(&mut self.worker_runtime, &defaults.worker_runtime);
        merge_option(&mut self.autoscaling, &defaults.autoscaling);
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::ResourceSpec;
    use crate::template::TemplateString;

    fn container_with_resources(cpu: &str, mem: &str) -> ContainerSpec {
        ContainerSpec {
            image: "nginx:latest".to_string(),
            command: Some(vec!["/usr/bin/nginx".to_string()]),
            resources: Some(ResourceRequirements {
                requests: Some(ResourceQuantity {
                    cpu: Some(cpu.to_string()),
                    memory: Some(mem.to_string()),
                }),
                limits: Some(ResourceQuantity {
                    cpu: Some(cpu.to_string()),
                    memory: Some(mem.to_string()),
                }),
            }),
            security: Some(SecurityContext {
                run_as_user: Some(65534),
                apparmor_profile: Some("Unconfined".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    // =========================================================================
    // Scalar override
    // =========================================================================

    #[test]
    fn scalar_override_target_wins() {
        let mut target = ResourceQuantity {
            cpu: Some("2".to_string()),
            memory: None,
        };
        let defaults = ResourceQuantity {
            cpu: Some("1".to_string()),
            memory: Some("1Gi".to_string()),
        };
        target.merge_from(&defaults);
        assert_eq!(target.cpu.as_deref(), Some("2"), "target cpu should win");
        assert_eq!(
            target.memory.as_deref(),
            Some("1Gi"),
            "default memory fills in"
        );
    }

    #[test]
    fn scalar_override_none_uses_default() {
        let mut target = ResourceQuantity::default();
        let defaults = ResourceQuantity {
            cpu: Some("500m".to_string()),
            memory: Some("256Mi".to_string()),
        };
        target.merge_from(&defaults);
        assert_eq!(target.cpu.as_deref(), Some("500m"));
        assert_eq!(target.memory.as_deref(), Some("256Mi"));
    }

    // =========================================================================
    // Map merge
    // =========================================================================

    #[test]
    fn map_merge_extends_with_defaults() {
        let mut target = WorkloadSpec {
            containers: BTreeMap::from([(
                "main".to_string(),
                ContainerSpec {
                    image: "myapp:v2".to_string(),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        let defaults = WorkloadSpec {
            containers: BTreeMap::from([
                ("main".to_string(), container_with_resources("1", "1Gi")),
                (
                    "sidecar".to_string(),
                    ContainerSpec {
                        image: "fluentbit:latest".to_string(),
                        ..Default::default()
                    },
                ),
            ]),
            ..Default::default()
        };
        target.merge_from(&defaults);

        // "main" exists in target — deep merged (image stays "myapp:v2", gets resources from default)
        assert_eq!(target.containers["main"].image, "myapp:v2");
        assert!(target.containers["main"].resources.is_some());
        // "sidecar" only in defaults — added
        assert!(target.containers.contains_key("sidecar"));
    }

    #[test]
    fn map_merge_target_key_not_overwritten() {
        let mut target_resources = BTreeMap::new();
        target_resources.insert(
            "db".to_string(),
            ResourceSpec {
                id: Some("my-db".to_string()),
                ..Default::default()
            },
        );
        let mut default_resources = BTreeMap::new();
        default_resources.insert(
            "db".to_string(),
            ResourceSpec {
                id: Some("default-db".to_string()),
                ..Default::default()
            },
        );

        let mut target = WorkloadSpec {
            resources: target_resources,
            ..Default::default()
        };
        let defaults = WorkloadSpec {
            resources: default_resources,
            ..Default::default()
        };
        target.merge_from(&defaults);
        assert_eq!(
            target.resources["db"].id.as_deref(),
            Some("my-db"),
            "target resource key should not be overwritten"
        );
    }

    // =========================================================================
    // List replace
    // =========================================================================

    #[test]
    fn list_replace_target_wins() {
        let mut target = ContainerSpec {
            image: "app:latest".to_string(),
            command: Some(vec!["/usr/bin/custom".to_string()]),
            ..Default::default()
        };
        let defaults = ContainerSpec {
            image: "app:latest".to_string(),
            command: Some(vec!["/usr/bin/default".to_string(), "arg1".to_string()]),
            ..Default::default()
        };
        target.merge_from(&defaults);
        assert_eq!(
            target.command,
            Some(vec!["/usr/bin/custom".to_string()]),
            "target command should replace, not append"
        );
    }

    #[test]
    fn list_replace_empty_uses_default() {
        let mut target = ContainerSpec {
            image: "app:latest".to_string(),
            command: None,
            ..Default::default()
        };
        let defaults = ContainerSpec {
            image: "app:latest".to_string(),
            command: Some(vec!["/usr/bin/default".to_string()]),
            ..Default::default()
        };
        target.merge_from(&defaults);
        assert_eq!(target.command, Some(vec!["/usr/bin/default".to_string()]),);
    }

    // =========================================================================
    // Nested container merge
    // =========================================================================

    #[test]
    fn nested_container_resources_deep_merge() {
        let mut target = ContainerSpec {
            image: "".to_string(), // empty — will get default
            resources: Some(ResourceRequirements {
                limits: Some(ResourceQuantity {
                    cpu: None,
                    memory: Some("8Gi".to_string()), // override memory only
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let defaults = container_with_resources("500m", "1Gi");
        target.merge_from(&defaults);

        assert_eq!(
            target.image, "nginx:latest",
            "empty image filled from default"
        );

        let limits = target.resources.as_ref().unwrap().limits.as_ref().unwrap();
        assert_eq!(limits.cpu.as_deref(), Some("500m"), "cpu from default");
        assert_eq!(
            limits.memory.as_deref(),
            Some("8Gi"),
            "memory from target override"
        );

        let requests = target
            .resources
            .as_ref()
            .unwrap()
            .requests
            .as_ref()
            .unwrap();
        assert_eq!(
            requests.cpu.as_deref(),
            Some("500m"),
            "requests filled from default"
        );
    }

    #[test]
    fn nested_security_context_merge() {
        let mut target = ContainerSpec {
            image: "app:latest".to_string(),
            security: Some(SecurityContext {
                run_as_user: Some(1000), // override user
                ..Default::default()
            }),
            ..Default::default()
        };
        let defaults = ContainerSpec {
            image: "app:latest".to_string(),
            security: Some(SecurityContext {
                run_as_user: Some(65534),
                apparmor_profile: Some("Unconfined".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        target.merge_from(&defaults);

        let sec = target.security.as_ref().unwrap();
        assert_eq!(sec.run_as_user, Some(1000), "target user wins");
        assert_eq!(
            sec.apparmor_profile.as_deref(),
            Some("Unconfined"),
            "apparmor from default"
        );
    }

    // =========================================================================
    // RuntimeSpec merge
    // =========================================================================

    #[test]
    fn runtime_spec_merge() {
        let mut target = RuntimeSpec {
            image_pull_secrets: vec![], // empty — gets default
            ..Default::default()
        };
        let defaults = RuntimeSpec {
            image_pull_secrets: vec!["ghcr-creds".to_string()],
            sysctls: BTreeMap::from([("net.core.somaxconn".to_string(), "1024".to_string())]),
            host_network: Some(true),
            ..Default::default()
        };
        target.merge_from(&defaults);

        assert_eq!(target.image_pull_secrets, vec!["ghcr-creds"]);
        assert_eq!(target.sysctls["net.core.somaxconn"], "1024");
        assert_eq!(target.host_network, Some(true));
    }

    #[test]
    fn runtime_spec_target_list_wins() {
        let mut target = RuntimeSpec {
            image_pull_secrets: vec!["my-creds".to_string()],
            ..Default::default()
        };
        let defaults = RuntimeSpec {
            image_pull_secrets: vec!["default-creds".to_string()],
            ..Default::default()
        };
        target.merge_from(&defaults);
        assert_eq!(
            target.image_pull_secrets,
            vec!["my-creds"],
            "non-empty list should not be replaced"
        );
    }

    // =========================================================================
    // Full workload merge (integration)
    // =========================================================================

    #[test]
    fn full_workload_merge_defaults_pattern() {
        // Simulates: defaults provide image+command+resources+security,
        // task only overrides memory limit
        let defaults = WorkloadSpec {
            containers: BTreeMap::from([(
                "main".to_string(),
                container_with_resources("500m", "1Gi"),
            )]),
            resources: BTreeMap::from([(
                "ghcr-creds".to_string(),
                ResourceSpec {
                    id: Some("local-regcreds".to_string()),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        let mut task_workload = WorkloadSpec {
            containers: BTreeMap::from([(
                "main".to_string(),
                ContainerSpec {
                    image: "".to_string(),
                    resources: Some(ResourceRequirements {
                        limits: Some(ResourceQuantity {
                            memory: Some("8Gi".to_string()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        task_workload.merge_from(&defaults);

        let main = &task_workload.containers["main"];
        assert_eq!(main.image, "nginx:latest");
        assert_eq!(main.command, Some(vec!["/usr/bin/nginx".to_string()]));

        let limits = main.resources.as_ref().unwrap().limits.as_ref().unwrap();
        assert_eq!(limits.cpu.as_deref(), Some("500m"));
        assert_eq!(limits.memory.as_deref(), Some("8Gi"));

        assert!(main.security.is_some());
        assert_eq!(main.security.as_ref().unwrap().run_as_user, Some(65534));

        // resources map merged
        assert!(task_workload.resources.contains_key("ghcr-creds"));
    }

    // =========================================================================
    // Variables (BTreeMap<String, TemplateString>) merge
    // =========================================================================

    #[test]
    fn container_variables_merge() {
        let mut target = ContainerSpec {
            image: "app:latest".to_string(),
            variables: BTreeMap::from([("MY_VAR".to_string(), TemplateString::from("override"))]),
            ..Default::default()
        };
        let defaults = ContainerSpec {
            image: "app:latest".to_string(),
            variables: BTreeMap::from([
                ("MY_VAR".to_string(), TemplateString::from("default")),
                ("OTHER_VAR".to_string(), TemplateString::from("value")),
            ]),
            ..Default::default()
        };
        target.merge_from(&defaults);

        assert_eq!(
            target.variables["MY_VAR"].as_str(),
            "override",
            "target key wins"
        );
        assert_eq!(
            target.variables["OTHER_VAR"].as_str(),
            "value",
            "new key added"
        );
    }
}
