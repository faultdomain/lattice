//! Backup annotation compiler for Velero integration
//!
//! Generates Velero pod annotations from a resolved `ServiceBackupSpec`.
//! These annotations tell Velero how to handle pre/post hooks and volume backups
//! when a backup schedule runs.
//!
//! ## Velero Annotation Format
//!
//! Single hook:
//! - `pre.hook.backup.velero.io/container: main`
//! - `pre.hook.backup.velero.io/command: ["/bin/sh", "-c", "pg_dump ..."]`
//! - `pre.hook.backup.velero.io/timeout: 600s`
//! - `pre.hook.backup.velero.io/on-error: Fail`
//!
//! Multiple hooks use indexed suffixes:
//! - `pre.hook.backup.velero.io/container-0: main`
//! - `pre.hook.backup.velero.io/command-0: ["/bin/sh", "-c", "first"]`
//! - `pre.hook.backup.velero.io/container-1: sidecar`
//! - `pre.hook.backup.velero.io/command-1: ["/bin/sh", "-c", "second"]`

use std::collections::BTreeMap;

use crate::crd::{HookErrorAction, ServiceBackupSpec, VolumeBackupDefault};

/// Compile Velero pod annotations from a resolved backup spec.
///
/// Returns a map of annotation key-value pairs to add to the Deployment's
/// PodTemplateSpec metadata.
pub fn compile_backup_annotations(spec: &ServiceBackupSpec) -> BTreeMap<String, String> {
    let mut annotations = BTreeMap::new();

    if let Some(hooks) = &spec.hooks {
        compile_hook_annotations(&mut annotations, "pre", &hooks.pre);
        compile_hook_annotations(&mut annotations, "post", &hooks.post);
    }

    if let Some(volumes) = &spec.volumes {
        compile_volume_annotations(&mut annotations, volumes);
    }

    annotations
}

/// Compile hook annotations for a phase (pre or post).
fn compile_hook_annotations(
    annotations: &mut BTreeMap<String, String>,
    phase: &str,
    hooks: &[crate::crd::BackupHook],
) {
    if hooks.is_empty() {
        return;
    }

    let use_index = hooks.len() > 1;

    for (i, hook) in hooks.iter().enumerate() {
        let suffix = if use_index {
            format!("-{}", i)
        } else {
            String::new()
        };

        let prefix = format!("{}.hook.backup.velero.io", phase);

        annotations.insert(
            format!("{}/container{}", prefix, suffix),
            hook.container.clone(),
        );

        // Velero expects command as JSON array
        let command_json =
            serde_json::to_string(&hook.command).unwrap_or_else(|_| "[]".to_string());
        annotations.insert(format!("{}/command{}", prefix, suffix), command_json);

        if let Some(timeout) = &hook.timeout {
            annotations.insert(format!("{}/timeout{}", prefix, suffix), timeout.clone());
        }

        match hook.on_error {
            HookErrorAction::Fail => {
                annotations.insert(format!("{}/on-error{}", prefix, suffix), "Fail".to_string());
            }
            HookErrorAction::Continue => {
                // Continue is the default, but be explicit
                annotations.insert(
                    format!("{}/on-error{}", prefix, suffix),
                    "Continue".to_string(),
                );
            }
        }
    }
}

/// Compile volume backup annotations.
fn compile_volume_annotations(
    annotations: &mut BTreeMap<String, String>,
    volumes: &crate::crd::VolumeBackupSpec,
) {
    match volumes.default_policy {
        VolumeBackupDefault::OptIn => {
            // Opt-in: only listed volumes are backed up
            if !volumes.include.is_empty() {
                annotations.insert(
                    "backup.velero.io/backup-volumes".to_string(),
                    volumes.include.join(","),
                );
            }
        }
        VolumeBackupDefault::OptOut => {
            // Opt-out: all volumes backed up except excluded
            if !volumes.exclude.is_empty() {
                annotations.insert(
                    "backup.velero.io/backup-volumes-excludes".to_string(),
                    volumes.exclude.join(","),
                );
            }
        }
    }
}

/// Merge backup specs with policy overlay priority.
///
/// Policy merge follows these rules:
/// 1. List all matching policies sorted by priority DESC, then name ASC
/// 2. Fold: higher-priority fields override lower-priority
/// 3. Inline spec overrides all policy defaults
/// 4. Merge granularity: top-level fields (hooks, volumes) — no deep merge
pub fn merge_backup_specs(
    policy_specs: &[&ServiceBackupSpec],
    inline_spec: Option<&ServiceBackupSpec>,
) -> Option<ServiceBackupSpec> {
    // Start with nothing
    let mut merged: Option<ServiceBackupSpec> = None;

    // Apply policies in order (lowest priority first, so higher priority overwrites)
    for policy_spec in policy_specs.iter().rev() {
        merged = Some(overlay_backup(merged.as_ref(), policy_spec));
    }

    // Inline spec wins over all policies
    if let Some(inline) = inline_spec {
        merged = Some(overlay_backup(merged.as_ref(), inline));
    }

    merged
}

/// Overlay `overlay` on top of `base`, replacing top-level fields that are set.
fn overlay_backup(
    base: Option<&ServiceBackupSpec>,
    overlay: &ServiceBackupSpec,
) -> ServiceBackupSpec {
    let base_hooks = base.and_then(|b| b.hooks.as_ref());
    let base_volumes = base.and_then(|b| b.volumes.as_ref());

    ServiceBackupSpec {
        hooks: overlay.hooks.clone().or_else(|| base_hooks.cloned()),
        volumes: overlay.volumes.clone().or_else(|| base_volumes.cloned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{BackupHook, BackupHooksSpec, HookErrorAction, VolumeBackupSpec};

    fn make_hook(name: &str, container: &str, cmd: &str) -> BackupHook {
        BackupHook {
            name: name.to_string(),
            container: container.to_string(),
            command: vec!["/bin/sh".to_string(), "-c".to_string(), cmd.to_string()],
            timeout: None,
            on_error: HookErrorAction::Continue,
        }
    }

    // =========================================================================
    // Single Hook Annotations
    // =========================================================================

    #[test]
    fn test_single_pre_hook() {
        let spec = ServiceBackupSpec {
            hooks: Some(BackupHooksSpec {
                pre: vec![BackupHook {
                    name: "freeze".to_string(),
                    container: "main".to_string(),
                    command: vec![
                        "/bin/sh".to_string(),
                        "-c".to_string(),
                        "pg_dump".to_string(),
                    ],
                    timeout: Some("600s".to_string()),
                    on_error: HookErrorAction::Fail,
                }],
                post: vec![],
            }),
            volumes: None,
        };

        let annotations = compile_backup_annotations(&spec);

        assert_eq!(annotations["pre.hook.backup.velero.io/container"], "main");
        assert_eq!(
            annotations["pre.hook.backup.velero.io/command"],
            r#"["/bin/sh","-c","pg_dump"]"#
        );
        assert_eq!(annotations["pre.hook.backup.velero.io/timeout"], "600s");
        assert_eq!(annotations["pre.hook.backup.velero.io/on-error"], "Fail");
    }

    // =========================================================================
    // Multiple Hook Indexing
    // =========================================================================

    #[test]
    fn test_multiple_pre_hooks_indexed() {
        let spec = ServiceBackupSpec {
            hooks: Some(BackupHooksSpec {
                pre: vec![
                    make_hook("first", "main", "echo first"),
                    make_hook("second", "sidecar", "echo second"),
                ],
                post: vec![],
            }),
            volumes: None,
        };

        let annotations = compile_backup_annotations(&spec);

        assert_eq!(annotations["pre.hook.backup.velero.io/container-0"], "main");
        assert_eq!(
            annotations["pre.hook.backup.velero.io/container-1"],
            "sidecar"
        );
        // No un-indexed keys when multiple hooks
        assert!(!annotations.contains_key("pre.hook.backup.velero.io/container"));
    }

    // =========================================================================
    // Pre + Post Hooks
    // =========================================================================

    #[test]
    fn test_pre_and_post_hooks() {
        let spec = ServiceBackupSpec {
            hooks: Some(BackupHooksSpec {
                pre: vec![make_hook("freeze", "main", "freeze")],
                post: vec![make_hook("cleanup", "main", "cleanup")],
            }),
            volumes: None,
        };

        let annotations = compile_backup_annotations(&spec);

        assert!(annotations.contains_key("pre.hook.backup.velero.io/container"));
        assert!(annotations.contains_key("post.hook.backup.velero.io/container"));
    }

    // =========================================================================
    // Volume Annotations
    // =========================================================================

    #[test]
    fn test_volume_opt_in() {
        let spec = ServiceBackupSpec {
            hooks: None,
            volumes: Some(VolumeBackupSpec {
                include: vec!["data".to_string(), "wal".to_string()],
                exclude: vec![],
                default_policy: VolumeBackupDefault::OptIn,
            }),
        };

        let annotations = compile_backup_annotations(&spec);

        assert_eq!(annotations["backup.velero.io/backup-volumes"], "data,wal");
        assert!(!annotations.contains_key("backup.velero.io/backup-volumes-excludes"));
    }

    #[test]
    fn test_volume_opt_out() {
        let spec = ServiceBackupSpec {
            hooks: None,
            volumes: Some(VolumeBackupSpec {
                include: vec![],
                exclude: vec!["tmp".to_string(), "cache".to_string()],
                default_policy: VolumeBackupDefault::OptOut,
            }),
        };

        let annotations = compile_backup_annotations(&spec);

        assert_eq!(
            annotations["backup.velero.io/backup-volumes-excludes"],
            "tmp,cache"
        );
        assert!(!annotations.contains_key("backup.velero.io/backup-volumes"));
    }

    // =========================================================================
    // Empty Spec
    // =========================================================================

    #[test]
    fn test_empty_spec_no_annotations() {
        let spec = ServiceBackupSpec {
            hooks: None,
            volumes: None,
        };

        let annotations = compile_backup_annotations(&spec);
        assert!(annotations.is_empty());
    }

    // =========================================================================
    // Policy Merge
    // =========================================================================

    #[test]
    fn test_merge_inline_overrides_policy() {
        let policy = ServiceBackupSpec {
            hooks: Some(BackupHooksSpec {
                pre: vec![make_hook("policy-hook", "main", "policy-cmd")],
                post: vec![],
            }),
            volumes: Some(VolumeBackupSpec {
                include: vec!["policy-vol".to_string()],
                exclude: vec![],
                default_policy: VolumeBackupDefault::OptIn,
            }),
        };

        let inline = ServiceBackupSpec {
            hooks: Some(BackupHooksSpec {
                pre: vec![make_hook("inline-hook", "main", "inline-cmd")],
                post: vec![],
            }),
            volumes: None, // Not set — should fall through to policy
        };

        let result = merge_backup_specs(&[&policy], Some(&inline)).unwrap();

        // Hooks from inline (overrides policy)
        assert_eq!(result.hooks.as_ref().unwrap().pre[0].name, "inline-hook");
        // Volumes from policy (inline didn't set it)
        assert_eq!(result.volumes.as_ref().unwrap().include, vec!["policy-vol"]);
    }

    #[test]
    fn test_merge_priority_ordering() {
        let low_priority = ServiceBackupSpec {
            hooks: Some(BackupHooksSpec {
                pre: vec![make_hook("low", "main", "low-cmd")],
                post: vec![],
            }),
            volumes: Some(VolumeBackupSpec {
                include: vec!["low-vol".to_string()],
                exclude: vec![],
                default_policy: VolumeBackupDefault::OptIn,
            }),
        };

        let high_priority = ServiceBackupSpec {
            hooks: Some(BackupHooksSpec {
                pre: vec![make_hook("high", "main", "high-cmd")],
                post: vec![],
            }),
            volumes: None,
        };

        // Policies passed highest-priority first
        let result = merge_backup_specs(&[&high_priority, &low_priority], None).unwrap();

        // Hooks from high priority
        assert_eq!(result.hooks.as_ref().unwrap().pre[0].name, "high");
        // Volumes from low priority (high didn't set it)
        assert_eq!(result.volumes.as_ref().unwrap().include, vec!["low-vol"]);
    }

    #[test]
    fn test_merge_no_policies_no_inline() {
        let result = merge_backup_specs(&[], None);
        assert!(result.is_none());
    }

    #[test]
    fn test_merge_policy_only() {
        let policy = ServiceBackupSpec {
            hooks: Some(BackupHooksSpec {
                pre: vec![make_hook("from-policy", "main", "cmd")],
                post: vec![],
            }),
            volumes: None,
        };

        let result = merge_backup_specs(&[&policy], None).unwrap();
        assert_eq!(result.hooks.as_ref().unwrap().pre[0].name, "from-policy");
    }

    #[test]
    fn test_merge_inline_only() {
        let inline = ServiceBackupSpec {
            hooks: None,
            volumes: Some(VolumeBackupSpec {
                include: vec!["data".to_string()],
                exclude: vec![],
                default_policy: VolumeBackupDefault::OptIn,
            }),
        };

        let result = merge_backup_specs(&[], Some(&inline)).unwrap();
        assert!(result.hooks.is_none());
        assert_eq!(result.volumes.as_ref().unwrap().include, vec!["data"]);
    }
}
