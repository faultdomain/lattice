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

use lattice_common::crd::{HookErrorAction, ServiceBackupSpec, VolumeBackupDefault};

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
    hooks: &[lattice_common::crd::BackupHook],
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

        let on_error = match hook.on_error {
            HookErrorAction::Fail => "Fail",
            HookErrorAction::Continue => "Continue",
            _ => "Continue",
        };
        annotations.insert(
            format!("{}/on-error{}", prefix, suffix),
            on_error.to_string(),
        );
    }
}

/// Compile volume backup annotations.
fn compile_volume_annotations(
    annotations: &mut BTreeMap<String, String>,
    volumes: &lattice_common::crd::VolumeBackupSpec,
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
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{BackupHook, BackupHooksSpec, HookErrorAction, VolumeBackupSpec};

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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
        };

        let annotations = compile_backup_annotations(&spec);
        assert!(annotations.is_empty());
    }

}
