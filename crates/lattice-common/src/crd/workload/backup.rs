//! Backup configuration shared across all Lattice workload CRDs.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::container::validate_absolute_command;

/// Error action for backup hooks
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum HookErrorAction {
    /// Continue backup even if hook fails (default)
    #[default]
    Continue,
    /// Fail the backup if hook fails
    Fail,
}

/// A single backup hook (pre or post)
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackupHook {
    /// Hook name (used in Velero annotation suffix)
    pub name: String,

    /// Target container name
    pub container: String,

    /// Command to execute
    pub command: Vec<String>,

    /// Timeout for hook execution (e.g., "600s", "10m")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,

    /// Action on hook failure
    #[serde(default)]
    pub on_error: HookErrorAction,
}

impl BackupHook {
    /// Validate that the hook's command[0] is an absolute path.
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.command.is_empty() {
            return Err(crate::Error::validation(format!(
                "backup hook '{}': command must not be empty",
                self.name
            )));
        }
        validate_absolute_command(&self.command, &format!("backup hook '{}'", self.name))
    }
}

/// Pre and post backup hooks
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct BackupHooksSpec {
    /// Hooks to run before backup
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pre: Vec<BackupHook>,

    /// Hooks to run after backup
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub post: Vec<BackupHook>,
}

/// Default volume backup behavior
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum VolumeBackupDefault {
    /// All volumes are backed up unless explicitly excluded (default)
    #[default]
    OptOut,
    /// Only explicitly included volumes are backed up
    OptIn,
}

/// Volume backup configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VolumeBackupSpec {
    /// Volumes to explicitly include in backup
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,

    /// Volumes to explicitly exclude from backup
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,

    /// Default backup policy for volumes not in include/exclude lists
    #[serde(default)]
    pub default_policy: VolumeBackupDefault,
}

/// Service-level backup configuration
///
/// Defines Velero backup hooks and volume backup policies for a service.
/// This spec is shared between `LatticeService.spec.backup` (inline) and
/// `LatticeServicePolicy.spec.backup` (policy overlay).
///
/// When `schedule` is set, the service controller generates a dedicated Velero
/// Schedule scoped to this service's namespace and labels. When `schedule` is
/// None, the service relies on cluster-wide backup schedules.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceBackupSpec {
    /// Cron schedule for service-level backups (e.g., "0 */1 * * *" for hourly)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,

    /// Reference to a BackupStore by name (omit to use default)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_ref: Option<String>,

    /// Retention configuration for service-level backups
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<super::super::cluster_backup::BackupRetentionSpec>,

    /// Pre/post backup hooks for application-aware backups
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hooks: Option<BackupHooksSpec>,

    /// Volume backup configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volumes: Option<VolumeBackupSpec>,
}

impl ServiceBackupSpec {
    /// Validate all backup hooks have absolute command paths.
    pub fn validate(&self) -> Result<(), crate::Error> {
        if let Some(ref hooks) = self.hooks {
            for hook in &hooks.pre {
                hook.validate()?;
            }
            for hook in &hooks.post {
                hook.validate()?;
            }
        }
        Ok(())
    }

    /// Collect all hook command[0] binaries for Tetragon whitelist inclusion.
    pub fn hook_binaries(&self) -> Vec<&str> {
        let mut binaries = Vec::new();
        if let Some(ref hooks) = self.hooks {
            for hook in hooks.pre.iter().chain(hooks.post.iter()) {
                if let Some(binary) = hook.command.first() {
                    binaries.push(binary.as_str());
                }
            }
        }
        binaries
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_error_action_serde() {
        assert_eq!(
            serde_json::to_string(&HookErrorAction::Continue).unwrap(),
            r#""Continue""#
        );
        assert_eq!(
            serde_json::to_string(&HookErrorAction::Fail).unwrap(),
            r#""Fail""#
        );
    }

    #[test]
    fn test_volume_backup_default_serde() {
        assert_eq!(
            serde_json::to_string(&VolumeBackupDefault::OptOut).unwrap(),
            r#""opt-out""#
        );
        assert_eq!(
            serde_json::to_string(&VolumeBackupDefault::OptIn).unwrap(),
            r#""opt-in""#
        );
    }

    fn make_hook(name: &str, command: Vec<String>) -> BackupHook {
        BackupHook {
            name: name.to_string(),
            container: "main".to_string(),
            command,
            timeout: None,
            on_error: HookErrorAction::default(),
        }
    }

    #[test]
    fn hook_absolute_command_passes_validation() {
        let hook = make_hook("freeze", vec!["/bin/sh".to_string(), "-c".to_string(), "sync".to_string()]);
        assert!(hook.validate().is_ok());
    }

    #[test]
    fn hook_relative_command_fails_validation() {
        let hook = make_hook("bad", vec!["sh".to_string(), "-c".to_string(), "sync".to_string()]);
        let err = hook.validate().unwrap_err();
        assert!(err.to_string().contains("must be an absolute path"));
    }

    #[test]
    fn hook_empty_command_fails_validation() {
        let hook = make_hook("empty", vec![]);
        let err = hook.validate().unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn backup_spec_validate_checks_all_hooks() {
        let spec = ServiceBackupSpec {
            hooks: Some(BackupHooksSpec {
                pre: vec![make_hook("ok", vec!["/bin/sh".to_string()])],
                post: vec![make_hook("bad", vec!["sh".to_string()])],
            }),
            ..Default::default()
        };
        let err = spec.validate().unwrap_err();
        assert!(err.to_string().contains("bad"));
    }

    #[test]
    fn hook_binaries_collects_from_pre_and_post() {
        let spec = ServiceBackupSpec {
            hooks: Some(BackupHooksSpec {
                pre: vec![make_hook("freeze", vec!["/bin/sh".to_string(), "-c".to_string()])],
                post: vec![make_hook("thaw", vec!["/usr/bin/pg_isready".to_string()])],
            }),
            ..Default::default()
        };
        let binaries = spec.hook_binaries();
        assert_eq!(binaries, vec!["/bin/sh", "/usr/bin/pg_isready"]);
    }

    #[test]
    fn hook_binaries_empty_when_no_hooks() {
        let spec = ServiceBackupSpec::default();
        assert!(spec.hook_binaries().is_empty());
    }
}
