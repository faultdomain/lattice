//! Container and sidecar specifications shared across all Lattice workload CRDs.
//!
//! Contains `ContainerSpec`, `SidecarSpec`, `SecurityContext`, probes, file/volume mounts,
//! resource requirements, and their validation logic.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::template::TemplateString;

use super::resources::ResourceRequirements;

// =============================================================================
// Probes
// =============================================================================

/// HTTP probe configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpGetProbe {
    /// Path to probe
    pub path: String,

    /// Port to probe
    pub port: u16,

    /// HTTP scheme (HTTP or HTTPS)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,

    /// Optional host header
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// Optional HTTP headers
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_headers: Option<Vec<HttpHeader>>,
}

/// HTTP header for probes
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct HttpHeader {
    /// Header name
    pub name: String,
    /// Header value
    pub value: String,
}

/// Exec probe configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct ExecProbe {
    /// Command to execute
    pub command: Vec<String>,
}

/// Probe configuration (liveness or readiness)
///
/// Score-compliant probe specification. Supports HTTP GET and exec probe types.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Probe {
    /// HTTP GET probe - performs an HTTP GET request
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_get: Option<HttpGetProbe>,

    /// Exec probe - executes a command inside the container
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecProbe>,

    /// Seconds after container start before probes begin (default: 0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_delay_seconds: Option<i32>,

    /// Seconds between probe attempts (default: 10)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period_seconds: Option<i32>,

    /// Seconds before the probe times out (default: 1)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<i32>,

    /// Consecutive failures before marking unhealthy (default: 3)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_threshold: Option<i32>,

    /// Consecutive successes before marking healthy (default: 1)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub success_threshold: Option<i32>,
}

// =============================================================================
// File and Volume Mounts
// =============================================================================

/// File mount specification
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FileMount {
    /// Inline file content (UTF-8, supports `${...}` placeholders)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<TemplateString>,

    /// Base64-encoded binary content
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_content: Option<String>,

    /// Path to content file (supports `${...}` placeholders)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<TemplateString>,

    /// File mode in octal
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,

    /// Disable placeholder expansion entirely
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_expand: bool,

    /// Reverse expansion mode for bash scripts: `${...}` stays literal,
    /// `$${...}` expands. Useful when shell variables are more common
    /// than Lattice templates.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reverse_expand: bool,
}

/// Volume mount specification
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VolumeMount {
    /// External volume reference (supports `${...}` placeholders).
    /// When omitted, creates an emptyDir volume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<TemplateString>,

    /// Sub path in the volume
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Mount as read-only
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,

    /// Storage medium for emptyDir ("Memory" for tmpfs). Only used when source is None.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub medium: Option<String>,

    /// Size limit for emptyDir (e.g., "1Gi"). Only used when source is None.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_limit: Option<String>,
}

// =============================================================================
// Security Context
// =============================================================================

/// Container security context
///
/// Controls Linux security settings for a container. All fields are optional.
/// When omitted entirely, the compiler applies Pod Security Standards "restricted"
/// profile defaults: drop ALL caps, no privilege escalation, non-root, read-only
/// rootfs, RuntimeDefault seccomp and AppArmor profiles.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecurityContext {
    /// Linux capabilities to add (e.g., NET_ADMIN, SYS_MODULE)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,

    /// Capabilities to drop (default: [ALL])
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drop_capabilities: Option<Vec<String>>,

    /// Run container in privileged mode (strongly discouraged)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,

    /// Mount root filesystem as read-only (default: true)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_root_filesystem: Option<bool>,

    /// Require the container to run as a non-root user (default: true)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_non_root: Option<bool>,

    /// UID to run the container as
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_user: Option<i64>,

    /// GID to run the container as
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_group: Option<i64>,

    /// Allow privilege escalation via setuid binaries (default: false)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_privilege_escalation: Option<bool>,

    /// Seccomp profile type: "RuntimeDefault", "Unconfined", or "Localhost"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seccomp_profile: Option<String>,

    /// Localhost seccomp profile path (only when seccomp_profile is "Localhost")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seccomp_localhost_profile: Option<String>,

    /// AppArmor profile type: "RuntimeDefault", "Unconfined", or "Localhost"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apparmor_profile: Option<String>,

    /// Localhost AppArmor profile name (only when apparmor_profile is "Localhost")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apparmor_localhost_profile: Option<String>,

    /// Binary execution whitelist.
    ///
    /// Only these binaries (plus auto-detected command/probe entrypoints) may
    /// execute. All other binaries are SIGKILL'd by Tetragon at the kernel level.
    /// Use `["*"]` to disable binary restrictions entirely (Cedar must still
    /// authorize the override). When empty and no `command` is declared, the
    /// compiler infers an implicit wildcard since the image ENTRYPOINT is unknown.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_binaries: Vec<String>,
}

/// Returns true if a container's binary entrypoint is unknown.
///
/// A container has unknown entrypoint when it declares no `command` (so the
/// image ENTRYPOINT is opaque) and no `allowedBinaries` (so we can't restrict).
/// Both the Tetragon compiler and Cedar authorization use this to decide whether
/// to infer an implicit wildcard.
pub fn has_unknown_binary_entrypoint(
    command: &Option<Vec<String>>,
    security: &Option<SecurityContext>,
) -> bool {
    command.is_none()
        && security
            .as_ref()
            .is_none_or(|s| s.allowed_binaries.is_empty())
}

// =============================================================================
// Sidecar Spec
// =============================================================================

/// Sidecar container specification
///
/// Identical to ContainerSpec but with additional sidecar-specific options.
/// Sidecars are infrastructure containers (VPN, logging, metrics) that support
/// the main application containers.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SidecarSpec {
    /// Container image
    pub image: String,

    /// Override container entrypoint
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,

    /// Override container arguments
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,

    /// Working directory inside the container
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,

    /// Environment variables (values support `${...}` placeholders)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub variables: BTreeMap<String, TemplateString>,

    /// Resource requirements
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,

    /// Files to mount in the container
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, FileMount>,

    /// Volumes to mount
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub volumes: BTreeMap<String, VolumeMount>,

    /// Liveness probe - restarts container when it fails
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness_probe: Option<Probe>,

    /// Readiness probe - removes container from service endpoints when it fails
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_probe: Option<Probe>,

    /// Startup probe - delays liveness/readiness checks until container is ready
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup_probe: Option<Probe>,

    /// Run as init container (runs once before main containers)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init: Option<bool>,

    /// Security context for the container
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<SecurityContext>,
}

impl SidecarSpec {
    /// Validate sidecar specification
    pub fn validate(&self, sidecar_name: &str) -> Result<(), crate::Error> {
        validate_image(&self.image, sidecar_name)?;
        validate_command_path(&self.command, sidecar_name)?;

        // Init sidecars must specify a command. Without it, `has_unknown_binary_entrypoint()`
        // returns true and disables Tetragon binary enforcement for the entire pod.
        // Init containers are explicit setup tasks — they always know their entrypoint.
        if self.init == Some(true) && self.command.is_none() {
            return Err(crate::Error::validation(format!(
                "sidecar '{}': init containers must specify a command",
                sidecar_name
            )));
        }

        for (path, file_mount) in &self.files {
            file_mount.validate(sidecar_name, path)?;
        }

        Ok(())
    }
}

// =============================================================================
// Container Spec
// =============================================================================

/// Container specification (Score-compatible)
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ContainerSpec {
    /// Container image (use "." for runtime-supplied image via config)
    pub image: String,

    /// Override container entrypoint
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,

    /// Override container arguments
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,

    /// Working directory inside the container
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,

    /// Environment variables (values support `${...}` placeholders)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub variables: BTreeMap<String, TemplateString>,

    /// Resource requirements
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,

    /// Files to mount in the container
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, FileMount>,

    /// Volumes to mount
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub volumes: BTreeMap<String, VolumeMount>,

    /// Liveness probe - restarts container when it fails
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness_probe: Option<Probe>,

    /// Readiness probe - removes container from service endpoints when it fails
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_probe: Option<Probe>,

    /// Startup probe - delays liveness/readiness checks until container is ready
    ///
    /// Useful for slow-starting containers. Liveness and readiness probes
    /// will not run until the startup probe succeeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup_probe: Option<Probe>,

    /// Security context for the container
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<SecurityContext>,
}

// =============================================================================
// Container Validation
// =============================================================================

impl ContainerSpec {
    /// Validate container specification
    pub fn validate(&self, container_name: &str) -> Result<(), crate::Error> {
        // Validate image format
        validate_image(&self.image, container_name)?;

        // Validate command[0] is an absolute path (Tetragon needs it for the allowlist)
        validate_command_path(&self.command, container_name)?;

        // Resource limits are required for every container
        let resources = self.resources.as_ref().ok_or_else(|| {
            crate::Error::validation(format!(
                "container '{}' must have resource limits",
                container_name
            ))
        })?;
        if resources.limits.is_none() {
            return Err(crate::Error::validation(format!(
                "container '{}' must have resource limits",
                container_name
            )));
        }

        // Validate resource quantities
        resources.validate(container_name)?;

        // Validate file mount modes
        for (path, file_mount) in &self.files {
            file_mount.validate(container_name, path)?;
        }

        Ok(())
    }
}

impl FileMount {
    /// Validate file mount specification
    pub fn validate(&self, container_name: &str, path: &str) -> Result<(), crate::Error> {
        // Validate mode is valid octal
        if let Some(ref mode) = self.mode {
            validate_file_mode(mode, container_name, path)?;
        }

        // Ensure at least one content source is specified
        let has_content =
            self.content.is_some() || self.binary_content.is_some() || self.source.is_some();
        if !has_content {
            return Err(crate::Error::validation(format!(
                "container '{}' file '{}': must specify content, binary_content, or source",
                container_name, path
            )));
        }

        Ok(())
    }
}

// =============================================================================
// Validation Helper Functions
// =============================================================================

/// Validate container image format
///
/// Accepts:
/// - Standard image references: "nginx:latest", "gcr.io/project/image:v1"
/// - Runtime placeholder: "." (Score spec - image supplied via config at render time)
///
/// Note: Per Score spec, `${...}` placeholders are NOT supported in image field.
/// Use "." for runtime-supplied images instead.
pub(crate) fn validate_image(image: &str, container_name: &str) -> Result<(), crate::Error> {
    if image.is_empty() {
        return Err(crate::Error::validation(format!(
            "container '{}': image cannot be empty",
            container_name
        )));
    }

    // "." is the Score placeholder for runtime-supplied image
    if image == "." {
        return Ok(());
    }

    // Basic validation: image must not contain whitespace or control characters
    if image.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(crate::Error::validation(format!(
            "container '{}': image '{}' contains invalid characters",
            container_name, image
        )));
    }

    // Reject shell metacharacters that could enable injection
    const SHELL_METACHARS: &[char] = &['`', '|', ';', '&', '$', '>', '<', '(', ')', '{', '}'];
    if image.chars().any(|c| SHELL_METACHARS.contains(&c)) {
        return Err(crate::Error::validation(format!(
            "container '{}': image '{}' contains shell metacharacters",
            container_name, image
        )));
    }

    Ok(())
}

/// Validate that command[0] is an absolute path.
///
/// Tetragon's `security_bprm_check` hook receives the kernel-resolved absolute path,
/// so relative paths in the allowlist would never match. Reject early with a clear error
/// instead of silently generating a broken allowlist.
pub(crate) fn validate_command_path(
    command: &Option<Vec<String>>,
    container_name: &str,
) -> Result<(), crate::Error> {
    if let Some(cmd) = command {
        if let Some(binary) = cmd.first() {
            if !binary.starts_with('/') {
                return Err(crate::Error::validation(format!(
                    "container '{}': command[0] '{}' must be an absolute path (start with '/')",
                    container_name, binary
                )));
            }
        }
    }
    Ok(())
}

/// Validate file mode is valid octal (e.g., "0644", "0755")
pub(crate) fn validate_file_mode(
    mode: &str,
    container_name: &str,
    path: &str,
) -> Result<(), crate::Error> {
    // Mode should be 3-4 octal digits, optionally prefixed with 0
    let mode_str = mode.strip_prefix('0').unwrap_or(mode);

    if mode_str.len() < 3 || mode_str.len() > 4 {
        return Err(crate::Error::validation(format!(
            "container '{}' file '{}': mode '{}' must be 3-4 octal digits (e.g., '0644')",
            container_name, path, mode
        )));
    }

    if !mode_str.chars().all(|c| ('0'..='7').contains(&c)) {
        return Err(crate::Error::validation(format!(
            "container '{}' file '{}': mode '{}' contains non-octal digits",
            container_name, path, mode
        )));
    }

    // Parse the mode value to check for insecure permissions
    let mode_val =
        u32::from_str_radix(mode_str, 8).expect("already validated as octal digits above");

    // Reject setuid (04000), setgid (02000), and sticky (01000) bits
    if mode_val & 0o7000 != 0 {
        return Err(crate::Error::validation(format!(
            "container '{}' file '{}': mode '{}' sets special bits (setuid/setgid/sticky) which are not allowed",
            container_name, path, mode
        )));
    }

    // Reject world-writable files (other-write bit)
    if mode_val & 0o002 != 0 {
        return Err(crate::Error::validation(format!(
            "container '{}' file '{}': mode '{}' is world-writable which is not allowed",
            container_name, path, mode
        )));
    }

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::workload::resources::{
        validate_cpu_quantity, validate_memory_quantity, ResourceQuantity, ResourceRequirements,
    };
    use crate::template::TemplateString;

    #[test]
    fn test_valid_cpu_quantities() {
        assert!(validate_cpu_quantity("100m", "main", "requests").is_ok());
        assert!(validate_cpu_quantity("1", "main", "limits").is_ok());
        assert!(validate_cpu_quantity("0.5", "main", "requests").is_ok());
        assert!(validate_cpu_quantity("2000m", "main", "limits").is_ok());
    }

    #[test]
    fn test_invalid_cpu_quantities() {
        assert!(validate_cpu_quantity("", "main", "requests").is_err());
        assert!(validate_cpu_quantity("abc", "main", "limits").is_err());
        assert!(validate_cpu_quantity("100x", "main", "requests").is_err());
        assert!(validate_cpu_quantity("1.5m", "main", "limits").is_err());
    }

    #[test]
    fn test_valid_memory_quantities() {
        assert!(validate_memory_quantity("128Mi", "main", "requests").is_ok());
        assert!(validate_memory_quantity("1Gi", "main", "limits").is_ok());
        assert!(validate_memory_quantity("1000000", "main", "requests").is_ok());
        assert!(validate_memory_quantity("512Ki", "main", "limits").is_ok());
        assert!(validate_memory_quantity("1M", "main", "requests").is_ok());
    }

    #[test]
    fn test_invalid_memory_quantities() {
        assert!(validate_memory_quantity("", "main", "requests").is_err());
        assert!(validate_memory_quantity("abc", "main", "limits").is_err());
        assert!(validate_memory_quantity("128Xi", "main", "requests").is_err());
    }

    #[test]
    fn test_valid_file_modes() {
        assert!(validate_file_mode("0644", "main", "/etc/config").is_ok());
        assert!(validate_file_mode("0755", "main", "/usr/bin/script").is_ok());
        assert!(validate_file_mode("644", "main", "/etc/config").is_ok());
        assert!(validate_file_mode("0400", "main", "/etc/secret").is_ok());
        assert!(validate_file_mode("0750", "main", "/usr/bin/script").is_ok());
    }

    #[test]
    fn test_invalid_file_modes() {
        assert!(validate_file_mode("0999", "main", "/etc/config").is_err());
        assert!(validate_file_mode("abc", "main", "/etc/config").is_err());
        assert!(validate_file_mode("12", "main", "/etc/config").is_err());
        assert!(validate_file_mode("12345", "main", "/etc/config").is_err());
    }

    #[test]
    fn test_file_mode_rejects_world_writable() {
        assert!(validate_file_mode("0777", "main", "/tmp/file").is_err());
        assert!(validate_file_mode("0666", "main", "/tmp/file").is_err());
        assert!(validate_file_mode("0772", "main", "/tmp/file").is_err());
    }

    #[test]
    fn test_file_mode_rejects_special_bits() {
        // setuid
        assert!(validate_file_mode("4755", "main", "/usr/bin/evil").is_err());
        // setgid
        assert!(validate_file_mode("2755", "main", "/usr/bin/evil").is_err());
        // sticky
        assert!(validate_file_mode("1755", "main", "/tmp/dir").is_err());
    }

    #[test]
    fn test_empty_image_fails() {
        assert!(validate_image("", "main").is_err());
    }

    #[test]
    fn test_image_with_whitespace_fails() {
        assert!(validate_image("nginx latest", "main").is_err());
        assert!(validate_image("nginx\tlatest", "main").is_err());
    }

    #[test]
    fn test_valid_images() {
        assert!(validate_image("nginx:latest", "main").is_ok());
        assert!(validate_image("registry.example.com/app:v1.2.3", "main").is_ok());
        assert!(validate_image("gcr.io/project/image@sha256:abc123", "main").is_ok());
    }

    #[test]
    fn test_dot_image_placeholder_valid() {
        assert!(validate_image(".", "main").is_ok());
    }

    #[test]
    fn test_image_with_shell_metacharacters_fails() {
        assert!(validate_image("nginx; rm -rf /", "main").is_err()); // also caught by whitespace
        assert!(validate_image("$(evil)", "main").is_err());
        assert!(validate_image("`whoami`", "main").is_err());
        assert!(validate_image("img|cat", "main").is_err());
        assert!(validate_image("img&bg", "main").is_err());
        assert!(validate_image("img>file", "main").is_err());
        assert!(validate_image("img<file", "main").is_err());
    }

    #[test]
    fn test_container_without_resource_limits_fails() {
        let container = ContainerSpec {
            image: "nginx:latest".to_string(),
            ..Default::default()
        };
        let result = container.validate("main");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must have resource limits"));
    }

    #[test]
    fn test_container_with_limits_passes() {
        let container = ContainerSpec {
            image: "nginx:latest".to_string(),
            resources: Some(ResourceRequirements {
                limits: Some(ResourceQuantity {
                    cpu: Some("1".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(container.validate("main").is_ok());
    }

    #[test]
    fn test_file_mount_requires_content() {
        let file = FileMount {
            content: None,
            binary_content: None,
            source: None,
            mode: None,
            no_expand: false,
            reverse_expand: false,
        };
        assert!(file.validate("main", "/etc/config").is_err());

        let file_with_content = FileMount {
            content: Some(TemplateString::from("data")),
            binary_content: None,
            source: None,
            mode: None,
            no_expand: false,
            reverse_expand: false,
        };
        assert!(file_with_content.validate("main", "/etc/config").is_ok());
    }

    #[test]
    fn test_command_absolute_path_passes() {
        assert!(validate_command_path(&Some(vec!["/usr/bin/app".to_string()]), "main").is_ok());
        assert!(validate_command_path(&Some(vec!["/bin/sh".to_string(), "-c".to_string()]), "main").is_ok());
        assert!(validate_command_path(&None, "main").is_ok());
    }

    #[test]
    fn test_command_relative_path_fails() {
        let result = validate_command_path(&Some(vec!["app".to_string()]), "main");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be an absolute path"));
    }

    #[test]
    fn test_command_empty_string_fails() {
        let result = validate_command_path(&Some(vec!["".to_string()]), "main");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be an absolute path"));
    }

    #[test]
    fn test_init_sidecar_requires_command() {
        let sidecar = SidecarSpec {
            image: "busybox:latest".to_string(),
            init: Some(true),
            command: None,
            ..Default::default()
        };
        let result = sidecar.validate("setup");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("init containers must specify a command"));
    }

    #[test]
    fn test_init_sidecar_with_command_passes() {
        let sidecar = SidecarSpec {
            image: "busybox:latest".to_string(),
            init: Some(true),
            command: Some(vec!["/bin/sh".to_string(), "-c".to_string(), "setup".to_string()]),
            ..Default::default()
        };
        assert!(sidecar.validate("setup").is_ok());
    }

    #[test]
    fn test_regular_sidecar_without_command_passes() {
        let sidecar = SidecarSpec {
            image: "fluentbit:latest".to_string(),
            init: Some(false),
            command: None,
            ..Default::default()
        };
        assert!(sidecar.validate("logger").is_ok());
    }

    #[test]
    fn test_sidecar_relative_command_fails() {
        let sidecar = SidecarSpec {
            image: "busybox:latest".to_string(),
            command: Some(vec!["sh".to_string()]),
            ..Default::default()
        };
        let result = sidecar.validate("setup");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be an absolute path"));
    }
}
