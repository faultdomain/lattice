//! Workload compilation error types
//!
//! Structured errors for workload compilation that include context
//! about where the error occurred (container, resource, volume, secret, etc.).

use std::fmt;

use lattice_common::template::TemplateError;

/// Errors that can occur during workload compilation
#[derive(Debug)]
pub enum CompilationError {
    /// Error related to a container (invalid spec, bad variable reference, etc.)
    Container {
        /// Container name
        container: String,
        /// Error message
        message: String,
    },

    /// Error related to a resource (missing, wrong type, bad config, etc.)
    Resource {
        /// Resource name
        name: String,
        /// Error message
        message: String,
    },

    /// LatticeService is missing required metadata
    MissingMetadata {
        /// Which metadata field is missing
        field: &'static str,
    },

    /// Invalid volume resource configuration
    Volume {
        /// Error message
        message: String,
    },

    /// Invalid secret resource configuration
    Secret {
        /// Error message
        message: String,
    },

    /// Cedar policy denied secret access
    SecretAccessDenied {
        /// Denial details
        details: String,
    },

    /// Cedar policy denied security override
    SecurityOverrideDenied {
        /// Denial details
        details: String,
    },

    /// Volume access denied (owner consent or Cedar policy)
    VolumeAccessDenied {
        /// Denial details
        details: String,
    },

    /// Template rendering error
    Template {
        /// The underlying template error
        source: TemplateError,
    },

    /// File compilation error
    FileCompilation {
        /// Error message
        message: String,
    },

    /// Custom Prometheus metrics require monitoring to be enabled on the cluster
    MonitoringRequired {
        /// The metric names that require monitoring
        metrics: Vec<String>,
    },

    /// Error from a compiler extension phase
    Extension {
        /// Phase name
        phase: String,
        /// Error message
        message: String,
    },
}

impl fmt::Display for CompilationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Container { container, message } => {
                write!(f, "invalid container '{}': {}", container, message)
            }
            Self::Resource { name, message } => {
                write!(f, "resource '{}': {}", name, message)
            }
            Self::MissingMetadata { field } => {
                write!(f, "LatticeService missing {}", field)
            }
            Self::Volume { message } => {
                write!(f, "invalid volume config: {}", message)
            }
            Self::Secret { message } => {
                write!(f, "invalid secret config: {}", message)
            }
            Self::SecretAccessDenied { details } => {
                write!(f, "secret access denied: {}", details)
            }
            Self::SecurityOverrideDenied { details } => {
                write!(f, "security override denied: {}", details)
            }
            Self::VolumeAccessDenied { details } => {
                write!(f, "volume access denied: {}", details)
            }
            Self::Template { source } => {
                write!(f, "template error: {}", source)
            }
            Self::FileCompilation { message } => {
                write!(f, "file compilation error: {}", message)
            }
            Self::MonitoringRequired { metrics } => {
                write!(
                    f,
                    "custom Prometheus metrics [{}] require monitoring to be enabled on the cluster",
                    metrics.join(", ")
                )
            }
            Self::Extension { phase, message } => {
                write!(f, "extension phase '{}': {}", phase, message)
            }
        }
    }
}

impl std::error::Error for CompilationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Template { source } => Some(source),
            _ => None,
        }
    }
}

impl CompilationError {
    /// Create a container-scoped error
    pub fn container(container: &str, message: String) -> Self {
        Self::Container {
            container: container.to_string(),
            message,
        }
    }

    /// Create a resource-scoped error
    pub fn resource(name: &str, message: String) -> Self {
        Self::Resource {
            name: name.to_string(),
            message,
        }
    }

    /// Create a missing-metadata error
    pub fn missing_metadata(field: &'static str) -> Self {
        Self::MissingMetadata { field }
    }

    /// Create a volume compilation error
    pub fn volume(message: impl Into<String>) -> Self {
        Self::Volume {
            message: message.into(),
        }
    }

    /// Create a secret compilation error
    pub fn secret(message: impl Into<String>) -> Self {
        Self::Secret {
            message: message.into(),
        }
    }

    /// Create a secret-access-denied error
    pub fn secret_access_denied(details: impl Into<String>) -> Self {
        Self::SecretAccessDenied {
            details: details.into(),
        }
    }

    /// Create a security-override-denied error
    pub fn security_override_denied(details: impl Into<String>) -> Self {
        Self::SecurityOverrideDenied {
            details: details.into(),
        }
    }

    /// Create a volume-access-denied error
    pub fn volume_access_denied(details: impl Into<String>) -> Self {
        Self::VolumeAccessDenied {
            details: details.into(),
        }
    }

    /// Create a file compilation error
    pub fn file_compilation(message: impl Into<String>) -> Self {
        Self::FileCompilation {
            message: message.into(),
        }
    }

    /// Create an extension phase error
    pub fn extension(phase: &str, message: impl Into<String>) -> Self {
        Self::Extension {
            phase: phase.to_string(),
            message: message.into(),
        }
    }

    /// Returns true if this is a Cedar policy denial (secret or security override)
    pub fn is_policy_denied(&self) -> bool {
        matches!(
            self,
            Self::SecretAccessDenied { .. }
                | Self::SecurityOverrideDenied { .. }
                | Self::VolumeAccessDenied { .. }
        )
    }
}

impl From<TemplateError> for CompilationError {
    fn from(err: TemplateError) -> Self {
        Self::Template { source: err }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_error_display() {
        let err = CompilationError::container("main", "missing image".to_string());
        let display = err.to_string();
        assert!(display.contains("main"));
        assert!(display.contains("missing image"));
    }

    #[test]
    fn test_resource_error_display() {
        let err = CompilationError::resource("db-creds", "vault path not set".to_string());
        let display = err.to_string();
        assert!(display.contains("db-creds"));
        assert!(display.contains("vault path not set"));
    }

    #[test]
    fn test_monitoring_required_display() {
        let err = CompilationError::MonitoringRequired {
            metrics: vec![
                "vllm_num_requests_waiting".to_string(),
                "gpu_utilization".to_string(),
            ],
        };
        let display = err.to_string();
        assert!(display.contains("vllm_num_requests_waiting"));
        assert!(display.contains("gpu_utilization"));
        assert!(display.contains("monitoring"));
    }

    #[test]
    fn test_missing_metadata_display() {
        let err = CompilationError::missing_metadata("name");
        assert_eq!(err.to_string(), "LatticeService missing name");
    }

    #[test]
    fn test_volume_error_display() {
        let err = CompilationError::volume("bad size");
        assert!(err.to_string().contains("bad size"));
    }

    #[test]
    fn test_secret_error_display() {
        let err = CompilationError::secret("missing provider");
        assert!(err.to_string().contains("missing provider"));
    }

    #[test]
    fn test_secret_access_denied_display() {
        let err = CompilationError::secret_access_denied("denied by policy");
        assert!(err.to_string().contains("denied by policy"));
        assert!(err.is_policy_denied());
    }

    #[test]
    fn test_security_override_denied_display() {
        let err = CompilationError::security_override_denied("capability:NET_ADMIN denied");
        let display = err.to_string();
        assert!(display.contains("security override denied"));
        assert!(display.contains("capability:NET_ADMIN denied"));
        assert!(err.is_policy_denied());
    }

    #[test]
    fn test_file_compilation_display() {
        let err = CompilationError::file_compilation("invalid key");
        assert!(err.to_string().contains("invalid key"));
    }

    #[test]
    fn test_is_policy_denied() {
        assert!(CompilationError::secret_access_denied("x").is_policy_denied());
        assert!(CompilationError::security_override_denied("x").is_policy_denied());
        assert!(!CompilationError::secret("x").is_policy_denied());
        assert!(!CompilationError::volume("x").is_policy_denied());
        assert!(!CompilationError::extension("p", "m").is_policy_denied());
    }

    #[test]
    fn test_extension_error_display() {
        let err = CompilationError::extension("flagger", "canary spec invalid");
        let display = err.to_string();
        assert!(display.contains("flagger"));
        assert!(display.contains("canary spec invalid"));
        assert!(!err.is_policy_denied());
    }

    #[test]
    fn test_template_error_source_chain() {
        let template_err = TemplateError::Syntax("bad template".to_string());
        let err = CompilationError::from(template_err);
        assert!(err.to_string().contains("bad template"));
        // source() should return the TemplateError
        assert!(std::error::Error::source(&err).is_some());
    }
}
