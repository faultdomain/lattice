//! Workload compilation error types
//!
//! Structured errors for workload compilation that include context
//! about where the error occurred (container, variable, file path).

use std::fmt;

use lattice_common::template::TemplateError;

/// Errors that can occur during workload compilation
#[derive(Debug)]
pub enum CompilationError {
    /// Error rendering a template variable
    TemplateVariable {
        /// Container where the error occurred
        container: String,
        /// Variable name that failed
        variable: String,
        /// Underlying error
        source: TemplateError,
    },

    /// Error rendering a file template
    TemplateFile {
        /// Container where the error occurred
        container: String,
        /// File path that failed
        path: String,
        /// Underlying error
        source: TemplateError,
    },

    /// Required resource not found
    ResourceNotFound {
        /// Resource name
        name: String,
        /// Resource type (e.g., "postgres", "redis")
        resource_type: String,
    },

    /// Provisioner failed to generate outputs
    ProvisionerError {
        /// Resource name
        name: String,
        /// Error message
        message: String,
    },

    /// Invalid container specification
    InvalidContainer {
        /// Container name
        container: String,
        /// Error message
        message: String,
    },

    /// Custom Prometheus metrics require monitoring to be enabled on the cluster
    MonitoringRequired {
        /// The metric names that require monitoring
        metrics: Vec<String>,
    },
}

impl fmt::Display for CompilationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TemplateVariable {
                container,
                variable,
                source,
            } => {
                write!(
                    f,
                    "failed to render variable '{}' in container '{}': {}",
                    variable, container, source
                )
            }
            Self::TemplateFile {
                container,
                path,
                source,
            } => {
                write!(
                    f,
                    "failed to render file '{}' in container '{}': {}",
                    path, container, source
                )
            }
            Self::ResourceNotFound {
                name,
                resource_type,
            } => {
                write!(
                    f,
                    "resource '{}' of type '{}' not found",
                    name, resource_type
                )
            }
            Self::ProvisionerError { name, message } => {
                write!(f, "provisioner error for resource '{}': {}", name, message)
            }
            Self::InvalidContainer { container, message } => {
                write!(f, "invalid container '{}': {}", container, message)
            }
            Self::MonitoringRequired { metrics } => {
                write!(
                    f,
                    "custom Prometheus metrics [{}] require monitoring to be enabled on the cluster",
                    metrics.join(", ")
                )
            }
        }
    }
}

impl std::error::Error for CompilationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TemplateVariable { source, .. } | Self::TemplateFile { source, .. } => {
                Some(source)
            }
            _ => None,
        }
    }
}

impl CompilationError {
    /// Create a template variable error
    pub fn template_variable(container: &str, variable: &str, source: TemplateError) -> Self {
        Self::TemplateVariable {
            container: container.to_string(),
            variable: variable.to_string(),
            source,
        }
    }

    /// Create a template file error
    pub fn template_file(container: &str, path: &str, source: TemplateError) -> Self {
        Self::TemplateFile {
            container: container.to_string(),
            path: path.to_string(),
            source,
        }
    }

    /// Create a resource not found error
    pub fn resource_not_found(name: &str, resource_type: &str) -> Self {
        Self::ResourceNotFound {
            name: name.to_string(),
            resource_type: resource_type.to_string(),
        }
    }

    /// Create a provisioner error
    pub fn provisioner_error(name: &str, message: &str) -> Self {
        Self::ProvisionerError {
            name: name.to_string(),
            message: message.to_string(),
        }
    }

    /// Create an invalid container error
    pub fn invalid_container(container: &str, message: &str) -> Self {
        Self::InvalidContainer {
            container: container.to_string(),
            message: message.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_variable_error_display() {
        let err = CompilationError::template_variable(
            "main",
            "DATABASE_URL",
            TemplateError::Undefined("resources.db.url".to_string()),
        );
        let display = err.to_string();
        assert!(display.contains("DATABASE_URL"));
        assert!(display.contains("main"));
        assert!(display.contains("resources.db.url"));
    }

    #[test]
    fn test_template_file_error_display() {
        let err = CompilationError::template_file(
            "main",
            "/etc/app/config.yaml",
            TemplateError::Syntax("unclosed brace".to_string()),
        );
        let display = err.to_string();
        assert!(display.contains("/etc/app/config.yaml"));
        assert!(display.contains("main"));
    }

    #[test]
    fn test_resource_not_found_display() {
        let err = CompilationError::resource_not_found("primary-db", "postgres");
        let display = err.to_string();
        assert!(display.contains("primary-db"));
        assert!(display.contains("postgres"));
    }

    #[test]
    fn test_provisioner_error_display() {
        let err = CompilationError::provisioner_error("cache", "connection refused");
        let display = err.to_string();
        assert!(display.contains("cache"));
        assert!(display.contains("connection refused"));
    }

    #[test]
    fn test_invalid_container_display() {
        let err = CompilationError::invalid_container("sidecar", "missing image");
        let display = err.to_string();
        assert!(display.contains("sidecar"));
        assert!(display.contains("missing image"));
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
    fn test_error_source() {
        let template_err = TemplateError::Undefined("foo".to_string());
        let err = CompilationError::template_variable("main", "VAR", template_err);

        // Should have a source error
        assert!(std::error::Error::source(&err).is_some());

        // Non-template errors don't have a source
        let err2 = CompilationError::resource_not_found("db", "postgres");
        assert!(std::error::Error::source(&err2).is_none());
    }
}
