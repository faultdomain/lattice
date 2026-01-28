//! Error types for the Cedar authorization engine

use thiserror::Error;

/// Cedar authorization error types
#[derive(Debug, Error)]
pub enum CedarError {
    /// Policy compilation error
    #[error("policy compilation error for {service}: {message}")]
    PolicyCompilation {
        /// Service name
        service: String,
        /// Error message
        message: String,
    },

    /// Policy evaluation error
    #[error("policy evaluation error: {message}")]
    PolicyEvaluation {
        /// Error message
        message: String,
    },

    /// JWT validation error
    #[error("JWT validation error: {message}")]
    JwtValidation {
        /// Error message
        message: String,
    },

    /// JWKS fetch error
    #[error("JWKS fetch error for {issuer}: {message}")]
    JwksFetch {
        /// OIDC issuer URL
        issuer: String,
        /// Error message
        message: String,
    },

    /// Missing or invalid header
    #[error("header error: {message}")]
    Header {
        /// Error message
        message: String,
    },

    /// Service not found in policy store
    #[error("service not found: {namespace}/{name}")]
    ServiceNotFound {
        /// Service namespace
        namespace: String,
        /// Service name
        name: String,
    },

    /// Configuration error
    #[error("configuration error: {message}")]
    Configuration {
        /// Error message
        message: String,
    },

    /// gRPC transport error
    #[error("gRPC error: {message}")]
    Grpc {
        /// Error message
        message: String,
    },

    /// Kubernetes API error
    #[error("kubernetes error: {0}")]
    Kube(#[from] kube::Error),
}

impl CedarError {
    /// Create a policy compilation error
    pub fn policy_compilation(service: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::PolicyCompilation {
            service: service.into(),
            message: msg.into(),
        }
    }

    /// Create a policy evaluation error
    pub fn policy_evaluation(msg: impl Into<String>) -> Self {
        Self::PolicyEvaluation {
            message: msg.into(),
        }
    }

    /// Create a JWT validation error
    pub fn jwt_validation(msg: impl Into<String>) -> Self {
        Self::JwtValidation {
            message: msg.into(),
        }
    }

    /// Create a JWKS fetch error
    pub fn jwks_fetch(issuer: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::JwksFetch {
            issuer: issuer.into(),
            message: msg.into(),
        }
    }

    /// Create a header error
    pub fn header(msg: impl Into<String>) -> Self {
        Self::Header {
            message: msg.into(),
        }
    }

    /// Create a service not found error
    pub fn service_not_found(namespace: impl Into<String>, name: impl Into<String>) -> Self {
        Self::ServiceNotFound {
            namespace: namespace.into(),
            name: name.into(),
        }
    }

    /// Create a configuration error
    pub fn configuration(msg: impl Into<String>) -> Self {
        Self::Configuration {
            message: msg.into(),
        }
    }

    /// Create a gRPC error
    pub fn grpc(msg: impl Into<String>) -> Self {
        Self::Grpc {
            message: msg.into(),
        }
    }

    /// Check if this error should result in a deny response (vs internal error)
    pub fn is_auth_failure(&self) -> bool {
        matches!(
            self,
            CedarError::JwtValidation { .. }
                | CedarError::Header { .. }
                | CedarError::PolicyEvaluation { .. }
        )
    }
}

/// Result type for Cedar operations
pub type Result<T> = std::result::Result<T, CedarError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_compilation_error() {
        let err = CedarError::policy_compilation("my-service", "invalid syntax");
        assert!(err.to_string().contains("my-service"));
        assert!(err.to_string().contains("invalid syntax"));
    }

    #[test]
    fn test_jwt_validation_error() {
        let err = CedarError::jwt_validation("token expired");
        assert!(err.to_string().contains("token expired"));
        assert!(err.is_auth_failure());
    }

    #[test]
    fn test_service_not_found_error() {
        let err = CedarError::service_not_found("default", "api-server");
        assert!(err.to_string().contains("default/api-server"));
        assert!(!err.is_auth_failure());
    }

    #[test]
    fn test_auth_failure_classification() {
        assert!(CedarError::jwt_validation("expired").is_auth_failure());
        assert!(CedarError::header("missing").is_auth_failure());
        assert!(CedarError::policy_evaluation("denied").is_auth_failure());
        assert!(!CedarError::service_not_found("ns", "svc").is_auth_failure());
        assert!(!CedarError::configuration("bad config").is_auth_failure());
    }
}
