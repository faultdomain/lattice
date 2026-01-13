//! Error types for the Lattice operator
//!
//! Errors are structured with fields to aid debugging in production.
//! Each error variant includes contextual information like cluster names,
//! provider types, and underlying causes.

use thiserror::Error;

/// Main error type for Lattice operations
#[derive(Debug, Error)]

pub enum Error {
    /// Kubernetes API error
    #[error("kubernetes error: {source}")]
    Kube {
        /// The underlying kube-rs error
        #[from]
        source: kube::Error,
    },

    /// Validation error for CRD specs
    #[error("validation error for {cluster}: {message}")]
    Validation {
        /// Name of the cluster with invalid configuration
        cluster: String,
        /// Description of what's invalid
        message: String,
        /// The invalid field path (e.g., "spec.nodes.controlPlane")
        field: Option<String>,
    },

    /// Infrastructure provider error
    #[error("provider error [{provider}] for {cluster}: {message}")]
    Provider {
        /// Name of the cluster being provisioned
        cluster: String,
        /// Provider type (docker, aws, gcp, azure)
        provider: String,
        /// Description of what failed
        message: String,
        /// Whether this error is retryable
        retryable: bool,
    },

    /// Pivot operation error
    #[error("pivot error for {cluster}: {message}")]
    Pivot {
        /// Name of the cluster being pivoted
        cluster: String,
        /// Description of what failed
        message: String,
        /// Phase of pivot that failed (export, transfer, import)
        phase: Option<String>,
    },

    /// Serialization/deserialization error
    #[error("serialization error: {message}")]
    Serialization {
        /// Description of what failed
        message: String,
        /// The resource kind being serialized (if known)
        kind: Option<String>,
    },

    /// CAPI installation error
    #[error("CAPI installation error: {message}")]
    CapiInstallation {
        /// Description of what failed
        message: String,
        /// Provider being installed (if applicable)
        provider: Option<String>,
    },

    /// Bootstrap/cell server error
    #[error("bootstrap error: {0}")]
    Bootstrap(String),
}

impl Error {
    /// Create a validation error with the given message
    ///
    /// For simple validation errors without cluster context.
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::Validation {
            cluster: "unknown".to_string(),
            message: msg.into(),
            field: None,
        }
    }

    /// Create a validation error with cluster context
    pub fn validation_for(cluster: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::Validation {
            cluster: cluster.into(),
            message: msg.into(),
            field: None,
        }
    }

    /// Create a validation error with cluster context and field path
    pub fn validation_for_field(
        cluster: impl Into<String>,
        field: impl Into<String>,
        msg: impl Into<String>,
    ) -> Self {
        Self::Validation {
            cluster: cluster.into(),
            message: msg.into(),
            field: Some(field.into()),
        }
    }

    /// Create a provider error with the given message
    ///
    /// For simple provider errors without full context.
    pub fn provider(msg: impl Into<String>) -> Self {
        Self::Provider {
            cluster: "unknown".to_string(),
            provider: "unknown".to_string(),
            message: msg.into(),
            retryable: true,
        }
    }

    /// Create a provider error with full context
    pub fn provider_for(
        cluster: impl Into<String>,
        provider: impl Into<String>,
        msg: impl Into<String>,
    ) -> Self {
        Self::Provider {
            cluster: cluster.into(),
            provider: provider.into(),
            message: msg.into(),
            retryable: true,
        }
    }

    /// Create a non-retryable provider error (e.g., configuration error)
    pub fn provider_permanent(
        cluster: impl Into<String>,
        provider: impl Into<String>,
        msg: impl Into<String>,
    ) -> Self {
        Self::Provider {
            cluster: cluster.into(),
            provider: provider.into(),
            message: msg.into(),
            retryable: false,
        }
    }

    /// Create a pivot error with the given message
    pub fn pivot(msg: impl Into<String>) -> Self {
        Self::Pivot {
            cluster: "unknown".to_string(),
            message: msg.into(),
            phase: None,
        }
    }

    /// Create a pivot error with cluster context
    pub fn pivot_for(cluster: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::Pivot {
            cluster: cluster.into(),
            message: msg.into(),
            phase: None,
        }
    }

    /// Create a pivot error with phase information
    pub fn pivot_in_phase(
        cluster: impl Into<String>,
        phase: impl Into<String>,
        msg: impl Into<String>,
    ) -> Self {
        Self::Pivot {
            cluster: cluster.into(),
            message: msg.into(),
            phase: Some(phase.into()),
        }
    }

    /// Create a serialization error with the given message
    pub fn serialization(msg: impl Into<String>) -> Self {
        Self::Serialization {
            message: msg.into(),
            kind: None,
        }
    }

    /// Create a serialization error with resource kind context
    pub fn serialization_for_kind(kind: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::Serialization {
            message: msg.into(),
            kind: Some(kind.into()),
        }
    }

    /// Create a CAPI installation error with the given message
    pub fn capi_installation(msg: impl Into<String>) -> Self {
        Self::CapiInstallation {
            message: msg.into(),
            provider: None,
        }
    }

    /// Create a CAPI installation error for a specific provider
    pub fn capi_installation_for_provider(
        provider: impl Into<String>,
        msg: impl Into<String>,
    ) -> Self {
        Self::CapiInstallation {
            message: msg.into(),
            provider: Some(provider.into()),
        }
    }

    /// Check if this error is retryable
    ///
    /// Validation and serialization errors are not retryable (require config fix).
    /// Provider and CAPI installation errors may be retryable.
    /// Kubernetes errors depend on the error type.
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::Kube { source } => {
                // Retry on transient K8s errors (connection, timeout)
                // Don't retry on 4xx errors (validation, not found, etc.)
                !matches!(
                    source,
                    kube::Error::Api(ae) if (400..500).contains(&ae.code)
                )
            }
            Error::Validation { .. } => false,
            Error::Provider { retryable, .. } => *retryable,
            Error::Pivot { .. } => true, // Pivots are generally retryable
            Error::Serialization { .. } => false,
            Error::CapiInstallation { .. } => true,
            Error::Bootstrap(_) => true, // Bootstrap errors are generally retryable
        }
    }

    /// Get the cluster name if this error is associated with a specific cluster
    pub fn cluster(&self) -> Option<&str> {
        match self {
            Error::Kube { .. } => None,
            Error::Validation { cluster, .. } => Some(cluster),
            Error::Provider { cluster, .. } => Some(cluster),
            Error::Pivot { cluster, .. } => Some(cluster),
            Error::Serialization { .. } => None,
            Error::CapiInstallation { .. } => None,
            Error::Bootstrap(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // Story Tests: Error Propagation in Cluster Operations
    // ==========================================================================
    //
    // These tests demonstrate how errors flow through the system during
    // various cluster lifecycle operations. Each error type represents
    // a different failure category with specific handling requirements.

    /// Story: CRD validation catches misconfigurations before provisioning
    ///
    /// When a user creates a LatticeCluster with invalid configuration,
    /// the validation layer catches it immediately with a clear error message.
    #[test]
    fn story_validation_prevents_invalid_cluster_creation() {
        // Scenario: User tries to create a cluster with invalid name
        let err = Error::validation("cluster name 'My Cluster!' contains invalid characters");
        assert!(err.to_string().contains("validation error"));
        assert!(err.to_string().contains("invalid characters"));

        // Scenario: User specifies even number of control plane nodes
        let err = Error::validation("control plane count must be odd for HA (1, 3, 5, ...)");
        assert!(err.to_string().contains("odd for HA"));

        // Scenario: User specifies zero control plane nodes
        let err = Error::validation("control plane count must be at least 1");
        assert!(err.to_string().contains("at least 1"));

        // Validation errors are categorized correctly for handling
        match Error::validation("any message") {
            Error::Validation { message, .. } => assert_eq!(message, "any message"),
            _ => panic!("Expected Validation variant"),
        }
    }

    /// Story: Structured errors include cluster context for debugging
    #[test]
    fn story_structured_errors_include_cluster_context() {
        // Validation error with cluster context
        let err = Error::validation_for("prod-cluster", "invalid node count");
        assert!(err.to_string().contains("prod-cluster"));
        assert_eq!(err.cluster(), Some("prod-cluster"));

        // Validation error with field path
        let err =
            Error::validation_for_field("test-cluster", "spec.nodes.controlPlane", "must be odd");
        match &err {
            Error::Validation { field, .. } => {
                assert_eq!(field.as_deref(), Some("spec.nodes.controlPlane"));
            }
            _ => panic!("Expected Validation variant"),
        }

        // Provider error with full context
        let err = Error::provider_for("my-cluster", "docker", "daemon not running");
        assert!(err.to_string().contains("docker"));
        assert!(err.to_string().contains("my-cluster"));
        assert_eq!(err.cluster(), Some("my-cluster"));
    }

    /// Story: Provider errors surface infrastructure failures
    ///
    /// When infrastructure provisioning fails (Docker, AWS, GCP, Azure),
    /// the error clearly indicates which provider failed and why.
    #[test]
    fn story_provider_errors_during_cluster_provisioning() {
        // Scenario: Docker daemon not running for local development
        let err = Error::provider_for("dev-cluster", "docker", "connection refused");
        assert!(err.to_string().contains("provider error"));
        assert!(err.to_string().contains("docker"));

        // Scenario: AWS credentials expired
        let err = Error::provider_for("prod-cluster", "aws", "token expired");
        assert!(err.to_string().contains("aws"));

        // Scenario: GCP quota exceeded (retryable)
        let err = Error::provider_for("gcp-cluster", "gcp", "quota exceeded");
        assert!(err.is_retryable());

        // Scenario: Non-retryable provider error (config problem)
        let err = Error::provider_permanent("bad-config", "aws", "invalid region");
        assert!(!err.is_retryable());
    }

    /// Story: Pivot errors indicate CAPI migration failures
    ///
    /// The pivot operation moves CAPI resources from parent to child cluster.
    /// Failures here require careful handling as the cluster may be in an
    /// intermediate state.
    #[test]
    fn story_pivot_errors_during_self_management_transition() {
        // Scenario: clusterctl move command fails
        let err = Error::pivot_for("target-cluster", "clusterctl move failed");
        assert!(err.to_string().contains("pivot error"));
        assert!(err.to_string().contains("target-cluster"));

        // Scenario: Pivot fails during export phase
        let err = Error::pivot_in_phase("my-cluster", "export", "MachineDeployment not found");
        match &err {
            Error::Pivot { phase, .. } => assert_eq!(phase.as_deref(), Some("export")),
            _ => panic!("Expected Pivot variant"),
        }

        // Pivot errors are retryable
        assert!(err.is_retryable());
    }

    /// Story: Serialization errors surface manifest/config issues
    ///
    /// When YAML/JSON processing fails, the error indicates what
    /// was being processed and what went wrong.
    #[test]
    fn story_serialization_errors_in_manifest_processing() {
        // Scenario: Invalid YAML in cluster spec
        let err = Error::serialization("invalid YAML: unexpected key");
        assert!(err.to_string().contains("serialization error"));

        // Scenario: Serialization error with resource kind context
        let err = Error::serialization_for_kind("KubeadmControlPlane", "missing field 'spec'");
        match &err {
            Error::Serialization { kind, .. } => {
                assert_eq!(kind.as_deref(), Some("KubeadmControlPlane"));
            }
            _ => panic!("Expected Serialization variant"),
        }

        // Serialization errors are not retryable (code/config bug)
        assert!(!err.is_retryable());
    }

    /// Story: Error helper functions accept both String and &str
    ///
    /// For ergonomic API usage, error constructors accept anything
    /// that implements Into<String>.
    #[test]
    fn story_error_construction_ergonomics() {
        // From String
        let dynamic_msg = format!("cluster {} not found", "test-cluster");
        let err = Error::validation(dynamic_msg);
        assert!(err.to_string().contains("test-cluster"));

        // From &str literal
        let err = Error::provider("static message");
        assert!(err.to_string().contains("static message"));

        // From formatted string
        let cluster_name = "prod-us-west";
        let err = Error::pivot(format!("pivot failed for {}", cluster_name));
        assert!(err.to_string().contains("prod-us-west"));
    }

    /// Story: Errors have is_retryable() for controller retry logic
    #[test]
    fn story_error_retryability() {
        // Validation errors should NOT retry (user must fix config)
        assert!(!Error::validation("bad config").is_retryable());

        // Provider errors are retryable by default
        assert!(Error::provider("timeout").is_retryable());

        // Permanent provider errors are NOT retryable
        assert!(!Error::provider_permanent("c", "p", "invalid config").is_retryable());

        // Pivot errors are retryable
        assert!(Error::pivot("partial state").is_retryable());

        // Serialization errors are NOT retryable
        assert!(!Error::serialization("parse error").is_retryable());

        // CAPI installation errors are retryable
        assert!(Error::capi_installation("timeout").is_retryable());
    }

    /// Story: Error cluster() accessor returns cluster name when available
    #[test]
    fn story_error_cluster_accessor() {
        // Validation has cluster
        assert_eq!(
            Error::validation_for("my-cluster", "msg").cluster(),
            Some("my-cluster")
        );

        // Provider has cluster
        assert_eq!(
            Error::provider_for("my-cluster", "docker", "msg").cluster(),
            Some("my-cluster")
        );

        // Pivot has cluster
        assert_eq!(
            Error::pivot_for("my-cluster", "msg").cluster(),
            Some("my-cluster")
        );

        // Serialization does NOT have cluster
        assert_eq!(Error::serialization("msg").cluster(), None);

        // CAPI installation does NOT have cluster
        assert_eq!(Error::capi_installation("msg").cluster(), None);

        // Bootstrap does NOT have cluster
        assert_eq!(
            Error::Bootstrap("bootstrap failed".to_string()).cluster(),
            None
        );
    }

    #[test]
    fn test_capi_installation_for_provider() {
        let err = Error::capi_installation_for_provider("docker", "daemon not running");
        // Check error message includes the message
        assert!(err.to_string().contains("daemon not running"));
        // Check provider is stored in the struct
        match &err {
            Error::CapiInstallation { provider, .. } => {
                assert_eq!(provider.as_deref(), Some("docker"));
            }
            _ => panic!("Expected CapiInstallation variant"),
        }
        assert!(err.is_retryable());
    }

    #[test]
    fn test_bootstrap_error_is_retryable() {
        let err = Error::Bootstrap("connection timeout".to_string());
        assert!(err.is_retryable());
    }
}
