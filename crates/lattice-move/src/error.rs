//! Error types for distributed CAPI resource move operations

use thiserror::Error;

/// Errors from distributed move operations
#[derive(Debug, Error)]
pub enum MoveError {
    /// CRD discovery failed
    #[error("discovery failed: {0}")]
    Discovery(String),

    /// Object not found during move
    #[error("object {kind}/{name} not found")]
    ObjectNotFound {
        /// Kubernetes kind
        kind: String,
        /// Object name
        name: String,
    },

    /// Batch operation failed
    #[error("batch {index} failed: {message}")]
    BatchFailed {
        /// Batch index that failed
        index: u32,
        /// Error message
        message: String,
    },

    /// Object already exists on target (not using replace)
    #[error("already exists: {kind}/{name}")]
    AlreadyExists {
        /// Kubernetes kind
        kind: String,
        /// Object name
        name: String,
    },

    /// Cycle detected in ownership graph
    #[error("cycle detected in ownership graph: {0}")]
    CycleDetected(String),

    /// UID mapping not found (owner not yet created)
    #[error("uid mapping not found for {source_uid}")]
    UidMappingNotFound {
        /// Source UID that was not found in mapping
        source_uid: String,
    },

    /// Namespace creation failed
    #[error("failed to create namespace {namespace}: {message}")]
    NamespaceCreation {
        /// Namespace that failed to create
        namespace: String,
        /// Error message
        message: String,
    },

    /// Pause/unpause operation failed
    #[error("pause operation failed: {0}")]
    PauseFailed(String),

    /// Source deletion failed
    #[error("source deletion failed: {0}")]
    DeletionFailed(String),

    /// Agent communication error
    #[error("agent communication error: {0}")]
    AgentCommunication(String),

    /// Move timed out
    #[error("move operation timed out after {seconds}s")]
    Timeout {
        /// Timeout in seconds
        seconds: u64,
    },

    /// Kubernetes API error
    #[error("kube error: {0}")]
    Kube(#[from] kube::Error),

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Move was cancelled
    #[error("move was cancelled")]
    Cancelled,
}

impl MoveError {
    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            MoveError::Kube(_)
                | MoveError::AgentCommunication(_)
                | MoveError::Timeout { .. }
                | MoveError::BatchFailed { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = MoveError::ObjectNotFound {
            kind: "Cluster".to_string(),
            name: "test-cluster".to_string(),
        };
        assert_eq!(err.to_string(), "object Cluster/test-cluster not found");

        let err = MoveError::BatchFailed {
            index: 3,
            message: "connection refused".to_string(),
        };
        assert_eq!(err.to_string(), "batch 3 failed: connection refused");

        let err = MoveError::Timeout { seconds: 300 };
        assert_eq!(err.to_string(), "move operation timed out after 300s");
    }

    #[test]
    fn test_is_retryable() {
        assert!(MoveError::Timeout { seconds: 30 }.is_retryable());
        assert!(MoveError::AgentCommunication("test".to_string()).is_retryable());
        assert!(MoveError::BatchFailed {
            index: 1,
            message: "error".to_string()
        }
        .is_retryable());

        assert!(!MoveError::Cancelled.is_retryable());
        assert!(!MoveError::CycleDetected("test".to_string()).is_retryable());
        assert!(!MoveError::AlreadyExists {
            kind: "Cluster".to_string(),
            name: "test".to_string()
        }
        .is_retryable());
    }
}
