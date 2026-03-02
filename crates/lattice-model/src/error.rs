//! Model-specific error types

use lattice_common::Retryable;

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("compilation failed for role '{role}': {source}")]
    RoleCompilation {
        role: String,
        source: lattice_workload::CompilationError,
    },

    #[error("kubernetes error: {0}")]
    Kube(#[from] kube::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("{0}")]
    Common(#[from] lattice_common::Error),

    #[error("role '{role}' validation failed: {message}")]
    RoleValidation { role: String, message: String },

    #[error("model has no roles")]
    NoRoles,

    #[error("missing namespace on LatticeModel")]
    MissingNamespace,

    #[error("Kthena ModelServing CRD not available")]
    KthenaCrdMissing,

    #[error("invalid model source URI: {0}")]
    InvalidModelUri(String),

    #[error("model download failed: {0}")]
    DownloadFailed(String),

    #[error("missing name on LatticeModel")]
    MissingName,

    #[error("missing UID on LatticeModel")]
    MissingUid,

    #[error("routing configured but inference port not specified")]
    MissingInferencePort,
}

impl Retryable for ModelError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::RoleCompilation { .. } => false,
            Self::Kube(_) => true,
            Self::Serialization(_) => false,
            Self::Common(e) => e.is_retryable(),
            Self::RoleValidation { .. } => false,
            Self::NoRoles => false,
            Self::MissingNamespace => false,
            Self::KthenaCrdMissing => true,
            Self::InvalidModelUri(_) => false,
            Self::DownloadFailed(_) => true,
            Self::MissingName => false,
            Self::MissingUid => false,
            Self::MissingInferencePort => false,
        }
    }
}
