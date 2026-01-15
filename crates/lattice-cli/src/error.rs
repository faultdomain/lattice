//! Error types for the CLI

use std::path::PathBuf;

/// CLI Result type
pub type Result<T> = std::result::Result<T, Error>;

/// CLI errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("git error: {0}")]
    Git(#[from] git2::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("not a lattice repository: {path}")]
    NotLatticeRepo { path: PathBuf },

    #[error("cluster not found: {name}")]
    ClusterNotFound { name: String },

    #[error("registration not found: {name}")]
    RegistrationNotFound { name: String },

    #[error("cluster already exists: {name}")]
    ClusterAlreadyExists { name: String },

    #[error("invalid LatticeCluster YAML: {0}")]
    InvalidYaml(String),

    #[error("validation error: {message}")]
    Validation { message: String },

    #[error("command failed: {message}")]
    CommandFailed { message: String },

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn validation(message: impl Into<String>) -> Self {
        Error::Validation {
            message: message.into(),
        }
    }

    pub fn command_failed(message: impl Into<String>) -> Self {
        Error::CommandFailed {
            message: message.into(),
        }
    }
}
