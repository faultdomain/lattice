//! Error types for the CLI

/// CLI Result type
pub type Result<T> = std::result::Result<T, Error>;

/// CLI errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("validation error: {message}")]
    Validation { message: String },

    #[error("command failed: {message}")]
    CommandFailed { message: String },
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
