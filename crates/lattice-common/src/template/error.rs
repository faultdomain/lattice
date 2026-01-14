//! Template error types

use std::fmt;

/// Errors that can occur during template operations
#[derive(Debug)]
pub enum TemplateError {
    /// Template rendering failed
    Render(minijinja::Error),
    /// Template syntax is invalid
    Syntax(String),
    /// Required variable is undefined
    Undefined(String),
    /// Filter operation failed
    Filter(String),
    /// Base64 encoding/decoding failed
    Base64(String),
    /// Container image "." placeholder has no config value
    MissingImage(String),
}

impl TemplateError {
    /// Create a missing image error for a container
    pub fn missing_image(container_name: &str) -> Self {
        Self::MissingImage(container_name.to_string())
    }
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Render(e) => write!(f, "template render error: {}", e),
            Self::Syntax(msg) => write!(f, "template syntax error: {}", msg),
            Self::Undefined(var) => write!(f, "undefined variable: {}", var),
            Self::Filter(msg) => write!(f, "filter error: {}", msg),
            Self::Base64(msg) => write!(f, "base64 error: {}", msg),
            Self::MissingImage(container) => write!(
                f,
                "container '{}' has image: \".\" but no image found in config (expected config.image.{} or config.image)",
                container, container
            ),
        }
    }
}

impl std::error::Error for TemplateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Render(e) => Some(e),
            _ => None,
        }
    }
}

impl From<minijinja::Error> for TemplateError {
    fn from(err: minijinja::Error) -> Self {
        Self::Render(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = TemplateError::Undefined("foo.bar".to_string());
        assert!(err.to_string().contains("undefined variable"));
        assert!(err.to_string().contains("foo.bar"));
    }

    #[test]
    fn test_syntax_error_display() {
        let err = TemplateError::Syntax("unclosed brace".to_string());
        assert!(err.to_string().contains("syntax error"));
    }
}
