//! Template string types
//!
//! Provides two string types for different use cases:
//! - `TemplateString`: Allows `${...}` placeholders for values that support templating
//! - `StaticString`: Rejects any template syntax for identifiers and keys

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A string that may contain `${...}` placeholders for template rendering
///
/// Use this for values that should support Score-compatible templating,
/// such as environment variable values, image tags, etc.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct TemplateString(String);

impl TemplateString {
    /// Create a new template string
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Get the underlying string
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check if this string contains any template placeholders
    pub fn has_placeholders(&self) -> bool {
        self.0.contains("${") || self.0.contains("{%")
    }

    /// Consume and return the inner string
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for TemplateString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for TemplateString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for TemplateString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// A string that must NOT contain template syntax
///
/// Use this for identifiers, keys, and names that should never be templated,
/// such as container names, resource keys, etc.
///
/// Rejects strings containing `${` or `{%` syntax at parse time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct StaticString(String);

impl StaticString {
    /// Get the underlying string
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for StaticString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Error when trying to create a StaticString from a template
#[derive(Debug, Clone)]
pub struct StaticStringError {
    /// The invalid value that contained template syntax
    pub value: String,
    /// Description of why it's invalid
    pub reason: &'static str,
}

impl fmt::Display for StaticStringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "static string cannot contain template syntax: {} (found in '{}')",
            self.reason, self.value
        )
    }
}

impl std::error::Error for StaticStringError {}

impl TryFrom<String> for StaticString {
    type Error = StaticStringError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.contains("${") {
            return Err(StaticStringError {
                value: s,
                reason: "contains ${...} placeholder",
            });
        }
        if s.contains("{%") {
            return Err(StaticStringError {
                value: s,
                reason: "contains {%...%} block",
            });
        }
        Ok(Self(s))
    }
}

impl<'de> Deserialize<'de> for StaticString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        StaticString::try_from(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_string_new() {
        let ts = TemplateString::new("hello ${world}");
        assert_eq!(ts.as_str(), "hello ${world}");
    }

    #[test]
    fn test_template_string_has_placeholders() {
        assert!(TemplateString::new("${foo}").has_placeholders());
        assert!(TemplateString::new("{% if x %}").has_placeholders());
        assert!(!TemplateString::new("plain text").has_placeholders());
    }

    #[test]
    fn test_static_string_valid() {
        let result: Result<StaticString, _> = "valid-name".to_string().try_into();
        assert!(result.is_ok());
    }

    #[test]
    fn test_static_string_rejects_placeholder() {
        let result: Result<StaticString, _> = "name-${var}".to_string().try_into();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("${...}"));
    }

    #[test]
    fn test_static_string_rejects_block() {
        let result: Result<StaticString, _> = "{% if x %}name{% endif %}".to_string().try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_static_string_serde_valid() {
        let json = r#""valid-name""#;
        let result: Result<StaticString, _> = serde_json::from_str(json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_static_string_serde_invalid() {
        let json = r#""invalid-${name}""#;
        let result: Result<StaticString, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }
}
