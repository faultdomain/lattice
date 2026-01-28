//! Cedar policy compilation
//!
//! Compiles Cedar policy text into validated PolicySets ready for evaluation.

use cedar_policy::{PolicySet, Schema};
use tracing::warn;

use crate::error::{CedarError, Result};

/// Cedar policy compiler with optional schema validation
#[derive(Debug, Clone)]
pub struct PolicyCompiler {
    /// Optional Cedar schema for validation
    schema: Option<Schema>,
}

impl Default for PolicyCompiler {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyCompiler {
    /// Create a new policy compiler without schema validation
    pub fn new() -> Self {
        Self { schema: None }
    }

    /// Create a policy compiler with schema validation
    pub fn with_schema(schema: Schema) -> Self {
        Self {
            schema: Some(schema),
        }
    }

    /// Compile Cedar policy text into a PolicySet
    ///
    /// Returns an error if:
    /// - The policy text has syntax errors
    /// - Schema validation fails (if schema is configured)
    pub fn compile(&self, service_name: &str, policy_text: &str) -> Result<PolicySet> {
        // Parse the policy text
        let policy_set: PolicySet = policy_text.parse().map_err(|e| {
            CedarError::policy_compilation(service_name, format!("parse error: {}", e))
        })?;

        // Validate against schema if configured
        if let Some(schema) = &self.schema {
            let validation_result = cedar_policy::Validator::new(schema.clone())
                .validate(&policy_set, cedar_policy::ValidationMode::Strict);

            if !validation_result.validation_passed() {
                let errors: Vec<String> = validation_result
                    .validation_errors()
                    .map(|e| e.to_string())
                    .collect();
                return Err(CedarError::policy_compilation(
                    service_name,
                    format!("schema validation failed: {}", errors.join("; ")),
                ));
            }

            // Log warnings but don't fail
            for warning in validation_result.validation_warnings() {
                warn!(
                    service = %service_name,
                    warning = %warning,
                    "Cedar policy validation warning"
                );
            }
        }

        Ok(policy_set)
    }

    /// Compile multiple policies by concatenating them
    ///
    /// This simply joins the policy texts with newlines and compiles the result.
    pub fn compile_all(&self, service_name: &str, policies: &[&str]) -> Result<PolicySet> {
        let combined_text = policies.join("\n\n");
        self.compile(service_name, &combined_text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_simple_policy() {
        let compiler = PolicyCompiler::new();
        let policy = r#"
            permit(
                principal,
                action,
                resource
            ) when {
                principal.role == "admin"
            };
        "#;

        let result = compiler.compile("test-service", policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compile_forbid_policy() {
        let compiler = PolicyCompiler::new();
        let policy = r#"
            forbid(
                principal,
                action,
                resource
            ) when {
                resource.path like "/admin/*"
            };
        "#;

        let result = compiler.compile("test-service", policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compile_invalid_policy() {
        let compiler = PolicyCompiler::new();
        let policy = "this is not valid cedar";

        let result = compiler.compile("test-service", policy);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("parse error"));
    }

    #[test]
    fn test_compile_multiple_policies() {
        let compiler = PolicyCompiler::new();
        let policy = r#"
            permit(
                principal,
                action == Action::"read",
                resource
            );

            forbid(
                principal,
                action == Action::"delete",
                resource
            ) when {
                !principal.isAdmin
            };
        "#;

        let result = compiler.compile("test-service", policy);
        assert!(result.is_ok());

        let policy_set = result.unwrap();
        assert_eq!(policy_set.policies().count(), 2);
    }

    #[test]
    fn test_compile_empty_policy() {
        let compiler = PolicyCompiler::new();
        let policy = "";

        let result = compiler.compile("test-service", policy);
        assert!(result.is_ok());

        let policy_set = result.unwrap();
        assert_eq!(policy_set.policies().count(), 0);
    }
}
