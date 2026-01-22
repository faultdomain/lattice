//! Environment variable compilation
//!
//! Compiles rendered environment variables into ConfigMap (non-sensitive)
//! and Secret (sensitive) resources.

use std::collections::BTreeMap;

use lattice_common::template::RenderedVariable;

use super::{ConfigMap, ConfigMapEnvSource, EnvFromSource, Secret, SecretEnvSource};

/// Result of compiling environment variables
#[derive(Debug, Default)]
pub struct CompiledEnv {
    /// ConfigMap for non-sensitive variables (if any)
    pub config_map: Option<ConfigMap>,
    /// Secret for sensitive variables (if any)
    pub secret: Option<Secret>,
    /// EnvFrom references for the container
    pub env_from: Vec<EnvFromSource>,
}

/// Compile rendered environment variables into ConfigMap/Secret
///
/// Routes variables based on their sensitivity:
/// - Non-sensitive -> ConfigMap
/// - Sensitive -> Secret
pub fn compile(
    service_name: &str,
    namespace: &str,
    variables: &BTreeMap<String, RenderedVariable>,
) -> CompiledEnv {
    let mut non_sensitive: BTreeMap<String, String> = BTreeMap::new();
    let mut sensitive: BTreeMap<String, String> = BTreeMap::new();

    for (key, var) in variables {
        if var.sensitive {
            sensitive.insert(key.clone(), var.value.clone());
        } else {
            non_sensitive.insert(key.clone(), var.value.clone());
        }
    }

    let mut result = CompiledEnv::default();

    // Create ConfigMap if there are non-sensitive variables
    if !non_sensitive.is_empty() {
        let cm_name = format!("{}-env", service_name);
        let mut cm = ConfigMap::new(&cm_name, namespace);
        cm.data = non_sensitive;
        result.config_map = Some(cm);
        result.env_from.push(EnvFromSource {
            config_map_ref: Some(ConfigMapEnvSource { name: cm_name }),
            secret_ref: None,
        });
    }

    // Create Secret if there are sensitive variables
    if !sensitive.is_empty() {
        let secret_name = format!("{}-env", service_name);
        let mut secret = Secret::new(&secret_name, namespace);
        secret.string_data = sensitive;
        result.secret = Some(secret);
        result.env_from.push(EnvFromSource {
            config_map_ref: None,
            secret_ref: Some(SecretEnvSource { name: secret_name }),
        });
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_non_sensitive_only() {
        let mut variables = BTreeMap::new();
        variables.insert("HOST".to_string(), RenderedVariable::plain("localhost"));
        variables.insert("PORT".to_string(), RenderedVariable::plain("8080"));

        let result = compile("api", "prod", &variables);

        // Should create ConfigMap, no Secret
        assert!(result.config_map.is_some());
        assert!(result.secret.is_none());

        let cm = result.config_map.expect("config_map should be set");
        assert_eq!(cm.metadata.name, "api-env");
        assert_eq!(cm.data.get("HOST"), Some(&"localhost".to_string()));
        assert_eq!(cm.data.get("PORT"), Some(&"8080".to_string()));

        // Should have one envFrom referencing ConfigMap
        assert_eq!(result.env_from.len(), 1);
        assert!(result.env_from[0].config_map_ref.is_some());
        assert!(result.env_from[0].secret_ref.is_none());
    }

    #[test]
    fn test_compile_sensitive_only() {
        let mut variables = BTreeMap::new();
        variables.insert(
            "DB_PASSWORD".to_string(),
            RenderedVariable::secret("secret123"),
        );

        let result = compile("api", "prod", &variables);

        // Should create Secret, no ConfigMap
        assert!(result.config_map.is_none());
        assert!(result.secret.is_some());

        let secret = result.secret.expect("secret should be set");
        assert_eq!(secret.metadata.name, "api-env");
        assert_eq!(
            secret.string_data.get("DB_PASSWORD"),
            Some(&"secret123".to_string())
        );

        // Should have one envFrom referencing Secret
        assert_eq!(result.env_from.len(), 1);
        assert!(result.env_from[0].config_map_ref.is_none());
        assert!(result.env_from[0].secret_ref.is_some());
    }

    #[test]
    fn test_compile_mixed() {
        let mut variables = BTreeMap::new();
        variables.insert("HOST".to_string(), RenderedVariable::plain("localhost"));
        variables.insert("PASSWORD".to_string(), RenderedVariable::secret("secret"));

        let result = compile("api", "prod", &variables);

        // Should create both ConfigMap and Secret
        assert!(result.config_map.is_some());
        assert!(result.secret.is_some());

        // Should have two envFrom references
        assert_eq!(result.env_from.len(), 2);
    }

    #[test]
    fn test_compile_empty() {
        let variables = BTreeMap::new();

        let result = compile("api", "prod", &variables);

        // Should create neither
        assert!(result.config_map.is_none());
        assert!(result.secret.is_none());
        assert!(result.env_from.is_empty());
    }
}
