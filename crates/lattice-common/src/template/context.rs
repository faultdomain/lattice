//! Template context for Score-compatible rendering
//!
//! Provides the context structure that maps Score placeholders to values:
//! - `${metadata.name}` - Service metadata
//! - `${resources.NAME.FIELD}` - Resource outputs
//! - `${cluster.*}` - Lattice cluster context
//! - `${env.*}` - Environment config
//! - `${config.*}` - Service config

use minijinja::Value;
use std::collections::HashMap;

/// Template context containing all values available for placeholder resolution
#[derive(Debug, Clone, Default)]
pub struct TemplateContext {
    /// Score: `${metadata.name}`, `${metadata.annotations.KEY}`
    pub metadata: MetadataContext,

    /// Score: `${resources.NAME.FIELD}`
    /// Resolved from ResourceSpec + provisioner outputs
    pub resources: HashMap<String, ResourceOutputs>,

    /// Lattice extension: `${cluster.name}`, `${cluster.environment}`
    pub cluster: HashMap<String, String>,

    /// Lattice extension: `${env.KEY}` from LatticeEnvironment.spec.config
    pub env: HashMap<String, String>,

    /// Lattice extension: `${config.KEY}` from LatticeServiceConfig
    pub config: HashMap<String, String>,
}

impl TemplateContext {
    /// Create a new builder for TemplateContext
    pub fn builder() -> TemplateContextBuilder {
        TemplateContextBuilder::default()
    }

    /// Convert to minijinja Value for rendering
    pub fn to_value(&self) -> Value {
        let mut map = HashMap::new();

        // metadata
        let mut metadata_map = HashMap::new();
        metadata_map.insert("name".to_string(), Value::from(self.metadata.name.clone()));
        metadata_map.insert(
            "annotations".to_string(),
            Value::from_iter(self.metadata.annotations.clone()),
        );
        map.insert("metadata".to_string(), Value::from_iter(metadata_map));

        // resources — normalize hyphens to underscores so minijinja doesn't
        // interpret `my-db` as subtraction. Templates are also normalized in
        // TemplateEngine::render() so `${resources.my-db.host}` matches `my_db`.
        let resources_map: HashMap<String, Value> = self
            .resources
            .iter()
            .map(|(name, outputs)| (name.replace('-', "_"), outputs.to_value()))
            .collect();
        map.insert("resources".to_string(), Value::from_iter(resources_map));

        // cluster
        map.insert(
            "cluster".to_string(),
            Value::from_iter(self.cluster.clone()),
        );

        // env
        map.insert("env".to_string(), Value::from_iter(self.env.clone()));

        // config
        map.insert("config".to_string(), Value::from_iter(self.config.clone()));

        Value::from_iter(map)
    }
}

/// Builder for TemplateContext
#[derive(Debug, Default)]
pub struct TemplateContextBuilder {
    metadata: Option<MetadataContext>,
    resources: HashMap<String, ResourceOutputs>,
    cluster: HashMap<String, String>,
    env: HashMap<String, String>,
    config: HashMap<String, String>,
}

impl TemplateContextBuilder {
    /// Set the metadata context
    pub fn metadata(
        mut self,
        name: impl Into<String>,
        annotations: HashMap<String, String>,
    ) -> Self {
        self.metadata = Some(MetadataContext {
            name: name.into(),
            annotations,
        });
        self
    }

    /// Add a resource with its outputs
    pub fn resource(mut self, name: impl Into<String>, outputs: ResourceOutputs) -> Self {
        self.resources.insert(name.into(), outputs);
        self
    }

    /// Add a cluster context value
    pub fn cluster(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.cluster.insert(key.into(), value.into());
        self
    }

    /// Add an environment config value
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Add a service config value
    pub fn config(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.insert(key.into(), value.into());
        self
    }

    /// Build the TemplateContext
    pub fn build(self) -> TemplateContext {
        TemplateContext {
            metadata: self.metadata.unwrap_or_default(),
            resources: self.resources,
            cluster: self.cluster,
            env: self.env,
            config: self.config,
        }
    }
}

/// Metadata context for Score's `${metadata.*}` placeholders
#[derive(Debug, Clone, Default)]
pub struct MetadataContext {
    /// Service name: `${metadata.name}`
    pub name: String,
    /// Annotations: `${metadata.annotations.KEY}`
    pub annotations: HashMap<String, String>,
}

/// Resource outputs resolved from provisioners
///
/// Outputs are split into non-sensitive (ConfigMap) and sensitive (Secret) maps.
/// The provisioner explicitly declares which outputs are sensitive.
#[derive(Debug, Clone, Default)]
pub struct ResourceOutputs {
    /// Non-sensitive outputs -> ConfigMap
    /// e.g., host, port, database name, public URLs
    pub outputs: HashMap<String, String>,
    /// Sensitive outputs -> Secret
    /// e.g., passwords, connection strings with credentials
    pub sensitive: HashMap<String, String>,
}

impl ResourceOutputs {
    /// Create a new builder
    pub fn builder() -> ResourceOutputsBuilder {
        ResourceOutputsBuilder::default()
    }

    /// Get a field value and whether it's sensitive
    ///
    /// Returns `Some((value, is_sensitive))` if found, `None` otherwise.
    pub fn get(&self, field: &str) -> Option<(&str, bool)> {
        if let Some(v) = self.outputs.get(field) {
            Some((v.as_str(), false))
        } else if let Some(v) = self.sensitive.get(field) {
            Some((v.as_str(), true))
        } else {
            None
        }
    }

    /// Check if a field is sensitive
    pub fn is_sensitive(&self, field: &str) -> bool {
        self.sensitive.contains_key(field)
    }

    /// Convert to minijinja Value for template rendering
    ///
    /// Both sensitive and non-sensitive values are merged for rendering.
    /// Sensitivity tracking happens separately during rendering.
    pub fn to_value(&self) -> Value {
        let mut map: HashMap<String, Value> = HashMap::new();

        // Add non-sensitive outputs
        for (key, value) in &self.outputs {
            map.insert(key.clone(), Value::from(value.clone()));
        }

        // Add sensitive outputs (they render the same, but sensitivity is tracked separately)
        for (key, value) in &self.sensitive {
            map.insert(key.clone(), Value::from(value.clone()));
        }

        Value::from_iter(map)
    }
}

/// Builder for ResourceOutputs
#[derive(Debug, Default)]
pub struct ResourceOutputsBuilder {
    outputs: HashMap<String, String>,
    sensitive: HashMap<String, String>,
}

impl ResourceOutputsBuilder {
    /// Add a non-sensitive output
    ///
    /// Use this for public information like hosts, ports, database names.
    pub fn output(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.outputs.insert(key.into(), value.into());
        self
    }

    /// Add a sensitive output
    ///
    /// Use this for credentials, passwords, connection strings with credentials.
    /// These values will be routed to Kubernetes Secrets.
    pub fn sensitive(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.sensitive.insert(key.into(), value.into());
        self
    }

    /// Build the ResourceOutputs
    pub fn build(self) -> ResourceOutputs {
        ResourceOutputs {
            outputs: self.outputs,
            sensitive: self.sensitive,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_builder() {
        let ctx = TemplateContext::builder()
            .metadata("my-service", HashMap::new())
            .resource(
                "db",
                ResourceOutputs::builder().output("host", "db.svc").build(),
            )
            .cluster("name", "prod")
            .env("log_level", "info")
            .config("version", "1.0")
            .build();

        assert_eq!(ctx.metadata.name, "my-service");
        assert!(ctx.resources.contains_key("db"));
        assert_eq!(ctx.cluster.get("name"), Some(&"prod".to_string()));
        assert_eq!(ctx.env.get("log_level"), Some(&"info".to_string()));
        assert_eq!(ctx.config.get("version"), Some(&"1.0".to_string()));
    }

    #[test]
    fn test_resource_outputs_builder() {
        let outputs = ResourceOutputs::builder()
            .output("host", "pg.svc")
            .output("port", "5432")
            .output("url", "postgres://pg.svc:5432")
            .sensitive("username", "admin")
            .sensitive("password", "secret123")
            .output("pool_size", "10")
            .build();

        // Check non-sensitive outputs
        assert_eq!(outputs.outputs.get("host"), Some(&"pg.svc".to_string()));
        assert_eq!(outputs.outputs.get("port"), Some(&"5432".to_string()));
        assert_eq!(outputs.outputs.get("pool_size"), Some(&"10".to_string()));

        // Check sensitive outputs
        assert_eq!(
            outputs.sensitive.get("username"),
            Some(&"admin".to_string())
        );
        assert_eq!(
            outputs.sensitive.get("password"),
            Some(&"secret123".to_string())
        );
    }

    #[test]
    fn test_resource_outputs_get() {
        let outputs = ResourceOutputs::builder()
            .output("host", "db.svc")
            .sensitive("password", "secret")
            .build();

        // Non-sensitive field
        let (value, sensitive) = outputs.get("host").expect("host output should exist");
        assert_eq!(value, "db.svc");
        assert!(!sensitive);

        // Sensitive field
        let (value, sensitive) = outputs
            .get("password")
            .expect("password output should exist");
        assert_eq!(value, "secret");
        assert!(sensitive);

        // Non-existent field
        assert!(outputs.get("nonexistent").is_none());
    }

    #[test]
    fn test_resource_outputs_is_sensitive() {
        let outputs = ResourceOutputs::builder()
            .output("host", "db.svc")
            .sensitive("password", "secret")
            .build();

        assert!(!outputs.is_sensitive("host"));
        assert!(outputs.is_sensitive("password"));
        assert!(!outputs.is_sensitive("nonexistent"));
    }

    #[test]
    fn test_to_value() {
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .resource(
                "db",
                ResourceOutputs::builder()
                    .output("host", "db.svc")
                    .output("port", "5432")
                    .build(),
            )
            .build();

        let value = ctx.to_value();
        // Basic sanity check - it should be indexable as a map
        assert!(!value.is_undefined());
    }

    #[test]
    fn test_to_value_includes_sensitive() {
        let outputs = ResourceOutputs::builder()
            .output("host", "db.svc")
            .sensitive("password", "secret")
            .build();

        let value = outputs.to_value();
        // Both should be present in the value for template rendering
        assert!(!value.is_undefined());
    }
}
