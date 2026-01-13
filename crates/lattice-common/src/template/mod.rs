//! Score-compatible templating for Lattice
//!
//! This module implements Score-compatible `${...}` placeholder syntax using
//! minijinja's custom syntax configuration. It enables Lattice to accept
//! Score-native workload definitions while providing Lattice-specific extensions.
//!
//! # Score Compatibility
//!
//! The following Score placeholders are supported:
//! - `${metadata.name}` - Service name from LatticeService
//! - `${metadata.annotations.KEY}` - Annotation values
//! - `${resources.NAME.FIELD}` - Resource outputs (host, port, url, etc.)
//!
//! # Lattice Extensions
//!
//! - `${cluster.name}`, `${cluster.environment}` - Cluster metadata
//! - `${env.KEY}` - Environment config from LatticeEnvironment
//! - `${config.KEY}` - Service config from LatticeServiceConfig
//! - `{% if %}...{% endif %}` - Conditionals
//! - `{% for %}...{% endfor %}` - Loops
//! - Filters: `${value | default("fallback")}`, `${value | base64_encode}`

mod context;
mod engine;
mod error;
mod filters;
mod provisioner;
mod renderer;
mod types;

pub use context::{MetadataContext, ResourceOutputs, TemplateContext};
pub use engine::TemplateEngine;
pub use error::TemplateError;
pub use provisioner::{
    ExternalServiceProvisioner, ProvisionerContext, ProvisionerRegistry, ResourceProvisioner,
    ServiceProvisioner,
};
pub use renderer::{
    RenderConfig, RenderedContainer, RenderedFile, RenderedVariable, RenderedVolume,
    TemplateRenderer,
};
pub use types::{StaticString, TemplateString};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // =========================================================================
    // Story: Score Variable Syntax
    // =========================================================================

    #[test]
    fn test_score_metadata_name() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("my-service", HashMap::new())
            .build();

        assert_eq!(
            engine.render("${metadata.name}", &ctx).unwrap(),
            "my-service"
        );
    }

    #[test]
    fn test_score_metadata_annotations() {
        let engine = TemplateEngine::new();
        let mut annotations = HashMap::new();
        annotations.insert("version".to_string(), "1.2.3".to_string());

        let ctx = TemplateContext::builder()
            .metadata("my-service", annotations)
            .build();

        assert_eq!(
            engine
                .render("${metadata.annotations.version}", &ctx)
                .unwrap(),
            "1.2.3"
        );
    }

    #[test]
    fn test_score_resource_outputs() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .resource(
                "db",
                ResourceOutputs::builder()
                    .output("host", "postgres.svc")
                    .output("port", "5432")
                    .build(),
            )
            .build();

        assert_eq!(
            engine
                .render("${resources.db.host}:${resources.db.port}", &ctx)
                .unwrap(),
            "postgres.svc:5432"
        );
    }

    // =========================================================================
    // Story: Lattice Extensions
    // =========================================================================

    #[test]
    fn test_lattice_cluster_context() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .cluster("name", "prod-cluster")
            .cluster("environment", "production")
            .build();

        assert_eq!(
            engine.render("${cluster.name}", &ctx).unwrap(),
            "prod-cluster"
        );
        assert_eq!(
            engine.render("${cluster.environment}", &ctx).unwrap(),
            "production"
        );
    }

    #[test]
    fn test_lattice_env_config() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .env("log_level", "debug")
            .build();

        assert_eq!(engine.render("${env.log_level}", &ctx).unwrap(), "debug");
    }

    #[test]
    fn test_lattice_service_config() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .config("version", "2.0.0")
            .config("replicas", "3")
            .build();

        assert_eq!(engine.render("${config.version}", &ctx).unwrap(), "2.0.0");
    }

    #[test]
    fn test_lattice_conditional_blocks() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .config("debug", "true")
            .build();

        let template = r#"{% if config.debug == "true" %}--debug{% endif %}"#;
        assert_eq!(engine.render(template, &ctx).unwrap(), "--debug");
    }

    // =========================================================================
    // Story: Strict Undefined Variables
    // =========================================================================

    #[test]
    fn test_undefined_variable_errors() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .build();

        let result = engine.render("${undefined.var}", &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_undefined_resource_errors() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .build();

        let result = engine.render("${resources.missing.host}", &ctx);
        assert!(result.is_err());
    }

    // =========================================================================
    // Story: Filters
    // =========================================================================

    #[test]
    fn test_default_filter() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .config("port", "8080")
            .build();

        // With value present
        assert_eq!(
            engine
                .render("${config.port | default(\"3000\")}", &ctx)
                .unwrap(),
            "8080"
        );
    }

    #[test]
    fn test_base64_encode_filter() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .config("secret", "hello")
            .build();

        assert_eq!(
            engine
                .render("${config.secret | base64_encode}", &ctx)
                .unwrap(),
            "aGVsbG8=" // base64("hello")
        );
    }

    #[test]
    fn test_base64_decode_filter() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .config("encoded", "aGVsbG8=")
            .build();

        assert_eq!(
            engine
                .render("${config.encoded | base64_decode}", &ctx)
                .unwrap(),
            "hello"
        );
    }

    // =========================================================================
    // Story: StaticString Rejects Templates
    // =========================================================================

    #[test]
    fn test_static_string_accepts_plain_text() {
        let result: Result<StaticString, _> = "my-service".to_string().try_into();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "my-service");
    }

    #[test]
    fn test_static_string_rejects_dollar_brace() {
        let result: Result<StaticString, _> = "my-${name}".to_string().try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_static_string_rejects_block_syntax() {
        let result: Result<StaticString, _> = "{% if x %}foo{% endif %}".to_string().try_into();
        assert!(result.is_err());
    }

    // =========================================================================
    // Story: TemplateString Allows Templates
    // =========================================================================

    #[test]
    fn test_template_string_allows_placeholders() {
        let ts = TemplateString::new("${metadata.name}-svc");
        assert!(ts.has_placeholders());
    }

    #[test]
    fn test_template_string_detects_static() {
        let ts = TemplateString::new("static-value");
        assert!(!ts.has_placeholders());
    }

    // =========================================================================
    // Story: ResourceOutputs Builder
    // =========================================================================

    #[test]
    fn test_resource_outputs_builder() {
        let outputs = ResourceOutputs::builder()
            .output("host", "db.svc.cluster.local")
            .output("port", "5432")
            .output("url", "postgres://db.svc.cluster.local:5432")
            .sensitive(
                "connection_string",
                "postgres://user:pass@db.svc.cluster.local:5432/mydb",
            )
            .output("pool_size", "10")
            .build();

        assert_eq!(
            outputs.outputs.get("host"),
            Some(&"db.svc.cluster.local".to_string())
        );
        assert_eq!(outputs.outputs.get("port"), Some(&"5432".to_string()));
        assert_eq!(
            outputs.outputs.get("url"),
            Some(&"postgres://db.svc.cluster.local:5432".to_string())
        );
        // connection_string is in sensitive, not outputs
        assert!(outputs.sensitive.contains_key("connection_string"));
    }

    // =========================================================================
    // Story: Complex Template Rendering
    // =========================================================================

    #[test]
    fn test_complex_template_with_multiple_resources() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .resource(
                "postgres",
                ResourceOutputs::builder()
                    .output("host", "pg.svc")
                    .output("port", "5432")
                    .build(),
            )
            .resource(
                "redis",
                ResourceOutputs::builder()
                    .output("host", "redis.svc")
                    .output("port", "6379")
                    .build(),
            )
            .cluster("registry", "gcr.io/myproject")
            .config("version", "1.0.0")
            .build();

        let template = "${cluster.registry}/api:${config.version}";
        assert_eq!(
            engine.render(template, &ctx).unwrap(),
            "gcr.io/myproject/api:1.0.0"
        );

        let conn_template = "postgres://${resources.postgres.host}:${resources.postgres.port}/mydb";
        assert_eq!(
            engine.render(conn_template, &ctx).unwrap(),
            "postgres://pg.svc:5432/mydb"
        );
    }

    // =========================================================================
    // Story: Score Escape Syntax ($${...})
    // =========================================================================

    #[test]
    fn test_score_escape_produces_literal() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .build();

        // Score spec: $${...} renders as literal ${...}
        assert_eq!(engine.render("$${literal}", &ctx).unwrap(), "${literal}");
    }

    #[test]
    fn test_score_escape_mixed_with_variables() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .config("port", "8080")
            .build();

        // Mix escaped and real variables
        assert_eq!(
            engine
                .render("PORT=$${PORT:-${config.port}}", &ctx)
                .unwrap(),
            "PORT=${PORT:-8080}"
        );
    }

    #[test]
    fn test_literal_dollar_without_brace() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .build();

        // Plain $ without { passes through unchanged
        assert_eq!(engine.render("$PATH", &ctx).unwrap(), "$PATH");
        assert_eq!(engine.render("cost: $100", &ctx).unwrap(), "cost: $100");
    }
}
