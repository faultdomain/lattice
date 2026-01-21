//! Template engine with Score-compatible syntax
//!
//! Uses minijinja with custom syntax configuration:
//! - Variable delimiters: `${...}` (Score-compatible)
//! - Block delimiters: `{%...%}` (Lattice extensions)
//! - Comment delimiters: `{#...#}`
//! - Escape: `$${...}` produces literal `${...}` (Score-compatible)

use minijinja::syntax::SyntaxConfig;
use minijinja::{Environment, UndefinedBehavior};

use super::context::TemplateContext;
use super::error::TemplateError;
use super::filters;

/// Placeholder for escaped `$${` during preprocessing
const ESCAPED_PLACEHOLDER: &str = "\x00__LATTICE_ESCAPED_DOLLAR_BRACE__\x00";

/// Template engine for Score-compatible placeholder resolution
///
/// Supports:
/// - `${...}` variable syntax (Score-compatible)
/// - `$${...}` escape syntax (produces literal `${...}`)
/// - `{%...%}` block syntax (Lattice extensions)
/// - Strict undefined variable handling
/// - Custom filters (default, base64_encode, base64_decode, required)
pub struct TemplateEngine {
    env: Environment<'static>,
}

impl Default for TemplateEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl TemplateEngine {
    /// Create a new template engine with Score-compatible syntax
    pub fn new() -> Self {
        let syntax = SyntaxConfig::builder()
            .variable_delimiters("${", "}")
            .block_delimiters("{%", "%}")
            .comment_delimiters("{#", "#}")
            .build()
            .expect("valid syntax config");

        let mut env = Environment::new();
        env.set_syntax(syntax);
        env.set_undefined_behavior(UndefinedBehavior::Strict);

        // Register filters
        env.add_filter("default", filters::default_filter);
        env.add_filter("base64_encode", filters::base64_encode);
        env.add_filter("base64_decode", filters::base64_decode);
        env.add_filter("required", filters::required);
        env.add_filter("upper", filters::upper);
        env.add_filter("lower", filters::lower);

        Self { env }
    }

    /// Render a template string with the given context
    ///
    /// Supports Score-compatible `$${...}` escape syntax - `$${foo}` renders as `${foo}`.
    ///
    /// # Errors
    ///
    /// Returns `TemplateError` if:
    /// - Template syntax is invalid
    /// - A referenced variable is undefined
    /// - A filter operation fails
    pub fn render(&self, template: &str, ctx: &TemplateContext) -> Result<String, TemplateError> {
        // Preprocess: replace $${...} with placeholder to prevent interpretation
        let preprocessed = template.replace("$${", ESCAPED_PLACEHOLDER);

        // Render the template
        let rendered = self
            .env
            .render_str(&preprocessed, ctx.to_value())
            .map_err(TemplateError::from)?;

        // Postprocess: restore escaped sequences as literal ${
        Ok(rendered.replace(ESCAPED_PLACEHOLDER, "${"))
    }

    /// Check if a template is valid without rendering
    ///
    /// This validates the syntax but doesn't check for undefined variables.
    pub fn validate_syntax(&self, template: &str) -> Result<(), TemplateError> {
        self.env
            .compile_expression(template)
            .map(|_| ())
            .or_else(|_| {
                // Try as a full template instead of expression
                self.env
                    .get_template(template)
                    .map(|_| ())
                    .map_err(TemplateError::from)
            })
            .or(Ok(())) // If both fail, the string might just be static
    }

    /// Check if a string contains any template syntax
    pub fn has_template_syntax(s: &str) -> bool {
        s.contains("${") || s.contains("{%") || s.contains("{#")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::template::context::ResourceOutputs;

    fn basic_context() -> TemplateContext {
        TemplateContext::builder()
            .metadata("test-service", HashMap::new())
            .build()
    }

    #[test]
    fn test_simple_variable() {
        let engine = TemplateEngine::new();
        let ctx = basic_context();

        let result = engine
            .render("${metadata.name}", &ctx)
            .expect("simple variable should render successfully");
        assert_eq!(result, "test-service");
    }

    #[test]
    fn test_variable_in_text() {
        let engine = TemplateEngine::new();
        let ctx = basic_context();

        let result = engine
            .render("Hello ${metadata.name}!", &ctx)
            .expect("variable in text should render successfully");
        assert_eq!(result, "Hello test-service!");
    }

    #[test]
    fn test_multiple_variables() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .config("version", "1.0")
            .config("env", "prod")
            .build();

        let result = engine
            .render("${metadata.name}-${config.version}-${config.env}", &ctx)
            .expect("multiple variables should render successfully");
        assert_eq!(result, "api-1.0-prod");
    }

    #[test]
    fn test_resource_access() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .resource(
                "postgres",
                ResourceOutputs::builder()
                    .output("host", "pg.svc.cluster.local")
                    .output("port", "5432")
                    .build(),
            )
            .build();

        let result = engine
            .render(
                "${resources.postgres.host}:${resources.postgres.port}",
                &ctx,
            )
            .expect("resource access should render successfully");
        assert_eq!(result, "pg.svc.cluster.local:5432");
    }

    #[test]
    fn test_undefined_strict() {
        let engine = TemplateEngine::new();
        let ctx = basic_context();

        let result = engine.render("${undefined_var}", &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_nested_undefined_strict() {
        let engine = TemplateEngine::new();
        let ctx = basic_context();

        let result = engine.render("${resources.missing.host}", &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_conditional_block() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .config("debug", "true")
            .build();

        let template = r#"{% if config.debug == "true" %}DEBUG{% else %}PROD{% endif %}"#;
        let result = engine
            .render(template, &ctx)
            .expect("conditional block should render successfully");
        assert_eq!(result, "DEBUG");
    }

    #[test]
    fn test_default_filter() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .config("port", "8080")
            .build();

        // Value exists
        let result = engine
            .render("${config.port | default(\"3000\")}", &ctx)
            .expect("default filter should render successfully");
        assert_eq!(result, "8080");
    }

    #[test]
    fn test_base64_filters() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .config("plain", "hello")
            .config("encoded", "aGVsbG8=")
            .build();

        let encoded = engine
            .render("${config.plain | base64_encode}", &ctx)
            .expect("base64_encode filter should render successfully");
        assert_eq!(encoded, "aGVsbG8=");

        let decoded = engine
            .render("${config.encoded | base64_decode}", &ctx)
            .expect("base64_decode filter should render successfully");
        assert_eq!(decoded, "hello");
    }

    #[test]
    fn test_case_filters() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .config("name", "Hello World")
            .build();

        assert_eq!(
            engine
                .render("${config.name | upper}", &ctx)
                .expect("upper filter should render successfully"),
            "HELLO WORLD"
        );
        assert_eq!(
            engine
                .render("${config.name | lower}", &ctx)
                .expect("lower filter should render successfully"),
            "hello world"
        );
    }

    #[test]
    fn test_literal_dollar() {
        let engine = TemplateEngine::new();
        let ctx = basic_context();

        // Plain $ without { passes through unchanged
        let result = engine
            .render("$PATH is set", &ctx)
            .expect("literal dollar should pass through");
        assert_eq!(result, "$PATH is set");
    }

    #[test]
    fn test_score_escape_double_dollar() {
        let engine = TemplateEngine::new();
        let ctx = basic_context();

        // Score spec: $${...} renders as literal ${...}
        let result = engine
            .render("$${literal}", &ctx)
            .expect("score escape should render successfully");
        assert_eq!(result, "${literal}");
    }

    #[test]
    fn test_score_escape_in_context() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .config("name", "myapp")
            .build();

        // Mix escaped and non-escaped
        let result = engine
            .render("echo $${VAR}; app=${config.name}", &ctx)
            .expect("mixed escape and variables should render successfully");
        assert_eq!(result, "echo ${VAR}; app=myapp");
    }

    #[test]
    fn test_score_escape_multiple() {
        let engine = TemplateEngine::new();
        let ctx = basic_context();

        // Multiple escapes in same template
        let result = engine
            .render("$${FOO} and $${BAR}", &ctx)
            .expect("multiple escapes should render successfully");
        assert_eq!(result, "${FOO} and ${BAR}");
    }

    #[test]
    fn test_raw_block_escapes_syntax() {
        let engine = TemplateEngine::new();
        let ctx = basic_context();

        // Use {% raw %} to include literal ${...}
        let result = engine
            .render("{% raw %}${literal}{% endraw %}", &ctx)
            .expect("raw block should render successfully");
        assert_eq!(result, "${literal}");
    }

    #[test]
    fn test_has_template_syntax() {
        assert!(TemplateEngine::has_template_syntax("${foo}"));
        assert!(TemplateEngine::has_template_syntax("{% if x %}"));
        assert!(TemplateEngine::has_template_syntax("{# comment #}"));
        assert!(!TemplateEngine::has_template_syntax("plain text"));
        assert!(!TemplateEngine::has_template_syntax("$foo")); // Not Score syntax
    }

    #[test]
    fn test_annotations() {
        let engine = TemplateEngine::new();
        let mut annotations = HashMap::new();
        annotations.insert("team".to_string(), "platform".to_string());
        annotations.insert("tier".to_string(), "backend".to_string());

        let ctx = TemplateContext::builder()
            .metadata("api", annotations)
            .build();

        assert_eq!(
            engine
                .render("${metadata.annotations.team}", &ctx)
                .expect("annotations should render successfully"),
            "platform"
        );
    }

    #[test]
    fn test_static_string_no_rendering() {
        let engine = TemplateEngine::new();
        let ctx = basic_context();

        // Plain strings should pass through unchanged
        let result = engine
            .render("plain-text-no-placeholders", &ctx)
            .expect("plain text should render successfully");
        assert_eq!(result, "plain-text-no-placeholders");
    }
}
