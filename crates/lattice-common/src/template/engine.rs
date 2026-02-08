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
    ///
    /// # Panics
    ///
    /// This function will panic if the minijinja syntax configuration fails to build.
    /// This should never happen with the hardcoded delimiters used here, but if it does,
    /// it indicates a fundamental incompatibility with the minijinja library version.
    pub fn new() -> Self {
        // Build syntax config with Score-compatible delimiters.
        // These are static, well-formed delimiters that should always succeed.
        // If this fails, it indicates a minijinja API change or library bug.
        let syntax = SyntaxConfig::builder()
            .variable_delimiters("${", "}")
            .block_delimiters("{%", "%}")
            .comment_delimiters("{#", "#}")
            .build()
            .expect("template syntax configuration is hardcoded and valid");

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

        // Normalize hyphens in identifier positions within ${...} expressions.
        // MiniJinja interprets `my-db` as `my` minus `db`, so we convert to `my_db`.
        let normalized = normalize_template_identifiers(&preprocessed);

        // Render the template
        let rendered = self
            .env
            .render_str(&normalized, ctx.to_value())
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

/// Normalize hyphens in identifier positions within `${...}` template expressions.
///
/// Converts `${resources.my-db.host}` → `${resources.my_db.host}` so that
/// minijinja doesn't interpret hyphens as the subtraction operator.
/// Quoted strings inside expressions are preserved (e.g., `${x | default("my-val")}` keeps the hyphen).
fn normalize_template_identifiers(template: &str) -> String {
    let mut result = String::with_capacity(template.len());
    let mut remaining = template;

    while let Some(start) = remaining.find("${") {
        result.push_str(&remaining[..start + 2]); // Include "${"
        remaining = &remaining[start + 2..];

        if let Some(end) = remaining.find('}') {
            let expression = &remaining[..end];
            result.push_str(&normalize_expression_hyphens(expression));
            result.push('}');
            remaining = &remaining[end + 1..];
        } else {
            // No closing brace, keep rest as-is
            result.push_str(remaining);
            remaining = "";
        }
    }

    result.push_str(remaining);
    result
}

/// Normalize hyphens to underscores in identifier positions within an expression,
/// skipping quoted strings.
fn normalize_expression_hyphens(expr: &str) -> String {
    let mut result = String::with_capacity(expr.len());
    let mut chars = expr.chars().peekable();
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    while let Some(ch) = chars.next() {
        match ch {
            '\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
                result.push(ch);
            }
            '"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
                result.push(ch);
            }
            '-' if !in_single_quote && !in_double_quote => {
                // Replace hyphen with underscore when between identifier characters
                let prev_is_ident = result
                    .chars()
                    .last()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_');
                let next_is_ident = chars
                    .peek()
                    .is_some_and(|c| c.is_alphanumeric() || *c == '_');
                if prev_is_ident && next_is_ident {
                    result.push('_');
                } else {
                    result.push('-');
                }
            }
            _ => result.push(ch),
        }
    }

    result
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

    #[test]
    fn test_validate_syntax_valid_expression() {
        let engine = TemplateEngine::new();
        assert!(engine.validate_syntax("${metadata.name}").is_ok());
    }

    #[test]
    fn test_validate_syntax_valid_block() {
        let engine = TemplateEngine::new();
        assert!(engine
            .validate_syntax("{% if true %}yes{% endif %}")
            .is_ok());
    }

    #[test]
    fn test_validate_syntax_static_string() {
        let engine = TemplateEngine::new();
        assert!(engine.validate_syntax("plain text").is_ok());
    }

    #[test]
    fn test_has_template_syntax_detects_variable() {
        assert!(TemplateEngine::has_template_syntax("Hello ${name}"));
        assert!(TemplateEngine::has_template_syntax("${foo}"));
    }

    #[test]
    fn test_has_template_syntax_detects_block() {
        assert!(TemplateEngine::has_template_syntax(
            "{% if true %}{% endif %}"
        ));
    }

    #[test]
    fn test_has_template_syntax_detects_comment() {
        assert!(TemplateEngine::has_template_syntax("{# comment #}"));
    }

    #[test]
    fn test_has_template_syntax_false_for_plain() {
        assert!(!TemplateEngine::has_template_syntax("plain text"));
        assert!(!TemplateEngine::has_template_syntax(""));
    }

    // =========================================================================
    // Hyphen normalization in identifiers
    // =========================================================================

    #[test]
    fn test_normalize_simple_hyphenated_resource() {
        let input = "${resources.my-db.host}";
        let result = normalize_template_identifiers(input);
        assert_eq!(result, "${resources.my_db.host}");
    }

    #[test]
    fn test_normalize_multiple_hyphens() {
        let input = "${resources.my-db-creds.some-key}";
        let result = normalize_template_identifiers(input);
        assert_eq!(result, "${resources.my_db_creds.some_key}");
    }

    #[test]
    fn test_normalize_preserves_quoted_strings() {
        let input = r#"${config.name | default("my-value")}"#;
        let result = normalize_template_identifiers(input);
        assert_eq!(result, r#"${config.name | default("my-value")}"#);
    }

    #[test]
    fn test_normalize_no_hyphens_unchanged() {
        let input = "${resources.db.host}";
        let result = normalize_template_identifiers(input);
        assert_eq!(result, "${resources.db.host}");
    }

    #[test]
    fn test_normalize_plain_text_hyphens_unchanged() {
        let input = "plain-text-with-hyphens";
        let result = normalize_template_identifiers(input);
        assert_eq!(result, "plain-text-with-hyphens");
    }

    #[test]
    fn test_normalize_multiple_expressions() {
        let input = "${resources.my-db.host}:${resources.my-db.port}";
        let result = normalize_template_identifiers(input);
        assert_eq!(result, "${resources.my_db.host}:${resources.my_db.port}");
    }

    #[test]
    fn test_hyphenated_resource_renders_correctly() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .resource(
                "my-db",
                ResourceOutputs::builder()
                    .output("host", "db.svc")
                    .output("port", "5432")
                    .build(),
            )
            .build();

        let result = engine
            .render("${resources.my-db.host}:${resources.my-db.port}", &ctx)
            .expect("hyphenated resource name should render");
        assert_eq!(result, "db.svc:5432");
    }

    #[test]
    fn test_hyphenated_resource_with_filter() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .resource(
                "my-db",
                ResourceOutputs::builder()
                    .output("host", "db.svc")
                    .build(),
            )
            .build();

        let result = engine
            .render(r#"${resources.my-db.host | default("fallback")}"#, &ctx)
            .expect("hyphenated resource with filter should render");
        assert_eq!(result, "db.svc");
    }
}
