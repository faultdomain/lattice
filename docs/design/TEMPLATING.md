# Templating Design

> Future work: Implement Jinja2-style templating for configuration values using Minijinja.

## Overview

Lattice needs a templating system to allow environment-specific configuration without duplicating service definitions. This document outlines the design for a Minijinja-based templating system.

## Why Minijinja

| Consideration | Decision |
|---------------|----------|
| **Syntax** | Jinja2 (`{{ }}`) - doesn't conflict with bash, Make, or shell expansion |
| **Familiarity** | Widely known from Ansible, Flask, Hugo, etc. |
| **Type preservation** | Renders integers as integers, not strings |
| **Error messages** | Line/column info, helpful suggestions |
| **Extensibility** | Custom filters and functions |
| **Performance** | Rust-native, no runtime interpretation |

### Why Not `${}`

The Elixir POC used `${var}` syntax which conflicts with:
- Bash variable expansion
- Makefile variables
- Docker Compose interpolation
- GitHub Actions expressions
- Most shell heredocs

```bash
# Problem: bash tries to expand ${cluster.host}
cat <<EOF
host: ${cluster.host}
EOF

# Solution: {{ }} is safe everywhere
cat <<EOF
host: {{ cluster.host }}
EOF
```

## Template Context

Templates have access to these namespaces:

```rust
pub struct TemplateContext {
    /// Cluster metadata
    /// - name: cluster name
    /// - domain: cluster base domain
    /// - environment: prod/staging/dev
    /// - provider: docker/aws/gcp/azure
    pub cluster: HashMap<String, Value>,

    /// Environment-level configuration (from LatticeEnvironment.spec.config)
    /// User-defined key-value pairs shared across services in an environment
    pub env: HashMap<String, Value>,

    /// Service-specific configuration (from LatticeServiceConfig)
    /// Merged: base config + environment overlay
    pub config: HashMap<String, Value>,

    /// Discovered service endpoints (from service graph)
    /// {{ services.redis.host }}, {{ services.redis.port }}
    pub services: HashMap<String, ServiceEndpoint>,

    /// Network configuration
    /// - zone: network zone
    /// - domain: service mesh domain
    /// - issuer: cert-manager issuer
    pub network: HashMap<String, Value>,
}

pub struct ServiceEndpoint {
    pub host: String,
    pub port: u16,
    pub url: String,  // Convenience: "http://{host}:{port}"
}
```

### Context Resolution Order

1. **cluster** - Set by controller from LatticeCluster
2. **env** - From LatticeEnvironment.spec.config
3. **config** - Merged from LatticeServiceConfig (base + env overlay)
4. **services** - Resolved from service graph at render time
5. **network** - From LatticeEnvironment.spec.networking

## Where Templating is Allowed

### Allowed (Values Only)

| Location | Example |
|----------|---------|
| Container image | `image: "{{ cluster.registry }}/app:{{ config.version }}"` |
| Container args | `args: ["--env={{ cluster.environment }}"]` |
| Container command | `command: ["./run", "--config={{ config.path }}"]` |
| Environment variable values | `DATABASE_URL: "{{ services.postgres.url }}"` |
| Resource requests/limits | `cpu: "{{ config.resources.cpu }}"` |
| File content (Score-style) | Full Jinja2 in mounted config files |
| Annotation values | `prometheus.io/port: "{{ config.metrics_port }}"` |
| Label values | `version: "{{ config.version }}"` (use sparingly) |

### NOT Allowed (Enforced at Parse Time)

| Location | Reason |
|----------|--------|
| `metadata.name` | Must be DNS-safe, used in selectors and references |
| `metadata.namespace` | Must be predictable for RBAC policies |
| Label keys | Used in label selectors, must be static |
| Annotation keys | Should be predictable for tooling |
| Container name | Referenced by other fields (probes, volumes) |
| Volume names | Referenced by volume mounts |
| Port names | Referenced by services |
| File target paths | Must be predictable for debugging |
| Any map/struct keys | Schema validation requires known keys |

## Module Structure

```
src/
└── template/
    ├── mod.rs           # Public API, TemplateEngine
    ├── context.rs       # TemplateContext builder
    ├── filters.rs       # Custom Minijinja filters
    ├── types.rs         # TemplateString, StaticString
    ├── validation.rs    # Pre-render validation
    └── error.rs         # TemplateError with field context
```

## Core Types

### TemplateString

A string field that supports templating:

```rust
/// A string that may contain Jinja2 template expressions.
///
/// Use this for fields where templating is allowed.
/// Literal strings (no `{{`) skip template processing for performance.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct TemplateString(String);

impl TemplateString {
    /// Render the template with the given context.
    /// Returns the original string if no template expressions are present.
    pub fn render(
        &self,
        engine: &TemplateEngine,
        ctx: &TemplateContext
    ) -> Result<String, TemplateError> {
        if self.needs_rendering() {
            engine.render_string(&self.0, ctx)
        } else {
            Ok(self.0.clone())
        }
    }

    /// Check if this string contains template expressions.
    pub fn needs_rendering(&self) -> bool {
        self.0.contains("{{") || self.0.contains("{%")
    }

    /// Get the raw template string (for validation/debugging).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
```

### StaticString

A string field that rejects templating at parse time:

```rust
/// A string that must NOT contain template expressions.
///
/// Use this for fields like metadata.name where templating is forbidden.
/// Parsing fails if `{{` or `{%` is present.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(try_from = "String")]
pub struct StaticString(String);

impl TryFrom<String> for StaticString {
    type Error = &'static str;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.contains("{{") || s.contains("{%") {
            Err("this field does not support templating")
        } else {
            Ok(StaticString(s))
        }
    }
}
```

### TemplateEngine

```rust
/// Minijinja-based template engine with custom filters.
pub struct TemplateEngine {
    env: minijinja::Environment<'static>,
}

impl TemplateEngine {
    pub fn new() -> Self {
        let mut env = minijinja::Environment::new();

        // Strict mode: undefined variables are errors
        env.set_undefined_behavior(minijinja::UndefinedBehavior::Strict);

        // Register custom filters
        env.add_filter("default", filters::default);
        env.add_filter("quote", filters::quote);
        env.add_filter("base64_encode", filters::base64_encode);
        env.add_filter("base64_decode", filters::base64_decode);
        env.add_filter("yaml", filters::yaml);
        env.add_filter("json", filters::json);
        env.add_filter("indent", filters::indent);
        env.add_filter("required", filters::required);

        Self { env }
    }

    /// Render a template string to a string result.
    pub fn render_string(
        &self,
        template: &str,
        ctx: &TemplateContext
    ) -> Result<String, TemplateError>;

    /// Render a template and preserve the output type.
    /// Use for fields like `replicas` where the result should be an integer.
    pub fn render_value(
        &self,
        template: &str,
        ctx: &TemplateContext
    ) -> Result<minijinja::Value, TemplateError>;

    /// Validate a template without rendering (check syntax + variable refs).
    pub fn validate(
        &self,
        template: &str,
        available_vars: &[&str]
    ) -> Result<(), TemplateError>;
}
```

## Custom Filters

```rust
// src/template/filters.rs

/// Default value if undefined or null.
/// Usage: {{ var | default("fallback") }}
pub fn default(value: Value, fallback: Value) -> Value;

/// Quote a string for shell safety.
/// Usage: {{ path | quote }}  ->  "/path/with spaces"
pub fn quote(s: &str) -> String;

/// Base64 encode.
/// Usage: {{ secret | base64_encode }}
pub fn base64_encode(s: &str) -> String;

/// Base64 decode.
/// Usage: {{ encoded | base64_decode }}
pub fn base64_decode(s: &str) -> Result<String, Error>;

/// Serialize to YAML (for nested config).
/// Usage: {{ config | yaml }}
pub fn yaml(value: Value) -> Result<String, Error>;

/// Serialize to JSON.
/// Usage: {{ config | json }}
pub fn json(value: Value) -> Result<String, Error>;

/// Indent each line (for YAML embedding).
/// Usage: {{ content | indent(4) }}
pub fn indent(s: &str, spaces: usize) -> String;

/// Fail if value is undefined (explicit requirement).
/// Usage: {{ critical_var | required }}
pub fn required(value: Value) -> Result<Value, Error>;
```

## Validation

### Pre-render Validation

Validate templates before creating any Kubernetes resources:

```rust
// src/template/validation.rs

pub struct ValidationResult {
    pub errors: Vec<TemplateError>,
    pub warnings: Vec<TemplateWarning>,
}

pub enum TemplateWarning {
    /// A secrets.* reference was found (will be resolved via ExternalSecret)
    SecretReference { field: String, secret_path: String },

    /// A service reference may not exist yet
    ServiceReference { field: String, service_name: String },

    /// Using default value (variable was undefined)
    UsingDefault { field: String, variable: String, default: String },
}

impl LatticeService {
    /// Validate all templates in the service spec.
    /// Call this before generating Kubernetes manifests.
    pub fn validate_templates(
        &self,
        ctx: &TemplateContext
    ) -> ValidationResult {
        let engine = TemplateEngine::new();
        let mut result = ValidationResult::default();

        for (i, container) in self.spec.containers.iter().enumerate() {
            let prefix = format!("spec.containers[{}]", i);

            // Validate image
            if let Err(e) = container.image.render(&engine, ctx) {
                result.errors.push(e.with_field(&format!("{}.image", prefix)));
            }

            // Validate env values
            for (key, value) in &container.env {
                if let Err(e) = value.render(&engine, ctx) {
                    result.errors.push(e.with_field(&format!("{}.env.{}", prefix, key)));
                }

                // Check for secret references
                if value.as_str().contains("secrets.") {
                    result.warnings.push(TemplateWarning::SecretReference {
                        field: format!("{}.env.{}", prefix, key),
                        secret_path: extract_secret_path(value.as_str()),
                    });
                }
            }

            // Validate args
            for (j, arg) in container.args.iter().enumerate() {
                if let Err(e) = arg.render(&engine, ctx) {
                    result.errors.push(e.with_field(&format!("{}.args[{}]", prefix, j)));
                }
            }

            // Validate file contents
            for file in &container.files {
                if let FileSource::Inline { content } = &file.source {
                    if let Err(e) = content.render(&engine, ctx) {
                        result.errors.push(e.with_field(
                            &format!("{}.files[target={}].content", prefix, file.target)
                        ));
                    }
                }
            }
        }

        result
    }
}
```

### Error Types

```rust
// src/template/error.rs

#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("syntax error in template at {field}: {message}")]
    Syntax {
        field: String,
        message: String,
        line: Option<usize>,
        column: Option<usize>,
    },

    #[error("undefined variable '{variable}' in {field}")]
    UndefinedVariable {
        field: String,
        variable: String,
        available: Vec<String>,  // For "did you mean?" suggestions
    },

    #[error("type error in {field}: expected {expected}, got {actual}")]
    TypeError {
        field: String,
        expected: String,
        actual: String,
    },

    #[error("filter error in {field}: {message}")]
    FilterError {
        field: String,
        filter: String,
        message: String,
    },
}

impl TemplateError {
    pub fn with_field(self, field: &str) -> Self {
        // Update the field path in the error
    }

    pub fn is_retryable(&self) -> bool {
        // Template errors are never retryable - they're config errors
        false
    }
}
```

## Usage Examples

### Service Definition

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: api  # Static - no templating
spec:
  containers:
    - name: api  # Static - no templating
      image: "{{ cluster.registry }}/api:{{ config.version }}"

      env:
        # Simple variable
        LOG_LEVEL: "{{ env.log_level | default('info') }}"

        # Service discovery
        DATABASE_URL: "{{ services.postgres.url }}"
        REDIS_HOST: "{{ services.redis.host }}"
        REDIS_PORT: "{{ services.redis.port }}"

        # Constructed URL
        API_BASE_URL: "https://api.{{ cluster.domain }}"

        # Config values
        MAX_CONNECTIONS: "{{ config.max_connections | default(100) }}"

      args:
        - "--port={{ config.port | default(8080) }}"
        - "--env={{ cluster.environment }}"
        {% if config.debug %}
        - "--debug"
        {% endif %}

      resources:
        cpu: "{{ config.resources.cpu | default('100m') }}"
        memory: "{{ config.resources.memory | default('128Mi') }}"

      files:
        - target: /etc/api/config.yaml
          content: |
            server:
              port: {{ config.port | default(8080) }}
              domain: {{ cluster.domain }}

            database:
              host: {{ services.postgres.host }}
              port: {{ services.postgres.port }}
              name: {{ config.database.name }}

            features:
              {% for feature in config.features %}
              - {{ feature }}
              {% endfor %}
```

### Environment Configuration

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeEnvironment
metadata:
  name: production
spec:
  config:
    log_level: warn
    debug: false
    max_connections: 500
```

### Service Configuration

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeServiceConfig
metadata:
  name: api
spec:
  # Base config (all environments)
  base:
    port: 8080
    database:
      name: api_db
    features:
      - feature_a
      - feature_b

  # Environment overrides
  environments:
    production:
      version: "1.2.3"
      resources:
        cpu: "500m"
        memory: "512Mi"
      max_connections: 1000
      features:
        - feature_a
        - feature_b
        - feature_c  # Production-only feature

    staging:
      version: "1.3.0-rc1"
      resources:
        cpu: "100m"
        memory: "128Mi"
```

## Integration with Controllers

### ServiceController Reconciliation

```rust
async fn reconcile(service: Arc<LatticeService>, ctx: Arc<Context>) -> Result<Action> {
    // 1. Build template context
    let template_ctx = build_context(&service, &ctx).await?;

    // 2. Validate all templates
    let validation = service.validate_templates(&template_ctx);
    if !validation.errors.is_empty() {
        // Update status with validation errors
        update_status_failed(&service, &validation.errors, &ctx).await?;
        // Don't requeue - this is a config error, not transient
        return Ok(Action::await_change());
    }

    // 3. Log warnings (secret refs, service refs)
    for warning in &validation.warnings {
        tracing::warn!(?warning, "template validation warning");
    }

    // 4. Render templates and generate manifests
    let engine = TemplateEngine::new();
    let rendered = service.render(&engine, &template_ctx)?;
    let manifests = generate_k8s_manifests(&rendered)?;

    // 5. Apply manifests
    apply_manifests(&manifests, &ctx).await?;

    Ok(Action::requeue(Duration::from_secs(60)))
}

async fn build_context(
    service: &LatticeService,
    ctx: &Context
) -> Result<TemplateContext> {
    // Fetch cluster info
    let cluster = ctx.kube.get::<LatticeCluster>(&ctx.cluster_name).await?;

    // Fetch environment config
    let env_name = service.spec.environment.as_ref()
        .ok_or(Error::validation("spec.environment is required"))?;
    let environment = ctx.kube.get::<LatticeEnvironment>(env_name).await?;

    // Fetch service config (merged base + env overlay)
    let service_config = ctx.kube.get::<LatticeServiceConfig>(&service.name_any()).await
        .ok()
        .map(|sc| sc.merged_config(env_name))
        .unwrap_or_default();

    // Build service endpoints from graph
    let services = ctx.service_graph
        .get_dependencies(&service.name_any())
        .into_iter()
        .filter_map(|dep| {
            ctx.service_graph.get_endpoint(&dep).map(|ep| (dep, ep))
        })
        .collect();

    Ok(TemplateContext {
        cluster: cluster.into_context(),
        env: environment.spec.config.clone(),
        config: service_config,
        services,
        network: environment.spec.networking.clone().into(),
    })
}
```

## Dependencies

Add to `Cargo.toml`:

```toml
[dependencies]
minijinja = { version = "2", features = ["builtins"] }
```

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_variable() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext {
            cluster: [("name".into(), "prod".into())].into(),
            ..Default::default()
        };

        let result = engine.render_string("cluster: {{ cluster.name }}", &ctx).unwrap();
        assert_eq!(result, "cluster: prod");
    }

    #[test]
    fn test_undefined_variable_strict() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::default();

        let result = engine.render_string("{{ undefined }}", &ctx);
        assert!(matches!(result, Err(TemplateError::UndefinedVariable { .. })));
    }

    #[test]
    fn test_default_filter() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::default();

        let result = engine.render_string(
            "{{ missing | default('fallback') }}",
            &ctx
        ).unwrap();
        assert_eq!(result, "fallback");
    }

    #[test]
    fn test_type_preservation() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext {
            config: [("replicas".into(), Value::from(3))].into(),
            ..Default::default()
        };

        let result = engine.render_value("{{ config.replicas }}", &ctx).unwrap();
        assert_eq!(result.as_i64(), Some(3));
    }

    #[test]
    fn test_static_string_rejects_templates() {
        let result = StaticString::try_from("hello {{ world }}".to_string());
        assert!(result.is_err());

        let result = StaticString::try_from("hello world".to_string());
        assert!(result.is_ok());
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_service_template_validation() {
    let service = LatticeService {
        spec: LatticeServiceSpec {
            containers: vec![ContainerSpec {
                name: "api".into(),
                image: TemplateString("{{ cluster.registry }}/api".into()),
                env: [(
                    "URL".into(),
                    TemplateString("{{ services.db.url }}".into())
                )].into(),
                ..Default::default()
            }],
            ..Default::default()
        },
        ..Default::default()
    };

    let ctx = TemplateContext {
        cluster: [("registry".into(), "gcr.io/project".into())].into(),
        services: [(
            "db".into(),
            ServiceEndpoint {
                host: "db.svc".into(),
                port: 5432,
                url: "postgres://db.svc:5432".into(),
            }
        )].into(),
        ..Default::default()
    };

    let result = service.validate_templates(&ctx);
    assert!(result.errors.is_empty());
}
```

## Migration from Elixir POC

The Elixir POC used `${namespace.path}` syntax. For migration:

1. **No automatic migration** - Require users to update to `{{ }}` syntax
2. **Helpful error messages** - Detect `${}` and suggest the Jinja2 equivalent
3. **Documentation** - Provide migration guide with examples

```rust
impl TemplateEngine {
    pub fn check_legacy_syntax(template: &str) -> Option<String> {
        let legacy_pattern = regex::Regex::new(r"\$\{(\w+)\.([^}]+)\}").unwrap();

        if legacy_pattern.is_match(template) {
            let suggestion = legacy_pattern.replace_all(template, "{{ $1.$2 }}");
            Some(format!(
                "Legacy ${{}} syntax detected. Please update to Jinja2 syntax:\n  {}",
                suggestion
            ))
        } else {
            None
        }
    }
}
```

## Future Considerations

### Template Includes (Not in v1)

```yaml
# Future: include common snippets
files:
  - target: /etc/app/config.yaml
    content: |
      {% include "common/logging.yaml" %}
      app:
        name: {{ service.name }}
```

### Secrets Integration

Templates can reference secrets, but they're not resolved by the template engine:

```yaml
env:
  # This is extracted and converted to ExternalSecret reference
  DB_PASSWORD: "{{ secrets.database.password }}"
```

The template validator extracts these references and creates corresponding `ExternalSecret` resources.

### Custom Functions (Not in v1)

```rust
// Future: register custom template functions
env.add_function("lookup_secret", |path: &str| {
    // Fetch from vault/external secrets manager
});
```
