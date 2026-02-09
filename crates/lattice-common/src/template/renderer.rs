//! Template Renderer
//!
//! High-level API for rendering Score templates in LatticeService specs.
//! Integrates the template engine, provisioners, and context building.

use std::collections::{BTreeMap, HashMap};

use crate::crd::{ContainerSpec, FileMount, LatticeService, VolumeMount, WorkloadSpec};
use crate::graph::ServiceGraph;

use super::context::TemplateContext;
use super::engine::TemplateEngine;
use super::error::TemplateError;
use super::provisioner::{ProvisionerContext, ProvisionerRegistry};
use super::types::TemplateString;

/// Configuration for template rendering
pub struct RenderConfig<'a> {
    /// The service graph for resolving dependencies
    pub graph: &'a ServiceGraph,
    /// Environment name
    pub environment: &'a str,
    /// Namespace where service deploys
    pub namespace: &'a str,
    /// Cluster domain (e.g., "cluster.local")
    pub cluster_domain: &'a str,
    /// Additional cluster context values
    pub cluster_context: BTreeMap<String, String>,
    /// Environment config from LatticeEnvironment
    pub env_config: BTreeMap<String, String>,
    /// Service-specific config
    pub service_config: BTreeMap<String, String>,
}

impl<'a> RenderConfig<'a> {
    /// Create a new render config with defaults
    pub fn new(graph: &'a ServiceGraph, environment: &'a str, namespace: &'a str) -> Self {
        Self {
            graph,
            environment,
            namespace,
            cluster_domain: "cluster.local",
            cluster_context: BTreeMap::new(),
            env_config: BTreeMap::new(),
            service_config: BTreeMap::new(),
        }
    }

    /// Set custom cluster domain
    pub fn with_cluster_domain(mut self, domain: &'a str) -> Self {
        self.cluster_domain = domain;
        self
    }

    /// Add cluster context value
    pub fn with_cluster(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.cluster_context.insert(key.into(), value.into());
        self
    }

    /// Add environment config value
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_config.insert(key.into(), value.into());
        self
    }

    /// Add service config value
    pub fn with_config(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.service_config.insert(key.into(), value.into());
        self
    }
}

/// A rendered variable with sensitivity tracking
#[derive(Clone, Debug, PartialEq)]
pub struct RenderedVariable {
    /// The rendered value
    pub value: String,
    /// Whether this variable contains sensitive data (should go to Secret)
    pub sensitive: bool,
}

impl RenderedVariable {
    /// Create a non-sensitive variable
    pub fn plain(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            sensitive: false,
        }
    }

    /// Create a sensitive variable
    pub fn secret(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            sensitive: true,
        }
    }
}

/// A reference to a secret variable: `${secret.RESOURCE.KEY}`
///
/// Secret variables are not rendered by the template engine — they compile
/// to K8s `secretKeyRef` env vars where the kubelet injects the value at
/// pod startup (ESO syncs the secret from Vault asynchronously).
#[derive(Clone, Debug, PartialEq)]
pub struct SecretVariableRef {
    /// Resource name (must reference a `type: secret` resource)
    pub resource_name: String,
    /// Key within the secret
    pub key: String,
}

/// Parse `${secret.RESOURCE.KEY}` if it is the entire value.
///
/// Returns `None` for non-secret templates (e.g., `${resources.db.host}`).
/// The value must be exactly `${secret.RESOURCE.KEY}` with no surrounding content.
pub fn parse_secret_ref(template: &str) -> Option<SecretVariableRef> {
    let trimmed = template.trim();
    let inner = trimmed.strip_prefix("${secret.")?.strip_suffix('}')?;

    let dot = inner.find('.')?;
    let resource_name = &inner[..dot];
    let key = &inner[dot + 1..];

    if resource_name.is_empty() || key.is_empty() || key.contains('.') {
        return None;
    }

    Some(SecretVariableRef {
        resource_name: resource_name.to_string(),
        key: key.to_string(),
    })
}

/// An env var that contains `${secret.*}` mixed with other content.
///
/// The non-secret parts have been rendered through the template engine.
/// The secret parts are replaced with ESO Go template syntax.
/// This needs to be mounted via an ESO ExternalSecret with `spec.target.template`.
#[derive(Clone, Debug, PartialEq)]
pub struct EsoTemplatedEnvVar {
    /// Rendered content with ESO Go template syntax for secret values
    /// e.g., `"host=postgres.svc,pass={{ .db_creds_password }}"`
    pub rendered_template: String,
    /// Secret references found in the content
    pub secret_refs: Vec<FileSecretRef>,
}

/// Rendered container spec with all templates resolved
#[derive(Clone, Debug)]
pub struct RenderedContainer {
    /// Container name
    pub name: String,
    /// Rendered image
    pub image: String,
    /// Command (unchanged)
    pub command: Option<Vec<String>>,
    /// Args (unchanged)
    pub args: Option<Vec<String>>,
    /// Rendered environment variables with sensitivity tracking
    pub variables: BTreeMap<String, RenderedVariable>,
    /// Pure secret variable references — compile to K8s `secretKeyRef` env vars.
    /// The value is exactly `${secret.RESOURCE.KEY}` with no surrounding content.
    pub secret_variables: BTreeMap<String, SecretVariableRef>,
    /// Env vars containing `${secret.*}` mixed with other content.
    /// These need ESO templating — the non-secret parts are pre-rendered,
    /// and secret parts use Go template syntax.
    pub eso_templated_variables: BTreeMap<String, EsoTemplatedEnvVar>,
    /// Rendered file mounts
    pub files: BTreeMap<String, RenderedFile>,
    /// Rendered volume mounts
    pub volumes: BTreeMap<String, RenderedVolume>,
}

/// A reference to a secret value found in file content: `${secret.RESOURCE.KEY}`
///
/// When file content contains secret references, the file must be rendered via
/// ESO's Go template engine at secret-sync time, not at compile time.
#[derive(Clone, Debug, PartialEq)]
pub struct FileSecretRef {
    /// Resource name (must reference a `type: secret` resource)
    pub resource_name: String,
    /// Key within the secret
    pub key: String,
    /// ESO data key — a Go-template-safe identifier for this secret value.
    /// Used as the key in `spec.data[].secretKey` and referenced in
    /// Go templates as `{{ .eso_data_key }}`.
    pub eso_data_key: String,
}

/// Rendered file mount
#[derive(Clone, Debug)]
pub struct RenderedFile {
    /// Rendered content (if inline)
    ///
    /// When `secret_refs` is non-empty, this content contains ESO Go template
    /// syntax (`{{ .key }}`) for secret values instead of the original
    /// `${secret.*}` placeholders.
    pub content: Option<String>,
    /// Binary content (unchanged)
    pub binary_content: Option<String>,
    /// Rendered source path
    pub source: Option<String>,
    /// File mode
    pub mode: Option<String>,
    /// Secret references found in the content
    ///
    /// If non-empty, this file must be rendered via an ESO ExternalSecret
    /// with `spec.target.template.data` instead of a plain ConfigMap.
    pub secret_refs: Vec<FileSecretRef>,
}

/// Rendered volume mount
#[derive(Clone, Debug)]
pub struct RenderedVolume {
    /// Rendered source reference (None for emptyDir volumes)
    pub source: Option<String>,
    /// Sub path
    pub path: Option<String>,
    /// Read only flag
    pub read_only: Option<bool>,
    /// Storage medium for emptyDir ("Memory" for tmpfs)
    pub medium: Option<String>,
    /// Size limit for emptyDir (e.g., "1Gi")
    pub size_limit: Option<String>,
}

/// Extract `${secret.RESOURCE.KEY}` references from content and replace with ESO Go templates.
///
/// In **normal mode** (`reverse_expand = false`):
///   `${secret.RESOURCE.KEY}` → `{{ .RESOURCE_KEY }}`
///
/// In **reverse mode** (`reverse_expand = true`):
///   `$${secret.RESOURCE.KEY}` → `{{ .RESOURCE_KEY }}`
///   `${secret.RESOURCE.KEY}` stays literal (it's a shell variable)
///
/// Returns the modified content plus a list of `FileSecretRef` entries.
pub fn extract_secret_refs(content: &str, reverse_expand: bool) -> (String, Vec<FileSecretRef>) {
    // In reverse mode, the secret prefix is `$${secret.` (3 extra chars)
    let prefix = if reverse_expand {
        "$${secret."
    } else {
        "${secret."
    };

    let mut result = String::with_capacity(content.len());
    let mut refs = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();
    let mut remaining = content;

    while let Some(start) = remaining.find(prefix) {
        // Copy everything before this match
        result.push_str(&remaining[..start]);

        let after_prefix = &remaining[start + prefix.len()..];
        if let Some(end) = after_prefix.find('}') {
            let inner = &after_prefix[..end];
            if let Some(ref_data) = parse_secret_ref_inner(inner) {
                let (resource, key, eso_data_key) = ref_data;

                if seen_keys.insert(eso_data_key.clone()) {
                    refs.push(FileSecretRef {
                        resource_name: resource,
                        key,
                        eso_data_key: eso_data_key.clone(),
                    });
                }

                result.push_str(&format!("{{{{ .{} }}}}", eso_data_key));
                remaining = &after_prefix[end + 1..];
                continue;
            }
            // Not a valid secret ref, keep as-is
            result.push_str(&remaining[..start + prefix.len() + end + 1]);
            remaining = &after_prefix[end + 1..];
        } else {
            // No closing brace, keep rest as-is (from the match position onward)
            result.push_str(&remaining[start..]);
            remaining = "";
        }
    }

    result.push_str(remaining);
    (result, refs)
}

/// Parse the inner part of a secret ref (`RESOURCE.KEY`) into
/// `(resource_name, key, eso_data_key)` or `None` if invalid.
pub fn parse_secret_ref_inner(inner: &str) -> Option<(String, String, String)> {
    let dot = inner.find('.')?;
    let resource = &inner[..dot];
    let key = &inner[dot + 1..];

    if resource.is_empty() || key.is_empty() || key.contains('.') {
        return None;
    }

    let eso_data_key = format!("{}_{}", resource.replace('-', "_"), key.replace('-', "_"));

    Some((resource.to_string(), key.to_string(), eso_data_key))
}

/// Template renderer for LatticeService specs
pub struct TemplateRenderer {
    engine: TemplateEngine,
    registry: ProvisionerRegistry,
}

impl Default for TemplateRenderer {
    fn default() -> Self {
        Self::new()
    }
}

impl TemplateRenderer {
    /// Create a new template renderer
    pub fn new() -> Self {
        Self {
            engine: TemplateEngine::new(),
            registry: ProvisionerRegistry::new(),
        }
    }

    /// Build template context for a service
    pub fn build_context(
        &self,
        service: &LatticeService,
        config: &RenderConfig<'_>,
    ) -> Result<TemplateContext, TemplateError> {
        let name = service.metadata.name.as_deref().unwrap_or("unknown");

        // Build metadata context (convert BTreeMap to HashMap)
        let annotations: HashMap<String, String> = service
            .metadata
            .annotations
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect();

        // Resolve resource outputs via provisioners
        let prov_ctx = ProvisionerContext::new(
            config.graph,
            config.environment,
            config.namespace,
            config.cluster_domain,
        );
        let resources = self
            .registry
            .resolve_all(&service.spec.workload, &prov_ctx)?;

        // Build the full context
        let mut builder = TemplateContext::builder().metadata(name, annotations);

        // Add resources
        for (name, outputs) in resources {
            builder = builder.resource(name, outputs);
        }

        // Add cluster context
        for (k, v) in &config.cluster_context {
            builder = builder.cluster(k, v);
        }

        // Add env config
        for (k, v) in &config.env_config {
            builder = builder.env(k, v);
        }

        // Add service config
        for (k, v) in &config.service_config {
            builder = builder.config(k, v);
        }

        Ok(builder.build())
    }

    /// Check if a template string references any sensitive fields
    ///
    /// Parses ${resources.NAME.FIELD} patterns and checks if any FIELD
    /// is marked as sensitive in the resource outputs.
    fn is_template_sensitive(&self, template: &str, ctx: &TemplateContext) -> bool {
        // Simple regex-free parsing of ${resources.NAME.FIELD} patterns
        let mut remaining = template;
        while let Some(start) = remaining.find("${resources.") {
            remaining = &remaining[start + 12..]; // Skip "${resources."
                                                  // Find the resource name (up to first .)
            if let Some(dot_pos) = remaining.find('.') {
                let resource_name = &remaining[..dot_pos];
                remaining = &remaining[dot_pos + 1..];
                // Find the field name (up to })
                if let Some(end_pos) = remaining.find('}') {
                    let field = &remaining[..end_pos];
                    // Check if this field is sensitive — try both original and
                    // normalized name since resource keys may contain hyphens
                    let normalized = resource_name.replace('-', "_");
                    let outputs = ctx
                        .resources
                        .get(resource_name)
                        .or_else(|| ctx.resources.get(&normalized));
                    if let Some(outputs) = outputs {
                        if outputs.is_sensitive(field) {
                            return true;
                        }
                    }
                    remaining = &remaining[end_pos + 1..];
                }
            }
        }
        false
    }

    /// Render all templates in a container spec
    pub fn render_container(
        &self,
        name: &str,
        container: &ContainerSpec,
        ctx: &TemplateContext,
    ) -> Result<RenderedContainer, TemplateError> {
        // Resolve image - handle Score's "." placeholder for runtime-supplied images
        let image = self.resolve_image(&container.image, name, ctx)?;

        // Render environment variables with sensitivity tracking.
        //
        // Three cases:
        // 1. Pure `${secret.RESOURCE.KEY}` → secretKeyRef (kubelet injects at pod start)
        // 2. Mixed content with `${secret.*}` → ESO template (rendered at sync time)
        // 3. No secret refs → render normally through template engine
        let mut variables = BTreeMap::new();
        let mut secret_variables = BTreeMap::new();
        let mut eso_templated_variables = BTreeMap::new();
        for (k, v) in &container.variables {
            let template_str = v.as_str();

            // Case 1: Pure ${secret.*} — bypass rendering, use secretKeyRef
            if let Some(secret_ref) = parse_secret_ref(template_str) {
                secret_variables.insert(k.clone(), secret_ref);
                continue;
            }

            // Case 2: Mixed content with ${secret.*} — extract secrets, render
            // non-secret parts, produce ESO Go template content
            if template_str.contains("${secret.") {
                let (preprocessed, refs) = extract_secret_refs(template_str, false);
                let rendered = self.engine.render(&preprocessed, ctx)?;
                eso_templated_variables.insert(
                    k.clone(),
                    EsoTemplatedEnvVar {
                        rendered_template: rendered,
                        secret_refs: refs,
                    },
                );
                continue;
            }

            // Case 3: No secret refs — render normally
            let rendered = self.engine.render(template_str, ctx)?;
            let sensitive = self.is_template_sensitive(template_str, ctx);
            variables.insert(
                k.clone(),
                RenderedVariable {
                    value: rendered,
                    sensitive,
                },
            );
        }

        // Render files
        let mut files = BTreeMap::new();
        for (path, file) in &container.files {
            let rendered = self.render_file(file, ctx)?;
            files.insert(path.clone(), rendered);
        }

        // Render volumes
        let mut volumes = BTreeMap::new();
        for (path, vol) in &container.volumes {
            let rendered = self.render_volume(vol, ctx)?;
            volumes.insert(path.clone(), rendered);
        }

        Ok(RenderedContainer {
            name: name.to_string(),
            image,
            command: container.command.clone(),
            args: container.args.clone(),
            variables,
            secret_variables,
            eso_templated_variables,
            files,
            volumes,
        })
    }

    /// Resolve container image, handling Score's "." placeholder
    ///
    /// Per Score spec, `image: "."` means the image is supplied at runtime.
    /// We resolve this from the config context in the following order:
    /// 1. `config.image.<container_name>` - container-specific image
    /// 2. `config.image` - default image for all containers
    ///
    /// If no image is found and "." was specified, returns an error.
    fn resolve_image(
        &self,
        image: &str,
        container_name: &str,
        ctx: &TemplateContext,
    ) -> Result<String, TemplateError> {
        if image != "." {
            // Not a placeholder, use as-is (no ${} templating per Score spec)
            return Ok(image.to_string());
        }

        // Look for container-specific image first
        let container_key = format!("image.{}", container_name);
        if let Some(img) = ctx.config.get(&container_key) {
            return Ok(img.clone());
        }

        // Fall back to default image
        if let Some(img) = ctx.config.get("image") {
            return Ok(img.clone());
        }

        // No image found
        Err(TemplateError::missing_image(container_name))
    }

    /// Render a file mount, detecting secret references in content
    fn render_file(
        &self,
        file: &FileMount,
        ctx: &TemplateContext,
    ) -> Result<RenderedFile, TemplateError> {
        let no_expand = file.no_expand;
        let reverse_expand = file.reverse_expand;

        let mut secret_refs = Vec::new();

        let content: Option<String> = if let Some(ref template) = file.content {
            let raw = template.as_str();
            if no_expand {
                Some(raw.to_string())
            } else {
                // Extract secret references, replace with ESO Go template
                // syntax, then render remaining templates through the engine.
                //
                // In normal mode: `${secret.*}` is the secret syntax
                // In reverse mode: `$${secret.*}` is the secret syntax
                //   (because `$${...}` means "expand this Lattice template")
                let (preprocessed, refs) = extract_secret_refs(raw, reverse_expand);
                secret_refs = refs;
                let rendered =
                    self.render_file_content(&preprocessed, ctx, false, reverse_expand)?;
                Some(rendered)
            }
        } else {
            None
        };

        let source: Option<String> = if let Some(ref template) = file.source {
            Some(self.render_file_content(template.as_str(), ctx, no_expand, reverse_expand)?)
        } else {
            None
        };

        Ok(RenderedFile {
            content,
            binary_content: file.binary_content.clone(),
            source,
            mode: file.mode.clone(),
            secret_refs,
        })
    }

    /// Render file content with expansion options
    fn render_file_content(
        &self,
        template: &str,
        ctx: &TemplateContext,
        no_expand: bool,
        reverse_expand: bool,
    ) -> Result<String, TemplateError> {
        if no_expand {
            return Ok(template.to_string());
        }

        if reverse_expand {
            // Reverse mode: ${...} stays literal, $${...} expands
            // Swap single and double dollar signs before rendering
            const PLACEHOLDER: &str = "\x00LATTICE_DOLLAR_BRACE\x00";
            let step1 = template.replace("$${", PLACEHOLDER);
            let step2 = step1.replace("${", "$${"); // Escape single so they stay literal
            let step3 = step2.replace(PLACEHOLDER, "${"); // Double becomes single for expansion
            self.engine.render(&step3, ctx)
        } else {
            self.engine.render(template, ctx)
        }
    }

    /// Render a volume mount
    fn render_volume(
        &self,
        vol: &VolumeMount,
        ctx: &TemplateContext,
    ) -> Result<RenderedVolume, TemplateError> {
        let source = match &vol.source {
            Some(s) => Some(self.engine.render(s.as_str(), ctx)?),
            None => None,
        };

        Ok(RenderedVolume {
            source,
            path: vol.path.clone(),
            read_only: vol.read_only,
            medium: vol.medium.clone(),
            size_limit: vol.size_limit.clone(),
        })
    }

    /// Render all containers in a workload spec
    pub fn render_all_containers(
        &self,
        spec: &WorkloadSpec,
        ctx: &TemplateContext,
    ) -> Result<BTreeMap<String, RenderedContainer>, TemplateError> {
        let mut rendered = BTreeMap::new();

        for (name, container) in &spec.containers {
            let rc = self.render_container(name, container, ctx)?;
            rendered.insert(name.clone(), rc);
        }

        Ok(rendered)
    }

    /// Render a single template string
    pub fn render_string(
        &self,
        template: &TemplateString,
        ctx: &TemplateContext,
    ) -> Result<String, TemplateError> {
        self.engine.render(template.as_str(), ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        ContainerSpec, DependencyDirection, LatticeServiceSpec, PortSpec, ResourceSpec,
        ResourceType, ServicePortsSpec, WorkloadSpec,
    };
    use crate::template::TemplateString;
    use kube::api::ObjectMeta;

    fn make_graph_with_db(env: &str) -> ServiceGraph {
        let graph = ServiceGraph::new();

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "postgres:15".to_string(),
                ..Default::default()
            },
        );

        let mut ports = BTreeMap::new();
        ports.insert(
            "postgres".to_string(),
            PortSpec {
                port: 5432,
                target_port: None,
                protocol: None,
            },
        );

        let spec = LatticeServiceSpec {
            workload: WorkloadSpec {
                containers,
                service: Some(ServicePortsSpec { ports }),
                ..Default::default()
            },
            ..Default::default()
        };

        graph.put_service(env, "postgres", &spec);
        graph
    }

    fn make_service_with_templates() -> LatticeService {
        let mut variables = BTreeMap::new();
        variables.insert(
            "DB_HOST".to_string(),
            TemplateString::from("${resources.db.host}"),
        );
        variables.insert(
            "DB_PORT".to_string(),
            TemplateString::from("${resources.db.port}"),
        );
        variables.insert(
            "LOG_LEVEL".to_string(),
            TemplateString::from("${config.log_level}"),
        );

        let mut files = BTreeMap::new();
        files.insert(
            "/etc/app/config.yaml".to_string(),
            FileMount {
                content: Some(TemplateString::from(
                    "database:\n  host: ${resources.db.host}\n  port: ${resources.db.port}",
                )),
                binary_content: None,
                source: None,
                mode: Some("0644".to_string()),
                no_expand: false,
                reverse_expand: false,
            },
        );

        // Note: volumes are left empty for this test since they reference
        // resources not in the graph. Volume rendering is tested separately.

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "myapp:latest".to_string(),
                variables,
                files,
                ..Default::default()
            },
        );

        let mut resources = BTreeMap::new();
        resources.insert(
            "db".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Outbound,
                id: Some("postgres".to_string()),
                class: None,
                metadata: None,
                params: None,
                namespace: None,
                inbound: None,
                outbound: None,
            },
        );

        LatticeService {
            metadata: ObjectMeta {
                name: Some("my-api".to_string()),
                namespace: Some("prod".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                workload: WorkloadSpec {
                    containers,
                    resources,
                    ..Default::default()
                },
                ..Default::default()
            },
            status: None,
        }
    }

    // =========================================================================
    // Story: Full template rendering pipeline
    // =========================================================================

    #[test]
    fn test_render_container_variables() {
        let graph = make_graph_with_db("prod");
        let service = make_service_with_templates();

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "prod", "prod-ns").with_config("log_level", "debug");

        let ctx = renderer
            .build_context(&service, &config)
            .expect("template context should build successfully");
        let rendered = renderer
            .render_container("main", &service.spec.workload.containers["main"], &ctx)
            .expect("container rendering should succeed");

        assert_eq!(
            rendered.variables.get("DB_HOST").map(|v| &v.value),
            Some(&"postgres.prod-ns.svc.cluster.local".to_string())
        );
        assert_eq!(
            rendered.variables.get("DB_PORT").map(|v| &v.value),
            Some(&"5432".to_string())
        );
        assert_eq!(
            rendered.variables.get("LOG_LEVEL").map(|v| &v.value),
            Some(&"debug".to_string())
        );
        // DB_HOST and DB_PORT reference service outputs which are not sensitive
        assert!(
            !rendered
                .variables
                .get("DB_HOST")
                .expect("DB_HOST should exist")
                .sensitive
        );
        assert!(
            !rendered
                .variables
                .get("DB_PORT")
                .expect("DB_PORT should exist")
                .sensitive
        );
    }

    #[test]
    fn test_render_file_content() {
        let graph = make_graph_with_db("prod");
        let service = make_service_with_templates();

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "prod", "prod-ns").with_config("log_level", "info"); // Required by the test fixture

        let ctx = renderer
            .build_context(&service, &config)
            .expect("template context should build successfully");
        let rendered = renderer
            .render_container("main", &service.spec.workload.containers["main"], &ctx)
            .expect("container rendering should succeed");

        let file = &rendered.files["/etc/app/config.yaml"];
        let content = file
            .content
            .as_ref()
            .expect("file content should be present");

        assert!(content.contains("host: postgres.prod-ns.svc.cluster.local"));
        assert!(content.contains("port: 5432"));
    }

    #[test]
    fn test_no_expand_preserves_templates() {
        let graph = ServiceGraph::new();

        let mut files = BTreeMap::new();
        files.insert(
            "/etc/script.sh".to_string(),
            FileMount {
                content: Some(TemplateString::from("echo ${VAR}")),
                binary_content: None,
                source: None,
                mode: None,
                no_expand: true,
                reverse_expand: false,
            },
        );

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "app:latest".to_string(),
                files,
                ..Default::default()
            },
        );

        let service = LatticeService {
            metadata: ObjectMeta {
                name: Some("test".to_string()),
                namespace: Some("test".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                workload: WorkloadSpec {
                    containers,
                    ..Default::default()
                },
                ..Default::default()
            },
            status: None,
        };

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "test", "test-ns");
        let ctx = renderer
            .build_context(&service, &config)
            .expect("template context should build successfully");

        let rendered = renderer
            .render_container("main", &service.spec.workload.containers["main"], &ctx)
            .expect("container rendering should succeed");

        // Should preserve the ${VAR} literally
        assert_eq!(
            rendered.files["/etc/script.sh"].content,
            Some("echo ${VAR}".to_string())
        );
    }

    #[test]
    fn test_reverse_expand_for_bash_scripts() {
        let graph = make_graph_with_db("prod");

        let mut files = BTreeMap::new();
        files.insert(
            "/etc/script.sh".to_string(),
            FileMount {
                // Bash variables stay literal, Lattice templates use $$
                content: Some(TemplateString::from(
                    "#!/bin/bash\nDB_HOST=$${resources.db.host}\necho \"Host: ${DB_HOST}\"",
                )),
                binary_content: None,
                source: None,
                mode: Some("0755".to_string()),
                no_expand: false,
                reverse_expand: true,
            },
        );

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "app:latest".to_string(),
                files,
                ..Default::default()
            },
        );

        let mut resources = BTreeMap::new();
        resources.insert(
            "db".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Outbound,
                id: Some("postgres".to_string()),
                class: None,
                metadata: None,
                params: None,
                namespace: None,
                inbound: None,
                outbound: None,
            },
        );

        let service = LatticeService {
            metadata: ObjectMeta {
                name: Some("test".to_string()),
                namespace: Some("prod".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                workload: WorkloadSpec {
                    containers,
                    resources,
                    ..Default::default()
                },
                ..Default::default()
            },
            status: None,
        };

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "prod", "prod-ns");
        let ctx = renderer
            .build_context(&service, &config)
            .expect("template context should build successfully");

        let rendered = renderer
            .render_container("main", &service.spec.workload.containers["main"], &ctx)
            .expect("container rendering should succeed");

        let content = rendered.files["/etc/script.sh"]
            .content
            .as_ref()
            .expect("file content should be present");

        // $${resources.db.host} should expand to the resolved value
        // ${DB_HOST} should stay literal as a bash variable
        assert!(
            content.contains("DB_HOST=postgres.prod-ns.svc.cluster.local"),
            "Lattice template ($${{...}}) should expand. Got: {}",
            content
        );
        assert!(
            content.contains("echo \"Host: ${DB_HOST}\""),
            "Bash variable (${{...}}) should stay literal. Got: {}",
            content
        );
    }

    #[test]
    fn test_render_all_containers() {
        let graph = make_graph_with_db("prod");
        let service = make_service_with_templates();

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "prod", "prod-ns").with_config("log_level", "info");

        let ctx = renderer
            .build_context(&service, &config)
            .expect("template context should build successfully");
        let rendered = renderer
            .render_all_containers(&service.spec.workload, &ctx)
            .expect("all containers should render successfully");

        assert!(rendered.contains_key("main"));
        assert_eq!(
            rendered["main"]
                .variables
                .get("LOG_LEVEL")
                .map(|v| &v.value),
            Some(&"info".to_string())
        );
    }

    #[test]
    fn test_escaped_placeholders_preserved() {
        let graph = ServiceGraph::new();

        let mut variables = BTreeMap::new();
        variables.insert(
            "SHELL_VAR".to_string(),
            TemplateString::from("$${HOME}/app"), // Escaped
        );

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "app:latest".to_string(),
                variables,
                ..Default::default()
            },
        );

        let service = LatticeService {
            metadata: ObjectMeta {
                name: Some("test".to_string()),
                namespace: Some("test".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                workload: WorkloadSpec {
                    containers,
                    ..Default::default()
                },
                ..Default::default()
            },
            status: None,
        };

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "test", "test-ns");
        let ctx = renderer
            .build_context(&service, &config)
            .expect("template context should build successfully");

        let rendered = renderer
            .render_container("main", &service.spec.workload.containers["main"], &ctx)
            .expect("container rendering should succeed");

        // $${HOME} should become ${HOME}
        assert_eq!(
            rendered.variables.get("SHELL_VAR").map(|v| &v.value),
            Some(&"${HOME}/app".to_string())
        );
    }

    #[test]
    fn test_cluster_and_env_context() {
        let graph = ServiceGraph::new();

        let mut variables = BTreeMap::new();
        variables.insert(
            "IMAGE".to_string(),
            TemplateString::from("${cluster.registry}/app:${env.version}"),
        );

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "placeholder".to_string(),
                variables,
                ..Default::default()
            },
        );

        let service = LatticeService {
            metadata: ObjectMeta {
                name: Some("test".to_string()),
                namespace: Some("prod".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                workload: WorkloadSpec {
                    containers,
                    ..Default::default()
                },
                ..Default::default()
            },
            status: None,
        };

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "prod", "prod-ns")
            .with_cluster("registry", "gcr.io/myproject")
            .with_env("version", "1.2.3");

        let ctx = renderer
            .build_context(&service, &config)
            .expect("template context should build successfully");
        let rendered = renderer
            .render_container("main", &service.spec.workload.containers["main"], &ctx)
            .expect("container rendering should succeed");

        assert_eq!(
            rendered.variables.get("IMAGE").map(|v| &v.value),
            Some(&"gcr.io/myproject/app:1.2.3".to_string())
        );
    }

    #[test]
    fn test_sensitivity_tracking() {
        // Create a context with a resource that has sensitive fields
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .resource(
                "db",
                crate::template::context::ResourceOutputs::builder()
                    .output("host", "db.svc")
                    .output("port", "5432")
                    .sensitive("password", "secret123")
                    .sensitive("connection_string", "postgres://user:secret123@db.svc:5432")
                    .build(),
            )
            .build();

        let mut variables = BTreeMap::new();
        // Non-sensitive: only references host
        variables.insert(
            "DB_HOST".to_string(),
            TemplateString::from("${resources.db.host}"),
        );
        // Sensitive: references password
        variables.insert(
            "DB_PASSWORD".to_string(),
            TemplateString::from("${resources.db.password}"),
        );
        // Sensitive: references connection_string
        variables.insert(
            "DB_URL".to_string(),
            TemplateString::from("${resources.db.connection_string}"),
        );
        // Mixed: references both sensitive and non-sensitive (should be sensitive)
        variables.insert(
            "MIXED".to_string(),
            TemplateString::from("host=${resources.db.host} pass=${resources.db.password}"),
        );

        let container = ContainerSpec {
            image: "app:latest".to_string(),
            variables,
            ..Default::default()
        };

        let renderer = TemplateRenderer::new();
        let rendered = renderer
            .render_container("main", &container, &ctx)
            .expect("container rendering should succeed");

        // DB_HOST only references non-sensitive field
        assert!(
            !rendered
                .variables
                .get("DB_HOST")
                .expect("DB_HOST should exist")
                .sensitive
        );

        // DB_PASSWORD references sensitive field
        assert!(
            rendered
                .variables
                .get("DB_PASSWORD")
                .expect("DB_PASSWORD should exist")
                .sensitive
        );

        // DB_URL references sensitive field
        assert!(
            rendered
                .variables
                .get("DB_URL")
                .expect("DB_URL should exist")
                .sensitive
        );

        // MIXED references both - should be marked sensitive
        assert!(
            rendered
                .variables
                .get("MIXED")
                .expect("MIXED should exist")
                .sensitive
        );
    }

    // =========================================================================
    // Story: Image "." placeholder resolution
    // =========================================================================

    #[test]
    fn test_image_dot_resolved_from_config() {
        let graph = ServiceGraph::new();

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: ".".to_string(), // Score placeholder
                ..Default::default()
            },
        );

        let service = LatticeService {
            metadata: ObjectMeta {
                name: Some("my-app".to_string()),
                namespace: Some("prod".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                workload: WorkloadSpec {
                    containers,
                    ..Default::default()
                },
                ..Default::default()
            },
            status: None,
        };

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "prod", "prod-ns")
            .with_config("image", "gcr.io/myproject/my-app:v1.2.3");

        let ctx = renderer
            .build_context(&service, &config)
            .expect("template context should build successfully");
        let rendered = renderer
            .render_container("main", &service.spec.workload.containers["main"], &ctx)
            .expect("container rendering should succeed");

        assert_eq!(rendered.image, "gcr.io/myproject/my-app:v1.2.3");
    }

    #[test]
    fn test_image_dot_resolved_from_container_specific_config() {
        let graph = ServiceGraph::new();

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: ".".to_string(),
                ..Default::default()
            },
        );
        containers.insert(
            "sidecar".to_string(),
            ContainerSpec {
                image: ".".to_string(),
                ..Default::default()
            },
        );

        let service = LatticeService {
            metadata: ObjectMeta {
                name: Some("my-app".to_string()),
                namespace: Some("prod".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                workload: WorkloadSpec {
                    containers,
                    ..Default::default()
                },
                ..Default::default()
            },
            status: None,
        };

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "prod", "prod-ns")
            .with_config("image.main", "gcr.io/myproject/main:v1")
            .with_config("image.sidecar", "gcr.io/myproject/sidecar:v2");

        let ctx = renderer
            .build_context(&service, &config)
            .expect("template context should build successfully");

        let main_rendered = renderer
            .render_container("main", &service.spec.workload.containers["main"], &ctx)
            .expect("main container rendering should succeed");
        let sidecar_rendered = renderer
            .render_container(
                "sidecar",
                &service.spec.workload.containers["sidecar"],
                &ctx,
            )
            .expect("sidecar container rendering should succeed");

        assert_eq!(main_rendered.image, "gcr.io/myproject/main:v1");
        assert_eq!(sidecar_rendered.image, "gcr.io/myproject/sidecar:v2");
    }

    #[test]
    fn test_image_dot_without_config_errors() {
        let graph = ServiceGraph::new();

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: ".".to_string(),
                ..Default::default()
            },
        );

        let service = LatticeService {
            metadata: ObjectMeta {
                name: Some("my-app".to_string()),
                namespace: Some("prod".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                workload: WorkloadSpec {
                    containers,
                    ..Default::default()
                },
                ..Default::default()
            },
            status: None,
        };

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "prod", "prod-ns"); // No image config!

        let ctx = renderer
            .build_context(&service, &config)
            .expect("template context should build successfully");
        let result =
            renderer.render_container("main", &service.spec.workload.containers["main"], &ctx);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("main"));
        assert!(err.to_string().contains("image"));
    }

    #[test]
    fn test_regular_image_not_affected() {
        let graph = ServiceGraph::new();

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "nginx:latest".to_string(), // Normal image
                ..Default::default()
            },
        );

        let service = LatticeService {
            metadata: ObjectMeta {
                name: Some("my-app".to_string()),
                namespace: Some("prod".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                workload: WorkloadSpec {
                    containers,
                    ..Default::default()
                },
                ..Default::default()
            },
            status: None,
        };

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "prod", "prod-ns");

        let ctx = renderer
            .build_context(&service, &config)
            .expect("template context should build successfully");
        let rendered = renderer
            .render_container("main", &service.spec.workload.containers["main"], &ctx)
            .expect("container rendering should succeed");

        assert_eq!(rendered.image, "nginx:latest");
    }

    // =========================================================================
    // Story: Volume rendering with templates
    // =========================================================================

    #[test]
    fn test_render_volume_with_template() {
        let ctx = TemplateContext::builder()
            .metadata("api", std::collections::HashMap::new())
            .resource(
                "storage",
                crate::template::context::ResourceOutputs::builder()
                    .output("name", "my-pvc")
                    .output("path", "/data/app")
                    .build(),
            )
            .build();

        let mut volumes = BTreeMap::new();
        volumes.insert(
            "/data".to_string(),
            VolumeMount {
                source: Some(TemplateString::from("${resources.storage.name}")),
                path: Some("subdir".to_string()),
                read_only: Some(true),
                medium: None,
                size_limit: None,
            },
        );

        let container = ContainerSpec {
            image: "app:latest".to_string(),
            volumes,
            ..Default::default()
        };

        let renderer = TemplateRenderer::new();
        let rendered = renderer
            .render_container("main", &container, &ctx)
            .expect("container rendering should succeed");

        assert_eq!(rendered.volumes["/data"].source, Some("my-pvc".to_string()));
        assert_eq!(rendered.volumes["/data"].path, Some("subdir".to_string()));
        assert_eq!(rendered.volumes["/data"].read_only, Some(true));
    }

    #[test]
    fn test_render_volume_with_complex_template() {
        let ctx = TemplateContext::builder()
            .metadata("api", std::collections::HashMap::new())
            .config("storage_class", "fast-ssd")
            .cluster("name", "prod-cluster")
            .build();

        let mut volumes = BTreeMap::new();
        volumes.insert(
            "/cache".to_string(),
            VolumeMount {
                source: Some(TemplateString::from(
                    "${cluster.name}-${config.storage_class}-cache",
                )),
                path: None,
                read_only: None,
                medium: None,
                size_limit: None,
            },
        );

        let container = ContainerSpec {
            image: "app:latest".to_string(),
            volumes,
            ..Default::default()
        };

        let renderer = TemplateRenderer::new();
        let rendered = renderer
            .render_container("main", &container, &ctx)
            .expect("container rendering should succeed");

        assert_eq!(
            rendered.volumes["/cache"].source,
            Some("prod-cluster-fast-ssd-cache".to_string())
        );
    }

    #[test]
    fn test_render_volume_static_source() {
        let ctx = TemplateContext::builder()
            .metadata("api", std::collections::HashMap::new())
            .build();

        let mut volumes = BTreeMap::new();
        volumes.insert(
            "/logs".to_string(),
            VolumeMount {
                source: Some(TemplateString::from("shared-logs-pvc")),
                path: Some("app-logs".to_string()),
                read_only: Some(false),
                medium: None,
                size_limit: None,
            },
        );

        let container = ContainerSpec {
            image: "app:latest".to_string(),
            volumes,
            ..Default::default()
        };

        let renderer = TemplateRenderer::new();
        let rendered = renderer
            .render_container("main", &container, &ctx)
            .expect("container rendering should succeed");

        assert_eq!(
            rendered.volumes["/logs"].source,
            Some("shared-logs-pvc".to_string())
        );
    }

    #[test]
    fn test_render_volume_undefined_variable_errors() {
        let ctx = TemplateContext::builder()
            .metadata("api", std::collections::HashMap::new())
            .build();

        let mut volumes = BTreeMap::new();
        volumes.insert(
            "/data".to_string(),
            VolumeMount {
                source: Some(TemplateString::from("${resources.missing.name}")),
                path: None,
                read_only: None,
                medium: None,
                size_limit: None,
            },
        );

        let container = ContainerSpec {
            image: "app:latest".to_string(),
            volumes,
            ..Default::default()
        };

        let renderer = TemplateRenderer::new();
        let result = renderer.render_container("main", &container, &ctx);

        assert!(result.is_err());
    }

    #[test]
    fn test_render_volume_sourceless_emptydir() {
        let ctx = TemplateContext::builder()
            .metadata("api", std::collections::HashMap::new())
            .build();

        let mut volumes = BTreeMap::new();
        volumes.insert(
            "/tmp".to_string(),
            VolumeMount {
                source: None,
                path: None,
                read_only: None,
                medium: None,
                size_limit: None,
            },
        );
        volumes.insert(
            "/dev/shm".to_string(),
            VolumeMount {
                source: None,
                path: None,
                read_only: None,
                medium: Some("Memory".to_string()),
                size_limit: Some("256Mi".to_string()),
            },
        );

        let container = ContainerSpec {
            image: "nginx:latest".to_string(),
            volumes,
            ..Default::default()
        };

        let renderer = TemplateRenderer::new();
        let rendered = renderer
            .render_container("main", &container, &ctx)
            .expect("sourceless volumes should render successfully");

        // Source should be None for emptyDir volumes
        assert!(rendered.volumes["/tmp"].source.is_none());
        assert!(rendered.volumes["/dev/shm"].source.is_none());

        // medium/size_limit should pass through
        assert_eq!(
            rendered.volumes["/dev/shm"].medium,
            Some("Memory".to_string())
        );
        assert_eq!(
            rendered.volumes["/dev/shm"].size_limit,
            Some("256Mi".to_string())
        );
    }

    // =========================================================================
    // Story: parse_secret_ref
    // =========================================================================

    #[test]
    fn test_parse_secret_ref_valid() {
        let result = parse_secret_ref("${secret.db-creds.password}");
        assert_eq!(
            result,
            Some(SecretVariableRef {
                resource_name: "db-creds".to_string(),
                key: "password".to_string(),
            })
        );
    }

    #[test]
    fn test_parse_secret_ref_with_whitespace() {
        let result = parse_secret_ref("  ${secret.db-creds.password}  ");
        assert!(result.is_some());
        assert_eq!(result.unwrap().resource_name, "db-creds");
    }

    #[test]
    fn test_parse_secret_ref_non_secret() {
        assert!(parse_secret_ref("${resources.db.host}").is_none());
        assert!(parse_secret_ref("plain-value").is_none());
        assert!(parse_secret_ref("${config.key}").is_none());
    }

    #[test]
    fn test_parse_secret_ref_rejects_nested_dots() {
        // Only RESOURCE.KEY is allowed, not RESOURCE.NESTED.KEY
        assert!(parse_secret_ref("${secret.db.nested.key}").is_none());
    }

    #[test]
    fn test_parse_secret_ref_rejects_empty_parts() {
        assert!(parse_secret_ref("${secret..key}").is_none());
        assert!(parse_secret_ref("${secret.db.}").is_none());
    }

    // =========================================================================
    // Story: Renderer intercepts ${secret.*} variables
    // =========================================================================

    #[test]
    fn test_render_container_separates_secret_variables() {
        let ctx = TemplateContext::builder()
            .metadata("api", std::collections::HashMap::new())
            .config("log_level", "debug")
            .build();

        let mut variables = BTreeMap::new();
        variables.insert(
            "LOG_LEVEL".to_string(),
            TemplateString::from("${config.log_level}"),
        );
        variables.insert(
            "DB_PASSWORD".to_string(),
            TemplateString::from("${secret.db-creds.password}"),
        );

        let container = ContainerSpec {
            image: "app:latest".to_string(),
            variables,
            ..Default::default()
        };

        let renderer = TemplateRenderer::new();
        let rendered = renderer
            .render_container("main", &container, &ctx)
            .expect("should render");

        // LOG_LEVEL should be in regular variables (rendered)
        assert_eq!(
            rendered.variables.get("LOG_LEVEL").map(|v| &v.value),
            Some(&"debug".to_string())
        );
        assert!(!rendered.variables.contains_key("DB_PASSWORD"));

        // DB_PASSWORD should be in secret_variables (not rendered)
        let secret_var = rendered
            .secret_variables
            .get("DB_PASSWORD")
            .expect("should have secret var");
        assert_eq!(secret_var.resource_name, "db-creds");
        assert_eq!(secret_var.key, "password");
    }

    #[test]
    fn test_render_container_mixed_secret_ref_becomes_eso_template() {
        let ctx = TemplateContext::builder()
            .metadata("api", std::collections::HashMap::new())
            .config("prefix", "myprefix")
            .build();

        let mut variables = BTreeMap::new();
        variables.insert(
            "CONN_STRING".to_string(),
            TemplateString::from("host=${config.prefix},pass=${secret.db.pass}"),
        );

        let container = ContainerSpec {
            image: "app:latest".to_string(),
            variables,
            ..Default::default()
        };

        let renderer = TemplateRenderer::new();
        let rendered = renderer
            .render_container("main", &container, &ctx)
            .expect("should render");

        // Should NOT be in regular variables or pure secret_variables
        assert!(!rendered.variables.contains_key("CONN_STRING"));
        assert!(!rendered.secret_variables.contains_key("CONN_STRING"));

        // Should be in eso_templated_variables
        let eso_var = rendered
            .eso_templated_variables
            .get("CONN_STRING")
            .expect("should have ESO templated var");

        // Non-secret parts should be rendered
        assert!(eso_var.rendered_template.contains("host=myprefix"));
        // Secret parts should be Go template syntax
        assert!(eso_var.rendered_template.contains("{{ .db_pass }}"));

        // Should track the secret ref
        assert_eq!(eso_var.secret_refs.len(), 1);
        assert_eq!(eso_var.secret_refs[0].resource_name, "db");
        assert_eq!(eso_var.secret_refs[0].key, "pass");
    }

    // =========================================================================
    // Story: File secret reference detection
    // =========================================================================

    #[test]
    fn test_extract_secret_refs_from_content() {
        let content =
            "database:\n  host: ${resources.db.host}\n  password: ${secret.db-creds.password}";
        let (result, refs) = extract_secret_refs(content, false);

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].resource_name, "db-creds");
        assert_eq!(refs[0].key, "password");
        assert_eq!(refs[0].eso_data_key, "db_creds_password");

        // The ${secret.*} should be replaced with Go template syntax
        assert!(result.contains("{{ .db_creds_password }}"));
        // The ${resources.*} should be left alone for engine rendering
        assert!(result.contains("${resources.db.host}"));
    }

    #[test]
    fn test_extract_secret_refs_multiple() {
        let content = "user=${secret.db.username} pass=${secret.db.password}";
        let (result, refs) = extract_secret_refs(content, false);

        assert_eq!(refs.len(), 2);
        assert!(result.contains("{{ .db_username }}"));
        assert!(result.contains("{{ .db_password }}"));
    }

    #[test]
    fn test_extract_secret_refs_deduplicates() {
        let content = "${secret.db.pass} and again ${secret.db.pass}";
        let (result, refs) = extract_secret_refs(content, false);

        // Should only have one ref even though the pattern appears twice
        assert_eq!(refs.len(), 1);
        // Both occurrences should be replaced
        assert_eq!(result.matches("{{ .db_pass }}").count(), 2);
    }

    #[test]
    fn test_extract_secret_refs_no_secrets() {
        let content = "just ${resources.db.host} and ${config.key}";
        let (result, refs) = extract_secret_refs(content, false);

        assert!(refs.is_empty());
        assert_eq!(result, content);
    }

    #[test]
    fn test_extract_secret_refs_at_start_of_content() {
        let content = "${secret.db.pass} is the password";
        let (result, refs) = extract_secret_refs(content, false);

        assert_eq!(refs.len(), 1);
        assert_eq!(result, "{{ .db_pass }} is the password");
    }

    #[test]
    fn test_extract_secret_refs_at_end_of_content() {
        let content = "password: ${secret.db.pass}";
        let (result, refs) = extract_secret_refs(content, false);

        assert_eq!(refs.len(), 1);
        assert_eq!(result, "password: {{ .db_pass }}");
    }

    #[test]
    fn test_extract_secret_refs_entire_content() {
        let content = "${secret.db.pass}";
        let (result, refs) = extract_secret_refs(content, false);

        assert_eq!(refs.len(), 1);
        assert_eq!(result, "{{ .db_pass }}");
    }

    #[test]
    fn test_extract_secret_refs_adjacent() {
        let content = "${secret.db.user}${secret.db.pass}";
        let (result, refs) = extract_secret_refs(content, false);

        assert_eq!(refs.len(), 2);
        assert_eq!(result, "{{ .db_user }}{{ .db_pass }}");
    }

    #[test]
    fn test_extract_secret_refs_hyphenated_resource_name() {
        let content = "${secret.my-db-creds.password}";
        let (result, refs) = extract_secret_refs(content, false);

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].resource_name, "my-db-creds");
        assert_eq!(refs[0].key, "password");
        assert_eq!(refs[0].eso_data_key, "my_db_creds_password");
        assert_eq!(result, "{{ .my_db_creds_password }}");
    }

    #[test]
    fn test_extract_secret_refs_ignores_nested_dots() {
        // ${secret.db.nested.key} has too many dots — not a valid secret ref
        let content = "${secret.db.nested.key}";
        let (result, refs) = extract_secret_refs(content, false);

        // Should not be parsed (key contains a dot)
        assert!(refs.is_empty());
        assert_eq!(result, content);
    }

    #[test]
    fn test_extract_secret_refs_empty_parts() {
        // ${secret..key} is invalid
        let content = "${secret..key}";
        let (result, refs) = extract_secret_refs(content, false);

        assert!(refs.is_empty());
        assert_eq!(result, content);
    }

    #[test]
    fn test_extract_secret_refs_no_closing_brace() {
        let content = "before ${secret.db.pass and after";
        let (result, refs) = extract_secret_refs(content, false);

        assert!(refs.is_empty());
        assert_eq!(result, content);
    }

    #[test]
    fn test_extract_secret_refs_mixed_with_other_templates() {
        let content = "host=${resources.db.host} port=${resources.db.port} pass=${secret.creds.pw}";
        let (result, refs) = extract_secret_refs(content, false);

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].resource_name, "creds");
        assert_eq!(refs[0].key, "pw");
        // Non-secret templates preserved for minijinja
        assert!(result.contains("${resources.db.host}"));
        assert!(result.contains("${resources.db.port}"));
        assert!(result.contains("{{ .creds_pw }}"));
    }

    #[test]
    fn test_extract_secret_refs_multiline() {
        let content =
            "database:\n  host: ${resources.db.host}\n  password: ${secret.db.pass}\n  port: 5432";
        let (result, refs) = extract_secret_refs(content, false);

        assert_eq!(refs.len(), 1);
        assert!(result.contains("host: ${resources.db.host}"));
        assert!(result.contains("password: {{ .db_pass }}"));
        assert!(result.contains("port: 5432"));
    }

    #[test]
    fn test_extract_secret_refs_from_different_resources() {
        let content = "${secret.db.pass} and ${secret.api.key}";
        let (result, refs) = extract_secret_refs(content, false);

        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].resource_name, "db");
        assert_eq!(refs[0].key, "pass");
        assert_eq!(refs[1].resource_name, "api");
        assert_eq!(refs[1].key, "key");
        assert_eq!(result, "{{ .db_pass }} and {{ .api_key }}");
    }

    #[test]
    fn test_extract_secret_refs_empty_content() {
        let (result, refs) = extract_secret_refs("", false);
        assert!(refs.is_empty());
        assert_eq!(result, "");
    }

    #[test]
    fn test_extract_secret_refs_plain_text() {
        let content = "just plain text without any templates";
        let (result, refs) = extract_secret_refs(content, false);
        assert!(refs.is_empty());
        assert_eq!(result, content);
    }

    // =========================================================================
    // Story: reverse_expand mode secret ref extraction
    // =========================================================================

    #[test]
    fn test_extract_secret_refs_reverse_mode_double_dollar() {
        // In reverse mode, $${secret.*} is the Lattice template syntax
        let content = "pass=$${secret.db.password}";
        let (result, refs) = extract_secret_refs(content, true);

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].resource_name, "db");
        assert_eq!(refs[0].key, "password");
        assert_eq!(result, "pass={{ .db_password }}");
    }

    #[test]
    fn test_extract_secret_refs_reverse_mode_single_dollar_stays_literal() {
        // In reverse mode, ${secret.*} should stay literal (bash variable)
        let content = "pass=${secret.db.password}";
        let (result, refs) = extract_secret_refs(content, true);

        assert!(refs.is_empty());
        assert_eq!(result, content);
    }

    #[test]
    fn test_extract_secret_refs_reverse_mode_mixed() {
        // Mix of reverse-mode Lattice templates and bash variables
        let content = "DB_PASS=$${secret.db.password}\nSHELL_VAR=${SOME_BASH_VAR}";
        let (result, refs) = extract_secret_refs(content, true);

        assert_eq!(refs.len(), 1);
        // $${secret.*} replaced with Go template
        assert!(result.contains("DB_PASS={{ .db_password }}"));
        // ${SOME_BASH_VAR} stays literal
        assert!(result.contains("SHELL_VAR=${SOME_BASH_VAR}"));
    }

    #[test]
    fn test_render_file_with_secret_refs() {
        let graph = make_graph_with_db("prod");

        let mut files = BTreeMap::new();
        files.insert(
            "/etc/app/config.yaml".to_string(),
            FileMount {
                content: Some(TemplateString::from(
                    "database:\n  host: ${resources.db.host}\n  password: ${secret.db-creds.password}",
                )),
                binary_content: None,
                source: None,
                mode: Some("0644".to_string()),
                no_expand: false,
                reverse_expand: false,
            },
        );

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "myapp:latest".to_string(),
                files,
                ..Default::default()
            },
        );

        let mut resources = BTreeMap::new();
        resources.insert(
            "db".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Outbound,
                id: Some("postgres".to_string()),
                class: None,
                metadata: None,
                params: None,
                namespace: None,
                inbound: None,
                outbound: None,
            },
        );

        let service = LatticeService {
            metadata: ObjectMeta {
                name: Some("my-api".to_string()),
                namespace: Some("prod".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                workload: WorkloadSpec {
                    containers,
                    resources,
                    ..Default::default()
                },
                ..Default::default()
            },
            status: None,
        };

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "prod", "prod-ns");
        let ctx = renderer.build_context(&service, &config).unwrap();
        let rendered = renderer
            .render_container("main", &service.spec.workload.containers["main"], &ctx)
            .unwrap();

        let file = &rendered.files["/etc/app/config.yaml"];
        let content = file.content.as_ref().unwrap();

        // Non-secret templates should be resolved
        assert!(content.contains("host: postgres.prod-ns.svc.cluster.local"));
        // Secret templates should become ESO Go template syntax
        assert!(content.contains("password: {{ .db_creds_password }}"));

        // Should have secret refs
        assert_eq!(file.secret_refs.len(), 1);
        assert_eq!(file.secret_refs[0].resource_name, "db-creds");
        assert_eq!(file.secret_refs[0].key, "password");
    }
}
