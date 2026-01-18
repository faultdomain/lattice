//! Template Renderer
//!
//! High-level API for rendering Score templates in LatticeService specs.
//! Integrates the template engine, provisioners, and context building.

use std::collections::{BTreeMap, HashMap};

use crate::crd::{ContainerSpec, FileMount, LatticeService, LatticeServiceSpec, VolumeMount};
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
    /// Rendered file mounts
    pub files: BTreeMap<String, RenderedFile>,
    /// Rendered volume mounts
    pub volumes: BTreeMap<String, RenderedVolume>,
}

/// Rendered file mount
#[derive(Clone, Debug)]
pub struct RenderedFile {
    /// Rendered content (if inline)
    pub content: Option<String>,
    /// Binary content (unchanged)
    pub binary_content: Option<String>,
    /// Rendered source path
    pub source: Option<String>,
    /// File mode
    pub mode: Option<String>,
}

/// Rendered volume mount
#[derive(Clone, Debug)]
pub struct RenderedVolume {
    /// Rendered source reference
    pub source: String,
    /// Sub path
    pub path: Option<String>,
    /// Read only flag
    pub read_only: Option<bool>,
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
        let resources = self.registry.resolve_all(&service.spec, &prov_ctx)?;

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
                    // Check if this field is sensitive
                    if let Some(outputs) = ctx.resources.get(resource_name) {
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

        // Render environment variables with sensitivity tracking
        let mut variables = BTreeMap::new();
        for (k, v) in &container.variables {
            let template_str = v.as_str();
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

    /// Render a file mount
    fn render_file(
        &self,
        file: &FileMount,
        ctx: &TemplateContext,
    ) -> Result<RenderedFile, TemplateError> {
        // Check if expansion is disabled
        let no_expand = file.no_expand.unwrap_or(false);

        let content: Option<String> = if let Some(ref template) = file.content {
            let template: &TemplateString = template;
            if no_expand {
                Some(template.as_str().to_string())
            } else {
                Some(self.engine.render(template.as_str(), ctx)?)
            }
        } else {
            None
        };

        let source: Option<String> = if let Some(ref template) = file.source {
            let template: &TemplateString = template;
            if no_expand {
                Some(template.as_str().to_string())
            } else {
                Some(self.engine.render(template.as_str(), ctx)?)
            }
        } else {
            None
        };

        Ok(RenderedFile {
            content,
            binary_content: file.binary_content.clone(),
            source,
            mode: file.mode.clone(),
        })
    }

    /// Render a volume mount
    fn render_volume(
        &self,
        vol: &VolumeMount,
        ctx: &TemplateContext,
    ) -> Result<RenderedVolume, TemplateError> {
        let source = self.engine.render(vol.source.as_str(), ctx)?;

        Ok(RenderedVolume {
            source,
            path: vol.path.clone(),
            read_only: vol.read_only,
        })
    }

    /// Render all containers in a service spec
    pub fn render_all_containers(
        &self,
        spec: &LatticeServiceSpec,
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
        ContainerSpec, DependencyDirection, LatticeServiceSpec, PortSpec, ReplicaSpec,
        ResourceSpec, ResourceType, ServicePortsSpec,
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
                command: None,
                args: None,
                variables: BTreeMap::new(),
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
                startup_probe: None,
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
            environment: env.to_string(),
            containers,
            resources: BTreeMap::new(),
            service: Some(ServicePortsSpec { ports }),
            replicas: ReplicaSpec::default(),
            deploy: crate::crd::DeploySpec::default(),
            ingress: None,
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
                no_expand: None,
            },
        );

        // Note: volumes are left empty for this test since they reference
        // resources not in the graph. Volume rendering is tested separately.

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "myapp:latest".to_string(),
                command: None,
                args: None,
                variables,
                files,
                volumes: BTreeMap::new(),
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
                startup_probe: None,
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
                outbound: None,
                inbound: None,
            },
        );

        LatticeService {
            metadata: ObjectMeta {
                name: Some("my-api".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                environment: "prod".to_string(),
                containers,
                resources,
                service: None,
                replicas: ReplicaSpec::default(),
                deploy: crate::crd::DeploySpec::default(),
                ingress: None,
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

        let ctx = renderer.build_context(&service, &config).unwrap();
        let rendered = renderer
            .render_container("main", &service.spec.containers["main"], &ctx)
            .unwrap();

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
        assert!(!rendered.variables.get("DB_HOST").unwrap().sensitive);
        assert!(!rendered.variables.get("DB_PORT").unwrap().sensitive);
    }

    #[test]
    fn test_render_file_content() {
        let graph = make_graph_with_db("prod");
        let service = make_service_with_templates();

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "prod", "prod-ns").with_config("log_level", "info"); // Required by the test fixture

        let ctx = renderer.build_context(&service, &config).unwrap();
        let rendered = renderer
            .render_container("main", &service.spec.containers["main"], &ctx)
            .unwrap();

        let file = &rendered.files["/etc/app/config.yaml"];
        let content = file.content.as_ref().unwrap();

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
                no_expand: Some(true), // Disable expansion
            },
        );

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "app:latest".to_string(),
                command: None,
                args: None,
                variables: BTreeMap::new(),
                files,
                volumes: BTreeMap::new(),
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
                startup_probe: None,
            },
        );

        let service = LatticeService {
            metadata: ObjectMeta {
                name: Some("test".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                environment: "test".to_string(),
                containers,
                resources: BTreeMap::new(),
                service: None,
                replicas: ReplicaSpec::default(),
                deploy: crate::crd::DeploySpec::default(),
                ingress: None,
            },
            status: None,
        };

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "test", "test-ns");
        let ctx = renderer.build_context(&service, &config).unwrap();

        let rendered = renderer
            .render_container("main", &service.spec.containers["main"], &ctx)
            .unwrap();

        // Should preserve the ${VAR} literally
        assert_eq!(
            rendered.files["/etc/script.sh"].content,
            Some("echo ${VAR}".to_string())
        );
    }

    #[test]
    fn test_render_all_containers() {
        let graph = make_graph_with_db("prod");
        let service = make_service_with_templates();

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "prod", "prod-ns").with_config("log_level", "info");

        let ctx = renderer.build_context(&service, &config).unwrap();
        let rendered = renderer.render_all_containers(&service.spec, &ctx).unwrap();

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
                command: None,
                args: None,
                variables,
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
                startup_probe: None,
            },
        );

        let service = LatticeService {
            metadata: ObjectMeta {
                name: Some("test".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                environment: "test".to_string(),
                containers,
                resources: BTreeMap::new(),
                service: None,
                replicas: ReplicaSpec::default(),
                deploy: crate::crd::DeploySpec::default(),
                ingress: None,
            },
            status: None,
        };

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "test", "test-ns");
        let ctx = renderer.build_context(&service, &config).unwrap();

        let rendered = renderer
            .render_container("main", &service.spec.containers["main"], &ctx)
            .unwrap();

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
                command: None,
                args: None,
                variables,
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
                startup_probe: None,
            },
        );

        let service = LatticeService {
            metadata: ObjectMeta {
                name: Some("test".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                environment: "prod".to_string(),
                containers,
                resources: BTreeMap::new(),
                service: None,
                replicas: ReplicaSpec::default(),
                deploy: crate::crd::DeploySpec::default(),
                ingress: None,
            },
            status: None,
        };

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "prod", "prod-ns")
            .with_cluster("registry", "gcr.io/myproject")
            .with_env("version", "1.2.3");

        let ctx = renderer.build_context(&service, &config).unwrap();
        let rendered = renderer
            .render_container("main", &service.spec.containers["main"], &ctx)
            .unwrap();

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
            command: None,
            args: None,
            variables,
            files: BTreeMap::new(),
            volumes: BTreeMap::new(),
            resources: None,
            liveness_probe: None,
            readiness_probe: None,
            startup_probe: None,
        };

        let renderer = TemplateRenderer::new();
        let rendered = renderer.render_container("main", &container, &ctx).unwrap();

        // DB_HOST only references non-sensitive field
        assert!(!rendered.variables.get("DB_HOST").unwrap().sensitive);

        // DB_PASSWORD references sensitive field
        assert!(rendered.variables.get("DB_PASSWORD").unwrap().sensitive);

        // DB_URL references sensitive field
        assert!(rendered.variables.get("DB_URL").unwrap().sensitive);

        // MIXED references both - should be marked sensitive
        assert!(rendered.variables.get("MIXED").unwrap().sensitive);
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
                command: None,
                args: None,
                variables: BTreeMap::new(),
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
                startup_probe: None,
            },
        );

        let service = LatticeService {
            metadata: ObjectMeta {
                name: Some("my-app".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                environment: "prod".to_string(),
                containers,
                resources: BTreeMap::new(),
                service: None,
                replicas: ReplicaSpec::default(),
                deploy: crate::crd::DeploySpec::default(),
                ingress: None,
            },
            status: None,
        };

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "prod", "prod-ns")
            .with_config("image", "gcr.io/myproject/my-app:v1.2.3");

        let ctx = renderer.build_context(&service, &config).unwrap();
        let rendered = renderer
            .render_container("main", &service.spec.containers["main"], &ctx)
            .unwrap();

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
                command: None,
                args: None,
                variables: BTreeMap::new(),
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
                startup_probe: None,
            },
        );
        containers.insert(
            "sidecar".to_string(),
            ContainerSpec {
                image: ".".to_string(),
                command: None,
                args: None,
                variables: BTreeMap::new(),
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
                startup_probe: None,
            },
        );

        let service = LatticeService {
            metadata: ObjectMeta {
                name: Some("my-app".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                environment: "prod".to_string(),
                containers,
                resources: BTreeMap::new(),
                service: None,
                replicas: ReplicaSpec::default(),
                deploy: crate::crd::DeploySpec::default(),
                ingress: None,
            },
            status: None,
        };

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "prod", "prod-ns")
            .with_config("image.main", "gcr.io/myproject/main:v1")
            .with_config("image.sidecar", "gcr.io/myproject/sidecar:v2");

        let ctx = renderer.build_context(&service, &config).unwrap();

        let main_rendered = renderer
            .render_container("main", &service.spec.containers["main"], &ctx)
            .unwrap();
        let sidecar_rendered = renderer
            .render_container("sidecar", &service.spec.containers["sidecar"], &ctx)
            .unwrap();

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
                command: None,
                args: None,
                variables: BTreeMap::new(),
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
                startup_probe: None,
            },
        );

        let service = LatticeService {
            metadata: ObjectMeta {
                name: Some("my-app".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                environment: "prod".to_string(),
                containers,
                resources: BTreeMap::new(),
                service: None,
                replicas: ReplicaSpec::default(),
                deploy: crate::crd::DeploySpec::default(),
                ingress: None,
            },
            status: None,
        };

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "prod", "prod-ns"); // No image config!

        let ctx = renderer.build_context(&service, &config).unwrap();
        let result = renderer.render_container("main", &service.spec.containers["main"], &ctx);

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
                command: None,
                args: None,
                variables: BTreeMap::new(),
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
                startup_probe: None,
            },
        );

        let service = LatticeService {
            metadata: ObjectMeta {
                name: Some("my-app".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                environment: "prod".to_string(),
                containers,
                resources: BTreeMap::new(),
                service: None,
                replicas: ReplicaSpec::default(),
                deploy: crate::crd::DeploySpec::default(),
                ingress: None,
            },
            status: None,
        };

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "prod", "prod-ns");

        let ctx = renderer.build_context(&service, &config).unwrap();
        let rendered = renderer
            .render_container("main", &service.spec.containers["main"], &ctx)
            .unwrap();

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
                source: TemplateString::from("${resources.storage.name}"),
                path: Some("subdir".to_string()),
                read_only: Some(true),
            },
        );

        let container = ContainerSpec {
            image: "app:latest".to_string(),
            command: None,
            args: None,
            variables: BTreeMap::new(),
            files: BTreeMap::new(),
            volumes,
            resources: None,
            liveness_probe: None,
            readiness_probe: None,
            startup_probe: None,
        };

        let renderer = TemplateRenderer::new();
        let rendered = renderer.render_container("main", &container, &ctx).unwrap();

        assert_eq!(rendered.volumes["/data"].source, "my-pvc");
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
                source: TemplateString::from("${cluster.name}-${config.storage_class}-cache"),
                path: None,
                read_only: None,
            },
        );

        let container = ContainerSpec {
            image: "app:latest".to_string(),
            command: None,
            args: None,
            variables: BTreeMap::new(),
            files: BTreeMap::new(),
            volumes,
            resources: None,
            liveness_probe: None,
            readiness_probe: None,
            startup_probe: None,
        };

        let renderer = TemplateRenderer::new();
        let rendered = renderer.render_container("main", &container, &ctx).unwrap();

        assert_eq!(
            rendered.volumes["/cache"].source,
            "prod-cluster-fast-ssd-cache"
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
                source: TemplateString::from("shared-logs-pvc"),
                path: Some("app-logs".to_string()),
                read_only: Some(false),
            },
        );

        let container = ContainerSpec {
            image: "app:latest".to_string(),
            command: None,
            args: None,
            variables: BTreeMap::new(),
            files: BTreeMap::new(),
            volumes,
            resources: None,
            liveness_probe: None,
            readiness_probe: None,
            startup_probe: None,
        };

        let renderer = TemplateRenderer::new();
        let rendered = renderer.render_container("main", &container, &ctx).unwrap();

        assert_eq!(rendered.volumes["/logs"].source, "shared-logs-pvc");
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
                source: TemplateString::from("${resources.missing.name}"),
                path: None,
                read_only: None,
            },
        );

        let container = ContainerSpec {
            image: "app:latest".to_string(),
            command: None,
            args: None,
            variables: BTreeMap::new(),
            files: BTreeMap::new(),
            volumes,
            resources: None,
            liveness_probe: None,
            readiness_probe: None,
            startup_probe: None,
        };

        let renderer = TemplateRenderer::new();
        let result = renderer.render_container("main", &container, &ctx);

        assert!(result.is_err());
    }
}
