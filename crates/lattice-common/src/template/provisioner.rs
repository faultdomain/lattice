//! Resource Provisioner Interface
//!
//! Defines how resource dependencies are resolved to template outputs.
//! Each resource type (service, external-service) has a provisioner that
//! knows how to resolve `${resources.NAME.*}` placeholders.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::warn;

use crate::crd::{LatticeServiceSpec, ResourceSpec, ResourceType};
use crate::graph::ServiceGraph;

use super::context::ResourceOutputs;
use super::error::TemplateError;

/// Context provided to provisioners during resolution
pub struct ProvisionerContext<'a> {
    /// The service graph for looking up dependencies
    pub graph: &'a ServiceGraph,
    /// The environment name
    pub environment: &'a str,
    /// The namespace where services are deployed
    pub namespace: &'a str,
    /// Cluster domain suffix (e.g., "cluster.local")
    pub cluster_domain: &'a str,
}

impl<'a> ProvisionerContext<'a> {
    /// Create a new provisioner context
    pub fn new(
        graph: &'a ServiceGraph,
        environment: &'a str,
        namespace: &'a str,
        cluster_domain: &'a str,
    ) -> Self {
        Self {
            graph,
            environment,
            namespace,
            cluster_domain,
        }
    }

    /// Build the FQDN for a service in the current namespace
    pub fn service_fqdn(&self, service_name: &str) -> String {
        format!(
            "{}.{}.svc.{}",
            service_name, self.namespace, self.cluster_domain
        )
    }
}

/// Trait for resolving resource outputs
///
/// Implementations resolve the outputs for a specific resource type,
/// making values like `${resources.postgres.host}` available.
pub trait ResourceProvisioner: Send + Sync {
    /// The resource type this provisioner handles
    fn resource_type(&self) -> ResourceType;

    /// Resolve outputs for a resource
    ///
    /// Given a resource spec and context, returns the outputs that will
    /// be available as `${resources.NAME.*}` in templates.
    fn resolve(
        &self,
        resource_name: &str,
        resource: &ResourceSpec,
        ctx: &ProvisionerContext<'_>,
    ) -> Result<ResourceOutputs, TemplateError>;
}

/// Provisioner for internal services (other LatticeServices)
///
/// Resolves service endpoints from the service graph.
#[derive(Debug, Default)]
pub struct ServiceProvisioner;

impl ResourceProvisioner for ServiceProvisioner {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Service
    }

    fn resolve(
        &self,
        resource_name: &str,
        resource: &ResourceSpec,
        ctx: &ProvisionerContext<'_>,
    ) -> Result<ResourceOutputs, TemplateError> {
        // Use the resource's id if provided, otherwise use the resource name
        let service_name = resource.id.as_deref().unwrap_or(resource_name);

        // Look up the service in the graph
        let node = ctx
            .graph
            .get_service(ctx.environment, service_name)
            .ok_or_else(|| {
                TemplateError::Undefined(format!(
                    "service '{}' not found in environment '{}'",
                    service_name, ctx.environment
                ))
            })?;

        let host = ctx.service_fqdn(service_name);

        // Get the primary port (first one, or "http" if exists)
        let port = node
            .ports
            .get("http")
            .or_else(|| node.ports.values().next())
            .copied();

        let url = port.map(|p| format!("http://{}:{}", host, p));

        // All outputs are non-sensitive for internal services
        Ok(ResourceOutputs::builder()
            .output("host", host)
            .output("port", port.unwrap_or(80).to_string())
            .output("url", url.unwrap_or_default())
            .build())
    }
}

/// Provisioner for external services (LatticeExternalService)
///
/// Resolves endpoints defined in LatticeExternalService CRDs.
#[derive(Debug, Default)]
pub struct ExternalServiceProvisioner;

impl ResourceProvisioner for ExternalServiceProvisioner {
    fn resource_type(&self) -> ResourceType {
        ResourceType::ExternalService
    }

    fn resolve(
        &self,
        resource_name: &str,
        resource: &ResourceSpec,
        ctx: &ProvisionerContext<'_>,
    ) -> Result<ResourceOutputs, TemplateError> {
        // Use the resource's id if provided, otherwise use the resource name
        let service_name = resource.id.as_deref().unwrap_or(resource_name);

        // Look up the external service in the graph
        let node = ctx
            .graph
            .get_service(ctx.environment, service_name)
            .ok_or_else(|| {
                TemplateError::Undefined(format!(
                    "external service '{}' not found in environment '{}'",
                    service_name, ctx.environment
                ))
            })?;

        // Get the primary endpoint (first one, or "default" if exists)
        let endpoint = node
            .endpoints
            .get("default")
            .or_else(|| node.endpoints.values().next())
            .ok_or_else(|| {
                TemplateError::Undefined(format!(
                    "external service '{}' has no endpoints",
                    resource_name
                ))
            })?;

        // All outputs are non-sensitive for external services
        // (if auth is needed, user should use ${secrets.*} namespace)
        Ok(ResourceOutputs::builder()
            .output("host", &endpoint.host)
            .output("port", endpoint.port.to_string())
            .output("url", &endpoint.url)
            .build())
    }
}

/// Registry of resource provisioners
///
/// Maps resource types to their provisioners for resolution.
pub struct ProvisionerRegistry {
    provisioners: HashMap<ResourceType, Arc<dyn ResourceProvisioner>>,
}

impl Default for ProvisionerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProvisionerRegistry {
    /// Create a new registry with built-in provisioners
    pub fn new() -> Self {
        let mut registry = Self {
            provisioners: HashMap::new(),
        };

        // Register built-in provisioners
        registry.register(Arc::new(ServiceProvisioner));
        registry.register(Arc::new(ExternalServiceProvisioner));

        registry
    }

    /// Register a provisioner
    pub fn register(&mut self, provisioner: Arc<dyn ResourceProvisioner>) {
        self.provisioners
            .insert(provisioner.resource_type(), provisioner);
    }

    /// Get the provisioner for a resource type
    pub fn get(&self, type_: &ResourceType) -> Option<&Arc<dyn ResourceProvisioner>> {
        self.provisioners.get(type_)
    }

    /// Resolve all resources from a service spec
    ///
    /// Returns a map of resource name -> outputs for use in template rendering.
    /// Emits a warning for any resource types that don't have a registered provisioner.
    pub fn resolve_all(
        &self,
        spec: &LatticeServiceSpec,
        ctx: &ProvisionerContext<'_>,
    ) -> Result<HashMap<String, ResourceOutputs>, TemplateError> {
        let mut outputs = HashMap::new();

        for (name, resource) in &spec.resources {
            if let Some(provisioner) = self.get(&resource.type_) {
                let resource_outputs = provisioner.resolve(name, resource, ctx)?;
                outputs.insert(name.clone(), resource_outputs);
            } else {
                warn!(
                    resource_name = %name,
                    resource_type = ?resource.type_,
                    "No provisioner registered for resource type; resource outputs will be unavailable"
                );
            }
        }

        Ok(outputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{DependencyDirection, LatticeExternalServiceSpec, ResourceSpec, ResourceType};
    use std::collections::BTreeMap;

    fn make_graph_with_service(env: &str, name: &str, port: u16) -> ServiceGraph {
        let graph = ServiceGraph::new();

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            crate::crd::ContainerSpec {
                image: "nginx:latest".to_string(),
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
            "http".to_string(),
            crate::crd::PortSpec {
                port,
                target_port: None,
                protocol: None,
            },
        );

        let spec = crate::crd::LatticeServiceSpec {
            environment: env.to_string(),
            containers,
            resources: BTreeMap::new(),
            service: Some(crate::crd::ServicePortsSpec { ports }),
            replicas: crate::crd::ReplicaSpec::default(),
            deploy: crate::crd::DeploySpec::default(),
            ingress: None,
        };

        graph.put_service(env, name, &spec);
        graph
    }

    fn make_graph_with_external(env: &str, name: &str, url: &str) -> ServiceGraph {
        let graph = ServiceGraph::new();

        let spec = LatticeExternalServiceSpec {
            environment: env.to_string(),
            endpoints: BTreeMap::from([("default".to_string(), url.to_string())]),
            allowed_requesters: vec!["*".to_string()],
            resolution: crate::crd::Resolution::Dns,
            description: None,
        };

        graph.put_external_service(env, name, &spec);
        graph
    }

    // =========================================================================
    // Story: ServiceProvisioner resolves internal services
    // =========================================================================

    #[test]
    fn test_service_provisioner_resolves_host() {
        let graph = make_graph_with_service("prod", "api", 8080);
        let ctx = ProvisionerContext::new(&graph, "prod", "prod-ns", "cluster.local");

        let provisioner = ServiceProvisioner;
        let resource = ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Outbound,
            id: None,
            class: None,
            metadata: None,
            params: None,
        };

        let outputs = provisioner.resolve("api", &resource, &ctx).unwrap();

        assert_eq!(
            outputs.outputs.get("host"),
            Some(&"api.prod-ns.svc.cluster.local".to_string())
        );
        assert_eq!(outputs.outputs.get("port"), Some(&"8080".to_string()));
        assert!(outputs.outputs.get("url").unwrap().contains("8080"));
        // Service outputs are never sensitive
        assert!(outputs.sensitive.is_empty());
    }

    #[test]
    fn test_service_provisioner_missing_service() {
        let graph = ServiceGraph::new();
        let ctx = ProvisionerContext::new(&graph, "prod", "prod-ns", "cluster.local");

        let provisioner = ServiceProvisioner;
        let resource = ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Outbound,
            id: None,
            class: None,
            metadata: None,
            params: None,
        };

        let result = provisioner.resolve("missing", &resource, &ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    // =========================================================================
    // Story: ExternalServiceProvisioner resolves external services
    // =========================================================================

    #[test]
    fn test_external_provisioner_resolves_endpoint() {
        let graph = make_graph_with_external("prod", "stripe", "https://api.stripe.com");
        let ctx = ProvisionerContext::new(&graph, "prod", "prod-ns", "cluster.local");

        let provisioner = ExternalServiceProvisioner;
        let resource = ResourceSpec {
            type_: ResourceType::ExternalService,
            direction: DependencyDirection::Outbound,
            id: None,
            class: None,
            metadata: None,
            params: None,
        };

        let outputs = provisioner.resolve("stripe", &resource, &ctx).unwrap();

        assert_eq!(
            outputs.outputs.get("host"),
            Some(&"api.stripe.com".to_string())
        );
        assert_eq!(outputs.outputs.get("port"), Some(&"443".to_string()));
        // External service outputs are never sensitive
        assert!(outputs.sensitive.is_empty());
    }

    #[test]
    fn test_external_provisioner_missing_service() {
        let graph = ServiceGraph::new();
        let ctx = ProvisionerContext::new(&graph, "prod", "prod-ns", "cluster.local");

        let provisioner = ExternalServiceProvisioner;
        let resource = ResourceSpec {
            type_: ResourceType::ExternalService,
            direction: DependencyDirection::Outbound,
            id: None,
            class: None,
            metadata: None,
            params: None,
        };

        let result = provisioner.resolve("missing", &resource, &ctx);
        assert!(result.is_err());
    }

    // =========================================================================
    // Story: ProvisionerRegistry manages multiple provisioners
    // =========================================================================

    #[test]
    fn test_registry_has_builtin_provisioners() {
        let registry = ProvisionerRegistry::new();

        assert!(registry.get(&ResourceType::Service).is_some());
        assert!(registry.get(&ResourceType::ExternalService).is_some());
    }

    #[test]
    fn test_registry_resolves_all_resources() {
        let graph = make_graph_with_service("prod", "postgres", 5432);
        let ctx = ProvisionerContext::new(&graph, "prod", "prod-ns", "cluster.local");

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
            },
        );

        // Create a minimal spec with the resources
        let spec = crate::crd::LatticeServiceSpec {
            environment: "prod".to_string(),
            containers: BTreeMap::from([(
                "main".to_string(),
                crate::crd::ContainerSpec {
                    image: "app:latest".to_string(),
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
            )]),
            resources,
            service: None,
            replicas: crate::crd::ReplicaSpec::default(),
            deploy: crate::crd::DeploySpec::default(),
            ingress: None,
        };

        let registry = ProvisionerRegistry::new();
        let outputs = registry.resolve_all(&spec, &ctx).unwrap();

        assert!(outputs.contains_key("db"));
        // The host uses the resource's id ("postgres"), not the resource name ("db")
        assert_eq!(
            outputs["db"].outputs.get("host"),
            Some(&"postgres.prod-ns.svc.cluster.local".to_string())
        );
    }

    // =========================================================================
    // Story: ProvisionerContext builds FQDNs correctly
    // =========================================================================

    #[test]
    fn test_context_builds_fqdn() {
        let graph = ServiceGraph::new();
        let ctx = ProvisionerContext::new(&graph, "prod", "my-namespace", "cluster.local");

        assert_eq!(
            ctx.service_fqdn("api"),
            "api.my-namespace.svc.cluster.local"
        );
    }

    #[test]
    fn test_context_custom_cluster_domain() {
        let graph = ServiceGraph::new();
        let ctx = ProvisionerContext::new(&graph, "prod", "ns", "my-cluster.internal");

        assert_eq!(ctx.service_fqdn("svc"), "svc.ns.svc.my-cluster.internal");
    }
}
