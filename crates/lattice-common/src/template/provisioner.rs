//! Resource Provisioner Interface
//!
//! Defines how resource dependencies are resolved to template outputs.
//! Each resource type (service, external-service, volume) has a provisioner that
//! knows how to resolve `${resources.NAME.*}` placeholders.
//!
//! ## Extensibility
//!
//! The provisioner system supports both built-in types (Service, ExternalService, Volume)
//! and custom resource types. Provisioners match resources using a `matches()` method
//! that can consider type, class, and id for flexible routing.
//!
//! ## Registry Priority
//!
//! The registry uses a "last match wins" strategy. Built-in provisioners are registered
//! first, so custom provisioners registered later can override built-in behavior.

use std::sync::Arc;

use tracing::warn;

use crate::crd::{LatticeServiceSpec, ResourceSpec, ResourceType};
use crate::graph::ServiceGraph;

use super::context::ResourceOutputs;
use super::error::TemplateError;
pub use super::output::ProvisionOutput;

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

/// Trait for resolving and provisioning resources
///
/// Implementations resolve the outputs for a specific resource type,
/// making values like `${resources.postgres.host}` available.
///
/// ## Matching
///
/// The `matches()` method determines which resources this provisioner handles.
/// It receives the resource type, class, and id to enable fine-grained routing:
/// - Built-in provisioners typically match by type only
/// - Custom provisioners can match by class (e.g., "aws-rds") or id (e.g., specific instance)
pub trait ResourceProvisioner: Send + Sync {
    /// URI identifying this provisioner (e.g., "builtin://service", "custom://postgres")
    fn uri(&self) -> &str;

    /// Check if this provisioner handles the given resource
    ///
    /// Takes ResourceType for type-safe matching of built-ins.
    /// Class and id enable fine-grained routing for custom provisioners.
    fn matches(&self, type_: &ResourceType, class: Option<&str>, id: Option<&str>) -> bool;

    /// Supported params for validation/documentation
    fn supported_params(&self) -> &[&str] {
        &[]
    }

    /// Expected outputs for validation/documentation
    fn expected_outputs(&self) -> &[&str] {
        &[]
    }

    /// Resolve outputs for a resource (template substitution)
    ///
    /// Given a resource spec and context, returns the outputs that will
    /// be available as `${resources.NAME.*}` in templates.
    fn resolve(
        &self,
        resource_name: &str,
        resource: &ResourceSpec,
        ctx: &ProvisionerContext<'_>,
    ) -> Result<ResourceOutputs, TemplateError>;

    /// Generate K8s manifests (PVCs, Secrets, etc.)
    ///
    /// Default implementation returns empty output.
    fn provision(
        &self,
        _resource_name: &str,
        _resource: &ResourceSpec,
        _ctx: &ProvisionerContext<'_>,
    ) -> Result<ProvisionOutput, TemplateError> {
        Ok(ProvisionOutput::default())
    }
}

/// Provisioner for internal services (other LatticeServices)
///
/// Resolves service endpoints from the service graph.
#[derive(Debug, Default)]
pub struct ServiceProvisioner;

impl ResourceProvisioner for ServiceProvisioner {
    fn uri(&self) -> &str {
        "builtin://service"
    }

    fn matches(&self, type_: &ResourceType, _class: Option<&str>, _id: Option<&str>) -> bool {
        matches!(type_, ResourceType::Service)
    }

    fn expected_outputs(&self) -> &[&str] {
        &["host", "port", "url"]
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
    fn uri(&self) -> &str {
        "builtin://external-service"
    }

    fn matches(&self, type_: &ResourceType, _class: Option<&str>, _id: Option<&str>) -> bool {
        matches!(type_, ResourceType::ExternalService)
    }

    fn expected_outputs(&self) -> &[&str] {
        &["host", "port", "url"]
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

/// Provisioner for persistent volumes
///
/// Resolves volume claim names for Score-compatible volume resources.
/// PVC generation and affinity rules are handled by VolumeCompiler.
#[derive(Debug, Default)]
pub struct VolumeProvisioner;

impl ResourceProvisioner for VolumeProvisioner {
    fn uri(&self) -> &str {
        "builtin://volume"
    }

    fn matches(&self, type_: &ResourceType, _class: Option<&str>, _id: Option<&str>) -> bool {
        matches!(type_, ResourceType::Volume)
    }

    fn supported_params(&self) -> &[&str] {
        &["size", "storageClass", "accessMode"]
    }

    fn expected_outputs(&self) -> &[&str] {
        &["claim_name"]
    }

    fn resolve(
        &self,
        resource_name: &str,
        resource: &ResourceSpec,
        ctx: &ProvisionerContext<'_>,
    ) -> Result<ResourceOutputs, TemplateError> {
        // Use the service name from context if available, otherwise use resource name
        // The actual PVC name is computed based on whether there's an id
        let service_name = ctx.namespace; // Use namespace as service name fallback
        let claim_name = resource
            .volume_pvc_name(service_name, resource_name)
            .unwrap_or_else(|| format!("{}-{}", service_name, resource_name));

        Ok(ResourceOutputs::builder()
            .output("claim_name", claim_name)
            .build())
    }
}

/// Registry of resource provisioners
///
/// Uses an ordered list with "last match wins" semantics. Built-in provisioners
/// are registered first (lowest priority), allowing custom provisioners to override.
pub struct ProvisionerRegistry {
    /// Ordered list of provisioners (later registrations have higher priority)
    provisioners: Vec<Arc<dyn ResourceProvisioner>>,
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
            provisioners: Vec::new(),
        };

        // Register built-in provisioners (lowest priority - registered first)
        registry.register(Arc::new(ServiceProvisioner));
        registry.register(Arc::new(ExternalServiceProvisioner));
        registry.register(Arc::new(VolumeProvisioner));

        registry
    }

    /// Register a provisioner (later registrations have higher priority)
    pub fn register(&mut self, provisioner: Arc<dyn ResourceProvisioner>) {
        self.provisioners.push(provisioner);
    }

    /// Find matching provisioner (iterates from end, last match wins)
    pub fn find(
        &self,
        type_: &ResourceType,
        class: Option<&str>,
        id: Option<&str>,
    ) -> Option<&Arc<dyn ResourceProvisioner>> {
        self.provisioners
            .iter()
            .rev()
            .find(|p| p.matches(type_, class, id))
    }

    /// Get the provisioner for a resource type (convenience method)
    ///
    /// Uses the resource's type, class, and id to find a matching provisioner.
    pub fn get_for_resource(
        &self,
        resource: &ResourceSpec,
    ) -> Option<&Arc<dyn ResourceProvisioner>> {
        self.find(
            &resource.type_,
            resource.class.as_deref(),
            resource.id.as_deref(),
        )
    }

    /// Resolve all resources from a service spec
    ///
    /// Returns a map of resource name -> outputs for use in template rendering.
    /// Emits a warning for any resource types that don't have a registered provisioner.
    pub fn resolve_all(
        &self,
        spec: &LatticeServiceSpec,
        ctx: &ProvisionerContext<'_>,
    ) -> Result<std::collections::HashMap<String, ResourceOutputs>, TemplateError> {
        let mut outputs = std::collections::HashMap::new();

        for (name, resource) in &spec.resources {
            if let Some(provisioner) = self.get_for_resource(resource) {
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

    /// Provision all resources from a service spec
    ///
    /// Returns a combined ProvisionOutput with all manifests and outputs.
    pub fn provision_all(
        &self,
        spec: &LatticeServiceSpec,
        ctx: &ProvisionerContext<'_>,
    ) -> Result<ProvisionOutput, TemplateError> {
        let mut combined = ProvisionOutput::default();

        for (name, resource) in &spec.resources {
            if let Some(provisioner) = self.get_for_resource(resource) {
                let output = provisioner.provision(name, resource, ctx)?;
                combined.merge(output);
            }
        }

        Ok(combined)
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
                security: None,
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
            containers,
            resources: BTreeMap::new(),
            service: Some(crate::crd::ServicePortsSpec { ports }),
            replicas: crate::crd::ReplicaSpec::default(),
            deploy: crate::crd::DeploySpec::default(),
            ingress: None,
            sidecars: BTreeMap::new(),
            sysctls: BTreeMap::new(),
            host_network: None,
            share_process_namespace: None,
            authorization: None,
        };

        graph.put_service(env, name, &spec);
        graph
    }

    fn make_graph_with_external(env: &str, name: &str, url: &str) -> ServiceGraph {
        let graph = ServiceGraph::new();

        let spec = LatticeExternalServiceSpec {
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
            namespace: None,
            inbound: None,
            outbound: None,
        };

        let outputs = provisioner
            .resolve("api", &resource, &ctx)
            .expect("service resolution should succeed");

        assert_eq!(
            outputs.outputs.get("host"),
            Some(&"api.prod-ns.svc.cluster.local".to_string())
        );
        assert_eq!(outputs.outputs.get("port"), Some(&"8080".to_string()));
        assert!(outputs
            .outputs
            .get("url")
            .expect("url output should exist")
            .contains("8080"));
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
            namespace: None,
            inbound: None,
            outbound: None,
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
            namespace: None,
            inbound: None,
            outbound: None,
        };

        let outputs = provisioner
            .resolve("stripe", &resource, &ctx)
            .expect("external service resolution should succeed");

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
            namespace: None,
            inbound: None,
            outbound: None,
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

        // Find by type
        assert!(registry.find(&ResourceType::Service, None, None).is_some());
        assert!(registry
            .find(&ResourceType::ExternalService, None, None)
            .is_some());
        assert!(registry.find(&ResourceType::Volume, None, None).is_some());
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
                namespace: None,
                inbound: None,
                outbound: None,
            },
        );

        // Create a minimal spec with the resources
        let spec = crate::crd::LatticeServiceSpec {
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
                    security: None,
                },
            )]),
            resources,
            service: None,
            replicas: crate::crd::ReplicaSpec::default(),
            deploy: crate::crd::DeploySpec::default(),
            ingress: None,
            sidecars: BTreeMap::new(),
            sysctls: BTreeMap::new(),
            host_network: None,
            share_process_namespace: None,
            authorization: None,
        };

        let registry = ProvisionerRegistry::new();
        let outputs = registry
            .resolve_all(&spec, &ctx)
            .expect("registry resolution should succeed");

        assert!(outputs.contains_key("db"));
        // The host uses the resource's id ("postgres"), not the resource name ("db")
        assert_eq!(
            outputs["db"].outputs.get("host"),
            Some(&"postgres.prod-ns.svc.cluster.local".to_string())
        );
    }

    #[test]
    fn test_provisioner_type_safe_matching() {
        let registry = ProvisionerRegistry::new();

        // Built-in matches by enum variant (type-safe)
        let p = registry.find(&ResourceType::Service, None, None);
        assert!(p.is_some());
        assert_eq!(p.unwrap().uri(), "builtin://service");

        let p = registry.find(&ResourceType::ExternalService, None, None);
        assert!(p.is_some());
        assert_eq!(p.unwrap().uri(), "builtin://external-service");

        // Custom type has no default provisioner
        let p = registry.find(&ResourceType::Custom("postgres".to_string()), None, None);
        assert!(p.is_none());
    }

    #[test]
    fn test_provisioner_uri_and_outputs() {
        let service_prov = ServiceProvisioner;
        assert_eq!(service_prov.uri(), "builtin://service");
        assert_eq!(service_prov.expected_outputs(), &["host", "port", "url"]);

        let ext_prov = ExternalServiceProvisioner;
        assert_eq!(ext_prov.uri(), "builtin://external-service");
        assert_eq!(ext_prov.expected_outputs(), &["host", "port", "url"]);

        let vol_prov = VolumeProvisioner;
        assert_eq!(vol_prov.uri(), "builtin://volume");
        assert_eq!(vol_prov.expected_outputs(), &["claim_name"]);
        assert_eq!(
            vol_prov.supported_params(),
            &["size", "storageClass", "accessMode"]
        );
    }

    // =========================================================================
    // Story: VolumeProvisioner resolves claim names
    // =========================================================================

    #[test]
    fn test_volume_provisioner_resolves_claim_name() {
        let graph = ServiceGraph::new();
        let ctx = ProvisionerContext::new(&graph, "prod", "myapp", "cluster.local");

        let provisioner = VolumeProvisioner;
        let resource = ResourceSpec {
            type_: ResourceType::Volume,
            direction: DependencyDirection::default(),
            id: None,
            class: None,
            metadata: None,
            params: Some(BTreeMap::from([(
                "size".to_string(),
                serde_json::json!("10Gi"),
            )])),
            namespace: None,
            inbound: None,
            outbound: None,
        };

        let outputs = provisioner
            .resolve("config", &resource, &ctx)
            .expect("volume resolution should succeed");

        // Without id, claim name is service-resource format
        assert_eq!(
            outputs.outputs.get("claim_name"),
            Some(&"myapp-config".to_string())
        );
    }

    #[test]
    fn test_volume_provisioner_resolves_claim_name_with_id() {
        let graph = ServiceGraph::new();
        let ctx = ProvisionerContext::new(&graph, "prod", "myapp", "cluster.local");

        let provisioner = VolumeProvisioner;
        let resource = ResourceSpec {
            type_: ResourceType::Volume,
            direction: DependencyDirection::default(),
            id: Some("media-library".to_string()),
            class: None,
            metadata: None,
            params: Some(BTreeMap::from([(
                "size".to_string(),
                serde_json::json!("1Ti"),
            )])),
            namespace: None,
            inbound: None,
            outbound: None,
        };

        let outputs = provisioner
            .resolve("media", &resource, &ctx)
            .expect("volume resolution should succeed");

        // With id, claim name uses vol- prefix
        assert_eq!(
            outputs.outputs.get("claim_name"),
            Some(&"vol-media-library".to_string())
        );
    }

    #[test]
    fn test_volume_provisioner_matches() {
        let provisioner = VolumeProvisioner;

        // Should match Volume type
        assert!(provisioner.matches(&ResourceType::Volume, None, None));

        // Should not match Service type
        assert!(!provisioner.matches(&ResourceType::Service, None, None));

        // Should not match custom type
        assert!(!provisioner.matches(&ResourceType::Custom("postgres".to_string()), None, None));
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
