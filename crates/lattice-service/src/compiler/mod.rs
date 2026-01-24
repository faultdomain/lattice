//! Service Compiler for Lattice
//!
//! This module provides a unified API for compiling LatticeService resources into
//! Kubernetes manifests - both workload resources (Deployment, Service, etc.) and
//! network policies (AuthorizationPolicy, CiliumNetworkPolicy).
//!
//! # Architecture
//!
//! The ServiceCompiler delegates to specialized compilers:
//! - [`WorkloadCompiler`](crate::workload::WorkloadCompiler): Generates Deployment, Service, ServiceAccount, HPA
//! - [`PolicyCompiler`](crate::policy::PolicyCompiler): Generates AuthorizationPolicy, CiliumNetworkPolicy, ServiceEntry
//!
//! # Usage
//!
//! ```text
//! let graph = ServiceGraph::new();
//! let compiler = ServiceCompiler::new(&graph, "prod.lattice.local");
//! let output = compiler.compile(&lattice_service);
//! // output.workloads, output.policies
//! ```
//!
//! # Environment Resolution
//!
//! The compiler determines the environment from the LatticeService in this order:
//! 1. Label `lattice.dev/environment` on the service
//! 2. Falls back to namespace

use crate::crd::LatticeService;
use crate::graph::ServiceGraph;
use crate::ingress::{GeneratedIngress, GeneratedWaypoint, IngressCompiler, WaypointCompiler};
use crate::policy::{AuthorizationPolicy, GeneratedPolicies, PolicyCompiler};
use crate::workload::{GeneratedWorkloads, WorkloadCompiler};

// Re-export types for convenience
pub use crate::ingress::{Certificate, Gateway, HttpRoute};
pub use crate::policy::{CiliumNetworkPolicy, ServiceEntry};
pub use crate::workload::{Deployment, HorizontalPodAutoscaler, Service, ServiceAccount};

/// Combined output from compiling a LatticeService
#[derive(Clone, Debug, Default)]
pub struct CompiledService {
    /// Generated workload resources (Deployment, Service, ServiceAccount, HPA)
    pub workloads: GeneratedWorkloads,
    /// Generated network policies (AuthorizationPolicy, CiliumNetworkPolicy, ServiceEntry)
    pub policies: GeneratedPolicies,
    /// Generated ingress resources (Gateway, HTTPRoute, Certificate)
    pub ingress: GeneratedIngress,
    /// Generated waypoint Gateway for east-west L7 policy enforcement
    pub waypoint: GeneratedWaypoint,
}

impl CompiledService {
    /// Create empty compiled service
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if any resources were generated
    pub fn is_empty(&self) -> bool {
        self.workloads.is_empty()
            && self.policies.is_empty()
            && self.ingress.is_empty()
            && self.waypoint.is_empty()
    }

    /// Total count of all generated resources
    pub fn resource_count(&self) -> usize {
        let workload_count = [
            self.workloads.deployment.is_some(),
            self.workloads.service.is_some(),
            self.workloads.service_account.is_some(),
            self.workloads.hpa.is_some(),
        ]
        .iter()
        .filter(|&&x| x)
        .count();

        workload_count
            + self.policies.total_count()
            + self.ingress.total_count()
            + self.waypoint.total_count()
    }
}

/// Unified service compiler that generates both workload and policy resources
///
/// This compiler orchestrates the generation of all Kubernetes resources for a
/// LatticeService by delegating to specialized compilers:
/// - WorkloadCompiler for Deployment, Service, ServiceAccount, HPA
/// - PolicyCompiler for AuthorizationPolicy, CiliumNetworkPolicy, ServiceEntry
pub struct ServiceCompiler<'a> {
    graph: &'a ServiceGraph,
    trust_domain: String,
}

impl<'a> ServiceCompiler<'a> {
    /// Create a new service compiler
    ///
    /// # Arguments
    /// * `graph` - The service graph for policy generation (bilateral agreement checks)
    /// * `trust_domain` - SPIFFE trust domain (e.g., "prod.lattice.local")
    pub fn new(graph: &'a ServiceGraph, trust_domain: impl Into<String>) -> Self {
        Self {
            graph,
            trust_domain: trust_domain.into(),
        }
    }

    /// Compile a LatticeService into Kubernetes resources
    ///
    /// Generates:
    /// - Workloads: Deployment, Service, ServiceAccount, HPA
    /// - Policies: AuthorizationPolicy, CiliumNetworkPolicy, ServiceEntry
    /// - Ingress: Gateway, HTTPRoute, Certificate (if ingress configured)
    /// - Waypoint: Istio ambient mesh L7 policy enforcement
    ///
    /// The environment (and namespace) comes from `spec.environment`, since
    /// LatticeService is cluster-scoped.
    pub fn compile(&self, service: &LatticeService) -> CompiledService {
        let name = service.metadata.name.as_deref().unwrap_or("unknown");
        // Environment is in spec, determines namespace for workloads
        let env = &service.spec.environment;
        let namespace = env; // Environment determines namespace

        // Delegate to specialized compilers
        let workloads = WorkloadCompiler::compile(service, namespace);
        let policy_compiler = PolicyCompiler::new(self.graph, &self.trust_domain);
        let mut policies = policy_compiler.compile(name, namespace, env);

        // Compile waypoint Gateway for east-west L7 policies (Istio ambient mesh)
        let waypoint = WaypointCompiler::compile(namespace);

        // Get primary service port for ingress routing
        let service_port = service
            .spec
            .service
            .as_ref()
            .and_then(|s| s.ports.values().next())
            .map(|p| p.port)
            .unwrap_or(80);

        // Compile ingress resources if configured
        let ingress = if let Some(ref ingress_spec) = service.spec.ingress {
            let ingress = IngressCompiler::compile(name, namespace, ingress_spec, service_port);

            // Add gateway allow policy for north-south traffic
            let ports: Vec<u16> = service
                .spec
                .service
                .as_ref()
                .map(|s| s.ports.values().map(|p| p.port).collect())
                .unwrap_or_default();

            let gateway_policy =
                policy_compiler.compile_gateway_allow_policy(name, namespace, &ports);
            policies.authorization_policies.push(gateway_policy);

            ingress
        } else {
            GeneratedIngress::new()
        };

        CompiledService {
            workloads,
            policies,
            ingress,
            waypoint,
        }
    }

    /// Compile the mesh-wide default-deny AuthorizationPolicy
    ///
    /// This should be applied once per cluster in istio-system namespace.
    pub fn compile_mesh_default_deny(&self) -> AuthorizationPolicy {
        PolicyCompiler::compile_mesh_default_deny()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        CertIssuerRef, ContainerSpec, DependencyDirection, DeploySpec, IngressSpec, IngressTls,
        PortSpec, ReplicaSpec, ResourceSpec, ResourceType, ServicePortsSpec, TlsMode,
    };
    use std::collections::BTreeMap;

    fn make_service(name: &str, env: &str) -> LatticeService {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
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
            PortSpec {
                port: 80,
                target_port: None,
                protocol: None,
            },
        );

        LatticeService {
            metadata: kube::api::ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: crate::crd::LatticeServiceSpec {
                environment: env.to_string(),
                containers,
                resources: BTreeMap::new(),
                service: Some(ServicePortsSpec { ports }),
                replicas: ReplicaSpec { min: 1, max: None },
                deploy: DeploySpec::default(),
                ingress: None,
            },
            status: None,
        }
    }

    fn make_service_with_ingress(name: &str, env: &str) -> LatticeService {
        let mut service = make_service(name, env);
        service.spec.ingress = Some(IngressSpec {
            hosts: vec!["api.example.com".to_string()],
            paths: None,
            tls: Some(IngressTls {
                mode: TlsMode::Auto,
                secret_name: None,
                issuer_ref: Some(CertIssuerRef {
                    name: "letsencrypt-prod".to_string(),
                    kind: None,
                }),
            }),
            rate_limit: None,
            gateway_class: None,
        });
        service
    }

    fn make_service_spec_for_graph(
        env: &str,
        deps: Vec<&str>,
        callers: Vec<&str>,
    ) -> crate::crd::LatticeServiceSpec {
        let mut resources = BTreeMap::new();
        for dep in deps {
            resources.insert(
                dep.to_string(),
                ResourceSpec {
                    type_: ResourceType::Service,
                    direction: DependencyDirection::Outbound,
                    id: None,
                    class: None,
                    metadata: None,
                    params: None,
                    inbound: None,
                    outbound: None,
                },
            );
        }
        for caller in callers {
            resources.insert(
                caller.to_string(),
                ResourceSpec {
                    type_: ResourceType::Service,
                    direction: DependencyDirection::Inbound,
                    id: None,
                    class: None,
                    metadata: None,
                    params: None,
                    inbound: None,
                    outbound: None,
                },
            );
        }

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
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
            PortSpec {
                port: 8080,
                target_port: None,
                protocol: None,
            },
        );

        crate::crd::LatticeServiceSpec {
            environment: env.to_string(),
            containers,
            resources,
            service: Some(ServicePortsSpec { ports }),
            replicas: ReplicaSpec::default(),
            deploy: DeploySpec::default(),
            ingress: None,
        }
    }

    // =========================================================================
    // Story: Unified Compilation Delegates to Specialized Compilers
    // =========================================================================

    #[test]
    fn story_compile_delegates_to_both_compilers() {
        let graph = ServiceGraph::new();
        let env = "prod";

        // api allows gateway
        let api_spec = make_service_spec_for_graph("prod", vec![], vec!["gateway"]);
        graph.put_service(env, "api", &api_spec);

        // gateway calls api
        let gateway_spec = make_service_spec_for_graph("prod", vec!["api"], vec![]);
        graph.put_service(env, "gateway", &gateway_spec);

        // Create LatticeService for api
        let service = make_service("api", "prod");

        let compiler = ServiceCompiler::new(&graph, "prod.lattice.local");
        let output = compiler.compile(&service);

        // Should have workloads (from WorkloadCompiler)
        assert!(output.workloads.deployment.is_some());
        assert!(output.workloads.service.is_some());
        assert!(output.workloads.service_account.is_some());

        // Should have policies (from PolicyCompiler)
        assert!(!output.policies.authorization_policies.is_empty());
        assert!(!output.policies.cilium_policies.is_empty());
    }

    // =========================================================================
    // Story: Environment Resolution
    // =========================================================================

    #[test]
    fn story_environment_from_label() {
        let graph = ServiceGraph::new();

        // Put service in "staging" environment
        let spec = make_service_spec_for_graph("default", vec![], vec![]);
        graph.put_service("staging", "my-app", &spec);

        // Create LatticeService with staging label
        let service = make_service("my-app", "staging");

        let compiler = ServiceCompiler::new(&graph, "test.lattice.local");
        let output = compiler.compile(&service);

        // Should find service in graph and generate cilium policy
        assert!(!output.policies.cilium_policies.is_empty());
    }

    #[test]
    fn story_environment_falls_back_to_namespace() {
        let graph = ServiceGraph::new();

        // Put service in "prod-ns" environment (same as namespace)
        let spec = make_service_spec_for_graph("default", vec![], vec![]);
        graph.put_service("prod-ns", "my-app", &spec);

        // Create LatticeService without env label
        let service = make_service("my-app", "prod-ns");

        let compiler = ServiceCompiler::new(&graph, "test.lattice.local");
        let output = compiler.compile(&service);

        // Should find service using namespace as env
        assert!(!output.policies.cilium_policies.is_empty());
    }

    // =========================================================================
    // Story: Workloads Generated Even Without Graph Entry
    // =========================================================================

    #[test]
    fn story_workloads_without_graph_entry() {
        let graph = ServiceGraph::new();
        // Don't add service to graph

        let service = make_service("my-app", "default");

        let compiler = ServiceCompiler::new(&graph, "test.lattice.local");
        let output = compiler.compile(&service);

        // Should still have workloads
        assert!(output.workloads.deployment.is_some());
        assert!(output.workloads.service_account.is_some());

        // But no policies (not in graph)
        assert!(output.policies.is_empty());
    }

    // =========================================================================
    // Story: Resource Count
    // =========================================================================

    #[test]
    fn story_resource_count() {
        let graph = ServiceGraph::new();
        let spec = make_service_spec_for_graph("default", vec![], vec![]);
        graph.put_service("default", "my-app", &spec);

        let service = make_service("my-app", "default");

        let compiler = ServiceCompiler::new(&graph, "test.lattice.local");
        let output = compiler.compile(&service);

        // Deployment + Service + ServiceAccount + CiliumPolicy + WaypointGateway + WaypointAuthPolicy = 6
        // (VirtualService is generated per dependency, not per service)
        assert_eq!(output.resource_count(), 6);
    }

    // =========================================================================
    // Story: Mesh Default Deny
    // =========================================================================

    #[test]
    fn story_mesh_default_deny() {
        let graph = ServiceGraph::new();
        let compiler = ServiceCompiler::new(&graph, "test.lattice.local");

        let policy = compiler.compile_mesh_default_deny();

        assert_eq!(policy.metadata.name, "mesh-default-deny");
        assert_eq!(policy.metadata.namespace, "istio-system");
    }

    // =========================================================================
    // Story: CompiledService Utility Methods
    // =========================================================================

    #[test]
    fn story_compiled_service_is_empty() {
        let empty = CompiledService::new();
        assert!(empty.is_empty());

        let graph = ServiceGraph::new();
        let service = make_service("my-app", "default");

        let compiler = ServiceCompiler::new(&graph, "test.lattice.local");
        let output = compiler.compile(&service);
        assert!(!output.is_empty());
    }

    // =========================================================================
    // Story: Ingress Integration
    // =========================================================================

    #[test]
    fn story_service_with_ingress_generates_gateway_resources() {
        let graph = ServiceGraph::new();
        let spec = make_service_spec_for_graph("prod", vec![], vec![]);
        graph.put_service("prod", "api", &spec);

        let service = make_service_with_ingress("api", "prod");

        let compiler = ServiceCompiler::new(&graph, "prod.lattice.local");
        let output = compiler.compile(&service);

        // Should have ingress resources
        assert!(output.ingress.gateway.is_some());
        assert!(output.ingress.http_route.is_some());
        assert!(output.ingress.certificate.is_some());

        let gateway = output
            .ingress
            .gateway
            .expect("gateway should be generated for ingress");
        assert_eq!(gateway.metadata.name, "api-gateway");
        assert_eq!(gateway.metadata.namespace, "prod");

        let route = output
            .ingress
            .http_route
            .expect("http route should be generated for ingress");
        assert_eq!(route.metadata.name, "api-route");

        // Should have gateway allow policy
        let gateway_policies: Vec<_> = output
            .policies
            .authorization_policies
            .iter()
            .filter(|p| p.metadata.name.starts_with("allow-gateway-to-"))
            .collect();
        assert_eq!(gateway_policies.len(), 1);
    }

    #[test]
    fn story_service_without_ingress_has_no_gateway_resources() {
        let graph = ServiceGraph::new();
        let spec = make_service_spec_for_graph("prod", vec![], vec![]);
        graph.put_service("prod", "api", &spec);

        let service = make_service("api", "prod");

        let compiler = ServiceCompiler::new(&graph, "prod.lattice.local");
        let output = compiler.compile(&service);

        // Should NOT have ingress resources
        assert!(output.ingress.is_empty());
        assert!(output.ingress.gateway.is_none());
        assert!(output.ingress.http_route.is_none());
        assert!(output.ingress.certificate.is_none());
    }

    #[test]
    fn story_resource_count_includes_ingress() {
        let graph = ServiceGraph::new();
        let spec = make_service_spec_for_graph("prod", vec![], vec![]);
        graph.put_service("prod", "api", &spec);

        let service = make_service_with_ingress("api", "prod");

        let compiler = ServiceCompiler::new(&graph, "prod.lattice.local");
        let output = compiler.compile(&service);

        // Should include: Deployment + Service + ServiceAccount + CiliumPolicy +
        //                 Gateway + HTTPRoute + Certificate + GatewayAllowPolicy
        // = 3 workloads + 2 policies + 3 ingress = at least 8
        assert!(output.resource_count() >= 6);
    }
}
