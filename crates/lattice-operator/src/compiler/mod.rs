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
use crate::policy::{AuthorizationPolicy, GeneratedPolicies, PolicyCompiler};
use crate::workload::{GeneratedWorkloads, WorkloadCompiler};

// Re-export types for convenience
pub use crate::policy::{CiliumNetworkPolicy, ServiceEntry};
pub use crate::workload::{Deployment, HorizontalPodAutoscaler, Service, ServiceAccount};

/// Combined output from compiling a LatticeService
#[derive(Clone, Debug, Default)]
pub struct CompiledService {
    /// Generated workload resources (Deployment, Service, ServiceAccount, HPA)
    pub workloads: GeneratedWorkloads,
    /// Generated network policies (AuthorizationPolicy, CiliumNetworkPolicy, ServiceEntry)
    pub policies: GeneratedPolicies,
}

impl CompiledService {
    /// Create empty compiled service
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if any resources were generated
    pub fn is_empty(&self) -> bool {
        self.workloads.is_empty() && self.policies.is_empty()
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

        workload_count + self.policies.total_count()
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
        let policies =
            PolicyCompiler::new(self.graph, &self.trust_domain).compile(name, namespace, env);

        CompiledService {
            workloads,
            policies,
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
        ContainerSpec, DependencyDirection, DeploySpec, PortSpec, ReplicaSpec, ResourceSpec,
        ResourceType, ServicePortsSpec,
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
            },
            status: None,
        }
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

        // Deployment + Service + ServiceAccount + CiliumPolicy = 4
        assert_eq!(output.resource_count(), 4);
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
}
