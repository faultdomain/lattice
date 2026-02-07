//! Service Compiler for Lattice
//!
//! This module provides a unified API for compiling LatticeService resources into
//! Kubernetes manifests - both workload resources (Deployment, Service, etc.) and
//! network policies (AuthorizationPolicy, CiliumNetworkPolicy).
//!
//! # Architecture
//!
//! The ServiceCompiler delegates to specialized compilers:
//! - [`WorkloadCompiler`](crate::workload::WorkloadCompiler): Generates Deployment, Service, ServiceAccount, ScaledObject
//! - [`PolicyCompiler`](crate::policy::PolicyCompiler): Generates AuthorizationPolicy, CiliumNetworkPolicy, ServiceEntry
//!
//! # Usage
//!
//! ```text
//! let graph = ServiceGraph::new();
//! let cedar = PolicyEngine::new();
//! let compiler = ServiceCompiler::new(&graph, "prod-cluster", ProviderType::Docker, &cedar, true);
//! let output = compiler.compile(&lattice_service).await;
//! // output.workloads, output.policies
//! ```
//!
//! # Environment Resolution
//!
//! The compiler determines the environment from the LatticeService in this order:
//! 1. Label `lattice.dev/environment` on the service
//! 2. Falls back to namespace

use lattice_cedar::{PolicyEngine, SecretAuthzRequest};

use lattice_common::mesh;

use crate::crd::{LatticeService, ProviderType};
use crate::graph::ServiceGraph;
use crate::ingress::{GeneratedIngress, GeneratedWaypoint, IngressCompiler, WaypointCompiler};
use crate::policy::{GeneratedPolicies, PolicyCompiler};
use crate::workload::{GeneratedWorkloads, SecretsCompiler, VolumeCompiler, WorkloadCompiler};

/// Errors that can occur during service compilation
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    /// LatticeService is missing required metadata
    #[error("LatticeService missing {field}")]
    MissingMetadata { field: &'static str },
    /// Invalid volume resource configuration
    #[error("invalid volume config: {0}")]
    InvalidVolume(String),
    /// Invalid secret resource configuration
    #[error("invalid secret config: {0}")]
    InvalidSecret(String),
    /// Cedar policy denied secret access
    #[error("secret access denied: {0}")]
    SecretAccessDenied(String),
    /// Workload compilation failed (e.g. monitoring required for custom metrics)
    #[error("workload compilation error: {0}")]
    WorkloadCompilation(String),
}

impl From<CompileError> for crate::Error {
    fn from(err: CompileError) -> Self {
        crate::Error::validation(err.to_string())
    }
}

/// Combined output from compiling a LatticeService
#[derive(Clone, Debug, Default)]
pub struct CompiledService {
    /// Generated workload resources (Deployment, Service, ServiceAccount, ScaledObject)
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
            self.workloads.scaled_object.is_some(),
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
/// - WorkloadCompiler for Deployment, Service, ServiceAccount, ScaledObject
/// - PolicyCompiler for AuthorizationPolicy, CiliumNetworkPolicy, ServiceEntry
/// - Cedar PolicyEngine for secret access authorization
pub struct ServiceCompiler<'a> {
    graph: &'a ServiceGraph,
    cluster_name: String,
    provider_type: ProviderType,
    cedar: &'a PolicyEngine,
    monitoring_enabled: bool,
}

impl<'a> ServiceCompiler<'a> {
    /// Create a new service compiler
    ///
    /// # Arguments
    /// * `graph` - The service graph for policy generation (bilateral agreement checks)
    /// * `cluster_name` - Cluster name used in trust domain (lattice.{cluster}.local)
    /// * `provider_type` - Infrastructure provider for topology-aware scheduling
    /// * `cedar` - Cedar policy engine for secret access authorization
    /// * `monitoring_enabled` - Whether the cluster has monitoring (VictoriaMetrics) enabled
    pub fn new(
        graph: &'a ServiceGraph,
        cluster_name: impl Into<String>,
        provider_type: ProviderType,
        cedar: &'a PolicyEngine,
        monitoring_enabled: bool,
    ) -> Self {
        Self {
            graph,
            cluster_name: cluster_name.into(),
            provider_type,
            cedar,
            monitoring_enabled,
        }
    }

    /// Compile a LatticeService into Kubernetes resources
    ///
    /// Generates:
    /// - Workloads: Deployment, Service, ServiceAccount, ScaledObject
    /// - Policies: AuthorizationPolicy, CiliumNetworkPolicy, ServiceEntry
    /// - Ingress: Gateway, HTTPRoute, Certificate (if ingress configured)
    /// - Waypoint: Istio ambient mesh L7 policy enforcement
    ///
    /// The namespace comes from the CRD's metadata (LatticeService is namespace-scoped).
    ///
    /// Secret resources are authorized via Cedar policies before ESO generation.
    /// Default-deny: services with secrets require an explicit `permit` policy.
    ///
    /// # Errors
    ///
    /// Returns `CompileError::MissingMetadata` if the service is missing name or namespace.
    /// Returns `CompileError::SecretAccessDenied` if Cedar denies access to any secret path.
    pub async fn compile(&self, service: &LatticeService) -> Result<CompiledService, CompileError> {
        let name = service
            .metadata
            .name
            .as_deref()
            .ok_or(CompileError::MissingMetadata { field: "name" })?;
        let namespace = service
            .metadata
            .namespace
            .as_deref()
            .ok_or(CompileError::MissingMetadata { field: "namespace" })?;

        // Compile volumes first (PVCs must exist before Deployment references them)
        let compiled_volumes = VolumeCompiler::compile(name, namespace, &service.spec)
            .map_err(CompileError::InvalidVolume)?;

        // Compile secrets (ExternalSecrets for syncing from Vault via ESO)
        let compiled_secrets = SecretsCompiler::compile(name, namespace, &service.spec)
            .map_err(CompileError::InvalidSecret)?;

        // Authorize secret access via Cedar — default-deny
        self.authorize_secrets(name, namespace, &service.spec)
            .await?;

        // Delegate to specialized compilers
        let mut workloads = WorkloadCompiler::compile(
            name,
            service,
            namespace,
            &compiled_volumes,
            self.provider_type,
            self.monitoring_enabled,
        )
        .map_err(|e| CompileError::WorkloadCompilation(e.to_string()))?;

        // Add PVCs to workloads
        workloads.pvcs = compiled_volumes.pvcs;

        // Add ExternalSecrets and secret refs to workloads
        workloads.external_secrets = compiled_secrets.external_secrets;
        workloads.secret_refs = compiled_secrets.secret_refs;

        // Inject Velero backup annotations into pod template if backup is configured
        if let Some(ref backup_spec) = service.spec.backup {
            let backup_annotations =
                crate::workload::backup::compile_backup_annotations(backup_spec);
            if let Some(ref mut deployment) = workloads.deployment {
                deployment
                    .spec
                    .template
                    .metadata
                    .annotations
                    .extend(backup_annotations);
            }
        }

        let policy_compiler = PolicyCompiler::new(self.graph, &self.cluster_name);
        let mut policies = policy_compiler.compile(name, namespace);

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

            let gateway_name = mesh::ingress_gateway_name(namespace);
            let gateway_policy =
                policy_compiler.compile_gateway_allow_policy(name, namespace, &ports);
            policies.authorization_policies.push(gateway_policy);

            // Add Cilium L4 rule: allow Istio gateway proxy → service
            if let Some(cilium_policy) = policies.cilium_policies.first_mut() {
                cilium_policy
                    .spec
                    .ingress
                    .push(PolicyCompiler::compile_gateway_ingress_rule(
                        &gateway_name,
                        &ports,
                    ));
            }

            ingress
        } else {
            GeneratedIngress::new()
        };

        Ok(CompiledService {
            workloads,
            policies,
            ingress,
            waypoint,
        })
    }

    /// Authorize secret access via Cedar policies.
    ///
    /// Collects all secret resources from the spec, builds a batch authorization
    /// request, and evaluates it. Returns an error if any path is denied.
    /// No-ops if the service has no secret resources.
    async fn authorize_secrets(
        &self,
        name: &str,
        namespace: &str,
        spec: &crate::crd::LatticeServiceSpec,
    ) -> Result<(), CompileError> {
        let secret_paths: Vec<_> = spec
            .resources
            .iter()
            .filter(|(_, r)| r.is_secret())
            .filter_map(|(resource_name, r)| {
                let vault_path = r.secret_vault_path()?.to_string();
                let provider = r.secret_params().ok()??.provider;
                Some((resource_name.clone(), vault_path, provider))
            })
            .collect();

        if secret_paths.is_empty() {
            return Ok(());
        }

        let result = self
            .cedar
            .authorize_secrets(&SecretAuthzRequest {
                service_name: name.to_string(),
                namespace: namespace.to_string(),
                secret_paths,
            })
            .await;

        if !result.is_allowed() {
            let details = result
                .denied
                .iter()
                .map(|d| format!("'{}': {}", d.resource_name, d.reason))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(CompileError::SecretAccessDenied(details));
        }

        Ok(())
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

    fn make_service(name: &str, namespace: &str) -> LatticeService {
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
                security: None,
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
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: crate::crd::LatticeServiceSpec {
                containers,
                resources: BTreeMap::new(),
                service: Some(ServicePortsSpec { ports }),
                replicas: ReplicaSpec {
                    min: 1,
                    max: None,
                    autoscaling: vec![],
                },
                deploy: DeploySpec::default(),
                ingress: None,
                sidecars: BTreeMap::new(),
                sysctls: BTreeMap::new(),
                host_network: None,
                share_process_namespace: None,
                backup: None,
                gpu: None,
            },
            status: None,
        }
    }

    fn make_service_with_ingress(name: &str, namespace: &str) -> LatticeService {
        let mut service = make_service(name, namespace);
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
            gateway_class: None,
        });
        service
    }

    fn make_service_spec_for_graph(
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
                    namespace: None,
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
                    namespace: None,
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
                security: None,
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
            containers,
            resources,
            service: Some(ServicePortsSpec { ports }),
            replicas: ReplicaSpec::default(),
            deploy: DeploySpec::default(),
            ingress: None,
            sidecars: BTreeMap::new(),
            sysctls: BTreeMap::new(),
            host_network: None,
            share_process_namespace: None,
            backup: None,
            gpu: None,
        }
    }

    // =========================================================================
    // Story: Unified Compilation Delegates to Specialized Compilers
    // =========================================================================

    #[tokio::test]
    async fn story_compile_delegates_to_both_compilers() {
        let graph = ServiceGraph::new();
        let cedar = PolicyEngine::new();
        let env = "prod";

        // api allows gateway
        let api_spec = make_service_spec_for_graph(vec![], vec!["gateway"]);
        graph.put_service(env, "api", &api_spec);

        // gateway calls api
        let gateway_spec = make_service_spec_for_graph(vec!["api"], vec![]);
        graph.put_service(env, "gateway", &gateway_spec);

        // Create LatticeService for api
        let service = make_service("api", "prod");

        let compiler =
            ServiceCompiler::new(&graph, "prod-cluster", ProviderType::Docker, &cedar, true);
        let output = compiler.compile(&service).await.unwrap();

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

    #[tokio::test]
    async fn story_environment_from_label() {
        let graph = ServiceGraph::new();
        let cedar = PolicyEngine::new();

        // Put service in "staging" environment
        let spec = make_service_spec_for_graph(vec![], vec![]);
        graph.put_service("staging", "my-app", &spec);

        // Create LatticeService with staging label
        let service = make_service("my-app", "staging");

        let compiler =
            ServiceCompiler::new(&graph, "test-cluster", ProviderType::Docker, &cedar, true);
        let output = compiler.compile(&service).await.unwrap();

        // Should find service in graph and generate cilium policy
        assert!(!output.policies.cilium_policies.is_empty());
    }

    #[tokio::test]
    async fn story_environment_falls_back_to_namespace() {
        let graph = ServiceGraph::new();
        let cedar = PolicyEngine::new();

        // Put service in "prod-ns" environment (same as namespace)
        let spec = make_service_spec_for_graph(vec![], vec![]);
        graph.put_service("prod-ns", "my-app", &spec);

        // Create LatticeService without env label
        let service = make_service("my-app", "prod-ns");

        let compiler =
            ServiceCompiler::new(&graph, "test-cluster", ProviderType::Docker, &cedar, true);
        let output = compiler.compile(&service).await.unwrap();

        // Should find service using namespace as env
        assert!(!output.policies.cilium_policies.is_empty());
    }

    // =========================================================================
    // Story: Workloads Generated Even Without Graph Entry
    // =========================================================================

    #[tokio::test]
    async fn story_workloads_without_graph_entry() {
        let graph = ServiceGraph::new();
        let cedar = PolicyEngine::new();
        // Don't add service to graph

        let service = make_service("my-app", "default");

        let compiler =
            ServiceCompiler::new(&graph, "test-cluster", ProviderType::Docker, &cedar, true);
        let output = compiler.compile(&service).await.unwrap();

        // Should still have workloads
        assert!(output.workloads.deployment.is_some());
        assert!(output.workloads.service_account.is_some());

        // But no policies (not in graph)
        assert!(output.policies.is_empty());
    }

    // =========================================================================
    // Story: Resource Count
    // =========================================================================

    #[tokio::test]
    async fn story_resource_count() {
        let graph = ServiceGraph::new();
        let cedar = PolicyEngine::new();
        let spec = make_service_spec_for_graph(vec![], vec![]);
        graph.put_service("default", "my-app", &spec);

        let service = make_service("my-app", "default");

        let compiler =
            ServiceCompiler::new(&graph, "test-cluster", ProviderType::Docker, &cedar, true);
        let output = compiler.compile(&service).await.unwrap();

        // Deployment + Service + ServiceAccount + CiliumPolicy + WaypointGateway + WaypointAuthPolicy = 6
        // (VirtualService is generated per dependency, not per service)
        assert_eq!(output.resource_count(), 6);
    }

    // =========================================================================
    // Story: CompiledService Utility Methods
    // =========================================================================

    #[tokio::test]
    async fn story_compiled_service_is_empty() {
        let empty = CompiledService::new();
        assert!(empty.is_empty());

        let graph = ServiceGraph::new();
        let cedar = PolicyEngine::new();
        let service = make_service("my-app", "default");

        let compiler =
            ServiceCompiler::new(&graph, "test-cluster", ProviderType::Docker, &cedar, true);
        let output = compiler.compile(&service).await.unwrap();
        assert!(!output.is_empty());
    }

    // =========================================================================
    // Story: Ingress Integration
    // =========================================================================

    #[tokio::test]
    async fn story_service_with_ingress_generates_gateway_resources() {
        let graph = ServiceGraph::new();
        let cedar = PolicyEngine::new();
        let spec = make_service_spec_for_graph(vec![], vec![]);
        graph.put_service("prod", "api", &spec);

        let service = make_service_with_ingress("api", "prod");

        let compiler =
            ServiceCompiler::new(&graph, "prod-cluster", ProviderType::Docker, &cedar, true);
        let output = compiler.compile(&service).await.unwrap();

        // Should have ingress resources
        assert!(output.ingress.gateway.is_some());
        assert!(output.ingress.http_route.is_some());
        assert!(output.ingress.certificate.is_some());

        let gateway = output
            .ingress
            .gateway
            .expect("gateway should be generated for ingress");
        assert_eq!(gateway.metadata.name, "prod-ingress");
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

    #[tokio::test]
    async fn story_service_without_ingress_has_no_gateway_resources() {
        let graph = ServiceGraph::new();
        let cedar = PolicyEngine::new();
        let spec = make_service_spec_for_graph(vec![], vec![]);
        graph.put_service("prod", "api", &spec);

        let service = make_service("api", "prod");

        let compiler =
            ServiceCompiler::new(&graph, "prod-cluster", ProviderType::Docker, &cedar, true);
        let output = compiler.compile(&service).await.unwrap();

        // Should NOT have ingress resources
        assert!(output.ingress.is_empty());
        assert!(output.ingress.gateway.is_none());
        assert!(output.ingress.http_route.is_none());
        assert!(output.ingress.certificate.is_none());
    }

    #[tokio::test]
    async fn story_resource_count_includes_ingress() {
        let graph = ServiceGraph::new();
        let cedar = PolicyEngine::new();
        let spec = make_service_spec_for_graph(vec![], vec![]);
        graph.put_service("prod", "api", &spec);

        let service = make_service_with_ingress("api", "prod");

        let compiler =
            ServiceCompiler::new(&graph, "prod-cluster", ProviderType::Docker, &cedar, true);
        let output = compiler.compile(&service).await.unwrap();

        // Should include: Deployment + Service + ServiceAccount + CiliumPolicy +
        //                 Gateway + HTTPRoute + Certificate + GatewayAllowPolicy
        // = 3 workloads + 2 policies + 3 ingress = at least 8
        assert!(output.resource_count() >= 6);
    }

    // =========================================================================
    // Story: Backup Annotations Injected into Deployment
    // =========================================================================

    #[tokio::test]
    async fn story_backup_annotations_injected() {
        use crate::crd::{
            BackupHook, BackupHooksSpec, HookErrorAction, ServiceBackupSpec, VolumeBackupDefault,
            VolumeBackupSpec,
        };

        let graph = ServiceGraph::new();
        let cedar = PolicyEngine::new();

        let mut service = make_service("my-db", "prod");
        service.spec.backup = Some(ServiceBackupSpec {
            hooks: Some(BackupHooksSpec {
                pre: vec![BackupHook {
                    name: "freeze".to_string(),
                    container: "main".to_string(),
                    command: vec![
                        "/bin/sh".to_string(),
                        "-c".to_string(),
                        "pg_dump".to_string(),
                    ],
                    timeout: Some("600s".to_string()),
                    on_error: HookErrorAction::Fail,
                }],
                post: vec![],
            }),
            volumes: Some(VolumeBackupSpec {
                include: vec!["data".to_string()],
                exclude: vec![],
                default_policy: VolumeBackupDefault::OptIn,
            }),
        });

        let compiler =
            ServiceCompiler::new(&graph, "test-cluster", ProviderType::Docker, &cedar, true);
        let output = compiler.compile(&service).await.unwrap();

        let deployment = output.workloads.deployment.expect("should have deployment");
        let annotations = &deployment.spec.template.metadata.annotations;

        assert_eq!(
            annotations.get("pre.hook.backup.velero.io/container"),
            Some(&"main".to_string())
        );
        assert_eq!(
            annotations.get("pre.hook.backup.velero.io/timeout"),
            Some(&"600s".to_string())
        );
        assert_eq!(
            annotations.get("pre.hook.backup.velero.io/on-error"),
            Some(&"Fail".to_string())
        );
        assert_eq!(
            annotations.get("backup.velero.io/backup-volumes"),
            Some(&"data".to_string())
        );
    }

    #[tokio::test]
    async fn story_no_backup_no_annotations() {
        let graph = ServiceGraph::new();
        let cedar = PolicyEngine::new();
        let service = make_service("my-app", "default");

        let compiler =
            ServiceCompiler::new(&graph, "test-cluster", ProviderType::Docker, &cedar, true);
        let output = compiler.compile(&service).await.unwrap();

        let deployment = output.workloads.deployment.expect("should have deployment");
        let annotations = &deployment.spec.template.metadata.annotations;

        // No backup-related annotations
        assert!(annotations.keys().all(|k| !k.contains("velero")));
    }
}
