//! Service Compiler for Lattice
//!
//! This module provides a unified API for compiling LatticeService resources into
//! Kubernetes manifests - both workload resources (Deployment, Service, etc.) and
//! network policies (AuthorizationPolicy, CiliumNetworkPolicy).
//!
//! # Architecture
//!
//! The ServiceCompiler delegates to specialized compilers:
//! - [`lattice_workload::WorkloadCompiler`]: Runs the shared compilation pipeline
//! - [`WorkloadCompiler`](crate::workload::WorkloadCompiler): Wraps in service-specific resources
//! - MeshMember CR: Emitted for the `lattice-mesh-member` controller to generate mesh policies
//!
//! # Usage
//!
//! ```text
//! let graph = ServiceGraph::new();
//! let cedar = PolicyEngine::new();
//! let compiler = ServiceCompiler::new(&graph, "prod-cluster", ProviderType::Docker, &cedar, MonitoringConfig::default());
//! let output = compiler.compile(&lattice_service).await;
//! // output.workloads, output.policies
//! ```
//!
//! # Environment Resolution
//!
//! The compiler determines the environment from the LatticeService in this order:
//! 1. Label `lattice.dev/environment` on the service
//! 2. Falls back to namespace

mod phase;
mod vm_service_scrape;
pub use phase::{CompilationContext, CompilerPhase};
pub use vm_service_scrape::VMServiceScrapePhase;

use std::sync::Arc;

use kube::discovery::ApiResource;
use lattice_cedar::PolicyEngine;
use lattice_common::crd::LatticeMeshMember;
use lattice_common::policy::tetragon::TracingPolicyNamespaced;
use lattice_workload::CompilationError;

use crate::crd::{LatticeService, MonitoringConfig, ProviderType, ServiceBackupSpec};
use crate::graph::ServiceGraph;
use crate::workload::{GeneratedWorkloads, WorkloadCompiler};

/// Which layer a dynamic resource should be applied in.
///
/// Layer 1 (Infrastructure) is applied first — policies, config, secrets.
/// Layer 2 (Workload) is applied after infrastructure is ready — Deployments, etc.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyLayer {
    /// Applied alongside policies, secrets, and other infrastructure (Layer 1)
    Infrastructure,
    /// Applied alongside Deployments (Layer 2, after infrastructure is ready)
    Workload,
}

/// A dynamically-typed Kubernetes resource produced by a compiler extension.
///
/// This lets `CompilerPhase` implementations emit arbitrary resource types
/// (Flagger Canary, Argo Rollout, VMServiceScrape, etc.) without adding
/// a named field to `CompiledService` for each one.
#[derive(Clone, Debug)]
pub struct DynamicResource {
    /// Kubernetes kind (for logging)
    pub kind: String,
    /// Resource name (for logging and the SSA patch key)
    pub name: String,
    /// Serialized resource JSON
    pub json: serde_json::Value,
    /// API group/version/resource metadata for the SSA patch
    pub api_resource: ApiResource,
    /// Which apply layer this resource belongs to
    pub layer: ApplyLayer,
}

/// Combined output from compiling a LatticeService
#[derive(Clone, Debug, Default)]
pub struct CompiledService {
    /// Generated workload resources (Deployment, Service, ServiceAccount, ScaledObject)
    pub workloads: GeneratedWorkloads,
    /// LatticeMeshMember CR — the mesh-member controller handles all network concerns
    pub mesh_member: Option<LatticeMeshMember>,
    /// Tetragon TracingPolicyNamespaced resources for runtime enforcement
    pub tracing_policies: Vec<TracingPolicyNamespaced>,
    /// Dynamic resources from compiler extension phases
    pub extensions: Vec<DynamicResource>,
}

impl CompiledService {
    /// Check if any resources were generated
    pub fn is_empty(&self) -> bool {
        self.workloads.is_empty()
            && self.mesh_member.is_none()
            && self.tracing_policies.is_empty()
            && self.extensions.is_empty()
    }

    /// Total count of all generated resources
    pub fn resource_count(&self) -> usize {
        let workload_count = [
            self.workloads.deployment.is_some(),
            self.workloads.service.is_some(),
            self.workloads.service_account.is_some(),
            self.workloads.pdb.is_some(),
            self.workloads.scaled_object.is_some(),
        ]
        .iter()
        .filter(|&&x| x)
        .count();

        workload_count
            + self.workloads.env_config_maps.len()
            + self.workloads.env_secrets.len()
            + self.workloads.files_config_maps.len()
            + self.workloads.files_secrets.len()
            + self.workloads.pvcs.len()
            + self.workloads.external_secrets.len()
            + self.mesh_member.as_ref().map_or(0, |_| 1)
            + self.tracing_policies.len()
            + self.extensions.len()
    }
}

/// Unified service compiler that generates both workload and policy resources
///
/// This compiler orchestrates the generation of all Kubernetes resources for a
/// LatticeService by delegating to specialized compilers:
/// - lattice_workload::WorkloadCompiler for the shared pipeline (volumes, secrets, authorization, templates, pod template)
/// - WorkloadCompiler for service-specific wrapping (Deployment, Service, ServiceAccount, ScaledObject)
/// - MeshMember CR emission for mesh policy generation
/// - Cedar PolicyEngine for secret access authorization (via lattice_workload)
pub struct ServiceCompiler<'a> {
    graph: &'a ServiceGraph,
    cluster_name: String,
    provider_type: ProviderType,
    cedar: &'a PolicyEngine,
    monitoring: MonitoringConfig,
    extension_phases: &'a [Arc<dyn CompilerPhase>],
    effective_backup: Option<ServiceBackupSpec>,
}

impl<'a> ServiceCompiler<'a> {
    /// Create a new service compiler
    ///
    /// # Arguments
    /// * `graph` - The service graph for policy generation (bilateral agreement checks)
    /// * `cluster_name` - Cluster name used in trust domain (lattice.{cluster}.local)
    /// * `provider_type` - Infrastructure provider for topology-aware scheduling
    /// * `cedar` - Cedar policy engine for secret access authorization
    /// * `monitoring` - Monitoring configuration for this cluster
    pub fn new(
        graph: &'a ServiceGraph,
        cluster_name: impl Into<String>,
        provider_type: ProviderType,
        cedar: &'a PolicyEngine,
        monitoring: MonitoringConfig,
    ) -> Self {
        Self {
            graph,
            cluster_name: cluster_name.into(),
            provider_type,
            cedar,
            monitoring,
            extension_phases: &[],
            effective_backup: None,
        }
    }

    /// Attach extension phases that run after core compilation.
    ///
    /// Phases can inspect the service and compiled output, then append
    /// `DynamicResource` entries to `compiled.extensions`.
    pub fn with_phases(mut self, phases: &'a [Arc<dyn CompilerPhase>]) -> Self {
        self.extension_phases = phases;
        self
    }

    /// Set the effective backup spec (merged from policies + inline).
    ///
    /// When set, this overrides the service's inline `spec.backup` during compilation.
    pub fn with_effective_backup(mut self, backup: Option<ServiceBackupSpec>) -> Self {
        self.effective_backup = backup;
        self
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
    /// Returns `CompilationError::MissingMetadata` if the service is missing name or namespace.
    /// Returns `CompilationError::SecretAccessDenied` if Cedar denies access to any secret path.
    pub async fn compile(
        &self,
        service: &LatticeService,
    ) -> Result<CompiledService, CompilationError> {
        let name = service
            .metadata
            .name
            .as_deref()
            .ok_or(CompilationError::missing_metadata("name"))?;
        let namespace = service
            .metadata
            .namespace
            .as_deref()
            .ok_or(CompilationError::missing_metadata("namespace"))?;

        // Use lattice_workload::WorkloadCompiler for the shared pipeline
        let compiled = lattice_workload::WorkloadCompiler::new(
            name,
            namespace,
            &service.spec.workload,
            &service.spec.runtime,
            self.provider_type,
        )
        .with_cedar(self.cedar)
        .with_graph(self.graph)
        .with_cluster_name(&self.cluster_name)
        .with_volume_authorization(lattice_workload::VolumeAuthorizationMode::Full {
            graph: self.graph,
        })
        .with_annotations(&service.metadata.annotations.clone().unwrap_or_default())
        .with_image_pull_secrets(&service.spec.runtime.image_pull_secrets)
        .with_ingress(service.spec.ingress.clone())
        .compile()
        .await?;

        let mesh_member = compiled.mesh_member;

        // Build service-specific resources from compiled pod template
        let mut workloads = WorkloadCompiler::compile(
            name,
            service,
            namespace,
            compiled.pod_template,
            &self.monitoring,
        )?;

        // Populate config resources from the shared pipeline output
        workloads.env_config_maps = compiled.config.env_config_maps;
        workloads.env_secrets = compiled.config.env_secrets;
        workloads.files_config_maps = compiled.config.files_config_maps;
        workloads.files_secrets = compiled.config.files_secrets;
        workloads.pvcs = compiled.config.pvcs;
        workloads.external_secrets = compiled.config.external_secrets;
        workloads.secret_refs = compiled.config.secret_refs;

        // Add config hash as pod annotation to trigger rollouts on config changes
        if let Some(ref mut deployment) = workloads.deployment {
            deployment
                .spec
                .template
                .metadata
                .annotations
                .insert("lattice.dev/config-hash".to_string(), compiled.config_hash);
        }

        // Inject Velero backup annotations into pod template if backup is configured.
        // Use effective_backup (merged from policies + inline) when set, else fall back
        // to the service's inline spec.backup.
        let backup_spec = self
            .effective_backup
            .as_ref()
            .or(service.spec.backup.as_ref());
        if let Some(backup_spec) = backup_spec {
            let backup_annotations =
                lattice_workload::backup::compile_backup_annotations(backup_spec);
            if let Some(ref mut deployment) = workloads.deployment {
                deployment
                    .spec
                    .template
                    .metadata
                    .annotations
                    .extend(backup_annotations);
            }
        }

        // Collect backup hook binaries for Tetragon whitelist inclusion.
        // Uses the effective backup (merged from policies + inline) so policy-injected
        // hooks are also whitelisted. Velero executes these inside the pod.
        let hook_binaries = backup_spec
            .map(|b| b.hook_binaries())
            .unwrap_or_default();
        let tracing_policies = lattice_tetragon::compile_tracing_policies(
            name,
            namespace,
            &service.spec.workload,
            &service.spec.runtime,
            &hook_binaries,
        );

        let mut compiled = CompiledService {
            workloads,
            mesh_member,
            tracing_policies,
            extensions: Vec::new(),
        };

        // Run extension phases (Flagger, VMServiceScrape, rate limiting, etc.)
        if !self.extension_phases.is_empty() {
            let phase_ctx = CompilationContext {
                service,
                name,
                namespace,
                graph: self.graph,
                cluster_name: &self.cluster_name,
                provider_type: self.provider_type,
                monitoring: self.monitoring.clone(),
            };
            for phase in self.extension_phases {
                phase
                    .compile(&phase_ctx, &mut compiled)
                    .await
                    .map_err(|e| CompilationError::extension(phase.name(), e))?;
            }
        }

        Ok(compiled)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        CertIssuerRef, ContainerSpec, DependencyDirection, IngressSpec, IngressTls, PortSpec,
        ResourceSpec, RouteKind, RouteSpec, SecurityContext, ServicePortsSpec, WorkloadSpec,
    };
    use std::collections::BTreeMap;

    fn make_service(name: &str, namespace: &str) -> LatticeService {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "nginx:latest".to_string(),
                command: Some(vec!["/usr/sbin/nginx".to_string()]),
                ..Default::default()
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
                workload: WorkloadSpec {
                    containers,
                    service: Some(ServicePortsSpec { ports }),
                    ..Default::default()
                },
                ..Default::default()
            },
            status: None,
        }
    }

    fn make_service_with_ingress(name: &str, namespace: &str) -> LatticeService {
        let mut service = make_service(name, namespace);
        service.spec.ingress = Some(IngressSpec {
            gateway_class: None,
            routes: BTreeMap::from([(
                "public".to_string(),
                RouteSpec {
                    kind: RouteKind::HTTPRoute,
                    hosts: vec!["api.example.com".to_string()],
                    port: None,
                    listen_port: None,
                    rules: None,
                    tls: Some(IngressTls {
                        secret_name: None,
                        issuer_ref: Some(CertIssuerRef {
                            name: "letsencrypt-prod".to_string(),
                            kind: None,
                        }),
                    }),
                },
            )]),
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
                    direction: DependencyDirection::Outbound,
                    ..Default::default()
                },
            );
        }
        for caller in callers {
            resources.insert(
                caller.to_string(),
                ResourceSpec {
                    direction: DependencyDirection::Inbound,
                    ..Default::default()
                },
            );
        }

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                ..Default::default()
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
            workload: WorkloadSpec {
                containers,
                resources,
                service: Some(ServicePortsSpec { ports }),
            },
            ..Default::default()
        }
    }

    /// Create a test compiler with default settings (Docker provider, monitoring enabled).
    fn test_compiler<'a>(graph: &'a ServiceGraph, cedar: &'a PolicyEngine) -> ServiceCompiler<'a> {
        ServiceCompiler::new(
            graph,
            "test-cluster",
            ProviderType::Docker,
            cedar,
            MonitoringConfig::default(),
        )
    }

    /// Create a fresh graph + cedar pair for tests.
    fn test_setup() -> (ServiceGraph, PolicyEngine) {
        (ServiceGraph::new(), PolicyEngine::new())
    }

    /// Set the security context on the "main" container.
    fn set_main_security(service: &mut LatticeService, security: SecurityContext) {
        service
            .spec
            .workload
            .containers
            .get_mut("main")
            .unwrap()
            .security = Some(security);
    }

    // =========================================================================
    // Story: Unified Compilation Delegates to Specialized Compilers
    // =========================================================================

    #[tokio::test]
    async fn compile_delegates_to_both_compilers() {
        let (graph, cedar) = test_setup();
        let env = "prod";

        // api allows gateway
        let api_spec = make_service_spec_for_graph(vec![], vec!["gateway"]);
        graph.put_service(env, "api", &api_spec);

        // gateway calls api
        let gateway_spec = make_service_spec_for_graph(vec!["api"], vec![]);
        graph.put_service(env, "gateway", &gateway_spec);

        // Create LatticeService for api
        let service = make_service("api", "prod");

        let compiler = test_compiler(&graph, &cedar);
        let output = compiler.compile(&service).await.unwrap();

        // Should have workloads (from WorkloadCompiler)
        assert!(output.workloads.deployment.is_some());
        assert!(output.workloads.service.is_some());
        assert!(output.workloads.service_account.is_some());

        // Should have a MeshMember CR (network concerns delegated to mesh-member controller)
        assert!(output.mesh_member.is_some());
    }

    // =========================================================================
    // Story: Environment Resolution
    // =========================================================================

    #[tokio::test]
    async fn environment_from_label() {
        let (graph, cedar) = test_setup();

        // Put service in "staging" environment
        let spec = make_service_spec_for_graph(vec![], vec![]);
        graph.put_service("staging", "my-app", &spec);

        // Create LatticeService with staging label
        let service = make_service("my-app", "staging");

        let compiler = test_compiler(&graph, &cedar);
        let output = compiler.compile(&service).await.unwrap();

        // Should find service in graph and generate a MeshMember CR
        assert!(output.mesh_member.is_some());
    }

    #[tokio::test]
    async fn environment_falls_back_to_namespace() {
        let (graph, cedar) = test_setup();

        // Put service in "prod-ns" environment (same as namespace)
        let spec = make_service_spec_for_graph(vec![], vec![]);
        graph.put_service("prod-ns", "my-app", &spec);

        // Create LatticeService without env label
        let service = make_service("my-app", "prod-ns");

        let compiler = test_compiler(&graph, &cedar);
        let output = compiler.compile(&service).await.unwrap();

        // Should find service using namespace as env
        assert!(output.mesh_member.is_some());
    }

    // =========================================================================
    // Story: Workloads Generated Even Without Graph Entry
    // =========================================================================

    #[tokio::test]
    async fn workloads_without_graph_entry() {
        let (graph, cedar) = test_setup();
        // Don't add service to graph

        let service = make_service("my-app", "default");

        let compiler = test_compiler(&graph, &cedar);
        let output = compiler.compile(&service).await.unwrap();

        // Should still have workloads
        assert!(output.workloads.deployment.is_some());
        assert!(output.workloads.service_account.is_some());

        // No MeshMember when service is not in the graph
        assert!(output.mesh_member.is_none());
    }

    // =========================================================================
    // Story: Resource Count
    // =========================================================================

    #[tokio::test]
    async fn resource_count() {
        let (graph, cedar) = test_setup();
        let spec = make_service_spec_for_graph(vec![], vec![]);
        graph.put_service("default", "my-app", &spec);

        let service = make_service("my-app", "default");

        let compiler = test_compiler(&graph, &cedar);
        let output = compiler.compile(&service).await.unwrap();

        // Deployment + Service + ServiceAccount + MeshMember + 1 TracingPolicy (binary whitelist)
        assert_eq!(output.resource_count(), 5);
    }

    // =========================================================================
    // Story: CompiledService Utility Methods
    // =========================================================================

    #[tokio::test]
    async fn compiled_service_is_empty() {
        let empty = CompiledService::default();
        assert!(empty.is_empty());

        let (graph, cedar) = test_setup();
        let service = make_service("my-app", "default");

        let compiler = test_compiler(&graph, &cedar);
        let output = compiler.compile(&service).await.unwrap();
        assert!(!output.is_empty());
    }

    // =========================================================================
    // Story: Ingress Integration
    // =========================================================================

    #[tokio::test]
    async fn service_with_ingress_populates_mesh_member_ingress() {
        let (graph, cedar) = test_setup();
        let spec = make_service_spec_for_graph(vec![], vec![]);
        graph.put_service("prod", "api", &spec);

        let service = make_service_with_ingress("api", "prod");

        let compiler = test_compiler(&graph, &cedar);
        let output = compiler.compile(&service).await.unwrap();

        // Ingress spec should be passed through to the MeshMember CR
        let mm = output.mesh_member.expect("should have mesh member");
        assert!(
            mm.spec.ingress.is_some(),
            "MeshMember should carry ingress spec"
        );
    }

    #[tokio::test]
    async fn service_without_ingress_has_no_mesh_member_ingress() {
        let (graph, cedar) = test_setup();
        let spec = make_service_spec_for_graph(vec![], vec![]);
        graph.put_service("prod", "api", &spec);

        let service = make_service("api", "prod");

        let compiler = test_compiler(&graph, &cedar);
        let output = compiler.compile(&service).await.unwrap();

        let mm = output.mesh_member.expect("should have mesh member");
        assert!(
            mm.spec.ingress.is_none(),
            "MeshMember should not carry ingress spec"
        );
    }

    // =========================================================================
    // Story: Backup Annotations Injected into Deployment
    // =========================================================================

    #[tokio::test]
    async fn backup_annotations_injected() {
        use crate::crd::{
            BackupHook, BackupHooksSpec, HookErrorAction, ServiceBackupSpec, VolumeBackupDefault,
            VolumeBackupSpec,
        };

        let (graph, cedar) = test_setup();

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
            ..Default::default()
        });

        let compiler = test_compiler(&graph, &cedar);
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
    async fn no_backup_no_annotations() {
        let (graph, cedar) = test_setup();
        let service = make_service("my-app", "default");

        let compiler = test_compiler(&graph, &cedar);
        let output = compiler.compile(&service).await.unwrap();

        let deployment = output.workloads.deployment.expect("should have deployment");
        let annotations = &deployment.spec.template.metadata.annotations;

        // No backup-related annotations
        assert!(annotations.keys().all(|k| !k.contains("velero")));
    }

    // =========================================================================
    // Story: DynamicResource Extensions
    // =========================================================================

    #[test]
    fn extensions_counted_in_resource_count() {
        let mut compiled = CompiledService::default();
        assert_eq!(compiled.resource_count(), 0);

        compiled.extensions.push(DynamicResource {
            kind: "VMServiceScrape".to_string(),
            name: "my-scrape".to_string(),
            json: serde_json::json!({"metadata": {"name": "my-scrape"}}),
            api_resource: kube::discovery::ApiResource::erase::<
                k8s_openapi::api::core::v1::ConfigMap,
            >(&()),
            layer: ApplyLayer::Infrastructure,
        });

        assert_eq!(compiled.resource_count(), 1);
    }

    #[test]
    fn extensions_included_in_is_empty() {
        let mut compiled = CompiledService::default();
        assert!(compiled.is_empty());

        compiled.extensions.push(DynamicResource {
            kind: "Canary".to_string(),
            name: "my-canary".to_string(),
            json: serde_json::json!({}),
            api_resource: kube::discovery::ApiResource::erase::<
                k8s_openapi::api::core::v1::ConfigMap,
            >(&()),
            layer: ApplyLayer::Workload,
        });

        assert!(!compiled.is_empty());
    }

    // =========================================================================
    // Story: CompilerPhase Extension Hook
    // =========================================================================

    /// A no-op phase that records it was called
    struct TrackingPhase {
        called: std::sync::atomic::AtomicBool,
    }

    impl TrackingPhase {
        fn new() -> Self {
            Self {
                called: std::sync::atomic::AtomicBool::new(false),
            }
        }

        fn was_called(&self) -> bool {
            self.called.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl CompilerPhase for TrackingPhase {
        fn name(&self) -> &str {
            "tracking"
        }

        async fn compile(
            &self,
            _ctx: &CompilationContext<'_>,
            _output: &mut CompiledService,
        ) -> Result<(), String> {
            self.called.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn compiler_phase_gets_called() {
        let (graph, cedar) = test_setup();
        let service = make_service("my-app", "default");

        let phase = Arc::new(TrackingPhase::new());
        let phases: Vec<Arc<dyn CompilerPhase>> = vec![phase.clone()];

        let compiler = test_compiler(&graph, &cedar).with_phases(&phases);
        compiler.compile(&service).await.unwrap();

        assert!(phase.was_called());
    }

    #[tokio::test]
    async fn phase_can_add_dynamic_resource() {
        struct AddResourcePhase;

        #[async_trait::async_trait]
        impl CompilerPhase for AddResourcePhase {
            fn name(&self) -> &str {
                "add-resource"
            }

            async fn compile(
                &self,
                ctx: &CompilationContext<'_>,
                output: &mut CompiledService,
            ) -> Result<(), String> {
                output.extensions.push(DynamicResource {
                    kind: "VMServiceScrape".to_string(),
                    name: format!("{}-scrape", ctx.name),
                    json: serde_json::json!({
                        "apiVersion": "operator.victoriametrics.com/v1beta1",
                        "kind": "VMServiceScrape",
                        "metadata": {"name": format!("{}-scrape", ctx.name), "namespace": ctx.namespace}
                    }),
                    api_resource: kube::discovery::ApiResource::erase::<k8s_openapi::api::core::v1::ConfigMap>(&()),
                    layer: ApplyLayer::Infrastructure,
                });
                Ok(())
            }
        }

        let (graph, cedar) = test_setup();
        let service = make_service("my-app", "default");

        let phases: Vec<Arc<dyn CompilerPhase>> = vec![Arc::new(AddResourcePhase)];
        let compiler = test_compiler(&graph, &cedar).with_phases(&phases);
        let output = compiler.compile(&service).await.unwrap();

        assert_eq!(output.extensions.len(), 1);
        assert_eq!(output.extensions[0].kind, "VMServiceScrape");
        assert_eq!(output.extensions[0].name, "my-app-scrape");
        assert_eq!(output.extensions[0].layer, ApplyLayer::Infrastructure);
    }

    #[tokio::test]
    async fn phase_error_stops_compilation() {
        struct FailingPhase;

        #[async_trait::async_trait]
        impl CompilerPhase for FailingPhase {
            fn name(&self) -> &str {
                "failing"
            }

            async fn compile(
                &self,
                _ctx: &CompilationContext<'_>,
                _output: &mut CompiledService,
            ) -> Result<(), String> {
                Err("something went wrong".to_string())
            }
        }

        let (graph, cedar) = test_setup();
        let service = make_service("my-app", "default");

        let phases: Vec<Arc<dyn CompilerPhase>> = vec![Arc::new(FailingPhase)];
        let compiler = test_compiler(&graph, &cedar).with_phases(&phases);
        let err = compiler.compile(&service).await.unwrap_err();

        let msg = err.to_string();
        assert!(
            msg.contains("failing"),
            "error should name the phase: {}",
            msg
        );
        assert!(
            msg.contains("something went wrong"),
            "error should contain phase message: {}",
            msg
        );
    }

    #[tokio::test]
    async fn no_phases_no_extensions() {
        let (graph, cedar) = test_setup();
        let service = make_service("my-app", "default");

        // No with_phases call — default empty
        let compiler = test_compiler(&graph, &cedar);
        let output = compiler.compile(&service).await.unwrap();

        assert!(output.extensions.is_empty());
    }

    // =========================================================================
    // Story: Security Override Authorization in Compilation
    // =========================================================================

    #[tokio::test]
    async fn compile_fails_when_security_override_denied() {
        let (graph, cedar) = test_setup(); // default-deny

        let mut service = make_service("my-app", "prod");
        set_main_security(
            &mut service,
            SecurityContext {
                capabilities: vec!["NET_ADMIN".to_string()],
                ..Default::default()
            },
        );

        let compiler = test_compiler(&graph, &cedar);
        let err = compiler.compile(&service).await.unwrap_err();

        assert!(err.is_policy_denied());
        let msg = err.to_string();
        assert!(msg.contains("security override denied"));
        assert!(msg.contains("capability:NET_ADMIN"));
    }

    #[tokio::test]
    async fn compile_succeeds_when_security_override_permitted() {
        let graph = ServiceGraph::new();
        let cedar = PolicyEngine::with_policies(
            r#"
            permit(
                principal == Lattice::Service::"prod/my-app",
                action == Lattice::Action::"OverrideSecurity",
                resource == Lattice::SecurityOverride::"capability:NET_ADMIN"
            );
            "#,
        )
        .unwrap();

        let mut service = make_service("my-app", "prod");
        set_main_security(
            &mut service,
            SecurityContext {
                capabilities: vec!["NET_ADMIN".to_string()],
                ..Default::default()
            },
        );

        let compiler = test_compiler(&graph, &cedar);
        let output = compiler.compile(&service).await.unwrap();

        assert!(output.workloads.deployment.is_some());
    }

    #[tokio::test]
    async fn compile_no_overrides_no_policy_needed() {
        let (graph, cedar) = test_setup(); // default-deny — but no overrides, so should pass

        let service = make_service("my-app", "default");

        let compiler = test_compiler(&graph, &cedar);
        let output = compiler.compile(&service).await.unwrap();

        assert!(output.workloads.deployment.is_some());
    }

    // =========================================================================
    // Story: Effective Backup from Policy Overrides Inline
    // =========================================================================

    #[tokio::test]
    async fn effective_backup_overrides_inline() {
        use crate::crd::{
            BackupHook, BackupHooksSpec, HookErrorAction, ServiceBackupSpec, VolumeBackupDefault,
            VolumeBackupSpec,
        };

        let (graph, cedar) = test_setup();

        // Service has inline backup with hooks only
        let mut service = make_service("my-db", "prod");
        service.spec.backup = Some(ServiceBackupSpec {
            hooks: Some(BackupHooksSpec {
                pre: vec![BackupHook {
                    name: "inline-freeze".to_string(),
                    container: "main".to_string(),
                    command: vec!["/bin/sh".to_string(), "-c".to_string(), "sync".to_string()],
                    timeout: None,
                    on_error: HookErrorAction::Continue,
                }],
                post: vec![],
            }),
            volumes: None,
            ..Default::default()
        });

        // Effective backup from policy merge: has volumes but no hooks
        let effective = ServiceBackupSpec {
            hooks: None,
            volumes: Some(VolumeBackupSpec {
                include: vec!["data".to_string()],
                exclude: vec![],
                default_policy: VolumeBackupDefault::OptIn,
            }),
            ..Default::default()
        };

        let compiler = test_compiler(&graph, &cedar).with_effective_backup(Some(effective));
        let output = compiler.compile(&service).await.unwrap();

        let deployment = output.workloads.deployment.expect("should have deployment");
        let annotations = &deployment.spec.template.metadata.annotations;

        // Effective backup is used — it has volumes but NOT hooks
        assert_eq!(
            annotations.get("backup.velero.io/backup-volumes"),
            Some(&"data".to_string())
        );
        // Inline hooks are NOT used because effective_backup takes precedence
        assert!(!annotations.contains_key("pre.hook.backup.velero.io/container"));
    }

    #[tokio::test]
    async fn effective_backup_none_falls_back_to_inline() {
        use crate::crd::{BackupHook, BackupHooksSpec, HookErrorAction, ServiceBackupSpec};

        let (graph, cedar) = test_setup();

        let mut service = make_service("my-db", "prod");
        service.spec.backup = Some(ServiceBackupSpec {
            hooks: Some(BackupHooksSpec {
                pre: vec![BackupHook {
                    name: "inline-hook".to_string(),
                    container: "main".to_string(),
                    command: vec!["/bin/sh".to_string(), "-c".to_string(), "sync".to_string()],
                    timeout: Some("30s".to_string()),
                    on_error: HookErrorAction::Fail,
                }],
                post: vec![],
            }),
            volumes: None,
            ..Default::default()
        });

        // No effective backup — should fall back to inline
        let compiler = test_compiler(&graph, &cedar).with_effective_backup(None);
        let output = compiler.compile(&service).await.unwrap();

        let deployment = output.workloads.deployment.expect("should have deployment");
        let annotations = &deployment.spec.template.metadata.annotations;

        assert_eq!(
            annotations.get("pre.hook.backup.velero.io/container"),
            Some(&"main".to_string())
        );
        assert_eq!(
            annotations.get("pre.hook.backup.velero.io/timeout"),
            Some(&"30s".to_string())
        );
    }
}
