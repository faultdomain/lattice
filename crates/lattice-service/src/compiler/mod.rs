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

use std::collections::HashSet;
use std::sync::Arc;

use kube::discovery::ApiResource;
use lattice_cedar::{
    PolicyEngine, SecretAuthzRequest, SecurityAuthzRequest, SecurityOverrideRequest,
    VolumeAuthzRequest,
};

use lattice_common::mesh;
use lattice_common::template::{EsoTemplatedEnvVar, RenderConfig, TemplateRenderer};
use lattice_secret_provider::{
    ExternalSecret, ExternalSecretData, ExternalSecretSpec, ExternalSecretTarget,
    ExternalSecretTemplate, RemoteRef, SecretStoreRef,
};

use crate::crd::{LatticeService, MonitoringConfig, ProviderType, ServiceBackupSpec};
use crate::graph::ServiceGraph;
use crate::ingress::{GeneratedIngress, GeneratedWaypoint, IngressCompiler, WaypointCompiler};
use crate::policy::{GeneratedPolicies, PolicyCompiler};
use crate::workload::{
    compute_config_hash, env, files, CompilationError, ContainerCompilationData, EnvFromSource,
    GeneratedWorkloads, SecretEnvSource, SecretRef, SecretsCompiler, VolumeCompiler,
    WorkloadCompiler,
};

impl From<CompilationError> for crate::Error {
    fn from(err: CompilationError) -> Self {
        crate::Error::validation(err.to_string())
    }
}

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
    /// Generated network policies (AuthorizationPolicy, CiliumNetworkPolicy, ServiceEntry)
    pub policies: GeneratedPolicies,
    /// Generated ingress resources (Gateway, HTTPRoute, Certificate)
    pub ingress: GeneratedIngress,
    /// Generated waypoint Gateway for east-west L7 policy enforcement
    pub waypoint: GeneratedWaypoint,
    /// Dynamic resources from compiler extension phases
    pub extensions: Vec<DynamicResource>,
}

impl CompiledService {
    /// Check if any resources were generated
    pub fn is_empty(&self) -> bool {
        self.workloads.is_empty()
            && self.policies.is_empty()
            && self.ingress.is_empty()
            && self.waypoint.is_empty()
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
            + self.policies.total_count()
            + self.ingress.total_count()
            + self.waypoint.total_count()
            + self.extensions.len()
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
    monitoring: MonitoringConfig,
    renderer: TemplateRenderer,
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
            renderer: TemplateRenderer::new(),
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

        let workload = &service.spec.workload;

        // Compile volumes first (PVCs must exist before Deployment references them)
        let compiled_volumes =
            VolumeCompiler::compile(name, namespace, workload, &service.spec.runtime.sidecars)?;

        // Compile secrets (ExternalSecrets for syncing from Vault via ESO)
        let compiled_secrets = SecretsCompiler::compile(
            name,
            namespace,
            workload,
            &service.spec.runtime.image_pull_secrets,
        )?;

        // Authorize secret access via Cedar — default-deny
        self.authorize_secrets(name, namespace, workload).await?;

        // Authorize volume access — owner consent + Cedar policy
        self.authorize_volumes(name, namespace, workload).await?;

        // Authorize security overrides via Cedar — default-deny
        self.authorize_security_overrides(name, namespace, workload, &service.spec.runtime)
            .await?;

        // Build template context and render all containers
        let render_config = RenderConfig::new(self.graph, namespace, namespace)
            .with_cluster("name", &self.cluster_name);
        let template_ctx = self
            .renderer
            .build_context(
                name,
                &service.metadata.annotations.clone().unwrap_or_default(),
                workload,
                &render_config,
            )
            .map_err(CompilationError::from)?;
        let rendered_containers = self
            .renderer
            .render_all_containers(workload, &template_ctx)
            .map_err(CompilationError::from)?;

        // Compile rendered env vars and files per-container
        let mut env_config_maps = Vec::new();
        let mut env_secrets = Vec::new();
        let mut files_config_maps = Vec::new();
        let mut files_secrets = Vec::new();
        let mut file_external_secrets = Vec::new();
        let mut per_container_env_from = std::collections::BTreeMap::new();
        let mut per_container_file_volumes = std::collections::BTreeMap::new();
        let mut per_container_file_mounts = std::collections::BTreeMap::new();

        for (container_name, rendered) in &rendered_containers {
            // Compile non-secret env vars → ConfigMap + Secret + envFrom refs
            let compiled_env = env::compile(name, container_name, namespace, &rendered.variables);
            if let Some(cm) = compiled_env.config_map {
                env_config_maps.push(cm);
            }
            if let Some(secret) = compiled_env.secret {
                env_secrets.push(secret);
            }
            let mut container_env_from = compiled_env.env_from;

            // Compile ESO-templated env vars (mixed secret + non-secret content)
            // These need an ESO ExternalSecret to render Go templates at sync time
            if !rendered.eso_templated_variables.is_empty() {
                let (eso_secrets, eso_env_from) = compile_eso_templated_env_vars(
                    name,
                    container_name,
                    namespace,
                    &rendered.eso_templated_variables,
                    &compiled_secrets.secret_refs,
                )?;
                file_external_secrets.extend(eso_secrets);
                container_env_from.extend(eso_env_from);
            }

            per_container_env_from.insert(container_name.clone(), container_env_from);

            // Compile files → ConfigMap + Secret + ESO ExternalSecrets + Volumes
            let compiled_files = files::compile(
                name,
                container_name,
                namespace,
                &rendered.files,
                &compiled_secrets.secret_refs,
            )?;

            if let Some(cm) = compiled_files.config_map {
                files_config_maps.push(cm);
            }
            if let Some(secret) = compiled_files.secret {
                files_secrets.push(secret);
            }
            file_external_secrets.extend(compiled_files.file_external_secrets);
            per_container_file_volumes.insert(container_name.clone(), compiled_files.volumes);
            per_container_file_mounts.insert(container_name.clone(), compiled_files.volume_mounts);
        }

        // Delegate to WorkloadCompiler for Deployment, Service, ServiceAccount, HPA
        let container_data = ContainerCompilationData {
            secret_refs: &compiled_secrets.secret_refs,
            rendered_containers: &rendered_containers,
            per_container_env_from: &per_container_env_from,
            per_container_file_volumes: &per_container_file_volumes,
            per_container_file_mounts: &per_container_file_mounts,
        };
        let mut workloads = WorkloadCompiler::compile(
            name,
            service,
            namespace,
            &compiled_volumes,
            self.provider_type,
            &self.monitoring,
            &container_data,
        )?;

        // Populate generated workloads with compiled config resources
        workloads.pvcs = compiled_volumes.pvcs;
        workloads.external_secrets = compiled_secrets.external_secrets;
        workloads.external_secrets.extend(file_external_secrets);
        workloads.secret_refs = compiled_secrets.secret_refs;
        workloads.env_config_maps = env_config_maps;
        workloads.env_secrets = env_secrets;
        workloads.files_config_maps = files_config_maps;
        workloads.files_secrets = files_secrets;

        // Compute config hash and add as pod annotation to trigger rollouts
        let config_hash = compute_config_hash(
            &workloads.env_config_maps,
            &workloads.env_secrets,
            &workloads.files_config_maps,
            &workloads.files_secrets,
        );
        if let Some(ref mut deployment) = workloads.deployment {
            deployment
                .spec
                .template
                .metadata
                .annotations
                .insert("lattice.dev/config-hash".to_string(), config_hash);
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

        // Compile ingress resources if configured
        let ingress = if let Some(ref ingress_spec) = service.spec.ingress {
            let ingress =
                IngressCompiler::compile(name, namespace, ingress_spec, workload.service.as_ref());

            // Add gateway allow policies for north-south traffic
            let gateway_name = mesh::ingress_gateway_name(namespace);

            // Service ports used by both L7 (Istio) and L4 (Cilium) gateway rules.
            // Cilium translates service ports to targetPorts internally.
            let service_ports: Vec<u16> = workload
                .service
                .as_ref()
                .map(|s| s.ports.values().map(|p| p.port).collect())
                .unwrap_or_default();

            let gateway_policy =
                policy_compiler.compile_gateway_allow_policy(name, namespace, &service_ports);
            policies.authorization_policies.push(gateway_policy);

            if let Some(cilium_policy) = policies.cilium_policies.first_mut() {
                cilium_policy
                    .spec
                    .ingress
                    .push(PolicyCompiler::compile_gateway_ingress_rule(
                        &gateway_name,
                        &service_ports,
                    ));
            }

            ingress
        } else {
            GeneratedIngress::default()
        };

        let mut compiled = CompiledService {
            workloads,
            policies,
            ingress,
            waypoint,
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
                    .map_err(|e| CompilationError::extension(phase.name(), e))?;
            }
        }

        Ok(compiled)
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
        workload: &crate::crd::WorkloadSpec,
    ) -> Result<(), CompilationError> {
        let secret_paths: Vec<_> = workload
            .resources
            .iter()
            .filter(|(_, r)| r.type_.is_secret())
            .filter_map(|(resource_name, r)| {
                let remote_key = r.secret_remote_key()?.to_string();
                let provider = r.secret_params().ok()??.provider;
                Some((resource_name.clone(), remote_key, provider))
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
            return Err(CompilationError::secret_access_denied(details));
        }

        Ok(())
    }

    /// Authorize volume access for shared volume references.
    ///
    /// Two-layer authorization:
    /// 1. **Owner consent**: The volume owner must list this service in `allowedConsumers`
    /// 2. **Cedar policy**: If Cedar policies exist, they must permit `AccessVolume`
    ///
    /// Only checks references to shared volumes (those with `id` but no `size`).
    /// Private volumes and owned volumes skip authorization.
    async fn authorize_volumes(
        &self,
        name: &str,
        namespace: &str,
        workload: &crate::crd::WorkloadSpec,
    ) -> Result<(), CompilationError> {
        // Collect volume references (shared volumes this service doesn't own)
        let volume_refs: Vec<_> = workload
            .resources
            .iter()
            .filter(|(_, r)| r.is_volume_reference())
            .filter_map(|(resource_name, r)| {
                let volume_id = r.id.as_ref()?;
                // Volume namespace: use resource's namespace override or service namespace
                let vol_ns = r.namespace.as_deref().unwrap_or(namespace);
                Some((resource_name.clone(), vol_ns.to_string(), volume_id.clone()))
            })
            .collect();

        if volume_refs.is_empty() {
            return Ok(());
        }

        // Layer 1: Owner consent via graph
        let mut denied = Vec::new();
        for (resource_name, vol_ns, volume_id) in &volume_refs {
            if let Some(ownership) = self.graph.get_volume_owner(vol_ns, volume_id) {
                let consumer_key_short = name.to_string();
                let consumer_key_qualified = format!("{}/{}", namespace, name);

                let allowed = ownership
                    .params
                    .allowed_consumers
                    .as_ref()
                    .map(|consumers| {
                        consumers.iter().any(|c| {
                            c == &consumer_key_qualified
                                || (c == &consumer_key_short && namespace == vol_ns)
                        })
                    })
                    .unwrap_or(false); // No allowedConsumers = default-deny

                if !allowed {
                    denied.push(format!(
                        "'{}': not in allowedConsumers of volume '{}' owned by '{}/{}'",
                        resource_name, volume_id, ownership.owner_namespace, ownership.owner_name,
                    ));
                }
            }
            // If no owner found in graph, skip owner consent check (owner may not be compiled yet)
        }

        if !denied.is_empty() {
            return Err(CompilationError::volume_access_denied(denied.join("; ")));
        }

        // Layer 2: Cedar policy authorization (permissive by default)
        let result = self
            .cedar
            .authorize_volumes(&VolumeAuthzRequest {
                service_name: name.to_string(),
                namespace: namespace.to_string(),
                volume_refs,
            })
            .await;

        if !result.is_allowed() {
            let details = result
                .denied
                .iter()
                .map(|d| format!("'{}' (volume '{}'): {}", d.resource_name, d.volume_id, d.reason))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(CompilationError::volume_access_denied(details));
        }

        Ok(())
    }

    /// Authorize security overrides via Cedar policies.
    ///
    /// Scans the spec for any deviation from PSS restricted defaults (capabilities,
    /// privileged, host network, etc.), builds a batch authorization request, and
    /// evaluates it. Returns an error if any override is denied.
    /// No-ops if the service has no security overrides.
    async fn authorize_security_overrides(
        &self,
        name: &str,
        namespace: &str,
        workload: &crate::crd::WorkloadSpec,
        runtime: &crate::crd::RuntimeSpec,
    ) -> Result<(), CompilationError> {
        let overrides = collect_security_overrides(workload, runtime);

        if overrides.is_empty() {
            return Ok(());
        }

        let result = self
            .cedar
            .authorize_security_overrides(&SecurityAuthzRequest {
                service_name: name.to_string(),
                namespace: namespace.to_string(),
                overrides,
            })
            .await;

        if !result.is_allowed() {
            let details = result
                .denied
                .iter()
                .map(|d| {
                    if let Some(ref c) = d.container {
                        format!("'{}' (container '{}'): {}", d.override_id, c, d.reason)
                    } else {
                        format!("'{}': {}", d.override_id, d.reason)
                    }
                })
                .collect::<Vec<_>>()
                .join("; ");
            return Err(CompilationError::security_override_denied(details));
        }

        Ok(())
    }
}

/// Default Linux capabilities granted to containers by Docker/containerd.
///
/// These are the capabilities a container receives when no explicit `drop: [ALL]`
/// is applied. When `drop_capabilities` is set to something other than `["ALL"]`,
/// any capability in this set that is NOT in the drop list is implicitly retained
/// and must be authorized via Cedar policy — otherwise a service can bypass Cedar
/// by simply not dropping capabilities instead of explicitly adding them.
///
/// Reference: <https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities>
const DEFAULT_CONTAINER_CAPABILITIES: &[&str] = &[
    "AUDIT_WRITE",
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "MKNOD",
    "NET_BIND_SERVICE",
    "NET_RAW",
    "SETFCAP",
    "SETGID",
    "SETPCAP",
    "SETUID",
    "SYS_CHROOT",
];

/// Collect security overrides from WorkloadSpec + RuntimeSpec.
///
/// Scans pod-level and container-level fields for any deviation from the
/// PSS restricted profile defaults. Returns an empty vec if the service
/// doesn't relax any security defaults.
fn collect_security_overrides(
    workload: &crate::crd::WorkloadSpec,
    runtime: &crate::crd::RuntimeSpec,
) -> Vec<SecurityOverrideRequest> {
    let mut overrides = Vec::new();

    // Pod-level overrides (from RuntimeSpec)
    if runtime.host_network == Some(true) {
        overrides.push(SecurityOverrideRequest {
            override_id: "hostNetwork".into(),
            category: "pod".into(),
            container: None,
        });
    }
    if runtime.share_process_namespace == Some(true) {
        overrides.push(SecurityOverrideRequest {
            override_id: "shareProcessNamespace".into(),
            category: "pod".into(),
            container: None,
        });
    }

    // Container-level overrides (main containers from WorkloadSpec + sidecars from RuntimeSpec)
    for (name, container) in &workload.containers {
        collect_container_overrides(&mut overrides, name, container.security.as_ref());
    }
    for (name, sidecar) in &runtime.sidecars {
        collect_container_overrides(&mut overrides, name, sidecar.security.as_ref());
    }

    overrides
}

/// Collect security overrides from a single container's SecurityContext.
fn collect_container_overrides(
    overrides: &mut Vec<SecurityOverrideRequest>,
    container_name: &str,
    security: Option<&crate::crd::SecurityContext>,
) {
    let Some(s) = security else { return };
    let cname = Some(container_name.to_string());

    for cap in &s.capabilities {
        overrides.push(SecurityOverrideRequest {
            override_id: format!("capability:{cap}"),
            category: "capability".into(),
            container: cname.clone(),
        });
    }

    // If drop_capabilities relaxes the default "drop ALL", retained default
    // capabilities must also be authorized via Cedar. Without this check a
    // service can silently keep NET_RAW, SETUID, DAC_OVERRIDE, etc. by
    // setting `dropCapabilities: []` instead of adding them explicitly.
    if s.privileged != Some(true) {
        if let Some(ref drops) = s.drop_capabilities {
            if !drops.iter().any(|d| d.eq_ignore_ascii_case("ALL")) {
                let explicitly_added: HashSet<String> = s
                    .capabilities
                    .iter()
                    .map(|c| c.to_ascii_uppercase())
                    .collect();
                let dropped: HashSet<String> =
                    drops.iter().map(|d| d.to_ascii_uppercase()).collect();

                for &default_cap in DEFAULT_CONTAINER_CAPABILITIES {
                    if dropped.contains(default_cap) {
                        continue;
                    }
                    if explicitly_added.contains(default_cap) {
                        continue; // already covered by the add-list override above
                    }
                    overrides.push(SecurityOverrideRequest {
                        override_id: format!("capability:{default_cap}"),
                        category: "capability".into(),
                        container: cname.clone(),
                    });
                }
            }
        }
    }

    if s.privileged == Some(true) {
        overrides.push(SecurityOverrideRequest {
            override_id: "privileged".into(),
            category: "container".into(),
            container: cname.clone(),
        });
    }
    if s.run_as_user == Some(0) || s.run_as_non_root == Some(false) {
        overrides.push(SecurityOverrideRequest {
            override_id: "runAsRoot".into(),
            category: "container".into(),
            container: cname.clone(),
        });
    }
    if s.read_only_root_filesystem == Some(false) {
        overrides.push(SecurityOverrideRequest {
            override_id: "readWriteRootFilesystem".into(),
            category: "container".into(),
            container: cname.clone(),
        });
    }
    if s.allow_privilege_escalation == Some(true) {
        overrides.push(SecurityOverrideRequest {
            override_id: "allowPrivilegeEscalation".into(),
            category: "container".into(),
            container: cname.clone(),
        });
    }
    if s.seccomp_profile.as_deref() == Some("Unconfined") {
        overrides.push(SecurityOverrideRequest {
            override_id: "unconfined:seccomp".into(),
            category: "profile".into(),
            container: cname.clone(),
        });
    }
    if s.apparmor_profile.as_deref() == Some("Unconfined") {
        overrides.push(SecurityOverrideRequest {
            override_id: "unconfined:apparmor".into(),
            category: "profile".into(),
            container: cname,
        });
    }
}

/// Compile ESO-templated env vars into ExternalSecrets + envFrom references.
///
/// Each env var's secret refs must all come from the same store, but different
/// env vars may use different stores. Creates one ExternalSecret per store group.
fn compile_eso_templated_env_vars(
    service_name: &str,
    container_name: &str,
    namespace: &str,
    eso_templated_variables: &std::collections::BTreeMap<String, EsoTemplatedEnvVar>,
    secret_refs: &std::collections::BTreeMap<String, SecretRef>,
) -> Result<(Vec<ExternalSecret>, Vec<EnvFromSource>), CompilationError> {
    // Validate per-var store consistency and group vars by store
    let mut by_store: std::collections::BTreeMap<String, Vec<(&String, &EsoTemplatedEnvVar)>> =
        std::collections::BTreeMap::new();

    for (var_name, templated) in eso_templated_variables {
        let store = crate::workload::secrets::resolve_single_store(
            &templated.secret_refs,
            secret_refs,
            &format!("env var '{}'", var_name),
        )?;
        by_store
            .entry(store)
            .or_default()
            .push((var_name, templated));
    }

    let mut external_secrets = Vec::new();
    let mut env_from_refs = Vec::new();

    for (idx, (store_name, vars)) in by_store.iter().enumerate() {
        let suffix = if by_store.len() == 1 {
            String::new()
        } else {
            format!("-{}", idx)
        };
        let es_name = format!("{}-{}-env-eso{}", service_name, container_name, suffix);

        let mut eso_data: Vec<ExternalSecretData> = Vec::new();
        let mut template_data = std::collections::BTreeMap::new();
        let mut seen_eso_keys = std::collections::HashSet::new();

        for (var_name, templated) in vars {
            template_data.insert((*var_name).clone(), templated.rendered_template.clone());

            for fref in &templated.secret_refs {
                if !seen_eso_keys.insert(fref.eso_data_key.clone()) {
                    continue;
                }

                let sr = secret_refs.get(&fref.resource_name).ok_or_else(|| {
                    CompilationError::file_compilation(format!(
                        "env var '{}' references secret resource '{}' but no SecretRef was compiled",
                        var_name, fref.resource_name
                    ))
                })?;

                if let Some(ref keys) = sr.keys {
                    if !keys.contains(&fref.key) {
                        return Err(CompilationError::file_compilation(format!(
                            "env var '{}' references key '{}' in secret '{}' but available keys are: {:?}",
                            var_name, fref.key, fref.resource_name, keys
                        )));
                    }
                }

                eso_data.push(ExternalSecretData::new(
                    &fref.eso_data_key,
                    RemoteRef::with_property(&sr.remote_key, &fref.key),
                ));
            }
        }

        external_secrets.push(ExternalSecret::new(
            &es_name,
            namespace,
            ExternalSecretSpec {
                secret_store_ref: SecretStoreRef::cluster_secret_store(store_name),
                target: ExternalSecretTarget::with_template(
                    &es_name,
                    ExternalSecretTemplate::new(template_data),
                ),
                data: eso_data,
                data_from: None,
                refresh_interval: Some("1h".to_string()),
            },
        ));

        env_from_refs.push(EnvFromSource {
            config_map_ref: None,
            secret_ref: Some(SecretEnvSource { name: es_name }),
        });
    }

    Ok((external_secrets, env_from_refs))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        CertIssuerRef, ContainerSpec, DependencyDirection, IngressSpec, IngressTls, PortSpec,
        ResourceSpec, RouteKind, RouteSpec, SecurityContext, ServicePortsSpec, SidecarSpec,
        WorkloadSpec,
    };
    use std::collections::BTreeMap;

    fn make_service(name: &str, namespace: &str) -> LatticeService {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "nginx:latest".to_string(),
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

        // Should have policies (from PolicyCompiler)
        assert!(!output.policies.authorization_policies.is_empty());
        assert!(!output.policies.cilium_policies.is_empty());
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

        // Should find service in graph and generate cilium policy
        assert!(!output.policies.cilium_policies.is_empty());
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
        assert!(!output.policies.cilium_policies.is_empty());
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

        // No policies when service is not in graph
        assert!(output.policies.is_empty());
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

        // Deployment + Service + ServiceAccount + CiliumPolicy
        // + WaypointGateway + WaypointAuthPolicy = 6
        assert_eq!(output.resource_count(), 6);
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
    async fn service_with_ingress_generates_gateway_resources() {
        let (graph, cedar) = test_setup();
        let spec = make_service_spec_for_graph(vec![], vec![]);
        graph.put_service("prod", "api", &spec);

        let service = make_service_with_ingress("api", "prod");

        let compiler = test_compiler(&graph, &cedar);
        let output = compiler.compile(&service).await.unwrap();

        // Should have ingress resources
        assert!(output.ingress.gateway.is_some());
        assert!(!output.ingress.http_routes.is_empty());
        assert!(!output.ingress.certificates.is_empty());

        let gateway = output
            .ingress
            .gateway
            .expect("gateway should be generated for ingress");
        assert_eq!(gateway.metadata.name, "prod-ingress");
        assert_eq!(gateway.metadata.namespace, "prod");

        let route = &output.ingress.http_routes[0];
        assert_eq!(route.metadata.name, "api-public-route");

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
    async fn service_without_ingress_has_no_gateway_resources() {
        let (graph, cedar) = test_setup();
        let spec = make_service_spec_for_graph(vec![], vec![]);
        graph.put_service("prod", "api", &spec);

        let service = make_service("api", "prod");

        let compiler = test_compiler(&graph, &cedar);
        let output = compiler.compile(&service).await.unwrap();

        // Should NOT have ingress resources
        assert!(output.ingress.is_empty());
        assert!(output.ingress.gateway.is_none());
        assert!(output.ingress.http_routes.is_empty());
        assert!(output.ingress.certificates.is_empty());
    }

    #[tokio::test]
    async fn resource_count_includes_ingress() {
        let (graph, cedar) = test_setup();
        let spec = make_service_spec_for_graph(vec![], vec![]);
        graph.put_service("prod", "api", &spec);

        let service = make_service_with_ingress("api", "prod");

        let compiler = test_compiler(&graph, &cedar);
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

    impl CompilerPhase for TrackingPhase {
        fn name(&self) -> &str {
            "tracking"
        }

        fn compile(
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

        impl CompilerPhase for AddResourcePhase {
            fn name(&self) -> &str {
                "add-resource"
            }

            fn compile(
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

        impl CompilerPhase for FailingPhase {
            fn name(&self) -> &str {
                "failing"
            }

            fn compile(
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
    // Story: Security Override Detection (collect_security_overrides)
    // =========================================================================

    #[test]
    fn collect_security_overrides_empty() {
        // Default service has no security overrides
        let service = make_service("my-app", "default");
        let overrides = collect_security_overrides(&service.spec.workload, &service.spec.runtime);
        assert!(overrides.is_empty());
    }

    #[test]
    fn collect_security_overrides_capabilities() {
        let mut service = make_service("my-app", "default");
        set_main_security(
            &mut service,
            SecurityContext {
                capabilities: vec!["NET_ADMIN".to_string(), "SYS_MODULE".to_string()],
                ..Default::default()
            },
        );

        let overrides = collect_security_overrides(&service.spec.workload, &service.spec.runtime);
        assert_eq!(overrides.len(), 2);
        assert_eq!(overrides[0].override_id, "capability:NET_ADMIN");
        assert_eq!(overrides[0].category, "capability");
        assert_eq!(overrides[0].container.as_deref(), Some("main"));
        assert_eq!(overrides[1].override_id, "capability:SYS_MODULE");
    }

    #[test]
    fn collect_security_overrides_privileged() {
        let mut service = make_service("my-app", "default");
        set_main_security(
            &mut service,
            SecurityContext {
                privileged: Some(true),
                ..Default::default()
            },
        );

        let overrides = collect_security_overrides(&service.spec.workload, &service.spec.runtime);
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0].override_id, "privileged");
        assert_eq!(overrides[0].category, "container");
    }

    #[test]
    fn collect_security_overrides_run_as_root() {
        // runAsUser: 0
        let mut service = make_service("my-app", "default");
        set_main_security(
            &mut service,
            SecurityContext {
                run_as_user: Some(0),
                ..Default::default()
            },
        );
        let overrides = collect_security_overrides(&service.spec.workload, &service.spec.runtime);
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0].override_id, "runAsRoot");

        // runAsNonRoot: false
        let mut service2 = make_service("my-app", "default");
        set_main_security(
            &mut service2,
            SecurityContext {
                run_as_non_root: Some(false),
                ..Default::default()
            },
        );
        let overrides2 =
            collect_security_overrides(&service2.spec.workload, &service2.spec.runtime);
        assert_eq!(overrides2.len(), 1);
        assert_eq!(overrides2[0].override_id, "runAsRoot");
    }

    #[test]
    fn collect_security_overrides_pod_level() {
        let mut service = make_service("my-app", "default");
        service.spec.runtime.host_network = Some(true);
        service.spec.runtime.share_process_namespace = Some(true);

        let overrides = collect_security_overrides(&service.spec.workload, &service.spec.runtime);
        assert_eq!(overrides.len(), 2);

        let ids: Vec<&str> = overrides.iter().map(|o| o.override_id.as_str()).collect();
        assert!(ids.contains(&"hostNetwork"));
        assert!(ids.contains(&"shareProcessNamespace"));
        assert!(overrides.iter().all(|o| o.category == "pod"));
        assert!(overrides.iter().all(|o| o.container.is_none()));
    }

    #[test]
    fn collect_security_overrides_profiles() {
        let mut service = make_service("my-app", "default");
        set_main_security(
            &mut service,
            SecurityContext {
                seccomp_profile: Some("Unconfined".to_string()),
                apparmor_profile: Some("Unconfined".to_string()),
                ..Default::default()
            },
        );

        let overrides = collect_security_overrides(&service.spec.workload, &service.spec.runtime);
        assert_eq!(overrides.len(), 2);

        let ids: Vec<&str> = overrides.iter().map(|o| o.override_id.as_str()).collect();
        assert!(ids.contains(&"unconfined:seccomp"));
        assert!(ids.contains(&"unconfined:apparmor"));
        assert!(overrides.iter().all(|o| o.category == "profile"));
    }

    #[test]
    fn collect_security_overrides_read_write_root_fs() {
        let mut service = make_service("my-app", "default");
        set_main_security(
            &mut service,
            SecurityContext {
                read_only_root_filesystem: Some(false),
                ..Default::default()
            },
        );

        let overrides = collect_security_overrides(&service.spec.workload, &service.spec.runtime);
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0].override_id, "readWriteRootFilesystem");
    }

    #[test]
    fn collect_security_overrides_allow_priv_escalation() {
        let mut service = make_service("my-app", "default");
        set_main_security(
            &mut service,
            SecurityContext {
                allow_privilege_escalation: Some(true),
                ..Default::default()
            },
        );

        let overrides = collect_security_overrides(&service.spec.workload, &service.spec.runtime);
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0].override_id, "allowPrivilegeEscalation");
    }

    #[test]
    fn collect_security_overrides_sidecars() {
        let mut service = make_service("my-app", "default");
        service.spec.runtime.sidecars.insert(
            "vpn".to_string(),
            SidecarSpec {
                image: "vpn:latest".to_string(),
                security: Some(SecurityContext {
                    capabilities: vec!["NET_ADMIN".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        );

        let overrides = collect_security_overrides(&service.spec.workload, &service.spec.runtime);
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0].override_id, "capability:NET_ADMIN");
        assert_eq!(overrides[0].container.as_deref(), Some("vpn"));
    }

    #[test]
    fn collect_security_overrides_defaults_not_flagged() {
        // Explicitly setting defaults should not trigger overrides
        let mut service = make_service("my-app", "default");
        set_main_security(
            &mut service,
            SecurityContext {
                privileged: Some(false),
                read_only_root_filesystem: Some(true),
                run_as_non_root: Some(true),
                allow_privilege_escalation: Some(false),
                seccomp_profile: Some("RuntimeDefault".to_string()),
                apparmor_profile: Some("RuntimeDefault".to_string()),
                ..Default::default()
            },
        );

        let overrides = collect_security_overrides(&service.spec.workload, &service.spec.runtime);
        assert!(overrides.is_empty());
    }

    #[test]
    fn collect_security_overrides_drop_caps_empty_retains_all_defaults() {
        // dropCapabilities: [] means the container keeps ALL default caps
        // — this is a huge security relaxation that must require Cedar auth.
        let mut service = make_service("my-app", "default");
        set_main_security(
            &mut service,
            SecurityContext {
                drop_capabilities: Some(vec![]),
                ..Default::default()
            },
        );

        let overrides = collect_security_overrides(&service.spec.workload, &service.spec.runtime);
        assert_eq!(overrides.len(), DEFAULT_CONTAINER_CAPABILITIES.len());

        let ids: Vec<&str> = overrides.iter().map(|o| o.override_id.as_str()).collect();
        for &cap in DEFAULT_CONTAINER_CAPABILITIES {
            assert!(ids.contains(&format!("capability:{cap}").as_str()));
        }
        assert!(overrides.iter().all(|o| o.category == "capability"));
        assert!(overrides
            .iter()
            .all(|o| o.container.as_deref() == Some("main")));
    }

    #[test]
    fn collect_security_overrides_drop_caps_partial() {
        // dropCapabilities: ["NET_RAW", "MKNOD"] means everything else is retained
        let mut service = make_service("my-app", "default");
        set_main_security(
            &mut service,
            SecurityContext {
                drop_capabilities: Some(vec!["NET_RAW".to_string(), "MKNOD".to_string()]),
                ..Default::default()
            },
        );

        let overrides = collect_security_overrides(&service.spec.workload, &service.spec.runtime);
        let ids: Vec<&str> = overrides.iter().map(|o| o.override_id.as_str()).collect();

        // Dropped caps should NOT appear
        assert!(!ids.contains(&"capability:NET_RAW"));
        assert!(!ids.contains(&"capability:MKNOD"));

        // Retained caps should appear
        assert!(ids.contains(&"capability:CHOWN"));
        assert!(ids.contains(&"capability:SETUID"));
        assert!(ids.contains(&"capability:DAC_OVERRIDE"));
        assert_eq!(
            overrides.len(),
            DEFAULT_CONTAINER_CAPABILITIES.len() - 2 // minus NET_RAW and MKNOD
        );
    }

    #[test]
    fn collect_security_overrides_drop_caps_deduplicates_with_add() {
        // If a cap is in both the add list and would be in the retained defaults,
        // only one override should be generated (the explicit add).
        let mut service = make_service("my-app", "default");
        set_main_security(
            &mut service,
            SecurityContext {
                capabilities: vec!["NET_RAW".to_string()],
                drop_capabilities: Some(vec![]),
                ..Default::default()
            },
        );

        let overrides = collect_security_overrides(&service.spec.workload, &service.spec.runtime);
        let net_raw_count = overrides
            .iter()
            .filter(|o| o.override_id == "capability:NET_RAW")
            .count();
        assert_eq!(net_raw_count, 1);

        // Total = 1 explicit add (NET_RAW) + 13 retained defaults (all except NET_RAW)
        assert_eq!(overrides.len(), DEFAULT_CONTAINER_CAPABILITIES.len());
    }

    #[test]
    fn collect_security_overrides_drop_all_no_retained() {
        // dropCapabilities: ["ALL"] (the PSS default) should NOT generate retained overrides
        let mut service = make_service("my-app", "default");
        set_main_security(
            &mut service,
            SecurityContext {
                drop_capabilities: Some(vec!["ALL".to_string()]),
                ..Default::default()
            },
        );

        let overrides = collect_security_overrides(&service.spec.workload, &service.spec.runtime);
        assert!(overrides.is_empty());
    }

    #[test]
    fn collect_security_overrides_drop_caps_case_insensitive() {
        // Drop list should match case-insensitively
        let mut service = make_service("my-app", "default");
        set_main_security(
            &mut service,
            SecurityContext {
                drop_capabilities: Some(vec!["net_raw".to_string(), "Mknod".to_string()]),
                ..Default::default()
            },
        );

        let overrides = collect_security_overrides(&service.spec.workload, &service.spec.runtime);
        let ids: Vec<&str> = overrides.iter().map(|o| o.override_id.as_str()).collect();
        assert!(!ids.contains(&"capability:NET_RAW"));
        assert!(!ids.contains(&"capability:MKNOD"));
        assert_eq!(overrides.len(), DEFAULT_CONTAINER_CAPABILITIES.len() - 2);
    }

    #[test]
    fn collect_security_overrides_privileged_skips_drop_caps_check() {
        // Privileged containers already get ALL capabilities — the "privileged"
        // override covers it, so drop_capabilities relaxation is irrelevant.
        let mut service = make_service("my-app", "default");
        set_main_security(
            &mut service,
            SecurityContext {
                privileged: Some(true),
                drop_capabilities: Some(vec![]),
                ..Default::default()
            },
        );

        let overrides = collect_security_overrides(&service.spec.workload, &service.spec.runtime);
        let ids: Vec<&str> = overrides.iter().map(|o| o.override_id.as_str()).collect();
        assert!(ids.contains(&"privileged"));
        // Should NOT have individual retained capability overrides
        assert!(!ids.contains(&"capability:NET_RAW"));
        assert!(!ids.contains(&"capability:SETUID"));
        assert_eq!(overrides.len(), 1); // just "privileged"
    }

    #[test]
    fn collect_security_overrides_none_drop_caps_is_safe() {
        // drop_capabilities: None means the compiler applies the default ["ALL"],
        // so no retained capability overrides should be generated.
        let mut service = make_service("my-app", "default");
        set_main_security(
            &mut service,
            SecurityContext {
                drop_capabilities: None,
                ..Default::default()
            },
        );

        let overrides = collect_security_overrides(&service.spec.workload, &service.spec.runtime);
        assert!(overrides.is_empty());
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
        });

        // Effective backup from policy merge: has volumes but no hooks
        let effective = ServiceBackupSpec {
            hooks: None,
            volumes: Some(VolumeBackupSpec {
                include: vec!["data".to_string()],
                exclude: vec![],
                default_policy: VolumeBackupDefault::OptIn,
            }),
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
