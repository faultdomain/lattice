//! WorkloadCompiler — orchestrates the full compilation pipeline
//!
//! This is the single entry point for compiling a `WorkloadSpec` into Kubernetes
//! primitives. CRD-specific crates (lattice-service, lattice-job, lattice-kthena)
//! call this compiler and wrap the output in their own resource types.

use std::collections::BTreeMap;

use lattice_cedar::PolicyEngine;
use lattice_common::crd::{
    EgressRule, EgressTarget, IngressSpec, LatticeMeshMember, LatticeMeshMemberSpec,
    MeshMemberPort, MeshMemberTarget, PeerAuth, ProviderType, RuntimeSpec, WorkloadSpec,
};
use lattice_common::graph::ServiceGraph;
use lattice_common::kube_utils::{LabelSelector, OwnerReference};
use lattice_common::mesh;
use lattice_common::template::{RenderConfig, TemplateRenderer};
use lattice_common::LABEL_NAME;

use crate::authorization::VolumeAuthorizationMode;
use crate::compiled::{CompiledConfig, CompiledWorkload};
use crate::error::CompilationError;
use crate::helpers::{compute_config_hash, ContainerCompilationData};
use crate::k8s::{EnvFromSource, SecretEnvSource};
use crate::pipeline::eso_templated::compile_eso_templated_env_vars;
use crate::pipeline::volumes::VolumeCompiler;
use crate::pipeline::{env, files, pod_template::PodTemplateCompiler, secrets::SecretsCompiler};

/// Orchestrates compilation of a `WorkloadSpec` into Kubernetes resources.
///
/// Uses a builder pattern for optional features:
///
/// ```rust,ignore
/// let compiled = WorkloadCompiler::new(name, namespace, "service", workload, runtime, provider_type, cedar)
///     .with_cluster_name(cluster_name)
///     .with_volume_authorization(VolumeAuthorizationMode::Full { graph })
///     .with_annotations(&annotations)
///     .compile()
///     .await?;
/// ```
pub struct WorkloadCompiler<'a> {
    name: &'a str,
    namespace: &'a str,
    kind: &'a str,
    workload: &'a WorkloadSpec,
    runtime: &'a RuntimeSpec,
    provider_type: ProviderType,
    cedar: &'a PolicyEngine,
    cluster_name: Option<&'a str>,
    volume_auth: Option<VolumeAuthorizationMode<'a>>,
    annotations: BTreeMap<String, String>,
    image_pull_secrets: &'a [String],
    renderer: TemplateRenderer,
    graph: Option<&'a ServiceGraph>,
    ingress: Option<IngressSpec>,
    owner_references: Vec<OwnerReference>,
    has_topology: bool,
    eso_content_hash: String,
    quotas: &'a [lattice_common::crd::LatticeQuota],
    replicas: u32,
    namespace_labels: std::collections::BTreeMap<String, String>,
    workload_annotations: std::collections::BTreeMap<String, String>,
}

impl<'a> WorkloadCompiler<'a> {
    /// Create a new WorkloadCompiler with required parameters.
    ///
    /// Cedar is required — authorization cannot be bypassed.
    /// `kind` identifies the workload type ("service", "job", "model") for
    /// Cedar policy evaluation.
    pub fn new(
        name: &'a str,
        namespace: &'a str,
        kind: &'a str,
        workload: &'a WorkloadSpec,
        runtime: &'a RuntimeSpec,
        provider_type: ProviderType,
        cedar: &'a PolicyEngine,
    ) -> Self {
        Self {
            name,
            namespace,
            kind,
            workload,
            runtime,
            provider_type,
            cedar,
            cluster_name: None,
            volume_auth: None,
            annotations: BTreeMap::new(),
            image_pull_secrets: &[],
            renderer: TemplateRenderer::new(),
            graph: None,
            ingress: None,
            owner_references: Vec::new(),
            has_topology: false,
            eso_content_hash: String::new(),
            quotas: &[],
            replicas: 1,
            namespace_labels: std::collections::BTreeMap::new(),
            workload_annotations: std::collections::BTreeMap::new(),
        }
    }

    /// Set cluster name for template resolution.
    pub fn with_cluster_name(mut self, cluster_name: &'a str) -> Self {
        self.cluster_name = Some(cluster_name);
        self
    }

    /// Set volume authorization mode.
    pub fn with_volume_authorization(mut self, mode: VolumeAuthorizationMode<'a>) -> Self {
        self.volume_auth = Some(mode);
        self
    }

    /// Set annotations for template resolution context.
    pub fn with_annotations(mut self, annotations: &BTreeMap<String, String>) -> Self {
        self.annotations = annotations.clone();
        self
    }

    /// Set image pull secret names for ESO dockerconfigjson inference.
    pub fn with_image_pull_secrets(mut self, secrets: &'a [String]) -> Self {
        self.image_pull_secrets = secrets;
        self
    }

    /// Set service graph for template resolution.
    pub fn with_graph(mut self, graph: &'a ServiceGraph) -> Self {
        self.graph = Some(graph);
        self
    }

    /// Set ingress configuration for the mesh member.
    pub fn with_ingress(mut self, ingress: Option<IngressSpec>) -> Self {
        self.ingress = ingress;
        self
    }

    /// Set owner references for generated PVCs (GC cascading).
    pub fn with_owner_references(mut self, refs: Vec<OwnerReference>) -> Self {
        self.owner_references = refs;
        self
    }

    /// Mark this workload as having topology-aware scheduling.
    ///
    /// When set, the pod template uses the Volcano scheduler (`schedulerName: "volcano"`)
    /// even if no GPU is present. The actual topology configuration (mode, maxTier) is
    /// handled at the CRD-specific level (VCJob, ModelServing, Service PodGroup).
    pub fn with_topology(mut self) -> Self {
        self.has_topology = true;
        self
    }

    /// Set the ESO content hash for triggering rollouts on secret rotation.
    pub fn with_eso_content_hash(mut self, hash: String) -> Self {
        self.eso_content_hash = hash;
        self
    }

    /// Set quota list and workload identity for quota enforcement.
    pub fn with_quotas(
        mut self,
        quotas: &'a [lattice_common::crd::LatticeQuota],
        replicas: u32,
        namespace_labels: std::collections::BTreeMap<String, String>,
        workload_annotations: std::collections::BTreeMap<String, String>,
    ) -> Self {
        self.quotas = quotas;
        self.replicas = replicas;
        self.namespace_labels = namespace_labels;
        self.workload_annotations = workload_annotations;
        self
    }

    /// Compile files for a container/sidecar and collect outputs into the accumulator vecs.
    #[allow(clippy::too_many_arguments)]
    fn collect_compiled_files(
        service_name: &str,
        container_name: &str,
        namespace: &str,
        rendered_files: &BTreeMap<String, lattice_common::template::RenderedFile>,
        secret_refs: &BTreeMap<String, crate::pipeline::secrets::SecretRef>,
        files_config_maps: &mut Vec<crate::k8s::ConfigMap>,
        files_secrets: &mut Vec<crate::k8s::Secret>,
        file_external_secrets: &mut Vec<lattice_secret_provider::eso::ExternalSecret>,
        per_container_file_volumes: &mut BTreeMap<String, Vec<crate::k8s::Volume>>,
        per_container_file_mounts: &mut BTreeMap<String, Vec<crate::k8s::VolumeMount>>,
    ) -> Result<(), CompilationError> {
        let compiled = files::compile(
            service_name,
            container_name,
            namespace,
            rendered_files,
            secret_refs,
        )?;

        if let Some(cm) = compiled.config_map {
            files_config_maps.push(cm);
        }
        if let Some(secret) = compiled.secret {
            files_secrets.push(secret);
        }
        file_external_secrets.extend(compiled.file_external_secrets);
        per_container_file_volumes.insert(container_name.to_string(), compiled.volumes);
        per_container_file_mounts.insert(container_name.to_string(), compiled.volume_mounts);
        Ok(())
    }

    /// Compile the workload spec into Kubernetes primitives.
    ///
    /// Runs the full pipeline: volumes → secrets → authorization (Cedar) →
    /// template rendering → env/file compilation → pod template → config hash.
    pub async fn compile(self) -> Result<CompiledWorkload, CompilationError> {
        // Compile volumes
        let compiled_volumes = VolumeCompiler::compile(
            self.name,
            self.namespace,
            self.workload,
            &self.runtime.sidecars,
            &self.owner_references,
        )?;

        // Compile secrets
        let compiled_secrets = SecretsCompiler::compile(
            self.name,
            self.namespace,
            self.workload,
            self.image_pull_secrets,
        )?;

        // Quota enforcement — check resource limits before authorization
        if !self.quotas.is_empty() {
            lattice_quota::enforcement::enforce_quotas(
                self.quotas,
                self.name,
                self.namespace,
                &self.namespace_labels,
                &self.workload_annotations,
                self.workload,
                self.replicas,
            )
            .map_err(|e| CompilationError::quota_exceeded(e.to_string()))?;
        }

        // Authorization — Cedar is always enforced
        crate::authorization::secrets::authorize_secrets(
            self.cedar,
            self.name,
            self.namespace,
            self.kind,
            self.workload,
        )
        .await?;

        let has_volume_refs = !self.workload.referenced_volume_ids().is_empty();
        if has_volume_refs && self.volume_auth.is_none() {
            return Err(CompilationError::missing_metadata(
                "volume authorization mode must be set for workloads with volume references",
            ));
        }
        if let Some(ref volume_auth) = self.volume_auth {
            match volume_auth {
                VolumeAuthorizationMode::Full { graph } => {
                    crate::authorization::volumes::authorize_volumes(
                        self.cedar,
                        graph,
                        self.name,
                        self.namespace,
                        self.kind,
                        self.workload,
                    )
                    .await?;
                }
                VolumeAuthorizationMode::CedarOnly => {
                    crate::authorization::volumes::authorize_volumes_cedar_only(
                        self.cedar,
                        self.name,
                        self.namespace,
                        self.kind,
                        self.workload,
                    )
                    .await?;
                }
            }
        }

        crate::authorization::security::authorize_security_overrides(
            self.cedar,
            self.name,
            self.namespace,
            self.kind,
            self.workload,
            self.runtime,
        )
        .await?;

        crate::authorization::external_endpoints::authorize_external_endpoints(
            self.cedar,
            self.name,
            self.namespace,
            self.kind,
            self.workload,
        )
        .await?;

        // Build template context and render all containers
        let graph = self.graph.ok_or_else(|| {
            CompilationError::missing_metadata("service graph (call .with_graph())")
        })?;
        let mut render_config = RenderConfig::new(graph, self.namespace, self.namespace);
        if let Some(cluster_name) = self.cluster_name {
            render_config = render_config.with_cluster("name", cluster_name);
        }

        let template_ctx = self
            .renderer
            .build_context(self.name, &self.annotations, self.workload, &render_config)
            .map_err(CompilationError::from)?;
        let rendered_containers = self
            .renderer
            .render_all_containers(self.workload, &template_ctx)
            .map_err(CompilationError::from)?;

        // Compile env vars and files per container
        let mut env_config_maps = Vec::new();
        let mut env_secrets = Vec::new();
        let mut files_config_maps = Vec::new();
        let mut files_secrets = Vec::new();
        let mut file_external_secrets = Vec::new();
        let mut per_container_env_from = BTreeMap::new();
        let mut per_container_file_volumes = BTreeMap::new();
        let mut per_container_file_mounts = BTreeMap::new();

        for (container_name, rendered) in &rendered_containers {
            // Compile non-secret env vars
            let compiled_env = env::compile(
                self.name,
                container_name,
                self.namespace,
                &rendered.variables,
            );
            if let Some(cm) = compiled_env.config_map {
                env_config_maps.push(cm);
            }
            if let Some(secret) = compiled_env.secret {
                env_secrets.push(secret);
            }
            let mut container_env_from = compiled_env.env_from;

            // Compile ESO-templated env vars
            if !rendered.eso_templated_variables.is_empty() {
                let (eso_secrets, eso_env_from) = compile_eso_templated_env_vars(
                    self.name,
                    container_name,
                    self.namespace,
                    &rendered.eso_templated_variables,
                    &compiled_secrets.secret_refs,
                )?;
                file_external_secrets.extend(eso_secrets);
                container_env_from.extend(eso_env_from);
            }

            // Resolve env_from secret resource references
            if let Some(container_spec) = self.workload.containers.get(container_name) {
                for resource_name in &container_spec.env_from {
                    let secret_ref = compiled_secrets
                        .secret_refs
                        .get(resource_name.as_str())
                        .ok_or_else(|| {
                            CompilationError::secret(format!(
                                "container '{}' env_from references '{}' which is not a \
                                 type: secret resource",
                                container_name, resource_name
                            ))
                        })?;
                    container_env_from.push(EnvFromSource {
                        config_map_ref: None,
                        secret_ref: Some(SecretEnvSource {
                            name: secret_ref.secret_name.clone(),
                        }),
                    });
                }
            }

            per_container_env_from.insert(container_name.clone(), container_env_from);

            // Compile files
            Self::collect_compiled_files(
                self.name,
                container_name,
                self.namespace,
                &rendered.files,
                &compiled_secrets.secret_refs,
                &mut files_config_maps,
                &mut files_secrets,
                &mut file_external_secrets,
                &mut per_container_file_volumes,
                &mut per_container_file_mounts,
            )?;
        }

        // Compile sidecar files (sidecars use SidecarSpec, not ContainerSpec,
        // so they aren't included in render_all_containers)
        for (sidecar_name, sidecar_spec) in &self.runtime.sidecars {
            if sidecar_spec.files.is_empty() {
                continue;
            }

            let rendered_files = self
                .renderer
                .render_files(&sidecar_spec.files, &template_ctx)
                .map_err(CompilationError::from)?;

            Self::collect_compiled_files(
                self.name,
                sidecar_name,
                self.namespace,
                &rendered_files,
                &compiled_secrets.secret_refs,
                &mut files_config_maps,
                &mut files_secrets,
                &mut file_external_secrets,
                &mut per_container_file_volumes,
                &mut per_container_file_mounts,
            )?;
        }

        // Collect shared volume IDs for pod co-location scheduling.
        // Owners get labels (lattice.io/vol-<id>), consumers get pod affinity matching those labels.
        let owned_volume_ids: Vec<String> = self
            .workload
            .owned_volume_ids()
            .iter()
            .map(|(_, vol_id)| vol_id.to_string())
            .collect();

        // Only add affinity for referenced volumes that have a known different
        // owner in the graph. This ensures the affinity target pod (the owner)
        // actually exists before requiring co-location.
        let referenced_volume_ids: Vec<String> = if let Some(graph) = self.graph {
            self.workload
                .referenced_volume_ids()
                .iter()
                .filter(|(_, vol_id)| {
                    graph
                        .get_volume_owner(self.namespace, vol_id)
                        .is_some_and(|owner| {
                            owner.owner_name != self.name || owner.owner_namespace != self.namespace
                        })
                })
                .map(|(_, vol_id)| vol_id.to_string())
                .collect()
        } else {
            vec![]
        };

        // Compile pod template
        let container_data = ContainerCompilationData {
            secret_refs: &compiled_secrets.secret_refs,
            rendered_containers: &rendered_containers,
            per_container_env_from: &per_container_env_from,
            per_container_file_volumes: &per_container_file_volumes,
            per_container_file_mounts: &per_container_file_mounts,
        };

        let mut pod_template = PodTemplateCompiler::compile(
            self.name,
            self.workload,
            self.runtime,
            &compiled_volumes,
            self.provider_type,
            &container_data,
            self.has_topology,
        )?;

        // Add volume ownership labels for shared volume co-location
        for vol_id in &owned_volume_ids {
            pod_template.labels.insert(
                format!("{}{}", lattice_common::LABEL_VOLUME_PREFIX, vol_id),
                "true".to_string(),
            );
        }

        // Build pod affinity for shared volume co-location.
        // Consumers match the volume ownership label (lattice.io/vol-<id>: true)
        // on the owner's pods, forcing co-location on the same node.
        if !referenced_volume_ids.is_empty() {
            pod_template.affinity = Some(crate::k8s::Affinity {
                pod_affinity: Some(crate::k8s::PodAffinity {
                    required_during_scheduling_ignored_during_execution: referenced_volume_ids
                        .iter()
                        .map(|vol_id| crate::k8s::PodAffinityTerm {
                            label_selector: LabelSelector {
                                match_labels: [(
                                    format!("{}{}", lattice_common::LABEL_VOLUME_PREFIX, vol_id),
                                    "true".to_string(),
                                )]
                                .into_iter()
                                .collect(),
                            },
                            topology_key: "kubernetes.io/hostname".to_string(),
                        })
                        .collect(),
                }),
            });
        }

        // Assemble config and compute hash
        let mut all_external_secrets = compiled_secrets.external_secrets;
        all_external_secrets.extend(file_external_secrets);

        let config = CompiledConfig {
            env_config_maps,
            env_secrets,
            files_config_maps,
            files_secrets,
            pvcs: compiled_volumes.pvcs,
            external_secrets: all_external_secrets,
            secret_refs: compiled_secrets.secret_refs,
        };

        let config_hash = compute_config_hash(
            &config.env_config_maps,
            &config.env_secrets,
            &config.files_config_maps,
            &config.files_secrets,
            &self.eso_content_hash,
        );

        // Build LatticeMeshMember CR for mesh policy delegation.
        //
        // Read allowed_callers and dependencies directly from the WorkloadSpec
        // (the authoritative source) instead of the shared ServiceGraph. The graph
        // can have stale data when the MeshMember controller's crash-recovery
        // `put_mesh_member` races with the LatticeService controller's `put_service`.
        let caller_refs = self.workload.allowed_callers(self.namespace);
        let allows_all = caller_refs.iter().any(|r| r.name == "*");

        let mut allowed_callers: Vec<lattice_common::crd::ServiceRef> = if allows_all {
            vec![lattice_common::crd::ServiceRef::local("*")]
        } else {
            caller_refs
        };
        // Sort for deterministic SSA output
        allowed_callers.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));

        // When the service has ingress routes, the namespace's shared gateway proxy
        // needs to reach the backend. The gateway is registered in the graph by the
        // MeshMember controller (via IngressCompiler), so this forms a bilateral
        // agreement: the gateway has depends_all, this service allows it.
        if self.ingress.as_ref().is_some_and(|i| !i.routes.is_empty()) {
            allowed_callers.push(lattice_common::crd::ServiceRef::local(
                mesh::ingress_gateway_sa_name(self.namespace),
            ));
        }

        let mut dependencies: Vec<lattice_common::crd::ServiceRef> =
            self.workload.internal_dependencies(self.namespace);
        // Sort for deterministic SSA output
        dependencies.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));

        let ports: Vec<MeshMemberPort> = self
            .workload
            .service
            .as_ref()
            .map(|s| {
                s.ports
                    .iter()
                    .map(|(port_name, ps)| MeshMemberPort {
                        port: ps.target_port.unwrap_or(ps.port),
                        service_port: if ps.target_port.is_some() {
                            Some(ps.port)
                        } else {
                            None
                        },
                        name: port_name.clone(),
                        peer_auth: PeerAuth::Strict,
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Detect inline external-service resources and build FQDN egress rules
        // from params.endpoints (the inline endpoint model).
        let inline_egress: Vec<EgressRule> = self
            .workload
            .resources
            .iter()
            .filter(|(_, r)| r.type_.is_external_service() && r.direction.is_outbound())
            .flat_map(|(name, r)| {
                let id = r.id.as_deref().unwrap_or(name);
                // Skip if a same-named internal service exists in the graph
                if graph.get_service(self.namespace, id).is_some() {
                    return vec![];
                }
                // Try entity reference first (entity:name or entity:name:port)
                if let Some(rule) = EgressRule::from_entity_id(id) {
                    return vec![rule];
                }
                // Read endpoints from params.endpoints (inline model)
                if let Some(params) = r.params.as_external_service() {
                    return params
                        .parsed_endpoints()
                        .into_values()
                        .map(|ep| EgressRule {
                            target: EgressTarget::for_host(&ep.host),
                            ports: vec![ep.port],
                            protocol: ep.network_protocol(),
                        })
                        .collect();
                }
                vec![]
            })
            .collect();

        // Every workload gets a MeshMember so it always gets a CNP (at minimum
        // allowing DNS). Ports/dependencies/egress may be empty.
        let mesh_member = Some(LatticeMeshMember::new(
            self.name,
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(
                    [(LABEL_NAME.to_string(), self.name.to_string())]
                        .into_iter()
                        .collect(),
                ),
                ports,
                allowed_callers,
                dependencies,
                egress: inline_egress,
                allow_peer_traffic: false,
                ingress: self.ingress,
                service_account: None,
                depends_all: false,
                ambient: true,
            },
        ));

        Ok(CompiledWorkload {
            pod_template,
            config,
            config_hash,
            mesh_member,
        })
    }
}
