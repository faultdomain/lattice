//! WorkloadCompiler — orchestrates the full compilation pipeline
//!
//! This is the single entry point for compiling a `WorkloadSpec` into Kubernetes
//! primitives. CRD-specific crates (lattice-service, lattice-job, lattice-kthena)
//! call this compiler and wrap the output in their own resource types.

use std::collections::BTreeMap;

use lattice_cedar::PolicyEngine;
use lattice_common::crd::{
    CallerRef, IngressSpec, LatticeMeshMember, LatticeMeshMemberSpec, MeshMemberPort,
    MeshMemberTarget, PeerAuth, ProviderType, RuntimeSpec, WorkloadSpec,
};
use lattice_common::graph::ServiceGraph;
use lattice_common::template::{RenderConfig, TemplateRenderer};
use lattice_common::LABEL_NAME;

use crate::authorization::VolumeAuthorizationMode;
use crate::compiled::{CompiledConfig, CompiledWorkload};
use crate::error::CompilationError;
use crate::helpers::{compute_config_hash, ContainerCompilationData};
use crate::pipeline::eso_templated::compile_eso_templated_env_vars;
use crate::pipeline::volumes::VolumeCompiler;
use crate::pipeline::{env, files, pod_template::PodTemplateCompiler, secrets::SecretsCompiler};

/// Orchestrates compilation of a `WorkloadSpec` into Kubernetes resources.
///
/// Uses a builder pattern for optional features:
///
/// ```rust,ignore
/// let compiled = WorkloadCompiler::new(name, namespace, workload, runtime, provider_type)
///     .with_cedar(cedar)
///     .with_cluster_name(cluster_name)
///     .with_volume_authorization(VolumeAuthorizationMode::Full { graph })
///     .with_annotations(&annotations)
///     .compile()
///     .await?;
/// ```
pub struct WorkloadCompiler<'a> {
    name: &'a str,
    namespace: &'a str,
    workload: &'a WorkloadSpec,
    runtime: &'a RuntimeSpec,
    provider_type: ProviderType,
    cedar: Option<&'a PolicyEngine>,
    cluster_name: Option<&'a str>,
    volume_auth: Option<VolumeAuthorizationMode<'a>>,
    annotations: BTreeMap<String, String>,
    image_pull_secrets: &'a [String],
    renderer: TemplateRenderer,
    graph: Option<&'a ServiceGraph>,
    ingress: Option<IngressSpec>,
}

impl<'a> WorkloadCompiler<'a> {
    /// Create a new WorkloadCompiler with required parameters.
    pub fn new(
        name: &'a str,
        namespace: &'a str,
        workload: &'a WorkloadSpec,
        runtime: &'a RuntimeSpec,
        provider_type: ProviderType,
    ) -> Self {
        Self {
            name,
            namespace,
            workload,
            runtime,
            provider_type,
            cedar: None,
            cluster_name: None,
            volume_auth: None,
            annotations: BTreeMap::new(),
            image_pull_secrets: &[],
            renderer: TemplateRenderer::new(),
            graph: None,
            ingress: None,
        }
    }

    /// Set Cedar policy engine for authorization.
    pub fn with_cedar(mut self, cedar: &'a PolicyEngine) -> Self {
        self.cedar = Some(cedar);
        self
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

    /// Compile the workload spec into Kubernetes primitives.
    ///
    /// Runs the full pipeline: volumes → secrets → authorization (Cedar) →
    /// template rendering → env/file compilation → pod template → config hash.
    pub async fn compile(self) -> Result<CompiledWorkload, CompilationError> {
        // 1. Compile volumes
        let compiled_volumes = VolumeCompiler::compile(
            self.name,
            self.namespace,
            self.workload,
            &self.runtime.sidecars,
        )?;

        // 2. Compile secrets
        let compiled_secrets = SecretsCompiler::compile(
            self.name,
            self.namespace,
            self.workload,
            self.image_pull_secrets,
        )?;

        // 3-5. Authorization (if Cedar is configured)
        if let Some(cedar) = self.cedar {
            crate::authorization::secrets::authorize_secrets(
                cedar,
                &crate::authorization::ServicePrincipal,
                self.name,
                self.namespace,
                self.workload,
            )
            .await?;

            if let Some(ref volume_auth) = self.volume_auth {
                match volume_auth {
                    VolumeAuthorizationMode::Full { graph } => {
                        crate::authorization::volumes::authorize_volumes(
                            cedar,
                            graph,
                            self.name,
                            self.namespace,
                            self.workload,
                        )
                        .await?;
                    }
                    VolumeAuthorizationMode::CedarOnly => {
                        // Skip owner consent, only Cedar policy check
                        // (volumes authorization without graph)
                    }
                }
            }

            crate::authorization::security::authorize_security_overrides(
                cedar,
                self.name,
                self.namespace,
                self.workload,
                self.runtime,
            )
            .await?;
        }

        // 6. Build template context and render all containers
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

        // 7-9. Compile env vars and files per container
        let mut env_config_maps = Vec::new();
        let mut env_secrets = Vec::new();
        let mut files_config_maps = Vec::new();
        let mut files_secrets = Vec::new();
        let mut file_external_secrets = Vec::new();
        let mut per_container_env_from = BTreeMap::new();
        let mut per_container_file_volumes = BTreeMap::new();
        let mut per_container_file_mounts = BTreeMap::new();

        for (container_name, rendered) in &rendered_containers {
            // 7. Compile non-secret env vars
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

            // 8. Compile ESO-templated env vars
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

            per_container_env_from.insert(container_name.clone(), container_env_from);

            // 9. Compile files
            let compiled_files = files::compile(
                self.name,
                container_name,
                self.namespace,
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

        // 10. Compile pod template
        let container_data = ContainerCompilationData {
            secret_refs: &compiled_secrets.secret_refs,
            rendered_containers: &rendered_containers,
            per_container_env_from: &per_container_env_from,
            per_container_file_volumes: &per_container_file_volumes,
            per_container_file_mounts: &per_container_file_mounts,
        };

        let pod_template = PodTemplateCompiler::compile(
            self.name,
            self.workload,
            self.runtime,
            &compiled_volumes,
            self.provider_type,
            &container_data,
        )?;

        // 11. Assemble config and compute hash
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
        );

        // Build LatticeMeshMember CR for mesh policy delegation.
        let service_node = graph.get_service(self.namespace, self.name);
        let mut allowed_callers: Vec<CallerRef> = service_node
            .as_ref()
            .map(|n| {
                n.allowed_callers
                    .iter()
                    .map(|(ns, name)| CallerRef {
                        name: name.clone(),
                        namespace: if ns == self.namespace {
                            None
                        } else {
                            Some(ns.clone())
                        },
                    })
                    .collect()
            })
            .unwrap_or_default();
        // Sort for deterministic SSA output (HashSet iteration order is unstable)
        allowed_callers.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));

        if service_node.as_ref().is_some_and(|n| n.allows_all) {
            allowed_callers = vec![CallerRef {
                name: "*".to_string(),
                namespace: None,
            }];
        }

        let mut dependencies: Vec<lattice_common::crd::ServiceRef> = service_node
            .as_ref()
            .map(|n| {
                n.dependencies
                    .iter()
                    .map(|(ns, name)| lattice_common::crd::ServiceRef {
                        name: name.clone(),
                        namespace: if ns == self.namespace {
                            None
                        } else {
                            Some(ns.clone())
                        },
                    })
                    .collect()
            })
            .unwrap_or_default();
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
                        name: port_name.clone(),
                        peer_auth: PeerAuth::Strict,
                    })
                    .collect()
            })
            .unwrap_or_default();

        let has_mesh_participation = !ports.is_empty() || !dependencies.is_empty();
        let mesh_member = if service_node.is_some() && has_mesh_participation {
            Some(LatticeMeshMember::new(
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
                    egress: vec![],
                    allow_peer_traffic: false,
                    ingress: self.ingress,
                    service_account: None,
                    depends_all: false,
                },
            ))
        } else {
            None
        };

        Ok(CompiledWorkload {
            pod_template,
            config,
            config_hash,
            mesh_member,
        })
    }
}
