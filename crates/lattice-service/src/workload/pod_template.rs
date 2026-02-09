//! Pod template compiler — shared pod template compilation from WorkloadSpec
//!
//! Extracts the reusable core that compiles a `WorkloadSpec` into K8s pod template
//! components. Used by LatticeService (Deployment), LatticeJob (VCJob tasks),
//! and LatticeModel (ModelServing roles).

use std::collections::BTreeMap;

use crate::crd::{GpuParams, ProviderType, RuntimeSpec, WorkloadSpec};

use super::error::CompilationError;
use super::volume::GeneratedVolumes;
use super::{
    AppArmorProfile, Capabilities, Container, ContainerCompilationData, ContainerPort, EnvVar,
    K8sSecurityContext, LabelSelector, LocalObjectReference, PodSecurityContext, ResourceQuantity,
    ResourceRequirements, SeccompProfile, Sysctl, Volume,
};
use super::{
    gpu_shm_volume, gpu_tolerations, image_pull_policy, merge_gpu_resources,
    SecretRef, TopologySpreadConstraint,
};

/// Compiled pod template — all the fields needed to build a K8s PodTemplateSpec.
///
/// This is the reusable output from `PodTemplateCompiler::compile()`.
/// Each CRD compiler wraps this in its own outer resource type.
pub struct CompiledPodTemplate {
    pub containers: Vec<Container>,
    pub init_containers: Vec<Container>,
    pub volumes: Vec<Volume>,
    pub labels: BTreeMap<String, String>,
    pub service_account_name: String,
    pub affinity: Option<super::volume::Affinity>,
    pub security_context: Option<PodSecurityContext>,
    pub host_network: Option<bool>,
    pub share_process_namespace: Option<bool>,
    pub topology_spread_constraints: Vec<TopologySpreadConstraint>,
    pub node_selector: Option<BTreeMap<String, String>>,
    pub tolerations: Vec<super::Toleration>,
    pub runtime_class_name: Option<String>,
    pub scheduling_gates: Vec<super::SchedulingGate>,
    pub image_pull_secrets: Vec<LocalObjectReference>,
}

/// Shared pod template compiler.
///
/// Compiles a `WorkloadSpec` into pod template components that are reusable
/// across LatticeService, LatticeJob, and LatticeModel.
pub struct PodTemplateCompiler;

impl PodTemplateCompiler {
    /// Compile a WorkloadSpec into a complete pod template.
    ///
    /// This is the shared core used by all CRD compilers. It handles:
    /// - Container compilation (image, env, ports, probes, security, volume mounts)
    /// - Sidecar compilation (init + regular containers)
    /// - Pod-level security context
    /// - Volume assembly (PVC, emptyDir, file volumes, GPU SHM)
    /// - Topology spread, GPU tolerations/node selector
    /// - imagePullSecrets resolution
    pub fn compile(
        name: &str,
        workload: &WorkloadSpec,
        runtime: &RuntimeSpec,
        volumes: &GeneratedVolumes,
        provider_type: ProviderType,
        container_data: &ContainerCompilationData<'_>,
    ) -> Result<CompiledPodTemplate, CompilationError> {
        // Extract GPU params from resources (find the `type: gpu` resource)
        let gpu = Self::extract_gpu(workload);
        let gpu_ref = gpu.as_ref();

        // Compile main containers with volume mounts
        let mut containers =
            Self::compile_containers(workload, gpu_ref, volumes, container_data)?;

        // Compile sidecars (init + regular)
        let (init_containers, sidecar_containers) = Self::compile_sidecars(runtime, volumes);

        // Merge sidecar containers with main containers
        containers.extend(sidecar_containers);

        // Build pod labels
        let mut labels = BTreeMap::new();
        labels.insert(lattice_common::LABEL_NAME.to_string(), name.to_string());
        labels.insert(
            lattice_common::LABEL_MANAGED_BY.to_string(),
            lattice_common::LABEL_MANAGED_BY_LATTICE.to_string(),
        );

        // Add volume ownership labels (for RWO affinity)
        for (k, v) in &volumes.pod_labels {
            labels.insert(k.clone(), v.clone());
        }

        // Build pod volumes from PVCs and emptyDir
        let mut pod_volumes: Vec<Volume> = volumes
            .volumes
            .iter()
            .map(|pv| Volume {
                name: pv.name.clone(),
                config_map: None,
                secret: None,
                empty_dir: pv.empty_dir.clone(),
                persistent_volume_claim: pv.persistent_volume_claim.clone(),
            })
            .collect();

        // Add SHM volume for GPU pods
        if let Some((shm_vol, _)) = gpu_shm_volume(gpu_ref) {
            pod_volumes.push(shm_vol);
        }

        // Add file volumes from files::compile (deduplicate by name)
        let existing_vol_names: std::collections::HashSet<_> =
            pod_volumes.iter().map(|v| v.name.clone()).collect();
        for file_vols in container_data.per_container_file_volumes.values() {
            for vol in file_vols {
                if !existing_vol_names.contains(&vol.name) {
                    pod_volumes.push(vol.clone());
                }
            }
        }

        // Compile pod-level security context (always returns secure defaults)
        let security_context = Some(Self::compile_pod_security_context(runtime));

        // Resolve imagePullSecrets from spec resource names to K8s Secret names
        let image_pull_secrets =
            Self::compile_image_pull_secrets(runtime, workload, container_data.secret_refs)?;

        Ok(CompiledPodTemplate {
            containers,
            init_containers,
            volumes: pod_volumes,
            labels,
            service_account_name: name.to_string(),
            affinity: volumes.affinity.clone(),
            security_context,
            host_network: runtime.host_network,
            share_process_namespace: runtime.share_process_namespace,
            topology_spread_constraints: vec![TopologySpreadConstraint {
                max_skew: 1,
                topology_key: provider_type.topology_spread_key().to_string(),
                when_unsatisfiable: "ScheduleAnyway".to_string(),
                label_selector: LabelSelector {
                    match_labels: {
                        let mut labels = BTreeMap::new();
                        labels.insert(
                            lattice_common::LABEL_NAME.to_string(),
                            name.to_string(),
                        );
                        labels
                    },
                },
            }],
            node_selector: gpu_ref.and_then(|g| g.node_selector()),
            tolerations: gpu_tolerations(gpu_ref),
            runtime_class_name: gpu_ref.map(|_| "nvidia".to_string()),
            scheduling_gates: volumes.scheduling_gates.clone(),
            image_pull_secrets,
        })
    }

    /// Extract GPU params from workload resources.
    fn extract_gpu(workload: &WorkloadSpec) -> Option<GpuParams> {
        workload
            .resources
            .values()
            .find(|r| r.type_.is_gpu())
            .and_then(|r| r.gpu_params().ok().flatten())
    }

    /// Compile containers from a WorkloadSpec using rendered container data
    pub fn compile_containers(
        workload: &WorkloadSpec,
        gpu: Option<&GpuParams>,
        volumes: &GeneratedVolumes,
        container_data: &ContainerCompilationData<'_>,
    ) -> Result<Vec<Container>, CompilationError> {
        workload
            .containers
            .iter()
            .enumerate()
            .map(|(idx, (container_name, container_spec))| {
                let rendered = container_data.rendered_containers.get(container_name);

                // Build secret env vars from rendered secret_variables
                let env = if let Some(rc) = rendered {
                    Self::compile_secret_env_vars(
                        container_name,
                        &rc.secret_variables,
                        container_data.secret_refs,
                        &workload.resources,
                    )?
                } else {
                    vec![]
                };

                // EnvFrom refs from env::compile (ConfigMap/Secret for non-secret vars)
                let env_from = container_data
                    .per_container_env_from
                    .get(container_name)
                    .cloned()
                    .unwrap_or_default();

                // Use rendered image if available, fall back to spec
                let image = rendered
                    .map(|rc| rc.image.clone())
                    .unwrap_or_else(|| container_spec.image.clone());

                // Use rendered command/args if available
                let command = rendered
                    .and_then(|rc| rc.command.clone())
                    .or_else(|| container_spec.command.clone());
                let args = rendered
                    .and_then(|rc| rc.args.clone())
                    .or_else(|| container_spec.args.clone());

                // Get ports from service spec
                let ports: Vec<ContainerPort> = workload
                    .service
                    .as_ref()
                    .map(|svc| {
                        svc.ports
                            .iter()
                            .map(|(port_name, port_spec)| ContainerPort {
                                name: Some(port_name.clone()),
                                container_port: port_spec.target_port.unwrap_or(port_spec.port),
                                protocol: port_spec.protocol.clone(),
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                // Convert resources
                let resources = container_spec
                    .resources
                    .as_ref()
                    .map(|r| ResourceRequirements {
                        requests: r.requests.as_ref().map(|req| ResourceQuantity {
                            cpu: req.cpu.clone(),
                            memory: req.memory.clone(),
                            ..Default::default()
                        }),
                        limits: r.limits.as_ref().map(|lim| ResourceQuantity {
                            cpu: lim.cpu.clone(),
                            memory: lim.memory.clone(),
                            ..Default::default()
                        }),
                    });

                // Merge GPU resources into limits (first container only)
                let resources = if idx == 0 {
                    merge_gpu_resources(resources, gpu)
                } else {
                    resources
                };

                // Convert probes using helper
                let liveness_probe = container_spec
                    .liveness_probe
                    .as_ref()
                    .map(Self::compile_probe);
                let readiness_probe = container_spec
                    .readiness_probe
                    .as_ref()
                    .map(Self::compile_probe);
                let startup_probe = container_spec
                    .startup_probe
                    .as_ref()
                    .map(Self::compile_probe);

                // Get volume mounts for this container (PVC volumes)
                let mut volume_mounts = volumes
                    .volume_mounts
                    .get(container_name)
                    .cloned()
                    .unwrap_or_default();

                // Add file volume mounts from files::compile
                if let Some(file_mounts) =
                    container_data.per_container_file_mounts.get(container_name)
                {
                    volume_mounts.extend(file_mounts.iter().cloned());
                }

                // Add SHM volume mount for GPU pods (first container only)
                if idx == 0 {
                    if let Some((_, shm_mount)) = gpu_shm_volume(gpu) {
                        volume_mounts.push(shm_mount);
                    }
                }

                // Compile security context (always returns secure defaults)
                let security_context =
                    Self::compile_security_context(container_spec.security.as_ref());

                Ok(Container {
                    name: container_name.clone(),
                    image_pull_policy: Some(image_pull_policy(&image)),
                    image,
                    command,
                    args,
                    env,
                    env_from,
                    ports,
                    resources,
                    liveness_probe,
                    readiness_probe,
                    startup_probe,
                    volume_mounts,
                    security_context: Some(security_context),
                })
            })
            .collect()
    }

    /// Compile `${secret.RESOURCE.KEY}` references into K8s `secretKeyRef` env vars
    fn compile_secret_env_vars(
        container_name: &str,
        secret_variables: &BTreeMap<String, lattice_common::template::SecretVariableRef>,
        secret_refs: &BTreeMap<String, SecretRef>,
        resources: &BTreeMap<String, crate::crd::ResourceSpec>,
    ) -> Result<Vec<EnvVar>, CompilationError> {
        let mut env = Vec::with_capacity(secret_variables.len());
        for (var_name, secret_var) in secret_variables {
            let resource = resources.get(&secret_var.resource_name).ok_or_else(|| {
                CompilationError::container(
                    container_name,
                    format!(
                        "variable '{}' references secret resource '{}' which does not exist",
                        var_name, secret_var.resource_name
                    ),
                )
            })?;

            if !resource.is_secret() {
                return Err(CompilationError::container(
                    container_name,
                    format!(
                        "variable '{}' references resource '{}' via ${{secret.*}} but it is type '{}', not 'secret'",
                        var_name, secret_var.resource_name, resource.type_
                    ),
                ));
            }

            let secret_ref = secret_refs.get(&secret_var.resource_name).ok_or_else(|| {
                CompilationError::container(
                    container_name,
                    format!(
                        "variable '{}' references secret resource '{}' but no SecretRef was compiled (missing vault path or params?)",
                        var_name, secret_var.resource_name
                    ),
                )
            })?;

            if let Some(ref keys) = secret_ref.keys {
                if !keys.contains(&secret_var.key) {
                    return Err(CompilationError::container(
                        container_name,
                        format!(
                            "variable '{}' references key '{}' in secret '{}' but available keys are: {:?}",
                            var_name, secret_var.key, secret_var.resource_name, keys
                        ),
                    ));
                }
            }

            env.push(EnvVar::from_secret(
                var_name,
                &secret_ref.secret_name,
                &secret_var.key,
            ));
        }
        Ok(env)
    }

    /// Compile a Score-compliant Probe to a K8s ProbeSpec
    pub fn compile_probe(p: &crate::crd::Probe) -> super::ProbeSpec {
        super::ProbeSpec {
            http_get: p.http_get.as_ref().map(|h| super::HttpGetAction {
                path: h.path.clone(),
                port: h.port,
                scheme: h.scheme.clone(),
                host: h.host.clone(),
                http_headers: h.http_headers.as_ref().map(|headers| {
                    headers
                        .iter()
                        .map(|hdr| super::HttpHeader {
                            name: hdr.name.clone(),
                            value: hdr.value.clone(),
                        })
                        .collect()
                }),
            }),
            exec: p.exec.as_ref().map(|e| super::ExecAction {
                command: e.command.clone(),
            }),
        }
    }

    /// Compile a CRD SecurityContext to a K8s SecurityContext with PSS restricted defaults.
    pub fn compile_security_context(
        security: Option<&crate::crd::SecurityContext>,
    ) -> K8sSecurityContext {
        let default = crate::crd::SecurityContext::default();
        let s = security.unwrap_or(&default);

        let is_privileged = s.privileged == Some(true);

        let capabilities = if is_privileged && s.capabilities.is_empty() {
            None
        } else {
            Some(Capabilities {
                add: if s.capabilities.is_empty() {
                    None
                } else {
                    Some(s.capabilities.clone())
                },
                drop: if is_privileged {
                    None
                } else {
                    Some(
                        s.drop_capabilities
                            .clone()
                            .unwrap_or_else(|| vec!["ALL".to_string()]),
                    )
                },
            })
        };

        let run_as_non_root = if s.run_as_user == Some(0) {
            Some(s.run_as_non_root.unwrap_or(false))
        } else {
            Some(s.run_as_non_root.unwrap_or(true))
        };

        let allow_privilege_escalation = if is_privileged {
            s.allow_privilege_escalation
        } else {
            Some(s.allow_privilege_escalation.unwrap_or(false))
        };

        let seccomp_profile = Some(SeccompProfile {
            type_: s
                .seccomp_profile
                .clone()
                .unwrap_or_else(|| "RuntimeDefault".to_string()),
            localhost_profile: s.seccomp_localhost_profile.clone(),
        });

        let app_armor_profile = Some(AppArmorProfile {
            type_: s
                .apparmor_profile
                .clone()
                .unwrap_or_else(|| "RuntimeDefault".to_string()),
            localhost_profile: s.apparmor_localhost_profile.clone(),
        });

        K8sSecurityContext {
            capabilities,
            privileged: s.privileged,
            read_only_root_filesystem: Some(s.read_only_root_filesystem.unwrap_or(true)),
            run_as_non_root,
            run_as_user: s.run_as_user,
            run_as_group: s.run_as_group,
            allow_privilege_escalation,
            seccomp_profile,
            app_armor_profile,
        }
    }

    /// Compile pod-level security context with secure defaults.
    pub fn compile_pod_security_context(runtime: &RuntimeSpec) -> PodSecurityContext {
        let sysctls = if runtime.sysctls.is_empty() {
            None
        } else {
            Some(
                runtime
                    .sysctls
                    .iter()
                    .map(|(name, value)| Sysctl {
                        name: name.clone(),
                        value: value.clone(),
                    })
                    .collect(),
            )
        };

        PodSecurityContext {
            run_as_non_root: Some(true),
            fs_group: Some(65534),
            fs_group_change_policy: Some("OnRootMismatch".to_string()),
            seccomp_profile: Some(SeccompProfile {
                type_: "RuntimeDefault".to_string(),
                localhost_profile: None,
            }),
            sysctls,
        }
    }

    /// Compile sidecars into init containers and regular sidecar containers
    fn compile_sidecars(
        runtime: &RuntimeSpec,
        volumes: &GeneratedVolumes,
    ) -> (Vec<Container>, Vec<Container>) {
        let mut init_containers = Vec::new();
        let mut sidecar_containers = Vec::new();

        for (sidecar_name, sidecar_spec) in &runtime.sidecars {
            let env: Vec<EnvVar> = sidecar_spec
                .variables
                .iter()
                .map(|(k, v)| EnvVar::literal(k, v.to_string()))
                .collect();

            let resources = sidecar_spec
                .resources
                .as_ref()
                .map(|r| ResourceRequirements {
                    requests: r.requests.as_ref().map(|req| ResourceQuantity {
                        cpu: req.cpu.clone(),
                        memory: req.memory.clone(),
                        ..Default::default()
                    }),
                    limits: r.limits.as_ref().map(|lim| ResourceQuantity {
                        cpu: lim.cpu.clone(),
                        memory: lim.memory.clone(),
                        ..Default::default()
                    }),
                });

            let is_init = sidecar_spec.init.unwrap_or(false);
            let (liveness_probe, readiness_probe, startup_probe) = if is_init {
                (None, None, None)
            } else {
                (
                    sidecar_spec
                        .liveness_probe
                        .as_ref()
                        .map(Self::compile_probe),
                    sidecar_spec
                        .readiness_probe
                        .as_ref()
                        .map(Self::compile_probe),
                    sidecar_spec.startup_probe.as_ref().map(Self::compile_probe),
                )
            };

            let volume_mounts = volumes
                .volume_mounts
                .get(sidecar_name)
                .cloned()
                .unwrap_or_default();

            let security_context = Self::compile_security_context(sidecar_spec.security.as_ref());

            let container = Container {
                name: sidecar_name.clone(),
                image_pull_policy: Some(image_pull_policy(&sidecar_spec.image)),
                image: sidecar_spec.image.clone(),
                command: sidecar_spec.command.clone(),
                args: sidecar_spec.args.clone(),
                env,
                env_from: vec![],
                ports: vec![],
                resources,
                liveness_probe,
                readiness_probe,
                startup_probe,
                volume_mounts,
                security_context: Some(security_context),
            };

            if is_init {
                init_containers.push(container);
            } else {
                sidecar_containers.push(container);
            }
        }

        (init_containers, sidecar_containers)
    }

    /// Resolve `imagePullSecrets` resource names to K8s Secret names
    pub fn compile_image_pull_secrets(
        runtime: &RuntimeSpec,
        workload: &WorkloadSpec,
        secret_refs: &BTreeMap<String, SecretRef>,
    ) -> Result<Vec<LocalObjectReference>, CompilationError> {
        runtime
            .image_pull_secrets
            .iter()
            .map(|resource_name| {
                let resource = workload.resources.get(resource_name).ok_or_else(|| {
                    CompilationError::resource(
                        resource_name,
                        format!(
                            "imagePullSecrets references resource '{}' which does not exist",
                            resource_name
                        ),
                    )
                })?;

                if !resource.is_secret() {
                    return Err(CompilationError::resource(
                        resource_name,
                        format!(
                            "imagePullSecrets references resource '{}' but it is type '{}', not 'secret'",
                            resource_name, resource.type_
                        ),
                    ));
                }

                let secret_ref = secret_refs.get(resource_name).ok_or_else(|| {
                    CompilationError::resource(
                        resource_name,
                        format!(
                            "imagePullSecrets references resource '{}' but no SecretRef was compiled",
                            resource_name
                        ),
                    )
                })?;

                Ok(LocalObjectReference {
                    name: secret_ref.secret_name.clone(),
                })
            })
            .collect()
    }
}
