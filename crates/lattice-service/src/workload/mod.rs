//! Workload types for Lattice services
//!
//! This module defines service-specific Kubernetes workload resource types:
//! - Deployment: Container orchestration
//! - Service: Network exposure
//! - ServiceAccount: SPIFFE identity for mTLS
//! - ScaledObject: KEDA-based auto-scaling
//! - PodDisruptionBudget: HA protection during node drains
//!
//! Shared types (ConfigMap, Secret, Container, Volume, etc.) come from `lattice_workload::k8s`.
//! The compilation pipeline (env, files, secrets, volumes, pod_template) is in `lattice_workload`.
//!
//! For workload generation, use [`crate::compiler::ServiceCompiler`].

use std::collections::BTreeMap;

use lattice_common::kube_utils::HasApiResource;
use lattice_workload::k8s::{
    ConfigMap, Container, LabelSelector, LocalObjectReference, ObjectMeta, PodSecurityContext,
    SchedulingGate, Secret, TopologySpreadConstraint, Volume,
};
use lattice_workload::{CompilationError, CompiledPodTemplate};
use serde::{Deserialize, Serialize};

// =============================================================================
// Deployment
// =============================================================================

/// Kubernetes Deployment
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Deployment {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Spec
    pub spec: DeploymentSpec,
}

/// Deployment spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentSpec {
    /// Number of replicas
    pub replicas: u32,
    /// Label selector
    pub selector: LabelSelector,
    /// Pod template
    pub template: PodTemplateSpec,
    /// Deployment strategy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<DeploymentStrategy>,
}

/// Deployment strategy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentStrategy {
    /// Strategy type: RollingUpdate or Recreate
    #[serde(rename = "type")]
    pub type_: String,
    /// Rolling update config
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolling_update: Option<RollingUpdateConfig>,
}

/// Rolling update configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RollingUpdateConfig {
    /// Max unavailable pods
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_unavailable: Option<String>,
    /// Max surge pods
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_surge: Option<String>,
}

/// Pod template spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodTemplateSpec {
    /// Pod metadata
    pub metadata: PodMeta,
    /// Pod spec
    pub spec: PodSpec,
}

/// Pod metadata (subset of ObjectMeta)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodMeta {
    /// Labels
    pub labels: BTreeMap<String, String>,
    /// Annotations
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// Pod spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodSpec {
    /// Service account name
    pub service_account_name: String,
    /// Whether to automount the service account token into pods
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automount_service_account_token: Option<bool>,
    /// Containers
    pub containers: Vec<Container>,
    /// Init containers (run before main containers)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub init_containers: Vec<Container>,
    /// Volumes
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<Volume>,
    /// Pod affinity rules (for RWO volume co-location)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affinity: Option<lattice_workload::Affinity>,
    /// Pod-level security context
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_context: Option<PodSecurityContext>,
    /// Use host network namespace
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_network: Option<bool>,
    /// Share PID namespace between containers
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_process_namespace: Option<bool>,
    /// Topology spread constraints for HA
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub topology_spread_constraints: Vec<TopologySpreadConstraint>,
    /// Node selector for scheduling onto specific nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_selector: Option<BTreeMap<String, String>>,
    /// Tolerations for scheduling onto tainted nodes
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tolerations: Vec<lattice_workload::k8s::Toleration>,
    /// Runtime class name (e.g., "nvidia" for GPU workloads)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_class_name: Option<String>,
    /// Scheduling gates — block pod scheduling until gates are removed
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scheduling_gates: Vec<SchedulingGate>,
    /// Image pull secrets for authenticating to private registries
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub image_pull_secrets: Vec<LocalObjectReference>,
    /// Scheduler name (e.g., "volcano" for GPU workloads using Volcano vGPU)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler_name: Option<String>,
}

// =============================================================================
// Service
// =============================================================================

/// Kubernetes Service
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Spec
    pub spec: ServiceSpec,
}

/// Service spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSpec {
    /// Selector
    pub selector: BTreeMap<String, String>,
    /// Ports
    pub ports: Vec<ServicePort>,
    /// Service type
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

/// Service port
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServicePort {
    /// Port name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Port number
    pub port: u16,
    /// Target port
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_port: Option<u16>,
    /// Protocol
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

// =============================================================================
// ServiceAccount
// =============================================================================

/// Kubernetes ServiceAccount
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccount {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Whether to automount the service account token into pods
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automount_service_account_token: Option<bool>,
}

// =============================================================================
// PodDisruptionBudget
// =============================================================================

/// Kubernetes PodDisruptionBudget for ensuring availability during node drains
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodDisruptionBudget {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Spec
    pub spec: PdbSpec,
}

/// PDB spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PdbSpec {
    /// Minimum number of pods that must remain available
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_available: Option<u32>,
    /// Label selector to match pods
    pub selector: LabelSelector,
}

// =============================================================================
// KEDA ScaledObject
// =============================================================================

/// KEDA ScaledObject — manages pod autoscaling via triggers (cpu, memory, prometheus, etc.)
///
/// KEDA creates and manages an HPA under the hood. All autoscaling goes through
/// ScaledObject triggers, giving a single code path for both resource-based
/// (cpu/memory) and custom Prometheus metrics.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScaledObject {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Spec
    pub spec: ScaledObjectSpec,
}

impl HasApiResource for ScaledObject {
    const API_VERSION: &'static str = "keda.sh/v1alpha1";
    const KIND: &'static str = "ScaledObject";
}

/// ScaledObject spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScaledObjectSpec {
    /// Reference to the target Deployment/StatefulSet to scale
    pub scale_target_ref: ScaleTargetRef,
    /// Minimum replica count
    pub min_replica_count: u32,
    /// Maximum replica count
    pub max_replica_count: u32,
    /// Autoscaling triggers (cpu, memory, prometheus, etc.)
    pub triggers: Vec<ScaledObjectTrigger>,
}

/// Scale target reference
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScaleTargetRef {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Name
    pub name: String,
}

/// A single KEDA trigger (one scaling signal)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScaledObjectTrigger {
    /// Trigger type: "cpu", "memory", or "prometheus"
    #[serde(rename = "type")]
    pub type_: String,
    /// Metric type for resource triggers (e.g. "Utilization")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric_type: Option<String>,
    /// Trigger-specific key-value metadata
    pub metadata: BTreeMap<String, String>,
}

// =============================================================================
// Generated Workloads Container
// =============================================================================

/// Collection of all workload resources generated for a service
#[derive(Clone, Debug, Default)]
pub struct GeneratedWorkloads {
    /// Kubernetes Deployment
    pub deployment: Option<Deployment>,
    /// Kubernetes Service
    pub service: Option<Service>,
    /// Kubernetes ServiceAccount
    pub service_account: Option<ServiceAccount>,
    /// PodDisruptionBudget for HA services
    pub pdb: Option<PodDisruptionBudget>,
    /// KEDA ScaledObject for autoscaling
    pub scaled_object: Option<ScaledObject>,
    /// ConfigMaps for non-sensitive env vars (one per container)
    pub env_config_maps: Vec<ConfigMap>,
    /// Secrets for sensitive env vars (one per container)
    pub env_secrets: Vec<Secret>,
    /// ConfigMaps for file mounts — text content (one per container)
    pub files_config_maps: Vec<ConfigMap>,
    /// Secrets for file mounts — binary content (one per container)
    pub files_secrets: Vec<Secret>,
    /// PersistentVolumeClaims for owned volumes
    pub pvcs: Vec<lattice_workload::PersistentVolumeClaim>,
    /// ExternalSecrets for syncing secrets from SecretProvider (Vault)
    pub external_secrets: Vec<lattice_secret_provider::eso::ExternalSecret>,
    /// Secret references for template resolution (resource_name -> SecretRef)
    pub secret_refs: BTreeMap<String, lattice_workload::SecretRef>,
}

impl GeneratedWorkloads {
    /// Check if any workloads were generated
    pub fn is_empty(&self) -> bool {
        self.deployment.is_none()
            && self.service.is_none()
            && self.service_account.is_none()
            && self.pdb.is_none()
            && self.scaled_object.is_none()
            && self.env_config_maps.is_empty()
            && self.env_secrets.is_empty()
            && self.files_config_maps.is_empty()
            && self.files_secrets.is_empty()
            && self.pvcs.is_empty()
            && self.external_secrets.is_empty()
    }
}

// =============================================================================
// Workload Compiler
// =============================================================================

use crate::crd::{
    AutoscalingMetric, AutoscalingSpec, DeployStrategy, LatticeService, LatticeServiceSpec,
    MonitoringConfig, WorkloadSpec,
};

/// Compiler for generating LatticeService-specific Kubernetes workload resources.
///
/// Takes a pre-compiled `CompiledPodTemplate` from `lattice_workload::WorkloadCompiler`
/// and wraps it in service-specific resources: Deployment, Service, ServiceAccount, PDB, ScaledObject.
pub struct WorkloadCompiler;

impl WorkloadCompiler {
    /// Compile a LatticeService into workload resources.
    ///
    /// Takes a pre-compiled pod template from the shared pipeline and wraps it
    /// in service-specific Kubernetes resources.
    pub fn compile(
        name: &str,
        service: &LatticeService,
        namespace: &str,
        pod_template: CompiledPodTemplate,
        monitoring: &MonitoringConfig,
    ) -> Result<GeneratedWorkloads, CompilationError> {
        let spec = &service.spec;
        let workload = &spec.workload;
        let mut output = GeneratedWorkloads {
            service_account: Some(Self::compile_service_account(name, namespace)),
            ..Default::default()
        };

        // Wrap pod template in a Deployment with service-specific fields
        output.deployment = Some(Self::build_deployment(name, namespace, spec, pod_template));

        // Generate Service if ports are defined
        if workload.service.is_some() {
            output.service = Some(Self::compile_service(name, namespace, workload));
        }

        // Generate PDB for HA services (replicas >= 2)
        if spec.replicas >= 2 {
            output.pdb = Some(Self::compile_pdb(name, namespace, spec.replicas));
        }

        // Generate KEDA ScaledObject if autoscaling is configured
        if let Some(ref autoscaling) = spec.autoscaling {
            output.scaled_object = Some(Self::compile_scaled_object(
                name,
                namespace,
                spec.replicas,
                autoscaling,
                monitoring,
            )?);
        }

        Ok(output)
    }

    fn compile_service_account(name: &str, namespace: &str) -> ServiceAccount {
        ServiceAccount {
            api_version: "v1".to_string(),
            kind: "ServiceAccount".to_string(),
            metadata: ObjectMeta::new(name, namespace),
            automount_service_account_token: Some(false),
        }
    }

    /// Build a Deployment from a compiled pod template and service-specific config.
    fn build_deployment(
        name: &str,
        namespace: &str,
        spec: &LatticeServiceSpec,
        pod_template: CompiledPodTemplate,
    ) -> Deployment {
        let strategy = Self::compile_strategy(spec);

        Deployment {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
            metadata: ObjectMeta::new(name, namespace),
            spec: DeploymentSpec {
                replicas: spec.replicas,
                selector: LabelSelector {
                    match_labels: {
                        let mut selector = BTreeMap::new();
                        selector.insert(lattice_common::LABEL_NAME.to_string(), name.to_string());
                        selector
                    },
                },
                template: PodTemplateSpec {
                    metadata: PodMeta {
                        labels: pod_template.labels,
                        annotations: BTreeMap::new(),
                    },
                    spec: PodSpec {
                        service_account_name: pod_template.service_account_name,
                        automount_service_account_token: Some(false),
                        containers: pod_template.containers,
                        init_containers: pod_template.init_containers,
                        volumes: pod_template.volumes,
                        affinity: pod_template.affinity,
                        security_context: pod_template.security_context,
                        host_network: pod_template.host_network,
                        share_process_namespace: pod_template.share_process_namespace,
                        topology_spread_constraints: pod_template.topology_spread_constraints,
                        node_selector: pod_template.node_selector,
                        tolerations: pod_template.tolerations,
                        runtime_class_name: pod_template.runtime_class_name,
                        scheduling_gates: pod_template.scheduling_gates,
                        image_pull_secrets: pod_template.image_pull_secrets,
                        scheduler_name: pod_template.scheduler_name,
                    },
                },
                strategy,
            },
        }
    }

    /// Compile deployment strategy from deploy config.
    fn compile_strategy(spec: &LatticeServiceSpec) -> Option<DeploymentStrategy> {
        match spec.deploy.strategy {
            DeployStrategy::Rolling => Some(DeploymentStrategy {
                type_: "RollingUpdate".to_string(),
                rolling_update: Some(RollingUpdateConfig {
                    max_unavailable: Some("25%".to_string()),
                    max_surge: Some("25%".to_string()),
                }),
            }),
            DeployStrategy::Canary => Some(DeploymentStrategy {
                type_: "RollingUpdate".to_string(),
                rolling_update: Some(RollingUpdateConfig {
                    max_unavailable: Some("0".to_string()),
                    max_surge: Some("100%".to_string()),
                }),
            }),
        }
    }

    /// Compile a PodDisruptionBudget for HA services.
    fn compile_pdb(name: &str, namespace: &str, replicas: u32) -> PodDisruptionBudget {
        PodDisruptionBudget {
            api_version: "policy/v1".to_string(),
            kind: "PodDisruptionBudget".to_string(),
            metadata: ObjectMeta::new(name, namespace),
            spec: PdbSpec {
                min_available: Some(replicas.saturating_sub(1).max(1)),
                selector: LabelSelector {
                    match_labels: {
                        let mut labels = BTreeMap::new();
                        labels.insert(lattice_common::LABEL_NAME.to_string(), name.to_string());
                        labels
                    },
                },
            },
        }
    }

    fn compile_service(name: &str, namespace: &str, workload: &WorkloadSpec) -> Service {
        let mut selector = BTreeMap::new();
        selector.insert(lattice_common::LABEL_NAME.to_string(), name.to_string());

        let ports: Vec<ServicePort> = workload
            .service
            .as_ref()
            .map(|svc| {
                svc.ports
                    .iter()
                    .map(|(port_name, port_spec)| ServicePort {
                        name: Some(port_name.clone()),
                        port: port_spec.port,
                        target_port: port_spec.target_port,
                        protocol: port_spec.protocol.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Waypoint label is applied conditionally by the service compiler
        // when L7 enforcement is needed (e.g., external dependencies).
        let metadata = ObjectMeta::new(name, namespace);

        Service {
            api_version: "v1".to_string(),
            kind: "Service".to_string(),
            metadata,
            spec: ServiceSpec {
                selector,
                ports,
                type_: None,
            },
        }
    }

    /// Compile a KEDA ScaledObject from the service's autoscaling config.
    fn compile_scaled_object(
        name: &str,
        namespace: &str,
        replicas: u32,
        autoscaling: &AutoscalingSpec,
        monitoring: &MonitoringConfig,
    ) -> Result<ScaledObject, CompilationError> {
        use lattice_infra::bootstrap::prometheus::{query_path, query_port, query_url};

        let metrics = if autoscaling.metrics.is_empty() {
            vec![AutoscalingMetric {
                metric: "cpu".to_string(),
                target: 80,
            }]
        } else {
            autoscaling.metrics.clone()
        };

        let custom_metrics: Vec<String> = metrics
            .iter()
            .filter(|m| !matches!(m.metric.as_str(), "cpu" | "memory"))
            .map(|m| m.metric.clone())
            .collect();
        if !custom_metrics.is_empty() && !monitoring.enabled {
            return Err(CompilationError::MonitoringRequired {
                metrics: custom_metrics,
            });
        }

        // Validate custom metric names to prevent PromQL injection
        for m in &metrics {
            if !matches!(m.metric.as_str(), "cpu" | "memory")
                && !is_valid_promql_metric_name(&m.metric)
            {
                return Err(CompilationError::Resource {
                    name: m.metric.clone(),
                    message: format!(
                        "invalid Prometheus metric name '{}': must match [a-zA-Z_:][a-zA-Z0-9_:]*",
                        m.metric
                    ),
                });
            }
        }

        let server_address = format!(
            "{}:{}{}",
            query_url(monitoring.ha),
            query_port(monitoring.ha),
            query_path(monitoring.ha)
        );

        let triggers = metrics
            .iter()
            .map(|m| match m.metric.as_str() {
                "cpu" | "memory" => ScaledObjectTrigger {
                    type_: m.metric.clone(),
                    metric_type: Some("Utilization".to_string()),
                    metadata: [("value".to_string(), m.target.to_string())]
                        .into_iter()
                        .collect(),
                },
                _ => ScaledObjectTrigger {
                    type_: "prometheus".to_string(),
                    metric_type: None,
                    metadata: [
                        ("serverAddress".to_string(), server_address.clone()),
                        (
                            "query".to_string(),
                            format!(
                                "avg({}{{namespace=\"{}\",pod=~\"{}-.*\"}})",
                                m.metric, namespace, name
                            ),
                        ),
                        ("threshold".to_string(), m.target.to_string()),
                    ]
                    .into_iter()
                    .collect(),
                },
            })
            .collect();

        Ok(ScaledObject {
            api_version: ScaledObject::API_VERSION.to_string(),
            kind: ScaledObject::KIND.to_string(),
            metadata: ObjectMeta::new(name, namespace),
            spec: ScaledObjectSpec {
                scale_target_ref: ScaleTargetRef {
                    api_version: "apps/v1".to_string(),
                    kind: "Deployment".to_string(),
                    name: name.to_string(),
                },
                min_replica_count: replicas,
                max_replica_count: autoscaling.max,
                triggers,
            },
        })
    }
}

/// Validate that a metric name is a valid Prometheus metric identifier.
///
/// Prometheus metric names must match `[a-zA-Z_:][a-zA-Z0-9_:]*`.
/// This prevents PromQL injection when interpolating user-supplied names into queries.
fn is_valid_promql_metric_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' && first != ':' {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        AutoscalingMetric, AutoscalingSpec, ContainerSpec, PortSpec, ResourceSpec, ResourceType,
        ServicePortsSpec,
    };

    /// Helper to compile a service through the lattice_workload pipeline then
    /// through the service-specific WorkloadCompiler.
    async fn test_compile_with_monitoring(
        service: &LatticeService,
        monitoring: MonitoringConfig,
    ) -> Result<GeneratedWorkloads, CompilationError> {
        let name = service
            .metadata
            .name
            .as_deref()
            .expect("test service must have a name");
        let namespace = service
            .metadata
            .namespace
            .as_deref()
            .expect("test service must have a namespace");

        let graph = lattice_common::graph::ServiceGraph::new();
        let cedar = lattice_cedar::PolicyEngine::with_policies(
            r#"
            permit(
                principal,
                action == Lattice::Action::"OverrideSecurity",
                resource
            );
            permit(
                principal,
                action == Lattice::Action::"AccessSecret",
                resource
            );
            "#,
        )
        .unwrap();

        let compiled = lattice_workload::WorkloadCompiler::new(
            name,
            namespace,
            &service.spec.workload,
            &service.spec.runtime,
            crate::crd::ProviderType::Docker,
        )
        .with_cedar(&cedar)
        .with_graph(&graph)
        .with_cluster_name("test-cluster")
        .with_image_pull_secrets(&service.spec.runtime.image_pull_secrets)
        .compile()
        .await?;

        let mut workloads = WorkloadCompiler::compile(
            name,
            service,
            namespace,
            compiled.pod_template,
            &monitoring,
        )?;

        workloads.env_config_maps = compiled.config.env_config_maps;
        workloads.env_secrets = compiled.config.env_secrets;
        workloads.files_config_maps = compiled.config.files_config_maps;
        workloads.files_secrets = compiled.config.files_secrets;
        workloads.pvcs = compiled.config.pvcs;
        workloads.external_secrets = compiled.config.external_secrets;
        workloads.secret_refs = compiled.config.secret_refs;

        Ok(workloads)
    }

    /// Core test compilation helper with monitoring enabled by default.
    async fn test_compile(
        service: &LatticeService,
    ) -> Result<GeneratedWorkloads, CompilationError> {
        test_compile_with_monitoring(service, MonitoringConfig::default()).await
    }

    /// Helper to compile a service with no secret refs
    async fn compile_service(service: &LatticeService) -> GeneratedWorkloads {
        test_compile(service)
            .await
            .expect("test workload compilation should succeed")
    }

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

    // =========================================================================
    // Story: Always Generate ServiceAccount
    // =========================================================================

    #[tokio::test]
    async fn always_generates_service_account() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service).await;

        let sa = output.service_account.expect("should have service account");
        assert_eq!(sa.metadata.name, "my-app");
        assert_eq!(sa.metadata.namespace, "default");
        assert_eq!(sa.api_version, "v1");
        assert_eq!(sa.kind, "ServiceAccount");
        assert_eq!(sa.automount_service_account_token, Some(false));
    }

    // =========================================================================
    // Story: Always Generate Deployment
    // =========================================================================

    #[tokio::test]
    async fn always_generates_deployment() {
        let service = make_service("my-app", "prod");
        let output = compile_service(&service).await;

        let deployment = output.deployment.expect("should have deployment");
        assert_eq!(deployment.metadata.name, "my-app");
        assert_eq!(deployment.metadata.namespace, "prod");
        assert_eq!(deployment.api_version, "apps/v1");
        assert_eq!(deployment.kind, "Deployment");
        assert_eq!(deployment.spec.replicas, 1);
    }

    #[tokio::test]
    async fn deployment_has_correct_labels() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service).await;

        let deployment = output.deployment.expect("deployment should be set");
        assert_eq!(
            deployment
                .spec
                .selector
                .match_labels
                .get(lattice_common::LABEL_NAME),
            Some(&"my-app".to_string())
        );
        assert_eq!(
            deployment
                .spec
                .template
                .metadata
                .labels
                .get(lattice_common::LABEL_MANAGED_BY),
            Some(&lattice_common::LABEL_MANAGED_BY_LATTICE.to_string())
        );
    }

    #[tokio::test]
    async fn deployment_has_complete_spec() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service).await;

        let deployment = output.deployment.expect("deployment should be set");

        assert!(!deployment.spec.template.spec.containers.is_empty());
        assert_eq!(deployment.spec.template.spec.containers[0].name, "main");
        assert_eq!(
            deployment.spec.template.spec.containers[0].image,
            "nginx:latest"
        );

        assert_eq!(deployment.spec.template.spec.service_account_name, "my-app");

        assert_eq!(
            deployment
                .spec
                .template
                .spec
                .topology_spread_constraints
                .len(),
            1
        );
        let constraint = &deployment.spec.template.spec.topology_spread_constraints[0];
        assert_eq!(constraint.max_skew, 1);
        assert_eq!(constraint.topology_key, "kubernetes.io/hostname");
        assert_eq!(constraint.when_unsatisfiable, "ScheduleAnyway");
    }

    // =========================================================================
    // Story: Generate Service When Ports Defined
    // =========================================================================

    #[tokio::test]
    async fn generates_service_with_ports() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service).await;

        let svc = output.service.expect("should have service");
        assert_eq!(svc.metadata.name, "my-app");
        assert_eq!(svc.api_version, "v1");
        assert_eq!(svc.kind, "Service");
        assert!(!svc.spec.ports.is_empty());
    }

    #[tokio::test]
    async fn no_service_without_ports() {
        let mut service = make_service("my-app", "default");
        service.spec.workload.service = None;

        let output = compile_service(&service).await;
        assert!(output.service.is_none());
    }

    // =========================================================================
    // Story: Generate KEDA ScaledObject When Max Replicas Set
    // =========================================================================

    #[tokio::test]
    async fn scaled_object_generated_with_max_replicas() {
        let mut service = make_service("my-app", "default");
        service.spec.replicas = 2;
        service.spec.autoscaling = Some(AutoscalingSpec {
            max: 10,
            metrics: vec![],
        });

        let output = compile_service(&service).await;

        let so = output.scaled_object.expect("should have ScaledObject");
        assert_eq!(so.api_version, "keda.sh/v1alpha1");
        assert_eq!(so.kind, "ScaledObject");
        assert_eq!(so.metadata.name, "my-app");
        assert_eq!(so.spec.min_replica_count, 2);
        assert_eq!(so.spec.max_replica_count, 10);
        assert_eq!(so.spec.scale_target_ref.name, "my-app");
        assert_eq!(so.spec.scale_target_ref.kind, "Deployment");
    }

    #[tokio::test]
    async fn no_scaled_object_without_max_replicas() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service).await;
        assert!(output.scaled_object.is_none());
    }

    #[tokio::test]
    async fn scaled_object_default_cpu_80() {
        let mut service = make_service("my-app", "default");
        service.spec.replicas = 1;
        service.spec.autoscaling = Some(AutoscalingSpec {
            max: 5,
            metrics: vec![],
        });
        let output = compile_service(&service).await;
        let so = output.scaled_object.expect("should have ScaledObject");
        assert_eq!(so.spec.triggers.len(), 1);
        let t = &so.spec.triggers[0];
        assert_eq!(t.type_, "cpu");
        assert_eq!(t.metric_type.as_deref(), Some("Utilization"));
        assert_eq!(t.metadata.get("value").unwrap(), "80");
    }

    #[tokio::test]
    async fn scaled_object_custom_metrics_require_monitoring() {
        let mut service = make_service("my-app", "default");
        service.spec.replicas = 1;
        service.spec.autoscaling = Some(AutoscalingSpec {
            max: 10,
            metrics: vec![AutoscalingMetric {
                metric: "vllm_num_requests_waiting".to_string(),
                target: 5,
            }],
        });

        let result = test_compile_with_monitoring(
            &service,
            MonitoringConfig {
                enabled: false,
                ha: false,
            },
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("monitoring"));
        assert!(err.contains("vllm_num_requests_waiting"));
    }

    // =========================================================================
    // Story: PodDisruptionBudget for HA Services
    // =========================================================================

    #[tokio::test]
    async fn pdb_generated_for_ha_services() {
        let mut service = make_service("my-app", "default");
        service.spec.replicas = 3;

        let output = compile_service(&service).await;

        let pdb = output.pdb.expect("should have PDB");
        assert_eq!(pdb.api_version, "policy/v1");
        assert_eq!(pdb.kind, "PodDisruptionBudget");
        assert_eq!(pdb.metadata.name, "my-app");
        assert_eq!(pdb.spec.min_available, Some(2));
    }

    #[tokio::test]
    async fn no_pdb_for_single_replica() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service).await;
        assert!(output.pdb.is_none());
    }

    // =========================================================================
    // Story: Deployment Strategy
    // =========================================================================

    #[tokio::test]
    async fn rolling_strategy() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service).await;

        let strategy = output
            .deployment
            .expect("deployment should be generated")
            .spec
            .strategy
            .expect("strategy should be set");
        assert_eq!(strategy.type_, "RollingUpdate");
        let rolling = strategy
            .rolling_update
            .expect("rolling update should be configured");
        assert_eq!(rolling.max_unavailable, Some("25%".to_string()));
        assert_eq!(rolling.max_surge, Some("25%".to_string()));
    }

    #[tokio::test]
    async fn canary_strategy() {
        let mut service = make_service("my-app", "default");
        service.spec.deploy.strategy = DeployStrategy::Canary;

        let output = compile_service(&service).await;

        let strategy = output
            .deployment
            .expect("deployment should be generated")
            .spec
            .strategy
            .expect("strategy should be set");
        assert_eq!(strategy.type_, "RollingUpdate");
        let rolling = strategy
            .rolling_update
            .expect("rolling update should be configured");
        assert_eq!(rolling.max_unavailable, Some("0".to_string()));
        assert_eq!(rolling.max_surge, Some("100%".to_string()));
    }

    // =========================================================================
    // Story: GeneratedWorkloads Utility Methods
    // =========================================================================

    #[tokio::test]
    async fn is_empty() {
        let empty = GeneratedWorkloads::default();
        assert!(empty.is_empty());

        let service = make_service("my-app", "default");
        let output = compile_service(&service).await;
        assert!(!output.is_empty());
    }

    // =========================================================================
    // Story: GPU Resource Compilation
    // =========================================================================

    #[tokio::test]
    async fn gpu_full_gpu_in_limits() {
        let mut service = make_service("gpu-app", "default");
        service.spec.workload.resources.insert(
            "my-gpu".to_string(),
            ResourceSpec {
                type_: ResourceType::Gpu,
                params: Some({
                    let mut p = std::collections::BTreeMap::new();
                    p.insert("count".to_string(), serde_json::json!(1));
                    p
                }),
                ..Default::default()
            },
        );

        let output = compile_service(&service).await;
        let deployment = output.deployment.expect("should have deployment");
        let main = &deployment.spec.template.spec.containers[0];
        let limits = main.resources.as_ref().unwrap().limits.as_ref().unwrap();

        assert_eq!(limits.gpu, Some("1".to_string()));
        assert!(limits.gpu_memory.is_none());
        assert!(limits.gpu_cores.is_none());
    }

    #[tokio::test]
    async fn gpu_resources_serialize_as_volcano_vgpu() {
        let mut service = make_service("gpu-app", "default");
        service.spec.workload.resources.insert(
            "my-gpu".to_string(),
            ResourceSpec {
                type_: ResourceType::Gpu,
                params: Some({
                    let mut p = std::collections::BTreeMap::new();
                    p.insert("count".to_string(), serde_json::json!(1));
                    p
                }),
                ..Default::default()
            },
        );

        let output = compile_service(&service).await;
        let deployment = output.deployment.expect("should have deployment");
        let json = serde_json::to_string(&deployment).unwrap();

        assert!(json.contains("volcano.sh/vgpu-number"));
        // nvidia.com/gpu still appears as toleration key (node taint), not as a resource name
        assert!(!json.contains("nvidia.com/gpumem"));
        assert!(!json.contains("nvidia.com/gpucores"));
    }

    #[tokio::test]
    async fn gpu_toleration_added_by_default() {
        let mut service = make_service("gpu-app", "default");
        service.spec.workload.resources.insert(
            "my-gpu".to_string(),
            ResourceSpec {
                type_: ResourceType::Gpu,
                params: Some({
                    let mut p = std::collections::BTreeMap::new();
                    p.insert("count".to_string(), serde_json::json!(1));
                    p
                }),
                ..Default::default()
            },
        );

        let output = compile_service(&service).await;
        let deployment = output.deployment.expect("should have deployment");
        let tolerations = &deployment.spec.template.spec.tolerations;

        assert_eq!(tolerations.len(), 1);
        assert_eq!(tolerations[0].key, Some("nvidia.com/gpu".to_string()));
    }

    #[tokio::test]
    async fn no_gpu_no_tolerations_or_selector() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service).await;
        let deployment = output.deployment.expect("should have deployment");

        assert!(deployment.spec.template.spec.tolerations.is_empty());
        assert!(deployment.spec.template.spec.node_selector.is_none());
    }

    #[tokio::test]
    async fn gpu_workload_gets_volcano_scheduler() {
        let mut service = make_service("gpu-app", "default");
        service.spec.workload.resources.insert(
            "my-gpu".to_string(),
            ResourceSpec {
                type_: ResourceType::Gpu,
                params: Some({
                    let mut p = std::collections::BTreeMap::new();
                    p.insert("count".to_string(), serde_json::json!(1));
                    p
                }),
                ..Default::default()
            },
        );

        let output = compile_service(&service).await;
        let deployment = output.deployment.expect("should have deployment");

        assert_eq!(
            deployment.spec.template.spec.scheduler_name,
            Some("volcano".to_string())
        );
    }

    #[tokio::test]
    async fn non_gpu_workload_has_no_scheduler_name() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service).await;
        let deployment = output.deployment.expect("should have deployment");

        assert!(deployment.spec.template.spec.scheduler_name.is_none());
    }

    // =========================================================================
    // Story: imagePullSecrets Resolution
    // =========================================================================

    #[tokio::test]
    async fn no_image_pull_secrets_by_default() {
        let service = make_service("myapp", "prod");
        let output = compile_service(&service).await;
        let deployment = output.deployment.unwrap();
        assert!(deployment.spec.template.spec.image_pull_secrets.is_empty());
    }

    // =========================================================================
    // Story: Secret Variable Resolution in Env Vars
    // =========================================================================

    #[tokio::test]
    async fn secret_var_compiles_to_secret_key_ref() {
        use lattice_common::template::TemplateString;

        let mut service = make_service("myapp", "prod");
        service
            .spec
            .workload
            .containers
            .get_mut("main")
            .unwrap()
            .variables
            .insert(
                "DB_PASSWORD".to_string(),
                TemplateString::from("${secret.db-creds.password}"),
            );
        service.spec.workload.resources.insert(
            "db-creds".to_string(),
            crate::crd::ResourceSpec {
                type_: crate::crd::ResourceType::Secret,
                id: Some("vault/path".to_string()),
                params: Some({
                    let mut p = BTreeMap::new();
                    p.insert("provider".to_string(), serde_json::json!("vault"));
                    p.insert("keys".to_string(), serde_json::json!(["password"]));
                    p
                }),
                ..Default::default()
            },
        );

        let output = compile_service(&service).await;
        let deployment = output.deployment.expect("should have deployment");
        let env = &deployment.spec.template.spec.containers[0].env;
        let db_pass = env
            .iter()
            .find(|e| e.name == "DB_PASSWORD")
            .expect("should have DB_PASSWORD");
        assert!(db_pass.value.is_none());
        let vf = db_pass.value_from.as_ref().expect("should have valueFrom");
        let skr = vf
            .secret_key_ref
            .as_ref()
            .expect("should have secretKeyRef");
        assert_eq!(skr.key, "password");
    }

    // =========================================================================
    // Story: Host Network and Share Process Namespace
    // =========================================================================

    #[tokio::test]
    async fn host_network_and_share_process_namespace() {
        let mut service = make_service("my-app", "default");
        service.spec.runtime.host_network = Some(true);
        service.spec.runtime.share_process_namespace = Some(true);

        let output = compile_service(&service).await;
        let deployment = output.deployment.expect("should have deployment");

        assert_eq!(deployment.spec.template.spec.host_network, Some(true));
        assert_eq!(
            deployment.spec.template.spec.share_process_namespace,
            Some(true)
        );
    }

    #[tokio::test]
    async fn host_network_none_by_default() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service).await;
        let deployment = output.deployment.expect("should have deployment");

        assert!(deployment.spec.template.spec.host_network.is_none());
        assert!(deployment
            .spec
            .template
            .spec
            .share_process_namespace
            .is_none());
    }

    // =========================================================================
    // Story: Init Containers Separated
    // =========================================================================

    #[tokio::test]
    async fn init_containers_separated() {
        use crate::crd::SidecarSpec;

        let mut service = make_service("my-app", "default");
        service.spec.runtime.sidecars.insert(
            "init-setup".to_string(),
            SidecarSpec {
                image: "busybox:latest".to_string(),
                command: Some(vec!["/bin/sh".to_string(), "-c".to_string()]),
                args: Some(vec!["echo hello".to_string()]),
                init: Some(true),
                ..Default::default()
            },
        );
        service.spec.runtime.sidecars.insert(
            "vpn".to_string(),
            SidecarSpec {
                image: "wireguard:latest".to_string(),
                init: Some(false),
                ..Default::default()
            },
        );

        let output = compile_service(&service).await;
        let deployment = output.deployment.expect("should have deployment");

        assert_eq!(deployment.spec.template.spec.init_containers.len(), 1);
        assert_eq!(
            deployment.spec.template.spec.init_containers[0].name,
            "init-setup"
        );

        assert_eq!(deployment.spec.template.spec.containers.len(), 2);
        assert!(deployment
            .spec
            .template
            .spec
            .containers
            .iter()
            .any(|c| c.name == "main"));
        assert!(deployment
            .spec
            .template
            .spec
            .containers
            .iter()
            .any(|c| c.name == "vpn"));
    }
}
