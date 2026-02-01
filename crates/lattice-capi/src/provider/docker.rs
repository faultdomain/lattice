//! Docker/Kind infrastructure provider
//!
//! This module implements the [`Provider`] trait for Docker/Kind clusters,
//! which is useful for local development and testing.
//!
//! # Generated CAPI Resources
//!
//! The DockerProvider generates the following Cluster API resources:
//!
//! 1. **Cluster** - The main CAPI cluster resource
//! 2. **DockerCluster** - Docker-specific cluster infrastructure
//! 3. **KubeadmControlPlane** - Control plane configuration with node count
//! 4. **DockerMachineTemplate** (control plane) - Machine template for control plane nodes
//! 5. **MachineDeployment** - Worker node deployment
//! 6. **DockerMachineTemplate** (workers) - Machine template for worker nodes
//! 7. **KubeadmConfigTemplate** - Kubeadm configuration for workers
//!
//! # Example
//!
//! ```text
//! let provider = DockerProvider::new();
//! let cluster: LatticeCluster = ...;
//! let manifests = provider.generate_capi_manifests(&cluster).await?;
//! ```

use async_trait::async_trait;
use serde_json::json;

use super::{
    build_cert_sans, build_post_kubeadm_commands, control_plane_name, create_cluster_labels,
    generate_bootstrap_config_template_for_pool, generate_cluster, generate_control_plane,
    generate_machine_deployment_for_pool, get_cluster_name, pool_resource_suffix, CAPIManifest,
    ClusterConfig, ControlPlaneConfig, InfrastructureRef, Provider, WorkerPoolConfig,
};
use lattice_common::crd::{BootstrapProvider, LatticeCluster, ProviderSpec, ProviderType};
use lattice_common::{Error, Result};

/// Default namespace for CAPI resources
const DEFAULT_NAMESPACE: &str = "default";

/// Docker infrastructure API group (used in refs)
const DOCKER_INFRASTRUCTURE_API_GROUP: &str = "infrastructure.cluster.x-k8s.io";

/// Docker infrastructure API version for kubeadm (v1beta2 - latest CAPI)
const DOCKER_INFRASTRUCTURE_API_VERSION_V1BETA2: &str = "infrastructure.cluster.x-k8s.io/v1beta2";

/// Docker infrastructure API version for RKE2 (v1beta1 - required by CAPRKE2)
/// See: https://github.com/rancher/cluster-api-provider-rke2/issues/789
const DOCKER_INFRASTRUCTURE_API_VERSION_V1BETA1: &str = "infrastructure.cluster.x-k8s.io/v1beta1";

/// Docker/Kind infrastructure provider
///
/// This provider generates Cluster API manifests for Docker-based clusters,
/// primarily used for local development and testing with kind.
#[derive(Debug, Default, Clone)]
pub struct DockerProvider {
    /// Default namespace for generated resources
    namespace: String,
}

impl DockerProvider {
    /// Create a new DockerProvider with default settings
    pub fn new() -> Self {
        Self {
            namespace: DEFAULT_NAMESPACE.to_string(),
        }
    }

    /// Create a new DockerProvider with a custom namespace
    pub fn with_namespace(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
        }
    }

    /// Get the namespace for resources
    fn get_namespace(&self, cluster: &LatticeCluster) -> String {
        cluster
            .metadata
            .namespace
            .clone()
            .unwrap_or_else(|| self.namespace.clone())
    }

    /// Get the Docker infrastructure API version based on bootstrap provider
    ///
    /// CAPRKE2 requires v1beta1 for compatibility, while kubeadm works with v1beta2.
    /// See: https://github.com/rancher/cluster-api-provider-rke2/issues/789
    fn get_infra_api_version(bootstrap: &BootstrapProvider) -> &'static str {
        match bootstrap {
            BootstrapProvider::Rke2 => DOCKER_INFRASTRUCTURE_API_VERSION_V1BETA1,
            BootstrapProvider::Kubeadm => DOCKER_INFRASTRUCTURE_API_VERSION_V1BETA2,
        }
    }

    /// Generate the DockerCluster resource (Docker-specific)
    fn generate_docker_cluster(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = get_cluster_name(cluster)?;
        let namespace = self.get_namespace(cluster);
        let labels = create_cluster_labels(name);
        let api_version = Self::get_infra_api_version(&cluster.spec.provider.kubernetes.bootstrap);

        // For RKE2, we need a custom HAProxy config that uses HTTP health checks
        // and disables SSL verification. The field is nested under spec.loadBalancer
        let spec = match cluster.spec.provider.kubernetes.bootstrap {
            BootstrapProvider::Rke2 => {
                json!({
                    "loadBalancer": {
                        "customHAProxyConfigTemplateRef": {
                            "name": format!("{}-lb-config", name)
                        }
                    }
                })
            }
            _ => json!({}),
        };

        Ok(
            CAPIManifest::new(api_version, "DockerCluster", name, &namespace)
                .with_labels(labels)
                .with_spec(spec),
        )
    }

    /// Generate HAProxy ConfigMap for RKE2 clusters
    ///
    /// RKE2 requires a custom HAProxy configuration because:
    /// 1. Health checks must use HTTP GET /healthz instead of TCP
    /// 2. SSL verification must be disabled for backend connections
    /// 3. An additional frontend on port 9345 is needed for RKE2 supervisor/join
    fn generate_haproxy_configmap(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = get_cluster_name(cluster)?;
        let namespace = self.get_namespace(cluster);
        let labels = create_cluster_labels(name);
        let configmap_name = format!("{}-lb-config", name);

        // HAProxy config template for RKE2 - uses Go template syntax for CAPD
        let haproxy_config = r#"# HAProxy config for RKE2 with CAPD
global
  log /dev/log local0
  log /dev/log local1 notice
  daemon
  maxconn 4096

resolvers docker
  nameserver dns 127.0.0.11:53

defaults
  log global
  mode tcp
  option dontlognull
  timeout connect 5s
  timeout client 1m
  timeout server 1m
  default-server init-addr none

frontend stats
  mode http
  bind *:8404
  stats enable
  stats uri /stats
  stats refresh 10s
  stats admin if TRUE

frontend control-plane
  bind *:{{ .FrontendControlPlanePort }}
  {{ if .IPv6 -}}
  bind :::{{ .FrontendControlPlanePort }};
  {{- end }}
  default_backend kube-apiservers

backend kube-apiservers
  option httpchk GET /healthz
  http-check expect status 200
  {{range $server, $backend := .BackendServers}}
  server {{ $server }} {{ JoinHostPort $backend.Address $.BackendControlPlanePort }} check check-ssl verify none resolvers docker resolve-prefer {{ if $.IPv6 -}} ipv6 {{- else -}} ipv4 {{- end }}
  {{- end}}

frontend rke2-join
  bind *:9345
  {{ if .IPv6 -}}
  bind :::9345;
  {{- end }}
  default_backend rke2-servers

backend rke2-servers
  option httpchk GET /v1-rke2/readyz
  http-check expect status 403
  {{range $server, $backend := .BackendServers}}
  server {{ $server }} {{ $backend.Address }}:9345 check check-ssl verify none resolvers docker resolve-prefer {{ if $.IPv6 -}} ipv6 {{- else -}} ipv4 {{- end }}
  {{- end}}
"#;

        // Build ConfigMap manifest with data field
        Ok(
            CAPIManifest::new("v1", "ConfigMap", &configmap_name, &namespace)
                .with_labels(labels)
                .with_data(json!({
                    "value": haproxy_config
                })),
        )
    }

    /// Generate the DockerMachineTemplate for control plane nodes (Docker-specific)
    fn generate_control_plane_machine_template(
        &self,
        cluster: &LatticeCluster,
    ) -> Result<CAPIManifest> {
        let name = get_cluster_name(cluster)?;
        let namespace = self.get_namespace(cluster);
        let labels = create_cluster_labels(name);
        let template_name = control_plane_name(name);
        let api_version = Self::get_infra_api_version(&cluster.spec.provider.kubernetes.bootstrap);

        let spec = json!({
            "template": {
                "spec": {
                    "extraMounts": [{
                        "containerPath": "/var/run/docker.sock",
                        "hostPath": "/var/run/docker.sock"
                    }]
                }
            }
        });

        Ok(CAPIManifest::new(
            api_version,
            "DockerMachineTemplate",
            &template_name,
            &namespace,
        )
        .with_labels(labels)
        .with_spec(spec))
    }

    /// Generate the DockerMachineTemplate for a worker pool (Docker-specific)
    fn generate_worker_machine_template_for_pool(
        &self,
        cluster: &LatticeCluster,
        pool_id: &str,
    ) -> Result<CAPIManifest> {
        let name = get_cluster_name(cluster)?;
        let namespace = self.get_namespace(cluster);
        let labels = create_cluster_labels(name);
        let suffix = pool_resource_suffix(pool_id);
        let template_name = format!("{}-{}", name, suffix);
        let api_version = Self::get_infra_api_version(&cluster.spec.provider.kubernetes.bootstrap);

        let spec = json!({
            "template": {
                "spec": {
                    "extraMounts": [{
                        "containerPath": "/var/run/docker.sock",
                        "hostPath": "/var/run/docker.sock"
                    }]
                }
            }
        });

        Ok(CAPIManifest::new(
            api_version,
            "DockerMachineTemplate",
            &template_name,
            &namespace,
        )
        .with_labels(labels)
        .with_spec(spec))
    }
}

#[async_trait]
impl Provider for DockerProvider {
    /// Generate all CAPI manifests for the Docker provider
    ///
    /// This generates the following resources:
    /// 1. Cluster
    /// 2. DockerCluster
    /// 3. KubeadmControlPlane
    /// 4. DockerMachineTemplate (control plane)
    /// 5. MachineDeployment (workers)
    /// 6. DockerMachineTemplate (workers)
    /// 7. KubeadmConfigTemplate (workers)
    async fn generate_capi_manifests(
        &self,
        cluster: &LatticeCluster,
        bootstrap: &super::BootstrapInfo,
    ) -> Result<Vec<CAPIManifest>> {
        let name = get_cluster_name(cluster)?;
        let namespace = self.get_namespace(cluster);
        let k8s_version = &cluster.spec.provider.kubernetes.version;

        // Build certSANs - Docker always includes localhost/127.0.0.1 for local access
        let mut cert_sans = build_cert_sans(cluster);
        for local_san in ["localhost", "127.0.0.1"] {
            if !cert_sans.iter().any(|s| s == local_san) {
                cert_sans.insert(0, local_san.to_string());
            }
        }

        // Build config structs
        let config = ClusterConfig {
            name,
            namespace: &namespace,
            k8s_version,
            labels: create_cluster_labels(name),
            bootstrap: cluster.spec.provider.kubernetes.bootstrap.clone(),
            provider_type: ProviderType::Docker,
        };

        let infra_api_version =
            Self::get_infra_api_version(&cluster.spec.provider.kubernetes.bootstrap);
        let infra = InfrastructureRef {
            api_group: DOCKER_INFRASTRUCTURE_API_GROUP,
            api_version: infra_api_version,
            cluster_kind: "DockerCluster",
            machine_template_kind: "DockerMachineTemplate",
        };

        let cp_config = ControlPlaneConfig {
            replicas: cluster.spec.nodes.control_plane,
            cert_sans,
            post_kubeadm_commands: build_post_kubeadm_commands(name, bootstrap)?,
            vip: None,
            ssh_authorized_keys: vec![],
        };

        // Use shared functions for provider-agnostic resources
        let mut manifests = vec![generate_cluster(&config, &infra)];

        // For RKE2, add the HAProxy ConfigMap BEFORE DockerCluster (which references it)
        if cluster.spec.provider.kubernetes.bootstrap == BootstrapProvider::Rke2 {
            manifests.push(self.generate_haproxy_configmap(cluster)?);
        }

        manifests.push(self.generate_docker_cluster(cluster)?);
        manifests.push(generate_control_plane(&config, &infra, &cp_config));
        manifests.push(self.generate_control_plane_machine_template(cluster)?);

        // Worker pool resources - generate MachineDeployment, MachineTemplate, ConfigTemplate per pool
        for (pool_id, pool_spec) in &cluster.spec.nodes.worker_pools {
            let pool_config = WorkerPoolConfig {
                pool_id,
                spec: pool_spec,
            };
            manifests.push(generate_machine_deployment_for_pool(
                &config,
                &infra,
                &pool_config,
            ));
            manifests.push(self.generate_worker_machine_template_for_pool(cluster, pool_id)?);
            manifests.push(generate_bootstrap_config_template_for_pool(
                &config,
                &pool_config,
            ));
        }

        Ok(manifests)
    }

    /// Validate that the provider spec is valid for Docker
    ///
    /// Checks:
    /// - Kubernetes version must be specified and valid format
    async fn validate_spec(&self, spec: &ProviderSpec) -> Result<()> {
        // Validate Kubernetes version format (basic check)
        let version = &spec.kubernetes.version;
        if version.is_empty() {
            return Err(Error::validation("kubernetes version must be specified"));
        }

        // Check version format (should be like "1.31.0" or "v1.31.0")
        let version_clean = version.strip_prefix('v').unwrap_or(version);
        let parts: Vec<&str> = version_clean.split('.').collect();
        if parts.len() < 2 {
            return Err(Error::validation(format!(
                "invalid kubernetes version format: {}, expected format like '1.31.0'",
                version
            )));
        }

        // Verify each part is a number
        for part in &parts {
            if part.parse::<u32>().is_err() {
                return Err(Error::validation(format!(
                    "invalid kubernetes version format: {}, version parts must be numbers",
                    version
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{
        build_post_kubeadm_commands, CAPI_BOOTSTRAP_API_VERSION, CAPI_CLUSTER_API_VERSION,
        CAPI_CONTROLPLANE_API_VERSION,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use lattice_common::crd::{
        BootstrapProvider, EndpointsSpec, KubernetesSpec, LatticeClusterSpec, NodeSpec,
        ProviderConfig, ProviderSpec, ServiceSpec, WorkerPoolSpec,
    };

    /// Helper to create a sample LatticeCluster for testing
    fn sample_cluster(name: &str, workers: u32) -> LatticeCluster {
        let worker_pools = if workers > 0 {
            std::collections::BTreeMap::from([(
                "default".to_string(),
                WorkerPoolSpec {
                    replicas: workers,
                    ..Default::default()
                },
            )])
        } else {
            std::collections::BTreeMap::new()
        };

        LatticeCluster {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: LatticeClusterSpec {
                provider_ref: "docker".to_string(),
                provider: ProviderSpec {
                    kubernetes: KubernetesSpec {
                        version: "1.32.0".to_string(),
                        cert_sans: Some(vec!["127.0.0.1".to_string(), "localhost".to_string()]),
                        bootstrap: BootstrapProvider::default(),
                    },
                    config: ProviderConfig::docker(),
                    credentials_secret_ref: None,
                },
                nodes: NodeSpec {
                    control_plane: 1,
                    worker_pools,
                },
                networking: None,
                parent_config: None,
                environment: None,
                region: None,
                workload: None,
            },
            status: None,
        }
    }

    /// Helper to create a cell (management) cluster
    fn sample_parent_cluster(name: &str) -> LatticeCluster {
        let mut cluster = sample_cluster(name, 2);
        cluster.spec.parent_config = Some(EndpointsSpec {
            host: Some("172.18.255.1".to_string()),
            grpc_port: 50051,
            bootstrap_port: 8443,
            proxy_port: 8081,
            service: ServiceSpec {
                type_: "LoadBalancer".to_string(),
            },
        });
        cluster
    }

    /// Helper to create a workload cluster (no cell configuration)
    fn sample_workload_cluster(name: &str) -> LatticeCluster {
        sample_cluster(name, 3)
    }

    /// Provider Configuration Tests
    ///
    /// These tests verify that the DockerProvider can be configured correctly
    /// for different deployment scenarios.
    mod provider_configuration {
        use super::*;

        /// Story: By default, resources should be created in the "default" namespace
        /// since most local development setups use this namespace.
        #[test]
        fn default_provider_uses_default_namespace() {
            let provider = DockerProvider::new();
            assert_eq!(provider.namespace, "default");
        }

        /// Story: Teams may want to isolate CAPI resources in a dedicated namespace
        /// like "capi-system" for better organization and RBAC control.
        #[test]
        fn custom_namespace_can_be_configured() {
            let provider = DockerProvider::with_namespace("capi-system");
            assert_eq!(provider.namespace, "capi-system");
        }
    }

    /// Manifest Generation Error Handling
    ///
    /// Tests that verify the provider handles edge cases gracefully.
    mod manifest_generation_errors {
        use super::*;
        use crate::provider::BootstrapInfo;

        /// Story: A LatticeCluster CRD must have a name to generate CAPI resources.
        /// If somehow a cluster without a name is submitted, we should fail with
        /// a clear validation error rather than generating invalid manifests.
        #[tokio::test]
        async fn cluster_without_name_fails_gracefully() {
            let provider = DockerProvider::new();
            let cluster = LatticeCluster {
                metadata: ObjectMeta {
                    name: None,
                    ..Default::default()
                },
                spec: sample_cluster("test", 0).spec,
                status: None,
            };
            let bootstrap = BootstrapInfo::default();

            let result = provider.generate_capi_manifests(&cluster, &bootstrap).await;

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("cluster name required"));
        }
    }

    /// CAPI Manifest Generation Tests
    ///
    /// These tests verify that the DockerProvider generates the correct set of
    /// Cluster API resources for different cluster configurations. Each manifest
    /// represents a Kubernetes resource that CAPI uses to provision infrastructure.
    mod generate_capi_manifests {
        use super::*;
        use crate::provider::BootstrapInfo;

        /// Story: A typical cluster with control plane and workers needs 7 CAPI resources:
        /// - Cluster (main CAPI cluster object)
        /// - DockerCluster (Docker-specific infrastructure config)
        /// - KubeadmControlPlane (control plane nodes)
        /// - DockerMachineTemplate (control plane machine config)
        /// - MachineDeployment (worker node deployment)
        /// - DockerMachineTemplate (worker machine config)
        /// - KubeadmConfigTemplate (worker bootstrap config)
        #[tokio::test]
        async fn full_cluster_generates_seven_manifests() {
            let provider = DockerProvider::new();
            let cluster = sample_cluster("test-cluster", 2);
            let bootstrap = BootstrapInfo::default();
            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .expect("manifest generation should succeed");

            assert_eq!(manifests.len(), 7);
        }

        /// Story: A control-plane-only cluster (no worker pools) generates only core resources.
        /// Worker pool resources are only created when pools are defined.
        #[tokio::test]
        async fn control_plane_only_cluster_generates_core_manifests_only() {
            let provider = DockerProvider::new();
            let cluster = sample_cluster("test-cluster", 0);
            let bootstrap = BootstrapInfo::default();
            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .expect("manifest generation should succeed");

            // 4 manifests: Cluster, DockerCluster, KubeadmControlPlane, DockerMachineTemplate (CP)
            // No worker pool resources since no pools are defined
            assert_eq!(manifests.len(), 4);

            // Verify no MachineDeployment
            let deployment = manifests.iter().find(|m| m.kind == "MachineDeployment");
            assert!(
                deployment.is_none(),
                "should not have MachineDeployment with no worker pools"
            );
        }

        /// Story: The Cluster resource is the top-level CAPI object that ties
        /// everything together with references to the control plane and infrastructure.
        #[tokio::test]
        async fn cluster_resource_has_correct_references() {
            let provider = DockerProvider::new();
            let cluster = sample_cluster("my-cluster", 2);
            let bootstrap = BootstrapInfo::default();
            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .expect("manifest generation should succeed");

            let cluster_manifest = manifests
                .iter()
                .find(|m| m.kind == "Cluster")
                .expect("should have Cluster manifest");

            assert_eq!(cluster_manifest.api_version, CAPI_CLUSTER_API_VERSION);
            assert_eq!(cluster_manifest.metadata.name, "my-cluster");
            assert_eq!(
                cluster_manifest.metadata.namespace,
                Some("default".to_string())
            );

            let spec = cluster_manifest.spec.as_ref().expect("spec should exist");
            assert!(spec.get("controlPlaneRef").is_some());
            assert!(spec.get("infrastructureRef").is_some());
            assert!(spec.get("clusterNetwork").is_some());
        }

        /// Story: DockerCluster provides Docker/kind-specific infrastructure config.
        #[tokio::test]
        async fn docker_cluster_resource_is_generated() {
            let provider = DockerProvider::new();
            let cluster = sample_cluster("my-cluster", 2);
            let bootstrap = BootstrapInfo::default();
            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .expect("manifest generation should succeed");

            let docker_cluster = manifests
                .iter()
                .find(|m| m.kind == "DockerCluster")
                .expect("should have DockerCluster manifest");

            assert_eq!(
                docker_cluster.api_version,
                DOCKER_INFRASTRUCTURE_API_VERSION_V1BETA2
            );
            assert_eq!(docker_cluster.metadata.name, "my-cluster");
        }

        /// Story: For HA clusters, users specify the number of control plane nodes.
        /// The KubeadmControlPlane resource should reflect the requested replica count.
        #[tokio::test]
        async fn control_plane_respects_replica_count() {
            let provider = DockerProvider::new();
            let mut cluster = sample_cluster("my-cluster", 2);
            cluster.spec.nodes.control_plane = 3;
            let bootstrap = BootstrapInfo::default();

            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .expect("manifest generation should succeed");

            let control_plane = manifests
                .iter()
                .find(|m| m.kind == "KubeadmControlPlane")
                .expect("should have KubeadmControlPlane manifest");

            assert_eq!(control_plane.api_version, CAPI_CONTROLPLANE_API_VERSION);
            assert_eq!(control_plane.metadata.name, "my-cluster-control-plane");

            let spec = control_plane.spec.as_ref().expect("spec should exist");
            assert_eq!(spec.get("replicas").expect("replicas should exist"), 3);
            assert_eq!(
                spec.get("version").expect("version should exist"),
                "v1.32.0"
            );
        }

        /// Story: MachineDeployment is always created with replicas=0 during initial
        /// provisioning. After pivot, the cluster's local controller will scale up
        /// to match spec.nodes.worker_pools. This ensures fast cluster creation.
        #[tokio::test]
        async fn worker_deployment_starts_with_zero_replicas() {
            let provider = DockerProvider::new();
            // Even with spec.nodes.worker_pools[default].replicas=5, MachineDeployment starts at 0
            let cluster = sample_cluster("my-cluster", 5);
            let bootstrap = BootstrapInfo::default();

            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .expect("manifest generation should succeed");

            let deployment = manifests
                .iter()
                .find(|m| m.kind == "MachineDeployment")
                .expect("should have MachineDeployment manifest");

            assert_eq!(deployment.api_version, CAPI_CLUSTER_API_VERSION);
            assert_eq!(deployment.metadata.name, "my-cluster-pool-default");

            let spec = deployment.spec.as_ref().expect("spec should exist");
            // Always 0 - scaling happens after pivot
            assert_eq!(spec.get("replicas").expect("replicas should exist"), 0);
            assert_eq!(
                spec.get("clusterName").expect("clusterName should exist"),
                "my-cluster"
            );
        }

        /// Story: Control plane and workers use different machine templates since
        /// they may have different resource requirements or configurations.
        #[tokio::test]
        async fn separate_machine_templates_for_cp_and_workers() {
            let provider = DockerProvider::new();
            let cluster = sample_cluster("my-cluster", 2);
            let bootstrap = BootstrapInfo::default();

            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .expect("manifest generation should succeed");

            let machine_templates: Vec<_> = manifests
                .iter()
                .filter(|m| m.kind == "DockerMachineTemplate")
                .collect();

            // Should have 2: one for control plane, one for workers (default pool)
            assert_eq!(machine_templates.len(), 2);

            let cp_template = machine_templates
                .iter()
                .find(|m| m.metadata.name == "my-cluster-control-plane")
                .expect("should have control plane template");
            assert_eq!(
                cp_template.api_version,
                DOCKER_INFRASTRUCTURE_API_VERSION_V1BETA2
            );

            let worker_template = machine_templates
                .iter()
                .find(|m| m.metadata.name == "my-cluster-pool-default")
                .expect("should have worker template");
            assert_eq!(
                worker_template.api_version,
                DOCKER_INFRASTRUCTURE_API_VERSION_V1BETA2
            );
        }

        /// Story: Workers need kubeadm configuration for joining the cluster.
        #[tokio::test]
        async fn kubeadm_config_template_generated_for_workers() {
            let provider = DockerProvider::new();
            let cluster = sample_cluster("my-cluster", 2);
            let bootstrap = BootstrapInfo::default();

            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .expect("manifest generation should succeed");

            let config_template = manifests
                .iter()
                .find(|m| m.kind == "KubeadmConfigTemplate")
                .expect("should have KubeadmConfigTemplate manifest");

            assert_eq!(config_template.api_version, CAPI_BOOTSTRAP_API_VERSION);
            assert_eq!(config_template.metadata.name, "my-cluster-pool-default");
        }

        /// Story: certSANs allow the API server certificate to be valid for
        /// additional hostnames/IPs (like localhost for local access).
        #[tokio::test]
        async fn cert_sans_included_in_control_plane_config() {
            let provider = DockerProvider::new();
            let cluster = sample_cluster("my-cluster", 2);
            let bootstrap = BootstrapInfo::default();

            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .expect("manifest generation should succeed");

            let control_plane = manifests
                .iter()
                .find(|m| m.kind == "KubeadmControlPlane")
                .expect("should have KubeadmControlPlane");

            let spec = control_plane.spec.as_ref().expect("spec should exist");
            let kubeadm_config = spec
                .get("kubeadmConfigSpec")
                .expect("kubeadmConfigSpec should exist");
            let cluster_config = kubeadm_config
                .get("clusterConfiguration")
                .expect("clusterConfiguration should exist");
            let api_server = cluster_config
                .get("apiServer")
                .expect("apiServer should exist");
            let cert_sans = api_server.get("certSANs").expect("certSANs should exist");

            assert!(cert_sans
                .as_array()
                .expect("certSANs should be an array")
                .contains(&json!("127.0.0.1")));
            assert!(cert_sans
                .as_array()
                .expect("certSANs should be an array")
                .contains(&json!("localhost")));
        }

        /// Story: All CAPI resources must be labeled with the cluster name so
        /// CAPI can track which resources belong to which cluster.
        #[tokio::test]
        async fn all_resources_labeled_with_cluster_name() {
            let provider = DockerProvider::new();
            let cluster = sample_cluster("labeled-cluster", 2);
            let bootstrap = BootstrapInfo::default();

            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .expect("manifest generation should succeed");

            for manifest in &manifests {
                let labels = manifest
                    .metadata
                    .labels
                    .as_ref()
                    .expect("should have labels");
                assert_eq!(
                    labels.get("cluster.x-k8s.io/cluster-name"),
                    Some(&"labeled-cluster".to_string()),
                    "manifest {} should have cluster name label",
                    manifest.kind
                );
            }
        }

        /// Story: Generated manifests must be valid YAML that can be applied
        /// to a Kubernetes cluster via kubectl or CAPI.
        #[tokio::test]
        async fn manifests_serialize_to_valid_yaml() {
            let provider = DockerProvider::new();
            let cluster = sample_cluster("yaml-test", 2);
            let bootstrap = BootstrapInfo::default();

            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .expect("manifest generation should succeed");

            for manifest in &manifests {
                let json = manifest.to_json().expect("should serialize");
                assert!(!json.is_empty(), "JSON should not be empty");

                // Verify it can be parsed back
                let parsed: CAPIManifest = serde_json::from_str(&json).expect("should parse back");
                assert_eq!(parsed.kind, manifest.kind);
                assert_eq!(parsed.metadata.name, manifest.metadata.name);
            }
        }
    }

    /// Provider Spec Validation Tests
    ///
    /// These tests verify that the DockerProvider correctly validates
    /// cluster specifications before attempting to generate manifests.
    mod validate_spec {
        use super::*;

        /// Story: A standard version like "1.32.0" should be accepted.
        #[tokio::test]
        async fn accepts_standard_semver_version() {
            let provider = DockerProvider::new();
            let spec = ProviderSpec {
                kubernetes: KubernetesSpec {
                    version: "1.32.0".to_string(),
                    cert_sans: None,
                    bootstrap: BootstrapProvider::default(),
                },
                config: ProviderConfig::docker(),
                credentials_secret_ref: None,
            };

            let result = provider.validate_spec(&spec).await;
            assert!(result.is_ok());
        }

        /// Story: Some users prefer the "v" prefix (v1.32.0) which is common
        /// in Kubernetes version strings.
        #[tokio::test]
        async fn accepts_version_with_v_prefix() {
            let provider = DockerProvider::new();
            let spec = ProviderSpec {
                kubernetes: KubernetesSpec {
                    version: "v1.32.0".to_string(),
                    cert_sans: None,
                    bootstrap: BootstrapProvider::default(),
                },
                config: ProviderConfig::docker(),
                credentials_secret_ref: None,
            };

            let result = provider.validate_spec(&spec).await;
            assert!(result.is_ok());
        }

        /// Story: Two-part versions like "1.32" are valid for specifying
        /// a minor version without pinning to a patch release.
        #[tokio::test]
        async fn accepts_two_part_version() {
            let provider = DockerProvider::new();
            let spec = ProviderSpec {
                kubernetes: KubernetesSpec {
                    version: "1.32".to_string(),
                    cert_sans: None,
                    bootstrap: BootstrapProvider::default(),
                },
                config: ProviderConfig::docker(),
                credentials_secret_ref: None,
            };

            let result = provider.validate_spec(&spec).await;
            assert!(result.is_ok());
        }

        /// Story: Kubernetes version is required - we can't provision without knowing
        /// which version to install.
        #[tokio::test]
        async fn rejects_empty_version() {
            let provider = DockerProvider::new();
            let spec = ProviderSpec {
                kubernetes: KubernetesSpec {
                    version: "".to_string(),
                    cert_sans: None,
                    bootstrap: BootstrapProvider::default(),
                },
                config: ProviderConfig::docker(),
                credentials_secret_ref: None,
            };

            let result = provider.validate_spec(&spec).await;
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("must be specified"));
        }

        /// Story: "latest" is not a valid version - we need explicit version numbers
        /// for reproducibility and to avoid unexpected upgrades.
        #[tokio::test]
        async fn rejects_invalid_version_format() {
            let provider = DockerProvider::new();
            let spec = ProviderSpec {
                kubernetes: KubernetesSpec {
                    version: "latest".to_string(),
                    cert_sans: None,
                    bootstrap: BootstrapProvider::default(),
                },
                config: ProviderConfig::docker(),
                credentials_secret_ref: None,
            };

            let result = provider.validate_spec(&spec).await;
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("invalid"));
        }

        /// Story: Pre-release versions like "1.32.beta" aren't supported -
        /// production clusters should use stable releases.
        #[tokio::test]
        async fn rejects_version_with_non_numeric_parts() {
            let provider = DockerProvider::new();
            let spec = ProviderSpec {
                kubernetes: KubernetesSpec {
                    version: "1.32.beta".to_string(),
                    cert_sans: None,
                    bootstrap: BootstrapProvider::default(),
                },
                config: ProviderConfig::docker(),
                credentials_secret_ref: None,
            };

            let result = provider.validate_spec(&spec).await;
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("must be numbers"));
        }
    }

    /// Post-Kubeadm Bootstrap Command Tests
    ///
    /// These tests verify the commands injected into kubeadm configuration
    /// for different cluster types (cell vs workload vs standalone).
    mod bootstrap_commands {
        use super::*;
        use crate::provider::BootstrapInfo;

        /// Story: All clusters should untaint control plane so it can run pods.
        /// This is essential for single-node clusters and the pivot flow.
        #[test]
        fn all_clusters_untaint_control_plane() {
            let bootstrap = BootstrapInfo::default();

            let commands = build_post_kubeadm_commands("test", &bootstrap).unwrap();

            assert!(!commands.is_empty());
            let commands_str = commands.join("\n");
            assert!(commands_str.contains("taint nodes"));
            assert!(commands_str.contains("NoSchedule-"));
        }

        /// Story: Workload clusters with bootstrap info should call the
        /// manifests endpoint to get CNI + agent manifests piped to kubectl.
        #[test]
        fn workload_cluster_calls_manifests_endpoint() {
            let bootstrap = BootstrapInfo::new(
                "https://mgmt.example.com:8080".to_string(),
                "test-token-123".to_string(),
                "-----BEGIN CERTIFICATE-----\nTEST_CA_CERT\n-----END CERTIFICATE-----".to_string(),
            );

            let commands = build_post_kubeadm_commands("workload-1", &bootstrap).unwrap();

            assert!(!commands.is_empty());
            let commands_str = commands.join("\n");
            assert!(commands_str.contains("mgmt.example.com:8080")); // Bootstrap endpoint
                                                                     // Script sets CLUSTER_NAME variable and uses it in URL
            assert!(commands_str.contains(r#"CLUSTER_NAME="workload-1""#)); // Cluster name variable
            assert!(commands_str.contains("/api/clusters/$CLUSTER_NAME/manifests")); // Manifests path with bash var
            assert!(commands_str.contains("test-token-123")); // Token in header
            assert!(commands_str.contains("--cacert")); // Uses CA cert for TLS
            assert!(commands_str.contains("TEST_CA_CERT")); // CA cert content written
            assert!(commands_str.contains("kubectl")); // Pipes to kubectl apply
        }

        /// Story: Cell clusters don't have bootstrap info since
        /// they ARE the management cluster. They just untaint.
        #[test]
        fn cell_cluster_does_not_call_bootstrap() {
            let bootstrap = BootstrapInfo::default();

            let commands = build_post_kubeadm_commands("mgmt", &bootstrap).unwrap();

            let commands_str = commands.join("\n");
            assert!(!commands_str.contains("/api/clusters"));
            assert!(commands_str.contains("taint")); // But still untaints
        }

        /// Story: Standalone clusters (no bootstrap info) just untaint,
        /// no bootstrap endpoint call needed.
        #[test]
        fn standalone_cluster_only_untaints() {
            let bootstrap = BootstrapInfo::default();

            let commands = build_post_kubeadm_commands("standalone", &bootstrap).unwrap();

            assert_eq!(commands.len(), 1); // Just the untaint command
            assert!(commands[0].contains("taint"));
        }
    }

    /// End-to-End Provider Tests
    ///
    /// These tests verify complete workflows through the provider,
    /// simulating real-world usage scenarios.
    mod end_to_end {
        use super::*;
        use crate::provider::BootstrapInfo;

        /// Story: A cell (management) cluster should generate all necessary
        /// CAPI resources that can be applied to bootstrap the platform.
        #[tokio::test]
        async fn cell_cluster_generates_complete_capi_stack() {
            let provider = DockerProvider::new();
            let cluster = sample_parent_cluster("mgmt");
            let bootstrap = BootstrapInfo::default();

            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .expect("manifest generation should succeed");

            // Verify all expected resource kinds are present
            let kinds: Vec<&str> = manifests.iter().map(|m| m.kind.as_str()).collect();
            assert!(kinds.contains(&"Cluster"), "missing Cluster");
            assert!(kinds.contains(&"DockerCluster"), "missing DockerCluster");
            assert!(
                kinds.contains(&"KubeadmControlPlane"),
                "missing KubeadmControlPlane"
            );
            assert!(
                kinds.contains(&"MachineDeployment"),
                "missing MachineDeployment"
            );

            // Verify all manifests can serialize to JSON
            for manifest in &manifests {
                manifest.to_json().expect("manifest should serialize");
            }
        }

        /// Story: A workload cluster should generate valid manifests that
        /// correctly reference the cluster name throughout all resources.
        #[tokio::test]
        async fn workload_cluster_has_consistent_naming() {
            let provider = DockerProvider::new();
            let cluster = sample_workload_cluster("workload-1");
            let bootstrap = BootstrapInfo::default();

            // First validate
            provider
                .validate_spec(&cluster.spec.provider)
                .await
                .expect("spec validation should succeed");

            // Then generate
            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .expect("manifest generation should succeed");

            // 4 base + 3 per pool (1 pool = default) = 7
            assert_eq!(manifests.len(), 7);

            // Verify cluster reference in MachineDeployment
            let deployment = manifests
                .iter()
                .find(|m| m.kind == "MachineDeployment")
                .expect("MachineDeployment should exist");
            let spec = deployment.spec.as_ref().expect("spec should exist");
            assert_eq!(
                spec.get("clusterName").expect("clusterName should exist"),
                "workload-1"
            );
        }

        /// Story: HA clusters with 3 control plane nodes should generate
        /// a KubeadmControlPlane with replicas=3 for fault tolerance.
        #[tokio::test]
        async fn ha_cluster_has_three_control_plane_nodes() {
            let provider = DockerProvider::new();
            let mut cluster = sample_cluster("ha-cluster", 3);
            cluster.spec.nodes.control_plane = 3;
            let bootstrap = BootstrapInfo::default();

            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .expect("manifest generation should succeed");

            let control_plane = manifests
                .iter()
                .find(|m| m.kind == "KubeadmControlPlane")
                .expect("KubeadmControlPlane should exist");

            let spec = control_plane.spec.as_ref().expect("spec should exist");
            assert_eq!(spec.get("replicas").expect("replicas should exist"), 3);
        }
    }

    /// RKE2 Bootstrap Provider Tests
    ///
    /// These tests verify that RKE2 clusters generate the correct manifests,
    /// including the custom HAProxy ConfigMap required for CAPD.
    mod rke2_support {
        use super::*;
        use crate::provider::BootstrapInfo;

        /// Helper to create an RKE2 cluster
        fn sample_rke2_cluster(name: &str, workers: u32) -> LatticeCluster {
            let mut cluster = sample_cluster(name, workers);
            cluster.spec.provider.kubernetes.bootstrap = BootstrapProvider::Rke2;
            cluster
        }

        /// Story: RKE2 clusters need 8 manifests: 7 standard + HAProxy ConfigMap
        #[tokio::test]
        async fn rke2_cluster_generates_eight_manifests() {
            let provider = DockerProvider::new();
            let cluster = sample_rke2_cluster("rke2-test", 2);
            let bootstrap = BootstrapInfo::default();

            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .expect("manifest generation should succeed");

            // 8 manifests: Cluster, ConfigMap, DockerCluster, RKE2ControlPlane,
            // DockerMachineTemplate (CP), MachineDeployment, DockerMachineTemplate (workers),
            // RKE2ConfigTemplate
            assert_eq!(manifests.len(), 8);
        }

        /// Story: RKE2 clusters must include a ConfigMap with HAProxy configuration
        #[tokio::test]
        async fn rke2_generates_haproxy_configmap() {
            let provider = DockerProvider::new();
            let cluster = sample_rke2_cluster("rke2-test", 2);
            let bootstrap = BootstrapInfo::default();

            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .expect("manifest generation should succeed");

            let configmap = manifests
                .iter()
                .find(|m| m.kind == "ConfigMap")
                .expect("RKE2 should generate a ConfigMap");

            assert_eq!(configmap.api_version, "v1");
            assert_eq!(configmap.metadata.name, "rke2-test-lb-config");

            // Verify the data contains the HAProxy config
            let data = configmap.data.as_ref().expect("ConfigMap should have data");
            let value = data.get("value").expect("should have value key");
            let config = value.as_str().expect("value should be a string");

            // Key features of the RKE2 HAProxy config
            assert!(config.contains("option httpchk GET /healthz"));
            assert!(config.contains("check-ssl verify none"));
            assert!(config.contains("frontend rke2-join"));
            assert!(config.contains("bind *:9345"));
            assert!(config.contains("/v1-rke2/readyz"));
        }

        /// Story: RKE2 DockerCluster must reference the custom HAProxy ConfigMap
        #[tokio::test]
        async fn rke2_docker_cluster_references_haproxy_configmap() {
            let provider = DockerProvider::new();
            let cluster = sample_rke2_cluster("rke2-test", 2);
            let bootstrap = BootstrapInfo::default();

            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .expect("manifest generation should succeed");

            let docker_cluster = manifests
                .iter()
                .find(|m| m.kind == "DockerCluster")
                .expect("should have DockerCluster");

            let spec = docker_cluster.spec.as_ref().expect("should have spec");
            let lb = spec.get("loadBalancer").expect("should have loadBalancer");
            let haproxy_ref = lb
                .get("customHAProxyConfigTemplateRef")
                .expect("should have customHAProxyConfigTemplateRef");
            let ref_name = haproxy_ref.get("name").expect("should have name");

            assert_eq!(ref_name, "rke2-test-lb-config");
        }

        /// Story: Kubeadm clusters should NOT have the HAProxy ConfigMap
        #[tokio::test]
        async fn kubeadm_cluster_has_no_haproxy_configmap() {
            let provider = DockerProvider::new();
            let cluster = sample_cluster("kubeadm-test", 2); // Uses default kubeadm
            let bootstrap = BootstrapInfo::default();

            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .expect("manifest generation should succeed");

            // 4 base + 3 per pool (1 pool = default) = 7 manifests (no ConfigMap)
            assert_eq!(manifests.len(), 7);

            // No ConfigMap
            let configmap = manifests.iter().find(|m| m.kind == "ConfigMap");
            assert!(configmap.is_none());

            // DockerCluster should have empty spec
            let docker_cluster = manifests
                .iter()
                .find(|m| m.kind == "DockerCluster")
                .expect("should have DockerCluster");
            let spec = docker_cluster.spec.as_ref().expect("should have spec");
            assert!(spec.get("loadBalancer").is_none());
        }
    }
}
