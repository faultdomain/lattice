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
//! ```ignore
//! use lattice::provider::{Provider, DockerProvider};
//! use lattice::crd::LatticeCluster;
//!
//! let provider = DockerProvider::new();
//! let cluster = /* create LatticeCluster */;
//! let manifests = provider.generate_capi_manifests(&cluster).await?;
//! ```

use async_trait::async_trait;
use serde_json::json;
use std::collections::BTreeMap;

use super::{CAPIManifest, Provider};
use crate::crd::{LatticeCluster, ProviderSpec, ProviderType};
use crate::Result;

/// Default namespace for CAPI resources
const DEFAULT_NAMESPACE: &str = "default";

/// CAPI API versions
const CAPI_CLUSTER_API_VERSION: &str = "cluster.x-k8s.io/v1beta1";
const CAPI_CONTROLPLANE_API_VERSION: &str = "controlplane.cluster.x-k8s.io/v1beta1";
const CAPI_BOOTSTRAP_API_VERSION: &str = "bootstrap.cluster.x-k8s.io/v1beta1";
const DOCKER_INFRASTRUCTURE_API_VERSION: &str = "infrastructure.cluster.x-k8s.io/v1beta1";

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

    /// Get the cluster name from a LatticeCluster, or return an error
    fn get_cluster_name(cluster: &LatticeCluster) -> Result<&str> {
        cluster
            .metadata
            .name
            .as_deref()
            .ok_or_else(|| crate::Error::validation("cluster must have a name"))
    }

    /// Get the namespace for resources
    fn get_namespace(&self, cluster: &LatticeCluster) -> String {
        cluster
            .metadata
            .namespace
            .clone()
            .unwrap_or_else(|| self.namespace.clone())
    }

    /// Create standard labels for CAPI resources
    fn create_labels(cluster_name: &str) -> BTreeMap<String, String> {
        let mut labels = BTreeMap::new();
        labels.insert(
            "cluster.x-k8s.io/cluster-name".to_string(),
            cluster_name.to_string(),
        );
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            "lattice".to_string(),
        );
        labels
    }

    /// Generate the main Cluster resource
    fn generate_cluster(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = Self::get_cluster_name(cluster)?;
        let namespace = self.get_namespace(cluster);
        let labels = Self::create_labels(name);

        let spec = json!({
            "clusterNetwork": {
                "pods": {
                    "cidrBlocks": ["192.168.0.0/16"]
                },
                "services": {
                    "cidrBlocks": ["10.128.0.0/12"]
                }
            },
            "controlPlaneRef": {
                "apiVersion": CAPI_CONTROLPLANE_API_VERSION,
                "kind": "KubeadmControlPlane",
                "name": format!("{}-control-plane", name),
                "namespace": namespace
            },
            "infrastructureRef": {
                "apiVersion": DOCKER_INFRASTRUCTURE_API_VERSION,
                "kind": "DockerCluster",
                "name": name,
                "namespace": namespace
            }
        });

        Ok(
            CAPIManifest::new(CAPI_CLUSTER_API_VERSION, "Cluster", name, &namespace)
                .with_labels(labels)
                .with_spec(spec),
        )
    }

    /// Generate the DockerCluster resource
    fn generate_docker_cluster(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = Self::get_cluster_name(cluster)?;
        let namespace = self.get_namespace(cluster);
        let labels = Self::create_labels(name);

        // DockerCluster has minimal spec - most config is in the Cluster resource
        let spec = json!({});

        Ok(CAPIManifest::new(
            DOCKER_INFRASTRUCTURE_API_VERSION,
            "DockerCluster",
            name,
            &namespace,
        )
        .with_labels(labels)
        .with_spec(spec))
    }

    /// Generate the KubeadmControlPlane resource
    fn generate_control_plane(
        &self,
        cluster: &LatticeCluster,
        bootstrap: &super::BootstrapInfo,
    ) -> Result<CAPIManifest> {
        let name = Self::get_cluster_name(cluster)?;
        let namespace = self.get_namespace(cluster);
        let labels = Self::create_labels(name);
        let cp_name = format!("{}-control-plane", name);

        let k8s_version = &cluster.spec.provider.kubernetes.version;
        let replicas = cluster.spec.nodes.control_plane;

        // Build certSANs - always include localhost/127.0.0.1 for local access
        let mut cert_sans = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        // Add any user-specified SANs
        if let Some(ref user_sans) = cluster.spec.provider.kubernetes.cert_sans {
            for san in user_sans {
                if !cert_sans.contains(san) {
                    cert_sans.push(san.clone());
                }
            }
        }

        // Build postKubeadmCommands for agent bootstrap
        let post_kubeadm_commands = self.build_post_kubeadm_commands(cluster, bootstrap);

        let mut kubeadm_config_spec = json!({
            "clusterConfiguration": {
                "apiServer": {
                    "certSANs": cert_sans
                },
                "controllerManager": {
                    "extraArgs": {
                        "bind-address": "0.0.0.0"
                    }
                },
                "scheduler": {
                    "extraArgs": {
                        "bind-address": "0.0.0.0"
                    }
                }
            },
            "initConfiguration": {
                "nodeRegistration": {
                    "criSocket": "/var/run/containerd/containerd.sock",
                    "kubeletExtraArgs": {
                        "eviction-hard": "nodefs.available<0%,imagefs.available<0%"
                    }
                }
            },
            "joinConfiguration": {
                "nodeRegistration": {
                    "criSocket": "/var/run/containerd/containerd.sock",
                    "kubeletExtraArgs": {
                        "eviction-hard": "nodefs.available<0%,imagefs.available<0%"
                    }
                }
            }
        });

        // Add postKubeadmCommands if any
        if !post_kubeadm_commands.is_empty() {
            kubeadm_config_spec["postKubeadmCommands"] = json!(post_kubeadm_commands);
        }

        let spec = json!({
            "replicas": replicas,
            "version": format!("v{}", k8s_version),
            "machineTemplate": {
                "infrastructureRef": {
                    "apiVersion": DOCKER_INFRASTRUCTURE_API_VERSION,
                    "kind": "DockerMachineTemplate",
                    "name": format!("{}-control-plane", name),
                    "namespace": namespace
                }
            },
            "kubeadmConfigSpec": kubeadm_config_spec
        });

        Ok(CAPIManifest::new(
            CAPI_CONTROLPLANE_API_VERSION,
            "KubeadmControlPlane",
            &cp_name,
            &namespace,
        )
        .with_labels(labels)
        .with_spec(spec))
    }

    /// Generate the DockerMachineTemplate for control plane nodes
    fn generate_control_plane_machine_template(
        &self,
        cluster: &LatticeCluster,
    ) -> Result<CAPIManifest> {
        let name = Self::get_cluster_name(cluster)?;
        let namespace = self.get_namespace(cluster);
        let labels = Self::create_labels(name);
        let template_name = format!("{}-control-plane", name);

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
            DOCKER_INFRASTRUCTURE_API_VERSION,
            "DockerMachineTemplate",
            &template_name,
            &namespace,
        )
        .with_labels(labels)
        .with_spec(spec))
    }

    /// Generate the MachineDeployment for worker nodes
    fn generate_worker_deployment(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = Self::get_cluster_name(cluster)?;
        let namespace = self.get_namespace(cluster);
        let labels = Self::create_labels(name);
        let deployment_name = format!("{}-md-0", name);

        let k8s_version = &cluster.spec.provider.kubernetes.version;
        let replicas = cluster.spec.nodes.workers;

        let spec = json!({
            "clusterName": name,
            "replicas": replicas,
            "selector": {
                "matchLabels": {}
            },
            "template": {
                "spec": {
                    "clusterName": name,
                    "version": format!("v{}", k8s_version),
                    "bootstrap": {
                        "configRef": {
                            "apiVersion": CAPI_BOOTSTRAP_API_VERSION,
                            "kind": "KubeadmConfigTemplate",
                            "name": format!("{}-md-0", name),
                            "namespace": namespace
                        }
                    },
                    "infrastructureRef": {
                        "apiVersion": DOCKER_INFRASTRUCTURE_API_VERSION,
                        "kind": "DockerMachineTemplate",
                        "name": format!("{}-md-0", name),
                        "namespace": namespace
                    }
                }
            }
        });

        Ok(CAPIManifest::new(
            CAPI_CLUSTER_API_VERSION,
            "MachineDeployment",
            &deployment_name,
            &namespace,
        )
        .with_labels(labels)
        .with_spec(spec))
    }

    /// Generate the DockerMachineTemplate for worker nodes
    fn generate_worker_machine_template(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = Self::get_cluster_name(cluster)?;
        let namespace = self.get_namespace(cluster);
        let labels = Self::create_labels(name);
        let template_name = format!("{}-md-0", name);

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
            DOCKER_INFRASTRUCTURE_API_VERSION,
            "DockerMachineTemplate",
            &template_name,
            &namespace,
        )
        .with_labels(labels)
        .with_spec(spec))
    }

    /// Generate the KubeadmConfigTemplate for worker nodes
    fn generate_worker_config_template(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = Self::get_cluster_name(cluster)?;
        let namespace = self.get_namespace(cluster);
        let labels = Self::create_labels(name);
        let template_name = format!("{}-md-0", name);

        let spec = json!({
            "template": {
                "spec": {
                    "joinConfiguration": {
                        "nodeRegistration": {
                            "criSocket": "/var/run/containerd/containerd.sock",
                            "kubeletExtraArgs": {
                                "eviction-hard": "nodefs.available<0%,imagefs.available<0%"
                            }
                        }
                    }
                }
            }
        });

        Ok(CAPIManifest::new(
            CAPI_BOOTSTRAP_API_VERSION,
            "KubeadmConfigTemplate",
            &template_name,
            &namespace,
        )
        .with_labels(labels)
        .with_spec(spec))
    }

    /// Build postKubeadmCommands for agent bootstrap
    ///
    /// This generates the commands that will be run after kubeadm completes.
    /// For workload clusters with a cell reference, this includes calling
    /// the registration webhook to get the agent bootstrap payload.
    fn build_post_kubeadm_commands(
        &self,
        cluster: &LatticeCluster,
        bootstrap: &super::BootstrapInfo,
    ) -> Vec<String> {
        let mut commands = Vec::new();
        let name = cluster.metadata.name.as_deref().unwrap_or("unknown");

        // Untaint control plane so pods can schedule (all clusters need this)
        commands.push(
            r#"kubectl --kubeconfig=/etc/kubernetes/admin.conf taint nodes --all node-role.kubernetes.io/control-plane:NoSchedule-"#
                .to_string(),
        );

        // If cluster has bootstrap info, fetch and apply manifests from parent
        if let (Some(ref endpoint), Some(ref token), Some(ref ca_cert)) = (
            &bootstrap.bootstrap_endpoint,
            &bootstrap.bootstrap_token,
            &bootstrap.ca_cert_pem,
        ) {
            commands.push(format!(
                r#"echo "Bootstrapping cluster {name} from {endpoint}""#
            ));

            // Write CA cert to verify TLS connection to parent
            commands.push(format!(
                r#"cat > /tmp/cell-ca.crt << 'CACERT'
{ca_cert}
CACERT"#
            ));

            // Retry fetching manifests until success (with backoff)
            commands.push(format!(
                r#"echo "Fetching bootstrap manifests from parent..."
MANIFEST_FILE=/tmp/bootstrap-manifests.yaml
RETRY_DELAY=5
while true; do
  if curl -sf --cacert /tmp/cell-ca.crt "{endpoint}/api/clusters/{name}/manifests" \
    -H "Authorization: Bearer {token}" \
    -o "$MANIFEST_FILE"; then
    echo "Successfully fetched bootstrap manifests"
    break
  fi
  echo "Failed to fetch manifests, retrying in ${{RETRY_DELAY}}s..."
  sleep $RETRY_DELAY
  RETRY_DELAY=$((RETRY_DELAY < 60 ? RETRY_DELAY * 2 : 60))
done"#,
            ));

            // Apply manifests with retry
            commands.push(
                r#"echo "Applying bootstrap manifests..."
RETRY_DELAY=5
while true; do
  if kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f /tmp/bootstrap-manifests.yaml; then
    echo "Successfully applied bootstrap manifests"
    break
  fi
  echo "Failed to apply manifests, retrying in ${RETRY_DELAY}s..."
  sleep $RETRY_DELAY
  RETRY_DELAY=$((RETRY_DELAY < 60 ? RETRY_DELAY * 2 : 60))
done"#
                    .to_string(),
            );

            // Clean up temp files
            commands.push(r#"rm -f /tmp/cell-ca.crt /tmp/bootstrap-manifests.yaml"#.to_string());

            // Note: Control plane re-taint happens after pivot completes, not here
        }

        commands
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
        // Core cluster resources and control plane resources
        let mut manifests = vec![
            self.generate_cluster(cluster)?,
            self.generate_docker_cluster(cluster)?,
            self.generate_control_plane(cluster, bootstrap)?,
            self.generate_control_plane_machine_template(cluster)?,
        ];

        // Worker resources (only if workers > 0)
        if cluster.spec.nodes.workers > 0 {
            manifests.push(self.generate_worker_deployment(cluster)?);
            manifests.push(self.generate_worker_machine_template(cluster)?);
            manifests.push(self.generate_worker_config_template(cluster)?);
        }

        Ok(manifests)
    }

    /// Validate that the provider spec is valid for Docker
    ///
    /// Checks:
    /// - Provider type must be Docker
    /// - Kubernetes version must be specified
    async fn validate_spec(&self, spec: &ProviderSpec) -> Result<()> {
        // Verify provider type is Docker
        if spec.type_ != ProviderType::Docker {
            return Err(crate::Error::provider(format!(
                "DockerProvider received non-docker provider type: {}",
                spec.type_
            )));
        }

        // Validate Kubernetes version format (basic check)
        let version = &spec.kubernetes.version;
        if version.is_empty() {
            return Err(crate::Error::validation(
                "kubernetes version must be specified",
            ));
        }

        // Check version format (should be like "1.31.0" or "v1.31.0")
        let version_clean = version.strip_prefix('v').unwrap_or(version);
        let parts: Vec<&str> = version_clean.split('.').collect();
        if parts.len() < 2 {
            return Err(crate::Error::validation(format!(
                "invalid kubernetes version format: {}, expected format like '1.31.0'",
                version
            )));
        }

        // Verify each part is a number
        for part in &parts {
            if part.parse::<u32>().is_err() {
                return Err(crate::Error::validation(format!(
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
    use crate::crd::{
        CellSpec, KubernetesSpec, LatticeClusterSpec, NodeSpec, ProviderSpec, ProviderType,
        ServiceSpec,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    /// Helper to create a sample LatticeCluster for testing
    fn sample_cluster(name: &str, workers: u32) -> LatticeCluster {
        LatticeCluster {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: LatticeClusterSpec {
                provider: ProviderSpec {
                    type_: ProviderType::Docker,
                    kubernetes: KubernetesSpec {
                        version: "1.31.0".to_string(),
                        cert_sans: Some(vec!["127.0.0.1".to_string(), "localhost".to_string()]),
                    },
                },
                nodes: NodeSpec {
                    control_plane: 1,
                    workers,
                },
                networking: None,
                cell: None,
                cell_ref: None,
                environment: None,
                region: None,
                workload: None,
            },
            status: None,
        }
    }

    /// Helper to create a cell (management) cluster
    fn sample_cell_cluster(name: &str) -> LatticeCluster {
        let mut cluster = sample_cluster(name, 2);
        cluster.spec.cell = Some(CellSpec {
            host: "172.18.255.1".to_string(),
            grpc_port: 50051,
            bootstrap_port: 8443,
            service: ServiceSpec {
                type_: "LoadBalancer".to_string(),
            },
        });
        cluster
    }

    /// Helper to create a workload cluster with cell reference
    fn sample_workload_cluster(name: &str, cell_ref: &str) -> LatticeCluster {
        let mut cluster = sample_cluster(name, 3);
        cluster.spec.cell_ref = Some(cell_ref.to_string());
        cluster
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

        /// Story: A LatticeCluster CRD must have a name to generate CAPI resources.
        /// If somehow a cluster without a name is submitted, we should fail with
        /// a clear validation error rather than generating invalid manifests.
        #[tokio::test]
        async fn cluster_without_name_fails_gracefully() {
            use crate::provider::BootstrapInfo;

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
            assert!(result.unwrap_err().to_string().contains("must have a name"));
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
                .unwrap();

            assert_eq!(manifests.len(), 7);
        }

        /// Story: A control-plane-only cluster (useful for single-node dev clusters)
        /// needs only 4 resources since worker-related resources are skipped.
        #[tokio::test]
        async fn control_plane_only_cluster_generates_four_manifests() {
            let provider = DockerProvider::new();
            let cluster = sample_cluster("test-cluster", 0);
            let bootstrap = BootstrapInfo::default();
            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .unwrap();

            assert_eq!(manifests.len(), 4);
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
                .unwrap();

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

            let spec = cluster_manifest.spec.as_ref().unwrap();
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
                .unwrap();

            let docker_cluster = manifests
                .iter()
                .find(|m| m.kind == "DockerCluster")
                .expect("should have DockerCluster manifest");

            assert_eq!(
                docker_cluster.api_version,
                DOCKER_INFRASTRUCTURE_API_VERSION
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
                .unwrap();

            let control_plane = manifests
                .iter()
                .find(|m| m.kind == "KubeadmControlPlane")
                .expect("should have KubeadmControlPlane manifest");

            assert_eq!(control_plane.api_version, CAPI_CONTROLPLANE_API_VERSION);
            assert_eq!(control_plane.metadata.name, "my-cluster-control-plane");

            let spec = control_plane.spec.as_ref().unwrap();
            assert_eq!(spec.get("replicas").unwrap(), 3);
            assert_eq!(spec.get("version").unwrap(), "v1.31.0");
        }

        /// Story: Worker node count is configurable. The MachineDeployment manages
        /// scaling workers up or down to match the desired count.
        #[tokio::test]
        async fn worker_deployment_respects_replica_count() {
            let provider = DockerProvider::new();
            let cluster = sample_cluster("my-cluster", 5);
            let bootstrap = BootstrapInfo::default();

            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .unwrap();

            let deployment = manifests
                .iter()
                .find(|m| m.kind == "MachineDeployment")
                .expect("should have MachineDeployment manifest");

            assert_eq!(deployment.api_version, CAPI_CLUSTER_API_VERSION);
            assert_eq!(deployment.metadata.name, "my-cluster-md-0");

            let spec = deployment.spec.as_ref().unwrap();
            assert_eq!(spec.get("replicas").unwrap(), 5);
            assert_eq!(spec.get("clusterName").unwrap(), "my-cluster");
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
                .unwrap();

            let machine_templates: Vec<_> = manifests
                .iter()
                .filter(|m| m.kind == "DockerMachineTemplate")
                .collect();

            // Should have 2: one for control plane, one for workers
            assert_eq!(machine_templates.len(), 2);

            let cp_template = machine_templates
                .iter()
                .find(|m| m.metadata.name == "my-cluster-control-plane")
                .expect("should have control plane template");
            assert_eq!(cp_template.api_version, DOCKER_INFRASTRUCTURE_API_VERSION);

            let worker_template = machine_templates
                .iter()
                .find(|m| m.metadata.name == "my-cluster-md-0")
                .expect("should have worker template");
            assert_eq!(
                worker_template.api_version,
                DOCKER_INFRASTRUCTURE_API_VERSION
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
                .unwrap();

            let config_template = manifests
                .iter()
                .find(|m| m.kind == "KubeadmConfigTemplate")
                .expect("should have KubeadmConfigTemplate manifest");

            assert_eq!(config_template.api_version, CAPI_BOOTSTRAP_API_VERSION);
            assert_eq!(config_template.metadata.name, "my-cluster-md-0");
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
                .unwrap();

            let control_plane = manifests
                .iter()
                .find(|m| m.kind == "KubeadmControlPlane")
                .expect("should have KubeadmControlPlane");

            let spec = control_plane.spec.as_ref().unwrap();
            let kubeadm_config = spec.get("kubeadmConfigSpec").unwrap();
            let cluster_config = kubeadm_config.get("clusterConfiguration").unwrap();
            let api_server = cluster_config.get("apiServer").unwrap();
            let cert_sans = api_server.get("certSANs").unwrap();

            assert!(cert_sans.as_array().unwrap().contains(&json!("127.0.0.1")));
            assert!(cert_sans.as_array().unwrap().contains(&json!("localhost")));
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
                .unwrap();

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
                .unwrap();

            for manifest in &manifests {
                let yaml = manifest.to_yaml().expect("should serialize to YAML");
                assert!(!yaml.is_empty(), "YAML should not be empty");

                // Verify it can be parsed back
                let parsed: CAPIManifest =
                    serde_yaml::from_str(&yaml).expect("should parse back from YAML");
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

        /// Story: A standard version like "1.31.0" should be accepted.
        #[tokio::test]
        async fn accepts_standard_semver_version() {
            let provider = DockerProvider::new();
            let spec = ProviderSpec {
                type_: ProviderType::Docker,
                kubernetes: KubernetesSpec {
                    version: "1.31.0".to_string(),
                    cert_sans: None,
                },
            };

            let result = provider.validate_spec(&spec).await;
            assert!(result.is_ok());
        }

        /// Story: Some users prefer the "v" prefix (v1.31.0) which is common
        /// in Kubernetes version strings.
        #[tokio::test]
        async fn accepts_version_with_v_prefix() {
            let provider = DockerProvider::new();
            let spec = ProviderSpec {
                type_: ProviderType::Docker,
                kubernetes: KubernetesSpec {
                    version: "v1.31.0".to_string(),
                    cert_sans: None,
                },
            };

            let result = provider.validate_spec(&spec).await;
            assert!(result.is_ok());
        }

        /// Story: Two-part versions like "1.31" are valid for specifying
        /// a minor version without pinning to a patch release.
        #[tokio::test]
        async fn accepts_two_part_version() {
            let provider = DockerProvider::new();
            let spec = ProviderSpec {
                type_: ProviderType::Docker,
                kubernetes: KubernetesSpec {
                    version: "1.31".to_string(),
                    cert_sans: None,
                },
            };

            let result = provider.validate_spec(&spec).await;
            assert!(result.is_ok());
        }

        /// Story: If someone accidentally sends an AWS spec to the Docker provider,
        /// it should fail fast with a clear error.
        #[tokio::test]
        async fn rejects_non_docker_provider_type() {
            let provider = DockerProvider::new();
            let spec = ProviderSpec {
                type_: ProviderType::Aws,
                kubernetes: KubernetesSpec {
                    version: "1.31.0".to_string(),
                    cert_sans: None,
                },
            };

            let result = provider.validate_spec(&spec).await;
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("non-docker"));
        }

        /// Story: Kubernetes version is required - we can't provision without knowing
        /// which version to install.
        #[tokio::test]
        async fn rejects_empty_version() {
            let provider = DockerProvider::new();
            let spec = ProviderSpec {
                type_: ProviderType::Docker,
                kubernetes: KubernetesSpec {
                    version: "".to_string(),
                    cert_sans: None,
                },
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
                type_: ProviderType::Docker,
                kubernetes: KubernetesSpec {
                    version: "latest".to_string(),
                    cert_sans: None,
                },
            };

            let result = provider.validate_spec(&spec).await;
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("invalid"));
        }

        /// Story: Pre-release versions like "1.31.beta" aren't supported -
        /// production clusters should use stable releases.
        #[tokio::test]
        async fn rejects_version_with_non_numeric_parts() {
            let provider = DockerProvider::new();
            let spec = ProviderSpec {
                type_: ProviderType::Docker,
                kubernetes: KubernetesSpec {
                    version: "1.31.beta".to_string(),
                    cert_sans: None,
                },
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
            let provider = DockerProvider::new();
            let cluster = sample_cluster("test", 0);
            let bootstrap = BootstrapInfo::default();

            let commands = provider.build_post_kubeadm_commands(&cluster, &bootstrap);

            assert!(!commands.is_empty());
            let commands_str = commands.join("\n");
            assert!(commands_str.contains("taint nodes"));
            assert!(commands_str.contains("NoSchedule-"));
        }

        /// Story: Workload clusters with bootstrap info should call the
        /// manifests endpoint to get CNI + agent manifests piped to kubectl.
        #[test]
        fn workload_cluster_calls_manifests_endpoint() {
            let provider = DockerProvider::new();
            let cluster = sample_workload_cluster("workload-1", "mgmt.example.com");
            let bootstrap = BootstrapInfo::new(
                "https://mgmt.example.com:8080".to_string(),
                "test-token-123".to_string(),
                "-----BEGIN CERTIFICATE-----\nTEST_CA_CERT\n-----END CERTIFICATE-----".to_string(),
            );

            let commands = provider.build_post_kubeadm_commands(&cluster, &bootstrap);

            assert!(!commands.is_empty());
            let commands_str = commands.join("\n");
            assert!(commands_str.contains("mgmt.example.com:8080")); // Bootstrap endpoint
            assert!(commands_str.contains("/api/clusters/workload-1/manifests")); // Manifests path
            assert!(commands_str.contains("test-token-123")); // Token in header
            assert!(commands_str.contains("--cacert /tmp/cell-ca.crt")); // Uses CA cert for TLS
            assert!(commands_str.contains("TEST_CA_CERT")); // CA cert content written
            assert!(commands_str.contains("kubectl")); // Pipes to kubectl apply
        }

        /// Story: Cell clusters don't have bootstrap info since
        /// they ARE the management cluster. They just untaint.
        #[test]
        fn cell_cluster_does_not_call_bootstrap() {
            let provider = DockerProvider::new();
            let cluster = sample_cell_cluster("mgmt");
            let bootstrap = BootstrapInfo::default();

            let commands = provider.build_post_kubeadm_commands(&cluster, &bootstrap);

            let commands_str = commands.join("\n");
            assert!(!commands_str.contains("/api/clusters"));
            assert!(commands_str.contains("taint")); // But still untaints
        }

        /// Story: Standalone clusters (no bootstrap info) just untaint,
        /// no bootstrap endpoint call needed.
        #[test]
        fn standalone_cluster_only_untaints() {
            let provider = DockerProvider::new();
            let cluster = sample_cluster("standalone", 2);
            let bootstrap = BootstrapInfo::default();

            let commands = provider.build_post_kubeadm_commands(&cluster, &bootstrap);

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
            let cluster = sample_cell_cluster("mgmt");
            let bootstrap = BootstrapInfo::default();

            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .unwrap();

            // Verify we can serialize all manifests to YAML
            let mut yaml_docs = Vec::new();
            for manifest in &manifests {
                yaml_docs.push(manifest.to_yaml().unwrap());
            }

            // Join with separator for multi-document YAML
            let full_yaml = yaml_docs.join("---\n");
            assert!(full_yaml.contains("kind: Cluster"));
            assert!(full_yaml.contains("kind: DockerCluster"));
            assert!(full_yaml.contains("kind: KubeadmControlPlane"));
            assert!(full_yaml.contains("kind: MachineDeployment"));
        }

        /// Story: A workload cluster should generate valid manifests that
        /// correctly reference the cluster name throughout all resources.
        #[tokio::test]
        async fn workload_cluster_has_consistent_naming() {
            let provider = DockerProvider::new();
            let cluster = sample_workload_cluster("workload-1", "mgmt");
            let bootstrap = BootstrapInfo::default();

            // First validate
            provider
                .validate_spec(&cluster.spec.provider)
                .await
                .unwrap();

            // Then generate
            let manifests = provider
                .generate_capi_manifests(&cluster, &bootstrap)
                .await
                .unwrap();

            assert_eq!(manifests.len(), 7);

            // Verify cluster reference in MachineDeployment
            let deployment = manifests
                .iter()
                .find(|m| m.kind == "MachineDeployment")
                .unwrap();
            let spec = deployment.spec.as_ref().unwrap();
            assert_eq!(spec.get("clusterName").unwrap(), "workload-1");
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
                .unwrap();

            let control_plane = manifests
                .iter()
                .find(|m| m.kind == "KubeadmControlPlane")
                .unwrap();

            let spec = control_plane.spec.as_ref().unwrap();
            assert_eq!(spec.get("replicas").unwrap(), 3);
        }
    }
}
