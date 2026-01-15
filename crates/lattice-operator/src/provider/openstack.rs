//! OpenStack infrastructure provider (CAPO)
//!
//! This provider generates Cluster API manifests for provisioning Kubernetes
//! clusters on OpenStack using the CAPO provider. Works with any OpenStack
//! cloud including OVH Public Cloud.
//!
//! CAPO API: infrastructure.cluster.x-k8s.io/v1beta1

use async_trait::async_trait;
use std::collections::BTreeMap;

use super::{
    build_post_kubeadm_commands, generate_bootstrap_config_template, generate_cluster,
    generate_control_plane, generate_machine_deployment, BootstrapInfo, CAPIManifest,
    ClusterConfig, ControlPlaneConfig, InfrastructureRef, Provider,
};
use crate::crd::{LatticeCluster, OpenstackConfig, ProviderSpec};
use crate::Result;

/// CAPO API version
const OPENSTACK_API_VERSION: &str = "infrastructure.cluster.x-k8s.io/v1beta1";

/// OpenStack infrastructure provider
///
/// Generates CAPI manifests for OpenStack using the CAPO provider.
/// Supports both kubeadm and RKE2 bootstrap providers.
#[derive(Clone, Debug)]
pub struct OpenstackProvider {
    /// Namespace for CAPI resources
    namespace: String,
}

impl OpenstackProvider {
    /// Create a new OpenStack provider with the given namespace
    pub fn with_namespace(namespace: &str) -> Self {
        Self {
            namespace: namespace.to_string(),
        }
    }

    /// Get infrastructure reference for OpenStack
    fn infra_ref(&self) -> InfrastructureRef<'static> {
        InfrastructureRef {
            api_group: "infrastructure.cluster.x-k8s.io",
            api_version: OPENSTACK_API_VERSION,
            cluster_kind: "OpenStackCluster",
            machine_template_kind: "OpenStackMachineTemplate",
        }
    }

    /// Extract OpenstackConfig from the cluster's provider config
    fn get_openstack_config(cluster: &LatticeCluster) -> Option<&OpenstackConfig> {
        cluster.spec.provider.config.openstack.as_ref()
    }

    /// Generate OpenStackCluster manifest
    fn generate_openstack_cluster(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = cluster
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| crate::Error::validation("cluster name required".to_string()))?;

        let os_config = Self::get_openstack_config(cluster);

        // Cloud name from clouds.yaml
        let cloud_name = os_config
            .and_then(|c| c.cloud_name.clone())
            .unwrap_or_else(|| "openstack".to_string());

        // External network for floating IPs
        let external_network = os_config
            .and_then(|c| c.external_network.clone())
            .unwrap_or_else(|| "Ext-Net".to_string());

        // DNS nameservers
        let dns_nameservers = os_config
            .and_then(|c| c.dns_nameservers.clone())
            .unwrap_or_else(|| vec!["8.8.8.8".to_string()]);

        // Build managed subnets or use existing network
        let network_spec = if let Some(network_id) = os_config.and_then(|c| c.network_id.clone()) {
            // Use existing network
            let mut spec = serde_json::json!({
                "id": network_id
            });
            if let Some(subnet_id) = os_config.and_then(|c| c.subnet_id.clone()) {
                spec["subnets"] = serde_json::json!([{"id": subnet_id}]);
            }
            Some(spec)
        } else {
            None
        };

        let managed_subnet_cidr = os_config
            .and_then(|c| c.managed_subnet_cidr.clone())
            .unwrap_or_else(|| "10.6.0.0/24".to_string());

        let mut spec_json = serde_json::json!({
            "identityRef": {
                "cloudName": cloud_name,
                "name": format!("{}-cloud-config", name),
                "kind": "Secret"
            },
            "externalNetwork": {
                "id": external_network
            },
            "apiServerLoadBalancer": {
                "enabled": true
            }
        });

        // Add network config
        if let Some(network) = network_spec {
            spec_json["network"] = network;
        } else {
            // Use managed subnets
            spec_json["managedSubnets"] = serde_json::json!([{
                "cidr": managed_subnet_cidr,
                "dnsNameservers": dns_nameservers
            }]);
        }

        // Add control plane endpoint if specified
        if let Some(ref endpoints) = cluster.spec.endpoints {
            spec_json["controlPlaneEndpoint"] = serde_json::json!({
                "host": endpoints.host,
                "port": 6443
            });
        }

        Ok(CAPIManifest::new(
            OPENSTACK_API_VERSION,
            "OpenStackCluster",
            name,
            &self.namespace,
        )
        .with_spec(spec_json))
    }

    /// Generate OpenStackMachineTemplate for control plane nodes
    fn generate_cp_machine_template(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = cluster
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| crate::Error::validation("cluster name required".to_string()))?;

        let os_config = Self::get_openstack_config(cluster);

        // Flavor (instance type)
        let flavor = os_config
            .and_then(|c| c.cp_flavor.clone())
            .unwrap_or_else(|| "m1.large".to_string());

        // Image name
        let image_name = os_config
            .and_then(|c| c.image_name.clone())
            .unwrap_or_else(|| "Ubuntu 22.04".to_string());

        // SSH key (optional)
        let ssh_key_name = os_config.and_then(|c| c.ssh_key_name.clone());

        // Root volume size
        let root_volume_size = os_config.and_then(|c| c.cp_root_volume_size);

        let mut machine_spec = serde_json::json!({
            "flavor": flavor,
            "image": {
                "filter": {
                    "name": image_name
                }
            }
        });

        // Add SSH key if specified
        if let Some(key_name) = ssh_key_name {
            machine_spec["sshKeyName"] = serde_json::json!(key_name);
        }

        // Add root volume if specified
        if let Some(size) = root_volume_size {
            machine_spec["rootVolume"] = serde_json::json!({
                "sizeGiB": size
            });
        }

        let spec_json = serde_json::json!({
            "template": {
                "spec": machine_spec
            }
        });

        Ok(CAPIManifest::new(
            OPENSTACK_API_VERSION,
            "OpenStackMachineTemplate",
            format!("{}-cp", name),
            &self.namespace,
        )
        .with_spec(spec_json))
    }

    /// Generate OpenStackMachineTemplate for worker nodes
    fn generate_worker_machine_template(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = cluster
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| crate::Error::validation("cluster name required".to_string()))?;

        let os_config = Self::get_openstack_config(cluster);

        // Flavor (instance type)
        let flavor = os_config
            .and_then(|c| c.worker_flavor.clone())
            .unwrap_or_else(|| "m1.large".to_string());

        // Image name
        let image_name = os_config
            .and_then(|c| c.image_name.clone())
            .unwrap_or_else(|| "Ubuntu 22.04".to_string());

        // SSH key (optional)
        let ssh_key_name = os_config.and_then(|c| c.ssh_key_name.clone());

        // Root volume size
        let root_volume_size = os_config.and_then(|c| c.worker_root_volume_size);

        let mut machine_spec = serde_json::json!({
            "flavor": flavor,
            "image": {
                "filter": {
                    "name": image_name
                }
            }
        });

        // Add SSH key if specified
        if let Some(key_name) = ssh_key_name {
            machine_spec["sshKeyName"] = serde_json::json!(key_name);
        }

        // Add root volume if specified
        if let Some(size) = root_volume_size {
            machine_spec["rootVolume"] = serde_json::json!({
                "sizeGiB": size
            });
        }

        let spec_json = serde_json::json!({
            "template": {
                "spec": machine_spec
            }
        });

        Ok(CAPIManifest::new(
            OPENSTACK_API_VERSION,
            "OpenStackMachineTemplate",
            format!("{}-md-0", name),
            &self.namespace,
        )
        .with_spec(spec_json))
    }
}

#[async_trait]
impl Provider for OpenstackProvider {
    async fn generate_capi_manifests(
        &self,
        cluster: &LatticeCluster,
        bootstrap: &BootstrapInfo,
    ) -> Result<Vec<CAPIManifest>> {
        let name = cluster
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| crate::Error::validation("cluster name required".to_string()))?;

        let spec = &cluster.spec;
        let k8s_version = &spec.provider.kubernetes.version;
        let bootstrap_provider = &spec.provider.kubernetes.bootstrap;

        // Build cluster config
        let mut labels = BTreeMap::new();
        labels.insert("cluster.x-k8s.io/cluster-name".to_string(), name.clone());
        labels.insert("lattice.dev/cluster".to_string(), name.clone());

        let config = ClusterConfig {
            name,
            namespace: &self.namespace,
            k8s_version,
            labels,
            bootstrap: bootstrap_provider.clone(),
        };

        let infra = self.infra_ref();

        // Build control plane config
        let post_commands = build_post_kubeadm_commands(name, bootstrap);
        let cert_sans = spec
            .provider
            .kubernetes
            .cert_sans
            .clone()
            .unwrap_or_default();

        let cp_config = ControlPlaneConfig {
            replicas: spec.nodes.control_plane,
            cert_sans,
            post_kubeadm_commands: post_commands,
        };

        // Generate manifests
        let mut manifests = Vec::new();

        // 1. CAPI Cluster (provider-agnostic)
        manifests.push(generate_cluster(&config, &infra));

        // 2. OpenStackCluster (infrastructure)
        manifests.push(self.generate_openstack_cluster(cluster)?);

        // 3. Control Plane (KubeadmControlPlane or RKE2ControlPlane)
        manifests.push(generate_control_plane(&config, &infra, &cp_config));

        // 4. Control Plane Machine Template
        manifests.push(self.generate_cp_machine_template(cluster)?);

        // 5. MachineDeployment for workers (replicas=0)
        manifests.push(generate_machine_deployment(&config, &infra));

        // 6. Worker Machine Template
        manifests.push(self.generate_worker_machine_template(cluster)?);

        // 7. Bootstrap Config Template for workers
        manifests.push(generate_bootstrap_config_template(&config));

        Ok(manifests)
    }

    async fn validate_spec(&self, spec: &ProviderSpec) -> Result<()> {
        // Validate Kubernetes version format
        let version = &spec.kubernetes.version;
        if !version.starts_with("1.") && !version.starts_with("v1.") {
            return Err(crate::Error::validation(format!(
                "invalid kubernetes version: {version}, expected format: 1.x.x or v1.x.x"
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{BootstrapProvider, KubernetesSpec, NodeSpec, ProviderConfig};
    use kube::api::ObjectMeta;
    use lattice_common::crd::LatticeClusterSpec;

    fn make_test_cluster(name: &str) -> LatticeCluster {
        LatticeCluster {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: LatticeClusterSpec {
                provider: ProviderSpec {
                    kubernetes: KubernetesSpec {
                        version: "1.31.0".to_string(),
                        cert_sans: None,
                        bootstrap: BootstrapProvider::Kubeadm,
                    },
                    config: ProviderConfig::openstack(OpenstackConfig::default()),
                },
                nodes: NodeSpec {
                    control_plane: 3,
                    workers: 5,
                },
                endpoints: None,
                networking: None,
                environment: None,
                region: None,
                workload: None,
            },
            status: None,
        }
    }

    #[tokio::test]
    async fn test_generates_seven_manifests_for_kubeadm() {
        let provider = OpenstackProvider::with_namespace("capi-system");
        let cluster = make_test_cluster("test-cluster");
        let bootstrap = BootstrapInfo::default();

        let manifests = provider
            .generate_capi_manifests(&cluster, &bootstrap)
            .await
            .unwrap();

        assert_eq!(manifests.len(), 7);

        // Verify manifest kinds
        let kinds: Vec<&str> = manifests.iter().map(|m| m.kind.as_str()).collect();
        assert!(kinds.contains(&"Cluster"));
        assert!(kinds.contains(&"OpenStackCluster"));
        assert!(kinds.contains(&"KubeadmControlPlane"));
        assert!(kinds.contains(&"OpenStackMachineTemplate"));
        assert!(kinds.contains(&"MachineDeployment"));
        assert!(kinds.contains(&"KubeadmConfigTemplate"));
    }

    #[tokio::test]
    async fn test_openstack_cluster_has_correct_api_version() {
        let provider = OpenstackProvider::with_namespace("capi-system");
        let cluster = make_test_cluster("test-cluster");
        let bootstrap = BootstrapInfo::default();

        let manifests = provider
            .generate_capi_manifests(&cluster, &bootstrap)
            .await
            .unwrap();

        let os_cluster = manifests
            .iter()
            .find(|m| m.kind == "OpenStackCluster")
            .unwrap();

        assert_eq!(
            os_cluster.api_version,
            "infrastructure.cluster.x-k8s.io/v1beta1"
        );
    }

    #[tokio::test]
    async fn test_openstack_cluster_has_identity_ref() {
        let provider = OpenstackProvider::with_namespace("capi-system");
        let cluster = make_test_cluster("test-cluster");
        let bootstrap = BootstrapInfo::default();

        let manifests = provider
            .generate_capi_manifests(&cluster, &bootstrap)
            .await
            .unwrap();

        let os_cluster = manifests
            .iter()
            .find(|m| m.kind == "OpenStackCluster")
            .unwrap();

        let identity_ref = os_cluster
            .spec
            .as_ref()
            .unwrap()
            .get("identityRef")
            .unwrap();

        assert_eq!(identity_ref["kind"], "Secret");
        assert_eq!(identity_ref["name"], "test-cluster-cloud-config");
    }

    #[tokio::test]
    async fn test_validate_spec_accepts_valid_version() {
        let provider = OpenstackProvider::with_namespace("capi-system");
        let spec = ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "1.31.0".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm,
            },
            config: ProviderConfig::openstack(OpenstackConfig::default()),
        };

        assert!(provider.validate_spec(&spec).await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_spec_rejects_invalid_version() {
        let provider = OpenstackProvider::with_namespace("capi-system");
        let spec = ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "invalid".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm,
            },
            config: ProviderConfig::openstack(OpenstackConfig::default()),
        };

        assert!(provider.validate_spec(&spec).await.is_err());
    }

    #[tokio::test]
    async fn test_machine_deployment_starts_with_zero_replicas() {
        let provider = OpenstackProvider::with_namespace("capi-system");
        let cluster = make_test_cluster("test-cluster");
        let bootstrap = BootstrapInfo::default();

        let manifests = provider
            .generate_capi_manifests(&cluster, &bootstrap)
            .await
            .unwrap();

        let md = manifests
            .iter()
            .find(|m| m.kind == "MachineDeployment")
            .unwrap();

        let replicas = md.spec.as_ref().unwrap()["replicas"].as_i64().unwrap();
        assert_eq!(replicas, 0, "MachineDeployment must start with replicas=0");
    }
}
