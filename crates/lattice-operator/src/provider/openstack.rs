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

        // API server load balancer configuration
        let api_server_lb_enabled = os_config.and_then(|c| c.api_server_lb_enabled).unwrap_or(true);
        let mut lb_config = serde_json::json!({ "enabled": api_server_lb_enabled });
        if let Some(allowed_cidrs) = os_config.and_then(|c| c.api_server_lb_allowed_cidrs.clone()) {
            lb_config["allowedCidrs"] = serde_json::json!(allowed_cidrs);
        }

        let mut spec_json = serde_json::json!({
            "identityRef": {
                "cloudName": cloud_name,
                "name": format!("{}-cloud-config", name),
                "kind": "Secret"
            },
            "externalNetwork": {
                "id": external_network
            },
            "apiServerLoadBalancer": lb_config
        });

        // Add router configuration
        if let Some(router_id) = os_config.and_then(|c| c.router_id.clone()) {
            spec_json["router"] = serde_json::json!({ "id": router_id });
        }

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

        // Floating IP configuration for API server
        if let Some(floating_ip) = os_config.and_then(|c| c.api_server_floating_ip.clone()) {
            spec_json["apiServerFloatingIP"] = serde_json::json!(floating_ip);
        }
        if let Some(disable) = os_config.and_then(|c| c.disable_api_server_floating_ip) {
            spec_json["disableAPIServerFloatingIP"] = serde_json::json!(disable);
        }

        // Managed security groups configuration
        if let Some(managed) = os_config.and_then(|c| c.managed_security_groups) {
            spec_json["managedSecurityGroups"] = serde_json::json!({
                "enabled": managed
            });
            if let Some(allow_all) = os_config.and_then(|c| c.allow_all_in_cluster_traffic) {
                spec_json["managedSecurityGroups"]["allowAllInClusterTraffic"] =
                    serde_json::json!(allow_all);
            }
        }

        // Tags
        if let Some(tags) = os_config.and_then(|c| c.tags.clone()) {
            spec_json["tags"] = serde_json::json!(tags);
        }

        // Bastion host configuration
        if let Some(bastion_enabled) = os_config.and_then(|c| c.bastion_enabled) {
            if bastion_enabled {
                let mut bastion_spec = serde_json::json!({ "enabled": true });
                if let Some(flavor) = os_config.and_then(|c| c.bastion_flavor.clone()) {
                    bastion_spec["flavor"] = serde_json::json!(flavor);
                }
                if let Some(image) = os_config.and_then(|c| c.bastion_image.clone()) {
                    bastion_spec["image"] = serde_json::json!({ "filter": { "name": image } });
                }
                if let Some(ssh_key) = os_config.and_then(|c| c.bastion_ssh_key_name.clone()) {
                    bastion_spec["sshKeyName"] = serde_json::json!(ssh_key);
                }
                if let Some(fip) = os_config.and_then(|c| c.bastion_floating_ip.clone()) {
                    bastion_spec["floatingIP"] = serde_json::json!(fip);
                }
                spec_json["bastion"] = bastion_spec;
            }
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

        let mut machine_spec = serde_json::json!({
            "flavor": flavor
        });

        // Image: prefer ID over name
        if let Some(image_id) = os_config.and_then(|c| c.image_id.clone()) {
            machine_spec["image"] = serde_json::json!({ "id": image_id });
        } else {
            let image_name = os_config
                .and_then(|c| c.image_name.clone())
                .unwrap_or_else(|| "Ubuntu 22.04".to_string());
            machine_spec["image"] = serde_json::json!({ "filter": { "name": image_name } });
        }

        // SSH key
        if let Some(key_name) = os_config.and_then(|c| c.ssh_key_name.clone()) {
            machine_spec["sshKeyName"] = serde_json::json!(key_name);
        }

        // Floating IP for nodes
        if let Some(use_fip) = os_config.and_then(|c| c.use_floating_ip) {
            machine_spec["floatingIPEnabled"] = serde_json::json!(use_fip);
        }

        // Availability zone
        if let Some(az) = os_config.and_then(|c| c.availability_zone.clone()) {
            machine_spec["availabilityZone"] = serde_json::json!(az);
        }

        // Server group for anti-affinity
        if let Some(sg_id) = os_config.and_then(|c| c.server_group_id.clone()) {
            machine_spec["serverGroup"] = serde_json::json!({ "id": sg_id });
        }

        // Custom server metadata
        if let Some(metadata) = os_config.and_then(|c| c.server_metadata.clone()) {
            machine_spec["serverMetadata"] = serde_json::json!(metadata);
        }

        // Security groups
        if let Some(sgs) = os_config.and_then(|c| c.security_groups.clone()) {
            let sg_refs: Vec<_> = sgs.iter().map(|sg| serde_json::json!({ "name": sg })).collect();
            machine_spec["securityGroups"] = serde_json::json!(sg_refs);
        }

        // Tags
        if let Some(tags) = os_config.and_then(|c| c.tags.clone()) {
            machine_spec["tags"] = serde_json::json!(tags);
        }

        // Root volume configuration
        let has_volume_config = os_config.and_then(|c| c.cp_root_volume_size).is_some()
            || os_config.and_then(|c| c.cp_root_volume_type.clone()).is_some()
            || os_config.and_then(|c| c.cp_root_volume_az.clone()).is_some();

        if has_volume_config {
            let mut root_volume = serde_json::json!({});
            if let Some(size) = os_config.and_then(|c| c.cp_root_volume_size) {
                root_volume["sizeGiB"] = serde_json::json!(size);
            }
            if let Some(vol_type) = os_config.and_then(|c| c.cp_root_volume_type.clone()) {
                root_volume["volumeType"] = serde_json::json!(vol_type);
            }
            if let Some(vol_az) = os_config.and_then(|c| c.cp_root_volume_az.clone()) {
                root_volume["availabilityZone"] = serde_json::json!(vol_az);
            }
            machine_spec["rootVolume"] = root_volume;
        }

        let spec_json = serde_json::json!({
            "template": {
                "spec": machine_spec
            }
        });

        Ok(CAPIManifest::new(
            OPENSTACK_API_VERSION,
            "OpenStackMachineTemplate",
            format!("{}-control-plane", name),
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

        let mut machine_spec = serde_json::json!({
            "flavor": flavor
        });

        // Image: prefer ID over name
        if let Some(image_id) = os_config.and_then(|c| c.image_id.clone()) {
            machine_spec["image"] = serde_json::json!({ "id": image_id });
        } else {
            let image_name = os_config
                .and_then(|c| c.image_name.clone())
                .unwrap_or_else(|| "Ubuntu 22.04".to_string());
            machine_spec["image"] = serde_json::json!({ "filter": { "name": image_name } });
        }

        // SSH key
        if let Some(key_name) = os_config.and_then(|c| c.ssh_key_name.clone()) {
            machine_spec["sshKeyName"] = serde_json::json!(key_name);
        }

        // Floating IP for nodes
        if let Some(use_fip) = os_config.and_then(|c| c.use_floating_ip) {
            machine_spec["floatingIPEnabled"] = serde_json::json!(use_fip);
        }

        // Availability zone
        if let Some(az) = os_config.and_then(|c| c.availability_zone.clone()) {
            machine_spec["availabilityZone"] = serde_json::json!(az);
        }

        // Server group for anti-affinity
        if let Some(sg_id) = os_config.and_then(|c| c.server_group_id.clone()) {
            machine_spec["serverGroup"] = serde_json::json!({ "id": sg_id });
        }

        // Custom server metadata
        if let Some(metadata) = os_config.and_then(|c| c.server_metadata.clone()) {
            machine_spec["serverMetadata"] = serde_json::json!(metadata);
        }

        // Security groups
        if let Some(sgs) = os_config.and_then(|c| c.security_groups.clone()) {
            let sg_refs: Vec<_> = sgs.iter().map(|sg| serde_json::json!({ "name": sg })).collect();
            machine_spec["securityGroups"] = serde_json::json!(sg_refs);
        }

        // Tags
        if let Some(tags) = os_config.and_then(|c| c.tags.clone()) {
            machine_spec["tags"] = serde_json::json!(tags);
        }

        // Root volume configuration
        let has_volume_config = os_config.and_then(|c| c.worker_root_volume_size).is_some()
            || os_config.and_then(|c| c.worker_root_volume_type.clone()).is_some()
            || os_config.and_then(|c| c.worker_root_volume_az.clone()).is_some();

        if has_volume_config {
            let mut root_volume = serde_json::json!({});
            if let Some(size) = os_config.and_then(|c| c.worker_root_volume_size) {
                root_volume["sizeGiB"] = serde_json::json!(size);
            }
            if let Some(vol_type) = os_config.and_then(|c| c.worker_root_volume_type.clone()) {
                root_volume["volumeType"] = serde_json::json!(vol_type);
            }
            if let Some(vol_az) = os_config.and_then(|c| c.worker_root_volume_az.clone()) {
                root_volume["availabilityZone"] = serde_json::json!(vol_az);
            }
            machine_spec["rootVolume"] = root_volume;
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

        // Generate manifests - extract fallible operations first
        let openstack_cluster = self.generate_openstack_cluster(cluster)?;
        let cp_machine_template = self.generate_cp_machine_template(cluster)?;
        let worker_machine_template = self.generate_worker_machine_template(cluster)?;

        Ok(vec![
            generate_cluster(&config, &infra),              // 1. CAPI Cluster
            openstack_cluster,                              // 2. OpenStackCluster
            generate_control_plane(&config, &infra, &cp_config), // 3. Control Plane
            cp_machine_template,                            // 4. CP Machine Template
            generate_machine_deployment(&config, &infra),   // 5. MachineDeployment
            worker_machine_template,                        // 6. Worker Machine Template
            generate_bootstrap_config_template(&config),    // 7. Bootstrap Config Template
        ])
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
                        version: "1.32.0".to_string(),
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
                version: "1.32.0".to_string(),
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

    fn make_full_config_cluster(name: &str) -> LatticeCluster {
        let mut server_metadata = std::collections::BTreeMap::new();
        server_metadata.insert("managed-by".to_string(), "lattice".to_string());

        LatticeCluster {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: LatticeClusterSpec {
                provider: ProviderSpec {
                    kubernetes: KubernetesSpec {
                        version: "1.32.0".to_string(),
                        cert_sans: None,
                        bootstrap: BootstrapProvider::Kubeadm,
                    },
                    config: ProviderConfig::openstack(OpenstackConfig {
                        cloud_name: Some("mycloud".to_string()),
                        external_network: Some("public-net".to_string()),
                        router_id: Some("router-123".to_string()),
                        api_server_lb_enabled: Some(true),
                        api_server_lb_allowed_cidrs: Some(vec!["10.0.0.0/8".to_string()]),
                        api_server_floating_ip: Some("203.0.113.10".to_string()),
                        managed_security_groups: Some(true),
                        allow_all_in_cluster_traffic: Some(true),
                        security_groups: Some(vec!["sg-custom".to_string()]),
                        bastion_enabled: Some(true),
                        bastion_flavor: Some("m1.small".to_string()),
                        bastion_image: Some("Ubuntu 22.04".to_string()),
                        ssh_key_name: Some("my-key".to_string()),
                        image_id: Some("image-uuid-123".to_string()),
                        availability_zone: Some("az1".to_string()),
                        server_group_id: Some("sg-anti-affinity".to_string()),
                        server_metadata: Some(server_metadata),
                        tags: Some(vec!["env:test".to_string(), "team:platform".to_string()]),
                        use_floating_ip: Some(true),
                        cp_flavor: Some("m1.xlarge".to_string()),
                        cp_root_volume_size: Some(100),
                        cp_root_volume_type: Some("ssd".to_string()),
                        cp_root_volume_az: Some("az1".to_string()),
                        worker_flavor: Some("m1.2xlarge".to_string()),
                        worker_root_volume_size: Some(200),
                        worker_root_volume_type: Some("ssd".to_string()),
                        worker_root_volume_az: Some("az1".to_string()),
                        ..Default::default()
                    }),
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
    async fn test_openstack_cluster_with_full_config() {
        let provider = OpenstackProvider::with_namespace("capi-system");
        let cluster = make_full_config_cluster("full-config");
        let bootstrap = BootstrapInfo::default();

        let manifests = provider
            .generate_capi_manifests(&cluster, &bootstrap)
            .await
            .unwrap();

        let os_cluster = manifests
            .iter()
            .find(|m| m.kind == "OpenStackCluster")
            .unwrap();
        let spec = os_cluster.spec.as_ref().unwrap();

        assert_eq!(spec["identityRef"]["cloudName"], "mycloud");
        assert_eq!(spec["router"]["id"], "router-123");
        assert_eq!(spec["apiServerLoadBalancer"]["enabled"], true);
        assert_eq!(spec["apiServerLoadBalancer"]["allowedCidrs"][0], "10.0.0.0/8");
        assert_eq!(spec["apiServerFloatingIP"], "203.0.113.10");
        assert_eq!(spec["managedSecurityGroups"]["enabled"], true);
        assert_eq!(spec["managedSecurityGroups"]["allowAllInClusterTraffic"], true);
        assert_eq!(spec["bastion"]["enabled"], true);
        assert_eq!(spec["bastion"]["flavor"], "m1.small");
        assert_eq!(spec["tags"][0], "env:test");
    }

    #[tokio::test]
    async fn test_openstack_cp_machine_template_with_full_config() {
        let provider = OpenstackProvider::with_namespace("capi-system");
        let cluster = make_full_config_cluster("full-config");
        let bootstrap = BootstrapInfo::default();

        let manifests = provider
            .generate_capi_manifests(&cluster, &bootstrap)
            .await
            .unwrap();

        let cp_template = manifests
            .iter()
            .find(|m| m.kind == "OpenStackMachineTemplate" && m.metadata.name.contains("control-plane"))
            .unwrap();
        let spec = &cp_template.spec.as_ref().unwrap()["template"]["spec"];

        assert_eq!(spec["flavor"], "m1.xlarge");
        assert_eq!(spec["image"]["id"], "image-uuid-123");
        assert_eq!(spec["sshKeyName"], "my-key");
        assert_eq!(spec["floatingIPEnabled"], true);
        assert_eq!(spec["availabilityZone"], "az1");
        assert_eq!(spec["serverGroup"]["id"], "sg-anti-affinity");
        assert_eq!(spec["serverMetadata"]["managed-by"], "lattice");
        assert_eq!(spec["securityGroups"][0]["name"], "sg-custom");
        assert_eq!(spec["rootVolume"]["sizeGiB"], 100);
        assert_eq!(spec["rootVolume"]["volumeType"], "ssd");
        assert_eq!(spec["rootVolume"]["availabilityZone"], "az1");
    }

    #[tokio::test]
    async fn test_openstack_worker_machine_template_with_full_config() {
        let provider = OpenstackProvider::with_namespace("capi-system");
        let cluster = make_full_config_cluster("full-config");
        let bootstrap = BootstrapInfo::default();

        let manifests = provider
            .generate_capi_manifests(&cluster, &bootstrap)
            .await
            .unwrap();

        let worker_template = manifests
            .iter()
            .find(|m| m.kind == "OpenStackMachineTemplate" && m.metadata.name.contains("md-0"))
            .unwrap();
        let spec = &worker_template.spec.as_ref().unwrap()["template"]["spec"];

        assert_eq!(spec["flavor"], "m1.2xlarge");
        assert_eq!(spec["rootVolume"]["sizeGiB"], 200);
        assert_eq!(spec["rootVolume"]["volumeType"], "ssd");
        assert_eq!(spec["rootVolume"]["availabilityZone"], "az1");
    }
}
