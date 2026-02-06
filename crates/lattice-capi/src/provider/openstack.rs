//! OpenStack infrastructure provider (CAPO)
//!
//! Generates Cluster API manifests for provisioning Kubernetes clusters on
//! OpenStack using the CAPO provider. Requires Octavia for API server load balancing.

use async_trait::async_trait;

use super::{
    build_cert_sans, build_post_kubeadm_commands, create_cluster_labels,
    generate_bootstrap_config_template_for_pool, generate_cluster, generate_control_plane,
    generate_machine_deployment_for_pool, get_cluster_name, pool_resource_suffix,
    validate_k8s_version, BootstrapInfo, CAPIManifest, ClusterConfig, ControlPlaneConfig,
    InfrastructureRef, Provider, WorkerPoolConfig,
};
use crate::constants::{
    DEFAULT_DNS_SERVERS, DEFAULT_NODE_CIDR_OPENSTACK, INFRASTRUCTURE_API_GROUP,
    OPENSTACK_API_VERSION,
};
use lattice_common::crd::{LatticeCluster, OpenStackConfig, ProviderSpec, ProviderType};
use lattice_common::{Error, Result, CAPO_NAMESPACE, OPENSTACK_CREDENTIALS_SECRET};

/// Configuration for generating an OpenStack machine template
struct MachineTemplateConfig<'a> {
    name: &'a str,
    openstack_cfg: &'a OpenStackConfig,
    flavor: &'a str,
    root_volume_size: Option<u32>,
    root_volume_type: Option<&'a str>,
    availability_zone: Option<&'a str>,
    suffix: &'a str,
}

/// OpenStack infrastructure provider
#[derive(Clone, Debug)]
pub struct OpenStackProvider {
    namespace: String,
}

impl OpenStackProvider {
    /// Create a new OpenStack provider with the given CAPI namespace
    pub fn with_namespace(namespace: &str) -> Self {
        Self {
            namespace: namespace.to_string(),
        }
    }

    fn infra_ref(&self) -> InfrastructureRef<'static> {
        InfrastructureRef {
            api_group: INFRASTRUCTURE_API_GROUP,
            api_version: OPENSTACK_API_VERSION,
            cluster_kind: "OpenStackCluster",
            machine_template_kind: "OpenStackMachineTemplate",
        }
    }

    fn get_config(cluster: &LatticeCluster) -> Option<&OpenStackConfig> {
        cluster.spec.provider.config.openstack.as_ref()
    }

    /// Generate OpenStackCluster manifest
    fn generate_openstack_cluster(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = get_cluster_name(cluster)?;
        let cfg = Self::get_config(cluster)
            .ok_or_else(|| Error::validation("openstack config required"))?;

        let cloud_name = cfg
            .cloud_name
            .clone()
            .unwrap_or_else(|| "openstack".to_string());

        let dns_nameservers = cfg
            .dns_nameservers
            .clone()
            .unwrap_or_else(|| DEFAULT_DNS_SERVERS.iter().map(|s| s.to_string()).collect());

        let node_cidr = cfg
            .node_cidr
            .clone()
            .unwrap_or_else(|| DEFAULT_NODE_CIDR_OPENSTACK.to_string());

        // Use filter.name for network lookup (more flexible than requiring UUID)
        let mut spec = serde_json::json!({
            "externalNetwork": {
                "filter": {
                    "name": &cfg.external_network
                }
            },
            "identityRef": {
                "cloudName": cloud_name,
                "name": OPENSTACK_CREDENTIALS_SECRET
            },
            "managedSubnets": [{
                "cidr": node_cidr,
                "dnsNameservers": dns_nameservers
            }]
        });

        // API server load balancer (Octavia) - always enabled
        let mut lb_config = serde_json::json!({ "enabled": true });
        if let Some(ref flavor) = cfg.api_server_load_balancer_flavor {
            lb_config["flavor"] = serde_json::json!(flavor);
        }
        spec["apiServerLoadBalancer"] = lb_config;

        // Managed security groups
        if cfg.managed_security_groups.unwrap_or(true) {
            let mut sg_config = serde_json::json!({});
            if cfg.allow_all_in_cluster_traffic.unwrap_or(false) {
                sg_config["allowAllInClusterTraffic"] = serde_json::json!(true);
            }
            spec["managedSecurityGroups"] = sg_config;
        }

        Ok(CAPIManifest::new(
            OPENSTACK_API_VERSION,
            "OpenStackCluster",
            name,
            &self.namespace,
        )
        .with_spec(spec))
    }

    /// Generate OpenStackMachineTemplate manifest
    fn generate_machine_template(&self, cfg: MachineTemplateConfig<'_>) -> CAPIManifest {
        let mut spec = serde_json::json!({
            "flavor": cfg.flavor,
            "image": {
                "filter": {
                    "name": &cfg.openstack_cfg.image_name
                }
            },
            "sshKeyName": &cfg.openstack_cfg.ssh_key_name
        });

        // Root volume configuration
        if let Some(size) = cfg.root_volume_size {
            let mut volume = serde_json::json!({
                "sizeGiB": size
            });
            if let Some(vol_type) = cfg.root_volume_type {
                volume["type"] = serde_json::json!(vol_type);
            }
            spec["rootVolume"] = volume;
        }

        // Availability zone
        if let Some(az) = cfg.availability_zone {
            spec["availabilityZone"] = serde_json::json!(az);
        }

        CAPIManifest::new(
            OPENSTACK_API_VERSION,
            "OpenStackMachineTemplate",
            format!("{}-{}", cfg.name, cfg.suffix),
            &self.namespace,
        )
        .with_spec(serde_json::json!({ "template": { "spec": spec } }))
    }
}

#[async_trait]
impl Provider for OpenStackProvider {
    async fn generate_capi_manifests(
        &self,
        cluster: &LatticeCluster,
        bootstrap: &BootstrapInfo,
    ) -> Result<Vec<CAPIManifest>> {
        let name = get_cluster_name(cluster)?;
        let spec = &cluster.spec;
        let cfg = Self::get_config(cluster)
            .ok_or_else(|| Error::validation("openstack config required"))?;

        let config = ClusterConfig {
            name,
            namespace: &self.namespace,
            k8s_version: &spec.provider.kubernetes.version,
            labels: create_cluster_labels(name),
            bootstrap: spec.provider.kubernetes.bootstrap.clone(),
            provider_type: ProviderType::OpenStack,
        };

        // No kube-vip for OpenStack - we use Octavia LB
        let cp_config = ControlPlaneConfig {
            replicas: spec.nodes.control_plane,
            cert_sans: build_cert_sans(cluster),
            post_kubeadm_commands: build_post_kubeadm_commands(name, bootstrap)?,
            vip: None,
            ssh_authorized_keys: cfg.ssh_authorized_keys.clone().unwrap_or_default(),
        };

        let infra = self.infra_ref();

        let mut manifests = vec![
            generate_cluster(&config, &infra),
            self.generate_openstack_cluster(cluster)?,
            generate_control_plane(&config, &infra, &cp_config)?,
            self.generate_machine_template(MachineTemplateConfig {
                name,
                openstack_cfg: cfg,
                flavor: &cfg.cp_flavor,
                root_volume_size: cfg.cp_root_volume_size_gb,
                root_volume_type: cfg.cp_root_volume_type.as_deref(),
                availability_zone: cfg.cp_availability_zone.as_deref(),
                suffix: "control-plane",
            }),
        ];

        // Generate worker pool resources
        for (pool_id, pool_spec) in &spec.nodes.worker_pools {
            let pool_config = WorkerPoolConfig {
                pool_id,
                spec: pool_spec,
            };
            let suffix = pool_resource_suffix(pool_id);

            manifests.push(generate_machine_deployment_for_pool(
                &config,
                &infra,
                &pool_config,
            ));
            manifests.push(self.generate_machine_template(MachineTemplateConfig {
                name,
                openstack_cfg: cfg,
                flavor: &cfg.worker_flavor,
                root_volume_size: cfg.worker_root_volume_size_gb,
                root_volume_type: cfg.worker_root_volume_type.as_deref(),
                availability_zone: cfg.worker_availability_zone.as_deref(),
                suffix: &suffix,
            }));
            manifests.push(generate_bootstrap_config_template_for_pool(
                &config,
                &pool_config,
            ));
        }

        Ok(manifests)
    }

    async fn validate_spec(&self, spec: &ProviderSpec) -> Result<()> {
        validate_k8s_version(&spec.kubernetes.version)?;

        // Validate OpenStack-specific config
        if let Some(ref cfg) = spec.config.openstack {
            if cfg.external_network.is_empty() {
                return Err(Error::validation(
                    "openstack config requires externalNetwork",
                ));
            }
            if cfg.cp_flavor.is_empty() {
                return Err(Error::validation("openstack config requires cpFlavor"));
            }
            if cfg.worker_flavor.is_empty() {
                return Err(Error::validation("openstack config requires workerFlavor"));
            }
            if cfg.image_name.is_empty() {
                return Err(Error::validation("openstack config requires imageName"));
            }
            if cfg.ssh_key_name.is_empty() {
                return Err(Error::validation("openstack config requires sshKeyName"));
            }
        }

        Ok(())
    }

    fn required_secrets(&self, cluster: &LatticeCluster) -> Vec<(String, String)> {
        super::get_provider_secrets(cluster, OPENSTACK_CREDENTIALS_SECRET, CAPO_NAMESPACE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::api::ObjectMeta;
    use lattice_common::crd::LatticeClusterSpec;
    use lattice_common::crd::{
        BootstrapProvider, KubernetesSpec, NodeSpec, ProviderConfig, ProviderSpec, WorkerPoolSpec,
    };

    fn test_openstack_config() -> OpenStackConfig {
        OpenStackConfig {
            external_network: "ext-net-123".to_string(),
            cp_flavor: "b2-30".to_string(),
            worker_flavor: "b2-15".to_string(),
            image_name: "Ubuntu 22.04".to_string(),
            ssh_key_name: "lattice-key".to_string(),
            ..Default::default()
        }
    }

    fn test_cluster(name: &str) -> LatticeCluster {
        LatticeCluster {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: LatticeClusterSpec {
                provider_ref: "openstack".to_string(),
                provider: ProviderSpec {
                    kubernetes: KubernetesSpec {
                        version: "1.32.0".to_string(),
                        cert_sans: None,
                        bootstrap: BootstrapProvider::Kubeadm,
                    },
                    config: ProviderConfig::openstack(test_openstack_config()),
                    credentials_secret_ref: None,
                },
                nodes: NodeSpec {
                    control_plane: 3,
                    worker_pools: std::collections::BTreeMap::from([(
                        "default".to_string(),
                        WorkerPoolSpec {
                            replicas: 5,
                            ..Default::default()
                        },
                    )]),
                },
                parent_config: None,
                networking: None,
                services: true,
            },
            status: None,
        }
    }

    #[tokio::test]
    async fn generates_seven_manifests() {
        let provider = OpenStackProvider::with_namespace("capi-system");
        let manifests = provider
            .generate_capi_manifests(&test_cluster("test"), &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");

        // 7 manifests: Cluster, OpenStackCluster, ControlPlane, 2x MachineTemplate, MachineDeployment, ConfigTemplate
        assert_eq!(manifests.len(), 7);
        let kinds: Vec<_> = manifests.iter().map(|m| m.kind.as_str()).collect();
        assert!(kinds.contains(&"Cluster"));
        assert!(kinds.contains(&"OpenStackCluster"));
        assert!(kinds.contains(&"KubeadmControlPlane"));
        assert!(kinds.contains(&"OpenStackMachineTemplate"));
        assert!(kinds.contains(&"MachineDeployment"));
        assert!(kinds.contains(&"KubeadmConfigTemplate"));
    }

    #[tokio::test]
    async fn uses_octavia_lb() {
        let provider = OpenStackProvider::with_namespace("capi-system");
        let manifests = provider
            .generate_capi_manifests(&test_cluster("test"), &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");

        let os_cluster = manifests
            .iter()
            .find(|m| m.kind == "OpenStackCluster")
            .expect("OpenStackCluster manifest should exist");
        let lb_enabled = &os_cluster.spec.as_ref().expect("spec should exist")
            ["apiServerLoadBalancer"]["enabled"];
        assert_eq!(lb_enabled, true);
    }

    #[tokio::test]
    async fn validates_kubernetes_version() {
        let provider = OpenStackProvider::with_namespace("capi-system");

        let valid = ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "1.32.0".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm,
            },
            config: ProviderConfig::openstack(test_openstack_config()),
            credentials_secret_ref: None,
        };
        assert!(provider.validate_spec(&valid).await.is_ok());

        let invalid = ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "invalid".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm,
            },
            config: ProviderConfig::openstack(test_openstack_config()),
            credentials_secret_ref: None,
        };
        assert!(provider.validate_spec(&invalid).await.is_err());
    }

    #[tokio::test]
    async fn validates_required_openstack_fields() {
        let provider = OpenStackProvider::with_namespace("capi-system");

        let mut cfg = test_openstack_config();
        cfg.external_network = String::new();

        let spec = ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "1.32.0".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm,
            },
            config: ProviderConfig::openstack(cfg),
            credentials_secret_ref: None,
        };

        let result = provider.validate_spec(&spec).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("externalNetwork"));
    }

    #[tokio::test]
    async fn supports_rke2_bootstrap() {
        let provider = OpenStackProvider::with_namespace("capi-system");
        let mut cluster = test_cluster("rke2-test");
        cluster.spec.provider.kubernetes.bootstrap = BootstrapProvider::Rke2;

        let manifests = provider
            .generate_capi_manifests(&cluster, &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");

        let cp = manifests
            .iter()
            .find(|m| m.kind.contains("ControlPlane"))
            .expect("ControlPlane manifest should exist");
        assert!(cp.kind.contains("RKE2"));
    }

    #[tokio::test]
    async fn configures_root_volumes() {
        let provider = OpenStackProvider::with_namespace("capi-system");
        let mut cluster = test_cluster("test");

        if let Some(ref mut cfg) = cluster.spec.provider.config.openstack {
            cfg.cp_root_volume_size_gb = Some(50);
            cfg.cp_root_volume_type = Some("high-speed".to_string());
            cfg.worker_root_volume_size_gb = Some(100);
        }

        let manifests = provider
            .generate_capi_manifests(&cluster, &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");

        let cp_template = manifests
            .iter()
            .find(|m| {
                m.kind == "OpenStackMachineTemplate" && m.metadata.name.contains("control-plane")
            })
            .expect("control plane template should exist");

        let root_volume = &cp_template.spec.as_ref().expect("spec should exist")["template"]
            ["spec"]["rootVolume"];
        assert_eq!(root_volume["sizeGiB"], 50);
        assert_eq!(root_volume["type"], "high-speed");
    }
}
