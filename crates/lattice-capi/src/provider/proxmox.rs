//! Proxmox VE infrastructure provider (CAPMOX)
//!
//! Generates Cluster API manifests for provisioning Kubernetes clusters on
//! Proxmox Virtual Environment using the CAPMOX provider.
//!
//! Requirements:
//! - VM template must be on Ceph storage for linked clones
//! - `lb_cidr` in ProxmoxConfig required for Cilium LB-IPAM

use async_trait::async_trait;

use super::{
    build_cert_sans, build_post_kubeadm_commands, create_cluster_labels,
    generate_bootstrap_config_template_for_pool, generate_cluster, generate_control_plane,
    generate_machine_deployment_for_pool, get_cluster_name, pool_resource_suffix,
    validate_k8s_version, BootstrapInfo, CAPIManifest, ClusterConfig, ControlPlaneConfig,
    InfrastructureRef, Provider, VipConfig, WorkerPoolConfig,
};
use crate::constants::{
    DEFAULT_DNS_SERVERS, DEFAULT_VIP_INTERFACE_PROXMOX, INFRASTRUCTURE_API_GROUP,
    PROXMOX_API_VERSION,
};
use lattice_common::crd::{
    InstanceType, Ipv4PoolConfig, LatticeCluster, ProviderSpec, ProviderType, ProxmoxConfig,
};
use lattice_common::{Error, Result, CAPMOX_NAMESPACE, PROXMOX_CREDENTIALS_SECRET};

/// VM sizing parameters for ProxmoxMachineTemplate
struct MachineSizing {
    cores: u32,
    memory_mib: u32,
    disk_size_gb: u32,
    sockets: u32,
}

impl MachineSizing {
    fn from_instance_type(instance_type: &Option<InstanceType>, default_disk_gb: u32) -> Self {
        instance_type
            .as_ref()
            .and_then(|it| it.as_resources())
            .map(|r| Self {
                cores: r.cores,
                memory_mib: r.memory_gib * 1024,
                disk_size_gb: r.disk_gib,
                sockets: r.sockets,
            })
            .unwrap_or(Self {
                cores: 4,
                memory_mib: 8192,
                disk_size_gb: default_disk_gb,
                sockets: 1,
            })
    }
}

/// Canonical name for a cluster's shared additional-network IP pool.
/// Used by both the InClusterIPPool resource and the machine template ipv4PoolRef.
fn additional_network_pool_name(cluster_name: &str, network_index: usize) -> String {
    format!("{}-net{}", cluster_name, network_index + 1)
}

/// Parse an Ipv4PoolConfig into the (address_range, prefix) tuple needed by CAPI manifests.
fn parse_ipv4_pool(pool: &Ipv4PoolConfig, context: &str) -> Result<(String, u8)> {
    pool.parse_range()
        .map(|(start, end, prefix)| (format!("{}-{}", start, end), prefix))
        .ok_or_else(|| {
            Error::validation(format!(
                "invalid {} ipv4Pool range: '{}'",
                context, pool.range
            ))
        })
}

/// Proxmox VE infrastructure provider
#[derive(Clone, Debug)]
pub struct ProxmoxProvider {
    namespace: String,
}

impl ProxmoxProvider {
    /// Create a new Proxmox provider with the given CAPI namespace
    pub fn with_namespace(namespace: &str) -> Self {
        Self {
            namespace: namespace.to_string(),
        }
    }

    fn infra_ref(&self) -> InfrastructureRef<'static> {
        InfrastructureRef {
            api_group: INFRASTRUCTURE_API_GROUP,
            api_version: PROXMOX_API_VERSION,
            cluster_kind: "ProxmoxCluster",
            machine_template_kind: "ProxmoxMachineTemplate",
        }
    }

    fn get_config(cluster: &LatticeCluster) -> Option<&ProxmoxConfig> {
        cluster.spec.provider.config.proxmox.as_ref()
    }

    /// Generate ProxmoxCluster manifest
    fn generate_proxmox_cluster(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = get_cluster_name(cluster)?;
        let cfg = Self::get_config(cluster)
            .ok_or_else(|| Error::validation("proxmox config required"))?;

        let dns_servers = cfg
            .dns_servers
            .clone()
            .unwrap_or_else(|| DEFAULT_DNS_SERVERS.iter().map(|s| s.to_string()).collect());
        let allowed_nodes = cfg.allowed_nodes.clone().unwrap_or_default();

        let (ip_range, prefix) = parse_ipv4_pool(&cfg.ipv4_pool, "cluster")?;

        // Use credentials_secret_ref from ProviderSpec if set, otherwise default
        let secret_ref = cluster.spec.provider.credentials_secret_ref.as_ref();
        let credentials_name = secret_ref
            .map(|s| s.name.clone())
            .unwrap_or_else(|| PROXMOX_CREDENTIALS_SECRET.to_string());

        let mut spec = serde_json::json!({
            "controlPlaneEndpoint": {
                "host": &cfg.control_plane_endpoint,
                "port": 6443
            },
            "dnsServers": dns_servers,
            "allowedNodes": allowed_nodes,
            "ipv4Config": {
                "addresses": [ip_range],
                "prefix": prefix,
                "gateway": &cfg.ipv4_pool.gateway
            },
            "credentialsRef": {
                "name": credentials_name,
                "namespace": &self.namespace
            }
        });

        if let Some(memory_adj) = cfg.memory_adjustment {
            spec["schedulerHints"] = serde_json::json!({ "memoryAdjustment": memory_adj });
        }

        Ok(
            CAPIManifest::new(PROXMOX_API_VERSION, "ProxmoxCluster", name, &self.namespace)
                .with_spec(spec),
        )
    }

    /// Generate ProxmoxMachineTemplate (shared logic for CP and workers)
    fn generate_machine_template(
        &self,
        name: &str,
        cfg: &ProxmoxConfig,
        sizing: MachineSizing,
        suffix: &str,
    ) -> CAPIManifest {
        let bridge = cfg.bridge.clone().unwrap_or_else(|| "vmbr0".to_string());
        let network_model = cfg
            .network_model
            .clone()
            .unwrap_or_else(|| "virtio".to_string());

        let mut network = serde_json::json!({
            "bridge": bridge,
            "model": network_model
        });
        if let Some(vlan) = cfg.vlan {
            network["vlan"] = serde_json::json!(vlan);
        }

        // Always use linked clones (template must be on Ceph)
        let mut spec = serde_json::json!({
            "full": false,
            "numSockets": sizing.sockets,
            "numCores": sizing.cores,
            "memoryMiB": sizing.memory_mib,
            "disks": {
                "bootVolume": {
                    "disk": "scsi0",
                    "sizeGb": sizing.disk_size_gb
                }
            },
            "network": { "default": network }
        });

        // Template source
        if let Some(ref node) = cfg.source_node {
            spec["sourceNode"] = serde_json::json!(node);
        }
        if let Some(ref tags) = cfg.template_tags {
            spec["templateSelector"] = serde_json::json!({ "matchTags": tags });
        } else {
            spec["templateID"] = serde_json::json!(cfg.template_id.unwrap_or(9001));
        }
        if let Some(ref snap) = cfg.snap_name {
            spec["snapName"] = serde_json::json!(snap);
        }

        // Placement
        if let Some(ref target) = cfg.target_node {
            spec["target"] = serde_json::json!(target);
        }
        if let Some(ref pool) = cfg.pool {
            spec["pool"] = serde_json::json!(pool);
        }
        if let Some(ref desc) = cfg.description {
            let desc_with_suffix = if suffix.starts_with("pool-") {
                format!(
                    "{} (worker: {})",
                    desc,
                    suffix.strip_prefix("pool-").unwrap_or(suffix)
                )
            } else {
                desc.clone()
            };
            spec["description"] = serde_json::json!(desc_with_suffix);
        }
        if let Some(ref tags) = cfg.tags {
            spec["tags"] = serde_json::json!(tags);
        }

        // VMID range
        if cfg.vmid_min.is_some() || cfg.vmid_max.is_some() {
            let mut range = serde_json::Map::new();
            if let Some(min) = cfg.vmid_min {
                range.insert("start".to_string(), serde_json::json!(min));
            }
            if let Some(max) = cfg.vmid_max {
                range.insert("end".to_string(), serde_json::json!(max));
            }
            spec["vmIDRange"] = serde_json::Value::Object(range);
        }

        // Health checks
        if cfg.skip_cloud_init_status.is_some() || cfg.skip_qemu_guest_agent.is_some() {
            let mut checks = serde_json::Map::new();
            if let Some(skip) = cfg.skip_cloud_init_status {
                checks.insert("skipCloudInitStatus".to_string(), serde_json::json!(skip));
            }
            if let Some(skip) = cfg.skip_qemu_guest_agent {
                checks.insert("skipQemuGuestAgent".to_string(), serde_json::json!(skip));
            }
            spec["checks"] = serde_json::Value::Object(checks);
        }

        // Attach additional network bridges for direct L2 reachability.
        // Each entry becomes a CAPMOX additionalDevice referencing a cluster-wide
        // shared IP pool (not per-template) so that CP and workers get unique IPs.
        if let Some(networks) = &cfg.additional_networks {
            if !networks.is_empty() {
                let devices: Vec<serde_json::Value> = networks
                    .iter()
                    .enumerate()
                    .map(|(i, net)| {
                        serde_json::json!({
                            "name": format!("net{}", i + 1),
                            "bridge": &net.bridge,
                            "model": "virtio",
                            "ipv4PoolRef": {
                                "apiGroup": "ipam.cluster.x-k8s.io",
                                "kind": "InClusterIPPool",
                                "name": additional_network_pool_name(name, i)
                            }
                        })
                    })
                    .collect();
                spec["network"]["additionalDevices"] = serde_json::Value::Array(devices);
            }
        }

        CAPIManifest::new(
            PROXMOX_API_VERSION,
            "ProxmoxMachineTemplate",
            format!("{}-{}", name, suffix),
            &self.namespace,
        )
        .with_spec(serde_json::json!({ "template": { "spec": spec } }))
    }

    /// Generate shared InClusterIPPool resources for additional networks.
    ///
    /// One pool per additional network, shared across all machine templates (CP
    /// and workers). This ensures IP addresses are unique across all nodes in the
    /// cluster instead of each template independently allocating from the same range.
    fn generate_additional_network_pools(
        &self,
        name: &str,
        cfg: &ProxmoxConfig,
        manifests: &mut Vec<CAPIManifest>,
    ) -> Result<()> {
        let networks = match &cfg.additional_networks {
            Some(nets) if !nets.is_empty() => nets,
            _ => return Ok(()),
        };

        for (i, net) in networks.iter().enumerate() {
            let pool_name = additional_network_pool_name(name, i);
            let (ip_range, prefix) = parse_ipv4_pool(&net.ipv4_pool, "additionalNetwork")?;

            manifests.push(
                CAPIManifest::new(
                    "ipam.cluster.x-k8s.io/v1alpha2",
                    "InClusterIPPool",
                    &pool_name,
                    &self.namespace,
                )
                .with_labels(std::collections::BTreeMap::from([(
                    "cluster.x-k8s.io/cluster-name".to_string(),
                    name.to_string(),
                )]))
                .with_spec(serde_json::json!({
                    "addresses": [ip_range],
                    "prefix": prefix,
                    "gateway": &net.ipv4_pool.gateway
                })),
            );
        }

        Ok(())
    }
}

#[async_trait]
impl Provider for ProxmoxProvider {
    async fn generate_capi_manifests(
        &self,
        cluster: &LatticeCluster,
        bootstrap: &BootstrapInfo,
    ) -> Result<Vec<CAPIManifest>> {
        let name = get_cluster_name(cluster)?;
        let spec = &cluster.spec;
        let cfg = Self::get_config(cluster)
            .ok_or_else(|| Error::validation("proxmox config required"))?;

        let config = ClusterConfig {
            name,
            namespace: &self.namespace,
            k8s_version: &spec.provider.kubernetes.version,
            labels: create_cluster_labels(name),
            bootstrap: spec.provider.kubernetes.bootstrap.clone(),
            provider_type: ProviderType::Proxmox,
            registry_mirrors: bootstrap.registry_mirrors.clone(),
        };

        // Build certSANs - also auto-add controlPlaneEndpoint for Proxmox
        let mut cert_sans = build_cert_sans(cluster);
        if !cert_sans.contains(&cfg.control_plane_endpoint) {
            cert_sans.push(cfg.control_plane_endpoint.clone());
        }

        // Configure kube-vip for the K8s API server VIP (controlPlaneEndpoint)
        // All Proxmox clusters need kube-vip to manage the API server VIP
        let vip = Some(VipConfig::new(
            cfg.control_plane_endpoint.clone(),
            Some(
                cfg.virtual_ip_network_interface
                    .clone()
                    .unwrap_or_else(|| DEFAULT_VIP_INTERFACE_PROXMOX.to_string()),
            ),
            cfg.kube_vip_image.clone(),
        ));

        let cp_config = ControlPlaneConfig {
            replicas: spec.nodes.control_plane.replicas,
            cert_sans,
            post_kubeadm_commands: build_post_kubeadm_commands(name, bootstrap)?,
            vip,
            ssh_authorized_keys: cfg.ssh_authorized_keys.clone().unwrap_or_default(),
            registry_mirrors: bootstrap.registry_mirrors.clone(),
        };

        let infra = self.infra_ref();

        let cp_sizing =
            MachineSizing::from_instance_type(&spec.nodes.control_plane.instance_type, 50);

        let mut manifests = vec![
            generate_cluster(&config, &infra),
            self.generate_proxmox_cluster(cluster)?,
            generate_control_plane(&config, &infra, &cp_config)?,
            self.generate_machine_template(name, cfg, cp_sizing, "control-plane"),
        ];

        // Generate shared InClusterIPPool resources for additional networks (one
        // pool per network, shared by CP and all worker templates so IPs are unique).
        self.generate_additional_network_pools(name, cfg, &mut manifests)?;

        // Generate worker pool resources
        for (pool_id, pool_spec) in &spec.nodes.worker_pools {
            let pool_config = WorkerPoolConfig {
                pool_id,
                spec: pool_spec,
            };
            let suffix = pool_resource_suffix(pool_id);

            let worker_sizing = MachineSizing::from_instance_type(&pool_spec.instance_type, 100);

            manifests.push(generate_machine_deployment_for_pool(
                &config,
                &infra,
                &pool_config,
            ));
            manifests.push(self.generate_machine_template(name, cfg, worker_sizing, &suffix));
            manifests.push(generate_bootstrap_config_template_for_pool(
                &config,
                &pool_config,
            ));
        }

        Ok(manifests)
    }

    async fn validate_spec(&self, spec: &ProviderSpec) -> Result<()> {
        validate_k8s_version(&spec.kubernetes.version)
    }

    fn required_secrets(&self, cluster: &LatticeCluster) -> Vec<(String, String)> {
        super::get_provider_secrets(cluster, PROXMOX_CREDENTIALS_SECRET, CAPMOX_NAMESPACE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::api::ObjectMeta;
    use lattice_common::crd::{
        AdditionalNetwork, BackupsConfig, BootstrapProvider, ControlPlaneSpec, KubernetesSpec,
        LatticeClusterSpec, MonitoringConfig, NodeResourceSpec, NodeSpec, ProviderConfig,
        WorkerPoolSpec,
    };

    fn test_proxmox_config() -> ProxmoxConfig {
        ProxmoxConfig {
            control_plane_endpoint: "10.0.0.100".to_string(),
            ipv4_pool: Ipv4PoolConfig {
                range: "10.0.0.101-120/24".to_string(),
                gateway: "10.0.0.1".to_string(),
            },
            source_node: None,
            template_id: None,
            template_tags: None,
            snap_name: None,
            target_node: None,
            pool: None,
            description: None,
            tags: None,
            allowed_nodes: None,
            dns_servers: None,
            ssh_authorized_keys: None,
            virtual_ip_network_interface: None,
            kube_vip_image: None,
            ipv6_pool: None,
            bridge: None,
            vlan: None,
            network_model: None,
            memory_adjustment: None,
            vmid_min: None,
            vmid_max: None,
            skip_cloud_init_status: None,
            skip_qemu_guest_agent: None,
            lb_cidr: None,
            additional_networks: None,
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
                provider_ref: "proxmox".to_string(),
                provider: ProviderSpec {
                    kubernetes: KubernetesSpec {
                        version: "1.32.0".to_string(),
                        cert_sans: None,
                        bootstrap: BootstrapProvider::Kubeadm,
                    },
                    config: ProviderConfig::proxmox(test_proxmox_config()),
                    credentials_secret_ref: None,
                },
                nodes: NodeSpec {
                    control_plane: ControlPlaneSpec {
                        replicas: 3,
                        instance_type: Some(InstanceType::resources(NodeResourceSpec {
                            cores: 4,
                            memory_gib: 8,
                            disk_gib: 50,
                            sockets: 1,
                        })),
                        root_volume: None,
                    },
                    worker_pools: std::collections::BTreeMap::from([(
                        "default".to_string(),
                        WorkerPoolSpec {
                            replicas: 5,
                            instance_type: Some(InstanceType::resources(NodeResourceSpec {
                                cores: 4,
                                memory_gib: 8,
                                disk_gib: 100,
                                sockets: 1,
                            })),
                            ..Default::default()
                        },
                    )]),
                },
                parent_config: None,

                services: true,
                gpu: false,
                monitoring: MonitoringConfig::default(),
                backups: BackupsConfig::default(),
                network_topology: None,
                registry_mirrors: None,
                dns: None,
                issuers: std::collections::BTreeMap::new(),
                lattice_image: "ghcr.io/evan-hines-js/lattice:latest".to_string(),
                cascade_upgrade: false,
            },
            status: None,
        }
    }

    #[tokio::test]
    async fn generates_seven_manifests() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let manifests = provider
            .generate_capi_manifests(&test_cluster("test"), &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");

        assert_eq!(manifests.len(), 7);
        let kinds: Vec<_> = manifests.iter().map(|m| m.kind.as_str()).collect();
        assert!(kinds.contains(&"Cluster"));
        assert!(kinds.contains(&"ProxmoxCluster"));
        assert!(kinds.contains(&"KubeadmControlPlane"));
        assert!(kinds.contains(&"ProxmoxMachineTemplate"));
        assert!(kinds.contains(&"MachineDeployment"));
        assert!(kinds.contains(&"KubeadmConfigTemplate"));
    }

    #[tokio::test]
    async fn uses_linked_clones() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let manifests = provider
            .generate_capi_manifests(&test_cluster("test"), &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");

        let template = manifests
            .iter()
            .find(|m| m.kind == "ProxmoxMachineTemplate")
            .expect("ProxmoxMachineTemplate should exist");
        let full = &template.spec.as_ref().expect("spec should exist")["template"]["spec"]["full"];
        assert_eq!(full, false);
    }

    #[tokio::test]
    async fn auto_adds_control_plane_endpoint_to_sans() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let manifests = provider
            .generate_capi_manifests(&test_cluster("test"), &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");

        let cp = manifests
            .iter()
            .find(|m| m.kind == "KubeadmControlPlane")
            .expect("KubeadmControlPlane should exist");
        let spec = cp.spec.as_ref().expect("spec should exist");
        let sans = spec["kubeadmConfigSpec"]["clusterConfiguration"]["apiServer"]["certSANs"]
            .as_array()
            .expect("certSANs should be an array");
        assert!(sans.contains(&serde_json::json!("10.0.0.100")));
    }

    #[tokio::test]
    async fn validates_kubernetes_version() {
        let provider = ProxmoxProvider::with_namespace("capi-system");

        let valid = ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "1.32.0".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm,
            },
            config: ProviderConfig::proxmox(test_proxmox_config()),
            credentials_secret_ref: None,
        };
        assert!(provider.validate_spec(&valid).await.is_ok());

        let invalid = ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "invalid".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm,
            },
            config: ProviderConfig::proxmox(test_proxmox_config()),
            credentials_secret_ref: None,
        };
        assert!(provider.validate_spec(&invalid).await.is_err());
    }

    #[tokio::test]
    async fn supports_rke2_bootstrap() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let mut cluster = test_cluster("rke2-test");
        cluster.spec.provider.kubernetes.bootstrap = BootstrapProvider::Rke2;

        let manifests = provider
            .generate_capi_manifests(&cluster, &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");

        let cp = manifests
            .iter()
            .find(|m| m.kind.contains("ControlPlane"))
            .expect("ControlPlane should exist");
        assert!(cp.kind.contains("RKE2"));
    }

    #[tokio::test]
    async fn additional_networks_generate_shared_pool() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let mut cluster = test_cluster("e2e-mgmt");
        // Add additional networks
        cluster
            .spec
            .provider
            .config
            .proxmox
            .as_mut()
            .unwrap()
            .additional_networks = Some(vec![AdditionalNetwork {
            bridge: "vmbr1".to_string(),
            ipv4_pool: Ipv4PoolConfig {
                range: "10.0.1.201-210/24".to_string(),
                gateway: "10.0.1.1".to_string(),
            },
        }]);

        let manifests = provider
            .generate_capi_manifests(&cluster, &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");

        let pool_names: Vec<_> = manifests
            .iter()
            .filter(|m| m.kind == "InClusterIPPool")
            .map(|m| m.metadata.name.as_str())
            .collect();

        // One shared pool per additional network, NOT per machine template
        assert!(
            pool_names.contains(&"e2e-mgmt-net1"),
            "should have shared pool, got: {:?}",
            pool_names
        );
        assert_eq!(
            pool_names.iter().filter(|n| **n == "e2e-mgmt-net1").count(),
            1,
            "shared pool should appear exactly once, got: {:?}",
            pool_names
        );
        // Per-template pools should NOT exist
        assert!(
            !pool_names.contains(&"e2e-mgmt-control-plane-net1"),
            "should not have per-template CP pool, got: {:?}",
            pool_names
        );
        assert!(
            !pool_names.contains(&"e2e-mgmt-pool-default-net1"),
            "should not have per-template worker pool, got: {:?}",
            pool_names
        );

        // Both CP and worker machine templates should reference the shared pool
        let machine_templates: Vec<_> = manifests
            .iter()
            .filter(|m| m.kind == "ProxmoxMachineTemplate")
            .collect();
        for mt in &machine_templates {
            let devices = mt.spec.as_ref().unwrap()["template"]["spec"]["network"]
                ["additionalDevices"]
                .as_array()
                .expect("should have additionalDevices");
            for dev in devices {
                let pool_ref = &dev["ipv4PoolRef"]["name"];
                assert_eq!(
                    pool_ref.as_str().unwrap(),
                    "e2e-mgmt-net1",
                    "machine template should reference shared pool"
                );
            }
        }
    }
}
