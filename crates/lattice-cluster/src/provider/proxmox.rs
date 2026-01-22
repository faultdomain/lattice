//! Proxmox VE infrastructure provider (CAPMOX)
//!
//! Generates Cluster API manifests for provisioning Kubernetes clusters on
//! Proxmox Virtual Environment using the CAPMOX provider.
//!
//! Requirements:
//! - VM template must be on Ceph storage for linked clones
//! - Cilium LB-IPAM pool is auto-derived from ipv4_pool gateway as .200/27

use async_trait::async_trait;
use std::collections::BTreeMap;

use super::{
    build_post_kubeadm_commands, generate_bootstrap_config_template, generate_cluster,
    generate_control_plane, generate_machine_deployment, BootstrapInfo, CAPIManifest,
    ClusterConfig, ControlPlaneConfig, InfrastructureRef, Provider, VipConfig,
};
use crate::{Error, Result};
use lattice_common::crd::{LatticeCluster, ProviderSpec, ProviderType, ProxmoxConfig};

const PROXMOX_API_VERSION: &str = "infrastructure.cluster.x-k8s.io/v1alpha1";
const DEFAULT_VIP_INTERFACE: &str = "ens18";

/// VM sizing parameters for ProxmoxMachineTemplate
struct MachineSizing {
    cores: u32,
    memory_mib: u32,
    disk_size_gb: u32,
    sockets: u32,
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
            api_group: "infrastructure.cluster.x-k8s.io",
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
        let name = cluster
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| Error::validation("cluster name required"))?;
        let cfg = Self::get_config(cluster)
            .ok_or_else(|| Error::validation("proxmox config required"))?;

        let dns_servers = cfg
            .dns_servers
            .clone()
            .unwrap_or_else(|| vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()]);
        let allowed_nodes = cfg.allowed_nodes.clone().unwrap_or_default();

        // Parse ipv4_pool range to get start-end and prefix
        let (ip_range, prefix) = cfg
            .ipv4_pool
            .parse_range()
            .map(|(start, end, prefix)| (format!("{}-{}", start, end), prefix))
            .ok_or_else(|| {
                Error::validation(format!(
                    "invalid ipv4Pool range format: '{}', expected format like '10.0.0.101-102/24'",
                    cfg.ipv4_pool.range
                ))
            })?;

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
                "name": cfg.secret_ref.as_ref().map(|s| s.name.clone())
                    .unwrap_or_else(|| "proxmox-credentials".to_string()),
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
            spec["templateID"] = serde_json::json!(cfg.template_id.unwrap_or(9000));
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
            let desc_with_suffix = if suffix == "md-0" {
                format!("{} (worker)", desc)
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

        CAPIManifest::new(
            PROXMOX_API_VERSION,
            "ProxmoxMachineTemplate",
            format!("{}-{}", name, suffix),
            &self.namespace,
        )
        .with_spec(serde_json::json!({ "template": { "spec": spec } }))
    }
}

#[async_trait]
impl Provider for ProxmoxProvider {
    async fn generate_capi_manifests(
        &self,
        cluster: &LatticeCluster,
        bootstrap: &BootstrapInfo,
    ) -> Result<Vec<CAPIManifest>> {
        let name = cluster
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| Error::validation("cluster name required"))?;
        let spec = &cluster.spec;
        let cfg = Self::get_config(cluster)
            .ok_or_else(|| Error::validation("proxmox config required"))?;

        // Build cluster config
        let mut labels = BTreeMap::new();
        labels.insert("cluster.x-k8s.io/cluster-name".to_string(), name.clone());
        labels.insert("lattice.dev/cluster".to_string(), name.clone());

        let config = ClusterConfig {
            name,
            namespace: &self.namespace,
            k8s_version: &spec.provider.kubernetes.version,
            labels,
            bootstrap: spec.provider.kubernetes.bootstrap.clone(),
            provider_type: ProviderType::Proxmox,
        };

        // Build certSANs - auto-add controlPlaneEndpoint and endpoints.host
        let mut cert_sans = spec
            .provider
            .kubernetes
            .cert_sans
            .clone()
            .unwrap_or_default();
        if !cert_sans.contains(&cfg.control_plane_endpoint) {
            cert_sans.push(cfg.control_plane_endpoint.clone());
        }
        if let Some(ref endpoints) = cluster.spec.parent_config {
            if let Some(ref host) = endpoints.host {
                if !cert_sans.contains(host) {
                    cert_sans.push(host.clone());
                }
            }
        }

        // Configure kube-vip for the K8s API server VIP (controlPlaneEndpoint)
        // All Proxmox clusters need kube-vip to manage the API server VIP
        let vip = Some(VipConfig::new(
            cfg.control_plane_endpoint.clone(),
            Some(
                cfg.virtual_ip_network_interface
                    .clone()
                    .unwrap_or_else(|| DEFAULT_VIP_INTERFACE.to_string()),
            ),
            cfg.kube_vip_image.clone(),
        ));

        let cp_config = ControlPlaneConfig {
            replicas: spec.nodes.control_plane,
            cert_sans,
            post_kubeadm_commands: build_post_kubeadm_commands(name, bootstrap),
            vip,
            ssh_authorized_keys: cfg.ssh_authorized_keys.clone().unwrap_or_default(),
        };

        let infra = self.infra_ref();

        Ok(vec![
            generate_cluster(&config, &infra),
            self.generate_proxmox_cluster(cluster)?,
            generate_control_plane(&config, &infra, &cp_config),
            self.generate_machine_template(
                name,
                cfg,
                MachineSizing {
                    cores: cfg.cp_cores,
                    memory_mib: cfg.cp_memory_mib,
                    disk_size_gb: cfg.cp_disk_size_gb,
                    sockets: cfg.cp_sockets.unwrap_or(1),
                },
                "control-plane",
            ),
            generate_machine_deployment(&config, &infra),
            self.generate_machine_template(
                name,
                cfg,
                MachineSizing {
                    cores: cfg.worker_cores,
                    memory_mib: cfg.worker_memory_mib,
                    disk_size_gb: cfg.worker_disk_size_gb,
                    sockets: cfg.worker_sockets.unwrap_or(1),
                },
                "md-0",
            ),
            generate_bootstrap_config_template(&config),
        ])
    }

    async fn validate_spec(&self, spec: &ProviderSpec) -> Result<()> {
        let version = &spec.kubernetes.version;
        if !version.starts_with("1.") && !version.starts_with("v1.") {
            return Err(Error::validation(format!(
                "invalid kubernetes version: {version}, expected format: 1.x.x or v1.x.x"
            )));
        }
        Ok(())
    }

    fn required_secrets(&self, cluster: &LatticeCluster) -> Vec<(String, String)> {
        let secret_ref = Self::get_config(cluster).and_then(|c| c.secret_ref.as_ref());
        vec![(
            secret_ref
                .map(|s| s.name.clone())
                .unwrap_or_else(|| "proxmox-credentials".to_string()),
            secret_ref
                .map(|s| s.namespace.clone())
                .unwrap_or_else(|| "capmox-system".to_string()),
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::api::ObjectMeta;
    use lattice_common::crd::{
        BootstrapProvider, KubernetesSpec, NodeSpec, ProviderConfig, ProviderSpec,
    };
    use lattice_common::crd::{Ipv4PoolConfig, LatticeClusterSpec};

    fn test_proxmox_config() -> ProxmoxConfig {
        ProxmoxConfig {
            control_plane_endpoint: "10.0.0.100".to_string(),
            ipv4_pool: Ipv4PoolConfig {
                range: "10.0.0.101-120/24".to_string(),
                gateway: "10.0.0.1".to_string(),
            },
            cp_cores: 4,
            cp_memory_mib: 8192,
            cp_disk_size_gb: 50,
            worker_cores: 4,
            worker_memory_mib: 8192,
            worker_disk_size_gb: 100,
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
            secret_ref: None,
            ipv6_pool: None,
            bridge: None,
            vlan: None,
            network_model: None,
            memory_adjustment: None,
            vmid_min: None,
            vmid_max: None,
            skip_cloud_init_status: None,
            skip_qemu_guest_agent: None,
            cp_sockets: None,
            worker_sockets: None,
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
                provider: ProviderSpec {
                    kubernetes: KubernetesSpec {
                        version: "1.32.0".to_string(),
                        cert_sans: None,
                        bootstrap: BootstrapProvider::Kubeadm,
                    },
                    config: ProviderConfig::proxmox(test_proxmox_config()),
                },
                nodes: NodeSpec {
                    control_plane: 3,
                    workers: 5,
                },
                parent_config: None,
                networking: None,
                environment: None,
                region: None,
                workload: None,
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
        };
        assert!(provider.validate_spec(&valid).await.is_ok());

        let invalid = ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "invalid".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm,
            },
            config: ProviderConfig::proxmox(test_proxmox_config()),
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
}
