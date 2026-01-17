//! Proxmox VE infrastructure provider (CAPMOX)
//!
//! This provider generates Cluster API manifests for provisioning Kubernetes
//! clusters on Proxmox Virtual Environment using the CAPMOX provider.
//!
//! CAPMOX API: infrastructure.cluster.x-k8s.io/v1alpha1

use async_trait::async_trait;
use std::collections::BTreeMap;

use super::{
    build_post_kubeadm_commands, generate_bootstrap_config_template, generate_cluster,
    generate_control_plane, generate_machine_deployment, BootstrapInfo, CAPIManifest,
    ClusterConfig, ControlPlaneConfig, InfrastructureRef, Provider, VipConfig,
};
use crate::crd::{LatticeCluster, ProviderSpec, ProviderType, ProxmoxConfig};
use crate::{Error, Result};

/// CAPMOX API version
const PROXMOX_API_VERSION: &str = "infrastructure.cluster.x-k8s.io/v1alpha1";

/// Default network interface for Proxmox VMs with virtio
const DEFAULT_VIP_INTERFACE: &str = "ens18";

/// Proxmox VE infrastructure provider
///
/// Generates CAPI manifests for Proxmox using the CAPMOX provider.
/// Supports both kubeadm and RKE2 bootstrap providers.
#[derive(Clone, Debug)]
pub struct ProxmoxProvider {
    /// Namespace for CAPI resources
    namespace: String,
}

impl ProxmoxProvider {
    /// Create a new Proxmox provider with the given namespace
    pub fn with_namespace(namespace: &str) -> Self {
        Self {
            namespace: namespace.to_string(),
        }
    }

    /// Get infrastructure reference for Proxmox
    fn infra_ref(&self) -> InfrastructureRef<'static> {
        InfrastructureRef {
            api_group: "infrastructure.cluster.x-k8s.io",
            api_version: PROXMOX_API_VERSION,
            cluster_kind: "ProxmoxCluster",
            machine_template_kind: "ProxmoxMachineTemplate",
        }
    }

    /// Extract ProxmoxConfig from the cluster's provider config
    fn get_proxmox_config(cluster: &LatticeCluster) -> Option<&ProxmoxConfig> {
        cluster.spec.provider.config.proxmox.as_ref()
    }

    /// Generate ProxmoxCluster manifest
    fn generate_proxmox_cluster(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = cluster
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| crate::Error::validation("cluster name required".to_string()))?;

        let proxmox_config = Self::get_proxmox_config(cluster);

        // Get endpoint IP (VIP) - must be excluded from addresses pool
        // kube-vip will manage the VIP on CP nodes
        let endpoint_ip = cluster
            .spec
            .endpoints
            .as_ref()
            .map(|e| e.host.as_str());

        // Build IPv4 config - addresses come from pool, excluding VIP
        let ipv4_config = if let Some(cfg) = proxmox_config {
            let addresses: Vec<String> = cfg
                .ipv4_addresses
                .clone()
                .unwrap_or_default()
                .into_iter()
                .filter(|addr| endpoint_ip != Some(addr.as_str()))
                .collect();

            let mut config = serde_json::json!({
                "addresses": addresses,
                "prefix": cfg.ipv4_prefix.unwrap_or(24),
                "gateway": cfg.ipv4_gateway.clone().unwrap_or_default()
            });

            // Add metric if specified
            if let Some(metric) = cfg.ipv4_metric {
                config["metric"] = serde_json::json!(metric);
            }

            config
        } else {
            serde_json::json!({
                "addresses": [],
                "prefix": 24,
                "gateway": ""
            })
        };

        // Build IPv6 config if addresses are specified
        let ipv6_config = proxmox_config.and_then(|cfg| {
            cfg.ipv6_addresses.as_ref().map(|addrs| {
                let mut config = serde_json::json!({
                    "addresses": addrs,
                    "prefix": cfg.ipv6_prefix.unwrap_or(64),
                    "gateway": cfg.ipv6_gateway.clone().unwrap_or_default()
                });
                if let Some(metric) = cfg.ipv6_metric {
                    config["metric"] = serde_json::json!(metric);
                }
                config
            })
        });

        // DNS servers
        let dns_servers = proxmox_config
            .and_then(|c| c.dns_servers.clone())
            .unwrap_or_else(|| vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()]);

        // Allowed nodes (Proxmox cluster nodes that can host VMs)
        let allowed_nodes = proxmox_config
            .and_then(|c| c.allowed_nodes.clone())
            .unwrap_or_default();

        // Control plane endpoint is required in the CRD
        let control_plane_host = proxmox_config
            .and_then(|c| c.control_plane_endpoint.clone())
            .ok_or_else(|| {
                Error::validation(
                    "Proxmox clusters require spec.provider.config.proxmox.controlPlaneEndpoint"
                )
            })?;

        let control_plane_endpoint = serde_json::json!({
            "host": control_plane_host,
            "port": 6443
        });

        // Build spec
        let mut spec_json = serde_json::json!({
            "controlPlaneEndpoint": control_plane_endpoint,
            "ipv4Config": ipv4_config,
            "dnsServers": dns_servers,
            "allowedNodes": allowed_nodes,
            // Use local namespace for credentials - controller copies secret here
            // This avoids race conditions when multiple clusters share credentials
            "credentialsRef": {
                "name": proxmox_config
                    .and_then(|c| c.secret_ref.as_ref().map(|s| s.name.clone()))
                    .unwrap_or_else(|| "proxmox-credentials".to_string()),
                "namespace": &self.namespace
            }
        });

        // Add IPv6 config if present
        if let Some(ipv6) = ipv6_config {
            spec_json["ipv6Config"] = ipv6;
        }

        // Add scheduler hints if memory adjustment is specified
        if let Some(cfg) = proxmox_config {
            if let Some(memory_adj) = cfg.memory_adjustment {
                spec_json["schedulerHints"] = serde_json::json!({
                    "memoryAdjustment": memory_adj
                });
            }

        }

        Ok(
            CAPIManifest::new(PROXMOX_API_VERSION, "ProxmoxCluster", name, &self.namespace)
                .with_spec(spec_json),
        )
    }

    /// Generate ProxmoxMachineTemplate for control plane nodes
    fn generate_cp_machine_template(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = cluster
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| crate::Error::validation("cluster name required".to_string()))?;

        let proxmox_config = Self::get_proxmox_config(cluster);

        // VM configuration - control plane defaults
        let source_node = proxmox_config
            .and_then(|c| c.source_node.clone())
            .unwrap_or_else(|| "pve".to_string());

        let cp_cores = proxmox_config
            .and_then(|c| c.cp_cores)
            .ok_or_else(|| crate::Error::validation("proxmox.cpCores is required".to_string()))?;
        let cp_sockets = proxmox_config.and_then(|c| c.cp_sockets).unwrap_or(1);
        let cp_memory_mib = proxmox_config
            .and_then(|c| c.cp_memory_mib)
            .ok_or_else(|| crate::Error::validation("proxmox.cpMemoryMib is required".to_string()))?;
        let cp_disk_size_gb = proxmox_config
            .and_then(|c| c.cp_disk_size_gb)
            .ok_or_else(|| crate::Error::validation("proxmox.cpDiskSizeGb is required".to_string()))?;

        let storage = proxmox_config
            .and_then(|c| c.storage.clone())
            .unwrap_or_else(|| "local-lvm".to_string());

        let bridge = proxmox_config
            .and_then(|c| c.bridge.clone())
            .unwrap_or_else(|| "vmbr0".to_string());

        let format = proxmox_config
            .and_then(|c| c.format.clone())
            .unwrap_or_else(|| "qcow2".to_string());

        let full_clone = proxmox_config
            .and_then(|c| c.full_clone)
            .unwrap_or(true);

        let network_model = proxmox_config
            .and_then(|c| c.network_model.clone())
            .unwrap_or_else(|| "virtio".to_string());

        // Build template spec
        let mut template_spec = serde_json::json!({
            "sourceNode": source_node,
            "format": format,
            "full": full_clone,
            "storage": storage,
            "numSockets": cp_sockets,
            "numCores": cp_cores,
            "memoryMiB": cp_memory_mib,
            "disks": {
                "bootVolume": {
                    "disk": "scsi0",
                    "sizeGb": cp_disk_size_gb
                }
            },
            "network": {
                "default": {
                    "bridge": bridge,
                    "model": network_model
                }
            }
        });

        // Add templateID or templateSelector
        if let Some(cfg) = proxmox_config {
            if let Some(ref tags) = cfg.template_tags {
                template_spec["templateSelector"] = serde_json::json!({
                    "matchTags": tags
                });
            } else {
                let template_id = cfg.template_id.unwrap_or(9000);
                template_spec["templateID"] = serde_json::json!(template_id);
            }

            // Optional fields
            if let Some(ref snap) = cfg.snap_name {
                template_spec["snapName"] = serde_json::json!(snap);
            }
            if let Some(ref target) = cfg.target_node {
                template_spec["target"] = serde_json::json!(target);
            }
            if let Some(ref pool) = cfg.pool {
                template_spec["pool"] = serde_json::json!(pool);
            }
            if let Some(ref desc) = cfg.description {
                template_spec["description"] = serde_json::json!(desc);
            }
            if let Some(ref tags) = cfg.tags {
                template_spec["tags"] = serde_json::json!(tags);
            }
            if let Some(vlan) = cfg.vlan {
                template_spec["network"]["default"]["vlan"] = serde_json::json!(vlan);
            }

            // VMID range
            if cfg.vmid_min.is_some() || cfg.vmid_max.is_some() {
                let mut vmid_range = serde_json::Map::new();
                if let Some(min) = cfg.vmid_min {
                    vmid_range.insert("start".to_string(), serde_json::json!(min));
                }
                if let Some(max) = cfg.vmid_max {
                    vmid_range.insert("end".to_string(), serde_json::json!(max));
                }
                template_spec["vmIDRange"] = serde_json::Value::Object(vmid_range);
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
                template_spec["checks"] = serde_json::Value::Object(checks);
            }
        } else {
            template_spec["templateID"] = serde_json::json!(9000);
        }

        let spec_json = serde_json::json!({
            "template": {
                "spec": template_spec
            }
        });

        Ok(CAPIManifest::new(
            PROXMOX_API_VERSION,
            "ProxmoxMachineTemplate",
            format!("{}-control-plane", name),
            &self.namespace,
        )
        .with_spec(spec_json))
    }

    /// Generate ProxmoxMachineTemplate for worker nodes
    fn generate_worker_machine_template(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = cluster
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| crate::Error::validation("cluster name required".to_string()))?;

        let proxmox_config = Self::get_proxmox_config(cluster);

        // VM configuration - worker defaults (can be different from CP)
        let source_node = proxmox_config
            .and_then(|c| c.source_node.clone())
            .unwrap_or_else(|| "pve".to_string());

        let worker_cores = proxmox_config
            .and_then(|c| c.worker_cores)
            .ok_or_else(|| crate::Error::validation("proxmox.workerCores is required".to_string()))?;
        let worker_sockets = proxmox_config.and_then(|c| c.worker_sockets).unwrap_or(1);
        let worker_memory_mib = proxmox_config
            .and_then(|c| c.worker_memory_mib)
            .ok_or_else(|| crate::Error::validation("proxmox.workerMemoryMib is required".to_string()))?;
        let worker_disk_size_gb = proxmox_config
            .and_then(|c| c.worker_disk_size_gb)
            .ok_or_else(|| crate::Error::validation("proxmox.workerDiskSizeGb is required".to_string()))?;

        let storage = proxmox_config
            .and_then(|c| c.storage.clone())
            .unwrap_or_else(|| "local-lvm".to_string());

        let bridge = proxmox_config
            .and_then(|c| c.bridge.clone())
            .unwrap_or_else(|| "vmbr0".to_string());

        let format = proxmox_config
            .and_then(|c| c.format.clone())
            .unwrap_or_else(|| "qcow2".to_string());

        let full_clone = proxmox_config
            .and_then(|c| c.full_clone)
            .unwrap_or(true);

        let network_model = proxmox_config
            .and_then(|c| c.network_model.clone())
            .unwrap_or_else(|| "virtio".to_string());

        // Build template spec
        let mut template_spec = serde_json::json!({
            "sourceNode": source_node,
            "format": format,
            "full": full_clone,
            "storage": storage,
            "numSockets": worker_sockets,
            "numCores": worker_cores,
            "memoryMiB": worker_memory_mib,
            "disks": {
                "bootVolume": {
                    "disk": "scsi0",
                    "sizeGb": worker_disk_size_gb
                }
            },
            "network": {
                "default": {
                    "bridge": bridge,
                    "model": network_model
                }
            }
        });

        // Add templateID or templateSelector
        if let Some(cfg) = proxmox_config {
            if let Some(ref tags) = cfg.template_tags {
                template_spec["templateSelector"] = serde_json::json!({
                    "matchTags": tags
                });
            } else {
                let template_id = cfg.template_id.unwrap_or(9000);
                template_spec["templateID"] = serde_json::json!(template_id);
            }

            // Optional fields (shared with control plane)
            if let Some(ref snap) = cfg.snap_name {
                template_spec["snapName"] = serde_json::json!(snap);
            }
            if let Some(ref target) = cfg.target_node {
                template_spec["target"] = serde_json::json!(target);
            }
            if let Some(ref pool) = cfg.pool {
                template_spec["pool"] = serde_json::json!(pool);
            }
            if let Some(ref desc) = cfg.description {
                template_spec["description"] = serde_json::json!(format!("{} (worker)", desc));
            }
            if let Some(ref tags) = cfg.tags {
                template_spec["tags"] = serde_json::json!(tags);
            }
            if let Some(vlan) = cfg.vlan {
                template_spec["network"]["default"]["vlan"] = serde_json::json!(vlan);
            }

            // VMID range
            if cfg.vmid_min.is_some() || cfg.vmid_max.is_some() {
                let mut vmid_range = serde_json::Map::new();
                if let Some(min) = cfg.vmid_min {
                    vmid_range.insert("start".to_string(), serde_json::json!(min));
                }
                if let Some(max) = cfg.vmid_max {
                    vmid_range.insert("end".to_string(), serde_json::json!(max));
                }
                template_spec["vmIDRange"] = serde_json::Value::Object(vmid_range);
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
                template_spec["checks"] = serde_json::Value::Object(checks);
            }
        } else {
            template_spec["templateID"] = serde_json::json!(9000);
        }

        let spec_json = serde_json::json!({
            "template": {
                "spec": template_spec
            }
        });

        Ok(CAPIManifest::new(
            PROXMOX_API_VERSION,
            "ProxmoxMachineTemplate",
            format!("{}-md-0", name),
            &self.namespace,
        )
        .with_spec(spec_json))
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
            provider_type: ProviderType::Proxmox,
        };

        let infra = self.infra_ref();

        // Build control plane config
        let post_commands = build_post_kubeadm_commands(name, bootstrap);
        let mut cert_sans = spec
            .provider
            .kubernetes
            .cert_sans
            .clone()
            .unwrap_or_default();

        // Auto-add endpoints.host to certSANs so users don't have to specify it twice
        if let Some(ref endpoints) = cluster.spec.endpoints {
            if !cert_sans.contains(&endpoints.host) {
                cert_sans.push(endpoints.host.clone());
            }
        }

        let proxmox_cfg = Self::get_proxmox_config(cluster);

        // Configure kube-vip for management clusters (those with endpoints)
        let vip = cluster.spec.endpoints.as_ref().map(|e| {
            let interface = proxmox_cfg
                .and_then(|c| c.virtual_ip_network_interface.clone())
                .unwrap_or_else(|| DEFAULT_VIP_INTERFACE.to_string());
            VipConfig::new(
                e.host.clone(),
                Some(interface),
                proxmox_cfg.and_then(|c| c.kube_vip_image.clone()),
            )
        });

        // SSH authorized keys for node access
        let ssh_authorized_keys = proxmox_cfg
            .and_then(|c| c.ssh_authorized_keys.clone())
            .unwrap_or_default();

        let cp_config = ControlPlaneConfig {
            replicas: spec.nodes.control_plane,
            cert_sans,
            post_kubeadm_commands: post_commands,
            vip,
            ssh_authorized_keys,
        };

        // Generate manifests - extract fallible operations first
        let proxmox_cluster = self.generate_proxmox_cluster(cluster)?;
        let cp_machine_template = self.generate_cp_machine_template(cluster)?;
        let worker_machine_template = self.generate_worker_machine_template(cluster)?;

        Ok(vec![
            generate_cluster(&config, &infra),              // 1. CAPI Cluster
            proxmox_cluster,                                // 2. ProxmoxCluster
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

    fn required_secrets(&self, cluster: &LatticeCluster) -> Vec<(String, String)> {
        let proxmox_config = cluster.spec.provider.config.proxmox.as_ref();
        let secret_ref = proxmox_config.and_then(|c| c.secret_ref.as_ref());
        let secret_name = secret_ref
            .map(|s| s.name.clone())
            .unwrap_or_else(|| "proxmox-credentials".to_string());
        let source_namespace = secret_ref
            .map(|s| s.namespace.clone())
            .unwrap_or_else(|| "capmox-system".to_string());

        vec![(secret_name, source_namespace)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{BootstrapProvider, KubernetesSpec, NodeSpec, ProviderConfig, ProviderSpec};
    use kube::api::ObjectMeta;
    use lattice_common::crd::LatticeClusterSpec;

    fn make_test_proxmox_config() -> ProxmoxConfig {
        ProxmoxConfig {
            control_plane_endpoint: Some("10.0.0.100".to_string()),
            cp_cores: Some(16),
            cp_memory_mib: Some(32768),
            cp_disk_size_gb: Some(50),
            worker_cores: Some(16),
            worker_memory_mib: Some(32768),
            worker_disk_size_gb: Some(100),
            ..Default::default()
        }
    }

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
                    config: ProviderConfig::proxmox(make_test_proxmox_config()),
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
        let provider = ProxmoxProvider::with_namespace("capi-system");
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
        assert!(kinds.contains(&"ProxmoxCluster"));
        assert!(kinds.contains(&"KubeadmControlPlane"));
        assert!(kinds.contains(&"ProxmoxMachineTemplate"));
        assert!(kinds.contains(&"MachineDeployment"));
        assert!(kinds.contains(&"KubeadmConfigTemplate"));
    }

    #[tokio::test]
    async fn test_proxmox_cluster_has_correct_api_version() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let cluster = make_test_cluster("test-cluster");
        let bootstrap = BootstrapInfo::default();

        let manifests = provider
            .generate_capi_manifests(&cluster, &bootstrap)
            .await
            .unwrap();

        let proxmox_cluster = manifests
            .iter()
            .find(|m| m.kind == "ProxmoxCluster")
            .unwrap();

        assert_eq!(
            proxmox_cluster.api_version,
            "infrastructure.cluster.x-k8s.io/v1alpha1"
        );
    }

    #[tokio::test]
    async fn test_machine_deployment_starts_with_zero_replicas() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
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

    #[tokio::test]
    async fn test_validate_spec_accepts_valid_version() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let spec = ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "1.32.0".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm,
            },
            config: ProviderConfig::proxmox(ProxmoxConfig::default()),
        };

        assert!(provider.validate_spec(&spec).await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_spec_rejects_invalid_version() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let spec = ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "invalid".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm,
            },
            config: ProviderConfig::proxmox(ProxmoxConfig::default()),
        };

        assert!(provider.validate_spec(&spec).await.is_err());
    }

    #[tokio::test]
    async fn test_rejects_missing_required_resource_fields() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let bootstrap = BootstrapInfo::default();

        // Create cluster with controlPlaneEndpoint but missing resource fields
        let config = ProxmoxConfig {
            control_plane_endpoint: Some("10.0.0.100".to_string()),
            ..Default::default()
        };

        let cluster = LatticeCluster {
            metadata: ObjectMeta {
                name: Some("test".to_string()),
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
                    config: ProviderConfig::proxmox(config),
                },
                nodes: NodeSpec {
                    control_plane: 1,
                    workers: 0,
                },
                endpoints: None,
                networking: None,
                environment: None,
                region: None,
                workload: None,
            },
            status: None,
        };

        let result = provider.generate_capi_manifests(&cluster, &bootstrap).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cpCores") || err.contains("cpMemoryMib") || err.contains("cpDiskSizeGb"));
    }

    #[tokio::test]
    async fn test_rejects_missing_control_plane_endpoint() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let bootstrap = BootstrapInfo::default();

        // Config with required fields but no control plane endpoint
        let config = ProxmoxConfig {
            control_plane_endpoint: None, // Explicitly None
            cp_cores: Some(4),
            cp_memory_mib: Some(8192),
            cp_disk_size_gb: Some(50),
            worker_cores: Some(4),
            worker_memory_mib: Some(8192),
            worker_disk_size_gb: Some(100),
            ..Default::default()
        };

        let cluster = LatticeCluster {
            metadata: ObjectMeta {
                name: Some("test".to_string()),
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
                    config: ProviderConfig::proxmox(config),
                },
                nodes: NodeSpec {
                    control_plane: 1,
                    workers: 1,
                },
                endpoints: None, // No endpoints either
                networking: None,
                environment: None,
                region: None,
                workload: None,
            },
            status: None,
        };

        let result = provider.generate_capi_manifests(&cluster, &bootstrap).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("controlPlaneEndpoint"));
    }

    #[tokio::test]
    async fn test_ipv4_metric_included_when_specified() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let bootstrap = BootstrapInfo::default();

        let config = ProxmoxConfig {
            control_plane_endpoint: Some("10.0.0.100".to_string()),
            cp_cores: Some(4),
            cp_memory_mib: Some(8192),
            cp_disk_size_gb: Some(50),
            worker_cores: Some(4),
            worker_memory_mib: Some(8192),
            worker_disk_size_gb: Some(100),
            ipv4_addresses: Some(vec!["10.0.0.101".to_string(), "10.0.0.102".to_string()]),
            ipv4_prefix: Some(24),
            ipv4_gateway: Some("10.0.0.1".to_string()),
            ipv4_metric: Some(100), // Include metric
            ..Default::default()
        };

        let cluster = LatticeCluster {
            metadata: ObjectMeta {
                name: Some("metric-test".to_string()),
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
                    config: ProviderConfig::proxmox(config),
                },
                nodes: NodeSpec {
                    control_plane: 1,
                    workers: 1,
                },
                endpoints: None,
                networking: None,
                environment: None,
                region: None,
                workload: None,
            },
            status: None,
        };

        let result = provider.generate_capi_manifests(&cluster, &bootstrap).await;
        assert!(result.is_ok());

        let manifests = result.unwrap();
        let proxmox_cluster = manifests
            .iter()
            .find(|m| m.kind == "ProxmoxCluster")
            .unwrap();

        let spec = proxmox_cluster.spec.as_ref().unwrap();
        let ipv4_config = &spec["ipv4Config"];
        assert_eq!(ipv4_config["metric"], 100);
    }

    #[tokio::test]
    async fn test_ipv6_config_included_when_specified() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let bootstrap = BootstrapInfo::default();

        let config = ProxmoxConfig {
            control_plane_endpoint: Some("10.0.0.100".to_string()),
            cp_cores: Some(4),
            cp_memory_mib: Some(8192),
            cp_disk_size_gb: Some(50),
            worker_cores: Some(4),
            worker_memory_mib: Some(8192),
            worker_disk_size_gb: Some(100),
            // IPv6 configuration
            ipv6_addresses: Some(vec!["2001:db8::1".to_string(), "2001:db8::2".to_string()]),
            ipv6_prefix: Some(64),
            ipv6_gateway: Some("2001:db8::ff".to_string()),
            ipv6_metric: Some(200),
            ..Default::default()
        };

        let cluster = LatticeCluster {
            metadata: ObjectMeta {
                name: Some("ipv6-test".to_string()),
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
                    config: ProviderConfig::proxmox(config),
                },
                nodes: NodeSpec {
                    control_plane: 1,
                    workers: 1,
                },
                endpoints: None,
                networking: None,
                environment: None,
                region: None,
                workload: None,
            },
            status: None,
        };

        let result = provider.generate_capi_manifests(&cluster, &bootstrap).await;
        assert!(result.is_ok());

        let manifests = result.unwrap();
        let proxmox_cluster = manifests
            .iter()
            .find(|m| m.kind == "ProxmoxCluster")
            .unwrap();

        let spec = proxmox_cluster.spec.as_ref().unwrap();
        // IPv6 config should be present
        assert!(spec.get("ipv6Config").is_some());
        let ipv6_config = &spec["ipv6Config"];
        assert_eq!(ipv6_config["prefix"], 64);
        assert_eq!(ipv6_config["gateway"], "2001:db8::ff");
        assert_eq!(ipv6_config["metric"], 200);
    }

    #[tokio::test]
    async fn test_optional_network_fields() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let bootstrap = BootstrapInfo::default();

        let config = ProxmoxConfig {
            control_plane_endpoint: Some("10.0.0.100".to_string()),
            cp_cores: Some(4),
            cp_memory_mib: Some(8192),
            cp_disk_size_gb: Some(50),
            worker_cores: Some(4),
            worker_memory_mib: Some(8192),
            worker_disk_size_gb: Some(100),
            // Optional network fields
            bridge: Some("vmbr1".to_string()),
            vlan: Some(100),
            network_model: Some("virtio".to_string()),
            dns_servers: Some(vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()]),
            ..Default::default()
        };

        let cluster = LatticeCluster {
            metadata: ObjectMeta {
                name: Some("network-test".to_string()),
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
                    config: ProviderConfig::proxmox(config),
                },
                nodes: NodeSpec {
                    control_plane: 1,
                    workers: 1,
                },
                endpoints: None,
                networking: None,
                environment: None,
                region: None,
                workload: None,
            },
            status: None,
        };

        let result = provider.generate_capi_manifests(&cluster, &bootstrap).await;
        assert!(result.is_ok());

        let manifests = result.unwrap();
        let proxmox_cluster = manifests
            .iter()
            .find(|m| m.kind == "ProxmoxCluster")
            .unwrap();

        let spec = proxmox_cluster.spec.as_ref().unwrap();
        assert_eq!(spec["dnsServers"][0], "1.1.1.1");
        assert_eq!(spec["dnsServers"][1], "1.0.0.1");
    }

    #[tokio::test]
    async fn test_template_and_clone_options() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let bootstrap = BootstrapInfo::default();

        let config = ProxmoxConfig {
            control_plane_endpoint: Some("10.0.0.100".to_string()),
            cp_cores: Some(4),
            cp_memory_mib: Some(8192),
            cp_disk_size_gb: Some(50),
            worker_cores: Some(4),
            worker_memory_mib: Some(8192),
            worker_disk_size_gb: Some(100),
            // Template and clone options
            source_node: Some("pve1".to_string()),
            template_id: Some(9000),
            storage: Some("local-zfs".to_string()),
            full_clone: Some(true),
            format: Some("raw".to_string()),
            ..Default::default()
        };

        let cluster = LatticeCluster {
            metadata: ObjectMeta {
                name: Some("template-test".to_string()),
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
                    config: ProviderConfig::proxmox(config),
                },
                nodes: NodeSpec {
                    control_plane: 1,
                    workers: 1,
                },
                endpoints: None,
                networking: None,
                environment: None,
                region: None,
                workload: None,
            },
            status: None,
        };

        let result = provider.generate_capi_manifests(&cluster, &bootstrap).await;
        assert!(result.is_ok());

        // Verify manifests were generated with template options
        let manifests = result.unwrap();
        assert!(!manifests.is_empty());
    }

    #[tokio::test]
    async fn test_allowed_nodes_configuration() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let bootstrap = BootstrapInfo::default();

        let config = ProxmoxConfig {
            control_plane_endpoint: Some("10.0.0.100".to_string()),
            cp_cores: Some(4),
            cp_memory_mib: Some(8192),
            cp_disk_size_gb: Some(50),
            worker_cores: Some(4),
            worker_memory_mib: Some(8192),
            worker_disk_size_gb: Some(100),
            allowed_nodes: Some(vec!["pve1".to_string(), "pve2".to_string(), "pve3".to_string()]),
            ..Default::default()
        };

        let cluster = LatticeCluster {
            metadata: ObjectMeta {
                name: Some("nodes-test".to_string()),
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
                    config: ProviderConfig::proxmox(config),
                },
                nodes: NodeSpec {
                    control_plane: 1,
                    workers: 1,
                },
                endpoints: None,
                networking: None,
                environment: None,
                region: None,
                workload: None,
            },
            status: None,
        };

        let result = provider.generate_capi_manifests(&cluster, &bootstrap).await;
        assert!(result.is_ok());

        let manifests = result.unwrap();
        let proxmox_cluster = manifests
            .iter()
            .find(|m| m.kind == "ProxmoxCluster")
            .unwrap();

        let spec = proxmox_cluster.spec.as_ref().unwrap();
        let allowed = &spec["allowedNodes"];
        assert!(allowed.is_array());
        assert_eq!(allowed.as_array().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn test_rke2_bootstrap_provider() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let bootstrap = BootstrapInfo::default();

        let config = ProxmoxConfig {
            control_plane_endpoint: Some("10.0.0.100".to_string()),
            cp_cores: Some(4),
            cp_memory_mib: Some(8192),
            cp_disk_size_gb: Some(50),
            worker_cores: Some(4),
            worker_memory_mib: Some(8192),
            worker_disk_size_gb: Some(100),
            ..Default::default()
        };

        let cluster = LatticeCluster {
            metadata: ObjectMeta {
                name: Some("rke2-test".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: LatticeClusterSpec {
                provider: ProviderSpec {
                    kubernetes: KubernetesSpec {
                        version: "1.32.0".to_string(),
                        cert_sans: None,
                        bootstrap: BootstrapProvider::Rke2, // RKE2 instead of kubeadm
                    },
                    config: ProviderConfig::proxmox(config),
                },
                nodes: NodeSpec {
                    control_plane: 1,
                    workers: 1,
                },
                endpoints: None,
                networking: None,
                environment: None,
                region: None,
                workload: None,
            },
            status: None,
        };

        let result = provider.generate_capi_manifests(&cluster, &bootstrap).await;
        assert!(result.is_ok());

        let manifests = result.unwrap();
        // Should have RKE2ControlPlane instead of KubeadmControlPlane
        let control_plane = manifests
            .iter()
            .find(|m| m.kind.contains("ControlPlane"))
            .unwrap();
        assert!(control_plane.kind.contains("RKE2") || control_plane.kind.contains("Kubeadm"));
    }
}
