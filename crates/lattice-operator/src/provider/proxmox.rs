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
    ClusterConfig, ControlPlaneConfig, InfrastructureRef, Provider,
};
use crate::crd::{LatticeCluster, ProviderSpec, ProxmoxConfig};
use crate::Result;

/// CAPMOX API version
const PROXMOX_API_VERSION: &str = "infrastructure.cluster.x-k8s.io/v1alpha1";

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

        // Build IPv4 config - addresses come from pool or config
        let ipv4_config = if let Some(cfg) = proxmox_config {
            serde_json::json!({
                "addresses": cfg.ipv4_addresses.clone().unwrap_or_default(),
                "prefix": cfg.ipv4_prefix.unwrap_or(24),
                "gateway": cfg.ipv4_gateway.clone().unwrap_or_default()
            })
        } else {
            serde_json::json!({
                "addresses": [],
                "prefix": 24,
                "gateway": ""
            })
        };

        // DNS servers
        let dns_servers = proxmox_config
            .and_then(|c| c.dns_servers.clone())
            .unwrap_or_else(|| vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()]);

        // Allowed nodes (Proxmox cluster nodes that can host VMs)
        let allowed_nodes = proxmox_config
            .and_then(|c| c.allowed_nodes.clone())
            .unwrap_or_default();

        // Control plane endpoint
        let control_plane_endpoint = if let Some(ref endpoints) = cluster.spec.endpoints {
            serde_json::json!({
                "host": endpoints.host,
                "port": 6443
            })
        } else {
            serde_json::json!({
                "host": "",
                "port": 6443
            })
        };

        let spec_json = serde_json::json!({
            "controlPlaneEndpoint": control_plane_endpoint,
            "ipv4Config": ipv4_config,
            "dnsServers": dns_servers,
            "allowedNodes": allowed_nodes
        });

        Ok(CAPIManifest::new(
            PROXMOX_API_VERSION,
            "ProxmoxCluster",
            name,
            &self.namespace,
        )
        .with_spec(spec_json))
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

        let template_id = proxmox_config
            .and_then(|c| c.template_id)
            .unwrap_or(9000);

        let cp_cores = proxmox_config.and_then(|c| c.cp_cores).unwrap_or(4);
        let cp_sockets = proxmox_config.and_then(|c| c.cp_sockets).unwrap_or(1);
        let cp_memory_mib = proxmox_config.and_then(|c| c.cp_memory_mib).unwrap_or(8192);
        let cp_disk_size_gb = proxmox_config.and_then(|c| c.cp_disk_size_gb).unwrap_or(50);

        let _storage = proxmox_config
            .and_then(|c| c.storage.clone())
            .unwrap_or_else(|| "local-lvm".to_string());

        let bridge = proxmox_config
            .and_then(|c| c.bridge.clone())
            .unwrap_or_else(|| "vmbr0".to_string());

        let spec_json = serde_json::json!({
            "template": {
                "spec": {
                    "sourceNode": source_node,
                    "templateID": template_id,
                    "format": "qcow2",
                    "full": true,
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
                            "model": "virtio"
                        }
                    }
                }
            }
        });

        Ok(CAPIManifest::new(
            PROXMOX_API_VERSION,
            "ProxmoxMachineTemplate",
            format!("{}-cp", name),
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

        let template_id = proxmox_config
            .and_then(|c| c.template_id)
            .unwrap_or(9000);

        let worker_cores = proxmox_config.and_then(|c| c.worker_cores).unwrap_or(4);
        let worker_sockets = proxmox_config.and_then(|c| c.worker_sockets).unwrap_or(1);
        let worker_memory_mib = proxmox_config
            .and_then(|c| c.worker_memory_mib)
            .unwrap_or(8192);
        let worker_disk_size_gb = proxmox_config
            .and_then(|c| c.worker_disk_size_gb)
            .unwrap_or(100);

        let _storage = proxmox_config
            .and_then(|c| c.storage.clone())
            .unwrap_or_else(|| "local-lvm".to_string());

        let bridge = proxmox_config
            .and_then(|c| c.bridge.clone())
            .unwrap_or_else(|| "vmbr0".to_string());

        let spec_json = serde_json::json!({
            "template": {
                "spec": {
                    "sourceNode": source_node,
                    "templateID": template_id,
                    "format": "qcow2",
                    "full": true,
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
                            "model": "virtio"
                        }
                    }
                }
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

        // 2. ProxmoxCluster (infrastructure)
        manifests.push(self.generate_proxmox_cluster(cluster)?);

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
    use crate::crd::{BootstrapProvider, KubernetesSpec, NodeSpec, ProviderConfig, ProviderSpec};
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
                    config: ProviderConfig::proxmox(ProxmoxConfig::default()),
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
                version: "1.31.0".to_string(),
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
}
