//! AWS infrastructure provider (CAPA)
//!
//! This provider generates Cluster API manifests for provisioning Kubernetes
//! clusters on Amazon Web Services using the CAPA provider.
//!
//! CAPA API: infrastructure.cluster.x-k8s.io/v1beta2

use async_trait::async_trait;
use std::collections::BTreeMap;

use super::{
    build_post_kubeadm_commands, generate_bootstrap_config_template, generate_cluster,
    generate_control_plane, generate_machine_deployment, BootstrapInfo, CAPIManifest,
    ClusterConfig, ControlPlaneConfig, InfrastructureRef, Provider,
};
use crate::crd::{AwsConfig, LatticeCluster, ProviderSpec};
use crate::Result;

/// CAPA API version
const AWS_API_VERSION: &str = "infrastructure.cluster.x-k8s.io/v1beta2";

/// AWS infrastructure provider
///
/// Generates CAPI manifests for AWS using the CAPA provider.
/// Supports both kubeadm and RKE2 bootstrap providers.
#[derive(Clone, Debug)]
pub struct AwsProvider {
    /// Namespace for CAPI resources
    namespace: String,
}

impl AwsProvider {
    /// Create a new AWS provider with the given namespace
    pub fn with_namespace(namespace: &str) -> Self {
        Self {
            namespace: namespace.to_string(),
        }
    }

    /// Get infrastructure reference for AWS
    fn infra_ref(&self) -> InfrastructureRef<'static> {
        InfrastructureRef {
            api_group: "infrastructure.cluster.x-k8s.io",
            api_version: AWS_API_VERSION,
            cluster_kind: "AWSCluster",
            machine_template_kind: "AWSMachineTemplate",
        }
    }

    /// Extract AwsConfig from the cluster's provider config
    fn get_aws_config(cluster: &LatticeCluster) -> Option<&AwsConfig> {
        cluster.spec.provider.config.aws.as_ref()
    }

    /// Generate AWSCluster manifest
    fn generate_aws_cluster(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = cluster
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| crate::Error::validation("cluster name required".to_string()))?;

        let aws_config = Self::get_aws_config(cluster);

        // AWS region
        let region = aws_config
            .and_then(|c| c.region.clone())
            .unwrap_or_else(|| "us-west-2".to_string());

        // SSH key name (optional)
        let ssh_key_name = aws_config.and_then(|c| c.ssh_key_name.clone());

        // Control plane endpoint
        let control_plane_endpoint = if let Some(ref endpoints) = cluster.spec.endpoints {
            serde_json::json!({
                "host": endpoints.host,
                "port": 6443
            })
        } else {
            serde_json::json!({})
        };

        let mut spec_json = serde_json::json!({
            "region": region,
            "controlPlaneLoadBalancer": {
                "scheme": "internet-facing"
            }
        });

        // Add SSH key if specified
        if let Some(key_name) = ssh_key_name {
            spec_json["sshKeyName"] = serde_json::json!(key_name);
        }

        // Add control plane endpoint if specified
        if cluster.spec.endpoints.is_some() {
            spec_json["controlPlaneEndpoint"] = control_plane_endpoint;
        }

        // Add VPC if specified
        if let Some(vpc_id) = aws_config.and_then(|c| c.vpc_id.clone()) {
            spec_json["network"] = serde_json::json!({
                "vpc": {
                    "id": vpc_id
                }
            });
        }

        Ok(
            CAPIManifest::new(AWS_API_VERSION, "AWSCluster", name, &self.namespace)
                .with_spec(spec_json),
        )
    }

    /// Generate AWSMachineTemplate for control plane nodes
    fn generate_cp_machine_template(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = cluster
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| crate::Error::validation("cluster name required".to_string()))?;

        let aws_config = Self::get_aws_config(cluster);

        // Instance configuration
        let instance_type = aws_config
            .and_then(|c| c.cp_instance_type.clone())
            .unwrap_or_else(|| "t3.large".to_string());

        let iam_instance_profile = aws_config
            .and_then(|c| c.cp_iam_instance_profile.clone())
            .unwrap_or_else(|| "control-plane.cluster-api-provider-aws.sigs.k8s.io".to_string());

        let ssh_key_name = aws_config.and_then(|c| c.ssh_key_name.clone());

        let root_volume_size = aws_config.and_then(|c| c.cp_root_volume_size).unwrap_or(80);

        let public_ip = aws_config.and_then(|c| c.public_ip).unwrap_or(false);

        let mut spec_json = serde_json::json!({
            "template": {
                "spec": {
                    "instanceType": instance_type,
                    "iamInstanceProfile": iam_instance_profile,
                    "publicIP": public_ip,
                    "rootVolume": {
                        "size": root_volume_size
                    }
                }
            }
        });

        // Add SSH key if specified
        if let Some(key_name) = ssh_key_name {
            spec_json["template"]["spec"]["sshKeyName"] = serde_json::json!(key_name);
        }

        // Add AMI if specified
        if let Some(ami_id) = aws_config.and_then(|c| c.ami_id.clone()) {
            spec_json["template"]["spec"]["ami"] = serde_json::json!({ "id": ami_id });
        }

        Ok(CAPIManifest::new(
            AWS_API_VERSION,
            "AWSMachineTemplate",
            format!("{}-cp", name),
            &self.namespace,
        )
        .with_spec(spec_json))
    }

    /// Generate AWSMachineTemplate for worker nodes
    fn generate_worker_machine_template(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = cluster
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| crate::Error::validation("cluster name required".to_string()))?;

        let aws_config = Self::get_aws_config(cluster);

        // Instance configuration
        let instance_type = aws_config
            .and_then(|c| c.worker_instance_type.clone())
            .unwrap_or_else(|| "t3.large".to_string());

        let iam_instance_profile = aws_config
            .and_then(|c| c.worker_iam_instance_profile.clone())
            .unwrap_or_else(|| "nodes.cluster-api-provider-aws.sigs.k8s.io".to_string());

        let ssh_key_name = aws_config.and_then(|c| c.ssh_key_name.clone());

        let root_volume_size = aws_config
            .and_then(|c| c.worker_root_volume_size)
            .unwrap_or(80);

        let public_ip = aws_config.and_then(|c| c.public_ip).unwrap_or(false);

        let mut spec_json = serde_json::json!({
            "template": {
                "spec": {
                    "instanceType": instance_type,
                    "iamInstanceProfile": iam_instance_profile,
                    "publicIP": public_ip,
                    "rootVolume": {
                        "size": root_volume_size
                    }
                }
            }
        });

        // Add SSH key if specified
        if let Some(key_name) = ssh_key_name {
            spec_json["template"]["spec"]["sshKeyName"] = serde_json::json!(key_name);
        }

        // Add AMI if specified
        if let Some(ami_id) = aws_config.and_then(|c| c.ami_id.clone()) {
            spec_json["template"]["spec"]["ami"] = serde_json::json!({ "id": ami_id });
        }

        Ok(CAPIManifest::new(
            AWS_API_VERSION,
            "AWSMachineTemplate",
            format!("{}-md-0", name),
            &self.namespace,
        )
        .with_spec(spec_json))
    }
}

#[async_trait]
impl Provider for AwsProvider {
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
        // AWS requires external cloud provider labels
        labels.insert("ccm".to_string(), "external".to_string());
        labels.insert("csi".to_string(), "external".to_string());

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

        // 2. AWSCluster (infrastructure)
        manifests.push(self.generate_aws_cluster(cluster)?);

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

        // Validate AWS config if present
        if let Some(aws_config) = &spec.config.aws {
            // Validate region format if specified
            if let Some(ref region) = aws_config.region {
                if !region.contains('-') {
                    return Err(crate::Error::validation(format!(
                        "invalid AWS region: {region}, expected format: us-west-2"
                    )));
                }
            }
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
                    config: ProviderConfig::aws(AwsConfig::default()),
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
        let provider = AwsProvider::with_namespace("capi-system");
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
        assert!(kinds.contains(&"AWSCluster"));
        assert!(kinds.contains(&"KubeadmControlPlane"));
        assert!(kinds.contains(&"AWSMachineTemplate"));
        assert!(kinds.contains(&"MachineDeployment"));
        assert!(kinds.contains(&"KubeadmConfigTemplate"));
    }

    #[tokio::test]
    async fn test_aws_cluster_has_correct_api_version() {
        let provider = AwsProvider::with_namespace("capi-system");
        let cluster = make_test_cluster("test-cluster");
        let bootstrap = BootstrapInfo::default();

        let manifests = provider
            .generate_capi_manifests(&cluster, &bootstrap)
            .await
            .unwrap();

        let aws_cluster = manifests.iter().find(|m| m.kind == "AWSCluster").unwrap();

        assert_eq!(
            aws_cluster.api_version,
            "infrastructure.cluster.x-k8s.io/v1beta2"
        );
    }

    #[tokio::test]
    async fn test_validate_spec_accepts_valid_version() {
        let provider = AwsProvider::with_namespace("capi-system");
        let spec = ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "1.31.0".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm,
            },
            config: ProviderConfig::aws(AwsConfig::default()),
        };

        assert!(provider.validate_spec(&spec).await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_spec_rejects_invalid_version() {
        let provider = AwsProvider::with_namespace("capi-system");
        let spec = ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "invalid".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm,
            },
            config: ProviderConfig::aws(AwsConfig::default()),
        };

        assert!(provider.validate_spec(&spec).await.is_err());
    }

    #[tokio::test]
    async fn test_validate_spec_rejects_invalid_region() {
        let provider = AwsProvider::with_namespace("capi-system");
        let spec = ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "1.31.0".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm,
            },
            config: ProviderConfig::aws(AwsConfig {
                region: Some("invalid".to_string()),
                ..Default::default()
            }),
        };

        assert!(provider.validate_spec(&spec).await.is_err());
    }
}
