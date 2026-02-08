//! AWS infrastructure provider (CAPA)
//!
//! Generates Cluster API manifests for provisioning Kubernetes clusters on
//! AWS using the CAPA provider. Uses NLB for API server load balancing.

use async_trait::async_trait;

use super::{
    build_cert_sans, build_post_kubeadm_commands, create_cluster_labels,
    generate_bootstrap_config_template_for_pool, generate_cluster, generate_control_plane,
    generate_machine_deployment_for_pool, get_cluster_name, pool_resource_suffix,
    validate_k8s_version, BootstrapInfo, CAPIManifest, ClusterConfig, ControlPlaneConfig,
    InfrastructureRef, Provider, WorkerPoolConfig,
};
use crate::constants::{AWS_API_VERSION, INFRASTRUCTURE_API_GROUP};
use lattice_common::crd::{AwsConfig, LatticeCluster, ProviderSpec, ProviderType};
use lattice_common::{Error, Result, AWS_CAPA_CREDENTIALS_SECRET, CAPA_NAMESPACE};

/// Configuration for generating an AWS machine template
struct MachineTemplateConfig<'a> {
    name: &'a str,
    aws_cfg: &'a AwsConfig,
    instance_type: &'a str,
    iam_profile: Option<&'a str>,
    root_volume_size: Option<u32>,
    root_volume_type: Option<&'a str>,
    suffix: &'a str,
}

/// AWS infrastructure provider
#[derive(Clone, Debug)]
pub struct AwsProvider {
    namespace: String,
}

impl AwsProvider {
    /// Create a new AWS provider with the given CAPI namespace
    pub fn with_namespace(namespace: &str) -> Self {
        Self {
            namespace: namespace.to_string(),
        }
    }

    fn infra_ref(&self) -> InfrastructureRef<'static> {
        InfrastructureRef {
            api_group: INFRASTRUCTURE_API_GROUP,
            api_version: AWS_API_VERSION,
            cluster_kind: "AWSCluster",
            machine_template_kind: "AWSMachineTemplate",
        }
    }

    fn get_config(cluster: &LatticeCluster) -> Option<&AwsConfig> {
        cluster.spec.provider.config.aws.as_ref()
    }

    /// Generate AWSCluster manifest
    fn generate_aws_cluster(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = cluster
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| Error::validation("cluster name required"))?;
        let cfg =
            Self::get_config(cluster).ok_or_else(|| Error::validation("aws config required"))?;

        let mut spec = serde_json::json!({
            "region": &cfg.region,
            "sshKeyName": &cfg.ssh_key_name
        });

        // Cilium CNI ingress rules (CAPA defaults to Calico which won't work)
        let cni_ingress_rules = serde_json::json!([
            { "description": "VXLAN (cilium)", "fromPort": 8472, "toPort": 8472, "protocol": "udp" },
            { "description": "health (cilium)", "fromPort": 4240, "toPort": 4240, "protocol": "tcp" },
            { "description": "ICMP", "fromPort": -1, "toPort": -1, "protocol": "icmp" }
        ]);

        // BYOI: use existing VPC and subnets
        if let Some(ref vpc_id) = cfg.vpc_id {
            let mut network = serde_json::json!({
                "vpc": { "id": vpc_id },
                "cni": { "cniIngressRules": cni_ingress_rules }
            });

            if let Some(ref subnets) = cfg.subnet_ids {
                let subnet_list: Vec<serde_json::Value> = subnets
                    .iter()
                    .map(|id| serde_json::json!({ "id": id }))
                    .collect();
                network["subnets"] = serde_json::json!(subnet_list);
            }

            spec["network"] = network;
        } else {
            // Non-BYOI: still need Cilium CNI rules
            spec["network"] = serde_json::json!({
                "cni": { "cniIngressRules": cni_ingress_rules }
            });
        }

        // Control plane load balancer configuration (NLB by default)
        let lb_type = cfg
            .load_balancer_type
            .clone()
            .unwrap_or_else(|| "nlb".to_string());
        let lb_scheme = if cfg.internal_load_balancer.unwrap_or(false) {
            "internal"
        } else {
            "internet-facing"
        };
        spec["controlPlaneLoadBalancer"] = serde_json::json!({
            "scheme": lb_scheme,
            "loadBalancerType": lb_type,
            "healthCheckProtocol": "HTTPS"
        });

        Ok(CAPIManifest::new(AWS_API_VERSION, "AWSCluster", name, &self.namespace).with_spec(spec))
    }

    /// Generate AWSMachineTemplate manifest
    fn generate_machine_template(&self, cfg: MachineTemplateConfig<'_>) -> CAPIManifest {
        let mut spec = serde_json::json!({
            "instanceType": cfg.instance_type,
            "sshKeyName": &cfg.aws_cfg.ssh_key_name
        });

        // IAM instance profile
        if let Some(profile) = cfg.iam_profile {
            spec["iamInstanceProfile"] = serde_json::json!(profile);
        }

        // AMI configuration
        if let Some(ref ami_id) = cfg.aws_cfg.ami_id {
            spec["ami"] = serde_json::json!({ "id": ami_id });
        }

        // Root volume configuration
        let volume_size = cfg.root_volume_size.unwrap_or(80);
        let volume_type = cfg.root_volume_type.unwrap_or("gp3");
        spec["rootVolume"] = serde_json::json!({
            "size": volume_size,
            "type": volume_type
        });

        // SSH authorized keys for cloud-init
        if let Some(keys) = &cfg.aws_cfg.ssh_authorized_keys {
            if !keys.is_empty() {
                spec["cloudInit"] = serde_json::json!({
                    "insecureSkipSecretsManager": true
                });
            }
        }

        CAPIManifest::new(
            AWS_API_VERSION,
            "AWSMachineTemplate",
            format!("{}-{}", cfg.name, cfg.suffix),
            &self.namespace,
        )
        .with_spec(serde_json::json!({ "template": { "spec": spec } }))
    }
}

#[async_trait]
impl Provider for AwsProvider {
    async fn generate_capi_manifests(
        &self,
        cluster: &LatticeCluster,
        bootstrap: &BootstrapInfo,
    ) -> Result<Vec<CAPIManifest>> {
        let name = get_cluster_name(cluster)?;
        let spec = &cluster.spec;
        let cfg =
            Self::get_config(cluster).ok_or_else(|| Error::validation("aws config required"))?;

        // Build cluster config with AWS-specific labels for addon ClusterResourceSets
        let mut labels = create_cluster_labels(name);
        // AWS clusters use external cloud controller manager and EBS CSI driver
        labels.insert("ccm".to_string(), "external".to_string());
        labels.insert("csi".to_string(), "external".to_string());

        let config = ClusterConfig {
            name,
            namespace: &self.namespace,
            k8s_version: &spec.provider.kubernetes.version,
            labels,
            bootstrap: spec.provider.kubernetes.bootstrap.clone(),
            provider_type: ProviderType::Aws,
        };

        // No kube-vip for AWS - we use NLB
        let cp_config = ControlPlaneConfig {
            replicas: spec.nodes.control_plane.replicas,
            cert_sans: build_cert_sans(cluster),
            post_kubeadm_commands: build_post_kubeadm_commands(name, bootstrap)?,
            vip: None,
            ssh_authorized_keys: cfg.ssh_authorized_keys.clone().unwrap_or_default(),
        };

        let infra = self.infra_ref();

        // Get IAM profiles with CAPA defaults
        let cp_iam = cfg
            .cp_iam_instance_profile
            .as_deref()
            .unwrap_or("control-plane.cluster-api-provider-aws.sigs.k8s.io");
        let worker_iam = cfg
            .worker_iam_instance_profile
            .as_deref()
            .unwrap_or("nodes.cluster-api-provider-aws.sigs.k8s.io");

        // Read CP instance type and root volume from node spec
        let cp_instance_type = spec
            .nodes
            .control_plane
            .instance_type
            .as_ref()
            .and_then(|it| it.as_named())
            .unwrap_or("m5.xlarge");
        let cp_root_volume_size = spec
            .nodes
            .control_plane
            .root_volume
            .as_ref()
            .map(|v| v.size_gb);
        let cp_root_volume_type = spec
            .nodes
            .control_plane
            .root_volume
            .as_ref()
            .and_then(|v| v.type_.as_deref());

        let mut manifests = vec![
            generate_cluster(&config, &infra),
            self.generate_aws_cluster(cluster)?,
            generate_control_plane(&config, &infra, &cp_config)?,
            self.generate_machine_template(MachineTemplateConfig {
                name,
                aws_cfg: cfg,
                instance_type: cp_instance_type,
                iam_profile: Some(cp_iam),
                root_volume_size: cp_root_volume_size,
                root_volume_type: cp_root_volume_type,
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

            // Read per-pool instance type and root volume from worker pool spec
            let worker_instance_type = pool_spec
                .instance_type
                .as_ref()
                .and_then(|it| it.as_named())
                .unwrap_or("m5.large");
            let worker_root_volume_size = pool_spec.root_volume.as_ref().map(|v| v.size_gb);
            let worker_root_volume_type = pool_spec
                .root_volume
                .as_ref()
                .and_then(|v| v.type_.as_deref());

            manifests.push(generate_machine_deployment_for_pool(
                &config,
                &infra,
                &pool_config,
            ));
            manifests.push(self.generate_machine_template(MachineTemplateConfig {
                name,
                aws_cfg: cfg,
                instance_type: worker_instance_type,
                iam_profile: Some(worker_iam),
                root_volume_size: worker_root_volume_size,
                root_volume_type: worker_root_volume_type,
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

        // Validate AWS-specific config
        if let Some(ref cfg) = spec.config.aws {
            if cfg.region.is_empty() {
                return Err(Error::validation("aws config requires region"));
            }
            if cfg.ssh_key_name.is_empty() {
                return Err(Error::validation("aws config requires sshKeyName"));
            }

            // BYOI requires both VPC and subnets
            if cfg.vpc_id.is_some() && cfg.subnet_ids.is_none() {
                return Err(Error::validation(
                    "aws config requires subnetIds when vpcId is specified",
                ));
            }
        }

        Ok(())
    }

    fn required_secrets(&self, cluster: &LatticeCluster) -> Vec<(String, String)> {
        super::get_provider_secrets(cluster, AWS_CAPA_CREDENTIALS_SECRET, CAPA_NAMESPACE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::api::ObjectMeta;
    use lattice_common::crd::LatticeClusterSpec;
    use lattice_common::crd::{
        BootstrapProvider, ControlPlaneSpec, InstanceType, KubernetesSpec, NodeSpec,
        ProviderConfig, ProviderSpec, RootVolume, WorkerPoolSpec,
    };

    fn test_aws_config() -> AwsConfig {
        AwsConfig {
            region: "us-west-2".to_string(),
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
                provider_ref: "aws".to_string(),
                provider: ProviderSpec {
                    kubernetes: KubernetesSpec {
                        version: "1.32.0".to_string(),
                        cert_sans: None,
                        bootstrap: BootstrapProvider::Kubeadm,
                    },
                    config: ProviderConfig::aws(test_aws_config()),
                    credentials_secret_ref: None,
                },
                nodes: NodeSpec {
                    control_plane: ControlPlaneSpec {
                        replicas: 3,
                        instance_type: Some(InstanceType::named("m5.xlarge")),
                        root_volume: None,
                    },
                    worker_pools: std::collections::BTreeMap::from([(
                        "default".to_string(),
                        WorkerPoolSpec {
                            replicas: 5,
                            instance_type: Some(InstanceType::named("m5.large")),
                            ..Default::default()
                        },
                    )]),
                },
                parent_config: None,
                networking: None,
                services: true,
                gpu: false,
                monitoring: true,
                backups: true,
            },
            status: None,
        }
    }

    #[tokio::test]
    async fn generates_seven_manifests() {
        let provider = AwsProvider::with_namespace("capi-system");
        let manifests = provider
            .generate_capi_manifests(&test_cluster("test"), &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");

        // 7 manifests: Cluster, AWSCluster, ControlPlane, 2x MachineTemplate, MachineDeployment, ConfigTemplate
        assert_eq!(manifests.len(), 7);
        let kinds: Vec<_> = manifests.iter().map(|m| m.kind.as_str()).collect();
        assert!(kinds.contains(&"Cluster"));
        assert!(kinds.contains(&"AWSCluster"));
        assert!(kinds.contains(&"KubeadmControlPlane"));
        assert!(kinds.contains(&"AWSMachineTemplate"));
        assert!(kinds.contains(&"MachineDeployment"));
        assert!(kinds.contains(&"KubeadmConfigTemplate"));
    }

    #[tokio::test]
    async fn uses_nlb_by_default() {
        let provider = AwsProvider::with_namespace("capi-system");
        let manifests = provider
            .generate_capi_manifests(&test_cluster("test"), &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");

        let aws_cluster = manifests
            .iter()
            .find(|m| m.kind == "AWSCluster")
            .expect("AWSCluster should exist");
        let lb = &aws_cluster.spec.as_ref().expect("spec should exist")["controlPlaneLoadBalancer"];
        assert_eq!(lb["loadBalancerType"], "nlb");
        assert_eq!(lb["scheme"], "internet-facing");
    }

    #[tokio::test]
    async fn uses_internal_lb_when_configured() {
        let provider = AwsProvider::with_namespace("capi-system");
        let mut cluster = test_cluster("test");

        if let Some(ref mut cfg) = cluster.spec.provider.config.aws {
            cfg.internal_load_balancer = Some(true);
        }

        let manifests = provider
            .generate_capi_manifests(&cluster, &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");

        let aws_cluster = manifests
            .iter()
            .find(|m| m.kind == "AWSCluster")
            .expect("AWSCluster should exist");
        let lb = &aws_cluster.spec.as_ref().expect("spec should exist")["controlPlaneLoadBalancer"];
        assert_eq!(lb["scheme"], "internal");
    }

    #[tokio::test]
    async fn validates_kubernetes_version() {
        let provider = AwsProvider::with_namespace("capi-system");

        let valid = ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "1.32.0".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm,
            },
            config: ProviderConfig::aws(test_aws_config()),
            credentials_secret_ref: None,
        };
        assert!(provider.validate_spec(&valid).await.is_ok());

        let invalid = ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "invalid".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm,
            },
            config: ProviderConfig::aws(test_aws_config()),
            credentials_secret_ref: None,
        };
        assert!(provider.validate_spec(&invalid).await.is_err());
    }

    #[tokio::test]
    async fn validates_required_aws_fields() {
        let provider = AwsProvider::with_namespace("capi-system");

        let mut cfg = test_aws_config();
        cfg.region = String::new();

        let spec = ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "1.32.0".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm,
            },
            config: ProviderConfig::aws(cfg),
            credentials_secret_ref: None,
        };

        let result = provider.validate_spec(&spec).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("region"));
    }

    #[tokio::test]
    async fn validates_vpc_requires_subnets() {
        let provider = AwsProvider::with_namespace("capi-system");

        let mut cfg = test_aws_config();
        cfg.vpc_id = Some("vpc-12345".to_string());

        let spec = ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "1.32.0".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm,
            },
            config: ProviderConfig::aws(cfg),
            credentials_secret_ref: None,
        };

        let result = provider.validate_spec(&spec).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("subnetIds"));
    }

    #[tokio::test]
    async fn supports_rke2_bootstrap() {
        let provider = AwsProvider::with_namespace("capi-system");
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
    async fn configures_root_volumes() {
        let provider = AwsProvider::with_namespace("capi-system");
        let mut cluster = test_cluster("test");

        // Root volumes are now on node spec, not provider config
        cluster.spec.nodes.control_plane.root_volume = Some(RootVolume {
            size_gb: 100,
            type_: Some("io1".to_string()),
        });
        if let Some(ref mut pool) = cluster.spec.nodes.worker_pools.get_mut("default") {
            pool.root_volume = Some(RootVolume {
                size_gb: 200,
                type_: None,
            });
        }

        let manifests = provider
            .generate_capi_manifests(&cluster, &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");

        let cp_template = manifests
            .iter()
            .find(|m| m.kind == "AWSMachineTemplate" && m.metadata.name.contains("control-plane"))
            .expect("control plane template should exist");

        let root_volume = &cp_template.spec.as_ref().expect("spec should exist")["template"]
            ["spec"]["rootVolume"];
        assert_eq!(root_volume["size"], 100);
        assert_eq!(root_volume["type"], "io1");
    }

    #[tokio::test]
    async fn uses_default_iam_profiles() {
        let provider = AwsProvider::with_namespace("capi-system");
        let manifests = provider
            .generate_capi_manifests(&test_cluster("test"), &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");

        let cp_template = manifests
            .iter()
            .find(|m| m.kind == "AWSMachineTemplate" && m.metadata.name.contains("control-plane"))
            .expect("control plane template should exist");

        let iam_profile = cp_template.spec.as_ref().expect("spec should exist")["template"]["spec"]
            ["iamInstanceProfile"]
            .as_str()
            .expect("iamInstanceProfile should be a string");
        assert_eq!(
            iam_profile,
            "control-plane.cluster-api-provider-aws.sigs.k8s.io"
        );
    }

    #[tokio::test]
    async fn uses_custom_iam_profiles() {
        let provider = AwsProvider::with_namespace("capi-system");
        let mut cluster = test_cluster("test");

        if let Some(ref mut cfg) = cluster.spec.provider.config.aws {
            cfg.cp_iam_instance_profile = Some("custom-cp-profile".to_string());
            cfg.worker_iam_instance_profile = Some("custom-worker-profile".to_string());
        }

        let manifests = provider
            .generate_capi_manifests(&cluster, &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");

        let cp_template = manifests
            .iter()
            .find(|m| m.kind == "AWSMachineTemplate" && m.metadata.name.contains("control-plane"))
            .expect("control plane template should exist");

        let iam_profile = cp_template.spec.as_ref().expect("spec should exist")["template"]["spec"]
            ["iamInstanceProfile"]
            .as_str()
            .expect("iamInstanceProfile should be a string");
        assert_eq!(iam_profile, "custom-cp-profile");

        let worker_template = manifests
            .iter()
            .find(|m| m.kind == "AWSMachineTemplate" && m.metadata.name.contains("pool-default"))
            .expect("worker template should exist");

        let worker_iam = worker_template.spec.as_ref().expect("spec should exist")["template"]
            ["spec"]["iamInstanceProfile"]
            .as_str()
            .expect("iamInstanceProfile should be a string");
        assert_eq!(worker_iam, "custom-worker-profile");
    }

    #[tokio::test]
    async fn uses_existing_vpc_when_configured() {
        let provider = AwsProvider::with_namespace("capi-system");
        let mut cluster = test_cluster("test");

        if let Some(ref mut cfg) = cluster.spec.provider.config.aws {
            cfg.vpc_id = Some("vpc-12345".to_string());
            cfg.subnet_ids = Some(vec!["subnet-a".to_string(), "subnet-b".to_string()]);
        }

        let manifests = provider
            .generate_capi_manifests(&cluster, &BootstrapInfo::default())
            .await
            .expect("manifest generation");

        let aws_cluster = manifests
            .iter()
            .find(|m| m.kind == "AWSCluster")
            .expect("AWSCluster");

        let spec = aws_cluster.spec.as_ref().expect("spec");
        assert_eq!(spec["network"]["vpc"]["id"].as_str().unwrap(), "vpc-12345");
        assert_eq!(spec["network"]["subnets"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn uses_custom_ami_when_configured() {
        let provider = AwsProvider::with_namespace("capi-system");
        let mut cluster = test_cluster("test");

        if let Some(ref mut cfg) = cluster.spec.provider.config.aws {
            cfg.ami_id = Some("ami-custom123".to_string());
        }

        let manifests = provider
            .generate_capi_manifests(&cluster, &BootstrapInfo::default())
            .await
            .expect("manifest generation");

        // Both control plane and worker templates should use the custom AMI
        let cp_template = manifests
            .iter()
            .find(|m| m.kind == "AWSMachineTemplate" && m.metadata.name.contains("control-plane"))
            .expect("control plane template");

        let cp_ami = cp_template.spec.as_ref().expect("spec")["template"]["spec"]["ami"]["id"]
            .as_str()
            .expect("ami id");
        assert_eq!(cp_ami, "ami-custom123");

        let worker_template = manifests
            .iter()
            .find(|m| m.kind == "AWSMachineTemplate" && m.metadata.name.contains("pool-default"))
            .expect("worker template");

        let worker_ami = worker_template.spec.as_ref().expect("spec")["template"]["spec"]["ami"]
            ["id"]
            .as_str()
            .expect("ami id");
        assert_eq!(worker_ami, "ami-custom123");
    }
}
