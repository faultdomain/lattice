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

        // Load balancer configuration
        let lb_scheme = aws_config
            .and_then(|c| c.lb_scheme.clone())
            .unwrap_or_else(|| "internet-facing".to_string());

        let mut lb_config = serde_json::json!({ "scheme": lb_scheme });

        if let Some(lb_type) = aws_config.and_then(|c| c.lb_type.clone()) {
            lb_config["loadBalancerType"] = serde_json::json!(lb_type);
        }
        if let Some(lb_name) = aws_config.and_then(|c| c.lb_name.clone()) {
            lb_config["name"] = serde_json::json!(lb_name);
        }
        if let Some(lb_sgs) = aws_config.and_then(|c| c.lb_additional_security_groups.clone()) {
            lb_config["additionalSecurityGroups"] = serde_json::json!(lb_sgs);
        }
        if let Some(lb_subnets) = aws_config.and_then(|c| c.lb_subnets.clone()) {
            let subnet_refs: Vec<_> = lb_subnets.iter().map(|s| serde_json::json!({ "id": s })).collect();
            lb_config["subnets"] = serde_json::json!(subnet_refs);
        }

        let mut spec_json = serde_json::json!({
            "region": region,
            "controlPlaneLoadBalancer": lb_config
        });

        // Partition (aws, aws-cn, aws-us-gov)
        if let Some(partition) = aws_config.and_then(|c| c.partition.clone()) {
            spec_json["partition"] = serde_json::json!(partition);
        }

        // SSH key
        if let Some(key_name) = aws_config.and_then(|c| c.ssh_key_name.clone()) {
            spec_json["sshKeyName"] = serde_json::json!(key_name);
        }

        // Control plane endpoint
        if let Some(ref endpoints) = cluster.spec.endpoints {
            spec_json["controlPlaneEndpoint"] = serde_json::json!({
                "host": endpoints.host,
                "port": 6443
            });
        }

        // Network configuration
        let has_network_config = aws_config.and_then(|c| c.vpc_id.clone()).is_some()
            || aws_config.and_then(|c| c.subnet_ids.clone()).is_some();

        if has_network_config {
            let mut network = serde_json::json!({});
            if let Some(vpc_id) = aws_config.and_then(|c| c.vpc_id.clone()) {
                network["vpc"] = serde_json::json!({ "id": vpc_id });
            }
            if let Some(subnet_ids) = aws_config.and_then(|c| c.subnet_ids.clone()) {
                let subnet_refs: Vec<_> = subnet_ids.iter().map(|s| serde_json::json!({ "id": s })).collect();
                network["subnets"] = serde_json::json!(subnet_refs);
            }
            spec_json["network"] = network;
        }

        // Node port ingress CIDRs
        if let Some(cidrs) = aws_config.and_then(|c| c.node_port_ingress_cidrs.clone()) {
            spec_json["additionalControlPlaneIngressRules"] = serde_json::json!([{
                "description": "Node port ingress",
                "protocol": "tcp",
                "fromPort": 30000,
                "toPort": 32767,
                "cidrBlocks": cidrs
            }]);
        }

        // Security group overrides
        if let Some(sg_overrides) = aws_config.and_then(|c| c.security_group_overrides.clone()) {
            spec_json["network"]["securityGroupOverrides"] = serde_json::json!(sg_overrides);
        }

        // Additional tags
        if let Some(tags) = aws_config.and_then(|c| c.additional_tags.clone()) {
            spec_json["additionalTags"] = serde_json::json!(tags);
        }

        // Bastion host configuration
        if let Some(bastion_enabled) = aws_config.and_then(|c| c.bastion_enabled) {
            if bastion_enabled {
                let mut bastion_spec = serde_json::json!({ "enabled": true });
                if let Some(instance_type) = aws_config.and_then(|c| c.bastion_instance_type.clone()) {
                    bastion_spec["instanceType"] = serde_json::json!(instance_type);
                }
                if let Some(ami_id) = aws_config.and_then(|c| c.bastion_ami_id.clone()) {
                    bastion_spec["ami"] = serde_json::json!({ "id": ami_id });
                }
                spec_json["bastion"] = bastion_spec;
            }
        }

        // AMI lookup configuration
        let has_image_lookup = aws_config.and_then(|c| c.image_lookup_format.clone()).is_some()
            || aws_config.and_then(|c| c.image_lookup_org.clone()).is_some()
            || aws_config.and_then(|c| c.image_lookup_base_os.clone()).is_some();

        if has_image_lookup {
            let mut image_lookup = serde_json::json!({});
            if let Some(format) = aws_config.and_then(|c| c.image_lookup_format.clone()) {
                image_lookup["format"] = serde_json::json!(format);
            }
            if let Some(org) = aws_config.and_then(|c| c.image_lookup_org.clone()) {
                image_lookup["org"] = serde_json::json!(org);
            }
            if let Some(base_os) = aws_config.and_then(|c| c.image_lookup_base_os.clone()) {
                image_lookup["baseOS"] = serde_json::json!(base_os);
            }
            spec_json["imageLookupFormat"] = image_lookup["format"].clone();
            spec_json["imageLookupOrg"] = image_lookup["org"].clone();
            spec_json["imageLookupBaseOS"] = image_lookup["baseOS"].clone();
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

        let public_ip = aws_config.and_then(|c| c.public_ip).unwrap_or(false);

        // Build root volume config
        let root_volume_size = aws_config.and_then(|c| c.cp_root_volume_size).unwrap_or(80);
        let mut root_volume = serde_json::json!({ "size": root_volume_size });

        if let Some(vol_type) = aws_config.and_then(|c| c.cp_root_volume_type.clone()) {
            root_volume["type"] = serde_json::json!(vol_type);
        }
        if let Some(iops) = aws_config.and_then(|c| c.cp_root_volume_iops) {
            root_volume["iops"] = serde_json::json!(iops);
        }
        if let Some(throughput) = aws_config.and_then(|c| c.cp_root_volume_throughput) {
            root_volume["throughput"] = serde_json::json!(throughput);
        }
        if let Some(encrypted) = aws_config.and_then(|c| c.cp_root_volume_encrypted) {
            root_volume["encrypted"] = serde_json::json!(encrypted);
        }

        let mut machine_spec = serde_json::json!({
            "instanceType": instance_type,
            "iamInstanceProfile": iam_instance_profile,
            "publicIP": public_ip,
            "rootVolume": root_volume
        });

        // SSH key
        if let Some(key_name) = aws_config.and_then(|c| c.ssh_key_name.clone()) {
            machine_spec["sshKeyName"] = serde_json::json!(key_name);
        }

        // AMI
        if let Some(ami_id) = aws_config.and_then(|c| c.ami_id.clone()) {
            machine_spec["ami"] = serde_json::json!({ "id": ami_id });
        }

        // Subnet (control plane specific)
        if let Some(subnet_id) = aws_config.and_then(|c| c.cp_subnet_id.clone()) {
            machine_spec["subnet"] = serde_json::json!({ "id": subnet_id });
        }

        // Additional security groups
        if let Some(sgs) = aws_config.and_then(|c| c.additional_security_groups.clone()) {
            let sg_refs: Vec<_> = sgs.iter().map(|sg| serde_json::json!({ "id": sg })).collect();
            machine_spec["additionalSecurityGroups"] = serde_json::json!(sg_refs);
        }

        // IMDS configuration
        let has_imds_config = aws_config.and_then(|c| c.imds_http_endpoint.clone()).is_some()
            || aws_config.and_then(|c| c.imds_http_tokens.clone()).is_some()
            || aws_config.and_then(|c| c.imds_http_put_response_hop_limit).is_some();

        if has_imds_config {
            let mut imds = serde_json::json!({});
            if let Some(endpoint) = aws_config.and_then(|c| c.imds_http_endpoint.clone()) {
                imds["httpEndpoint"] = serde_json::json!(endpoint);
            }
            if let Some(tokens) = aws_config.and_then(|c| c.imds_http_tokens.clone()) {
                imds["httpTokens"] = serde_json::json!(tokens);
            }
            if let Some(hop_limit) = aws_config.and_then(|c| c.imds_http_put_response_hop_limit) {
                imds["httpPutResponseHopLimit"] = serde_json::json!(hop_limit);
            }
            machine_spec["instanceMetadataOptions"] = imds;
        }

        // Placement configuration
        let has_placement = aws_config.and_then(|c| c.placement_group_name.clone()).is_some()
            || aws_config.and_then(|c| c.placement_group_partition).is_some()
            || aws_config.and_then(|c| c.tenancy.clone()).is_some();

        if has_placement {
            let mut placement = serde_json::json!({});
            if let Some(pg_name) = aws_config.and_then(|c| c.placement_group_name.clone()) {
                placement["groupName"] = serde_json::json!(pg_name);
            }
            if let Some(pg_partition) = aws_config.and_then(|c| c.placement_group_partition) {
                placement["partitionNumber"] = serde_json::json!(pg_partition);
            }
            if let Some(tenancy) = aws_config.and_then(|c| c.tenancy.clone()) {
                placement["tenancy"] = serde_json::json!(tenancy);
            }
            machine_spec["placementGroupName"] = placement.get("groupName").cloned().unwrap_or(serde_json::Value::Null);
            machine_spec["placementGroupPartition"] = placement.get("partitionNumber").cloned().unwrap_or(serde_json::Value::Null);
            machine_spec["tenancy"] = placement.get("tenancy").cloned().unwrap_or(serde_json::Value::Null);
        }

        // Capacity reservation
        if let Some(cr_id) = aws_config.and_then(|c| c.capacity_reservation_id.clone()) {
            machine_spec["capacityReservationId"] = serde_json::json!(cr_id);
        }

        // Spot/market configuration
        if let Some(market_type) = aws_config.and_then(|c| c.market_type.clone()) {
            let mut spot_config = serde_json::json!({ "marketType": market_type });
            if let Some(max_price) = aws_config.and_then(|c| c.spot_max_price.clone()) {
                spot_config["maxPrice"] = serde_json::json!(max_price);
            }
            machine_spec["spotMarketOptions"] = spot_config;
        }

        let spec_json = serde_json::json!({
            "template": {
                "spec": machine_spec
            }
        });

        Ok(CAPIManifest::new(
            AWS_API_VERSION,
            "AWSMachineTemplate",
            format!("{}-control-plane", name),
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

        let public_ip = aws_config.and_then(|c| c.public_ip).unwrap_or(false);

        // Build root volume config
        let root_volume_size = aws_config.and_then(|c| c.worker_root_volume_size).unwrap_or(80);
        let mut root_volume = serde_json::json!({ "size": root_volume_size });

        if let Some(vol_type) = aws_config.and_then(|c| c.worker_root_volume_type.clone()) {
            root_volume["type"] = serde_json::json!(vol_type);
        }
        if let Some(iops) = aws_config.and_then(|c| c.worker_root_volume_iops) {
            root_volume["iops"] = serde_json::json!(iops);
        }
        if let Some(throughput) = aws_config.and_then(|c| c.worker_root_volume_throughput) {
            root_volume["throughput"] = serde_json::json!(throughput);
        }
        if let Some(encrypted) = aws_config.and_then(|c| c.worker_root_volume_encrypted) {
            root_volume["encrypted"] = serde_json::json!(encrypted);
        }

        let mut machine_spec = serde_json::json!({
            "instanceType": instance_type,
            "iamInstanceProfile": iam_instance_profile,
            "publicIP": public_ip,
            "rootVolume": root_volume
        });

        // SSH key
        if let Some(key_name) = aws_config.and_then(|c| c.ssh_key_name.clone()) {
            machine_spec["sshKeyName"] = serde_json::json!(key_name);
        }

        // AMI
        if let Some(ami_id) = aws_config.and_then(|c| c.ami_id.clone()) {
            machine_spec["ami"] = serde_json::json!({ "id": ami_id });
        }

        // Subnet (worker specific)
        if let Some(subnet_id) = aws_config.and_then(|c| c.worker_subnet_id.clone()) {
            machine_spec["subnet"] = serde_json::json!({ "id": subnet_id });
        }

        // Additional security groups
        if let Some(sgs) = aws_config.and_then(|c| c.additional_security_groups.clone()) {
            let sg_refs: Vec<_> = sgs.iter().map(|sg| serde_json::json!({ "id": sg })).collect();
            machine_spec["additionalSecurityGroups"] = serde_json::json!(sg_refs);
        }

        // IMDS configuration
        let has_imds_config = aws_config.and_then(|c| c.imds_http_endpoint.clone()).is_some()
            || aws_config.and_then(|c| c.imds_http_tokens.clone()).is_some()
            || aws_config.and_then(|c| c.imds_http_put_response_hop_limit).is_some();

        if has_imds_config {
            let mut imds = serde_json::json!({});
            if let Some(endpoint) = aws_config.and_then(|c| c.imds_http_endpoint.clone()) {
                imds["httpEndpoint"] = serde_json::json!(endpoint);
            }
            if let Some(tokens) = aws_config.and_then(|c| c.imds_http_tokens.clone()) {
                imds["httpTokens"] = serde_json::json!(tokens);
            }
            if let Some(hop_limit) = aws_config.and_then(|c| c.imds_http_put_response_hop_limit) {
                imds["httpPutResponseHopLimit"] = serde_json::json!(hop_limit);
            }
            machine_spec["instanceMetadataOptions"] = imds;
        }

        // Placement configuration
        let has_placement = aws_config.and_then(|c| c.placement_group_name.clone()).is_some()
            || aws_config.and_then(|c| c.placement_group_partition).is_some()
            || aws_config.and_then(|c| c.tenancy.clone()).is_some();

        if has_placement {
            if let Some(pg_name) = aws_config.and_then(|c| c.placement_group_name.clone()) {
                machine_spec["placementGroupName"] = serde_json::json!(pg_name);
            }
            if let Some(pg_partition) = aws_config.and_then(|c| c.placement_group_partition) {
                machine_spec["placementGroupPartition"] = serde_json::json!(pg_partition);
            }
            if let Some(tenancy) = aws_config.and_then(|c| c.tenancy.clone()) {
                machine_spec["tenancy"] = serde_json::json!(tenancy);
            }
        }

        // Capacity reservation
        if let Some(cr_id) = aws_config.and_then(|c| c.capacity_reservation_id.clone()) {
            machine_spec["capacityReservationId"] = serde_json::json!(cr_id);
        }

        // Spot/market configuration
        if let Some(market_type) = aws_config.and_then(|c| c.market_type.clone()) {
            let mut spot_config = serde_json::json!({ "marketType": market_type });
            if let Some(max_price) = aws_config.and_then(|c| c.spot_max_price.clone()) {
                spot_config["maxPrice"] = serde_json::json!(max_price);
            }
            machine_spec["spotMarketOptions"] = spot_config;
        }

        let spec_json = serde_json::json!({
            "template": {
                "spec": machine_spec
            }
        });

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

        // Generate manifests - extract fallible operations first
        let aws_cluster = self.generate_aws_cluster(cluster)?;
        let cp_machine_template = self.generate_cp_machine_template(cluster)?;
        let worker_machine_template = self.generate_worker_machine_template(cluster)?;

        Ok(vec![
            generate_cluster(&config, &infra),              // 1. CAPI Cluster
            aws_cluster,                                    // 2. AWSCluster
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
