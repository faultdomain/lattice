//! AWS end-to-end test for Lattice cluster provisioning
//!
//! This test provisions a real AWS cluster using CAPA (Cluster API Provider AWS)
//! via the Lattice Installer, verifies it reaches Ready state, then tears it down.
//!
//! # Prerequisites
//!
//! 1. AWS credentials configured (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
//! 2. Run `clusterawsadm bootstrap iam create-cloudformation-stack` to create IAM resources
//!
//! # Environment Variables
//!
//! - AWS_REGION: AWS region (default: us-west-2)
//! - AWS_SSH_KEY_NAME: EC2 key pair name (optional, no SSH access if not set)
//! - AWS_VPC_ID: VPC ID (optional, uses default VPC if not set)
//! - AWS_AMI_ID: Custom AMI ID (optional, CAPA uses default if not set)
//!
//! # Running
//!
//! ```bash
//! # Set up IAM (one-time)
//! clusterawsadm bootstrap iam create-cloudformation-stack
//!
//! # Run the test
//! cargo test --features aws-e2e --test kind aws_e2e -- --nocapture
//! ```

#![cfg(feature = "aws-e2e")]

use std::process::Command as ProcessCommand;
use std::time::Duration;

use lattice_operator::install::{InstallConfig, Installer};

// =============================================================================
// Test Configuration
// =============================================================================

/// Name of the test cluster
const TEST_CLUSTER_NAME: &str = "aws-e2e-test";

/// Docker image for lattice operator
const LATTICE_IMAGE: &str = "ghcr.io/evan-hines-js/lattice:latest";

// =============================================================================
// Helper Functions
// =============================================================================

/// Run a shell command and return output
fn run_cmd(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = ProcessCommand::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run {}: {}", cmd, e))?;

    if !output.status.success() {
        return Err(format!(
            "{} failed: {}",
            cmd,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Generate the LatticeCluster YAML for AWS
fn generate_aws_cluster_config() -> String {
    let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string());
    let ssh_key_name = std::env::var("AWS_SSH_KEY_NAME").ok();
    let vpc_id = std::env::var("AWS_VPC_ID").ok();
    let ami_id = std::env::var("AWS_AMI_ID").ok();

    let mut aws_config = format!(
        r#"    aws:
      region: "{region}"
      cpInstanceType: "t3.large"
      workerInstanceType: "t3.large"
      cpRootVolumeSize: 50
      workerRootVolumeSize: 50
      publicIp: true"#
    );

    if let Some(key) = ssh_key_name {
        aws_config.push_str(&format!("\n      sshKeyName: \"{key}\""));
    }
    if let Some(vpc) = vpc_id {
        aws_config.push_str(&format!("\n      vpcId: \"{vpc}\""));
    }
    if let Some(ami) = ami_id {
        aws_config.push_str(&format!("\n      amiId: \"{ami}\""));
    }

    format!(
        r#"apiVersion: lattice.io/v1alpha1
kind: LatticeCluster
metadata:
  name: {TEST_CLUSTER_NAME}
spec:
  provider:
    kubernetes:
      version: "1.31.0"
      bootstrap: kubeadm
    config:
{aws_config}
  nodes:
    controlPlane: 1
    workers: 0
  environment: aws-e2e-test
  region: {region}
"#
    )
}

/// Cleanup function to delete bootstrap cluster
fn cleanup_bootstrap_cluster() {
    println!("\n[Cleanup] Deleting bootstrap cluster...");
    let _ = run_cmd(
        "kind",
        &[
            "delete",
            "cluster",
            "--name",
            &format!("{}-bootstrap", TEST_CLUSTER_NAME),
        ],
    );
}

// =============================================================================
// Test Implementation
// =============================================================================

/// Main AWS e2e test
///
/// This test:
/// 1. Uses the Lattice Installer to create bootstrap cluster
/// 2. Installs CAPI with AWS provider
/// 3. Provisions an AWS cluster
/// 4. Waits for Ready state
/// 5. Cleans up
#[tokio::test]
async fn test_aws_cluster_lifecycle() {
    println!("\n========================================");
    println!("AWS E2E Test: Cluster Lifecycle");
    println!("========================================\n");

    let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string());
    let ssh_key = std::env::var("AWS_SSH_KEY_NAME").unwrap_or_else(|_| "(none)".to_string());
    println!(
        "AWS Configuration:\n  Region: {}\n  SSH Key: {}",
        region, ssh_key
    );

    // Generate cluster config
    let cluster_config = generate_aws_cluster_config();
    println!("\nCluster config:\n{}", cluster_config);

    // Write config to temp file
    let config_path = std::env::temp_dir().join("aws-e2e-cluster.yaml");
    std::fs::write(&config_path, &cluster_config).expect("Failed to write cluster config");

    // Create installer config
    let install_config = InstallConfig {
        cluster_config_path: config_path.clone(),
        cluster_config_content: cluster_config,
        image: LATTICE_IMAGE.to_string(),
        keep_bootstrap_on_failure: true,
        timeout: Duration::from_secs(2400), // 40 minutes for AWS
        registry_credentials: None,
        bootstrap_override: None,
    };

    // Run installer
    println!("\n[1/2] Running Lattice Installer...");
    let installer = match Installer::new(install_config) {
        Ok(i) => i,
        Err(e) => {
            cleanup_bootstrap_cluster();
            panic!("Failed to create installer: {}", e);
        }
    };

    match installer.run().await {
        Ok(_) => {
            println!("\n[2/2] Installer completed successfully!");
        }
        Err(e) => {
            println!("\nInstaller failed: {}", e);
            cleanup_bootstrap_cluster();
            panic!("Installer failed: {}", e);
        }
    }

    // Cleanup
    cleanup_bootstrap_cluster();

    println!("\n========================================");
    println!("AWS E2E Test: PASSED");
    println!("========================================\n");
}

/// Test that verifies AWS manifest generation without provisioning
#[tokio::test]
async fn test_aws_manifest_generation() {
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use lattice_operator::crd::{
        AwsConfig, BootstrapProvider, KubernetesSpec, LatticeCluster, LatticeClusterSpec, NodeSpec,
        ProviderConfig, ProviderSpec,
    };
    use lattice_operator::provider::{AwsProvider, BootstrapInfo, Provider};

    println!("\n========================================");
    println!("AWS Manifest Generation Test");
    println!("========================================\n");

    let aws_config = AwsConfig {
        region: Some("us-west-2".to_string()),
        ssh_key_name: Some("test-key".to_string()),
        vpc_id: Some("vpc-12345".to_string()),
        ami_id: None,
        cp_instance_type: Some("t3.large".to_string()),
        worker_instance_type: Some("t3.medium".to_string()),
        cp_iam_instance_profile: None,
        worker_iam_instance_profile: None,
        subnet_ids: None,
        cp_root_volume_size: Some(100),
        worker_root_volume_size: Some(50),
        public_ip: Some(false),
    };

    let cluster = LatticeCluster {
        metadata: ObjectMeta {
            name: Some("manifest-test".to_string()),
            namespace: Some("default".to_string()),
            ..Default::default()
        },
        spec: LatticeClusterSpec {
            provider: ProviderSpec {
                kubernetes: KubernetesSpec {
                    version: "1.31.0".to_string(),
                    cert_sans: Some(vec!["api.example.com".to_string()]),
                    bootstrap: BootstrapProvider::Kubeadm,
                },
                config: ProviderConfig::aws(aws_config),
            },
            nodes: NodeSpec {
                control_plane: 3,
                workers: 5,
            },
            networking: None,
            endpoints: None,
            environment: None,
            region: None,
            workload: None,
        },
        status: None,
    };

    let provider = AwsProvider::with_namespace("capi-system");
    let bootstrap = BootstrapInfo::default();

    let manifests = provider
        .generate_capi_manifests(&cluster, &bootstrap)
        .await
        .expect("Failed to generate manifests");

    println!("Generated {} manifests:", manifests.len());
    for manifest in &manifests {
        println!("  - {} ({})", manifest.kind, manifest.metadata.name);
    }

    // Verify all expected manifests are present
    assert_eq!(manifests.len(), 7);

    let kinds: Vec<&str> = manifests.iter().map(|m| m.kind.as_str()).collect();
    assert!(kinds.contains(&"Cluster"), "Missing Cluster manifest");
    assert!(kinds.contains(&"AWSCluster"), "Missing AWSCluster manifest");
    assert!(
        kinds.contains(&"KubeadmControlPlane"),
        "Missing KubeadmControlPlane manifest"
    );
    assert!(
        kinds.contains(&"AWSMachineTemplate"),
        "Missing AWSMachineTemplate manifest"
    );
    assert!(
        kinds.contains(&"MachineDeployment"),
        "Missing MachineDeployment manifest"
    );
    assert!(
        kinds.contains(&"KubeadmConfigTemplate"),
        "Missing KubeadmConfigTemplate manifest"
    );

    // Verify AWSCluster has correct region
    let aws_cluster = manifests.iter().find(|m| m.kind == "AWSCluster").unwrap();
    let region = aws_cluster
        .spec
        .as_ref()
        .unwrap()
        .get("region")
        .and_then(|v| v.as_str())
        .unwrap();
    assert_eq!(region, "us-west-2");

    // Verify VPC is set
    let vpc_id = aws_cluster
        .spec
        .as_ref()
        .unwrap()
        .pointer("/network/vpc/id")
        .and_then(|v| v.as_str())
        .unwrap();
    assert_eq!(vpc_id, "vpc-12345");

    println!("\nManifest generation test PASSED");
}
