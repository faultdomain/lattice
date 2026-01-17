//! Infrastructure provider configurations for E2E tests
//!
//! Generates LatticeCluster YAML configs for different providers:
//! - Docker (CAPD)
//! - AWS (CAPA)
//! - OpenStack (CAPO)
//! - Proxmox

#![cfg(feature = "provider-e2e")]

use lattice_operator::crd::BootstrapProvider;

/// Supported infrastructure providers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfraProvider {
    Docker,
    Aws,
    OpenStack,
    Proxmox,
}

impl InfraProvider {
    pub fn from_env(var: &str, default: Self) -> Self {
        match std::env::var(var).as_deref() {
            Ok("aws") | Ok("AWS") => Self::Aws,
            Ok("openstack") | Ok("OPENSTACK") | Ok("ovh") | Ok("OVH") => Self::OpenStack,
            Ok("proxmox") | Ok("PROXMOX") => Self::Proxmox,
            Ok("docker") | Ok("DOCKER") => Self::Docker,
            _ => default,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Aws => "aws",
            Self::OpenStack => "openstack",
            Self::Proxmox => "proxmox",
        }
    }
}

impl std::fmt::Display for InfraProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Generate cluster config YAML for Docker provider
fn generate_docker_config(name: &str, bootstrap: &str, is_mgmt: bool) -> String {
    if is_mgmt {
        format!(
            r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: {name}
spec:
  provider:
    kubernetes:
      version: "1.32.0"
      bootstrap: {bootstrap}
      certSANs:
        - "127.0.0.1"
        - "localhost"
        - "172.18.255.10"
    config:
      docker: {{}}
  nodes:
    controlPlane: 1
    workers: 1
  networking:
    default:
      cidr: "172.18.255.10/32"
  endpoints:
    host: 172.18.255.10
    grpcPort: 50051
    bootstrapPort: 8443
    service:
      type: LoadBalancer
"#
        )
    } else {
        format!(
            r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: {name}
spec:
  provider:
    kubernetes:
      version: "1.32.0"
      bootstrap: {bootstrap}
      certSANs:
        - "127.0.0.1"
        - "localhost"
    config:
      docker: {{}}
  nodes:
    controlPlane: 1
    workers: 2
  environment: e2e-test
  region: local
"#
        )
    }
}

/// Generate cluster config YAML for AWS provider
fn generate_aws_config(name: &str, bootstrap: &str, is_mgmt: bool) -> String {
    let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string());
    let ssh_key = std::env::var("AWS_SSH_KEY_NAME").ok();
    let vpc_id = std::env::var("AWS_VPC_ID").ok();
    let ami_id = std::env::var("AWS_AMI_ID").ok();

    let mut aws_section = format!(
        r#"      region: "{region}"
      cpInstanceType: "t3.large"
      workerInstanceType: "t3.large"
      cpRootVolumeSize: 50
      workerRootVolumeSize: 50
      publicIp: true"#
    );

    if let Some(key) = ssh_key {
        aws_section.push_str(&format!("\n      sshKeyName: \"{key}\""));
    }
    if let Some(vpc) = vpc_id {
        aws_section.push_str(&format!("\n      vpcId: \"{vpc}\""));
    }
    if let Some(ami) = ami_id {
        aws_section.push_str(&format!("\n      amiId: \"{ami}\""));
    }

    let workers = if is_mgmt { 1 } else { 2 };

    format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: {name}
spec:
  provider:
    kubernetes:
      version: "1.32.0"
      bootstrap: {bootstrap}
      certSANs:
        - "127.0.0.1"
        - "localhost"
    config:
      aws:
{aws_section}
  nodes:
    controlPlane: 1
    workers: {workers}
  environment: e2e-test
  region: {region}
"#
    )
}

/// Generate cluster config YAML for OpenStack provider
fn generate_openstack_config(name: &str, bootstrap: &str, is_mgmt: bool) -> String {
    let cloud_name = std::env::var("OS_CLOUD_NAME").unwrap_or_else(|_| "openstack".to_string());
    let external_network =
        std::env::var("OS_EXTERNAL_NETWORK").unwrap_or_else(|_| "Ext-Net".to_string());
    let image_name = std::env::var("OS_IMAGE_NAME").unwrap_or_else(|_| "Ubuntu 22.04".to_string());
    let cp_flavor = std::env::var("OS_CP_FLAVOR").unwrap_or_else(|_| "m1.large".to_string());
    let worker_flavor =
        std::env::var("OS_WORKER_FLAVOR").unwrap_or_else(|_| "m1.large".to_string());
    let ssh_key = std::env::var("OS_SSH_KEY_NAME").ok();

    let mut openstack_section = format!(
        r#"      cloudName: "{cloud_name}"
      externalNetwork: "{external_network}"
      imageName: "{image_name}"
      cpFlavor: "{cp_flavor}"
      workerFlavor: "{worker_flavor}""#
    );

    if let Some(key) = ssh_key {
        openstack_section.push_str(&format!("\n      sshKeyName: \"{key}\""));
    }

    let workers = if is_mgmt { 1 } else { 2 };

    format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: {name}
spec:
  provider:
    kubernetes:
      version: "1.32.0"
      bootstrap: {bootstrap}
      certSANs:
        - "127.0.0.1"
        - "localhost"
    config:
      openstack:
{openstack_section}
  nodes:
    controlPlane: 1
    workers: {workers}
  environment: e2e-test
  region: openstack
"#
    )
}

/// Generate cluster config YAML for Proxmox provider
///
/// Required environment variables:
/// - PROXMOX_NODE: Proxmox node name (e.g., "pve")
/// - PROXMOX_TEMPLATE_ID: VM template ID (e.g., "9000")
/// - PROXMOX_VIP: Virtual IP for kube-vip (e.g., "10.0.0.100") - NOT in IP pool
/// - PROXMOX_IP_POOL: Comma-separated IPs for VMs (e.g., "10.0.0.101,10.0.0.102,10.0.0.103")
/// - PROXMOX_GATEWAY: Gateway IP (e.g., "10.0.0.1")
///
/// Optional:
/// - PROXMOX_STORAGE: Storage backend (default: "local-lvm")
/// - PROXMOX_BRIDGE: Network bridge (default: "vmbr0")
/// - PROXMOX_DNS: DNS servers (default: gateway IP)
/// - PROXMOX_SSH_KEY: SSH public key for node access
fn generate_proxmox_config(name: &str, bootstrap: &str, is_mgmt: bool) -> String {
    let node = std::env::var("PROXMOX_NODE").expect("PROXMOX_NODE required for proxmox provider");
    let template_id: u32 = std::env::var("PROXMOX_TEMPLATE_ID")
        .expect("PROXMOX_TEMPLATE_ID required")
        .parse()
        .expect("PROXMOX_TEMPLATE_ID must be a number");
    let ip_pool =
        std::env::var("PROXMOX_IP_POOL").expect("PROXMOX_IP_POOL required (comma-separated IPs)");
    let gateway = std::env::var("PROXMOX_GATEWAY").expect("PROXMOX_GATEWAY required");

    // VIP is separate from IP pool - kube-vip manages it
    let vip = std::env::var("PROXMOX_VIP").expect(
        "PROXMOX_VIP required (virtual IP for kube-vip, must NOT be in PROXMOX_IP_POOL)"
    );

    let storage = std::env::var("PROXMOX_STORAGE").unwrap_or_else(|_| "local-lvm".to_string());
    let bridge = std::env::var("PROXMOX_BRIDGE").unwrap_or_else(|_| "vmbr0".to_string());
    let dns = std::env::var("PROXMOX_DNS").unwrap_or_else(|_| gateway.clone());
    let ssh_key = std::env::var("PROXMOX_SSH_KEY").ok();
    let vip_interface = std::env::var("PROXMOX_VIP_INTERFACE").unwrap_or_else(|_| "eth0".to_string());

    // Parse IP pool (these are for VMs, NOT including VIP)
    let ips: Vec<&str> = ip_pool.split(',').map(|s| s.trim()).collect();
    let ip_yaml: String = ips
        .iter()
        .map(|ip| format!("          - \"{}\"", ip))
        .collect::<Vec<_>>()
        .join("\n");

    let workers = if is_mgmt { 1 } else { 2 };

    let ssh_keys_yaml = ssh_key
        .map(|k| format!("\n        sshAuthorizedKeys:\n          - \"{}\"", k))
        .unwrap_or_default();

    let endpoints_section = if is_mgmt {
        format!(
            r#"  endpoints:
    host: {vip}
    grpcPort: 50051
    bootstrapPort: 8443
    service:
      type: LoadBalancer"#
        )
    } else {
        String::new()
    };

    format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: {name}
spec:
  provider:
    kubernetes:
      version: "1.32.0"
      bootstrap: {bootstrap}
      certSANs:
        - "127.0.0.1"
        - "localhost"
        - "{vip}"
    config:
      proxmox:
        sourceNode: "{node}"
        templateId: {template_id}
        storage: "{storage}"
        bridge: "{bridge}"
        ipv4Addresses:
{ip_yaml}
        ipv4Prefix: 24
        ipv4Gateway: "{gateway}"
        dnsServers:
          - "{dns}"
        virtualIpNetworkInterface: "{vip_interface}"{ssh_keys_yaml}
        cpCores: 16
        cpMemoryMib: 32768
        cpDiskSizeGb: 50
        workerCores: 16
        workerMemoryMib: 32768
        workerDiskSizeGb: 100
  nodes:
    controlPlane: 1
    workers: {workers}
  environment: e2e-test
  region: proxmox
{endpoints_section}
"#
    )
}

/// Generate cluster config based on provider
pub fn generate_cluster_config(
    name: &str,
    provider: InfraProvider,
    bootstrap: BootstrapProvider,
    is_mgmt: bool,
) -> String {
    let bootstrap_str = match bootstrap {
        BootstrapProvider::Kubeadm => "kubeadm",
        BootstrapProvider::Rke2 => "rke2",
    };

    match provider {
        InfraProvider::Docker => generate_docker_config(name, bootstrap_str, is_mgmt),
        InfraProvider::Aws => generate_aws_config(name, bootstrap_str, is_mgmt),
        InfraProvider::OpenStack => generate_openstack_config(name, bootstrap_str, is_mgmt),
        InfraProvider::Proxmox => generate_proxmox_config(name, bootstrap_str, is_mgmt),
    }
}
