//! Install command - Bootstrap a new Lattice management cluster
//!
//! This command creates a new Lattice installation by:
//! 1. Reading cluster config from a git repository or local path
//! 2. Creating a temporary kind bootstrap cluster
//! 3. Installing CAPI providers and Lattice operator
//! 4. Provisioning the management cluster
//! 5. Pivoting CAPI resources to make it self-managing
//! 6. Optionally installing Flux for GitOps

use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use clap::Args;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing::{info, warn};

use lattice_operator::bootstrap::{
    generate_all_manifests, DefaultManifestGenerator, ManifestConfig, ManifestGenerator,
};
use lattice_operator::crd::{BootstrapProvider, LatticeCluster, ProviderType};
use lattice_operator::fips;

use crate::{git, Error, Result};

/// Install Lattice from a git repository or local path
#[derive(Args, Debug)]
pub struct InstallArgs {
    /// Path to LatticeCluster YAML config file
    #[arg(short = 'f', long = "config")]
    pub config_file: Option<PathBuf>,

    /// Git repository URL containing cluster definitions
    #[arg(long)]
    pub git_repo: Option<String>,

    /// Git branch to use
    #[arg(long, default_value = "main")]
    pub git_branch: String,

    /// Path to existing local repository (alternative to --git-repo)
    #[arg(long)]
    pub local_path: Option<PathBuf>,

    /// Path to git credentials (SSH key or token file)
    #[arg(long)]
    pub git_credentials: Option<PathBuf>,

    /// Lattice container image
    #[arg(
        long,
        env = "LATTICE_IMAGE",
        default_value = "ghcr.io/evan-hines-js/lattice:latest"
    )]
    pub image: String,

    /// Path to registry credentials file (dockerconfigjson format)
    #[arg(long, env = "REGISTRY_CREDENTIALS_FILE")]
    pub registry_credentials_file: Option<PathBuf>,

    /// Skip kind cluster deletion on failure (for debugging)
    #[arg(long)]
    pub keep_bootstrap_on_failure: bool,

    /// Timeout for the entire installation in seconds
    #[arg(long, default_value = "1200")]
    pub timeout_secs: u64,

    /// Kubernetes bootstrap provider (overrides config file if set)
    #[arg(long, value_parser = parse_bootstrap_provider)]
    pub bootstrap: Option<BootstrapProvider>,

    /// Dry run - show what would be done without making changes
    #[arg(long)]
    pub dry_run: bool,
}

fn parse_bootstrap_provider(s: &str) -> std::result::Result<BootstrapProvider, String> {
    match s.to_lowercase().as_str() {
        "rke2" => Ok(BootstrapProvider::Rke2),
        "kubeadm" => Ok(BootstrapProvider::Kubeadm),
        _ => Err(format!(
            "invalid bootstrap provider '{}', must be 'rke2' or 'kubeadm'",
            s
        )),
    }
}

/// Configuration for the installer
#[derive(Debug, Clone)]
pub struct InstallConfig {
    /// Path to the LatticeCluster YAML configuration file
    pub cluster_config_path: PathBuf,
    /// Raw YAML content of the cluster configuration
    pub cluster_config_content: String,
    /// Lattice container image
    pub image: String,
    /// Keep bootstrap cluster on failure
    pub keep_bootstrap_on_failure: bool,
    /// Installation timeout
    pub timeout: Duration,
    /// Optional registry credentials (dockerconfigjson format)
    pub registry_credentials: Option<String>,
    /// Optional bootstrap provider override
    pub bootstrap_override: Option<BootstrapProvider>,
}

/// The Lattice installer
pub struct Installer {
    config: InstallConfig,
    cluster: LatticeCluster,
    cluster_name: String,
}

/// Fixed bootstrap cluster name - concurrent installs are not supported
const BOOTSTRAP_CLUSTER_NAME: &str = "lattice-bootstrap";

impl Installer {
    /// Create a new installer with the given configuration
    pub fn new(config: InstallConfig) -> Result<Self> {
        let mut cluster: LatticeCluster =
            serde_yaml::from_str(&config.cluster_config_content).map_err(Error::Yaml)?;

        // Apply bootstrap override if provided
        if let Some(bootstrap) = &config.bootstrap_override {
            cluster.spec.provider.kubernetes.bootstrap = bootstrap.clone();
        }

        let cluster_name = cluster
            .metadata
            .name
            .clone()
            .ok_or_else(|| Error::validation("LatticeCluster must have metadata.name"))?;

        Ok(Self {
            config,
            cluster,
            cluster_name,
        })
    }

    fn cluster_name(&self) -> &str {
        &self.cluster_name
    }

    /// Get the path to the bootstrap cluster's kubeconfig file.
    /// Using a dedicated file avoids polluting the user's default kubeconfig.
    fn bootstrap_kubeconfig_path(&self) -> String {
        format!("/tmp/{}-kubeconfig", BOOTSTRAP_CLUSTER_NAME)
    }

    fn provider(&self) -> ProviderType {
        self.cluster.spec.provider.provider_type()
    }

    /// Get clusterctl init arguments based on configured providers
    fn clusterctl_init_args(&self) -> Vec<String> {
        let infra_arg = match self.provider() {
            ProviderType::Docker => "--infrastructure=docker",
            ProviderType::Proxmox => "--infrastructure=proxmox",
            ProviderType::OpenStack => "--infrastructure=openstack",
            ProviderType::Aws => "--infrastructure=aws",
            ProviderType::Gcp => "--infrastructure=gcp",
            ProviderType::Azure => "--infrastructure=azure",
        };

        let config_path = env!("CLUSTERCTL_CONFIG");

        let mut args = vec![
            "init".to_string(),
            infra_arg.to_string(),
            "--bootstrap=kubeadm,rke2".to_string(),
            "--control-plane=kubeadm,rke2".to_string(),
            format!("--config={}", config_path),
            "--wait-providers".to_string(),
        ];

        // Proxmox requires the in-cluster IPAM provider for IP address management
        if self.provider() == ProviderType::Proxmox {
            args.push("--ipam=in-cluster".to_string());
        }

        args
    }

    /// Run the installation
    pub async fn run(&self) -> Result<()> {
        let start = Instant::now();

        self.check_prerequisites().await?;

        let bootstrap_result = self.run_bootstrap().await;

        if bootstrap_result.is_err() && !self.config.keep_bootstrap_on_failure {
            info!("Deleting bootstrap cluster due to failure...");
            let _ = self.delete_kind_cluster().await;
        }

        bootstrap_result?;

        info!("Installation complete in {:?}", start.elapsed());
        info!(
            "Management cluster '{}' is now self-managing.",
            self.cluster_name()
        );

        Ok(())
    }

    async fn check_prerequisites(&self) -> Result<()> {
        info!("Checking prerequisites...");

        let tools = [
            ("docker", "Install Docker: https://docs.docker.com/get-docker/"),
            ("kind", "Install kind: https://kind.sigs.k8s.io/docs/user/quick-start/#installation"),
            ("kubectl", "Install kubectl: https://kubernetes.io/docs/tasks/tools/"),
            ("clusterctl", "Install clusterctl: https://cluster-api.sigs.k8s.io/user/quick-start#install-clusterctl"),
        ];

        for (tool, hint) in tools {
            if !self.check_tool(tool).await? {
                return Err(Error::command_failed(format!(
                    "{} not found. {}",
                    tool, hint
                )));
            }
        }

        Ok(())
    }

    async fn check_tool(&self, tool: &str) -> Result<bool> {
        let result = Command::new("which").arg(tool).output().await?;
        Ok(result.status.success())
    }

    async fn run_bootstrap(&self) -> Result<()> {
        info!("[Phase 1] Creating kind bootstrap cluster...");
        self.create_kind_cluster().await?;

        // Create provider credentials BEFORE deploying operator
        // The operator reads these during CAPI installation
        if self.provider() == ProviderType::Proxmox {
            info!("[Phase 1.5] Creating Proxmox credentials...");
            self.create_capmox_credentials(Some(&self.bootstrap_kubeconfig_path()))
                .await?;
        }

        info!("[Phase 2] Deploying Lattice operator...");
        self.deploy_lattice_operator().await?;

        info!("[Phase 3] Creating management cluster LatticeCluster CR...");
        self.create_management_cluster_crd().await?;

        info!("[Phase 4] Waiting for management cluster to be provisioned...");
        self.wait_for_management_cluster().await?;

        info!("[Phase 5] Applying bootstrap manifests to management cluster...");
        self.apply_bootstrap_to_management().await?;

        info!("[Phase 6] Pivoting CAPI resources to management cluster...");
        self.pivot_capi_resources().await?;

        info!("[Phase 7] Deleting bootstrap cluster...");
        self.delete_kind_cluster().await?;

        Ok(())
    }

    async fn create_kind_cluster(&self) -> Result<()> {
        let kind_config = r#"kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: /var/run/docker.sock
    containerPath: /var/run/docker.sock
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        tls-cipher-suites: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
"#;

        info!("Creating bootstrap cluster: {}", BOOTSTRAP_CLUSTER_NAME);

        let mut child = Command::new("kind")
            .args([
                "create",
                "cluster",
                "--name",
                BOOTSTRAP_CLUSTER_NAME,
                "--config",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin.write_all(kind_config.as_bytes()).await?;
        }

        let output = child.wait_with_output().await?;
        if !output.status.success() {
            return Err(Error::command_failed(format!(
                "kind create cluster failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        // Export kubeconfig to a dedicated file for this bootstrap cluster.
        // This avoids race conditions when multiple installs run concurrently.
        let bootstrap_kubeconfig = self.bootstrap_kubeconfig_path();
        let export_output = Command::new("kind")
            .args([
                "export",
                "kubeconfig",
                "--name",
                BOOTSTRAP_CLUSTER_NAME,
                "--kubeconfig",
                &bootstrap_kubeconfig,
            ])
            .output()
            .await?;

        if !export_output.status.success() {
            return Err(Error::command_failed(format!(
                "kind export kubeconfig failed: {}",
                String::from_utf8_lossy(&export_output.stderr)
            )));
        }

        self.run_command_with_kubeconfig(
            "kubectl",
            &[
                "wait",
                "--for=condition=Ready",
                "nodes",
                "--all",
                "--timeout=120s",
            ],
            &bootstrap_kubeconfig,
        )
        .await?;

        Ok(())
    }

    async fn delete_kind_cluster(&self) -> Result<()> {
        self.run_command(
            "kind",
            &["delete", "cluster", "--name", BOOTSTRAP_CLUSTER_NAME],
        )
        .await?;
        Ok(())
    }

    async fn deploy_lattice_operator(&self) -> Result<()> {
        let generator = DefaultManifestGenerator::new();
        let all_manifests = generator.generate(
            &self.config.image,
            self.config.registry_credentials.as_deref(),
            Some("lattice-installer"),
            None,
            None,
        );

        let provider_str = self.provider().to_string();
        let operator_manifests: Vec<String> = all_manifests
            .iter()
            .filter(|m: &&String| m.starts_with("{"))
            .map(|s| {
                if fips::is_deployment(s) {
                    let with_fips = fips::add_fips_relax_env(s);
                    let with_root = fips::add_root_install_env(&with_fips);
                    add_bootstrap_env(&with_root, &provider_str)
                } else {
                    s.to_string()
                }
            })
            .collect();

        let bootstrap_kubeconfig = self.bootstrap_kubeconfig_path();
        for manifest in &operator_manifests {
            self.kubectl_apply(manifest, Some(&bootstrap_kubeconfig))
                .await?;
        }

        // Wait for operator deployment to be ready
        info!("  Waiting for Lattice operator to be ready...");
        self.run_command_with_kubeconfig(
            "kubectl",
            &[
                "wait",
                "--for=condition=Available",
                "deployment/lattice-operator",
                "-n",
                "lattice-system",
                "--timeout=300s",
            ],
            &bootstrap_kubeconfig,
        )
        .await?;

        // Wait for CAPI CRDs to be available (operator installs CAPI on startup)
        info!("  Waiting for CAPI to be installed...");
        self.wait_for_capi_crds().await?;

        Ok(())
    }

    async fn wait_for_capi_crds(&self) -> Result<()> {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(300);
        let bootstrap_kubeconfig = self.bootstrap_kubeconfig_path();

        let required_crds = [
            "clusters.cluster.x-k8s.io",
            "machines.cluster.x-k8s.io",
            "clusterresourcesets.addons.cluster.x-k8s.io",
        ];

        for crd in required_crds {
            loop {
                if start.elapsed() > timeout {
                    return Err(Error::command_failed(format!(
                        "Timeout waiting for CRD: {}",
                        crd
                    )));
                }

                let result = self
                    .run_command_with_kubeconfig("kubectl", &["get", "crd", crd], &bootstrap_kubeconfig)
                    .await;

                if result.is_ok() {
                    info!("  CRD ready: {}", crd);
                    break;
                }

                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }

        Ok(())
    }

    async fn create_bootstrap_crs(&self) -> Result<()> {
        let generator = DefaultManifestGenerator::new();
        let cluster_name = self.cluster.metadata.name.as_deref();
        let provider_str = self.cluster.spec.provider.provider_type().to_string();
        let bootstrap_str = self.cluster.spec.provider.kubernetes.bootstrap.to_string();

        let config = ManifestConfig {
            image: &self.config.image,
            registry_credentials: self.config.registry_credentials.as_deref(),
            networking: self.cluster.spec.networking.as_ref(),
            cluster_name,
            provider: Some(&provider_str),
            bootstrap: Some(&bootstrap_str),
            parent_host: None,
            parent_grpc_port: lattice_operator::DEFAULT_GRPC_PORT,
            relax_fips: self
                .cluster
                .spec
                .provider
                .kubernetes
                .bootstrap
                .needs_fips_relax(),
        };

        let all_manifests = generate_all_manifests(&generator, &config);

        let yaml_manifests: Vec<&str> = all_manifests
            .iter()
            .filter(|m| m.starts_with("---") || m.starts_with("apiVersion:"))
            .map(|s| s.as_str())
            .collect();

        let operator_manifests: Vec<&str> = all_manifests
            .iter()
            .filter(|m| m.starts_with("{"))
            .map(|s| s.as_str())
            .collect();

        let cilium_yaml = yaml_manifests.join("\n---\n");
        let namespace = format!("capi-{}", self.cluster_name());

        let cilium_configmap = format!(
            r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: cilium-cni
  namespace: {namespace}
data:
  cilium.yaml: |
{cilium_data}
"#,
            namespace = namespace,
            cilium_data = cilium_yaml
                .lines()
                .map(|l| format!("    {}", l))
                .collect::<Vec<_>>()
                .join("\n")
        );

        let mut operator_data_keys = String::new();
        for (i, manifest) in operator_manifests.iter().enumerate() {
            let key_name = format!("{:02}-manifest.json", i + 1);
            let indented = manifest
                .lines()
                .map(|l| format!("    {}", l))
                .collect::<Vec<_>>()
                .join("\n");
            operator_data_keys.push_str(&format!("  {}: |\n{}\n", key_name, indented));
        }

        let operator_configmap = format!(
            r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: lattice-operator
  namespace: {namespace}
data:
{operator_data}
"#,
            namespace = namespace,
            operator_data = operator_data_keys.trim_end()
        );

        let crs = format!(
            r#"apiVersion: addons.cluster.x-k8s.io/v1beta1
kind: ClusterResourceSet
metadata:
  name: {cluster_name}-bootstrap
  namespace: {namespace}
spec:
  strategy: ApplyOnce
  clusterSelector:
    matchLabels:
      cluster.x-k8s.io/cluster-name: {cluster_name}
  resources:
    - kind: ConfigMap
      name: cilium-cni
    - kind: ConfigMap
      name: lattice-operator
"#,
            namespace = namespace,
            cluster_name = self.cluster_name()
        );

        let bootstrap_kubeconfig = self.bootstrap_kubeconfig_path();
        let _ = self
            .run_command_with_kubeconfig(
                "kubectl",
                &["create", "namespace", &namespace],
                &bootstrap_kubeconfig,
            )
            .await;

        self.kubectl_apply(&cilium_configmap, Some(&bootstrap_kubeconfig))
            .await?;
        self.kubectl_apply(&operator_configmap, Some(&bootstrap_kubeconfig))
            .await?;
        self.kubectl_apply_with_retry(&crs, Some(&bootstrap_kubeconfig), Duration::from_secs(120))
            .await?;

        Ok(())
    }

    async fn create_management_cluster_crd(&self) -> Result<()> {
        let bootstrap_kubeconfig = self.bootstrap_kubeconfig_path();

        self.kubectl_apply_with_retry(
            &self.config.cluster_config_content,
            Some(&bootstrap_kubeconfig),
            Duration::from_secs(120),
        )
        .await?;
        self.create_bootstrap_crs().await?;
        Ok(())
    }

    async fn wait_for_management_cluster(&self) -> Result<()> {
        let start = Instant::now();
        let timeout = Duration::from_secs(600);
        let bootstrap_kubeconfig = self.bootstrap_kubeconfig_path();

        loop {
            if start.elapsed() > timeout {
                return Err(Error::command_failed("Timeout waiting for cluster"));
            }

            let output = self
                .run_command_with_kubeconfig(
                    "kubectl",
                    &[
                        "get",
                        "latticecluster",
                        self.cluster_name(),
                        "-o",
                        "jsonpath={.status.phase}",
                    ],
                    &bootstrap_kubeconfig,
                )
                .await
                .unwrap_or_default();

            let phase = output.trim();
            info!(
                "Cluster phase: {}",
                if phase.is_empty() { "Pending" } else { phase }
            );

            match phase {
                "Ready" | "Pivoting" => break,
                "Failed" => return Err(Error::command_failed("Cluster provisioning failed")),
                _ => tokio::time::sleep(Duration::from_secs(10)).await,
            }
        }

        let namespace = format!("capi-{}", self.cluster_name());
        let secret_name = format!("{}-kubeconfig", self.cluster_name());

        loop {
            if start.elapsed() > timeout {
                return Err(Error::command_failed(
                    "Timeout waiting for kubeconfig secret",
                ));
            }

            if self
                .run_command_with_kubeconfig(
                    "kubectl",
                    &["get", "secret", &secret_name, "-n", &namespace],
                    &bootstrap_kubeconfig,
                )
                .await
                .is_ok()
            {
                break;
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        Ok(())
    }

    async fn apply_bootstrap_to_management(&self) -> Result<()> {
        let namespace = format!("capi-{}", self.cluster_name());
        let secret_name = format!("{}-kubeconfig", self.cluster_name());
        let bootstrap_kubeconfig = self.bootstrap_kubeconfig_path();

        let kubeconfig_b64 = self
            .run_command_with_kubeconfig(
                "kubectl",
                &[
                    "get",
                    "secret",
                    &secret_name,
                    "-n",
                    &namespace,
                    "-o",
                    "jsonpath={.data.value}",
                ],
                &bootstrap_kubeconfig,
            )
            .await?;

        let kubeconfig_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            kubeconfig_b64.trim(),
        )
        .map_err(|e| Error::command_failed(format!("Failed to decode kubeconfig: {}", e)))?;

        let mut kubeconfig = String::from_utf8(kubeconfig_bytes)
            .map_err(|e| Error::command_failed(format!("Invalid kubeconfig encoding: {}", e)))?;

        // Rewrite Docker provider kubeconfig to use localhost
        if self.cluster.spec.provider.provider_type() == ProviderType::Docker {
            let lb_container = format!("{}-lb", self.cluster_name());
            if let Ok(port_output) = self
                .run_command("docker", &["port", &lb_container, "6443"])
                .await
            {
                if let Some(port) = port_output.trim().split(':').next_back() {
                    let localhost_url = format!("https://127.0.0.1:{}", port);
                    if let Some(start) = kubeconfig.find("server: https://") {
                        if let Some(end) = kubeconfig[start..].find('\n') {
                            let old_server = &kubeconfig[start..start + end];
                            kubeconfig = kubeconfig
                                .replace(old_server, &format!("server: {}", localhost_url));
                        }
                    }
                }
            }
        }

        let kubeconfig_path = format!("/tmp/{}-kubeconfig", self.cluster_name());
        tokio::fs::write(&kubeconfig_path, &kubeconfig).await?;

        // Wait for API server
        let start = Instant::now();
        loop {
            if start.elapsed() > Duration::from_secs(300) {
                return Err(Error::command_failed("Timeout waiting for API server"));
            }

            let result = Command::new("kubectl")
                .args(["--kubeconfig", &kubeconfig_path, "get", "nodes"])
                .output()
                .await?;

            if result.status.success() {
                break;
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        // Wait for nodes to be ready
        self.run_command_with_kubeconfig(
            "kubectl",
            &[
                "wait",
                "--for=condition=Ready",
                "nodes",
                "--all",
                "--timeout=300s",
            ],
            &kubeconfig_path,
        )
        .await?;

        // Install CAPI
        let init_args = self.clusterctl_init_args();
        let init_args_ref: Vec<&str> = init_args.iter().map(|s| s.as_str()).collect();
        self.run_command_with_output_env(
            "clusterctl",
            &init_args_ref,
            &[("KUBECONFIG", &kubeconfig_path)],
        )
        .await?;

        // Wait for CAPI controllers
        self.run_command_with_kubeconfig(
            "kubectl",
            &[
                "wait",
                "--for=condition=Available",
                "deployment",
                "--all",
                "-n",
                "capi-system",
                "--timeout=300s",
            ],
            &kubeconfig_path,
        )
        .await?;

        // Create provider-specific credentials if needed
        if self.provider() == ProviderType::Proxmox {
            self.create_capmox_credentials(Some(&kubeconfig_path))
                .await?;
        }

        // Wait for Lattice operator
        self.run_command_with_kubeconfig(
            "kubectl",
            &[
                "wait",
                "--for=condition=Available",
                "deployment/lattice-operator",
                "-n",
                "lattice-system",
                "--timeout=120s",
            ],
            &kubeconfig_path,
        )
        .await?;

        // Apply self-referential LatticeCluster CR
        self.kubectl_apply_with_retry(
            &self.config.cluster_config_content,
            Some(&kubeconfig_path),
            Duration::from_secs(120),
        )
        .await?;

        Ok(())
    }

    /// Create CAPMOX credentials secret for Proxmox provider
    ///
    /// When kubeconfig is None, applies to current context (bootstrap cluster).
    /// When kubeconfig is Some, applies to the specified cluster (management cluster).
    async fn create_capmox_credentials(&self, kubeconfig: Option<&str>) -> Result<()> {
        let target = kubeconfig.map_or("bootstrap", |_| "management");
        info!("Creating CAPMOX credentials on {} cluster...", target);

        let url = std::env::var("PROXMOX_URL").map_err(|_| {
            Error::validation("PROXMOX_URL environment variable required for Proxmox provider")
        })?;
        let token = std::env::var("PROXMOX_TOKEN").map_err(|_| {
            Error::validation("PROXMOX_TOKEN environment variable required for Proxmox provider")
        })?;
        let secret = std::env::var("PROXMOX_SECRET").map_err(|_| {
            Error::validation("PROXMOX_SECRET environment variable required for Proxmox provider")
        })?;

        info!("  PROXMOX_URL: {}", url);
        info!("  PROXMOX_TOKEN: {}", token);

        let ns_manifest = r#"apiVersion: v1
kind: Namespace
metadata:
  name: capmox-system"#;

        self.kubectl_apply_with_retry(ns_manifest, kubeconfig, Duration::from_secs(30))
            .await?;

        let secret_manifest = format!(
            r#"apiVersion: v1
kind: Secret
metadata:
  name: capmox-manager-credentials
  namespace: capmox-system
  labels:
    platform.ionos.com/secret-type: proxmox-credentials
type: Opaque
stringData:
  url: "{url}"
  token: "{token}"
  secret: "{secret}""#
        );

        self.kubectl_apply_with_retry(&secret_manifest, kubeconfig, Duration::from_secs(30))
            .await?;

        info!("CAPMOX credentials created on {} cluster", target);
        Ok(())
    }

    async fn pivot_capi_resources(&self) -> Result<()> {
        let namespace = format!("capi-{}", self.cluster_name());
        let kubeconfig_path = format!("/tmp/{}-kubeconfig", self.cluster_name());
        let bootstrap_kubeconfig = self.bootstrap_kubeconfig_path();

        // Wait for CAPI CRDs on target cluster
        info!("Waiting for CAPI CRDs on management cluster...");
        let start = Instant::now();
        loop {
            if start.elapsed() > Duration::from_secs(300) {
                return Err(Error::command_failed("Timeout waiting for CAPI CRDs"));
            }

            let result = Command::new("kubectl")
                .args([
                    "--kubeconfig",
                    &kubeconfig_path,
                    "get",
                    "crd",
                    "clusters.cluster.x-k8s.io",
                ])
                .output()
                .await?;

            if result.status.success() {
                break;
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        // Wait for all machines to be provisioned before move
        info!("Waiting for all machines to be provisioned...");
        let start = Instant::now();
        loop {
            if start.elapsed() > Duration::from_secs(600) {
                return Err(Error::command_failed(
                    "Timeout waiting for machines to be provisioned",
                ));
            }

            // Check if any machines are still provisioning
            let result = Command::new("kubectl")
                .args([
                    "--kubeconfig",
                    &bootstrap_kubeconfig,
                    "get",
                    "machines",
                    "-n",
                    &namespace,
                    "-o",
                    "jsonpath={.items[*].status.phase}",
                ])
                .output()
                .await?;

            if result.status.success() {
                let phases = String::from_utf8_lossy(&result.stdout);
                let all_running = !phases.is_empty()
                    && phases.split_whitespace().all(|p| p == "Running");
                if all_running {
                    info!("All machines are Running");
                    break;
                }
                info!("Machine phases: {}", phases.trim());
            }

            tokio::time::sleep(Duration::from_secs(10)).await;
        }

        // Run clusterctl move with retries
        // Must specify both source (--kubeconfig) and destination (--to-kubeconfig)
        info!("Running clusterctl move from bootstrap to management cluster...");
        let mut last_error = None;
        for attempt in 1..=5 {
            let result = Command::new("clusterctl")
                .args([
                    "move",
                    "--kubeconfig",
                    &bootstrap_kubeconfig,
                    "--to-kubeconfig",
                    &kubeconfig_path,
                    "--namespace",
                    &namespace,
                ])
                .output()
                .await?;

            if result.status.success() {
                info!("clusterctl move completed successfully");
                return Ok(());
            }

            let stderr = String::from_utf8_lossy(&result.stderr);
            last_error = Some(stderr.to_string());

            if attempt < 5 {
                let delay = Duration::from_secs(10 * attempt as u64);
                warn!(
                    "clusterctl move failed (attempt {}/5), retrying in {:?}: {}",
                    attempt,
                    delay,
                    stderr.trim()
                );
                tokio::time::sleep(delay).await;
            }
        }

        Err(Error::command_failed(format!(
            "clusterctl move failed after 5 attempts: {}",
            last_error.unwrap_or_default()
        )))
    }

    async fn run_command(&self, cmd: &str, args: &[&str]) -> Result<String> {
        let output = Command::new(cmd).args(args).output().await?;

        if !output.status.success() {
            return Err(Error::command_failed(format!(
                "{} {} failed: {}",
                cmd,
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    async fn run_command_with_output_env(
        &self,
        cmd: &str,
        args: &[&str],
        env: &[(&str, &str)],
    ) -> Result<()> {
        let mut command = Command::new(cmd);
        command
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        for (key, value) in env {
            command.env(key, value);
        }

        let mut child = command.spawn()?;
        let stderr_handle = child.stderr.take();

        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();
            while let Some(line) = lines.next_line().await? {
                info!("  {}", line);
            }
        }

        let status = child.wait().await?;
        if !status.success() {
            let stderr_msg = if let Some(stderr) = stderr_handle {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                let mut output = Vec::new();
                while let Some(line) = lines.next_line().await.ok().flatten() {
                    output.push(line);
                }
                output.join("\n")
            } else {
                "command failed".to_string()
            };

            return Err(Error::command_failed(format!(
                "{} {} failed: {}",
                cmd,
                args.join(" "),
                stderr_msg
            )));
        }

        Ok(())
    }

    async fn run_command_with_kubeconfig(
        &self,
        cmd: &str,
        args: &[&str],
        kubeconfig: &str,
    ) -> Result<String> {
        let mut full_args = vec!["--kubeconfig", kubeconfig];
        full_args.extend(args);

        let output = Command::new(cmd).args(&full_args).output().await?;

        if !output.status.success() {
            return Err(Error::command_failed(format!(
                "{} {} failed: {}",
                cmd,
                full_args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    async fn kubectl_apply(&self, manifest: &str, kubeconfig: Option<&str>) -> Result<()> {
        let mut args = Vec::new();
        if let Some(kc) = kubeconfig {
            args.extend(["--kubeconfig", kc]);
        }
        // Use --server-side to handle "already exists" errors gracefully
        args.extend(["apply", "--server-side", "-f", "-"]);

        let mut child = Command::new("kubectl")
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin.write_all(manifest.as_bytes()).await?;
        }

        let output = child.wait_with_output().await?;
        if !output.status.success() {
            return Err(Error::command_failed(format!(
                "kubectl apply failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    async fn kubectl_apply_with_retry(
        &self,
        manifest: &str,
        kubeconfig: Option<&str>,
        timeout: Duration,
    ) -> Result<()> {
        let start = Instant::now();
        let mut last_error = String::new();
        loop {
            if start.elapsed() > timeout {
                return Err(Error::command_failed(format!(
                    "Timeout waiting for kubectl apply: {}",
                    last_error
                )));
            }

            match self.kubectl_apply(manifest, kubeconfig).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last_error = e.to_string();
                    info!("kubectl apply failed (retrying): {}", last_error);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }
}

/// Add bootstrap cluster environment variables to a deployment.
///
/// Sets LATTICE_BOOTSTRAP_CLUSTER=true and LATTICE_PROVIDER to the specified provider.
/// The bootstrap cluster needs these so the operator knows to install CAPI on startup.
fn add_bootstrap_env(deployment_json: &str, provider: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(deployment_json) else {
        return deployment_json.to_string();
    };

    let Some(containers) = value
        .pointer_mut("/spec/template/spec/containers")
        .and_then(|c| c.as_array_mut())
    else {
        return deployment_json.to_string();
    };

    for container in containers {
        let Some(env) = container.as_object_mut().and_then(|c| {
            c.entry("env")
                .or_insert_with(|| serde_json::json!([]))
                .as_array_mut()
        }) else {
            continue;
        };

        // Add LATTICE_BOOTSTRAP_CLUSTER=true if not present
        if !env
            .iter()
            .any(|e| e.get("name").and_then(|n| n.as_str()) == Some("LATTICE_BOOTSTRAP_CLUSTER"))
        {
            env.push(serde_json::json!({"name": "LATTICE_BOOTSTRAP_CLUSTER", "value": "true"}));
        }

        // Add LATTICE_PROVIDER if not present
        if !env
            .iter()
            .any(|e| e.get("name").and_then(|n| n.as_str()) == Some("LATTICE_PROVIDER"))
        {
            env.push(serde_json::json!({"name": "LATTICE_PROVIDER", "value": provider}));
        }
    }

    serde_json::to_string(&value).unwrap_or_else(|_| deployment_json.to_string())
}

pub async fn run(args: InstallArgs) -> Result<()> {
    // Get config file path - either directly specified or from git repo
    let (config_path, config_content) = if let Some(ref config_file) = args.config_file {
        let content = tokio::fs::read_to_string(config_file).await?;
        (config_file.clone(), content)
    } else {
        // Get repository path
        let repo_path = get_repository(&args).await?;
        let cluster_yaml = repo_path.join("cluster.yaml");

        if !cluster_yaml.exists() {
            return Err(Error::NotLatticeRepo { path: repo_path });
        }

        let content = tokio::fs::read_to_string(&cluster_yaml).await?;
        (cluster_yaml, content)
    };

    // Validate the cluster config
    let cluster: LatticeCluster = serde_yaml::from_str(&config_content)?;
    let cluster_name = cluster
        .metadata
        .name
        .as_ref()
        .ok_or_else(|| Error::validation("LatticeCluster must have metadata.name"))?;
    let provider = cluster.spec.provider.provider_type();

    info!("Config file: {:?}", config_path);
    info!("Management cluster: {}", cluster_name);
    info!("Provider: {}", provider);
    info!(
        "Kubernetes version: {}",
        cluster.spec.provider.kubernetes.version
    );

    if args.dry_run {
        info!("Dry run - would perform the following:");
        info!("  1. Create bootstrap kind cluster");
        info!("  2. Install CAPI controllers");
        info!("  3. Install Lattice operator");
        info!("  4. Apply root cluster: {}", config_path.display());
        info!("  5. Wait for cluster provisioning");
        info!("  6. Pivot CAPI resources");
        info!("  7. Delete bootstrap cluster");
        return Ok(());
    }

    // Read registry credentials if provided
    let registry_credentials = if let Some(creds_path) = &args.registry_credentials_file {
        Some(tokio::fs::read_to_string(creds_path).await?)
    } else {
        None
    };

    let config = InstallConfig {
        cluster_config_path: config_path,
        cluster_config_content: config_content,
        image: args.image,
        keep_bootstrap_on_failure: args.keep_bootstrap_on_failure,
        timeout: Duration::from_secs(args.timeout_secs),
        registry_credentials,
        bootstrap_override: args.bootstrap,
    };

    let installer = Installer::new(config)?;
    installer.run().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bootstrap_provider_rke2() {
        assert!(matches!(
            parse_bootstrap_provider("rke2"),
            Ok(BootstrapProvider::Rke2)
        ));
        assert!(matches!(
            parse_bootstrap_provider("RKE2"),
            Ok(BootstrapProvider::Rke2)
        ));
    }

    #[test]
    fn test_parse_bootstrap_provider_kubeadm() {
        assert!(matches!(
            parse_bootstrap_provider("kubeadm"),
            Ok(BootstrapProvider::Kubeadm)
        ));
        assert!(matches!(
            parse_bootstrap_provider("KUBEADM"),
            Ok(BootstrapProvider::Kubeadm)
        ));
    }

    #[test]
    fn test_parse_bootstrap_provider_invalid() {
        assert!(parse_bootstrap_provider("invalid").is_err());
    }

    #[test]
    fn test_add_bootstrap_env_adds_both_env_vars() {
        let deployment = r#"{
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "lattice",
                            "image": "lattice:latest"
                        }]
                    }
                }
            }
        }"#;

        let result = add_bootstrap_env(deployment, "proxmox");
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

        let env = parsed
            .pointer("/spec/template/spec/containers/0/env")
            .unwrap()
            .as_array()
            .unwrap();

        // Check LATTICE_BOOTSTRAP_CLUSTER
        assert!(env.iter().any(|e| {
            e.get("name").and_then(|n| n.as_str()) == Some("LATTICE_BOOTSTRAP_CLUSTER")
                && e.get("value").and_then(|v| v.as_str()) == Some("true")
        }));

        // Check LATTICE_PROVIDER
        assert!(env.iter().any(|e| {
            e.get("name").and_then(|n| n.as_str()) == Some("LATTICE_PROVIDER")
                && e.get("value").and_then(|v| v.as_str()) == Some("proxmox")
        }));
    }

    #[test]
    fn test_add_bootstrap_env_idempotent() {
        let deployment = r#"{
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "lattice",
                            "env": [
                                {"name": "LATTICE_BOOTSTRAP_CLUSTER", "value": "true"},
                                {"name": "LATTICE_PROVIDER", "value": "docker"}
                            ]
                        }]
                    }
                }
            }
        }"#;

        let result = add_bootstrap_env(deployment, "docker");
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

        let env = parsed
            .pointer("/spec/template/spec/containers/0/env")
            .unwrap()
            .as_array()
            .unwrap();

        // Should still only have one entry for each
        let bootstrap_count = env
            .iter()
            .filter(|e| e.get("name").and_then(|n| n.as_str()) == Some("LATTICE_BOOTSTRAP_CLUSTER"))
            .count();
        assert_eq!(bootstrap_count, 1);

        let provider_count = env
            .iter()
            .filter(|e| e.get("name").and_then(|n| n.as_str()) == Some("LATTICE_PROVIDER"))
            .count();
        assert_eq!(provider_count, 1);
    }

    #[test]
    fn test_add_bootstrap_env_invalid_json() {
        let invalid = "not json";
        let result = add_bootstrap_env(invalid, "docker");
        assert_eq!(result, invalid);
    }
}

async fn get_repository(args: &InstallArgs) -> Result<PathBuf> {
    if let Some(ref local_path) = args.local_path {
        if !local_path.exists() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Local path not found: {}", local_path.display()),
            )));
        }
        return Ok(local_path.clone());
    }

    if let Some(ref git_url) = args.git_repo {
        let temp_dir = tempfile::tempdir()?;
        let repo_path = temp_dir.path().to_path_buf();
        std::mem::forget(temp_dir);

        info!(url = git_url, "Cloning repository...");
        git::clone_repo(git_url, &repo_path, args.git_credentials.as_deref())?;
        git::checkout_branch(&repo_path, &args.git_branch)?;

        return Ok(repo_path);
    }

    Ok(PathBuf::from("."))
}
