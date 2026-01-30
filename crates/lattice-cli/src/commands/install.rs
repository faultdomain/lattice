//! Install command - Bootstrap a new Lattice management cluster
//!
//! Usage: lattice install -f cluster.yaml
//!
//! This command creates a self-managing Lattice cluster by:
//! 1. Creating a temporary kind bootstrap cluster
//! 2. Installing CAPI providers and Lattice operator
//! 3. Provisioning the management cluster from your LatticeCluster CRD
//! 4. Pivoting CAPI resources to make it self-managing
//! 5. Deleting the bootstrap cluster

use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use clap::Args;
use kube::Client;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing::info;

use super::kind_utils;

use lattice_common::clusterctl::move_to_kubeconfig;
use lattice_common::kube_utils;
use lattice_common::AwsCredentials;
use lattice_operator::bootstrap::{
    aws_credentials_manifests, generate_bootstrap_bundle, proxmox_credentials_manifests,
    BootstrapBundleConfig, DefaultManifestGenerator, ManifestGenerator,
};
use lattice_operator::crd::{
    BootstrapProvider, CloudProvider, CloudProviderSpec, CloudProviderType, LatticeCluster,
    ProviderType, SecretRef,
};
use lattice_operator::fips;

use crate::{Error, Result};

/// Extension trait to convert errors with Display to CLI Error::CommandFailed.
///
/// This reduces boilerplate for the common pattern of `.map_err(|e| Error::command_failed(e.to_string()))`.
trait CommandErrorExt<T> {
    /// Convert an error to `Error::CommandFailed` using its Display implementation.
    fn cmd_err(self) -> Result<T>;
}

impl<T, E: Display> CommandErrorExt<T> for std::result::Result<T, E> {
    fn cmd_err(self) -> Result<T> {
        self.map_err(|e| Error::command_failed(e.to_string()))
    }
}

/// Install a self-managing Lattice cluster from a LatticeCluster CRD
#[derive(Args, Debug)]
pub struct InstallArgs {
    /// Path to LatticeCluster YAML file
    #[arg(short = 'f', long = "file")]
    pub config_file: PathBuf,

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

    /// Kubernetes bootstrap provider (overrides config file if set)
    #[arg(long, value_parser = parse_bootstrap_provider)]
    pub bootstrap: Option<BootstrapProvider>,

    /// Dry run - show what would be done without making changes
    #[arg(long)]
    pub dry_run: bool,

    /// Write kubeconfig to this path after installation
    #[arg(long)]
    pub kubeconfig_out: Option<PathBuf>,
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

/// The Lattice installer
pub struct Installer {
    cluster_yaml: String,
    cluster: LatticeCluster,
    cluster_name: String,
    image: String,
    keep_bootstrap_on_failure: bool,
    registry_credentials: Option<String>,
}

/// Fixed bootstrap cluster name - concurrent installs are not supported
const BOOTSTRAP_CLUSTER_NAME: &str = "lattice-bootstrap";

impl Installer {
    /// Create a new installer
    pub fn new(
        cluster_yaml: String,
        image: String,
        keep_bootstrap_on_failure: bool,
        registry_credentials: Option<String>,
        bootstrap_override: Option<BootstrapProvider>,
    ) -> Result<Self> {
        let mut cluster: LatticeCluster = serde_yaml::from_str(&cluster_yaml)?;

        if let Some(bootstrap) = bootstrap_override {
            cluster.spec.provider.kubernetes.bootstrap = bootstrap;
        }

        let cluster_name = cluster
            .metadata
            .name
            .clone()
            .ok_or_else(|| Error::validation("LatticeCluster must have metadata.name"))?;

        Ok(Self {
            cluster_yaml,
            cluster,
            cluster_name,
            image,
            keep_bootstrap_on_failure,
            registry_credentials,
        })
    }

    /// Create a new installer from CLI args
    pub async fn from_args(args: &InstallArgs) -> Result<Self> {
        let cluster_yaml = tokio::fs::read_to_string(&args.config_file).await?;
        let registry_credentials = match &args.registry_credentials_file {
            Some(path) => Some(tokio::fs::read_to_string(path).await?),
            None => None,
        };

        Self::new(
            cluster_yaml,
            args.image.clone(),
            args.keep_bootstrap_on_failure,
            registry_credentials,
            args.bootstrap.clone(),
        )
    }

    fn cluster_name(&self) -> &str {
        &self.cluster_name
    }

    /// Returns the CAPI namespace for this cluster (e.g., "capi-my-cluster")
    fn capi_namespace(&self) -> String {
        format!("capi-{}", self.cluster_name)
    }

    /// Returns the kubeconfig secret name for this cluster (e.g., "my-cluster-kubeconfig")
    fn kubeconfig_secret_name(&self) -> String {
        format!("{}-kubeconfig", self.cluster_name)
    }

    fn bootstrap_kubeconfig_path(&self) -> PathBuf {
        PathBuf::from(format!("/tmp/{}-kubeconfig", BOOTSTRAP_CLUSTER_NAME))
    }

    /// Returns the path where the management cluster kubeconfig is stored
    pub fn kubeconfig_path(&self) -> PathBuf {
        PathBuf::from(format!("/tmp/{}-kubeconfig", self.cluster_name))
    }

    fn provider(&self) -> ProviderType {
        self.cluster.spec.provider.provider_type()
    }

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

        if self.provider() == ProviderType::Proxmox {
            args.push("--ipam=in-cluster".to_string());
        }

        args
    }

    /// Run the installation
    pub async fn run(&self) -> Result<()> {
        info!("Installing cluster: {}", self.cluster_name);
        info!("Provider: {}", self.provider());
        info!(
            "Kubernetes version: {}",
            self.cluster.spec.provider.kubernetes.version
        );

        let start = Instant::now();
        self.check_prerequisites().await?;

        let bootstrap_result = self.run_bootstrap().await;

        if bootstrap_result.is_err() && !self.keep_bootstrap_on_failure {
            info!("Deleting bootstrap cluster due to failure...");
            let _ = kind_utils::delete_kind_cluster(BOOTSTRAP_CLUSTER_NAME).await;
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

        // Only check for tools we actually need (no kubectl!)
        let tools = [
            (
                "docker",
                "Install Docker: https://docs.docker.com/get-docker/",
            ),
            (
                "kind",
                "Install kind: https://kind.sigs.k8s.io/docs/user/quick-start/#installation",
            ),
            (
                "clusterctl",
                "Install clusterctl: https://cluster-api.sigs.k8s.io/user/quick-start#install-clusterctl",
            ),
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
        info!("[Phase 1/8] Creating kind bootstrap cluster...");
        kind_utils::create_kind_cluster(BOOTSTRAP_CLUSTER_NAME, &self.bootstrap_kubeconfig_path())
            .await?;

        let bootstrap_client = self.bootstrap_client().await?;

        info!("[Phase 2/8] Deploying Lattice operator...");
        self.deploy_lattice_operator(&bootstrap_client).await?;

        // CloudProvider must be created AFTER operator deploys CRDs
        // Operator waits for CloudProvider before installing CAPI
        info!("[Phase 3/8] Creating CloudProvider and credentials...");
        self.create_cloud_provider_with_credentials(&bootstrap_client)
            .await?;

        info!("Waiting for CAPI to be installed...");
        self.wait_for_capi_crds(&bootstrap_client).await?;

        info!("[Phase 4/8] Creating management cluster LatticeCluster CR...");
        self.create_management_cluster_crd(&bootstrap_client)
            .await?;

        info!("[Phase 5/8] Waiting for management cluster to be provisioned...");
        self.wait_for_management_cluster(&bootstrap_client).await?;

        info!("[Phase 6/8] Applying bootstrap manifests to management cluster...");
        self.apply_bootstrap_to_management(&bootstrap_client)
            .await?;

        info!("[Phase 7/8] Pivoting CAPI resources to management cluster...");
        self.pivot_capi_resources().await?;

        info!("[Phase 8/8] Deleting bootstrap cluster...");
        kind_utils::delete_kind_cluster(BOOTSTRAP_CLUSTER_NAME).await?;

        Ok(())
    }

    async fn bootstrap_client(&self) -> Result<Client> {
        kube_utils::create_client(Some(&self.bootstrap_kubeconfig_path()))
            .await
            .cmd_err()
    }

    async fn management_client(&self) -> Result<Client> {
        let kubeconfig_path = self.kubeconfig_path();
        info!("Creating management client from {:?}", kubeconfig_path);

        // Use shorter timeout for management cluster connection to fail fast
        // if the address is unreachable (e.g., connecting to internal Docker IP)
        let connect_timeout = Duration::from_secs(10);
        let read_timeout = Duration::from_secs(30);

        kube_utils::create_client_with_timeout(
            Some(&kubeconfig_path),
            connect_timeout,
            read_timeout,
        )
        .await
        .cmd_err()
    }

    async fn deploy_lattice_operator(&self, client: &Client) -> Result<()> {
        let generator = DefaultManifestGenerator::new();
        let all_manifests = generator
            .generate(
                &self.image,
                self.registry_credentials.as_deref(),
                Some("lattice-installer"),
                None,
            )
            .await;

        let provider_str = self.provider().to_string();
        let provider_ref = &self.cluster.spec.provider_ref;
        let operator_manifests: Vec<String> = all_manifests
            .iter()
            .filter(|m: &&String| m.starts_with("{"))
            .map(|s| {
                if fips::is_deployment(s) {
                    let with_fips = fips::add_fips_relax_env(s);
                    add_bootstrap_env(&with_fips, &provider_str, provider_ref)
                } else {
                    s.to_string()
                }
            })
            .collect();

        for manifest in &operator_manifests {
            kube_utils::apply_manifest(client, manifest)
                .await
                .cmd_err()?;
        }

        info!("Waiting for Lattice operator to be ready...");
        kube_utils::wait_for_deployment(
            client,
            "lattice-operator",
            "lattice-system",
            Duration::from_secs(300),
        )
        .await
        .cmd_err()?;

        Ok(())
    }

    async fn wait_for_capi_crds(&self, client: &Client) -> Result<()> {
        let required_crds = [
            "clusters.cluster.x-k8s.io",
            "machines.cluster.x-k8s.io",
            "clusterresourcesets.addons.cluster.x-k8s.io",
        ];

        for crd in required_crds {
            kube_utils::wait_for_crd(client, crd, Duration::from_secs(300))
                .await
                .cmd_err()?;
        }

        Ok(())
    }

    async fn create_management_cluster_crd(&self, client: &Client) -> Result<()> {
        kube_utils::apply_manifest_with_retry(client, &self.cluster_yaml, Duration::from_secs(120))
            .await
            .cmd_err()?;
        Ok(())
    }

    async fn wait_for_management_cluster(&self, client: &Client) -> Result<()> {
        let start = Instant::now();
        let timeout = Duration::from_secs(600);
        let namespace = self.capi_namespace();
        let secret_name = self.kubeconfig_secret_name();

        // Wait for Ready/Pivoting phase
        loop {
            if start.elapsed() > timeout {
                return Err(Error::command_failed("Timeout waiting for cluster"));
            }

            let phase = get_latticecluster_phase(client, self.cluster_name()).await?;
            info!(
                "Cluster phase: {}",
                if phase.is_empty() { "Pending" } else { &phase }
            );

            match phase.as_str() {
                "Ready" | "Pivoting" => break,
                "Failed" => return Err(Error::command_failed("Cluster provisioning failed")),
                _ => tokio::time::sleep(Duration::from_secs(10)).await,
            }
        }

        // Wait for kubeconfig secret
        kube_utils::wait_for_secret(client, &secret_name, &namespace, timeout)
            .await
            .cmd_err()?;

        Ok(())
    }

    async fn apply_bootstrap_to_management(&self, bootstrap_client: &Client) -> Result<()> {
        info!("Fetching management cluster kubeconfig...");
        let kubeconfig = self.fetch_management_kubeconfig(bootstrap_client).await?;
        let kubeconfig_path = self.kubeconfig_path();
        info!("Writing kubeconfig to {:?}", kubeconfig_path);
        tokio::fs::write(&kubeconfig_path, &kubeconfig).await?;

        info!("Waiting for management cluster API server...");
        self.wait_for_api_server().await?;

        info!("Creating management cluster client...");
        let mgmt_client = self.management_client().await?;

        info!("Generating bootstrap manifests...");
        let manifests = self.generate_bootstrap_manifests().await?;
        info!("Applying {} bootstrap manifests...", manifests.len());

        let retry_config = lattice_common::retry::RetryConfig::infinite();
        for manifest in &manifests {
            let client = mgmt_client.clone();
            let m = manifest.clone();
            lattice_common::retry::retry_with_backoff(&retry_config, "apply_manifest", || {
                let c = client.clone();
                let manifest = m.clone();
                async move { kube_utils::apply_manifest(&c, &manifest).await }
            })
            .await
            .cmd_err()?;
        }

        info!("Waiting for nodes to be ready...");
        kube_utils::wait_for_nodes_ready(&mgmt_client, Duration::from_secs(300))
            .await
            .cmd_err()?;

        self.install_capi_on_management(&kubeconfig_path).await?;
        self.wait_for_management_controllers(&mgmt_client).await?;
        self.copy_cloud_provider_to_management(bootstrap_client, &mgmt_client)
            .await?;

        Ok(())
    }

    /// Generate all bootstrap manifests for the management cluster.
    ///
    /// Uses the same shared code as the bootstrap webhook to ensure consistency.
    async fn generate_bootstrap_manifests(&self) -> Result<Vec<String>> {
        let generator = DefaultManifestGenerator::new();

        let proxmox_ipv4_pool = self
            .cluster
            .spec
            .provider
            .config
            .proxmox
            .as_ref()
            .map(|p| &p.ipv4_pool);

        let config = BootstrapBundleConfig {
            image: &self.image,
            registry_credentials: self.registry_credentials.as_deref(),
            networking: self.cluster.spec.networking.as_ref(),
            proxmox_ipv4_pool,
            cluster_name: self.cluster_name(),
            provider: self.provider(),
            bootstrap: self.cluster.spec.provider.kubernetes.bootstrap.clone(),
            k8s_version: &self.cluster.spec.provider.kubernetes.version,
            parent_host: None, // Management cluster has no parent
            parent_grpc_port: lattice_operator::DEFAULT_GRPC_PORT,
            relax_fips: self
                .cluster
                .spec
                .provider
                .kubernetes
                .bootstrap
                .needs_fips_relax(),
            autoscaling_enabled: self
                .cluster
                .spec
                .nodes
                .worker_pools
                .values()
                .any(|p| p.is_autoscaling_enabled()),
            cluster_manifest: &self.cluster_yaml,
        };

        generate_bootstrap_bundle(&generator, &config)
            .await
            .map_err(|e| Error::command_failed(e.to_string()))
    }

    /// Copy CloudProvider and its credentials secret from bootstrap to management cluster
    async fn copy_cloud_provider_to_management(
        &self,
        bootstrap_client: &Client,
        mgmt_client: &Client,
    ) -> Result<()> {
        use lattice_agent::apply_distributed_resources;
        use lattice_cell::fetch_distributable_resources;

        // Fetch all distributable resources (CloudProviders, SecretsProviders, secrets)
        let resources = fetch_distributable_resources(bootstrap_client)
            .await
            .map_err(|e| Error::command_failed(format!("Failed to fetch resources: {}", e)))?;

        if resources.is_empty() {
            info!("No CloudProviders or SecretsProviders to copy");
            return Ok(());
        }

        info!(
            "Copying {} CloudProvider(s), {} SecretsProvider(s), {} secret(s) to management cluster",
            resources.cloud_providers.len(),
            resources.secrets_providers.len(),
            resources.secrets.len()
        );

        // Apply to management cluster
        apply_distributed_resources(mgmt_client, &resources)
            .await
            .map_err(|e| Error::command_failed(format!("Failed to apply resources: {}", e)))?;

        Ok(())
    }

    /// Fetches the management cluster kubeconfig from the bootstrap cluster secret,
    /// rewriting the server URL for Docker provider if needed.
    async fn fetch_management_kubeconfig(&self, bootstrap_client: &Client) -> Result<String> {
        let namespace = self.capi_namespace();
        let secret_name = self.kubeconfig_secret_name();

        info!("Fetching kubeconfig secret {}/{}", namespace, secret_name);
        let kubeconfig_bytes =
            kube_utils::get_secret_data(bootstrap_client, &secret_name, &namespace, "value")
                .await
                .cmd_err()?;

        let kubeconfig = String::from_utf8(kubeconfig_bytes)
            .map_err(|e| Error::command_failed(format!("Invalid kubeconfig encoding: {}", e)))?;
        info!("Kubeconfig fetched successfully");

        // Rewrite Docker provider kubeconfig to use localhost
        if self.provider() == ProviderType::Docker {
            info!("Rewriting kubeconfig for Docker provider...");
            self.rewrite_docker_kubeconfig(&kubeconfig).await
        } else {
            Ok(kubeconfig)
        }
    }

    /// Rewrites a kubeconfig's server URL to use localhost with the Docker-exposed port.
    /// Uses YAML parsing for safe manipulation instead of string replacement.
    async fn rewrite_docker_kubeconfig(&self, kubeconfig: &str) -> Result<String> {
        let lb_container = format!("{}-lb", self.cluster_name());
        info!("Looking up Docker port for container: {}", lb_container);

        // Retry getting the docker port - LB container may not be ready immediately
        let retry_config = lattice_common::retry::RetryConfig::infinite();
        let container = lb_container.clone();
        let port: String =
            lattice_common::retry::retry_with_backoff(&retry_config, "docker_port_lookup", || {
                let c = container.clone();
                async move {
                    let output = Command::new("docker")
                        .args(["port", &c, "6443"])
                        .output()
                        .await
                        .map_err(|e| format!("docker command failed: {}", e))?;

                    if !output.status.success() {
                        return Err("LB container port not ready".to_string());
                    }

                    let port_str = String::from_utf8_lossy(&output.stdout);
                    port_str
                        .trim()
                        .split(':')
                        .next_back()
                        .map(|p| p.to_string())
                        .ok_or_else(|| "failed to parse port".to_string())
                }
            })
            .await
            .map_err(|e| Error::command_failed(format!("Failed to get Docker LB port: {}", e)))?;

        info!("Docker LB port found: {}", port);
        let localhost_url = format!("https://127.0.0.1:{}", port);

        // Parse kubeconfig as YAML and update the server URL
        let mut config: serde_yaml::Value = serde_yaml::from_str(kubeconfig).map_err(|e| {
            Error::command_failed(format!("Failed to parse kubeconfig YAML: {}", e))
        })?;

        if let Some(clusters) = config.get_mut("clusters").and_then(|c| c.as_sequence_mut()) {
            for cluster in clusters {
                if let Some(cluster_data) = cluster.get_mut("cluster") {
                    if let Some(server) = cluster_data.get_mut("server") {
                        *server = serde_yaml::Value::String(localhost_url.clone());
                    }
                }
            }
        }

        serde_yaml::to_string(&config).map_err(|e| {
            Error::command_failed(format!("Failed to serialize kubeconfig YAML: {}", e))
        })
    }

    /// Waits for the management cluster API server to become reachable.
    async fn wait_for_api_server(&self) -> Result<()> {
        use k8s_openapi::api::core::v1::Namespace;
        use kube::Api;

        let start = Instant::now();
        loop {
            if start.elapsed() > Duration::from_secs(300) {
                return Err(Error::command_failed("Timeout waiting for API server"));
            }

            match self.management_client().await {
                Ok(client) => {
                    // Just check if we can list namespaces - proves API is reachable
                    let ns: Api<Namespace> = Api::all(client);
                    match ns.list(&Default::default()).await {
                        Ok(_) => {
                            info!("API server is reachable");
                            return Ok(());
                        }
                        Err(e) => info!("API not ready yet: {}", e),
                    }
                }
                Err(e) => info!("Client creation failed: {}", e),
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    /// Installs CAPI controllers on the management cluster via clusterctl.
    async fn install_capi_on_management(&self, kubeconfig_path: &Path) -> Result<()> {
        let init_args = self.clusterctl_init_args();
        let init_args_ref: Vec<&str> = init_args.iter().map(|s| s.as_str()).collect();
        self.run_clusterctl(&init_args_ref, kubeconfig_path).await
    }

    /// Waits for CAPI and Lattice controllers to be ready on the management cluster.
    async fn wait_for_management_controllers(&self, mgmt_client: &Client) -> Result<()> {
        // Wait for CAPI controllers
        kube_utils::wait_for_all_deployments(mgmt_client, "capi-system", Duration::from_secs(300))
            .await
            .cmd_err()?;

        // Wait for Lattice operator
        kube_utils::wait_for_deployment(
            mgmt_client,
            "lattice-operator",
            "lattice-system",
            Duration::from_secs(120),
        )
        .await
        .cmd_err()
    }

    /// Create CloudProvider and provider-specific credentials.
    ///
    /// Must be called AFTER operator deploys CRDs but BEFORE creating LatticeCluster.
    /// The operator waits for this CloudProvider to install CAPI providers.
    async fn create_cloud_provider_with_credentials(&self, client: &Client) -> Result<()> {
        match self.provider() {
            ProviderType::Proxmox => self.create_proxmox_credentials(client).await,
            ProviderType::Aws => self.create_aws_credentials(client).await,
            ProviderType::Docker => {
                self.create_cloud_provider(client, CloudProviderType::Docker, "")
                    .await
            }
            ProviderType::OpenStack | ProviderType::Gcp | ProviderType::Azure => {
                // TODO: Add credential support for these providers
                info!(
                    "Provider {:?} does not require credentials setup",
                    self.provider()
                );
                Ok(())
            }
        }
    }

    fn get_proxmox_credentials() -> Result<(String, String, String)> {
        let url = std::env::var("PROXMOX_URL").map_err(|_| {
            Error::validation("PROXMOX_URL environment variable required for Proxmox provider")
        })?;
        let token = std::env::var("PROXMOX_TOKEN").map_err(|_| {
            Error::validation("PROXMOX_TOKEN environment variable required for Proxmox provider")
        })?;
        let secret = std::env::var("PROXMOX_SECRET").map_err(|_| {
            Error::validation("PROXMOX_SECRET environment variable required for Proxmox provider")
        })?;
        Ok((url, token, secret))
    }

    async fn create_proxmox_credentials(&self, client: &Client) -> Result<()> {
        let (url, token, secret) = Self::get_proxmox_credentials()?;
        info!("PROXMOX_URL: {}", url);

        // Create credentials secret
        let manifests = proxmox_credentials_manifests(&url, &token, &secret);
        kube_utils::apply_manifest_with_retry(client, &manifests, Duration::from_secs(30))
            .await
            .cmd_err()?;

        // Create CloudProvider referencing the credentials
        self.create_cloud_provider(client, CloudProviderType::Proxmox, "proxmox-credentials")
            .await
    }

    fn get_aws_credentials() -> Result<AwsCredentials> {
        AwsCredentials::from_env().map_err(|e| Error::validation(e.to_string()))
    }

    async fn create_aws_credentials(&self, client: &Client) -> Result<()> {
        let creds = Self::get_aws_credentials()?;
        info!("AWS_REGION: {}", creds.region);

        // Create credentials secret
        let manifests = aws_credentials_manifests(&creds);
        kube_utils::apply_manifest_with_retry(client, &manifests, Duration::from_secs(30))
            .await
            .cmd_err()?;

        // Create CloudProvider referencing the credentials
        self.create_cloud_provider(client, CloudProviderType::AWS, "aws-credentials")
            .await
    }

    /// Create a CloudProvider CRD referencing credentials
    async fn create_cloud_provider(
        &self,
        client: &Client,
        provider_type: CloudProviderType,
        secret_name: &str,
    ) -> Result<()> {
        use kube::api::{Api, Patch, PatchParams};

        let provider_ref = &self.cluster.spec.provider_ref;
        let region = self
            .cluster
            .spec
            .provider
            .config
            .aws
            .as_ref()
            .map(|aws| aws.region.clone());

        // Only set credentials_secret_ref if a secret name is provided
        let credentials_secret_ref = if secret_name.is_empty() {
            None
        } else {
            Some(SecretRef {
                name: secret_name.to_string(),
                namespace: "lattice-system".to_string(),
            })
        };

        let mut cloud_provider = CloudProvider::new(
            provider_ref,
            CloudProviderSpec {
                provider_type,
                region,
                credentials_secret_ref,
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        );
        cloud_provider.metadata.namespace = Some("lattice-system".to_string());

        let api: Api<CloudProvider> = Api::namespaced(client.clone(), "lattice-system");
        api.patch(
            provider_ref,
            &PatchParams::apply("lattice-cli").force(),
            &Patch::Apply(&cloud_provider),
        )
        .await
        .map_err(|e| Error::command_failed(format!("Failed to create CloudProvider: {}", e)))?;

        info!("Created CloudProvider '{}'", provider_ref);
        Ok(())
    }

    async fn pivot_capi_resources(&self) -> Result<()> {
        let namespace = self.capi_namespace();
        let bootstrap_kubeconfig = self.bootstrap_kubeconfig_path();
        let mgmt_kubeconfig = self.kubeconfig_path();
        let bootstrap_client = self.bootstrap_client().await?;

        // Wait for CAPI CRDs on target cluster
        info!("Waiting for CAPI CRDs on management cluster...");
        let mgmt_client = self.management_client().await?;
        kube_utils::wait_for_crd(
            &mgmt_client,
            "clusters.cluster.x-k8s.io",
            Duration::from_secs(300),
        )
        .await
        .cmd_err()?;

        // Wait for all machines to be provisioned
        info!("Waiting for all machines to be provisioned...");
        let start = Instant::now();
        loop {
            if start.elapsed() > Duration::from_secs(600) {
                return Err(Error::command_failed(
                    "Timeout waiting for machines to be provisioned",
                ));
            }

            let phases = kube_utils::get_machine_phases(&bootstrap_client, &namespace)
                .await
                .cmd_err()?;

            let all_running = !phases.is_empty() && phases.iter().all(|p| p == "Running");
            if all_running {
                info!("All machines are Running");
                break;
            }
            info!("Machine phases: {}", phases.join(" "));

            tokio::time::sleep(Duration::from_secs(10)).await;
        }

        // Move CAPI resources from bootstrap to management cluster
        info!("Moving CAPI resources from bootstrap to management cluster...");
        move_to_kubeconfig(
            &bootstrap_kubeconfig,
            &mgmt_kubeconfig,
            &namespace,
            self.cluster_name(),
        )
        .await
        .cmd_err()
    }

    async fn run_clusterctl(&self, args: &[&str], kubeconfig: &Path) -> Result<()> {
        let mut command = Command::new("clusterctl");
        command
            .args(args)
            .env("KUBECONFIG", kubeconfig)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn()?;

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        // Spawn tasks to read stdout and stderr concurrently
        let stdout_task = tokio::spawn(async move {
            let mut lines_out = Vec::new();
            if let Some(stdout) = stdout {
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    info!("{}", line);
                    lines_out.push(line);
                }
            }
            lines_out
        });

        let stderr_task = tokio::spawn(async move {
            let mut lines_err = Vec::new();
            if let Some(stderr) = stderr {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    lines_err.push(line);
                }
            }
            lines_err
        });

        let status = child.wait().await?;
        let _ = stdout_task.await;
        let stderr_lines = stderr_task.await.unwrap_or_default();

        if !status.success() {
            let stderr_output = stderr_lines.join("\n");
            return Err(Error::command_failed(format!(
                "clusterctl {} failed: {}",
                args.join(" "),
                stderr_output
            )));
        }

        Ok(())
    }
}

/// Get LatticeCluster phase using dynamic API
async fn get_latticecluster_phase(client: &Client, name: &str) -> Result<String> {
    use kube::api::{Api, DynamicObject};
    use kube::discovery::ApiResource;

    let ar = ApiResource {
        group: "lattice.dev".to_string(),
        version: "v1alpha1".to_string(),
        kind: "LatticeCluster".to_string(),
        api_version: "lattice.dev/v1alpha1".to_string(),
        plural: "latticeclusters".to_string(),
    };

    let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);

    match api.get(name).await {
        Ok(cluster) => {
            let phase = cluster
                .data
                .get("status")
                .and_then(|s| s.get("phase"))
                .and_then(|p| p.as_str())
                .unwrap_or("Pending");
            Ok(phase.to_string())
        }
        Err(kube::Error::Api(e)) if e.code == 404 => Ok("Pending".to_string()),
        Err(e) => Err(Error::command_failed(format!(
            "Failed to get LatticeCluster {}: {}",
            name, e
        ))),
    }
}

/// Add bootstrap cluster environment variables to a deployment.
fn add_bootstrap_env(deployment_json: &str, provider: &str, provider_ref: &str) -> String {
    add_deployment_env(
        deployment_json,
        &[
            ("LATTICE_BOOTSTRAP_CLUSTER", "true"),
            ("LATTICE_PROVIDER", provider),
            ("LATTICE_PROVIDER_REF", provider_ref),
        ],
    )
}

/// Add environment variables to a deployment JSON.
/// Only adds variables that don't already exist.
fn add_deployment_env(deployment_json: &str, vars: &[(&str, &str)]) -> String {
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

        for (name, value_str) in vars {
            if !env
                .iter()
                .any(|e| e.get("name").and_then(|n| n.as_str()) == Some(*name))
            {
                env.push(serde_json::json!({"name": *name, "value": *value_str}));
            }
        }
    }

    serde_json::to_string(&value).unwrap_or_else(|_| deployment_json.to_string())
}

pub async fn run(args: InstallArgs) -> Result<()> {
    let installer = Installer::from_args(&args).await?;

    if args.dry_run {
        info!("Dry run for cluster: {}", installer.cluster_name());
        info!("Provider: {}", installer.provider());
        info!("1. Create bootstrap kind cluster");
        info!("2. Deploy Lattice operator (installs CRDs, CAPI)");
        info!("3. Create CloudProvider and credentials");
        info!("4. Apply LatticeCluster: {}", args.config_file.display());
        info!("5. Wait for cluster provisioning");
        info!("6. Apply bootstrap manifests to management cluster");
        info!("7. Pivot CAPI resources to make cluster self-managing");
        info!("8. Delete bootstrap cluster");
        if let Some(out) = &args.kubeconfig_out {
            info!("9. Write kubeconfig to: {}", out.display());
        }
        return Ok(());
    }

    installer.run().await?;

    // Copy kubeconfig to output path if specified
    if let Some(out) = &args.kubeconfig_out {
        let src = installer.kubeconfig_path();
        tokio::fs::copy(&src, out).await?;
        info!("Kubeconfig written to: {}", out.display());
    }

    Ok(())
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
    fn test_add_bootstrap_env_adds_all_env_vars() {
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

        let result = add_bootstrap_env(deployment, "proxmox", "proxmox");
        let parsed: serde_json::Value =
            serde_json::from_str(&result).expect("result should be valid JSON");

        let env = parsed
            .pointer("/spec/template/spec/containers/0/env")
            .expect("env path should exist in deployment")
            .as_array()
            .expect("env should be an array");

        assert!(env.iter().any(|e| {
            e.get("name").and_then(|n| n.as_str()) == Some("LATTICE_BOOTSTRAP_CLUSTER")
                && e.get("value").and_then(|v| v.as_str()) == Some("true")
        }));

        assert!(env.iter().any(|e| {
            e.get("name").and_then(|n| n.as_str()) == Some("LATTICE_PROVIDER")
                && e.get("value").and_then(|v| v.as_str()) == Some("proxmox")
        }));

        assert!(env.iter().any(|e| {
            e.get("name").and_then(|n| n.as_str()) == Some("LATTICE_PROVIDER_REF")
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

        let result = add_bootstrap_env(deployment, "docker", "docker");
        let parsed: serde_json::Value =
            serde_json::from_str(&result).expect("result should be valid JSON");

        let env = parsed
            .pointer("/spec/template/spec/containers/0/env")
            .expect("env path should exist in deployment")
            .as_array()
            .expect("env should be an array");

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
    fn test_add_deployment_env_invalid_json() {
        let invalid = "not json";
        let result = add_deployment_env(invalid, &[("TEST", "value")]);
        assert_eq!(result, invalid);
    }

    #[test]
    fn test_rewrite_kubeconfig_server_yaml() {
        let kubeconfig = r#"apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTg==
    server: https://10.0.0.1:6443
  name: my-cluster
contexts:
- context:
    cluster: my-cluster
    user: admin
  name: my-context
current-context: my-context
users:
- name: admin
  user:
    client-certificate-data: LS0tLS1CRUdJTg==
"#;

        let new_server = "https://127.0.0.1:12345";

        // Parse and update using the same logic as rewrite_docker_kubeconfig
        let mut config: serde_yaml::Value =
            serde_yaml::from_str(kubeconfig).expect("kubeconfig should be valid YAML");

        if let Some(clusters) = config.get_mut("clusters").and_then(|c| c.as_sequence_mut()) {
            for cluster in clusters {
                if let Some(cluster_data) = cluster.get_mut("cluster") {
                    if let Some(server) = cluster_data.get_mut("server") {
                        *server = serde_yaml::Value::String(new_server.to_string());
                    }
                }
            }
        }

        let result = serde_yaml::to_string(&config).expect("config should serialize to YAML");

        // Verify the server was updated
        let parsed: serde_yaml::Value =
            serde_yaml::from_str(&result).expect("result should be valid YAML");
        let server = parsed["clusters"][0]["cluster"]["server"]
            .as_str()
            .expect("server should be a string");
        assert_eq!(server, new_server);

        // Verify other fields are preserved
        let ca_data = parsed["clusters"][0]["cluster"]["certificate-authority-data"]
            .as_str()
            .expect("certificate-authority-data should be a string");
        assert_eq!(ca_data, "LS0tLS1CRUdJTg==");
    }

    #[test]
    fn test_rewrite_kubeconfig_multiple_clusters() {
        let kubeconfig = r#"apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://10.0.0.1:6443
  name: cluster-1
- cluster:
    server: https://10.0.0.2:6443
  name: cluster-2
"#;

        let new_server = "https://127.0.0.1:12345";

        let mut config: serde_yaml::Value =
            serde_yaml::from_str(kubeconfig).expect("kubeconfig should be valid YAML");

        if let Some(clusters) = config.get_mut("clusters").and_then(|c| c.as_sequence_mut()) {
            for cluster in clusters {
                if let Some(cluster_data) = cluster.get_mut("cluster") {
                    if let Some(server) = cluster_data.get_mut("server") {
                        *server = serde_yaml::Value::String(new_server.to_string());
                    }
                }
            }
        }

        let result = serde_yaml::to_string(&config).expect("config should serialize to YAML");
        let parsed: serde_yaml::Value =
            serde_yaml::from_str(&result).expect("result should be valid YAML");

        // Both clusters should be updated
        let server1 = parsed["clusters"][0]["cluster"]["server"]
            .as_str()
            .expect("server1 should be a string");
        let server2 = parsed["clusters"][1]["cluster"]["server"]
            .as_str()
            .expect("server2 should be a string");
        assert_eq!(server1, new_server);
        assert_eq!(server2, new_server);
    }

    #[test]
    fn test_capi_namespace_format() {
        // Test the naming conventions directly
        let cluster_name = "test-cluster";
        assert_eq!(format!("capi-{}", cluster_name), "capi-test-cluster");
        assert_eq!(
            format!("{}-kubeconfig", cluster_name),
            "test-cluster-kubeconfig"
        );
    }
}
