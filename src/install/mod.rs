//! Lattice Installer - Bootstrap management cluster creation
//!
//! This module handles the installation flow for creating a new Lattice management cluster:
//!
//! 1. Create a temporary kind bootstrap cluster
//! 2. Install CAPI providers on the bootstrap cluster
//! 3. Deploy Lattice operator to the bootstrap cluster
//! 4. Create LatticeCluster CRD for the management cluster (from config file)
//! 5. Wait for management cluster to be provisioned
//! 6. Apply bootstrap manifests to management cluster (CAPI, Lattice, same config file)
//! 7. Pivot CAPI resources via clusterctl move
//! 8. Delete the kind bootstrap cluster
//!
//! The cluster configuration is read from a LatticeCluster YAML file, making it
//! GitOps-friendly and allowing users to version control their management cluster spec.
//!
//! # Example
//!
//! ```no_run
//! use lattice::install::{InstallConfig, Installer};
//! use std::path::PathBuf;
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = InstallConfig {
//!         cluster_config_path: PathBuf::from("clusters/mgmt/cluster.yaml"),
//!         cluster_config_content: std::fs::read_to_string("clusters/mgmt/cluster.yaml").unwrap(),
//!         image: "ghcr.io/lattice/lattice:latest".to_string(),
//!         keep_bootstrap_on_failure: false,
//!         timeout: Duration::from_secs(1200),
//!         registry_credentials: None,
//!         bootstrap_override: None,
//!     };
//!
//!     let installer = Installer::new(config).unwrap();
//!     installer.run().await.unwrap();
//! }
//! ```

use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::crd::LatticeCluster;

/// Configuration for the Lattice installer
#[derive(Debug, Clone)]
pub struct InstallConfig {
    /// Path to the LatticeCluster YAML configuration file
    pub cluster_config_path: PathBuf,
    /// Raw YAML content of the cluster configuration
    /// This is applied as-is to both bootstrap and management clusters
    pub cluster_config_content: String,
    /// Lattice container image
    pub image: String,
    /// Keep bootstrap cluster on failure
    pub keep_bootstrap_on_failure: bool,
    /// Installation timeout
    pub timeout: Duration,
    /// Optional registry credentials (dockerconfigjson format) for pulling images
    pub registry_credentials: Option<String>,
    /// Optional bootstrap provider override (CLI can override config file)
    pub bootstrap_override: Option<crate::crd::BootstrapProvider>,
}

/// Errors that can occur during installation
#[derive(Debug, Error)]
pub enum InstallError {
    /// A prerequisite tool is missing
    #[error("prerequisite not found: {tool} - {hint}")]
    PrerequisiteNotFound {
        /// The tool that was not found
        tool: String,
        /// Hint for how to install it
        hint: String,
    },

    /// A command failed to execute
    #[error("command failed: {command} - {message}")]
    CommandFailed {
        /// The command that failed
        command: String,
        /// Error message
        message: String,
    },

    /// Installation timed out
    #[error("installation timed out after {0:?}")]
    Timeout(Duration),

    /// Kubernetes API error
    #[error("kubernetes error: {0}")]
    Kubernetes(String),

    /// Invalid cluster configuration
    #[error("invalid cluster config: {0}")]
    InvalidConfig(String),

    /// I/O error
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// The Lattice installer
#[derive(Debug)]
pub struct Installer {
    config: InstallConfig,
    /// Parsed LatticeCluster from config file
    cluster: LatticeCluster,
    /// Cluster name (extracted during validation)
    cluster_name: String,
}

impl Installer {
    /// Create a new installer with the given configuration
    ///
    /// Parses the LatticeCluster from the config content and validates it.
    /// If a bootstrap override is provided, it will override the bootstrap
    /// provider in the cluster spec.
    pub fn new(config: InstallConfig) -> Result<Self, InstallError> {
        let mut cluster: LatticeCluster = serde_yaml::from_str(&config.cluster_config_content)
            .map_err(|e| {
                InstallError::InvalidConfig(format!("failed to parse LatticeCluster YAML: {}", e))
            })?;

        // Apply bootstrap override if provided (CLI takes precedence over config file)
        if let Some(bootstrap) = &config.bootstrap_override {
            cluster.spec.provider.kubernetes.bootstrap = bootstrap.clone();
        }

        // Validate required fields and extract cluster name
        let cluster_name = cluster.metadata.name.clone().ok_or_else(|| {
            InstallError::InvalidConfig("LatticeCluster must have metadata.name".to_string())
        })?;

        Ok(Self {
            config,
            cluster,
            cluster_name,
        })
    }

    /// Get the cluster name from the parsed config
    fn cluster_name(&self) -> &str {
        &self.cluster_name
    }

    /// Get the provider type from the parsed config
    fn provider(&self) -> &crate::crd::ProviderType {
        &self.cluster.spec.provider.type_
    }

    /// Get the clusterctl infrastructure provider argument
    fn provider_arg(&self) -> String {
        use crate::crd::ProviderType;
        match self.provider() {
            ProviderType::Docker => "--infrastructure=docker".to_string(),
            ProviderType::Aws => "--infrastructure=aws".to_string(),
            ProviderType::Gcp => "--infrastructure=gcp".to_string(),
            ProviderType::Azure => "--infrastructure=azure".to_string(),
        }
    }

    /// Run the installation
    pub async fn run(&self) -> Result<(), InstallError> {
        let start = Instant::now();

        // Check prerequisites
        self.check_prerequisites().await?;

        // Create kind bootstrap cluster
        let bootstrap_result = self.run_bootstrap().await;

        // Cleanup on failure if configured
        if bootstrap_result.is_err() && !self.config.keep_bootstrap_on_failure {
            println!("\n[Cleanup] Deleting bootstrap cluster due to failure...");
            let _ = self.delete_kind_cluster().await;
        }

        bootstrap_result?;

        println!("\n=== Installation complete ===");
        println!("Duration: {:?}", start.elapsed());
        println!(
            "\nManagement cluster '{}' is now self-managing.",
            self.cluster_name()
        );

        Ok(())
    }

    /// Check that all required tools are installed
    async fn check_prerequisites(&self) -> Result<(), InstallError> {
        println!("=== Checking prerequisites ===\n");

        // clusterctl IS required on the host for the one-time bootstrap pivot
        // After initial install, the operator handles all subsequent pivots via agents
        let tools = [
            ("docker", "Install Docker: https://docs.docker.com/get-docker/"),
            ("kind", "Install kind: https://kind.sigs.k8s.io/docs/user/quick-start/#installation"),
            ("kubectl", "Install kubectl: https://kubernetes.io/docs/tasks/tools/"),
            ("clusterctl", "Install clusterctl: https://cluster-api.sigs.k8s.io/user/quick-start#install-clusterctl"),
        ];

        for (tool, hint) in tools {
            print!("  Checking {}... ", tool);
            if self.check_tool(tool).await? {
                println!("OK");
            } else {
                println!("NOT FOUND");
                return Err(InstallError::PrerequisiteNotFound {
                    tool: tool.to_string(),
                    hint: hint.to_string(),
                });
            }
        }

        // Check clusterctl version
        print!("  Checking clusterctl version... ");
        let version_output = self
            .run_command("clusterctl", &["version", "-o", "short"])
            .await?;
        println!("{}", version_output.trim());

        println!();
        Ok(())
    }

    /// Check if a tool is available
    async fn check_tool(&self, tool: &str) -> Result<bool, InstallError> {
        let result = Command::new("which").arg(tool).output().await?;
        Ok(result.status.success())
    }

    /// Run the bootstrap process
    async fn run_bootstrap(&self) -> Result<(), InstallError> {
        // Phase 1: Create kind cluster
        println!("[Phase 1] Creating kind bootstrap cluster...\n");
        self.create_kind_cluster().await?;

        // Phase 2: Deploy Lattice operator (it installs CAPI when it sees a LatticeCluster)
        println!("\n[Phase 2] Deploying Lattice operator...\n");
        self.deploy_lattice_operator().await?;

        // Phase 3: Create management cluster CR (operator will install CAPI and provision)
        println!("\n[Phase 3] Creating management cluster LatticeCluster CR...\n");
        self.create_management_cluster_crd().await?;

        // Phase 4: Wait for management cluster
        println!("\n[Phase 4] Waiting for management cluster to be provisioned...\n");
        self.wait_for_management_cluster().await?;

        // Phase 5: Apply bootstrap to management cluster
        println!("\n[Phase 5] Applying bootstrap manifests to management cluster...\n");
        self.apply_bootstrap_to_management().await?;

        // Phase 6: Pivot CAPI resources
        println!("\n[Phase 6] Pivoting CAPI resources to management cluster...\n");
        self.pivot_capi_resources().await?;

        // Phase 7: Delete bootstrap cluster
        println!("\n[Phase 7] Deleting bootstrap cluster...\n");
        self.delete_kind_cluster().await?;

        Ok(())
    }

    /// Create the kind bootstrap cluster
    async fn create_kind_cluster(&self) -> Result<(), InstallError> {
        // Delete existing cluster if present
        println!("  Deleting existing bootstrap cluster if present...");
        let _ = Command::new("kind")
            .args(["delete", "cluster", "--name", "lattice-bootstrap"])
            .output()
            .await;

        // Create kind config with FIPS-compatible TLS cipher suites
        let kind_config = r#"kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: /var/run/docker.sock
    containerPath: /var/run/docker.sock
  extraPortMappings:
  - containerPort: 30443
    hostPort: 30443
    protocol: TCP
  - containerPort: 30051
    hostPort: 30051
    protocol: TCP
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        tls-cipher-suites: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
"#;

        println!("  Creating kind cluster 'lattice-bootstrap'...");
        let mut child = Command::new("kind")
            .args([
                "create",
                "cluster",
                "--name",
                "lattice-bootstrap",
                "--config",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Write config to stdin
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin.write_all(kind_config.as_bytes()).await?;
        }

        let output = child.wait_with_output().await?;
        if !output.status.success() {
            return Err(InstallError::CommandFailed {
                command: "kind create cluster".to_string(),
                message: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        // Wait for nodes to be ready
        println!("  Waiting for nodes to be ready...");
        self.run_command(
            "kubectl",
            &[
                "wait",
                "--for=condition=Ready",
                "nodes",
                "--all",
                "--timeout=120s",
            ],
        )
        .await?;

        println!("  Bootstrap cluster created successfully");
        Ok(())
    }

    /// Delete the kind bootstrap cluster
    async fn delete_kind_cluster(&self) -> Result<(), InstallError> {
        println!("  Deleting kind cluster 'lattice-bootstrap'...");
        self.run_command(
            "kind",
            &["delete", "cluster", "--name", "lattice-bootstrap"],
        )
        .await?;
        println!("  Bootstrap cluster deleted");
        Ok(())
    }

    /// Deploy Lattice operator to the bootstrap cluster
    async fn deploy_lattice_operator(&self) -> Result<(), InstallError> {
        use crate::bootstrap::{DefaultManifestGenerator, ManifestGenerator};

        // Get operator manifests from the same generator used everywhere
        let generator =
            DefaultManifestGenerator::new().map_err(|e| InstallError::CommandFailed {
                command: "generate operator manifests".to_string(),
                message: e.to_string(),
            })?;

        // Generate all manifests but only use operator ones (JSON format)
        // Bootstrap kind cluster already has its own CNI, we don't need Cilium
        // Set cluster_name to "lattice-installer" - this is the bootstrap cluster, not the mgmt cluster
        let all_manifests = generator.generate(
            &self.config.image,
            self.config.registry_credentials.as_deref(),
            Some("lattice-installer"),
            None,
        );
        let operator_manifests: Vec<String> = all_manifests
            .iter()
            .filter(|m| m.starts_with("{"))
            .map(|s| {
                if crate::fips::is_deployment(s) {
                    // For bootstrap cluster:
                    // 1. Relax FIPS to fips140=on (not =only) for non-FIPS kind API server
                    // 2. Set LATTICE_ROOT_INSTALL=true to skip bootstrap script generation
                    let with_fips = crate::fips::add_fips_relax_env(s);
                    crate::fips::add_root_install_env(&with_fips)
                } else {
                    s.clone()
                }
            })
            .collect();

        // Apply operator manifests (namespace, serviceaccount, clusterrolebinding, deployment)
        println!("  Deploying Lattice operator...");
        for manifest in &operator_manifests {
            self.kubectl_apply(manifest, None).await?;
        }

        println!("  Lattice operator deployed successfully");
        Ok(())
    }

    /// Create ClusterResourceSet for Cilium CNI + Lattice operator installation
    ///
    /// Uses DefaultManifestGenerator - same code path as runtime cluster provisioning
    /// via webhook. CRS applies these to new clusters. Every cluster runs the same
    /// deployment - the controller reads LatticeCluster CRD to determine behavior.
    async fn create_bootstrap_crs(&self) -> Result<(), InstallError> {
        use crate::bootstrap::{generate_all_manifests, DefaultManifestGenerator, ManifestConfig};

        // Get all manifests using the same function as bootstrap webhook
        let generator =
            DefaultManifestGenerator::new().map_err(|e| InstallError::CommandFailed {
                command: "generate bootstrap manifests".to_string(),
                message: e.to_string(),
            })?;

        // Generate all manifests (Cilium YAML + operator JSON + LB-IPAM + CiliumNetworkPolicy)
        // Pass cluster name and provider so management cluster's operator knows its identity
        // Management cluster has no parent, so pass None for parent_host
        // relax_fips is based on bootstrap provider: kubeadm clusters need FIPS relaxation
        // because kubeadm's API server uses non-FIPS cipher suites (X25519)
        let cluster_name = self.cluster.metadata.name.as_deref();
        let provider_str = self.cluster.spec.provider.type_.to_string();
        let config = ManifestConfig {
            image: &self.config.image,
            registry_credentials: self.config.registry_credentials.as_deref(),
            networking: self.cluster.spec.networking.as_ref(),
            cluster_name,
            provider: Some(&provider_str),
            parent_host: None, // Cells have no parent
            parent_grpc_port: crate::DEFAULT_GRPC_PORT,
            relax_fips: self
                .cluster
                .spec
                .provider
                .kubernetes
                .bootstrap
                .needs_fips_relax(),
        };
        let all_manifests = generate_all_manifests(&generator, &config);

        // Split into YAML (Cilium + LB-IPAM) and JSON (operator)
        // YAML starts with "---" or "apiVersion:", JSON starts with "{"
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

        // Join YAML manifests with separator
        let cilium_yaml = yaml_manifests.join("\n---\n");

        // Create ConfigMaps
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

        // Create operator ConfigMap with each manifest in its own key
        // CRS applies each key as a separate manifest
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

        // Create ClusterResourceSet that matches the management cluster
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

        // Ensure namespace exists
        let _ = self
            .run_command("kubectl", &["create", "namespace", &namespace])
            .await;

        // Apply ConfigMaps (these don't need CRS CRD)
        self.kubectl_apply(&cilium_configmap, None).await?;
        self.kubectl_apply(&operator_configmap, None).await?;

        // Apply CRS with retry (waits for CAPI to be installed by operator)
        self.kubectl_apply_with_retry(&crs, None, Duration::from_secs(120))
            .await?;

        Ok(())
    }

    /// Create the management cluster LatticeCluster CRD
    ///
    /// Uses the actual config file content - no hardcoding.
    /// The same file is used on bootstrap and management clusters.
    /// Retries until the CRD is installed by the operator.
    async fn create_management_cluster_crd(&self) -> Result<(), InstallError> {
        println!(
            "  Applying LatticeCluster CR for '{}' from {:?}...",
            self.cluster_name(),
            self.config.cluster_config_path
        );

        self.kubectl_apply_with_retry(
            &self.config.cluster_config_content,
            None,
            Duration::from_secs(120),
        )
        .await?;

        println!("  Management cluster CR created");

        // Create CRS for Cilium + operator (retries until CAPI CRDs exist)
        println!("  Creating ClusterResourceSet for bootstrap manifests...");
        self.create_bootstrap_crs().await?;

        Ok(())
    }

    /// Wait for the management cluster to be provisioned
    async fn wait_for_management_cluster(&self) -> Result<(), InstallError> {
        let start = Instant::now();
        let timeout = Duration::from_secs(600); // 10 minutes

        loop {
            if start.elapsed() > timeout {
                return Err(InstallError::Timeout(timeout));
            }

            // Get cluster status
            let output = self
                .run_command(
                    "kubectl",
                    &[
                        "get",
                        "latticecluster",
                        self.cluster_name(),
                        "-o",
                        "jsonpath={.status.phase}",
                    ],
                )
                .await
                .unwrap_or_default();

            let phase = output.trim();
            println!(
                "  Cluster phase: {}",
                if phase.is_empty() { "Pending" } else { phase }
            );

            match phase {
                "Ready" | "Pivoting" => {
                    println!("  Management cluster is ready for pivot");
                    break;
                }
                "Failed" => {
                    return Err(InstallError::CommandFailed {
                        command: "wait for cluster".to_string(),
                        message: "Cluster provisioning failed".to_string(),
                    });
                }
                _ => {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            }
        }

        // Wait for kubeconfig secret
        println!("  Waiting for kubeconfig secret...");
        let namespace = format!("capi-{}", self.cluster_name());
        let secret_name = format!("{}-kubeconfig", self.cluster_name());

        loop {
            if start.elapsed() > timeout {
                return Err(InstallError::Timeout(timeout));
            }

            let result = self
                .run_command(
                    "kubectl",
                    &["get", "secret", &secret_name, "-n", &namespace],
                )
                .await;

            if result.is_ok() {
                println!("  Kubeconfig secret found");
                break;
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        Ok(())
    }

    /// Apply bootstrap manifests to the management cluster
    ///
    /// This installs everything the management cluster needs to be self-managing:
    /// - CAPI providers (same as bootstrap cluster)
    /// - Lattice CRD
    /// - Lattice operator
    /// - Self-referential LatticeCluster CRD
    ///
    /// NOTE: This works for ANY provider (docker, aws, gcp, azure) because:
    /// - The management cluster's API server is reachable (has public IP or LB)
    /// - We connect TO the management cluster using its kubeconfig
    /// - No inbound connection from management to bootstrap is needed
    async fn apply_bootstrap_to_management(&self) -> Result<(), InstallError> {
        // Get kubeconfig for management cluster
        let namespace = format!("capi-{}", self.cluster_name());
        let secret_name = format!("{}-kubeconfig", self.cluster_name());

        let kubeconfig_b64 = self
            .run_command(
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
            )
            .await?;

        // Decode kubeconfig
        let mut kubeconfig = String::from_utf8(
            base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                kubeconfig_b64.trim(),
            )
            .map_err(|e| InstallError::CommandFailed {
                command: "decode kubeconfig".to_string(),
                message: e.to_string(),
            })?,
        )
        .map_err(|e| InstallError::CommandFailed {
            command: "decode kubeconfig".to_string(),
            message: e.to_string(),
        })?;

        // For Docker provider, rewrite the server URL to use localhost with the LB's exposed port
        // The kubeconfig has an internal Docker IP that's not accessible from the host
        if self.cluster.spec.provider.type_ == crate::crd::ProviderType::Docker {
            let lb_container = format!("{}-lb", self.cluster_name());
            let port_output = self
                .run_command("docker", &["port", &lb_container, "6443"])
                .await
                .ok();

            if let Some(port_mapping) = port_output {
                // Output is like "0.0.0.0:55382" or "127.0.0.1:55382"
                if let Some(port) = port_mapping.trim().split(':').next_back() {
                    let localhost_url = format!("https://127.0.0.1:{}", port);
                    // Replace the server URL using regex-like replacement
                    if let Some(start) = kubeconfig.find("server: https://") {
                        if let Some(end) = kubeconfig[start..].find('\n') {
                            let old_server = &kubeconfig[start..start + end];
                            kubeconfig = kubeconfig
                                .replace(old_server, &format!("server: {}", localhost_url));
                            println!("  Rewrote kubeconfig server to {}", localhost_url);
                        }
                    }
                }
            }
        }

        let kubeconfig_path = format!("/tmp/{}-kubeconfig", self.cluster_name());
        tokio::fs::write(&kubeconfig_path, &kubeconfig).await?;
        println!("  Kubeconfig saved to {}", kubeconfig_path);

        // Wait for management cluster API server
        println!("  Waiting for management cluster API server...");
        let start = Instant::now();
        loop {
            if start.elapsed() > Duration::from_secs(300) {
                return Err(InstallError::Timeout(Duration::from_secs(300)));
            }

            let result = Command::new("kubectl")
                .args(["--kubeconfig", &kubeconfig_path, "get", "nodes"])
                .output()
                .await?;

            if result.status.success() {
                println!("  Management cluster API server is ready");
                break;
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        // Wait for nodes to be ready (Cilium CNI was installed via ClusterResourceSet)
        println!("  Waiting for management cluster nodes to be ready...");
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

        // Install CAPI on management cluster (required for pivot)
        // This is the ONE-TIME bootstrap install; after this, the operator handles CAPI
        println!("  Installing CAPI on management cluster...");
        let provider_arg = self.provider_arg();
        self.run_command_with_output_env(
            "clusterctl",
            &["init", &provider_arg, "--wait-providers"],
            &[("KUBECONFIG", &kubeconfig_path)],
        )
        .await?;

        // Wait for CAPI controllers on management cluster
        println!("  Waiting for CAPI controllers on management cluster...");
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

        // Wait for Lattice operator to be ready (CRS installed it)
        println!("  Waiting for Lattice operator on management cluster...");
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

        // Apply the same LatticeCluster CR to the management cluster
        // This makes it self-referential - the cluster manages itself
        // Retries until the CRD is installed by the operator
        println!(
            "  Applying LatticeCluster CR from {:?}...",
            self.config.cluster_config_path
        );
        self.kubectl_apply_with_retry(
            &self.config.cluster_config_content,
            Some(&kubeconfig_path),
            Duration::from_secs(120),
        )
        .await?;

        println!("  Management cluster bootstrap complete");
        Ok(())
    }

    /// Pivot CAPI resources to management cluster
    ///
    /// This is the ONE-TIME bootstrap pivot using clusterctl move.
    /// After initial install, all subsequent pivots are handled by the operator via agents.
    async fn pivot_capi_resources(&self) -> Result<(), InstallError> {
        let namespace = format!("capi-{}", self.cluster_name());
        let kubeconfig_path = format!("/tmp/{}-kubeconfig", self.cluster_name());

        // Wait for CAPI CRDs on management cluster
        println!("  Waiting for CAPI CRDs on management cluster...");
        let start = Instant::now();
        loop {
            if start.elapsed() > Duration::from_secs(300) {
                return Err(InstallError::Timeout(Duration::from_secs(300)));
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
                println!("  CAPI CRDs ready on management cluster");
                break;
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        // Run clusterctl move (ONE-TIME bootstrap pivot)
        println!("  Running clusterctl move...");
        self.run_command_with_output(
            "clusterctl",
            &[
                "move",
                "--to-kubeconfig",
                &kubeconfig_path,
                "--namespace",
                &namespace,
            ],
        )
        .await?;

        println!("  CAPI resources pivoted successfully");
        Ok(())
    }

    /// Run a command and return stdout
    async fn run_command(&self, cmd: &str, args: &[&str]) -> Result<String, InstallError> {
        let output = Command::new(cmd).args(args).output().await?;

        if !output.status.success() {
            return Err(InstallError::CommandFailed {
                command: format!("{} {}", cmd, args.join(" ")),
                message: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Run a command and stream output to stdout
    async fn run_command_with_output(&self, cmd: &str, args: &[&str]) -> Result<(), InstallError> {
        let mut child = Command::new(cmd)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Capture stderr for error reporting
        let stderr_handle = child.stderr.take();

        // Stream stdout
        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();
            while let Some(line) = lines.next_line().await? {
                println!("    {}", line);
            }
        }

        let status = child.wait().await?;
        if !status.success() {
            // Read stderr for the error message
            let stderr_msg = if let Some(stderr) = stderr_handle {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                let mut stderr_output = Vec::new();
                while let Some(line) = lines.next_line().await.ok().flatten() {
                    stderr_output.push(line);
                }
                stderr_output.join("\n")
            } else {
                "command failed".to_string()
            };

            return Err(InstallError::CommandFailed {
                command: format!("{} {}", cmd, args.join(" ")),
                message: stderr_msg,
            });
        }

        Ok(())
    }

    /// Run a command with environment variables and stream output to stdout
    async fn run_command_with_output_env(
        &self,
        cmd: &str,
        args: &[&str],
        env: &[(&str, &str)],
    ) -> Result<(), InstallError> {
        let mut command = Command::new(cmd);
        command
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        for (key, value) in env {
            command.env(key, value);
        }

        let mut child = command.spawn()?;

        // Capture stderr for error reporting
        let stderr_handle = child.stderr.take();

        // Stream stdout
        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();
            while let Some(line) = lines.next_line().await? {
                println!("    {}", line);
            }
        }

        let status = child.wait().await?;
        if !status.success() {
            // Read stderr for the error message
            let stderr_msg = if let Some(stderr) = stderr_handle {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                let mut stderr_output = Vec::new();
                while let Some(line) = lines.next_line().await.ok().flatten() {
                    stderr_output.push(line);
                }
                stderr_output.join("\n")
            } else {
                "command failed".to_string()
            };

            return Err(InstallError::CommandFailed {
                command: format!("{} {}", cmd, args.join(" ")),
                message: stderr_msg,
            });
        }

        Ok(())
    }

    /// Run a command with a specific kubeconfig
    async fn run_command_with_kubeconfig(
        &self,
        cmd: &str,
        args: &[&str],
        kubeconfig: &str,
    ) -> Result<String, InstallError> {
        let mut full_args = vec!["--kubeconfig", kubeconfig];
        full_args.extend(args);

        let output = Command::new(cmd).args(&full_args).output().await?;

        if !output.status.success() {
            return Err(InstallError::CommandFailed {
                command: format!("{} {}", cmd, full_args.join(" ")),
                message: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Apply a manifest using kubectl with optional kubeconfig
    async fn kubectl_apply(
        &self,
        manifest: &str,
        kubeconfig: Option<&str>,
    ) -> Result<(), InstallError> {
        let mut args = Vec::new();
        if let Some(kc) = kubeconfig {
            args.extend(["--kubeconfig", kc]);
        }
        args.extend(["apply", "-f", "-"]);

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
            return Err(InstallError::CommandFailed {
                command: "kubectl apply".to_string(),
                message: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        Ok(())
    }

    /// Apply a manifest, retrying until the CRD is established
    async fn kubectl_apply_with_retry(
        &self,
        manifest: &str,
        kubeconfig: Option<&str>,
        timeout: Duration,
    ) -> Result<(), InstallError> {
        let start = Instant::now();
        loop {
            if start.elapsed() > timeout {
                return Err(InstallError::Timeout(timeout));
            }

            match self.kubectl_apply(manifest, kubeconfig).await {
                Ok(()) => return Ok(()),
                Err(_) => {
                    println!("  Waiting for CRD to be established...");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cluster_yaml() -> String {
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: test-cluster
spec:
  provider:
    type: docker
    kubernetes:
      version: "1.32.0"
  nodes:
    controlPlane: 1
    workers: 2
  networking:
    default:
      cidr: "172.18.255.100/32"
  endpoints:
    host: 172.18.255.100
    grpcPort: 50051
    bootstrapPort: 8443
    service:
      type: LoadBalancer
"#
        .to_string()
    }

    fn sample_config() -> InstallConfig {
        InstallConfig {
            cluster_config_path: PathBuf::from("test/cluster.yaml"),
            cluster_config_content: sample_cluster_yaml(),
            image: "lattice:latest".to_string(),
            keep_bootstrap_on_failure: false,
            timeout: Duration::from_secs(1200),
            registry_credentials: None,
            bootstrap_override: None,
        }
    }

    #[test]
    fn test_install_config_creation() {
        let config = sample_config();

        assert_eq!(
            config.cluster_config_path,
            PathBuf::from("test/cluster.yaml")
        );
        assert!(config.cluster_config_content.contains("test-cluster"));
    }

    #[test]
    fn test_installer_parses_cluster_config() {
        use crate::crd::ProviderType;

        let config = sample_config();
        let installer = Installer::new(config).expect("should parse valid config");

        assert_eq!(installer.cluster_name(), "test-cluster");
        assert_eq!(*installer.provider(), ProviderType::Docker);
    }

    #[test]
    fn test_installer_validates_missing_name() {
        let yaml = r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata: {}
spec:
  provider:
    type: docker
    kubernetes:
      version: "1.32.0"
  nodes:
    controlPlane: 1
    workers: 2
"#;

        let config = InstallConfig {
            cluster_config_path: PathBuf::from("test/cluster.yaml"),
            cluster_config_content: yaml.to_string(),
            image: "lattice:latest".to_string(),
            keep_bootstrap_on_failure: false,
            timeout: Duration::from_secs(1200),
            registry_credentials: None,
            bootstrap_override: None,
        };

        let result = Installer::new(config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("must have metadata.name"),
            "Expected error about missing name, got: {}",
            err
        );
    }

    #[test]
    fn test_installer_validates_invalid_yaml() {
        let config = InstallConfig {
            cluster_config_path: PathBuf::from("test/cluster.yaml"),
            cluster_config_content: "not: valid: yaml: content".to_string(),
            image: "lattice:latest".to_string(),
            keep_bootstrap_on_failure: false,
            timeout: Duration::from_secs(1200),
            registry_credentials: None,
            bootstrap_override: None,
        };

        let result = Installer::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_provider_arg() {
        let config = sample_config();
        let installer = Installer::new(config).expect("should parse valid config");

        let arg = installer.provider_arg();
        assert_eq!(arg, "--infrastructure=docker");
    }

    #[test]
    fn test_install_error_display() {
        let err = InstallError::PrerequisiteNotFound {
            tool: "kind".to_string(),
            hint: "install it".to_string(),
        };
        assert!(err.to_string().contains("kind"));

        let err = InstallError::Timeout(Duration::from_secs(60));
        assert!(err.to_string().contains("60"));

        let err = InstallError::InvalidConfig("test error".to_string());
        assert!(err.to_string().contains("test error"));
    }
}
