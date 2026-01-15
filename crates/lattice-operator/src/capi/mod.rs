//! CAPI (Cluster API) provider management
//!
//! Handles installing and upgrading CAPI providers before provisioning clusters.
//! Tracks installed provider versions to enable:
//! - Idempotent installation (skip if already installed)
//! - Version upgrades when desired version changes
//! - Missing provider detection and installation
//!
//! Always installs both kubeadm and RKE2 bootstrap/control-plane providers
//! to ensure clusterctl move works between any clusters.

use std::collections::HashMap;
use std::process::Command;

use async_trait::async_trait;
#[cfg(test)]
use mockall::automock;
use tracing::{debug, info, warn};

use crate::crd::ProviderType;
use crate::Error;

/// Provider types supported by CAPI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapiProviderType {
    /// Core CAPI provider (cluster-api)
    Core,
    /// Bootstrap provider (kubeadm, rke2)
    Bootstrap,
    /// Control plane provider (kubeadm, rke2)
    ControlPlane,
    /// Infrastructure provider (docker, aws, gcp, azure)
    Infrastructure,
}

impl std::fmt::Display for CapiProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CapiProviderType::Core => write!(f, "CoreProvider"),
            CapiProviderType::Bootstrap => write!(f, "BootstrapProvider"),
            CapiProviderType::ControlPlane => write!(f, "ControlPlaneProvider"),
            CapiProviderType::Infrastructure => write!(f, "InfrastructureProvider"),
        }
    }
}

/// Information about an installed CAPI provider
#[derive(Debug, Clone)]
pub struct InstalledProvider {
    /// Provider name (cluster-api, kubeadm, rke2, docker, etc.)
    pub name: String,
    /// Type of provider
    pub provider_type: CapiProviderType,
    /// Installed version (e.g., "v1.12.1")
    pub version: String,
    /// Kubernetes namespace where provider is installed
    pub namespace: String,
}

/// Desired provider configuration
#[derive(Debug, Clone)]
pub struct DesiredProvider {
    /// Provider name (cluster-api, kubeadm, rke2, docker, etc.)
    pub name: String,
    /// Type of provider
    pub provider_type: CapiProviderType,
    /// Desired version (e.g., "v1.12.1")
    pub version: String,
}

/// Action to take for a provider
#[derive(Debug, Clone, PartialEq)]
pub enum ProviderAction {
    /// Provider already installed at correct version
    Skip,
    /// Provider needs to be installed (not present)
    Install,
    /// Provider needs version upgrade
    Upgrade {
        /// Current installed version
        from: String,
        /// Target version to upgrade to
        to: String,
    },
}

/// Configuration for CAPI provider installation
#[derive(Debug, Clone)]
pub struct CapiProviderConfig {
    /// Infrastructure provider (docker, aws, gcp, azure)
    pub infrastructure: ProviderType,
    /// Desired CAPI core version (from versions.toml)
    pub capi_version: String,
    /// Desired RKE2 provider version (from versions.toml)
    pub rke2_version: String,
}

impl CapiProviderConfig {
    /// Create a new CAPI provider configuration
    pub fn new(infrastructure: ProviderType) -> Self {
        // Load versions from build-time constants (set by build.rs from versions.toml)
        Self {
            infrastructure,
            capi_version: env!("CAPI_VERSION").to_string(),
            rke2_version: env!("RKE2_VERSION").to_string(),
        }
    }

    /// Create config with explicit versions (for testing)
    pub fn with_versions(
        infrastructure: ProviderType,
        capi_version: String,
        rke2_version: String,
    ) -> Self {
        Self {
            infrastructure,
            capi_version,
            rke2_version,
        }
    }

    /// Get the list of desired providers based on this config
    pub fn desired_providers(&self) -> Vec<DesiredProvider> {
        let infra_name = match self.infrastructure {
            ProviderType::Docker => "docker",
            ProviderType::Proxmox => "proxmox",
            ProviderType::OpenStack => "openstack",
            ProviderType::Aws => "aws",
            ProviderType::Gcp => "gcp",
            ProviderType::Azure => "azure",
        };

        vec![
            // Core CAPI
            DesiredProvider {
                name: "cluster-api".to_string(),
                provider_type: CapiProviderType::Core,
                version: format!("v{}", self.capi_version),
            },
            // Kubeadm bootstrap
            DesiredProvider {
                name: "kubeadm".to_string(),
                provider_type: CapiProviderType::Bootstrap,
                version: format!("v{}", self.capi_version),
            },
            // Kubeadm control plane
            DesiredProvider {
                name: "kubeadm".to_string(),
                provider_type: CapiProviderType::ControlPlane,
                version: format!("v{}", self.capi_version),
            },
            // RKE2 bootstrap
            DesiredProvider {
                name: "rke2".to_string(),
                provider_type: CapiProviderType::Bootstrap,
                version: format!("v{}", self.rke2_version),
            },
            // RKE2 control plane
            DesiredProvider {
                name: "rke2".to_string(),
                provider_type: CapiProviderType::ControlPlane,
                version: format!("v{}", self.rke2_version),
            },
            // Infrastructure provider
            DesiredProvider {
                name: infra_name.to_string(),
                provider_type: CapiProviderType::Infrastructure,
                version: format!("v{}", self.capi_version),
            },
        ]
    }
}

/// Trait for installing CAPI providers
#[cfg_attr(test, automock)]
#[async_trait]
pub trait CapiInstaller: Send + Sync {
    /// Ensure CAPI providers are installed/upgraded as needed
    async fn ensure(&self, config: &CapiProviderConfig) -> Result<(), Error>;
}

/// Ensure CAPI providers are installed
pub async fn ensure_capi_installed<I: CapiInstaller + ?Sized>(
    installer: &I,
    config: &CapiProviderConfig,
) -> Result<(), Error> {
    installer.ensure(config).await
}

/// Find a helm chart by prefix in the charts directory
fn find_chart(charts_dir: &str, prefix: &str) -> Result<String, Error> {
    let dir = std::fs::read_dir(charts_dir).map_err(|e| {
        Error::capi_installation(format!("failed to read charts dir {}: {}", charts_dir, e))
    })?;

    for entry in dir.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(prefix) && name.ends_with(".tgz") {
            return Ok(entry.path().to_string_lossy().to_string());
        }
    }

    Err(Error::capi_installation(format!(
        "no {} chart found in {}",
        prefix, charts_dir
    )))
}

/// CAPI installer using clusterctl
pub struct ClusterctlInstaller;

impl ClusterctlInstaller {
    /// Create a new clusterctl installer
    pub fn new() -> Self {
        Self
    }

    /// Get installed CAPI providers by checking provider namespaces
    fn get_installed_providers() -> Vec<InstalledProvider> {
        let mut providers = Vec::new();

        // Provider namespace patterns and their types
        let provider_checks = [
            ("capi-system", "cluster-api", CapiProviderType::Core),
            (
                "capi-kubeadm-bootstrap-system",
                "kubeadm",
                CapiProviderType::Bootstrap,
            ),
            (
                "capi-kubeadm-control-plane-system",
                "kubeadm",
                CapiProviderType::ControlPlane,
            ),
            ("rke2-bootstrap-system", "rke2", CapiProviderType::Bootstrap),
            (
                "rke2-control-plane-system",
                "rke2",
                CapiProviderType::ControlPlane,
            ),
            ("capd-system", "docker", CapiProviderType::Infrastructure),
            ("capa-system", "aws", CapiProviderType::Infrastructure),
            ("capg-system", "gcp", CapiProviderType::Infrastructure),
            ("capz-system", "azure", CapiProviderType::Infrastructure),
        ];

        for (namespace, name, provider_type) in provider_checks {
            if let Some(version) = Self::get_provider_version(namespace, name) {
                providers.push(InstalledProvider {
                    name: name.to_string(),
                    provider_type,
                    version,
                    namespace: namespace.to_string(),
                });
            }
        }

        providers
    }

    /// Get provider version from deployment labels
    fn get_provider_version(namespace: &str, _name: &str) -> Option<String> {
        // Check if namespace exists first
        let ns_check = Command::new("kubectl")
            .args(["get", "namespace", namespace])
            .output()
            .ok()?;

        if !ns_check.status.success() {
            return None;
        }

        // Get version from deployment label (CAPI convention: app.kubernetes.io/version)
        let output = Command::new("kubectl")
            .args([
                "get",
                "deployment",
                "-n",
                namespace,
                "-o",
                "jsonpath={.items[0].metadata.labels.app\\.kubernetes\\.io/version}",
            ])
            .output()
            .ok()?;

        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !version.is_empty() {
                return Some(version);
            }
        }

        // Fallback: check cluster-api.cattle.io/version label (RKE2 providers use this)
        let output = Command::new("kubectl")
            .args([
                "get",
                "deployment",
                "-n",
                namespace,
                "-o",
                "jsonpath={.items[0].metadata.labels.cluster-api\\.cattle\\.io/version}",
            ])
            .output()
            .ok()?;

        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !version.is_empty() {
                return Some(version);
            }
        }

        // If namespace exists but we can't get version, assume it's installed with unknown version
        Some("unknown".to_string())
    }

    /// Compute what actions are needed for each provider
    fn compute_provider_actions(
        installed: &[InstalledProvider],
        desired: &[DesiredProvider],
    ) -> HashMap<String, ProviderAction> {
        let mut actions = HashMap::new();

        // Build lookup of installed providers by (name, type)
        let installed_map: HashMap<(String, CapiProviderType), &InstalledProvider> = installed
            .iter()
            .map(|p| ((p.name.clone(), p.provider_type), p))
            .collect();

        for desired_provider in desired {
            let key = (
                desired_provider.name.clone(),
                desired_provider.provider_type,
            );
            let action_key = format!(
                "{}:{:?}",
                desired_provider.name, desired_provider.provider_type
            );

            if let Some(installed_provider) = installed_map.get(&key) {
                // Provider exists - check version
                if installed_provider.version == desired_provider.version {
                    actions.insert(action_key, ProviderAction::Skip);
                } else if installed_provider.version == "unknown" {
                    // Can't determine version, assume it's fine
                    actions.insert(action_key, ProviderAction::Skip);
                } else {
                    actions.insert(
                        action_key,
                        ProviderAction::Upgrade {
                            from: installed_provider.version.clone(),
                            to: desired_provider.version.clone(),
                        },
                    );
                }
            } else {
                // Provider not installed
                actions.insert(action_key, ProviderAction::Install);
            }
        }

        actions
    }

    /// Install cert-manager from local helm chart (required before CAPI providers)
    fn install_cert_manager() -> Result<(), Error> {
        // Check if cert-manager is already installed
        let check = Command::new("kubectl")
            .args(["get", "namespace", "cert-manager"])
            .output();

        if let Ok(output) = check {
            if output.status.success() {
                // Check if deployments are ready
                let ready = Command::new("kubectl")
                    .args([
                        "get",
                        "deployment",
                        "cert-manager",
                        "-n",
                        "cert-manager",
                        "-o",
                        "jsonpath={.status.availableReplicas}",
                    ])
                    .output();

                if let Ok(output) = ready {
                    let replicas = String::from_utf8_lossy(&output.stdout);
                    if replicas.trim().parse::<i32>().unwrap_or(0) > 0 {
                        info!("cert-manager already installed and ready");
                        return Ok(());
                    }
                }
            }
        }

        info!("Installing cert-manager from local helm chart");

        let charts_dir = std::env::var("LATTICE_CHARTS_DIR").unwrap_or_else(|_| {
            option_env!("LATTICE_CHARTS_DIR")
                .unwrap_or("/charts")
                .to_string()
        });

        let chart_path = find_chart(&charts_dir, "cert-manager")?;

        // Render manifests with helm template
        let template_output = Command::new("helm")
            .args([
                "template",
                "cert-manager",
                &chart_path,
                "--namespace",
                "cert-manager",
                "--set",
                "crds.enabled=true",
            ])
            .output()
            .map_err(|e| Error::capi_installation(format!("failed to run helm template: {}", e)))?;

        if !template_output.status.success() {
            return Err(Error::capi_installation(format!(
                "helm template cert-manager failed: {}",
                String::from_utf8_lossy(&template_output.stderr)
            )));
        }

        // Create namespace
        let _ = Command::new("kubectl")
            .args([
                "create",
                "namespace",
                "cert-manager",
                "--dry-run=client",
                "-o",
                "yaml",
            ])
            .output()
            .and_then(|ns_output| {
                Command::new("kubectl")
                    .args(["apply", "-f", "-"])
                    .stdin(std::process::Stdio::piped())
                    .spawn()
                    .and_then(|mut child| {
                        use std::io::Write;
                        if let Some(stdin) = child.stdin.as_mut() {
                            let _ = stdin.write_all(&ns_output.stdout);
                        }
                        child.wait()
                    })
            });

        // Apply cert-manager manifests
        let apply_output = Command::new("kubectl")
            .args(["apply", "-f", "-", "--server-side", "--force-conflicts"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(stdin) = child.stdin.as_mut() {
                    let _ = stdin.write_all(&template_output.stdout);
                }
                child.wait_with_output()
            })
            .map_err(|e| {
                Error::capi_installation(format!("failed to apply cert-manager: {}", e))
            })?;

        if !apply_output.status.success() {
            return Err(Error::capi_installation(format!(
                "kubectl apply cert-manager failed: {}",
                String::from_utf8_lossy(&apply_output.stderr)
            )));
        }

        // Wait for cert-manager to be ready
        info!("Waiting for cert-manager to be ready");
        let wait_output = Command::new("kubectl")
            .args([
                "wait",
                "--for=condition=Available",
                "deployment/cert-manager",
                "deployment/cert-manager-webhook",
                "deployment/cert-manager-cainjector",
                "-n",
                "cert-manager",
                "--timeout=120s",
            ])
            .output()
            .map_err(|e| {
                Error::capi_installation(format!("failed to wait for cert-manager: {}", e))
            })?;

        if !wait_output.status.success() {
            return Err(Error::capi_installation(format!(
                "cert-manager not ready: {}",
                String::from_utf8_lossy(&wait_output.stderr)
            )));
        }

        info!("cert-manager installed successfully");
        Ok(())
    }

    /// Build clusterctl init arguments for missing providers only
    fn build_init_args(
        config: &CapiProviderConfig,
        actions: &HashMap<String, ProviderAction>,
        config_path: &str,
    ) -> Option<Vec<String>> {
        let infra_name = match config.infrastructure {
            ProviderType::Docker => "docker",
            ProviderType::Proxmox => "proxmox",
            ProviderType::OpenStack => "openstack",
            ProviderType::Aws => "aws",
            ProviderType::Gcp => "gcp",
            ProviderType::Azure => "azure",
        };

        // Collect providers that need installation
        let mut bootstrap_providers = Vec::new();
        let mut control_plane_providers = Vec::new();
        let mut need_core = false;
        let mut need_infra = false;

        for (key, action) in actions {
            if *action != ProviderAction::Install {
                continue;
            }

            if key.contains("cluster-api:") {
                need_core = true;
            } else if key.contains(":Bootstrap") {
                let name = key.split(':').next().unwrap_or("");
                bootstrap_providers.push(name.to_string());
            } else if key.contains(":ControlPlane") {
                let name = key.split(':').next().unwrap_or("");
                control_plane_providers.push(name.to_string());
            } else if key.contains(":Infrastructure") {
                need_infra = true;
            }
        }

        // If nothing needs to be installed, return None
        if !need_core
            && !need_infra
            && bootstrap_providers.is_empty()
            && control_plane_providers.is_empty()
        {
            return None;
        }

        let mut args = vec![
            "120".to_string(),
            "clusterctl".to_string(),
            "init".to_string(),
        ];

        if need_infra {
            args.push("--infrastructure".to_string());
            args.push(infra_name.to_string());
        }

        if !bootstrap_providers.is_empty() {
            args.push("--bootstrap".to_string());
            args.push(bootstrap_providers.join(","));
        }

        if !control_plane_providers.is_empty() {
            args.push("--control-plane".to_string());
            args.push(control_plane_providers.join(","));
        }

        args.push("--config".to_string());
        args.push(config_path.to_string());

        Some(args)
    }

    /// Build clusterctl upgrade arguments for providers that need upgrading
    fn build_upgrade_args(
        config: &CapiProviderConfig,
        actions: &HashMap<String, ProviderAction>,
        config_path: &str,
    ) -> Option<Vec<String>> {
        let infra_name = match config.infrastructure {
            ProviderType::Docker => "docker",
            ProviderType::Proxmox => "proxmox",
            ProviderType::OpenStack => "openstack",
            ProviderType::Aws => "aws",
            ProviderType::Gcp => "gcp",
            ProviderType::Azure => "azure",
        };

        // Check if any providers need upgrading
        let needs_upgrade = actions
            .values()
            .any(|a| matches!(a, ProviderAction::Upgrade { .. }));
        if !needs_upgrade {
            return None;
        }

        // For upgrades, we specify exact versions for each component
        let mut args = vec![
            "120".to_string(),
            "clusterctl".to_string(),
            "upgrade".to_string(),
            "apply".to_string(),
        ];

        // Add core provider version
        args.push("--core".to_string());
        args.push(format!("cluster-api:v{}", config.capi_version));

        // Add bootstrap providers
        args.push("--bootstrap".to_string());
        args.push(format!(
            "kubeadm:v{},rke2:v{}",
            config.capi_version, config.rke2_version
        ));

        // Add control-plane providers
        args.push("--control-plane".to_string());
        args.push(format!(
            "kubeadm:v{},rke2:v{}",
            config.capi_version, config.rke2_version
        ));

        // Add infrastructure provider
        args.push("--infrastructure".to_string());
        args.push(format!("{}:v{}", infra_name, config.capi_version));

        args.push("--config".to_string());
        args.push(config_path.to_string());

        Some(args)
    }
}

impl Default for ClusterctlInstaller {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CapiInstaller for ClusterctlInstaller {
    async fn ensure(&self, config: &CapiProviderConfig) -> Result<(), Error> {
        // Get currently installed providers
        let installed = Self::get_installed_providers();
        let desired = config.desired_providers();

        debug!(
            installed = ?installed.iter().map(|p| format!("{}:{:?}@{}", p.name, p.provider_type, p.version)).collect::<Vec<_>>(),
            "Found installed CAPI providers"
        );

        // Compute what actions are needed
        let actions = Self::compute_provider_actions(&installed, &desired);

        // Log the plan
        for (key, action) in &actions {
            match action {
                ProviderAction::Skip => debug!(provider = %key, "Provider up to date"),
                ProviderAction::Install => info!(provider = %key, "Provider will be installed"),
                ProviderAction::Upgrade { from, to } => {
                    info!(provider = %key, from = %from, to = %to, "Provider will be upgraded")
                }
            }
        }

        // Check if any work is needed
        let needs_install = actions.values().any(|a| *a == ProviderAction::Install);
        let needs_upgrade = actions
            .values()
            .any(|a| matches!(a, ProviderAction::Upgrade { .. }));

        if !needs_install && !needs_upgrade {
            info!("All CAPI providers are up to date");
            return Ok(());
        }

        let config_path = std::env::var("CLUSTERCTL_CONFIG").unwrap_or_else(|_| {
            option_env!("CLUSTERCTL_CONFIG")
                .unwrap_or("/providers/clusterctl.yaml")
                .to_string()
        });

        // Install cert-manager first (required by CAPI)
        Self::install_cert_manager()?;

        // Handle installations first
        if needs_install {
            if let Some(args) = Self::build_init_args(config, &actions, &config_path) {
                let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                info!(args = ?args_ref, "Running clusterctl init for missing providers");

                let output = Command::new("timeout")
                    .args(&args_ref)
                    .env("GOPROXY", "off")
                    .env("CLUSTERCTL_DISABLE_VERSIONCHECK", "true")
                    .output()
                    .map_err(|e| {
                        Error::capi_installation(format!("failed to run clusterctl: {}", e))
                    })?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    return Err(Error::capi_installation(format!(
                        "clusterctl init failed: {} {}",
                        stdout, stderr
                    )));
                }

                info!("CAPI providers installed successfully");
            }
        }

        // Handle upgrades
        if needs_upgrade {
            if let Some(args) = Self::build_upgrade_args(config, &actions, &config_path) {
                let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                info!(args = ?args_ref, "Running clusterctl upgrade for outdated providers");

                let output = Command::new("timeout")
                    .args(&args_ref)
                    .env("GOPROXY", "off")
                    .env("CLUSTERCTL_DISABLE_VERSIONCHECK", "true")
                    .output()
                    .map_err(|e| {
                        Error::capi_installation(format!("failed to run clusterctl upgrade: {}", e))
                    })?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    // Don't fail on upgrade errors - log warning and continue
                    // Upgrades may fail if providers have incompatible changes
                    warn!(
                        stdout = %stdout,
                        stderr = %stderr,
                        "clusterctl upgrade had issues, continuing anyway"
                    );
                } else {
                    info!("CAPI providers upgraded successfully");
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desired_providers_includes_all_required() {
        let config = CapiProviderConfig::with_versions(
            ProviderType::Docker,
            "1.12.1".to_string(),
            "0.11.0".to_string(),
        );
        let providers = config.desired_providers();

        // Should have 6 providers: core, kubeadm bootstrap, kubeadm cp, rke2 bootstrap, rke2 cp, docker infra
        assert_eq!(providers.len(), 6);

        // Check core
        assert!(providers
            .iter()
            .any(|p| p.name == "cluster-api" && p.provider_type == CapiProviderType::Core));

        // Check kubeadm
        assert!(providers
            .iter()
            .any(|p| p.name == "kubeadm" && p.provider_type == CapiProviderType::Bootstrap));
        assert!(providers
            .iter()
            .any(|p| p.name == "kubeadm" && p.provider_type == CapiProviderType::ControlPlane));

        // Check rke2
        assert!(providers
            .iter()
            .any(|p| p.name == "rke2" && p.provider_type == CapiProviderType::Bootstrap));
        assert!(providers
            .iter()
            .any(|p| p.name == "rke2" && p.provider_type == CapiProviderType::ControlPlane));

        // Check infrastructure
        assert!(providers
            .iter()
            .any(|p| p.name == "docker" && p.provider_type == CapiProviderType::Infrastructure));
    }

    #[test]
    fn compute_actions_identifies_missing_providers() {
        let installed = vec![];
        let desired = vec![DesiredProvider {
            name: "cluster-api".to_string(),
            provider_type: CapiProviderType::Core,
            version: "v1.12.1".to_string(),
        }];

        let actions = ClusterctlInstaller::compute_provider_actions(&installed, &desired);

        assert_eq!(
            actions.get("cluster-api:Core"),
            Some(&ProviderAction::Install)
        );
    }

    #[test]
    fn compute_actions_identifies_upgrades() {
        let installed = vec![InstalledProvider {
            name: "cluster-api".to_string(),
            provider_type: CapiProviderType::Core,
            version: "v1.11.0".to_string(),
            namespace: "capi-system".to_string(),
        }];
        let desired = vec![DesiredProvider {
            name: "cluster-api".to_string(),
            provider_type: CapiProviderType::Core,
            version: "v1.12.1".to_string(),
        }];

        let actions = ClusterctlInstaller::compute_provider_actions(&installed, &desired);

        assert_eq!(
            actions.get("cluster-api:Core"),
            Some(&ProviderAction::Upgrade {
                from: "v1.11.0".to_string(),
                to: "v1.12.1".to_string()
            })
        );
    }

    #[test]
    fn compute_actions_skips_up_to_date() {
        let installed = vec![InstalledProvider {
            name: "cluster-api".to_string(),
            provider_type: CapiProviderType::Core,
            version: "v1.12.1".to_string(),
            namespace: "capi-system".to_string(),
        }];
        let desired = vec![DesiredProvider {
            name: "cluster-api".to_string(),
            provider_type: CapiProviderType::Core,
            version: "v1.12.1".to_string(),
        }];

        let actions = ClusterctlInstaller::compute_provider_actions(&installed, &desired);

        assert_eq!(actions.get("cluster-api:Core"), Some(&ProviderAction::Skip));
    }

    #[test]
    fn compute_actions_handles_unknown_version() {
        let installed = vec![InstalledProvider {
            name: "cluster-api".to_string(),
            provider_type: CapiProviderType::Core,
            version: "unknown".to_string(),
            namespace: "capi-system".to_string(),
        }];
        let desired = vec![DesiredProvider {
            name: "cluster-api".to_string(),
            provider_type: CapiProviderType::Core,
            version: "v1.12.1".to_string(),
        }];

        let actions = ClusterctlInstaller::compute_provider_actions(&installed, &desired);

        // Unknown version should be treated as skip (can't reliably determine if upgrade needed)
        assert_eq!(actions.get("cluster-api:Core"), Some(&ProviderAction::Skip));
    }

    #[test]
    fn all_infrastructure_providers_map_correctly() {
        for (provider, expected) in [
            (ProviderType::Docker, "docker"),
            (ProviderType::Aws, "aws"),
            (ProviderType::Gcp, "gcp"),
            (ProviderType::Azure, "azure"),
        ] {
            let config = CapiProviderConfig::with_versions(
                provider,
                "1.12.1".to_string(),
                "0.11.0".to_string(),
            );
            let providers = config.desired_providers();
            assert!(
                providers
                    .iter()
                    .any(|p| p.name == expected
                        && p.provider_type == CapiProviderType::Infrastructure)
            );
        }
    }

    #[tokio::test]
    async fn mock_installer_can_be_used() {
        let mut installer = MockCapiInstaller::new();
        installer.expect_ensure().returning(|_| Ok(()));

        let config = CapiProviderConfig::new(ProviderType::Docker);
        let result = ensure_capi_installed(&installer, &config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn mock_installer_propagates_errors() {
        let mut installer = MockCapiInstaller::new();
        installer
            .expect_ensure()
            .returning(|_| Err(Error::capi_installation("test error".to_string())));

        let config = CapiProviderConfig::new(ProviderType::Docker);
        let result = ensure_capi_installed(&installer, &config).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("test error"));
    }
}
