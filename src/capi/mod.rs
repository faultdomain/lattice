//! CAPI (Cluster API) provider installation
//!
//! Handles installing CAPI providers before provisioning clusters.
//! Always installs both kubeadm and RKE2 bootstrap/control-plane providers
//! to ensure clusterctl move works between any clusters.

use std::process::Command;

use async_trait::async_trait;
#[cfg(test)]
use mockall::automock;
use tracing::info;

use crate::crd::ProviderType;
use crate::Error;

/// Configuration for CAPI provider installation
#[derive(Debug, Clone)]
pub struct CapiProviderConfig {
    /// Infrastructure provider (docker, aws, gcp, azure)
    pub infrastructure: ProviderType,
}

impl CapiProviderConfig {
    /// Create a new CAPI provider configuration
    pub fn new(infrastructure: ProviderType) -> Self {
        Self { infrastructure }
    }
}

/// Trait for installing CAPI providers
#[cfg_attr(test, automock)]
#[async_trait]
pub trait CapiInstaller: Send + Sync {
    /// Install CAPI with the specified providers
    async fn install(&self, config: &CapiProviderConfig) -> Result<(), Error>;
}

/// Ensure CAPI providers are installed
pub async fn ensure_capi_installed<I: CapiInstaller + ?Sized>(
    installer: &I,
    config: &CapiProviderConfig,
) -> Result<(), Error> {
    installer.install(config).await
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

    /// Install cert-manager from local helm chart (required before CAPI providers)
    fn install_cert_manager() -> Result<(), Error> {
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

    /// Build clusterctl init arguments based on provider config
    ///
    /// Always installs BOTH kubeadm and RKE2 bootstrap/control-plane providers,
    /// regardless of which one this cluster uses. This is required because
    /// clusterctl move checks that the target cluster has all providers that
    /// exist on the source cluster.
    fn build_clusterctl_args(config: &CapiProviderConfig, config_path: &str) -> Vec<String> {
        let infra_name = match config.infrastructure {
            ProviderType::Docker => "docker",
            ProviderType::Aws => "aws",
            ProviderType::Gcp => "gcp",
            ProviderType::Azure => "azure",
        };

        // Always install both kubeadm and RKE2 providers
        // Must specify both explicitly - specifying one replaces the default
        let args = vec![
            "120".to_string(),
            "clusterctl".to_string(),
            "init".to_string(),
            "--infrastructure".to_string(),
            infra_name.to_string(),
            "--bootstrap".to_string(),
            "kubeadm,rke2".to_string(),
            "--control-plane".to_string(),
            "kubeadm,rke2".to_string(),
            "--config".to_string(),
            config_path.to_string(),
        ];

        args
    }
}

impl Default for ClusterctlInstaller {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CapiInstaller for ClusterctlInstaller {
    async fn install(&self, config: &CapiProviderConfig) -> Result<(), Error> {
        // Check if CAPI is already installed by looking for the Cluster CRD
        let crd_check = Command::new("kubectl")
            .args(["get", "crd", "clusters.cluster.x-k8s.io"])
            .output();

        if let Ok(output) = crd_check {
            if output.status.success() {
                info!("CAPI providers already installed, skipping initialization");
                return Ok(());
            }
        }

        info!(infrastructure = %config.infrastructure, "Installing CAPI providers (kubeadm + RKE2)");

        let config_path = std::env::var("CLUSTERCTL_CONFIG").unwrap_or_else(|_| {
            option_env!("CLUSTERCTL_CONFIG")
                .unwrap_or("/providers/clusterctl.yaml")
                .to_string()
        });

        // Install cert-manager first (required by CAPI)
        Self::install_cert_manager()?;

        // Build clusterctl arguments
        let args = Self::build_clusterctl_args(config, &config_path);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        info!(args = ?args_ref, "Running clusterctl init");

        let output = Command::new("timeout")
            .args(&args_ref)
            .env("GOPROXY", "off")
            .env("CLUSTERCTL_DISABLE_VERSIONCHECK", "true")
            .output()
            .map_err(|e| Error::capi_installation(format!("failed to run clusterctl: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(Error::capi_installation(format!(
                "clusterctl init failed: {} {}",
                stdout, stderr
            )));
        }

        info!("CAPI providers installed successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_installs_both_kubeadm_and_rke2_providers() {
        let config = CapiProviderConfig::new(ProviderType::Docker);
        let args = ClusterctlInstaller::build_clusterctl_args(&config, "/test/config.yaml");

        assert!(args.contains(&"--infrastructure".to_string()));
        assert!(args.contains(&"docker".to_string()));
        assert!(args.contains(&"--bootstrap".to_string()));
        assert!(args.contains(&"kubeadm,rke2".to_string()));
        assert!(args.contains(&"--control-plane".to_string()));
    }

    #[test]
    fn all_infrastructure_providers_map_correctly() {
        for (provider, expected) in [
            (ProviderType::Docker, "docker"),
            (ProviderType::Aws, "aws"),
            (ProviderType::Gcp, "gcp"),
            (ProviderType::Azure, "azure"),
        ] {
            let config = CapiProviderConfig::new(provider);
            let args = ClusterctlInstaller::build_clusterctl_args(&config, "/test/config.yaml");
            assert!(args.contains(&expected.to_string()));
        }
    }

    #[tokio::test]
    async fn mock_installer_can_be_used() {
        let mut installer = MockCapiInstaller::new();
        installer.expect_install().returning(|_| Ok(()));

        let config = CapiProviderConfig::new(ProviderType::Docker);
        let result = ensure_capi_installed(&installer, &config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn mock_installer_propagates_errors() {
        let mut installer = MockCapiInstaller::new();
        installer
            .expect_install()
            .returning(|_| Err(Error::capi_installation("test error".to_string())));

        let config = CapiProviderConfig::new(ProviderType::Docker);
        let result = ensure_capi_installed(&installer, &config).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("test error"));
    }
}
