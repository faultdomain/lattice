//! CAPI (Cluster API) management
//!
//! Handles ensuring CAPI and infrastructure providers are installed before
//! attempting to provision clusters. Always runs clusterctl init - it's
//! idempotent and handles versioning automatically.

use std::process::Command;

use async_trait::async_trait;
#[cfg(test)]
use mockall::automock;
use tracing::info;

use crate::crd::ProviderType;
use crate::Error;

/// Get the clusterctl provider name for installation
pub fn clusterctl_provider_name(provider: &ProviderType) -> &'static str {
    match provider {
        ProviderType::Docker => "docker",
        ProviderType::Aws => "aws",
        ProviderType::Gcp => "gcp",
        ProviderType::Azure => "azure",
    }
}

/// Trait for installing CAPI and infrastructure providers
///
/// This trait abstracts clusterctl command execution for testability.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait CapiInstaller: Send + Sync {
    /// Install CAPI with the specified infrastructure provider
    async fn install(&self, provider: &str) -> Result<(), Error>;
}

/// Ensure CAPI and the required provider are installed
///
/// Always runs clusterctl init - it's idempotent and handles versioning.
pub async fn ensure_capi_installed_with<I: CapiInstaller + ?Sized>(
    installer: &I,
    provider: &ProviderType,
) -> Result<(), Error> {
    let provider_name = clusterctl_provider_name(provider);
    installer.install(provider_name).await
}

// =============================================================================
// Real Implementation
// =============================================================================

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

/// CAPI installer that uses clusterctl
pub struct ClusterctlInstaller;

impl ClusterctlInstaller {
    /// Create a new installer
    pub fn new() -> Self {
        Self
    }
}

impl Default for ClusterctlInstaller {
    fn default() -> Self {
        Self::new()
    }
}

impl ClusterctlInstaller {
    /// Install cert-manager using local helm chart
    /// Required before clusterctl can install CAPI providers
    fn install_cert_manager() -> Result<(), Error> {
        info!("Installing cert-manager from local helm chart");

        let charts_dir = std::env::var("LATTICE_CHARTS_DIR").unwrap_or_else(|_| {
            option_env!("LATTICE_CHARTS_DIR")
                .unwrap_or("/charts")
                .to_string()
        });

        // Find cert-manager chart dynamically (supports any version)
        let chart_path = find_chart(&charts_dir, "cert-manager")?;

        // Render cert-manager manifests with helm template
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
            let stderr = String::from_utf8_lossy(&template_output.stderr);
            return Err(Error::capi_installation(format!(
                "helm template cert-manager failed: {}",
                stderr
            )));
        }

        // Create namespace first
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
            let stderr = String::from_utf8_lossy(&apply_output.stderr);
            return Err(Error::capi_installation(format!(
                "kubectl apply cert-manager failed: {}",
                stderr
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
            let stderr = String::from_utf8_lossy(&wait_output.stderr);
            return Err(Error::capi_installation(format!(
                "cert-manager not ready: {}",
                stderr
            )));
        }

        info!("cert-manager installed successfully");
        Ok(())
    }
}

#[async_trait]
impl CapiInstaller for ClusterctlInstaller {
    async fn install(&self, provider: &str) -> Result<(), Error> {
        info!(provider, "Installing CAPI with infrastructure provider");

        // Get local provider config path (always use local - we're air-gapped by design)
        let config_path = std::env::var("CLUSTERCTL_CONFIG").unwrap_or_else(|_| {
            option_env!("CLUSTERCTL_CONFIG")
                .unwrap_or("/providers/clusterctl.yaml")
                .to_string()
        });

        info!(config = %config_path, "Using clusterctl config file");

        // First, install cert-manager using our local helm chart
        // clusterctl expects cert-manager to be ready before installing providers
        Self::install_cert_manager()?;

        // Set environment variables for air-gapped operation
        // GOPROXY=off prevents Go proxy lookups
        // CLUSTERCTL_DISABLE_VERSIONCHECK=true skips version check requiring internet
        let output = Command::new("timeout")
            .args([
                "120",
                "clusterctl",
                "init",
                "--infrastructure",
                provider,
                "--config",
                &config_path,
            ])
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

        info!("CAPI installed successfully");
        Ok(())
    }
}

/// Convenience function to ensure CAPI is installed using default implementation
pub async fn ensure_capi_installed(provider: &ProviderType) -> Result<(), Error> {
    let installer = ClusterctlInstaller::new();
    ensure_capi_installed_with(&installer, provider).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::ProviderType;
    use mockall::predicate::*;

    // ==========================================================================
    // Story: Provider Name Mapping
    // ==========================================================================

    #[test]
    fn when_installing_providers_clusterctl_names_are_lowercase() {
        assert_eq!(clusterctl_provider_name(&ProviderType::Docker), "docker");
        assert_eq!(clusterctl_provider_name(&ProviderType::Aws), "aws");
        assert_eq!(clusterctl_provider_name(&ProviderType::Gcp), "gcp");
        assert_eq!(clusterctl_provider_name(&ProviderType::Azure), "azure");
    }

    // ==========================================================================
    // Story: CAPI Installation
    //
    // ensure_capi_installed_with always runs clusterctl init - it's idempotent
    // and handles versioning automatically.
    // ==========================================================================

    /// ensure_capi calls installer with "docker" for Docker provider
    #[tokio::test]
    async fn when_provider_is_docker_install_with_docker_name() {
        let mut installer = MockCapiInstaller::new();
        installer
            .expect_install()
            .with(eq("docker"))
            .times(1)
            .returning(|_| Ok(()));

        let result = ensure_capi_installed_with(&installer, &ProviderType::Docker).await;
        assert!(result.is_ok());
    }

    /// ensure_capi calls installer with "aws" for AWS provider
    #[tokio::test]
    async fn when_provider_is_aws_install_with_aws_name() {
        let mut installer = MockCapiInstaller::new();
        installer
            .expect_install()
            .with(eq("aws"))
            .times(1)
            .returning(|_| Ok(()));

        let result = ensure_capi_installed_with(&installer, &ProviderType::Aws).await;
        assert!(result.is_ok());
    }

    /// ensure_capi calls installer with "gcp" for GCP provider
    #[tokio::test]
    async fn when_provider_is_gcp_install_with_gcp_name() {
        let mut installer = MockCapiInstaller::new();
        installer
            .expect_install()
            .with(eq("gcp"))
            .times(1)
            .returning(|_| Ok(()));

        let result = ensure_capi_installed_with(&installer, &ProviderType::Gcp).await;
        assert!(result.is_ok());
    }

    /// ensure_capi calls installer with "azure" for Azure provider
    #[tokio::test]
    async fn when_provider_is_azure_install_with_azure_name() {
        let mut installer = MockCapiInstaller::new();
        installer
            .expect_install()
            .with(eq("azure"))
            .times(1)
            .returning(|_| Ok(()));

        let result = ensure_capi_installed_with(&installer, &ProviderType::Azure).await;
        assert!(result.is_ok());
    }

    /// When installation fails, the error propagates to the caller
    #[tokio::test]
    async fn when_installation_fails_error_propagates() {
        let mut installer = MockCapiInstaller::new();
        installer
            .expect_install()
            .with(eq("docker"))
            .returning(|_| {
                Err(Error::capi_installation(
                    "clusterctl init failed: timeout".to_string(),
                ))
            });

        let result = ensure_capi_installed_with(&installer, &ProviderType::Docker).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timeout"));
    }

    // ==========================================================================
    // Story: ClusterctlInstaller Construction
    // ==========================================================================

    #[test]
    fn clusterctl_installer_can_be_constructed_via_new_or_default() {
        let _via_new = ClusterctlInstaller::new();
        let _via_default = ClusterctlInstaller::default();
    }
}
