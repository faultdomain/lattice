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

#[async_trait]
impl CapiInstaller for ClusterctlInstaller {
    async fn install(&self, provider: &str) -> Result<(), Error> {
        info!(provider, "Installing CAPI with infrastructure provider");

        // Use timeout to fail fast - clusterctl can hang waiting for cert-manager
        // Better to fail and retry than block for 10+ minutes
        let output = Command::new("timeout")
            .args(["60", "clusterctl", "init", "--infrastructure", provider])
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
        installer.expect_install().with(eq("docker")).returning(|_| {
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
