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
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::Namespace;
use kube::api::{Api, ListParams, Patch, PatchParams, PostParams};
use kube::core::DynamicObject;
use kube::discovery::ApiResource;
use kube::Client as KubeClient;
#[cfg(test)]
use mockall::automock;
use tracing::{debug, info, warn};

use lattice_common::crd::{ProviderType, SecretRef};
use lattice_common::Error;

use crate::bootstrap::{
    AwsCredentials, CAPA_NAMESPACE, CAPMOX_NAMESPACE, CAPO_NAMESPACE, OPENSTACK_CREDENTIALS_SECRET,
    PROXMOX_CREDENTIALS_SECRET,
};

/// Copy credentials from CloudProvider's secret reference to the CAPI provider namespace.
///
/// CAPI providers expect credentials in specific namespaces with specific names:
/// - AWS: `capa-system/capa-manager-bootstrap-credentials`
/// - Proxmox: `capmox-system/proxmox-credentials`
/// - OpenStack: `capo-system/openstack-credentials`
pub async fn copy_credentials_to_provider_namespace(
    client: &KubeClient,
    provider: ProviderType,
    secret_ref: &SecretRef,
) -> Result<(), Error> {
    use k8s_openapi::api::core::v1::{Namespace, Secret};

    let (target_namespace, target_name) = match provider {
        ProviderType::Aws => (CAPA_NAMESPACE, "capa-manager-bootstrap-credentials"),
        ProviderType::Proxmox => (CAPMOX_NAMESPACE, "proxmox-credentials"),
        ProviderType::OpenStack => (CAPO_NAMESPACE, "openstack-credentials"),
        // Docker and other providers don't need credentials
        _ => return Ok(()),
    };

    // Read source secret from CloudProvider's credentials_secret_ref
    let source_api: Api<Secret> = Api::namespaced(client.clone(), &secret_ref.namespace);
    let source = match source_api.get(&secret_ref.name).await {
        Ok(s) => s,
        Err(kube::Error::Api(e)) if e.code == 404 => {
            return Err(Error::validation(format!(
                "Credentials secret '{}/{}' not found",
                secret_ref.namespace, secret_ref.name
            )));
        }
        Err(e) => return Err(e.into()),
    };

    // Create target namespace if needed
    let ns_api: Api<Namespace> = Api::all(client.clone());
    let ns = Namespace {
        metadata: kube::core::ObjectMeta {
            name: Some(target_namespace.to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let _ = ns_api.create(&PostParams::default(), &ns).await;

    // Copy secret to target namespace
    let target_api: Api<Secret> = Api::namespaced(client.clone(), target_namespace);
    let target = Secret {
        metadata: kube::core::ObjectMeta {
            name: Some(target_name.to_string()),
            namespace: Some(target_namespace.to_string()),
            ..Default::default()
        },
        data: source.data.clone(),
        string_data: source.string_data.clone(),
        type_: source.type_.clone(),
        ..Default::default()
    };

    target_api
        .patch(
            target_name,
            &PatchParams::apply("lattice-controller").force(),
            &Patch::Apply(&target),
        )
        .await
        .map_err(|e| {
            Error::capi_installation(format!(
                "Failed to copy credentials to {}/{}: {}",
                target_namespace, target_name, e
            ))
        })?;

    info!(
        source = format!("{}/{}", secret_ref.namespace, secret_ref.name),
        target = format!("{}/{}", target_namespace, target_name),
        "Copied provider credentials"
    );

    Ok(())
}

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

/// Provider-specific configuration for CAPI infrastructure providers
///
/// Consolidates all provider-specific logic in one place:
/// - clusterctl name and version
/// - credentials secret location and env var mapping
/// - extra clusterctl init arguments (e.g., IPAM for Proxmox)
#[derive(Debug, Clone)]
pub struct InfraProviderInfo {
    /// clusterctl infrastructure provider name
    pub name: &'static str,
    /// Provider version (from versions.toml)
    pub version: String,
    /// Credentials secret location: (namespace, name)
    pub credentials_secret: Option<(&'static str, &'static str)>,
    /// Mapping from secret keys to env var names for clusterctl template substitution
    pub credentials_env_map: &'static [(&'static str, &'static str)],
    /// Extra clusterctl init arguments (e.g., ["--ipam", "in-cluster"])
    pub extra_init_args: &'static [&'static str],
}

impl InfraProviderInfo {
    /// Get provider info for a given infrastructure type
    ///
    /// # Errors
    /// Returns an error if called with an unsupported provider type (GCP, Azure).
    pub fn for_provider(provider: ProviderType, capi_version: &str) -> Result<Self, Error> {
        match provider {
            ProviderType::Aws => Ok(Self {
                name: "aws",
                version: env!("CAPA_VERSION").to_string(),
                credentials_secret: Some(("capa-system", "capa-manager-bootstrap-credentials")),
                // AWS generates AWS_B64ENCODED_CREDENTIALS from these fields in get_provider_env_vars
                // credentials_env_map is not used directly - see generate_aws_b64_credentials()
                credentials_env_map: &[],
                extra_init_args: &[],
            }),
            ProviderType::Docker => Ok(Self {
                name: "docker",
                version: capi_version.to_string(), // CAPD is part of CAPI
                credentials_secret: None,
                credentials_env_map: &[],
                extra_init_args: &[],
            }),
            ProviderType::OpenStack => Ok(Self {
                name: "openstack",
                version: env!("CAPO_VERSION").to_string(),
                credentials_secret: Some((CAPO_NAMESPACE, OPENSTACK_CREDENTIALS_SECRET)),
                // OpenStack uses clouds.yaml in the secret, not individual env vars
                // The secret key "clouds.yaml" contains the full clouds.yaml file
                credentials_env_map: &[],
                extra_init_args: &[],
            }),
            ProviderType::Proxmox => Ok(Self {
                name: "proxmox",
                version: env!("CAPMOX_VERSION").to_string(),
                credentials_secret: Some((CAPMOX_NAMESPACE, PROXMOX_CREDENTIALS_SECRET)),
                credentials_env_map: &[
                    ("url", "PROXMOX_URL"),
                    ("token", "PROXMOX_TOKEN"),
                    ("secret", "PROXMOX_SECRET"),
                ],
                extra_init_args: &["--ipam", "in-cluster"],
            }),
            ProviderType::Gcp | ProviderType::Azure => Err(Error::capi_installation(format!(
                "Provider {:?} is not yet implemented",
                provider
            ))),
        }
    }
}

/// Configuration for CAPI provider installation
#[derive(Debug, Clone)]
pub struct CapiProviderConfig {
    /// Infrastructure provider (docker, aws, gcp, azure, proxmox, openstack)
    pub infrastructure: ProviderType,
    /// Desired CAPI core version (from versions.toml)
    pub capi_version: String,
    /// Desired RKE2 provider version (from versions.toml)
    pub rke2_version: String,
    /// Infrastructure provider info (name, version, credentials, etc.)
    pub infra_info: InfraProviderInfo,
    /// Override for credentials secret location (from LatticeCluster spec)
    /// If set, this takes precedence over the default in infra_info.
    pub credentials_secret_override: Option<(String, String)>,
}

impl CapiProviderConfig {
    /// Create a new CAPI provider configuration
    ///
    /// # Errors
    /// Returns an error if the provider type is not yet implemented.
    pub fn new(infrastructure: ProviderType) -> Result<Self, Error> {
        let capi_version = env!("CAPI_VERSION").to_string();
        let infra_info = InfraProviderInfo::for_provider(infrastructure, &capi_version)?;

        Ok(Self {
            infrastructure,
            capi_version,
            rke2_version: env!("RKE2_VERSION").to_string(),
            infra_info,
            credentials_secret_override: None,
        })
    }

    /// Set credentials secret override from LatticeCluster spec
    ///
    /// When set, this takes precedence over the default secret location.
    pub fn with_credentials_secret(mut self, namespace: String, name: String) -> Self {
        self.credentials_secret_override = Some((namespace, name));
        self
    }

    /// Get the effective credentials secret location
    ///
    /// Returns the override if set, otherwise the default from infra_info.
    pub fn credentials_secret(&self) -> Option<(&str, &str)> {
        if let Some((ref ns, ref name)) = self.credentials_secret_override {
            Some((ns.as_str(), name.as_str()))
        } else {
            self.infra_info.credentials_secret
        }
    }

    /// Create config with explicit versions (for testing)
    ///
    /// # Errors
    /// Returns an error if the provider type is not yet implemented.
    pub fn with_versions(
        infrastructure: ProviderType,
        capi_version: String,
        rke2_version: String,
    ) -> Result<Self, Error> {
        let name = match infrastructure {
            ProviderType::Aws => "aws",
            ProviderType::Docker => "docker",
            ProviderType::OpenStack => "openstack",
            ProviderType::Proxmox => "proxmox",
            ProviderType::Gcp | ProviderType::Azure => {
                return Err(Error::capi_installation(format!(
                    "Provider {:?} is not yet implemented",
                    infrastructure
                )));
            }
        };

        let infra_info = InfraProviderInfo {
            name,
            version: capi_version.clone(),
            credentials_secret: None,
            credentials_env_map: &[],
            extra_init_args: &[],
        };

        Ok(Self {
            infrastructure,
            capi_version,
            rke2_version,
            infra_info,
            credentials_secret_override: None,
        })
    }

    /// Get the list of desired providers based on this config
    pub fn desired_providers(&self) -> Vec<DesiredProvider> {
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
                name: self.infra_info.name.to_string(),
                provider_type: CapiProviderType::Infrastructure,
                version: format!("v{}", self.infra_info.version),
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

    /// Get installed CAPI providers by checking provider namespaces in parallel
    async fn get_installed_providers(client: &KubeClient) -> Vec<InstalledProvider> {
        // Provider namespace patterns and their types
        let provider_checks: Vec<(&str, &str, CapiProviderType)> = vec![
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
            (
                CAPMOX_NAMESPACE,
                "proxmox",
                CapiProviderType::Infrastructure,
            ),
            (
                CAPO_NAMESPACE,
                "openstack",
                CapiProviderType::Infrastructure,
            ),
            (CAPA_NAMESPACE, "aws", CapiProviderType::Infrastructure),
            ("capg-system", "gcp", CapiProviderType::Infrastructure),
            ("capz-system", "azure", CapiProviderType::Infrastructure),
        ];

        // Check all providers in parallel
        let futures: Vec<_> = provider_checks
            .into_iter()
            .map(|(namespace, name, provider_type)| {
                let client = client.clone();
                async move {
                    Self::get_provider_version(&client, namespace)
                        .await
                        .map(|version| InstalledProvider {
                            name: name.to_string(),
                            provider_type,
                            version,
                            namespace: namespace.to_string(),
                        })
                }
            })
            .collect();

        let results = futures::future::join_all(futures).await;
        results.into_iter().flatten().collect()
    }

    /// Get provider version from deployment labels using kube-rs
    async fn get_provider_version(client: &KubeClient, namespace: &str) -> Option<String> {
        // Check if namespace exists
        let namespaces: Api<Namespace> = Api::all(client.clone());
        if namespaces.get(namespace).await.is_err() {
            return None;
        }

        // Get deployments in the namespace
        let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
        let list = deployments.list(&ListParams::default()).await.ok()?;

        // Get first deployment and check labels
        let deployment = list.items.first()?;
        let labels = deployment.metadata.labels.as_ref()?;

        // Check app.kubernetes.io/version label (CAPI convention)
        if let Some(version) = labels.get("app.kubernetes.io/version") {
            if !version.is_empty() {
                return Some(version.clone());
            }
        }

        // Fallback: check cluster-api.cattle.io/version label (RKE2 providers)
        if let Some(version) = labels.get("cluster-api.cattle.io/version") {
            if !version.is_empty() {
                return Some(version.clone());
            }
        }

        // Namespace exists but can't get version
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
    async fn install_cert_manager(client: &KubeClient) -> Result<(), Error> {
        use std::time::Duration;

        // Check if cert-manager is already installed and ready
        let namespaces: Api<Namespace> = Api::all(client.clone());
        if namespaces.get("cert-manager").await.is_ok() {
            let deployments: Api<Deployment> = Api::namespaced(client.clone(), "cert-manager");
            if let Ok(deploy) = deployments.get("cert-manager").await {
                let available = deploy
                    .status
                    .as_ref()
                    .and_then(|s| s.available_replicas)
                    .unwrap_or(0);
                if available > 0 {
                    info!("cert-manager already installed and ready");
                    return Ok(());
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

        // Create namespace using kube-rs
        let ns = Namespace {
            metadata: kube::core::ObjectMeta {
                name: Some("cert-manager".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let _ = namespaces.create(&PostParams::default(), &ns).await;

        // Parse and apply manifests in parallel for faster installation
        let yaml_str = String::from_utf8_lossy(&template_output.stdout);
        let docs: Vec<&str> = yaml_str
            .split("\n---")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && s.contains("kind:"))
            .collect();

        let manifest_count = docs.len();
        debug!(
            count = manifest_count,
            "applying cert-manager manifests in parallel"
        );

        let futures: Vec<_> = docs
            .into_iter()
            .map(|doc| {
                let client = client.clone();
                let doc = doc.to_string();
                async move {
                    if let Err(e) = Self::apply_yaml_manifest(&client, &doc).await {
                        warn!(error = %e, "Failed to apply cert-manager manifest, continuing...");
                    }
                }
            })
            .collect();

        futures::future::join_all(futures).await;

        // Wait for cert-manager deployments to be ready using kube-rs
        info!("Waiting for cert-manager to be ready");
        let deployments: Api<Deployment> = Api::namespaced(client.clone(), "cert-manager");
        let required_deployments = [
            "cert-manager",
            "cert-manager-webhook",
            "cert-manager-cainjector",
        ];

        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(300); // 5 min for slow image pulls (RKE2)

        loop {
            if start.elapsed() > timeout {
                return Err(Error::capi_installation(
                    "cert-manager not ready: timeout".to_string(),
                ));
            }

            let all_ready = futures::future::try_join_all(
                required_deployments
                    .iter()
                    .map(|name| deployments.get(name)),
            )
            .await
            .map(|deps| {
                deps.iter().all(|d| {
                    d.status
                        .as_ref()
                        .and_then(|s| s.available_replicas)
                        .unwrap_or(0)
                        > 0
                })
            })
            .unwrap_or(false);

            if all_ready {
                break;
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        info!("cert-manager installed successfully");
        Ok(())
    }

    /// Apply a single YAML manifest using kube-rs server-side apply
    async fn apply_yaml_manifest(client: &KubeClient, yaml: &str) -> Result<(), String> {
        let value: serde_yaml::Value =
            serde_yaml::from_str(yaml).map_err(|e| format!("Invalid YAML: {}", e))?;

        let api_version = value["apiVersion"].as_str().ok_or("Missing apiVersion")?;
        let kind = value["kind"].as_str().ok_or("Missing kind")?;
        let name = value["metadata"]["name"]
            .as_str()
            .ok_or("Missing metadata.name")?;
        let namespace = value["metadata"]["namespace"].as_str();

        let (group, version) = if api_version.contains('/') {
            let parts: Vec<&str> = api_version.splitn(2, '/').collect();
            (parts[0].to_string(), parts[1].to_string())
        } else {
            (String::new(), api_version.to_string())
        };

        let plural = format!("{}s", kind.to_lowercase());
        let ar = ApiResource {
            group,
            version: version.clone(),
            kind: kind.to_string(),
            api_version: api_version.to_string(),
            plural,
        };

        let obj: DynamicObject =
            serde_yaml::from_str(yaml).map_err(|e| format!("Failed to parse: {}", e))?;

        let api: Api<DynamicObject> = if let Some(ns) = namespace {
            Api::namespaced_with(client.clone(), ns, &ar)
        } else {
            Api::all_with(client.clone(), &ar)
        };

        api.patch(
            name,
            &PatchParams::apply("lattice-operator").force(),
            &Patch::Apply(&obj),
        )
        .await
        .map_err(|e| format!("Apply failed: {}", e))?;

        Ok(())
    }

    /// Get provider-specific environment variables for clusterctl template substitution
    ///
    /// Reads credentials from pre-created secrets so clusterctl can substitute
    /// template variables like ${PROXMOX_URL} correctly.
    ///
    /// Uses the credentials_secret_override if set (from LatticeCluster spec),
    /// otherwise falls back to the default secret location for the provider.
    ///
    /// For AWS, this generates AWS_B64ENCODED_CREDENTIALS from individual credentials
    /// since clusterctl requires the encoded profile format.
    async fn get_provider_env_vars(
        client: &KubeClient,
        config: &CapiProviderConfig,
    ) -> Vec<(String, String)> {
        let mut env_vars = Vec::new();
        let info = &config.infra_info;

        // Use override if set, otherwise use default from infra_info
        if let Some((namespace, secret_name)) = config.credentials_secret() {
            if let Ok(secret) = Self::read_secret(client, namespace, secret_name).await {
                // AWS requires special handling: generate AWS_B64ENCODED_CREDENTIALS
                if config.infrastructure == ProviderType::Aws {
                    if let Some(creds) = AwsCredentials::from_secret(&secret) {
                        env_vars.push((
                            "AWS_B64ENCODED_CREDENTIALS".to_string(),
                            creds.to_b64_encoded(),
                        ));
                        info!(
                            provider = "aws",
                            secret = format!("{}/{}", namespace, secret_name),
                            "Generated AWS_B64ENCODED_CREDENTIALS for clusterctl"
                        );
                    }
                } else {
                    // Other providers: direct mapping from secret keys to env vars
                    for (secret_key, env_key) in info.credentials_env_map {
                        if let Some(value) = secret.get(*secret_key) {
                            env_vars.push((env_key.to_string(), value.clone()));
                        }
                    }
                    if !env_vars.is_empty() {
                        info!(
                            provider = info.name,
                            secret = format!("{}/{}", namespace, secret_name),
                            credentials_count = env_vars.len(),
                            "Loaded provider credentials for clusterctl"
                        );
                    }
                }
            }
        }

        env_vars
    }

    /// Read a secret and return its string data
    async fn read_secret(
        client: &KubeClient,
        namespace: &str,
        name: &str,
    ) -> Result<HashMap<String, String>, String> {
        use k8s_openapi::api::core::v1::Secret;

        let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
        let secret = secrets
            .get(name)
            .await
            .map_err(|e| format!("Failed to get secret {}/{}: {}", namespace, name, e))?;

        let mut data = HashMap::new();
        if let Some(string_data) = secret.string_data {
            data.extend(string_data);
        }
        if let Some(secret_data) = secret.data {
            for (key, value) in secret_data {
                if let Ok(decoded) = String::from_utf8(value.0) {
                    data.insert(key, decoded);
                }
            }
        }

        Ok(data)
    }

    /// Build clusterctl init arguments for missing providers only
    fn build_init_args(
        config: &CapiProviderConfig,
        actions: &HashMap<String, ProviderAction>,
        config_path: &str,
    ) -> Option<Vec<String>> {
        let info = &config.infra_info;

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
            args.push(info.name.to_string());

            // Add provider-specific extra init args (e.g., IPAM for Proxmox)
            for arg in info.extra_init_args {
                args.push(arg.to_string());
            }
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
        let info = &config.infra_info;

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
        args.push(format!("{}:v{}", info.name, info.version));

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
        // Create kube client for all k8s operations
        let client = KubeClient::try_default()
            .await
            .map_err(|e| Error::capi_installation(format!("Failed to create k8s client: {}", e)))?;

        // Get currently installed providers
        let installed = Self::get_installed_providers(&client).await;
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
        Self::install_cert_manager(&client).await?;

        // Handle installations first
        if needs_install {
            if let Some(args) = Self::build_init_args(config, &actions, &config_path) {
                let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                info!(args = ?args_ref, "Running clusterctl init for missing providers");

                // Read provider credentials from pre-created secret for template substitution
                let provider_env = Self::get_provider_env_vars(&client, config).await;

                let mut cmd = Command::new("timeout");
                cmd.args(&args_ref)
                    .env("GOPROXY", "off")
                    .env("CLUSTERCTL_DISABLE_VERSIONCHECK", "true");

                // Pass provider credentials as env vars for clusterctl template substitution
                for (key, value) in &provider_env {
                    cmd.env(key, value);
                }

                let output = cmd.output().map_err(|e| {
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
        )
        .expect("Docker provider should be supported");
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
    fn supported_infrastructure_providers_map_correctly() {
        for (provider, expected) in [
            (ProviderType::Aws, "aws"),
            (ProviderType::Docker, "docker"),
            (ProviderType::OpenStack, "openstack"),
            (ProviderType::Proxmox, "proxmox"),
        ] {
            let config = CapiProviderConfig::with_versions(
                provider,
                "1.12.1".to_string(),
                "0.11.0".to_string(),
            )
            .expect("supported provider should succeed");
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

        let config =
            CapiProviderConfig::new(ProviderType::Docker).expect("Docker provider should work");
        let result = ensure_capi_installed(&installer, &config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn mock_installer_propagates_errors() {
        let mut installer = MockCapiInstaller::new();
        installer
            .expect_ensure()
            .returning(|_| Err(Error::capi_installation("test error".to_string())));

        let config =
            CapiProviderConfig::new(ProviderType::Docker).expect("Docker provider should work");
        let result = ensure_capi_installed(&installer, &config).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("test error"));
    }
}
