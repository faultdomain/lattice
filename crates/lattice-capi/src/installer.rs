//! CAPI (Cluster API) provider management
//!
//! Handles installing and upgrading CAPI providers by reading pre-downloaded
//! YAML manifests, performing env var substitution, and applying them natively
//! via kube-rs. No external tools required.
//!
//! Always installs both kubeadm and RKE2 bootstrap/control-plane providers
//! to ensure move works between any clusters.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::Namespace;
use kube::api::{Api, ListParams, Patch, PatchParams, PostParams};
use kube::Client as KubeClient;
#[cfg(test)]
use mockall::automock;
use tracing::{debug, info, warn};

use lattice_common::crd::{ProviderType, SecretRef};
use lattice_common::credentials::{AwsCredentials, CredentialProvider};
use lattice_common::kube_utils::{self, ApplyOptions};
use lattice_common::{
    Error, AWS_CAPA_CREDENTIALS_SECRET, CAPA_NAMESPACE, CAPMOX_NAMESPACE, CAPO_NAMESPACE,
    OPENSTACK_CREDENTIALS_SECRET, PROXMOX_CREDENTIALS_SECRET,
};

/// Timeout for waiting on cert-manager and provider deployments
const DEPLOYMENT_READY_TIMEOUT: Duration = Duration::from_secs(300);

// =============================================================================
// Provider path mapping
// =============================================================================

/// Map (provider_name, provider_type) to the directory name under /providers/
fn provider_dir_name(name: &str, provider_type: CapiProviderType) -> &'static str {
    match (name, provider_type) {
        ("cluster-api", CapiProviderType::Core) => "cluster-api",
        ("kubeadm", CapiProviderType::Bootstrap) => "bootstrap-kubeadm",
        ("kubeadm", CapiProviderType::ControlPlane) => "control-plane-kubeadm",
        ("rke2", CapiProviderType::Bootstrap) => "bootstrap-rke2",
        ("rke2", CapiProviderType::ControlPlane) => "control-plane-rke2",
        ("docker", CapiProviderType::Infrastructure) => "infrastructure-docker",
        ("proxmox", CapiProviderType::Infrastructure) => "infrastructure-proxmox",
        ("aws", CapiProviderType::Infrastructure) => "infrastructure-aws",
        ("openstack", CapiProviderType::Infrastructure) => "infrastructure-openstack",
        ("in-cluster", _) => "ipam-in-cluster",
        _ => "unknown",
    }
}

/// Map (provider_name, provider_type) to the expected Kubernetes namespace
fn provider_namespace(name: &str, provider_type: CapiProviderType) -> Option<&'static str> {
    match (name, provider_type) {
        ("cluster-api", CapiProviderType::Core) => Some("capi-system"),
        ("kubeadm", CapiProviderType::Bootstrap) => Some("capi-kubeadm-bootstrap-system"),
        ("kubeadm", CapiProviderType::ControlPlane) => Some("capi-kubeadm-control-plane-system"),
        ("rke2", CapiProviderType::Bootstrap) => Some("rke2-bootstrap-system"),
        ("rke2", CapiProviderType::ControlPlane) => Some("rke2-control-plane-system"),
        ("docker", CapiProviderType::Infrastructure) => Some("capd-system"),
        ("proxmox", CapiProviderType::Infrastructure) => Some(CAPMOX_NAMESPACE),
        ("aws", CapiProviderType::Infrastructure) => Some(CAPA_NAMESPACE),
        ("openstack", CapiProviderType::Infrastructure) => Some(CAPO_NAMESPACE),
        ("in-cluster", _) => Some("caip-in-cluster-system"),
        _ => None,
    }
}

/// Map (provider_name, provider_type) to the component YAML filenames
fn provider_component_files(
    name: &str,
    provider_type: CapiProviderType,
) -> &'static [&'static str] {
    match (name, provider_type) {
        ("cluster-api", CapiProviderType::Core) => &["core-components.yaml"],
        ("kubeadm", CapiProviderType::Bootstrap) => &["bootstrap-components.yaml"],
        ("kubeadm", CapiProviderType::ControlPlane) => &["control-plane-components.yaml"],
        ("rke2", CapiProviderType::Bootstrap) => &["bootstrap-components.yaml"],
        ("rke2", CapiProviderType::ControlPlane) => &["control-plane-components.yaml"],
        ("docker", CapiProviderType::Infrastructure) => {
            &["infrastructure-components-development.yaml"]
        }
        ("proxmox", CapiProviderType::Infrastructure) => &["infrastructure-components.yaml"],
        ("aws", CapiProviderType::Infrastructure) => &["infrastructure-components.yaml"],
        ("openstack", CapiProviderType::Infrastructure) => &["infrastructure-components.yaml"],
        ("in-cluster", _) => &["ipam-components.yaml"],
        _ => &[],
    }
}

// =============================================================================
// Env var substitution
// =============================================================================

/// Substitute `${VAR}` patterns in YAML, handling bash-style defaults.
///
/// Supported patterns (matching clusterctl behavior):
/// - `${VAR}` — replaced with value from `vars`, or left as-is if missing
/// - `${VAR:=default}` — replaced with value from `vars`, or `default` if missing
/// - `${VAR:-default}` — same as `:=`
/// - `${VAR="default"}` — replaced with value from `vars`, or `default` if missing
/// - `${VAR/#pattern/replacement}` — bash string substitution (resolved to value or empty)
fn substitute_vars(yaml: &str, vars: &[(String, String)]) -> String {
    let var_map: HashMap<&str, &str> = vars.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let mut result = String::with_capacity(yaml.len());
    let mut remaining = yaml;

    while let Some(start) = remaining.find("${") {
        result.push_str(&remaining[..start]);
        let after_start = &remaining[start + 2..];

        if let Some(end) = after_start.find('}') {
            let expr = &after_start[..end];
            let replacement = resolve_var_expr(expr, &var_map);
            result.push_str(&replacement);
            remaining = &after_start[end + 1..];
        } else {
            // No closing brace — emit literal and advance past "${"
            result.push_str("${");
            remaining = after_start;
        }
    }
    result.push_str(remaining);
    result
}

/// Resolve a single variable expression (the content between `${` and `}`).
fn resolve_var_expr(expr: &str, vars: &HashMap<&str, &str>) -> String {
    // ${VAR/#pattern/replacement} — bash string substitution
    if let Some(slash_pos) = expr.find("/#") {
        let var_name = &expr[..slash_pos];
        return vars
            .get(var_name)
            .map(|s| s.to_string())
            .unwrap_or_default();
    }

    // ${VAR:=default} or ${VAR:-default}
    if let Some(pos) = expr.find(":=").or_else(|| expr.find(":-")) {
        let var_name = &expr[..pos];
        let default = &expr[pos + 2..];
        return vars
            .get(var_name)
            .map(|s| s.to_string())
            .unwrap_or_else(|| default.to_string());
    }

    // ${VAR="default"} — strip surrounding quotes from default
    if let Some(pos) = expr.find('=') {
        let var_name = &expr[..pos];
        let default = expr[pos + 1..].trim_matches('"');
        return vars
            .get(var_name)
            .map(|s| s.to_string())
            .unwrap_or_else(|| default.to_string());
    }

    // ${VAR} — plain substitution, leave as-is if missing
    vars.get(expr)
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("${{{}}}", expr))
}

// =============================================================================
// Credential helpers (free functions, testable without a struct)
// =============================================================================

/// Read a Kubernetes secret and return its data as string key-value pairs.
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

/// Build provider-specific env vars for template substitution.
///
/// Reads credentials from pre-created secrets to substitute template
/// variables like `${PROXMOX_URL}` in provider manifests.
async fn get_provider_env_vars(
    client: &KubeClient,
    config: &CapiProviderConfig,
) -> Vec<(String, String)> {
    let mut env_vars = Vec::new();
    let info = &config.infra_info;

    if let Some((namespace, secret_name)) = config.credentials_secret() {
        if let Ok(secret) = read_secret(client, namespace, secret_name).await {
            if config.infrastructure == ProviderType::Aws {
                match AwsCredentials::from_secret(&secret) {
                    Ok(creds) => {
                        env_vars.push((
                            "AWS_B64ENCODED_CREDENTIALS".to_string(),
                            creds.to_b64_encoded(),
                        ));
                        info!(provider = "aws", "Generated AWS_B64ENCODED_CREDENTIALS");
                    }
                    Err(e) => {
                        warn!(provider = "aws", error = %e, "Failed to load AWS credentials");
                    }
                }
            } else {
                for (secret_key, env_key) in info.credentials_env_map {
                    if let Some(value) = secret.get(*secret_key) {
                        env_vars.push((env_key.to_string(), value.clone()));
                    }
                }
                if !env_vars.is_empty() {
                    info!(
                        provider = info.name,
                        credentials_count = env_vars.len(),
                        "Loaded provider credentials"
                    );
                }
            }
        }
    }

    env_vars
}

// =============================================================================
// Version detection (free functions)
// =============================================================================

/// All known provider (name, type) pairs for discovery.
const KNOWN_PROVIDERS: &[(&str, CapiProviderType)] = &[
    ("cluster-api", CapiProviderType::Core),
    ("kubeadm", CapiProviderType::Bootstrap),
    ("kubeadm", CapiProviderType::ControlPlane),
    ("rke2", CapiProviderType::Bootstrap),
    ("rke2", CapiProviderType::ControlPlane),
    ("docker", CapiProviderType::Infrastructure),
    ("proxmox", CapiProviderType::Infrastructure),
    ("openstack", CapiProviderType::Infrastructure),
    ("aws", CapiProviderType::Infrastructure),
    ("in-cluster", CapiProviderType::Infrastructure),
];

/// Get installed CAPI providers by checking provider namespaces in parallel.
async fn get_installed_providers(client: &KubeClient) -> Vec<InstalledProvider> {
    let futures: Vec<_> = KNOWN_PROVIDERS
        .iter()
        .filter_map(|(name, provider_type)| {
            let namespace = provider_namespace(name, *provider_type)?;
            let client = client.clone();
            let name = *name;
            let provider_type = *provider_type;
            Some(async move {
                match get_provider_version(&client, namespace).await {
                    Ok(Some(version)) => Some(InstalledProvider {
                        name: name.to_string(),
                        provider_type,
                        version,
                        namespace: namespace.to_string(),
                    }),
                    Ok(None) => None,
                    Err(e) => {
                        tracing::warn!(namespace = %namespace, error = %e, "Failed to check provider version");
                        None
                    }
                }
            })
        })
        .collect();

    let results = futures::future::join_all(futures).await;
    results.into_iter().flatten().collect()
}

/// Get provider version from deployment labels.
///
/// Returns `Ok(Some(version))` if found, `Ok(None)` if namespace doesn't exist.
async fn get_provider_version(
    client: &KubeClient,
    namespace: &str,
) -> Result<Option<String>, String> {
    let namespaces: Api<Namespace> = Api::all(client.clone());
    match namespaces.get(namespace).await {
        Ok(_) => {}
        Err(kube::Error::Api(ae)) if ae.code == 404 => return Ok(None),
        Err(e) => return Err(format!("failed to check namespace {}: {}", namespace, e)),
    }

    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let list = deployments
        .list(&ListParams::default())
        .await
        .map_err(|e| format!("failed to list deployments in {}: {}", namespace, e))?;

    let Some(deployment) = list.items.first() else {
        return Ok(None);
    };
    let Some(labels) = deployment.metadata.labels.as_ref() else {
        return Ok(Some("unknown".to_string()));
    };

    if let Some(version) = labels.get("app.kubernetes.io/version") {
        if !version.is_empty() {
            return Ok(Some(version.clone()));
        }
    }

    // Fallback: RKE2 providers use a different label
    if let Some(version) = labels.get("cluster-api.cattle.io/version") {
        if !version.is_empty() {
            return Ok(Some(version.clone()));
        }
    }

    Ok(Some("unknown".to_string()))
}

/// Compute what actions are needed for each provider.
fn compute_provider_actions(
    installed: &[InstalledProvider],
    desired: &[DesiredProvider],
) -> HashMap<String, ProviderAction> {
    let mut actions = HashMap::new();

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
            if installed_provider.version == desired_provider.version
                || installed_provider.version == "unknown"
            {
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
            actions.insert(action_key, ProviderAction::Install);
        }
    }

    actions
}

// =============================================================================
// Credential copying
// =============================================================================

/// Copy credentials from CloudProvider's secret reference to the CAPI provider namespace.
///
/// CAPI providers expect credentials in specific namespaces with specific names.
/// This copies the source secret to the location expected by each CAPI provider.
pub async fn copy_credentials_to_provider_namespace(
    client: &KubeClient,
    provider: ProviderType,
    secret_ref: &SecretRef,
) -> Result<(), Error> {
    use k8s_openapi::api::core::v1::{Namespace, Secret};

    let (target_namespace, target_name) = match provider {
        ProviderType::Aws => (CAPA_NAMESPACE, AWS_CAPA_CREDENTIALS_SECRET),
        ProviderType::Proxmox => (CAPMOX_NAMESPACE, PROXMOX_CREDENTIALS_SECRET),
        ProviderType::OpenStack => (CAPO_NAMESPACE, OPENSTACK_CREDENTIALS_SECRET),
        _ => return Ok(()),
    };

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

    let ns_api: Api<Namespace> = Api::all(client.clone());
    let ns = Namespace {
        metadata: kube::core::ObjectMeta {
            name: Some(target_namespace.to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let _ = ns_api.create(&PostParams::default(), &ns).await;

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

// =============================================================================
// Public types
// =============================================================================

/// Provider types supported by CAPI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapiProviderType {
    Core,
    Bootstrap,
    ControlPlane,
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
    pub name: String,
    pub provider_type: CapiProviderType,
    pub version: String,
    pub namespace: String,
}

/// Desired provider configuration
#[derive(Debug, Clone)]
pub struct DesiredProvider {
    pub name: String,
    pub provider_type: CapiProviderType,
    pub version: String,
}

/// Action to take for a provider
#[derive(Debug, Clone, PartialEq)]
pub enum ProviderAction {
    Skip,
    Install,
    Upgrade { from: String, to: String },
}

/// Provider-specific configuration for CAPI infrastructure providers
#[derive(Debug, Clone)]
pub struct InfraProviderInfo {
    pub name: &'static str,
    pub version: String,
    pub credentials_secret: Option<(&'static str, &'static str)>,
    pub credentials_env_map: &'static [(&'static str, &'static str)],
    /// Whether this provider needs ipam-in-cluster (Proxmox)
    pub needs_ipam: bool,
}

impl InfraProviderInfo {
    /// Get provider info for a given infrastructure type
    pub fn for_provider(provider: ProviderType, capi_version: &str) -> Result<Self, Error> {
        match provider {
            ProviderType::Aws => Ok(Self {
                name: "aws",
                version: env!("CAPA_VERSION").to_string(),
                credentials_secret: Some((CAPA_NAMESPACE, AWS_CAPA_CREDENTIALS_SECRET)),
                credentials_env_map: &[],
                needs_ipam: false,
            }),
            ProviderType::Docker => Ok(Self {
                name: "docker",
                version: capi_version.to_string(),
                credentials_secret: None,
                credentials_env_map: &[],
                needs_ipam: false,
            }),
            ProviderType::OpenStack => Ok(Self {
                name: "openstack",
                version: env!("CAPO_VERSION").to_string(),
                credentials_secret: Some((CAPO_NAMESPACE, OPENSTACK_CREDENTIALS_SECRET)),
                credentials_env_map: &[],
                needs_ipam: false,
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
                needs_ipam: true,
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
    pub infrastructure: ProviderType,
    pub capi_version: String,
    pub rke2_version: String,
    pub infra_info: InfraProviderInfo,
    pub credentials_secret_override: Option<(String, String)>,
}

impl CapiProviderConfig {
    /// Create a new CAPI provider configuration from compile-time versions.
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

    pub fn with_credentials_secret(mut self, namespace: String, name: String) -> Self {
        self.credentials_secret_override = Some((namespace, name));
        self
    }

    /// Get the effective credentials secret location.
    pub fn credentials_secret(&self) -> Option<(&str, &str)> {
        if let Some((ref ns, ref name)) = self.credentials_secret_override {
            Some((ns.as_str(), name.as_str()))
        } else {
            self.infra_info.credentials_secret
        }
    }

    /// Create config with explicit versions (for testing).
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
            needs_ipam: false,
        };

        Ok(Self {
            infrastructure,
            capi_version,
            rke2_version,
            infra_info,
            credentials_secret_override: None,
        })
    }

    /// Get the list of desired providers based on this config.
    pub fn desired_providers(&self) -> Vec<DesiredProvider> {
        let mut providers = vec![
            DesiredProvider {
                name: "cluster-api".to_string(),
                provider_type: CapiProviderType::Core,
                version: format!("v{}", self.capi_version),
            },
            DesiredProvider {
                name: "kubeadm".to_string(),
                provider_type: CapiProviderType::Bootstrap,
                version: format!("v{}", self.capi_version),
            },
            DesiredProvider {
                name: "kubeadm".to_string(),
                provider_type: CapiProviderType::ControlPlane,
                version: format!("v{}", self.capi_version),
            },
            DesiredProvider {
                name: "rke2".to_string(),
                provider_type: CapiProviderType::Bootstrap,
                version: format!("v{}", self.rke2_version),
            },
            DesiredProvider {
                name: "rke2".to_string(),
                provider_type: CapiProviderType::ControlPlane,
                version: format!("v{}", self.rke2_version),
            },
            DesiredProvider {
                name: self.infra_info.name.to_string(),
                provider_type: CapiProviderType::Infrastructure,
                version: format!("v{}", self.infra_info.version),
            },
        ];

        // Proxmox needs the IPAM in-cluster provider
        if self.infra_info.needs_ipam {
            providers.push(DesiredProvider {
                name: "in-cluster".to_string(),
                provider_type: CapiProviderType::Infrastructure,
                version: format!("v{}", env!("IPAM_IN_CLUSTER_VERSION")),
            });
        }

        providers
    }

    /// Return the Kubernetes namespaces where all desired CAPI providers run.
    ///
    /// Used by the installer to wait for deployments before starting the pivot.
    pub fn provider_namespaces(&self) -> Vec<&'static str> {
        self.desired_providers()
            .iter()
            .filter_map(|p| provider_namespace(&p.name, p.provider_type))
            .collect()
    }
}

// =============================================================================
// Installer trait and implementation
// =============================================================================

/// Trait for installing CAPI providers
#[cfg_attr(test, automock)]
#[async_trait]
pub trait CapiInstaller: Send + Sync {
    /// Ensure CAPI providers are installed and up to date.
    async fn ensure(&self, config: &CapiProviderConfig) -> Result<(), Error>;
}

/// Native CAPI installer that reads pre-downloaded YAML manifests and applies them directly.
pub struct NativeInstaller;

impl NativeInstaller {
    pub fn new() -> Self {
        Self
    }

    /// Resolve the providers directory from env var or compile-time default.
    fn providers_dir() -> PathBuf {
        let dir = std::env::var("PROVIDERS_DIR").unwrap_or_else(|_| {
            option_env!("PROVIDERS_DIR")
                .unwrap_or("/providers")
                .to_string()
        });
        PathBuf::from(dir)
    }

    /// Read a provider's component YAML files from disk.
    fn read_provider_manifests(
        providers_dir: &Path,
        dir_name: &str,
        version: &str,
        components: &[&str],
    ) -> Result<Vec<String>, Error> {
        let provider_path = providers_dir.join(dir_name).join(version);
        let mut manifests = Vec::new();

        for component in components {
            let file_path = provider_path.join(component);
            let content = std::fs::read_to_string(&file_path).map_err(|e| {
                Error::capi_installation(format!(
                    "Failed to read provider manifest {}: {}",
                    file_path.display(),
                    e
                ))
            })?;
            manifests.push(content);
        }

        Ok(manifests)
    }

    /// Split a multi-document YAML string into individual documents.
    fn split_yaml_documents(yaml: &str) -> Vec<String> {
        yaml.split("\n---")
            .map(|doc| doc.trim().to_string())
            .filter(|doc| !doc.is_empty())
            .collect()
    }

    /// Apply a single provider's manifests with env var substitution.
    async fn apply_provider(
        client: &KubeClient,
        providers_dir: &Path,
        desired: &DesiredProvider,
        env_vars: &[(String, String)],
    ) -> Result<(), Error> {
        let dir_name = provider_dir_name(&desired.name, desired.provider_type);
        let components = provider_component_files(&desired.name, desired.provider_type);

        let raw_manifests =
            Self::read_provider_manifests(providers_dir, dir_name, &desired.version, components)?;

        let mut all_documents = Vec::new();
        for raw in &raw_manifests {
            let substituted = substitute_vars(raw, env_vars);
            all_documents.extend(Self::split_yaml_documents(&substituted));
        }

        info!(
            provider = %desired.name,
            provider_type = %desired.provider_type,
            version = %desired.version,
            documents = all_documents.len(),
            "Applying provider manifests"
        );

        kube_utils::apply_manifests_with_discovery(
            client,
            &all_documents,
            &ApplyOptions::default(),
        )
        .await
        .map_err(|e| {
            Error::capi_installation(format!(
                "Failed to apply {} {}: {}",
                desired.provider_type, desired.name, e
            ))
        })?;

        // Patch provider deployments with control-plane toleration so they
        // schedule on tainted CP nodes before workers are available.
        if let Some(namespace) = provider_namespace(&desired.name, desired.provider_type) {
            patch_deployments_with_cp_toleration(client, namespace).await?;
        }

        Ok(())
    }
}

/// Patch all Deployments in a namespace to tolerate the control-plane NoSchedule taint.
///
/// Uses strategic merge patch on the pod template spec. This is idempotent —
/// Kubernetes merges tolerations by key+effect, so re-patching is a no-op.
/// Only called during provider install/upgrade, not on every reconcile.
async fn patch_deployments_with_cp_toleration(
    client: &KubeClient,
    namespace: &str,
) -> Result<(), Error> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let list = match deployments.list(&ListParams::default()).await {
        Ok(list) => list,
        Err(kube::Error::Api(ae)) if ae.code == 404 => return Ok(()),
        Err(e) => {
            return Err(Error::capi_installation(format!(
                "Failed to list deployments in {}: {}",
                namespace, e
            )));
        }
    };

    let patch = serde_json::json!({
        "spec": {
            "template": {
                "spec": {
                    "tolerations": [{
                        "key": "node-role.kubernetes.io/control-plane",
                        "operator": "Exists",
                        "effect": "NoSchedule"
                    }]
                }
            }
        }
    });

    for deploy in &list.items {
        let name = deploy.metadata.name.as_deref().unwrap_or("unknown");
        deployments
            .patch(
                name,
                &PatchParams::default(),
                &Patch::Strategic(&patch),
            )
            .await
            .map_err(|e| {
                Error::capi_installation(format!(
                    "Failed to patch deployment {}/{} with CP toleration: {}",
                    namespace, name, e
                ))
            })?;
        debug!(namespace = %namespace, deployment = %name, "patched with control-plane toleration");
    }

    Ok(())
}

impl Default for NativeInstaller {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CapiInstaller for NativeInstaller {
    async fn ensure(&self, config: &CapiProviderConfig) -> Result<(), Error> {
        let client = kube_utils::create_client(None)
            .await
            .map_err(|e| Error::capi_installation(format!("Failed to create k8s client: {}", e)))?;

        let installed = get_installed_providers(&client).await;
        let desired = config.desired_providers();

        debug!(
            installed = ?installed.iter().map(|p| format!("{}:{:?}@{}", p.name, p.provider_type, p.version)).collect::<Vec<_>>(),
            "Found installed CAPI providers"
        );

        let actions = compute_provider_actions(&installed, &desired);

        for (key, action) in &actions {
            match action {
                ProviderAction::Skip => debug!(provider = %key, "Provider up to date"),
                ProviderAction::Install => info!(provider = %key, "Provider will be installed"),
                ProviderAction::Upgrade { from, to } => {
                    info!(provider = %key, from = %from, to = %to, "Provider will be upgraded")
                }
            }
        }

        let needs_work = actions
            .values()
            .any(|a| *a == ProviderAction::Install || matches!(a, ProviderAction::Upgrade { .. }));

        if !needs_work {
            info!("All CAPI providers are up to date");
            return Ok(());
        }

        let providers_dir = Self::providers_dir();

        // NOTE: cert-manager is installed separately via Helm-rendered manifests
        // (see lattice-infra::bootstrap::cert_manager). It must be ready before
        // this function is called.

        // Read provider credentials for template substitution
        let env_vars = get_provider_env_vars(&client, config).await;

        // Apply each provider that needs install or upgrade
        for desired_provider in &desired {
            let action_key = format!(
                "{}:{:?}",
                desired_provider.name, desired_provider.provider_type
            );
            let action = actions.get(&action_key).unwrap_or(&ProviderAction::Skip);

            match action {
                ProviderAction::Skip => continue,
                ProviderAction::Install => {
                    Self::apply_provider(&client, &providers_dir, desired_provider, &env_vars)
                        .await?;
                }
                ProviderAction::Upgrade { from, to } => {
                    info!(
                        provider = %desired_provider.name,
                        from = %from,
                        to = %to,
                        "Upgrading provider (re-applying manifests)"
                    );
                    // For upgrades, re-apply the manifests (SSA handles diffs)
                    if let Err(e) =
                        Self::apply_provider(&client, &providers_dir, desired_provider, &env_vars)
                            .await
                    {
                        warn!(
                            provider = %desired_provider.name,
                            error = %e,
                            "Provider upgrade had issues, continuing"
                        );
                    }
                }
            }
        }

        // Wait for all provider deployments to be ready
        // Check each provider namespace that was installed/upgraded
        for desired_provider in &desired {
            let action_key = format!(
                "{}:{:?}",
                desired_provider.name, desired_provider.provider_type
            );
            let action = actions.get(&action_key).unwrap_or(&ProviderAction::Skip);
            if *action == ProviderAction::Skip {
                continue;
            }

            let Some(namespace) =
                provider_namespace(&desired_provider.name, desired_provider.provider_type)
            else {
                debug!(provider = %desired_provider.name, "Unknown provider namespace, skipping readiness check");
                continue;
            };

            info!(namespace = %namespace, "Waiting for provider deployments...");
            if let Err(e) =
                kube_utils::wait_for_all_deployments(&client, namespace, DEPLOYMENT_READY_TIMEOUT)
                    .await
            {
                warn!(namespace = %namespace, error = %e, "Provider readiness check failed, continuing");
            }
        }

        info!("CAPI providers installed successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitute_vars_replaces_patterns() {
        let yaml = "url: ${PROXMOX_URL}\ntoken: ${PROXMOX_TOKEN}";
        let vars = vec![
            (
                "PROXMOX_URL".to_string(),
                "https://pve.example.com".to_string(),
            ),
            ("PROXMOX_TOKEN".to_string(), "root@pam!token".to_string()),
        ];
        let result = substitute_vars(yaml, &vars);
        assert_eq!(
            result,
            "url: https://pve.example.com\ntoken: root@pam!token"
        );
    }

    #[test]
    fn substitute_vars_leaves_unknown_patterns() {
        let yaml = "value: ${UNKNOWN_VAR}";
        let vars = vec![("OTHER".to_string(), "val".to_string())];
        let result = substitute_vars(yaml, &vars);
        assert_eq!(result, "value: ${UNKNOWN_VAR}");
    }

    #[test]
    fn substitute_vars_handles_colon_equals_default() {
        let yaml = "- --insecure-diagnostics=${CAPI_INSECURE_DIAGNOSTICS:=false}";
        let result = substitute_vars(yaml, &[]);
        assert_eq!(result, "- --insecure-diagnostics=false");
    }

    #[test]
    fn substitute_vars_colon_equals_prefers_provided_value() {
        let yaml = "- --insecure-diagnostics=${CAPI_INSECURE_DIAGNOSTICS:=false}";
        let vars = vec![("CAPI_INSECURE_DIAGNOSTICS".to_string(), "true".to_string())];
        let result = substitute_vars(yaml, &vars);
        assert_eq!(result, "- --insecure-diagnostics=true");
    }

    #[test]
    fn substitute_vars_handles_colon_dash_default() {
        let yaml = "value: ${MY_VAR:-hello}";
        let result = substitute_vars(yaml, &[]);
        assert_eq!(result, "value: hello");
    }

    #[test]
    fn substitute_vars_handles_equals_quoted_default() {
        let yaml = "host: ${PROXMOX_URL=\"\"}";
        let result = substitute_vars(yaml, &[]);
        assert_eq!(result, "host: ");
    }

    #[test]
    fn substitute_vars_handles_bash_string_substitution() {
        // ${VAR/#pattern/replacement} should resolve to value or empty
        let yaml = "role: ${AWS_CONTROLLER_IAM_ROLE/#arn/eks.amazonaws.com/role-arn: arn}";
        let result = substitute_vars(yaml, &[]);
        assert_eq!(result, "role: ");
    }

    #[test]
    fn substitute_vars_handles_multiple_defaults_in_one_string() {
        let yaml = "a=${X:=1} b=${Y:=2} c=${Z:=3}";
        let vars = vec![("Y".to_string(), "override".to_string())];
        let result = substitute_vars(yaml, &vars);
        assert_eq!(result, "a=1 b=override c=3");
    }

    #[test]
    fn split_yaml_documents_handles_multi_doc() {
        let yaml = "kind: A\n---\nkind: B\n---\nkind: C";
        let docs = NativeInstaller::split_yaml_documents(yaml);
        assert_eq!(docs.len(), 3);
        assert_eq!(docs[0], "kind: A");
        assert_eq!(docs[1], "kind: B");
        assert_eq!(docs[2], "kind: C");
    }

    #[test]
    fn split_yaml_documents_filters_empty() {
        let yaml = "kind: A\n---\n\n---\nkind: B";
        let docs = NativeInstaller::split_yaml_documents(yaml);
        assert_eq!(docs.len(), 2);
    }

    #[test]
    fn provider_dir_name_maps_correctly() {
        assert_eq!(
            provider_dir_name("cluster-api", CapiProviderType::Core),
            "cluster-api"
        );
        assert_eq!(
            provider_dir_name("kubeadm", CapiProviderType::Bootstrap),
            "bootstrap-kubeadm"
        );
        assert_eq!(
            provider_dir_name("kubeadm", CapiProviderType::ControlPlane),
            "control-plane-kubeadm"
        );
        assert_eq!(
            provider_dir_name("rke2", CapiProviderType::Bootstrap),
            "bootstrap-rke2"
        );
        assert_eq!(
            provider_dir_name("docker", CapiProviderType::Infrastructure),
            "infrastructure-docker"
        );
        assert_eq!(
            provider_dir_name("proxmox", CapiProviderType::Infrastructure),
            "infrastructure-proxmox"
        );
        assert_eq!(
            provider_dir_name("in-cluster", CapiProviderType::Infrastructure),
            "ipam-in-cluster"
        );
    }

    #[test]
    fn provider_component_files_returns_correct_files() {
        assert_eq!(
            provider_component_files("cluster-api", CapiProviderType::Core),
            &["core-components.yaml"]
        );
        assert_eq!(
            provider_component_files("docker", CapiProviderType::Infrastructure),
            &["infrastructure-components-development.yaml"]
        );
        assert_eq!(
            provider_component_files("in-cluster", CapiProviderType::Infrastructure),
            &["ipam-components.yaml"]
        );
    }

    #[test]
    fn desired_providers_includes_all_required() {
        let config = CapiProviderConfig::with_versions(
            ProviderType::Docker,
            "1.12.1".to_string(),
            "0.11.0".to_string(),
        )
        .expect("Docker provider should be supported");
        let providers = config.desired_providers();

        assert_eq!(providers.len(), 6);
        assert!(providers
            .iter()
            .any(|p| p.name == "cluster-api" && p.provider_type == CapiProviderType::Core));
        assert!(providers
            .iter()
            .any(|p| p.name == "kubeadm" && p.provider_type == CapiProviderType::Bootstrap));
        assert!(providers
            .iter()
            .any(|p| p.name == "kubeadm" && p.provider_type == CapiProviderType::ControlPlane));
        assert!(providers
            .iter()
            .any(|p| p.name == "rke2" && p.provider_type == CapiProviderType::Bootstrap));
        assert!(providers
            .iter()
            .any(|p| p.name == "rke2" && p.provider_type == CapiProviderType::ControlPlane));
        assert!(providers
            .iter()
            .any(|p| p.name == "docker" && p.provider_type == CapiProviderType::Infrastructure));
    }

    #[test]
    fn desired_providers_includes_ipam_for_proxmox() {
        let config =
            CapiProviderConfig::new(ProviderType::Proxmox).expect("Proxmox should be supported");
        let providers = config.desired_providers();
        assert!(providers.iter().any(|p| p.name == "in-cluster"));
    }

    #[test]
    fn compute_actions_identifies_missing_providers() {
        let installed = vec![];
        let desired = vec![DesiredProvider {
            name: "cluster-api".to_string(),
            provider_type: CapiProviderType::Core,
            version: "v1.12.1".to_string(),
        }];

        let actions = compute_provider_actions(&installed, &desired);
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

        let actions = compute_provider_actions(&installed, &desired);
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

        let actions = compute_provider_actions(&installed, &desired);
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

        let actions = compute_provider_actions(&installed, &desired);
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
        let result = installer.ensure(&config).await;
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
        let result = installer.ensure(&config).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("test error"));
    }
}
