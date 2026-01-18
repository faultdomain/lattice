//! Flux GitOps manifest generation
//!
//! Generates Flux manifests using `helm template` for consistent deployment.
//! Flux enables GitOps self-management - clusters watch their config in git
//! and automatically apply changes.
//!
//! The FluxReconciler renders base Flux components (controllers, CRDs).
//! GitOps resources (GitRepository, Kustomization, Secret) are generated
//! based on the parent cluster's GitOpsSpec and included in post-pivot manifests.

use std::process::Command;
use tracing::info;

use crate::crd::GitOpsSpec;

/// Default charts directory (set by LATTICE_CHARTS_DIR env var in container)
const DEFAULT_CHARTS_DIR: &str = "/charts";

/// Get charts directory - checks runtime env var first, then compile-time, then default
fn get_charts_dir() -> String {
    if let Ok(dir) = std::env::var("LATTICE_CHARTS_DIR") {
        return dir;
    }
    if let Some(dir) = option_env!("LATTICE_CHARTS_DIR") {
        return dir.to_string();
    }
    DEFAULT_CHARTS_DIR.to_string()
}

/// Flux configuration
#[derive(Debug, Clone)]
pub struct FluxConfig {
    /// Chart version (pinned to Lattice release)
    pub version: &'static str,
}

impl Default for FluxConfig {
    fn default() -> Self {
        Self {
            version: env!("FLUX_VERSION"),
        }
    }
}

/// Flux manifest generator
///
/// Renders Flux manifests via helm template. These are the base components
/// (source-controller, kustomize-controller, etc.). GitRepository and
/// Kustomization resources are created separately based on cluster config.
pub struct FluxReconciler {
    config: FluxConfig,
    manifests: Vec<String>,
}

impl FluxReconciler {
    /// Create with default config
    pub fn new() -> Result<Self, String> {
        Self::with_config(FluxConfig::default())
    }

    /// Create with custom config
    pub fn with_config(config: FluxConfig) -> Result<Self, String> {
        let manifests = Self::render_manifests(&config)?;
        Ok(Self { config, manifests })
    }

    /// Get the pre-rendered manifests
    pub fn manifests(&self) -> &[String] {
        &self.manifests
    }

    /// Get the expected version
    pub fn version(&self) -> &str {
        self.config.version
    }

    /// Render Flux manifests using helm template
    fn render_manifests(config: &FluxConfig) -> Result<Vec<String>, String> {
        let charts_dir = get_charts_dir();
        let chart_path = format!("{}/flux2-{}.tgz", charts_dir, config.version);

        info!(
            charts_dir = %charts_dir,
            chart_path = %chart_path,
            version = %config.version,
            "Rendering Flux manifests"
        );

        if !std::path::Path::new(&chart_path).exists() {
            // List what's actually in the charts directory
            let contents = std::fs::read_dir(&charts_dir)
                .map(|entries| {
                    entries
                        .filter_map(|e| e.ok())
                        .map(|e| e.file_name().to_string_lossy().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|e| format!("failed to read dir: {}", e));

            return Err(format!(
                "Flux chart not found at {} (charts_dir={}, contents=[{}])",
                chart_path, charts_dir, contents
            ));
        }

        // Flux helm values
        let values = [
            // Enable image automation for GitOps image updates
            "--set",
            "imageAutomationController.create=true",
            "--set",
            "imageReflectorController.create=true",
            // Disable NetworkPolicy - not all clusters have a CNI that supports it
            "--set",
            "policies.create=false",
        ];

        let output = Command::new("helm")
            .args([
                "template",
                "flux",
                &chart_path,
                "--namespace",
                "flux-system",
                "--create-namespace",
            ])
            .args(values)
            .output()
            .map_err(|e| format!("failed to run helm: {} (chart_path={})", e, chart_path))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "helm template failed: {} (chart_path={})",
                stderr, chart_path
            ));
        }

        let yaml_str = String::from_utf8_lossy(&output.stdout);

        let manifests: Vec<String> = yaml_str
            .split("\n---")
            .map(|doc| doc.trim())
            .filter(|doc| !doc.is_empty() && doc.contains("kind:"))
            .map(|doc| {
                if doc.starts_with("---") {
                    doc.to_string()
                } else {
                    format!("---\n{}", doc)
                }
            })
            .collect();

        info!(
            count = manifests.len(),
            version = config.version,
            "Rendered Flux manifests"
        );
        Ok(manifests)
    }
}

/// Resolved git credentials (read from a Kubernetes Secret)
#[derive(Clone, Debug, Default)]
pub struct ResolvedGitCredentials {
    /// SSH identity key (base64 encoded)
    pub ssh_identity: Option<String>,
    /// SSH known_hosts (base64 encoded)
    pub ssh_known_hosts: Option<String>,
    /// HTTPS username (base64 encoded)
    pub https_username: Option<String>,
    /// HTTPS password/token (base64 encoded)
    pub https_password: Option<String>,
}

impl ResolvedGitCredentials {
    /// Check if SSH credentials are present
    pub fn has_ssh(&self) -> bool {
        self.ssh_identity.is_some()
    }

    /// Check if HTTPS credentials are present
    pub fn has_https(&self) -> bool {
        self.https_username.is_some() && self.https_password.is_some()
    }

    /// Check if any credentials are present
    pub fn has_any(&self) -> bool {
        self.has_ssh() || self.has_https()
    }
}

/// Generate GitOps resource manifests for a cluster
///
/// Creates the cluster-specific resources needed for Flux GitOps:
/// - Secret with git credentials (if provided)
/// - GitRepository pointing to the repo
/// - Kustomization for the cluster's path
///
/// The base Flux controllers are installed/upgraded by the agent's controller.
pub fn generate_gitops_resources(
    gitops: &GitOpsSpec,
    cluster_name: &str,
    credentials: Option<&ResolvedGitCredentials>,
) -> Vec<String> {
    let mut manifests = Vec::new();
    let cluster_path = gitops.cluster_path(cluster_name);

    // Namespace (flux-system should exist from base install, but ensure it)
    manifests.push(
        r#"---
apiVersion: v1
kind: Namespace
metadata:
  name: flux-system
"#
        .to_string(),
    );

    // Git credentials Secret (if credentials were resolved from the parent's secret)
    let has_creds = credentials.map(|c| c.has_any()).unwrap_or(false);
    if let Some(creds) = credentials {
        if creds.has_ssh() {
            let identity = creds.ssh_identity.as_deref().unwrap_or("");
            let known_hosts = creds.ssh_known_hosts.as_deref().unwrap_or("");
            manifests.push(format!(
                r#"---
apiVersion: v1
kind: Secret
metadata:
  name: flux-git-auth
  namespace: flux-system
type: Opaque
data:
  identity: {identity}
  known_hosts: {known_hosts}
"#
            ));
        } else if creds.has_https() {
            let username = creds.https_username.as_deref().unwrap_or("");
            let password = creds.https_password.as_deref().unwrap_or("");
            manifests.push(format!(
                r#"---
apiVersion: v1
kind: Secret
metadata:
  name: flux-git-auth
  namespace: flux-system
type: Opaque
data:
  username: {username}
  password: {password}
"#
            ));
        }
    }

    // GitRepository
    let secret_ref = if has_creds {
        r#"
  secretRef:
    name: flux-git-auth"#
    } else {
        ""
    };

    manifests.push(format!(
        r#"---
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata:
  name: lattice-config
  namespace: flux-system
spec:
  interval: {interval}
  url: {url}
  ref:
    branch: {branch}{secret_ref}
"#,
        interval = gitops.interval,
        url = gitops.url,
        branch = gitops.branch,
    ));

    // Kustomization
    manifests.push(format!(
        r#"---
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: lattice-cluster
  namespace: flux-system
spec:
  interval: {interval}
  path: ./{path}
  prune: true
  sourceRef:
    kind: GitRepository
    name: lattice-config
"#,
        interval = gitops.interval,
        path = cluster_path,
    ));

    info!(
        cluster = %cluster_name,
        path = %cluster_path,
        has_credentials = has_creds,
        manifest_count = manifests.len(),
        "Generated GitOps resources"
    );

    manifests
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flux_config_default() {
        let config = FluxConfig::default();
        assert_eq!(config.version, env!("FLUX_VERSION"));
    }

    #[test]
    fn test_reconciler_creation() {
        // Only runs if helm is available
        if let Ok(reconciler) = FluxReconciler::new() {
            assert_eq!(reconciler.version(), env!("FLUX_VERSION"));
            assert!(!reconciler.manifests().is_empty());
        }
    }

    #[test]
    fn test_generate_gitops_resources_https() {
        let gitops = GitOpsSpec {
            url: "https://github.com/org/repo.git".to_string(),
            branch: "main".to_string(),
            base_path: "clusters".to_string(),
            interval: "5m".to_string(),
            secret_ref: None, // Credentials passed separately
        };

        let credentials = ResolvedGitCredentials {
            ssh_identity: None,
            ssh_known_hosts: None,
            https_username: Some("Z2l0".to_string()), // "git" base64
            https_password: Some("dG9rZW4xMjM=".to_string()), // "token123" base64
        };

        let manifests = generate_gitops_resources(&gitops, "prod-cluster", Some(&credentials));

        assert_eq!(manifests.len(), 4); // namespace, secret, gitrepository, kustomization
        assert!(manifests[1].contains("flux-git-auth"));
        assert!(manifests[2].contains("GitRepository"));
        assert!(manifests[2].contains("https://github.com/org/repo.git"));
        assert!(manifests[3].contains("Kustomization"));
        assert!(manifests[3].contains("clusters/prod-cluster"));
    }

    #[test]
    fn test_generate_gitops_resources_ssh() {
        let gitops = GitOpsSpec {
            url: "git@github.com:org/repo.git".to_string(),
            branch: "main".to_string(),
            base_path: "clusters".to_string(),
            interval: "10m".to_string(),
            secret_ref: None, // Credentials passed separately
        };

        let credentials = ResolvedGitCredentials {
            ssh_identity: Some("c3NoLXByaXZhdGUta2V5".to_string()), // base64 SSH key
            ssh_known_hosts: Some("a25vd25faG9zdHM=".to_string()),  // base64 known_hosts
            https_username: None,
            https_password: None,
        };

        let manifests = generate_gitops_resources(&gitops, "staging", Some(&credentials));

        assert_eq!(manifests.len(), 4);
        assert!(manifests[1].contains("identity:"));
        assert!(manifests[2].contains("git@github.com"));
        assert!(manifests[3].contains("clusters/staging"));
    }

    #[test]
    fn test_generate_gitops_resources_no_auth() {
        let gitops = GitOpsSpec {
            url: "https://github.com/public/repo.git".to_string(),
            branch: "main".to_string(),
            base_path: "configs".to_string(),
            interval: "1m".to_string(),
            secret_ref: None,
        };

        let manifests = generate_gitops_resources(&gitops, "dev", None);

        assert_eq!(manifests.len(), 3); // no secret needed
        assert!(manifests[1].contains("GitRepository"));
        assert!(!manifests[1].contains("secretRef")); // no secret reference
    }
}
