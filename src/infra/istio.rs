//! Istio service mesh manifest generation
//!
//! Generates Istio manifests using Helm charts with ambient mesh mode.
//! Installs two charts: base (CRDs) and istiod (control plane).

use std::process::Command;
use std::sync::OnceLock;
use tracing::info;

/// Default charts directory (set by LATTICE_CHARTS_DIR env var in container)
const DEFAULT_CHARTS_DIR: &str = "/charts";

/// Get charts directory - checks runtime env var first, then compile-time, then default
fn get_charts_dir() -> String {
    // Runtime env var takes precedence (for container override)
    if let Ok(dir) = std::env::var("LATTICE_CHARTS_DIR") {
        return dir;
    }
    // Compile-time env var set by build.rs (for local development)
    if let Some(dir) = option_env!("LATTICE_CHARTS_DIR") {
        return dir.to_string();
    }
    // Default for container
    DEFAULT_CHARTS_DIR.to_string()
}

/// Istio configuration
#[derive(Debug, Clone)]
pub struct IstioConfig {
    /// Istio version (pinned to Lattice release)
    pub version: &'static str,
}

impl Default for IstioConfig {
    fn default() -> Self {
        Self { version: "1.24.2" }
    }
}

/// Istio manifest generator
pub struct IstioReconciler {
    config: IstioConfig,
    manifests: OnceLock<Result<Vec<String>, String>>,
}

impl IstioReconciler {
    /// Create with default config
    pub fn new() -> Self {
        Self::with_config(IstioConfig::default())
    }

    /// Create with custom config
    pub fn with_config(config: IstioConfig) -> Self {
        Self {
            config,
            manifests: OnceLock::new(),
        }
    }

    /// Get the expected version
    pub fn version(&self) -> &str {
        self.config.version
    }

    /// Get manifests (lazily rendered)
    pub fn manifests(&self) -> Result<&[String], String> {
        let result = self
            .manifests
            .get_or_init(|| Self::render_manifests(&self.config));
        match result {
            Ok(m) => Ok(m),
            Err(e) => Err(e.clone()),
        }
    }

    /// Generate default PeerAuthentication for STRICT mTLS
    pub fn generate_peer_authentication() -> String {
        r#"---
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
  labels:
    app.kubernetes.io/managed-by: lattice
spec:
  mtls:
    mode: STRICT
"#
        .to_string()
    }

    fn render_manifests(config: &IstioConfig) -> Result<Vec<String>, String> {
        let mut all_manifests = Vec::new();

        // Use local chart tarballs (pulled at Docker build time or by build.rs)
        let charts_dir = get_charts_dir();
        let base_chart = format!("{}/base-{}.tgz", charts_dir, config.version);
        let istiod_chart = format!("{}/istiod-{}.tgz", charts_dir, config.version);

        // 1. Render istio base chart (CRDs)
        info!(version = config.version, "Rendering Istio base chart");
        let base_output = Command::new("helm")
            .args([
                "template",
                "istio-base",
                &base_chart,
                "--namespace",
                "istio-system",
            ])
            .output()
            .map_err(|e| format!("failed to run helm: {}", e))?;

        if !base_output.status.success() {
            let stderr = String::from_utf8_lossy(&base_output.stderr);
            return Err(format!("helm template base failed: {}", stderr));
        }

        all_manifests.extend(parse_yaml_documents(&String::from_utf8_lossy(
            &base_output.stdout,
        )));

        // 2. Render istiod chart (control plane with ambient mode)
        info!(
            version = config.version,
            "Rendering Istiod chart with ambient mode"
        );
        let istiod_output = Command::new("helm")
            .args([
                "template",
                "istiod",
                &istiod_chart,
                "--namespace",
                "istio-system",
                "--set",
                "profile=ambient",
                "--set",
                "pilot.resources.requests.cpu=100m",
                "--set",
                "pilot.resources.requests.memory=128Mi",
            ])
            .output()
            .map_err(|e| format!("failed to run helm: {}", e))?;

        if !istiod_output.status.success() {
            let stderr = String::from_utf8_lossy(&istiod_output.stderr);
            return Err(format!("helm template istiod failed: {}", stderr));
        }

        all_manifests.extend(parse_yaml_documents(&String::from_utf8_lossy(
            &istiod_output.stdout,
        )));

        info!(count = all_manifests.len(), "Rendered Istio manifests");
        Ok(all_manifests)
    }
}

impl Default for IstioReconciler {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse YAML string into individual documents
fn parse_yaml_documents(yaml_str: &str) -> Vec<String> {
    yaml_str
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
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = IstioConfig::default();
        assert_eq!(config.version, "1.24.2");
    }

    #[test]
    fn test_peer_authentication() {
        let policy = IstioReconciler::generate_peer_authentication();
        assert!(policy.contains("kind: PeerAuthentication"));
        assert!(policy.contains("mode: STRICT"));
    }

    #[test]
    fn test_reconciler_version() {
        let reconciler = IstioReconciler::new();
        assert_eq!(reconciler.version(), "1.24.2");
    }

    #[test]
    fn test_manifest_rendering() {
        // Only runs if helm is available with istio repo
        let reconciler = IstioReconciler::new();
        if let Ok(manifests) = reconciler.manifests() {
            // Should have rendered some manifests
            assert!(!manifests.is_empty());

            // Should contain CRDs from base chart
            let has_crd = manifests
                .iter()
                .any(|m| m.contains("kind: CustomResourceDefinition"));
            assert!(has_crd, "Should contain Istio CRDs");

            // Should contain istiod deployment
            let has_istiod = manifests.iter().any(|m| m.contains("name: istiod"));
            assert!(has_istiod, "Should contain istiod");
        }
    }
}
