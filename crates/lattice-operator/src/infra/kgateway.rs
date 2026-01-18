//! kgateway manifest generation
//!
//! Generates kgateway manifests using Helm charts. kgateway serves as both:
//! - North-south ingress gateway (GatewayClass: kgateway)
//! - East-west waypoint proxy for Istio Ambient (GatewayClass: kgateway-waypoint)
//!
//! This replaces Istio's gateway and waypoint with a more feature-rich L7 proxy
//! that supports rate limiting, transformations, and external auth natively.

use std::process::Command;
use std::sync::OnceLock;
use tracing::info;

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

/// kgateway configuration
#[derive(Debug, Clone)]
pub struct KgatewayConfig {
    /// kgateway version (pinned to Lattice release)
    pub version: &'static str,
}

impl Default for KgatewayConfig {
    fn default() -> Self {
        Self {
            version: env!("KGATEWAY_VERSION"),
        }
    }
}

/// kgateway manifest generator
pub struct KgatewayReconciler {
    config: KgatewayConfig,
    manifests: OnceLock<Result<Vec<String>, String>>,
}

impl KgatewayReconciler {
    /// Create with default config
    pub fn new() -> Self {
        Self::with_config(KgatewayConfig::default())
    }

    /// Create with custom config
    pub fn with_config(config: KgatewayConfig) -> Self {
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

    /// Generate GatewayClass for north-south ingress
    pub fn generate_ingress_gateway_class() -> String {
        r#"---
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: kgateway
  labels:
    app.kubernetes.io/managed-by: lattice
spec:
  controllerName: kgateway.dev/kgateway
"#
        .to_string()
    }

    /// Generate GatewayClass for Istio Ambient waypoint
    ///
    /// This GatewayClass is used when labeling namespaces with:
    /// `istio.io/use-waypoint=kgateway-waypoint`
    pub fn generate_waypoint_gateway_class() -> String {
        r#"---
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: kgateway-waypoint
  labels:
    app.kubernetes.io/managed-by: lattice
spec:
  controllerName: kgateway.dev/kgateway
  description: "kgateway as Istio Ambient waypoint proxy"
"#
        .to_string()
    }

    fn render_manifests(config: &KgatewayConfig) -> Result<Vec<String>, String> {
        let mut all_manifests = Vec::new();

        let charts_dir = get_charts_dir();
        let crds_chart = format!("{}/kgateway-crds-v{}.tgz", charts_dir, config.version);
        let kgateway_chart = format!("{}/kgateway-v{}.tgz", charts_dir, config.version);

        // 1. Render kgateway CRDs
        info!(version = config.version, "Rendering kgateway CRDs chart");
        let crds_output = Command::new("helm")
            .args([
                "template",
                "kgateway-crds",
                &crds_chart,
                "--namespace",
                "kgateway-system",
            ])
            .output()
            .map_err(|e| format!("failed to run helm: {}", e))?;

        if !crds_output.status.success() {
            let stderr = String::from_utf8_lossy(&crds_output.stderr);
            return Err(format!("helm template kgateway-crds failed: {}", stderr));
        }

        all_manifests.extend(parse_yaml_documents(&String::from_utf8_lossy(
            &crds_output.stdout,
        )));

        // 2. Render kgateway chart
        info!(version = config.version, "Rendering kgateway chart");
        let kgateway_output = Command::new("helm")
            .args([
                "template",
                "kgateway",
                &kgateway_chart,
                "--namespace",
                "kgateway-system",
                // Enable waypoint mode for Istio Ambient integration
                "--set",
                "gateway.enabled=true",
                "--set",
                "gateway.istio.enabled=true",
            ])
            .output()
            .map_err(|e| format!("failed to run helm: {}", e))?;

        if !kgateway_output.status.success() {
            let stderr = String::from_utf8_lossy(&kgateway_output.stderr);
            return Err(format!("helm template kgateway failed: {}", stderr));
        }

        all_manifests.extend(parse_yaml_documents(&String::from_utf8_lossy(
            &kgateway_output.stdout,
        )));

        // 3. Add GatewayClasses
        all_manifests.push(Self::generate_ingress_gateway_class());
        all_manifests.push(Self::generate_waypoint_gateway_class());

        info!(count = all_manifests.len(), "Rendered kgateway manifests");
        Ok(all_manifests)
    }
}

impl Default for KgatewayReconciler {
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
        let config = KgatewayConfig::default();
        assert_eq!(config.version, env!("KGATEWAY_VERSION"));
    }

    #[test]
    fn test_reconciler_version() {
        let reconciler = KgatewayReconciler::new();
        assert_eq!(reconciler.version(), env!("KGATEWAY_VERSION"));
    }

    #[test]
    fn test_ingress_gateway_class() {
        let gc = KgatewayReconciler::generate_ingress_gateway_class();
        assert!(gc.contains("kind: GatewayClass"));
        assert!(gc.contains("name: kgateway"));
        assert!(gc.contains("controllerName: kgateway.dev/kgateway"));
        assert!(gc.contains("app.kubernetes.io/managed-by: lattice"));
    }

    #[test]
    fn test_waypoint_gateway_class() {
        let gc = KgatewayReconciler::generate_waypoint_gateway_class();
        assert!(gc.contains("kind: GatewayClass"));
        assert!(gc.contains("name: kgateway-waypoint"));
        assert!(gc.contains("controllerName: kgateway.dev/kgateway"));
        assert!(gc.contains("Istio Ambient waypoint"));
    }

    #[test]
    fn test_manifest_rendering() {
        let reconciler = KgatewayReconciler::new();
        if let Ok(manifests) = reconciler.manifests() {
            assert!(!manifests.is_empty());

            // Should contain GatewayClasses
            let has_ingress_gc = manifests.iter().any(|m| {
                m.contains("kind: GatewayClass") && m.contains("name: kgateway")
            });
            assert!(has_ingress_gc, "Should contain ingress GatewayClass");

            let has_waypoint_gc = manifests.iter().any(|m| {
                m.contains("kind: GatewayClass") && m.contains("name: kgateway-waypoint")
            });
            assert!(has_waypoint_gc, "Should contain waypoint GatewayClass");
        }
    }

    #[test]
    fn test_parse_yaml_documents() {
        let yaml = "---\napiVersion: v1\nkind: ConfigMap\n---\napiVersion: v1\nkind: Secret";
        let docs = parse_yaml_documents(yaml);
        assert_eq!(docs.len(), 2);
    }
}
