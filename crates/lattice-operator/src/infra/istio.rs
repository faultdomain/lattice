//! Istio service mesh manifest generation
//!
//! Generates Istio manifests using Helm charts with ambient mesh mode.
//! Installs four charts: base (CRDs), istiod (control plane), istio-cni, and ztunnel.

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
        Self {
            version: env!("ISTIO_VERSION"),
        }
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

    /// Generate mesh-wide default-deny AuthorizationPolicy
    ///
    /// This is the security baseline for the mesh. With this policy in place,
    /// all traffic is denied unless explicitly allowed by service-specific policies.
    /// Must be deployed to istio-system to apply mesh-wide.
    pub fn generate_default_deny() -> String {
        r#"---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: mesh-default-deny
  namespace: istio-system
  labels:
    app.kubernetes.io/managed-by: lattice
spec:
  {}
"#
        .to_string()
    }

    /// Generate AuthorizationPolicy allowing traffic to lattice-operator
    ///
    /// The lattice-operator needs to accept connections from:
    /// - Workload cluster bootstrap (postKubeadmCommands calling webhook on 8443)
    /// - Workload cluster agents (gRPC on 50051)
    ///
    /// These connections come from outside the mesh, so we allow any source.
    pub fn generate_operator_allow_policy() -> String {
        r#"---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: lattice-operator-allow
  namespace: lattice-system
  labels:
    app.kubernetes.io/managed-by: lattice
spec:
  selector:
    matchLabels:
      app: lattice-operator
  action: ALLOW
  rules:
  - to:
    - operation:
        ports: ["8443", "50051"]
"#
        .to_string()
    }

    fn render_manifests(config: &IstioConfig) -> Result<Vec<String>, String> {
        let mut all_manifests = Vec::new();

        // Use local chart tarballs (pulled at Docker build time or by build.rs)
        let charts_dir = get_charts_dir();
        let base_chart = format!("{}/base-{}.tgz", charts_dir, config.version);
        let istiod_chart = format!("{}/istiod-{}.tgz", charts_dir, config.version);
        let cni_chart = format!("{}/cni-{}.tgz", charts_dir, config.version);
        let ztunnel_chart = format!("{}/ztunnel-{}.tgz", charts_dir, config.version);

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

        // 2. Render istio-cni chart (must be installed before ztunnel)
        info!(version = config.version, "Rendering Istio CNI chart");
        let cni_output = Command::new("helm")
            .args([
                "template",
                "istio-cni",
                &cni_chart,
                "--namespace",
                "istio-system",
                "--set",
                "profile=ambient",
                // Chain with Cilium CNI
                "--set",
                "cni.cniConfFileName=05-cilium.conflist",
            ])
            .output()
            .map_err(|e| format!("failed to run helm: {}", e))?;

        if !cni_output.status.success() {
            let stderr = String::from_utf8_lossy(&cni_output.stderr);
            return Err(format!("helm template istio-cni failed: {}", stderr));
        }

        all_manifests.extend(parse_yaml_documents(&String::from_utf8_lossy(
            &cni_output.stdout,
        )));

        // 3. Render istiod chart (control plane with ambient mode)
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

        // 4. Render ztunnel chart (L4 data plane for ambient mode)
        info!(version = config.version, "Rendering ztunnel chart");
        let ztunnel_output = Command::new("helm")
            .args([
                "template",
                "ztunnel",
                &ztunnel_chart,
                "--namespace",
                "istio-system",
            ])
            .output()
            .map_err(|e| format!("failed to run helm: {}", e))?;

        if !ztunnel_output.status.success() {
            let stderr = String::from_utf8_lossy(&ztunnel_output.stderr);
            return Err(format!("helm template ztunnel failed: {}", stderr));
        }

        all_manifests.extend(parse_yaml_documents(&String::from_utf8_lossy(
            &ztunnel_output.stdout,
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
    super::split_yaml_documents(yaml_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = IstioConfig::default();
        assert_eq!(config.version, env!("ISTIO_VERSION"));
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
        assert_eq!(reconciler.version(), env!("ISTIO_VERSION"));
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

            // Should contain ztunnel daemonset (ambient mode)
            let has_ztunnel = manifests.iter().any(|m| m.contains("name: ztunnel"));
            assert!(has_ztunnel, "Should contain ztunnel for ambient mode");

            // Should contain istio-cni daemonset
            let has_cni = manifests.iter().any(|m| m.contains("name: istio-cni"));
            assert!(has_cni, "Should contain istio-cni for ambient mode");
        }
    }

    #[test]
    fn test_default_deny_policy() {
        let policy = IstioReconciler::generate_default_deny();
        assert!(policy.contains("apiVersion: security.istio.io/v1"));
        assert!(policy.contains("kind: AuthorizationPolicy"));
        assert!(policy.contains("name: mesh-default-deny"));
        assert!(policy.contains("namespace: istio-system"));
        assert!(policy.contains("app.kubernetes.io/managed-by: lattice"));
        // Empty spec {} means deny all traffic
        assert!(policy.contains("spec:"));
        assert!(policy.contains("{}"));
        // No selector = mesh-wide
        assert!(!policy.contains("selector:"));
    }

    #[test]
    fn test_operator_allow_policy() {
        let policy = IstioReconciler::generate_operator_allow_policy();
        assert!(policy.contains("apiVersion: security.istio.io/v1"));
        assert!(policy.contains("kind: AuthorizationPolicy"));
        assert!(policy.contains("name: lattice-operator-allow"));
        assert!(policy.contains("namespace: lattice-system"));
        assert!(policy.contains("app.kubernetes.io/managed-by: lattice"));
        assert!(policy.contains("selector:"));
        assert!(policy.contains("app: lattice-operator"));
        assert!(policy.contains("action: ALLOW"));
        assert!(policy.contains("8443"));
        assert!(policy.contains("50051"));
    }

    #[test]
    fn test_parse_yaml_documents_single() {
        let yaml = "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test";
        let docs = parse_yaml_documents(yaml);
        assert_eq!(docs.len(), 1);
        assert!(docs[0].starts_with("---"));
        assert!(docs[0].contains("kind: ConfigMap"));
    }

    #[test]
    fn test_parse_yaml_documents_multiple() {
        let yaml = "---\napiVersion: v1\nkind: ConfigMap\n---\napiVersion: v1\nkind: Secret\n---\napiVersion: v1\nkind: Service";
        let docs = parse_yaml_documents(yaml);
        assert_eq!(docs.len(), 3);
    }

    #[test]
    fn test_parse_yaml_documents_filters_empty() {
        let yaml = "---\napiVersion: v1\nkind: ConfigMap\n---\n\n---\n# comment\n---\napiVersion: v1\nkind: Secret";
        let docs = parse_yaml_documents(yaml);
        assert_eq!(docs.len(), 2);
    }

    #[test]
    fn test_parse_yaml_documents_adds_separator() {
        let yaml = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test";
        let docs = parse_yaml_documents(yaml);
        assert_eq!(docs.len(), 1);
        assert!(docs[0].starts_with("---"));
    }
}
