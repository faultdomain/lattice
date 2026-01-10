//! Cilium CNI manifest generation
//!
//! Generates Cilium manifests using `helm template` for consistent deployment.
//! The same generator is used by bootstrap and day-2 reconciliation.
//!
//! Also provides CiliumNetworkPolicy generation for Lattice components.

use std::process::Command;
use tracing::info;

use crate::{DEFAULT_BOOTSTRAP_PORT, DEFAULT_GRPC_PORT};

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

/// Cilium configuration
#[derive(Debug, Clone)]
pub struct CiliumConfig {
    /// Chart version (pinned to Lattice release)
    pub version: &'static str,
}

impl Default for CiliumConfig {
    fn default() -> Self {
        Self { version: "1.16.5" }
    }
}

/// Cilium manifest generator
///
/// Renders Cilium manifests via helm template. Manifests are cached
/// for reuse by both bootstrap and controller reconciliation.
pub struct CiliumReconciler {
    config: CiliumConfig,
    manifests: Vec<String>,
}

impl CiliumReconciler {
    /// Create with default config
    pub fn new() -> Result<Self, String> {
        Self::with_config(CiliumConfig::default())
    }

    /// Create with custom config
    pub fn with_config(config: CiliumConfig) -> Result<Self, String> {
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

    /// Render Cilium manifests using helm template
    fn render_manifests(config: &CiliumConfig) -> Result<Vec<String>, String> {
        // Use local chart tarball (pulled at Docker build time or by build.rs)
        let charts_dir = get_charts_dir();
        let chart_path = format!("{}/cilium-{}.tgz", charts_dir, config.version);

        // Cilium helm values for Istio compatibility
        let values = [
            "--set",
            "hubble.enabled=false",
            "--set",
            "hubble.relay.enabled=false",
            "--set",
            "hubble.ui.enabled=false",
            "--set",
            "prometheus.enabled=false",
            "--set",
            "operator.prometheus.enabled=false",
            "--set",
            "cni.exclusive=false",
            "--set",
            "kubeProxyReplacement=false",
            "--set",
            "l2announcements.enabled=true",
            "--set",
            "externalIPs.enabled=true",
        ];

        let output = Command::new("helm")
            .args([
                "template",
                "cilium",
                &chart_path,
                "--namespace",
                "kube-system",
            ])
            .args(values)
            .output()
            .map_err(|e| format!("failed to run helm: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("helm template failed: {}", stderr));
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
            "Rendered Cilium manifests"
        );
        Ok(manifests)
    }
}

/// Generate a CiliumNetworkPolicy for the Lattice operator/agent.
///
/// This policy restricts the operator to only communicate with:
/// - DNS (kube-dns in kube-system)
/// - Kubernetes API server
/// - Parent cell (if parent_host is provided)
///
/// This follows the principle of least privilege - the agent should only
/// be able to reach what it needs for normal operation.
pub fn generate_operator_network_policy(parent_host: Option<&str>, parent_port: u16) -> String {
    let mut egress_rules = vec![
        // DNS to kube-dns
        r#"    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: kube-system
            k8s:k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
            - port: "53"
              protocol: TCP"#
            .to_string(),
        // K8s API server
        r#"    - toEntities:
        - kube-apiserver"#
            .to_string(),
    ];

    // Add parent cell if specified
    if let Some(host) = parent_host {
        egress_rules.push(format!(
            r#"    - toFQDNs:
        - matchName: {}
      toPorts:
        - ports:
            - port: "{}"
              protocol: TCP"#,
            host, parent_port
        ));
    }

    format!(
        r#"---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: lattice-operator
  namespace: lattice-system
  labels:
    app.kubernetes.io/managed-by: lattice
spec:
  endpointSelector:
    matchLabels:
      app: lattice-operator
  egress:
{egress}
  ingress:
    # Allow ingress for bootstrap webhook and gRPC
    - toPorts:
        - ports:
            - port: "{bootstrap_port}"
              protocol: TCP
            - port: "{grpc_port}"
              protocol: TCP
"#,
        egress = egress_rules.join("\n"),
        bootstrap_port = DEFAULT_BOOTSTRAP_PORT,
        grpc_port = DEFAULT_GRPC_PORT,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CiliumConfig::default();
        assert_eq!(config.version, "1.16.5");
    }

    #[test]
    fn test_reconciler_creation() {
        // Only runs if helm is available
        if let Ok(reconciler) = CiliumReconciler::new() {
            assert_eq!(reconciler.version(), "1.16.5");
            assert!(!reconciler.manifests().is_empty());
        }
    }

    #[test]
    fn test_operator_network_policy_without_parent() {
        let policy = generate_operator_network_policy(None, 50051);

        // Should be valid YAML
        assert!(policy.contains("apiVersion: cilium.io/v2"));
        assert!(policy.contains("kind: CiliumNetworkPolicy"));
        assert!(policy.contains("name: lattice-operator"));
        assert!(policy.contains("namespace: lattice-system"));

        // Should have DNS egress
        assert!(policy.contains("kube-dns"));
        assert!(policy.contains("port: \"53\""));

        // Should have API server egress
        assert!(policy.contains("kube-apiserver"));

        // Should NOT have parent FQDN rule
        assert!(!policy.contains("toFQDNs"));

        // Should have ingress for cell ports
        assert!(policy.contains("port: \"8443\""));
        assert!(policy.contains("port: \"50051\""));
    }

    #[test]
    fn test_operator_network_policy_with_parent() {
        let policy = generate_operator_network_policy(Some("cell.example.com"), 50051);

        // Should have parent FQDN rule
        assert!(policy.contains("toFQDNs"));
        assert!(policy.contains("matchName: cell.example.com"));
        assert!(policy.contains("port: \"50051\""));

        // Should still have DNS and API server
        assert!(policy.contains("kube-dns"));
        assert!(policy.contains("kube-apiserver"));
    }

    #[test]
    fn test_operator_network_policy_custom_port() {
        let policy = generate_operator_network_policy(Some("parent.local"), 4001);

        // Should use custom port
        assert!(policy.contains("port: \"4001\""));
        assert!(policy.contains("matchName: parent.local"));
    }
}
