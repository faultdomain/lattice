//! Infrastructure manifest generation
//!
//! Single source of truth for ALL infrastructure manifests. Used by:
//! - Bootstrap webhook: pre-installs everything in parallel with operator
//! - Operator startup: re-applies (idempotent via server-side apply)
//!
//! Server-side apply handles idempotency - no need to check if installed.

use std::process::Command;
use tracing::{debug, info, warn};

use super::{FluxReconciler, IstioReconciler};
use crate::crd::BootstrapProvider;

/// Configuration for infrastructure manifest generation
#[derive(Debug, Clone)]
pub struct InfrastructureConfig {
    /// Infrastructure provider type (docker, proxmox, aws, etc.)
    pub provider: String,
    /// Bootstrap mechanism (kubeadm or rke2)
    pub bootstrap: BootstrapProvider,
    /// Skip Cilium policies (true for kind/bootstrap clusters without Cilium)
    pub skip_cilium_policies: bool,
}

/// Generate ALL infrastructure manifests for a self-managing cluster
///
/// Includes: cert-manager, CAPI, Istio, Flux, Envoy Gateway
pub fn generate_all(config: &InfrastructureConfig) -> Vec<String> {
    let mut manifests = Vec::new();

    // cert-manager (CAPI prerequisite)
    if let Ok(cm) = generate_certmanager() {
        debug!(count = cm.len(), "generated cert-manager manifests");
        manifests.extend(cm);
    } else {
        warn!("failed to generate cert-manager manifests");
    }

    // CAPI providers
    if let Ok(capi) = generate_capi(&config.provider) {
        debug!(count = capi.len(), "generated CAPI manifests");
        manifests.extend(capi);
    } else {
        warn!("failed to generate CAPI manifests");
    }

    // Istio ambient
    manifests.extend(generate_istio(config.skip_cilium_policies));

    // Flux
    manifests.extend(generate_flux());

    // Envoy Gateway (north-south ingress)
    if let Ok(eg) = generate_envoy_gateway() {
        debug!(count = eg.len(), "generated Envoy Gateway manifests");
        manifests.extend(eg);
    } else {
        warn!("failed to generate Envoy Gateway manifests");
    }

    info!(
        total = manifests.len(),
        "generated infrastructure manifests"
    );
    manifests
}

/// Generate cert-manager manifests
pub fn generate_certmanager() -> Result<Vec<String>, String> {
    let charts_dir = charts_dir();
    let chart_path = find_chart(&charts_dir, "cert-manager")?;

    let output = Command::new("helm")
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
        .map_err(|e| format!("helm: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    let yaml = String::from_utf8_lossy(&output.stdout);
    let mut manifests = vec![namespace_yaml("cert-manager")];
    for m in split_yaml(&yaml) {
        manifests.push(inject_namespace(&m, "cert-manager"));
    }
    Ok(manifests)
}

/// Generate CAPI provider manifests
pub fn generate_capi(provider: &str) -> Result<Vec<String>, String> {
    let infra = match provider.to_lowercase().as_str() {
        "docker" => "docker",
        "proxmox" => "proxmox",
        "aws" => "aws",
        "gcp" => "gcp",
        "azure" => "azure",
        p => return Err(format!("unknown provider: {}", p)),
    };

    // Always include both kubeadm and rke2 for clusterctl move compatibility
    let output = Command::new("clusterctl")
        .args([
            "generate",
            "provider",
            "--infrastructure",
            infra,
            "--bootstrap",
            "kubeadm,rke2",
            "--control-plane",
            "kubeadm,rke2",
        ])
        .output()
        .map_err(|e| format!("clusterctl: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    Ok(split_yaml(&String::from_utf8_lossy(&output.stdout)))
}

/// Generate Istio manifests
pub fn generate_istio(skip_cilium_policies: bool) -> Vec<String> {
    let mut manifests = vec![namespace_yaml("istio-system")];

    let reconciler = IstioReconciler::new();
    if let Ok(istio) = reconciler.manifests() {
        manifests.extend(istio.iter().cloned());
    }

    // Istio policies
    manifests.push(IstioReconciler::generate_peer_authentication());
    manifests.push(IstioReconciler::generate_default_deny());
    manifests.push(IstioReconciler::generate_operator_allow_policy());

    // Cilium policies (skip on kind/bootstrap clusters)
    if !skip_cilium_policies {
        manifests.push(super::generate_ztunnel_allowlist());
        manifests.push(super::generate_default_deny());
    }

    manifests
}

/// Generate Flux manifests including allow policy
pub fn generate_flux() -> Vec<String> {
    let mut manifests = vec![namespace_yaml("flux-system")];

    match FluxReconciler::new() {
        Ok(r) => {
            for m in r.manifests() {
                manifests.push(inject_namespace(m, "flux-system"));
            }
        }
        Err(e) => warn!(error = %e, "failed to create Flux reconciler"),
    };
    manifests.push(allow_all_policy("flux", "flux-system"));
    manifests
}

/// Generate Envoy Gateway manifests for north-south ingress
pub fn generate_envoy_gateway() -> Result<Vec<String>, String> {
    let charts_dir = charts_dir();
    let chart_path = find_chart(&charts_dir, "gateway-helm")?;

    let output = Command::new("helm")
        .args([
            "template",
            "envoy-gateway",
            &chart_path,
            "--namespace",
            "envoy-gateway-system",
        ])
        .output()
        .map_err(|e| format!("helm: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    let yaml = String::from_utf8_lossy(&output.stdout);
    let mut manifests = vec![namespace_yaml("envoy-gateway-system")];
    for m in split_yaml(&yaml) {
        manifests.push(inject_namespace(&m, "envoy-gateway-system"));
    }

    // Add GatewayClass for Envoy Gateway (name: "eg")
    manifests.push(envoy_gateway_class());

    // Add allow policy for Envoy Gateway
    manifests.push(allow_all_policy("envoy-gateway", "envoy-gateway-system"));

    Ok(manifests)
}

/// Generate the Envoy Gateway GatewayClass
fn envoy_gateway_class() -> String {
    r#"apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: eg
  labels:
    app.kubernetes.io/managed-by: lattice
spec:
  controllerName: gateway.envoyproxy.io/gatewayclass-controller"#
        .to_string()
}

fn allow_all_policy(name: &str, namespace: &str) -> String {
    format!(
        r#"apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: {name}-allow-all
  namespace: {namespace}
  labels:
    app.kubernetes.io/managed-by: lattice
spec:
  action: ALLOW
  rules:
  - {{}}"#
    )
}

// Helpers

fn charts_dir() -> String {
    std::env::var("LATTICE_CHARTS_DIR").unwrap_or_else(|_| {
        option_env!("LATTICE_CHARTS_DIR")
            .unwrap_or("/charts")
            .to_string()
    })
}

fn find_chart(dir: &str, name: &str) -> Result<String, String> {
    let exact = format!("{}/{}", dir, name);
    if std::path::Path::new(&exact).exists() {
        return Ok(exact);
    }

    // Try versioned (e.g., cert-manager-v1.14.0)
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let f = entry.file_name().to_string_lossy().to_string();
            if f.starts_with(&format!("{}-", name)) || f == name {
                return Ok(entry.path().to_string_lossy().to_string());
            }
        }
    }

    Err(format!("chart {} not found in {}", name, dir))
}

fn namespace_yaml(name: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {}",
        name
    )
}

fn split_yaml(yaml: &str) -> Vec<String> {
    yaml.split("\n---")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.contains("kind:"))
        .collect()
}

/// Inject namespace into a manifest if it doesn't have one and is a namespaced resource
fn inject_namespace(manifest: &str, namespace: &str) -> String {
    if is_cluster_scoped(manifest) {
        return manifest.to_string();
    }

    // Check if namespace already exists (skip helm templates with {{ }})
    if manifest.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("namespace:") && !trimmed.contains("{{")
    }) {
        return manifest.to_string();
    }

    // Inject namespace after "metadata:"
    let mut result = String::new();
    let mut injected = false;

    for line in manifest.lines() {
        result.push_str(line);
        result.push('\n');

        if !injected && line.trim() == "metadata:" {
            injected = true;
            result.push_str(&format!("  namespace: {}\n", namespace));
        }
    }

    result
}

const CLUSTER_SCOPED_KINDS: &[&str] = &[
    "Namespace",
    "CustomResourceDefinition",
    "ClusterRole",
    "ClusterRoleBinding",
    "PriorityClass",
    "StorageClass",
    "PersistentVolume",
    "Node",
    "APIService",
    "ValidatingWebhookConfiguration",
    "MutatingWebhookConfiguration",
    "GatewayClass",
];

fn is_cluster_scoped(manifest: &str) -> bool {
    let kind = extract_kind(manifest);
    CLUSTER_SCOPED_KINDS.contains(&kind)
}

fn extract_kind(manifest: &str) -> &str {
    manifest
        .lines()
        .find(|line| line.starts_with("kind:"))
        .and_then(|line| line.strip_prefix("kind:"))
        .map(|k| k.trim())
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_yaml() {
        let yaml = "kind: A\n---\nkind: B\n---\n";
        let docs = split_yaml(yaml);
        assert_eq!(docs.len(), 2);
    }

    #[test]
    fn test_namespace_yaml() {
        let ns = namespace_yaml("test");
        assert!(ns.contains("kind: Namespace"));
        assert!(ns.contains("name: test"));
    }

    #[test]
    fn test_inject_namespace_adds_to_namespaced_resource() {
        let manifest = "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: test-sa";
        let result = inject_namespace(manifest, "my-namespace");
        assert!(result.contains("namespace: my-namespace"));
    }

    #[test]
    fn test_inject_namespace_preserves_existing() {
        let manifest =
            "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: test-sa\n  namespace: existing";
        let result = inject_namespace(manifest, "my-namespace");
        assert!(result.contains("namespace: existing"));
        assert!(!result.contains("namespace: my-namespace"));
    }

    #[test]
    fn test_inject_namespace_skips_cluster_scoped() {
        let manifest = "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: test-ns";
        let result = inject_namespace(manifest, "my-namespace");
        assert!(!result.contains("namespace: my-namespace"));
    }

    #[test]
    fn test_is_cluster_scoped() {
        assert!(is_cluster_scoped(
            "kind: Namespace\nmetadata:\n  name: test"
        ));
        assert!(is_cluster_scoped(
            "kind: ClusterRole\nmetadata:\n  name: test"
        ));
        assert!(is_cluster_scoped(
            "kind: CustomResourceDefinition\nmetadata:\n  name: test"
        ));
        assert!(!is_cluster_scoped(
            "kind: ServiceAccount\nmetadata:\n  name: test"
        ));
        assert!(!is_cluster_scoped(
            "kind: Deployment\nmetadata:\n  name: test"
        ));
    }
}
