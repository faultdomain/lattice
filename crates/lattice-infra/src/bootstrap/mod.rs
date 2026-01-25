//! Infrastructure manifest generation
//!
//! Single source of truth for ALL infrastructure manifests. Used by:
//! - Bootstrap webhook: pre-installs everything in parallel with operator
//! - Operator startup: re-applies (idempotent via server-side apply)
//!
//! Server-side apply handles idempotency - no need to check if installed.

pub mod cilium;
pub mod eso;
pub mod istio;

use tokio::process::Command;
use tracing::{debug, info, warn};

use lattice_common::crd::{BootstrapProvider, ProviderType};

// Re-export submodule types
pub use cilium::{
    cilium_version, generate_cilium_manifests, generate_default_deny,
    generate_operator_network_policy, generate_waypoint_egress_policy, generate_ztunnel_allowlist,
};
pub use istio::{IstioConfig, IstioReconciler};

/// Configuration for infrastructure manifest generation
#[derive(Debug, Clone)]
pub struct InfrastructureConfig {
    /// Infrastructure provider type (docker, proxmox, aws, etc.)
    pub provider: ProviderType,
    /// Bootstrap mechanism (kubeadm or rke2)
    pub bootstrap: BootstrapProvider,
    /// Skip Cilium policies (true for kind/bootstrap clusters without Cilium)
    pub skip_cilium_policies: bool,
}

/// Generate core infrastructure manifests (Istio, Gateway API)
///
/// Used by both operator startup and full cluster bootstrap.
/// This is an async function to avoid blocking the tokio runtime during
/// helm template execution.
pub async fn generate_core(skip_cilium_policies: bool) -> Vec<String> {
    let mut manifests = Vec::new();

    // Istio ambient
    manifests.extend(generate_istio(skip_cilium_policies).await);

    // Gateway API CRDs (required for Istio Gateway and waypoints)
    if let Ok(gw_api) = generate_gateway_api_crds() {
        debug!(count = gw_api.len(), "generated Gateway API CRDs");
        manifests.extend(gw_api);
    } else {
        warn!("failed to generate Gateway API CRDs");
    }

    manifests
}

/// Generate ALL infrastructure manifests for a self-managing cluster
///
/// Includes: cert-manager, CAPI, plus core infrastructure (Istio, Gateway API)
/// This is an async function to avoid blocking the tokio runtime during
/// helm and clusterctl execution.
pub async fn generate_all(config: &InfrastructureConfig) -> Vec<String> {
    let mut manifests = Vec::new();

    // cert-manager (CAPI prerequisite)
    if let Ok(cm) = generate_certmanager().await {
        debug!(count = cm.len(), "generated cert-manager manifests");
        manifests.extend(cm);
    } else {
        warn!("failed to generate cert-manager manifests");
    }

    // CAPI providers
    if let Ok(capi) = generate_capi(config.provider).await {
        debug!(count = capi.len(), "generated CAPI manifests");
        manifests.extend(capi);
    } else {
        warn!("failed to generate CAPI manifests");
    }

    // Core infrastructure (Istio, Gateway API)
    manifests.extend(generate_core(config.skip_cilium_policies).await);

    info!(
        total = manifests.len(),
        "generated infrastructure manifests"
    );
    manifests
}

/// Generate cert-manager manifests
///
/// This is an async function to avoid blocking the tokio runtime during
/// helm template execution.
pub async fn generate_certmanager() -> Result<Vec<String>, String> {
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
        .await
        .map_err(|e| format!("helm: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    let yaml = String::from_utf8_lossy(&output.stdout);
    let mut manifests = vec![namespace_yaml("cert-manager")];
    for m in split_yaml_documents(&yaml) {
        manifests.push(inject_namespace(&m, "cert-manager"));
    }
    Ok(manifests)
}

/// Generate CAPI provider manifests
///
/// This is an async function to avoid blocking the tokio runtime during
/// clusterctl execution.
pub async fn generate_capi(provider: ProviderType) -> Result<Vec<String>, String> {
    let infra = match provider {
        ProviderType::Docker => "docker",
        ProviderType::Proxmox => "proxmox",
        ProviderType::Aws => "aws",
        ProviderType::Gcp => "gcp",
        ProviderType::Azure => "azure",
        ProviderType::OpenStack => "openstack",
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
        .await
        .map_err(|e| format!("clusterctl: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    Ok(split_yaml_documents(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// Generate Istio manifests
///
/// This is an async function to avoid blocking the tokio runtime during
/// helm template execution.
pub async fn generate_istio(skip_cilium_policies: bool) -> Vec<String> {
    let mut manifests = vec![namespace_yaml("istio-system")];

    let reconciler = IstioReconciler::new();
    if let Ok(istio) = reconciler.manifests().await {
        manifests.extend(istio.iter().cloned());
    }

    // Istio policies
    manifests.push(IstioReconciler::generate_peer_authentication());
    manifests.push(IstioReconciler::generate_default_deny());
    manifests.push(IstioReconciler::generate_waypoint_default_deny());
    manifests.push(IstioReconciler::generate_operator_allow_policy());

    // Cilium policies (skip on kind/bootstrap clusters)
    if !skip_cilium_policies {
        manifests.push(cilium::generate_ztunnel_allowlist());
        manifests.push(cilium::generate_default_deny());
        manifests.push(cilium::generate_waypoint_egress_policy());
    }

    manifests
}

/// Generate Gateway API CRDs
pub fn generate_gateway_api_crds() -> Result<Vec<String>, String> {
    let charts_dir = charts_dir();
    let version = option_env!("GATEWAY_API_VERSION").unwrap_or("1.2.1");
    let crds_path = format!("{}/gateway-api-crds-v{}.yaml", charts_dir, version);

    let content =
        std::fs::read_to_string(&crds_path).map_err(|e| format!("read {}: {}", crds_path, e))?;

    Ok(split_yaml_documents(&content))
}

// Helpers

/// Get charts directory from environment or use default
pub fn charts_dir() -> String {
    std::env::var("LATTICE_CHARTS_DIR").unwrap_or_else(|_| {
        option_env!("LATTICE_CHARTS_DIR")
            .unwrap_or("/charts")
            .to_string()
    })
}

pub(crate) fn find_chart(dir: &str, name: &str) -> Result<String, String> {
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

pub(crate) fn namespace_yaml(name: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {}",
        name
    )
}

/// Split a multi-document YAML string into individual documents.
///
/// Filters out empty documents and documents without a `kind:` field.
/// Normalizes output to always have `---` prefix for kubectl apply compatibility.
pub fn split_yaml_documents(yaml: &str) -> Vec<String> {
    yaml.split("\n---")
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

/// Inject namespace into a manifest if it doesn't have one and is a namespaced resource
pub(crate) fn inject_namespace(manifest: &str, namespace: &str) -> String {
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
            result.push_str(&format!("namespace: {}\n", namespace));
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
    fn test_split_yaml_documents() {
        let yaml = "kind: A\n---\nkind: B\n---\n";
        let docs = split_yaml_documents(yaml);
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
