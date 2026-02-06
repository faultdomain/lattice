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
pub mod velero;

use kube::ResourceExt;
use tokio::process::Command;
use tracing::{debug, info};

use lattice_common::crd::{BootstrapProvider, LatticeCluster, ProviderType};
use lattice_common::DEFAULT_GRPC_PORT;

// Re-export submodule types
pub use cilium::{
    cilium_version, generate_cilium_manifests, generate_default_deny,
    generate_operator_network_policy, generate_waypoint_egress_policy, generate_ztunnel_allowlist,
};
pub use istio::{IstioConfig, IstioReconciler};

/// Configuration for infrastructure manifest generation
#[derive(Debug, Clone, Default)]
pub struct InfrastructureConfig {
    /// Infrastructure provider type (docker, proxmox, aws, etc.)
    pub provider: ProviderType,
    /// Bootstrap mechanism (kubeadm or rke2)
    pub bootstrap: BootstrapProvider,
    /// Cluster name for trust domain (lattice.{cluster}.local)
    pub cluster_name: String,
    /// Skip Cilium policies (true for kind/bootstrap clusters without Cilium)
    pub skip_cilium_policies: bool,
    /// Skip Istio, Gateway API CRDs, and mesh-related Cilium policies
    pub skip_service_mesh: bool,
    /// Parent cell hostname (None for root/management clusters)
    pub parent_host: Option<String>,
    /// Parent cell gRPC port (used with parent_host)
    pub parent_grpc_port: u16,
}

impl From<&LatticeCluster> for InfrastructureConfig {
    /// Create an InfrastructureConfig from a LatticeCluster
    ///
    /// Extracts provider, bootstrap, and cluster name.
    /// NOTE: Does NOT set parent_host - that must come from the `lattice-parent-config`
    /// secret (the upstream parent this cluster connects to), not from parent_config
    /// (which is for this cluster's own cell server endpoints).
    fn from(cluster: &LatticeCluster) -> Self {
        Self {
            provider: cluster.spec.provider.provider_type(),
            bootstrap: cluster.spec.provider.kubernetes.bootstrap.clone(),
            cluster_name: cluster.name_any(),
            skip_cilium_policies: false,
            skip_service_mesh: !cluster.spec.services,
            parent_host: None,
            parent_grpc_port: DEFAULT_GRPC_PORT,
        }
    }
}

/// Generate core infrastructure manifests (Istio, Gateway API, ESO)
///
/// Used by both operator startup and full cluster bootstrap.
/// This is an async function to avoid blocking the tokio runtime during
/// helm template execution.
pub async fn generate_core(config: &InfrastructureConfig) -> Result<Vec<String>, String> {
    let mut manifests = Vec::new();

    if !config.skip_service_mesh {
        // Istio ambient + Cilium policies
        manifests.extend(generate_istio(config).await?);

        // Gateway API CRDs (required for Istio Gateway and waypoints)
        let gw_api = generate_gateway_api_crds()?;
        debug!(count = gw_api.len(), "generated Gateway API CRDs");
        manifests.extend(gw_api);
    }

    // External Secrets Operator (for Vault integration)
    manifests.extend(eso::generate_eso().await?.iter().cloned());

    // Velero (for backup and restore)
    manifests.extend(velero::generate_velero().await?.iter().cloned());

    Ok(manifests)
}

/// Generate ALL infrastructure manifests for a self-managing cluster
///
/// Includes core infrastructure (Istio, Gateway API, ESO, Cilium policies).
/// NOTE: cert-manager and CAPI providers are installed via `clusterctl init`,
/// which manages their lifecycle (including upgrades).
///
/// This is an async function to avoid blocking the tokio runtime during
/// helm execution.
pub async fn generate_all(config: &InfrastructureConfig) -> Result<Vec<String>, String> {
    // Core infrastructure (Istio, Gateway API, ESO, Cilium policies)
    // cert-manager and CAPI are installed via clusterctl init
    let manifests = generate_core(config).await?;

    info!(
        total = manifests.len(),
        "generated infrastructure manifests"
    );
    Ok(manifests)
}

/// Generate Istio and Cilium policy manifests
///
/// This is an async function to avoid blocking the tokio runtime during
/// helm template execution.
pub async fn generate_istio(config: &InfrastructureConfig) -> Result<Vec<String>, String> {
    let mut manifests = vec![namespace_yaml("istio-system")];

    let reconciler = IstioReconciler::new(&config.cluster_name);
    let istio = reconciler.manifests().await?;
    manifests.extend(istio.iter().cloned());

    // Istio policies - serialize typed structs to JSON
    manifests.push(
        serde_json::to_string_pretty(&IstioReconciler::generate_peer_authentication())
            .map_err(|e| format!("Failed to serialize PeerAuthentication: {}", e))?,
    );
    manifests.push(
        serde_json::to_string_pretty(&IstioReconciler::generate_default_deny())
            .map_err(|e| format!("Failed to serialize AuthorizationPolicy: {}", e))?,
    );
    manifests.push(
        serde_json::to_string_pretty(&IstioReconciler::generate_waypoint_default_deny())
            .map_err(|e| format!("Failed to serialize AuthorizationPolicy: {}", e))?,
    );
    manifests.push(
        serde_json::to_string_pretty(&IstioReconciler::generate_operator_allow_policy())
            .map_err(|e| format!("Failed to serialize AuthorizationPolicy: {}", e))?,
    );

    // Cilium policies (skip on kind/bootstrap clusters) - serialize typed structs to JSON
    if !config.skip_cilium_policies {
        manifests.push(
            serde_json::to_string_pretty(&cilium::generate_ztunnel_allowlist()).map_err(|e| {
                format!("Failed to serialize CiliumClusterwideNetworkPolicy: {}", e)
            })?,
        );
        manifests.push(
            serde_json::to_string_pretty(&cilium::generate_default_deny()).map_err(|e| {
                format!("Failed to serialize CiliumClusterwideNetworkPolicy: {}", e)
            })?,
        );
        manifests.push(
            serde_json::to_string_pretty(&cilium::generate_waypoint_egress_policy()).map_err(
                |e| format!("Failed to serialize CiliumClusterwideNetworkPolicy: {}", e),
            )?,
        );
        // Operator network policy - allows operator to reach parent cell and accept agent connections
        manifests.push(
            serde_json::to_string_pretty(&cilium::generate_operator_network_policy(
                config.parent_host.as_deref(),
                config.parent_grpc_port,
            ))
            .map_err(|e| format!("Failed to serialize CiliumNetworkPolicy: {}", e))?,
        );
    }

    Ok(manifests)
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

/// Run `helm template` command and return parsed manifests
///
/// This is the centralized helper for all helm template execution.
/// Handles error conversion and YAML parsing consistently.
///
/// # Arguments
/// * `release_name` - Helm release name (e.g., "cilium", "istio-base")
/// * `chart_path` - Path to chart tarball
/// * `namespace` - Target namespace
/// * `extra_args` - Additional helm arguments (e.g., "--set", "key=value")
pub(crate) async fn run_helm_template(
    release_name: &str,
    chart_path: &str,
    namespace: &str,
    extra_args: &[&str],
) -> Result<Vec<String>, String> {
    let output = Command::new("helm")
        .args([
            "template",
            release_name,
            chart_path,
            "--namespace",
            namespace,
        ])
        .args(extra_args)
        .output()
        .await
        .map_err(|e| format!("failed to run helm: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("helm template {} failed: {}", release_name, stderr));
    }

    let yaml_str = String::from_utf8_lossy(&output.stdout);
    Ok(split_yaml_documents(&yaml_str))
}

/// Get charts directory from environment or use default
pub fn charts_dir() -> String {
    std::env::var("LATTICE_CHARTS_DIR").unwrap_or_else(|_| {
        option_env!("LATTICE_CHARTS_DIR")
            .unwrap_or("/charts")
            .to_string()
    })
}

pub(crate) fn namespace_yaml(name: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {}",
        name
    )
}

/// Split a multi-document YAML string into individual documents.
///
/// Only used for parsing external YAML sources (helm output, CRD files).
/// Filters out empty documents and comment-only blocks.
/// Normalizes output to always have `---` prefix for kubectl apply compatibility.
///
/// Note: JSON policies from our typed generators are added directly to manifest
/// lists and never go through this function.
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
}
