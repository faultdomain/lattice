//! Infrastructure manifest generation
//!
//! Single source of truth for ALL infrastructure manifests.
//! Used by operator startup (`ensure_infrastructure`)
//! to install Istio, Gateway API CRDs, ESO, Velero, VictoriaMetrics, KEDA, metrics-server, and GPU stack.
//!
//! Server-side apply handles idempotency - no need to check if installed.
//!
//! All Helm charts are pre-rendered at build time and embedded into the binary.

pub mod cert_manager;
pub mod cilium;
pub mod eso;
pub mod gpu;
pub mod istio;
pub mod keda;
pub mod metrics_server;
pub mod prometheus;
pub mod tetragon;
pub mod velero;

use std::sync::LazyLock;

use kube::ResourceExt;
use tracing::debug;

use lattice_common::crd::{
    BackupsConfig, BootstrapProvider, CedarPolicy, CedarPolicySpec, EgressRule, EgressTarget,
    LatticeCluster, LatticeMeshMember, LatticeMeshMemberSpec, MonitoringConfig, ProviderType,
};
use lattice_common::{
    DEFAULT_GRPC_PORT, LATTICE_SYSTEM_NAMESPACE, MONITORING_NAMESPACE, VMAGENT_SA_NAME,
};

/// Configuration for infrastructure manifest generation
#[derive(Debug, Clone)]
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
    /// Enable GPU infrastructure (NFD + NVIDIA device plugin + HAMi)
    pub gpu: bool,
    /// Monitoring infrastructure configuration (VictoriaMetrics + KEDA for autoscaling).
    pub monitoring: MonitoringConfig,
    /// Backup infrastructure configuration (Velero).
    pub backups: BackupsConfig,
}

impl Default for InfrastructureConfig {
    fn default() -> Self {
        Self {
            provider: ProviderType::default(),
            bootstrap: BootstrapProvider::default(),
            cluster_name: String::new(),
            skip_cilium_policies: false,
            skip_service_mesh: false,
            parent_host: None,
            parent_grpc_port: DEFAULT_GRPC_PORT,
            gpu: false,
            monitoring: MonitoringConfig::default(),
            backups: BackupsConfig::default(),
        }
    }
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
            gpu: cluster.spec.gpu,
            monitoring: cluster.spec.monitoring.clone(),
            backups: cluster.spec.backups.clone(),
        }
    }
}

/// Generate infrastructure manifests
///
/// Used by both operator startup and full cluster bootstrap.
/// All manifests are pre-rendered at build time — no subprocess execution.
/// NOTE: cert-manager and CAPI providers are installed via the native CAPI installer,
/// which manages their lifecycle (including upgrades).
pub async fn generate_core(config: &InfrastructureConfig) -> Result<Vec<String>, String> {
    let mut manifests = Vec::new();

    if !config.skip_service_mesh {
        // Istio ambient + Cilium policies
        manifests.extend(generate_istio(config)?);

        // Gateway API CRDs (required for Istio Gateway and waypoints)
        let gw_api = generate_gateway_api_crds();
        debug!(count = gw_api.len(), "generated Gateway API CRDs");
        manifests.extend(gw_api.iter().cloned());
    }

    // External Secrets Operator (always installed — required for credential management)
    manifests.extend(eso::generate_eso().iter().cloned());

    // Velero (for backup and restore)
    if config.backups.enabled {
        manifests.extend(velero::generate_velero().iter().cloned());
    }

    // VictoriaMetrics K8s Stack + KEDA (event-driven autoscaling)
    if config.monitoring.enabled {
        manifests.extend(
            prometheus::generate_prometheus(config.monitoring.ha)
                .iter()
                .cloned(),
        );
        manifests.extend(keda::generate_keda().iter().cloned());
        manifests.extend(metrics_server::generate_metrics_server().iter().cloned());

        // LMM CRDs for addon mesh policies (KEDA + monitoring)
        if !config.skip_service_mesh {
            manifests.extend(serialize_lmms(keda::generate_keda_mesh_members())?);
            manifests.extend(serialize_lmms(
                prometheus::generate_monitoring_mesh_members(config.monitoring.ha),
            )?);

            // Cedar policy: allow vmagent wildcard outbound for metrics scraping
            manifests.push(
                serde_json::to_string_pretty(&generate_vmagent_cedar_policy())
                    .map_err(|e| format!("Failed to serialize CedarPolicy: {e}"))?,
            );
        }
    }

    // GPU stack (NFD + NVIDIA device plugin + HAMi)
    if config.gpu {
        manifests.extend(gpu::generate_gpu_stack().iter().cloned());
    }

    // Tetragon runtime enforcement (eBPF kprobes on LSM hooks)
    manifests.extend(tetragon::generate_tetragon().iter().cloned());
    manifests.push(
        serde_json::to_string_pretty(&tetragon::generate_baseline_tracing_policy())
            .map_err(|e| format!("Failed to serialize baseline TracingPolicy: {e}"))?,
    );

    Ok(manifests)
}

/// Generate Istio and Cilium policy manifests
pub fn generate_istio(config: &InfrastructureConfig) -> Result<Vec<String>, String> {
    let mut manifests = vec![namespace_yaml("istio-system")];

    let reconciler = istio::IstioReconciler::new(&config.cluster_name);
    let istio = reconciler.manifests();
    manifests.extend(istio.iter().cloned());

    // Istio policies - serialize typed structs to JSON
    manifests.push(
        serde_json::to_string_pretty(&istio::IstioReconciler::generate_peer_authentication())
            .map_err(|e| format!("Failed to serialize PeerAuthentication: {}", e))?,
    );
    manifests.push(
        serde_json::to_string_pretty(&istio::IstioReconciler::generate_default_deny())
            .map_err(|e| format!("Failed to serialize AuthorizationPolicy: {}", e))?,
    );
    manifests.push(
        serde_json::to_string_pretty(&istio::IstioReconciler::generate_waypoint_default_deny())
            .map_err(|e| format!("Failed to serialize AuthorizationPolicy: {}", e))?,
    );
    manifests.push(
        serde_json::to_string_pretty(&istio::IstioReconciler::generate_operator_allow_policy())
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
            serde_json::to_string_pretty(&cilium::generate_mesh_proxy_egress_policy()).map_err(
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

/// Pre-rendered Gateway API CRDs embedded at build time.
static GATEWAY_API_CRDS: LazyLock<Vec<String>> = LazyLock::new(|| {
    split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/gateway-api-crds.yaml"
    )))
});

/// Generate Gateway API CRDs
pub fn generate_gateway_api_crds() -> &'static [String] {
    &GATEWAY_API_CRDS
}

// Helpers

pub(crate) fn namespace_yaml(name: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {}",
        name
    )
}

/// Egress rule allowing traffic to the kube-apiserver.
///
/// Required for system components (KEDA, VM operator, etc.) that need to
/// reach the Kubernetes API from within the ambient mesh.
/// Port 6443 is the actual endpoint port after DNAT from the ClusterIP (443).
pub(crate) fn kube_apiserver_egress() -> EgressRule {
    EgressRule {
        target: EgressTarget::Entity("kube-apiserver".to_string()),
        ports: vec![6443],
    }
}

/// Create a namespaced LatticeMeshMember.
pub(crate) fn lmm(name: &str, namespace: &str, spec: LatticeMeshMemberSpec) -> LatticeMeshMember {
    let mut member = LatticeMeshMember::new(name, spec);
    member.metadata.namespace = Some(namespace.to_string());
    member
}

/// Generate the CedarPolicy that permits vmagent's wildcard outbound.
///
/// vmagent uses `depends_all: true` to scrape metrics from any service that
/// exposes a "metrics" port. This Cedar policy authorizes that wildcard.
fn generate_vmagent_cedar_policy() -> CedarPolicy {
    let mut policy = CedarPolicy::new(
        "vmagent-wildcard-outbound",
        CedarPolicySpec {
            description: Some("Allow vmagent wildcard outbound for metrics scraping".to_string()),
            policies: format!(
                r#"permit(
    principal == Lattice::Service::"{}/{}",
    action == Lattice::Action::"AllowWildcard",
    resource == Lattice::Mesh::"outbound"
);"#,
                MONITORING_NAMESPACE, VMAGENT_SA_NAME,
            ),
            priority: 0,
            enabled: true,
            propagate: true,
        },
    );
    policy.metadata.namespace = Some(LATTICE_SYSTEM_NAMESPACE.to_string());
    policy
}

/// Serialize a vec of LMMs to JSON manifests.
fn serialize_lmms(members: Vec<LatticeMeshMember>) -> Result<Vec<String>, String> {
    members
        .iter()
        .map(|m| {
            serde_json::to_string_pretty(m)
                .map_err(|e| format!("Failed to serialize LatticeMeshMember: {e}"))
        })
        .collect()
}

/// Create a namespace YAML with Istio ambient mesh enrollment.
///
/// Used for infrastructure namespaces (e.g. monitoring) whose pods need
/// mTLS communication with workload pods enrolled in the ambient mesh.
pub(crate) fn namespace_yaml_ambient(name: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {}\n  labels:\n    istio.io/dataplane-mode: ambient",
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
        .filter(|doc| {
            let keep = !doc.is_empty() && doc.contains("kind:") && !doc.contains("helm.sh/hook");
            if !keep && !doc.is_empty() {
                tracing::debug!(
                    doc_preview = &doc[..doc.len().min(100)],
                    "Filtered out YAML document"
                );
            }
            keep
        })
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

    #[test]
    fn test_gateway_api_crds() {
        let crds = generate_gateway_api_crds();
        assert!(!crds.is_empty());
        assert!(crds.iter().any(|c| c.contains("CustomResourceDefinition")));
    }
}
