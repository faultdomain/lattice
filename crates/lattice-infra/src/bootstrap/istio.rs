//! Istio service mesh manifest generation
//!
//! Embeds pre-rendered Istio manifests from build time.
//! Installs four charts: base (CRDs), istiod (control plane), istio-cni, and ztunnel.

use std::collections::BTreeMap;
use std::sync::{LazyLock, OnceLock};

use lattice_common::kube_utils::ObjectMeta;
use lattice_common::policy::istio::{
    AuthorizationOperation, AuthorizationPolicy, AuthorizationPolicySpec, AuthorizationRule,
    MtlsConfig, OperationSpec, PeerAuthentication, PeerAuthenticationSpec, TargetRef,
    WorkloadSelector,
};
use lattice_common::{LATTICE_SYSTEM_NAMESPACE, OPERATOR_NAME};

use super::split_yaml_documents;

/// Pre-rendered static Istio manifests (base, cni) — no dynamic values.
static ISTIO_STATIC_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = Vec::new();
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/istio-base.yaml"
    ))));
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/istio-cni.yaml"
    ))));
    manifests
});

/// Pre-rendered istiod template with __LATTICE_CLUSTER_NAME__ placeholder.
static ISTIOD_TEMPLATE: &str = include_str!(concat!(env!("OUT_DIR"), "/istiod.yaml"));

/// Pre-rendered ztunnel template with __LATTICE_CLUSTER_NAME__ placeholder.
static ZTUNNEL_TEMPLATE: &str = include_str!(concat!(env!("OUT_DIR"), "/ztunnel.yaml"));

/// Istio configuration
#[derive(Debug, Clone)]
pub struct IstioConfig {
    /// Istio version (pinned to Lattice release)
    pub version: &'static str,
    /// Cluster name (unique per cluster, used for multiCluster.clusterName and network)
    pub cluster_name: String,
    /// Trust domain derived from the root CA fingerprint.
    /// All clusters sharing the same root CA get the same trust domain,
    /// enabling cross-cluster mTLS without trustDomainAliases.
    /// Format: `lattice.{sha256_hex_prefix}`
    pub trust_domain: String,
    /// Remote cluster names for meshNetworks gateway mapping.
    /// None = don't touch meshNetworks (preserves existing).
    /// Some(vec![]) = explicitly clear.
    pub remote_networks: Option<Vec<String>>,
}

impl IstioConfig {
    pub fn new(
        cluster_name: impl Into<String>,
        trust_domain: String,
        remote_networks: Option<Vec<String>>,
    ) -> Self {
        Self {
            version: env!("ISTIO_VERSION"),
            cluster_name: cluster_name.into(),
            trust_domain,
            remote_networks,
        }
    }
}

/// Istio manifest generator
pub struct IstioReconciler {
    config: IstioConfig,
    manifests: OnceLock<Vec<String>>,
}

impl IstioReconciler {
    pub fn new(
        cluster_name: impl Into<String>,
        trust_domain: String,
        remote_networks: Option<Vec<String>>,
    ) -> Self {
        Self {
            config: IstioConfig::new(cluster_name, trust_domain, remote_networks),
            manifests: OnceLock::new(),
        }
    }

    /// Get the expected version
    pub fn version(&self) -> &str {
        self.config.version
    }

    /// Get manifests (lazily rendered from embedded templates)
    pub fn manifests(&self) -> &[String] {
        self.manifests.get_or_init(|| {
            let mut all = Vec::new();

            // Static charts (base, cni)
            all.extend(ISTIO_STATIC_MANIFESTS.iter().cloned());

            // Istiod with cluster-specific values (trust domain, meshID, network, meshNetworks)
            let mut istiod_yaml = ISTIOD_TEMPLATE
                .replace("__LATTICE_CLUSTER_NAME__", &self.config.cluster_name)
                .replace("__LATTICE_TRUST_DOMAIN__", &self.config.trust_domain);

            let networks = self.config.remote_networks.as_deref().unwrap_or(&[]);
            istiod_yaml = istiod_yaml.replace(
                "__LATTICE_MESH_NETWORKS__: __LATTICE_MESH_NETWORKS__",
                &build_mesh_networks_yaml(networks),
            );
            all.extend(split_yaml_documents(&istiod_yaml));

            // Ztunnel with cluster-specific values (clusterName, network)
            let ztunnel_yaml =
                ZTUNNEL_TEMPLATE.replace("__LATTICE_CLUSTER_NAME__", &self.config.cluster_name);
            all.extend(split_yaml_documents(&ztunnel_yaml));

            all
        })
    }

    /// Generate default PeerAuthentication for STRICT mTLS
    pub fn generate_peer_authentication() -> PeerAuthentication {
        PeerAuthentication::new(
            ObjectMeta::new("default", "istio-system"),
            PeerAuthenticationSpec {
                selector: None,
                mtls: MtlsConfig {
                    mode: "STRICT".to_string(),
                },
                port_level_mtls: None,
            },
        )
    }

    /// Generate mesh-wide default-deny AuthorizationPolicy
    ///
    /// This is the security baseline for the mesh. With this policy in place,
    /// all traffic is denied unless explicitly allowed by service-specific policies.
    /// Must be deployed to istio-system to apply mesh-wide.
    pub fn generate_default_deny() -> AuthorizationPolicy {
        AuthorizationPolicy::new(
            ObjectMeta::new("mesh-default-deny", "istio-system"),
            AuthorizationPolicySpec {
                target_refs: vec![],
                selector: None,
                action: String::new(),
                rules: vec![],
            },
        )
    }

    /// Generate waypoint default-deny AuthorizationPolicy
    ///
    /// This targets the istio-waypoint GatewayClass to ensure default-deny is
    /// enforced AT the waypoint, not just at ztunnel. Without this, once
    /// waypoint->target is allowed, the waypoint becomes permissive to all sources.
    ///
    /// See: https://github.com/istio/istio/issues/54696
    pub fn generate_waypoint_default_deny() -> AuthorizationPolicy {
        AuthorizationPolicy::new(
            ObjectMeta::new("waypoint-default-deny", "istio-system"),
            AuthorizationPolicySpec {
                target_refs: vec![TargetRef {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "GatewayClass".to_string(),
                    name: "istio-waypoint".to_string(),
                }],
                selector: None,
                action: String::new(),
                rules: vec![],
            },
        )
    }

    /// Generate AuthorizationPolicy allowing the east-west gateway to forward
    /// cross-cluster HBONE traffic.
    ///
    /// The mesh-default-deny applies to the gateway envoy since it's in the mesh.
    /// Without this ALLOW, all cross-cluster HBONE forwarding is denied with
    /// `tcp.rbac.denied`. Uses targetRef (not selector) to attach to the gateway
    /// envoy — selector only attaches to ztunnel.
    ///
    /// Rules are allow-all (`[{}]`) because after HBONE termination the destination
    /// port is the inner service port, not 15008. Port filtering doesn't work here;
    /// mTLS identity is the enforcement layer.
    pub fn generate_eastwest_gateway_allow() -> AuthorizationPolicy {
        AuthorizationPolicy::new(
            ObjectMeta::new("eastwest-gateway-allow", "istio-system"),
            AuthorizationPolicySpec {
                target_refs: vec![TargetRef {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "Gateway".to_string(),
                    name: "istio-eastwestgateway".to_string(),
                }],
                selector: None,
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![],
                    to: vec![],
                }],
            },
        )
    }

    /// Generate AuthorizationPolicy allowing traffic to lattice-operator
    ///
    /// The lattice-operator needs to accept connections from:
    /// - Workload cluster bootstrap (postKubeadmCommands calling webhook on 8443)
    /// - Workload cluster agents (gRPC on 50051)
    ///
    /// These connections come from outside the mesh (kubeadm nodes during bootstrap
    /// have no SPIFFE identity, and agent gRPC uses Lattice's own PKI, not Istio mTLS).
    /// Restricting `from` principals would break bootstrap. Authentication is handled
    /// at the application layer: the bootstrap webhook validates cluster tokens, and
    /// the gRPC server validates Lattice-issued mTLS client certificates.
    pub fn generate_operator_allow_policy() -> AuthorizationPolicy {
        AuthorizationPolicy::new(
            ObjectMeta::new("lattice-operator-allow", LATTICE_SYSTEM_NAMESPACE),
            AuthorizationPolicySpec {
                target_refs: vec![],
                selector: Some(WorkloadSelector {
                    match_labels: BTreeMap::from([("app".to_string(), OPERATOR_NAME.to_string())]),
                }),
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![],
                    to: vec![AuthorizationOperation {
                        operation: OperationSpec {
                            ports: vec![
                                "8443".to_string(),
                                "50051".to_string(),
                                "8081".to_string(),
                                "8082".to_string(),
                                "8787".to_string(),
                            ],
                            hosts: vec![],
                        },
                    }],
                }],
            },
        )
    }
}

/// Build the YAML content for the meshNetworks `networks:` block.
///
/// Each remote network maps to its east-west gateway via `registryServiceName`,
/// so istiod auto-discovers the gateway's external IP from that cluster's registry.
fn build_mesh_networks_yaml(remote_networks: &[String]) -> String {
    if remote_networks.is_empty() {
        return "{}".to_string();
    }

    // The placeholder sits at 6-space indent under "networks:".
    // First line inherits indent from placeholder, subsequent lines need it explicit.
    let indent = "      ";
    let mut lines = Vec::new();
    for (i, name) in remote_networks.iter().enumerate() {
        if i == 0 {
            lines.push(format!("{}:", name));
        } else {
            lines.push(format!("{}{}:", indent, name));
        }
        lines.push(format!("{}  endpoints:", indent));
        lines.push(format!("{}  - fromRegistry: {}", indent, name));
        lines.push(format!("{}  gateways:", indent));
        lines.push(format!(
            "{}  - registryServiceName: istio-eastwestgateway.istio-system",
            indent
        ));
        lines.push(format!("{}    port: 15008", indent));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_with_cluster_name() {
        let config = IstioConfig::new("test-cluster", "lattice.test.local".to_string(), None);
        assert_eq!(config.version, env!("ISTIO_VERSION"));
        assert_eq!(config.cluster_name, "test-cluster");
    }

    #[test]
    fn test_peer_authentication() {
        let policy = IstioReconciler::generate_peer_authentication();
        assert_eq!(policy.metadata.name, "default");
        assert_eq!(policy.metadata.namespace, "istio-system");
        assert_eq!(policy.spec.mtls.mode, "STRICT");
    }

    #[test]
    fn test_reconciler_version() {
        let reconciler =
            IstioReconciler::new("test-cluster", "lattice.test.local".to_string(), None);
        assert_eq!(reconciler.version(), env!("ISTIO_VERSION"));
    }

    #[test]
    fn test_manifest_rendering() {
        let reconciler =
            IstioReconciler::new("test-cluster", "lattice.test.local".to_string(), None);
        let manifests = reconciler.manifests();

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

        // Should contain the CA-derived trust domain
        let has_trust = manifests.iter().any(|m| m.contains("lattice.test.local"));
        assert!(has_trust, "Should contain trust domain from config");
    }

    #[test]
    fn test_default_deny_policy() {
        let policy = IstioReconciler::generate_default_deny();
        assert_eq!(policy.metadata.name, "mesh-default-deny");
        assert_eq!(policy.metadata.namespace, "istio-system");
        assert!(policy
            .metadata
            .labels
            .contains_key("app.kubernetes.io/managed-by"));
        // Empty spec means deny all traffic (no rules, no action)
        assert!(policy.spec.rules.is_empty());
        assert!(policy.spec.action.is_empty());
        // No selector = mesh-wide
        assert!(policy.spec.selector.is_none());
    }

    #[test]
    fn test_operator_allow_policy() {
        let policy = IstioReconciler::generate_operator_allow_policy();
        assert_eq!(policy.metadata.name, "lattice-operator-allow");
        assert_eq!(policy.metadata.namespace, LATTICE_SYSTEM_NAMESPACE);
        assert!(policy
            .metadata
            .labels
            .contains_key("app.kubernetes.io/managed-by"));

        // Has selector for lattice-operator
        let selector = policy.spec.selector.as_ref().unwrap();
        assert_eq!(
            selector.match_labels.get("app"),
            Some(&"lattice-operator".to_string())
        );

        assert_eq!(policy.spec.action, "ALLOW");

        // Check ports are allowed
        let ports: Vec<&str> = policy
            .spec
            .rules
            .iter()
            .flat_map(|r| r.to.iter())
            .flat_map(|t| t.operation.ports.iter())
            .map(|s| s.as_str())
            .collect();
        assert!(ports.contains(&"8443"));
        assert!(ports.contains(&"50051"));
        assert!(ports.contains(&"8081"));
        assert!(ports.contains(&"8082"));
        assert!(ports.contains(&"8787"));
    }
}
