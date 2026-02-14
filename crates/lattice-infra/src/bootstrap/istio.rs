//! Istio service mesh manifest generation
//!
//! Embeds pre-rendered Istio manifests from build time.
//! Installs four charts: base (CRDs), istiod (control plane), istio-cni, and ztunnel.

use std::collections::BTreeMap;
use std::sync::{LazyLock, OnceLock};

use lattice_common::kube_utils::ObjectMeta;
use lattice_common::mesh;
use lattice_common::policy::{
    AuthorizationOperation, AuthorizationPolicy, AuthorizationPolicySpec, AuthorizationRule,
    MtlsConfig, OperationSpec, PeerAuthentication, PeerAuthenticationSpec, TargetRef,
    WorkloadSelector,
};
use lattice_common::LATTICE_SYSTEM_NAMESPACE;

use super::keda::{KEDA_NAMESPACE, KEDA_SERVICE_ACCOUNT};
use super::prometheus::{
    MONITORING_NAMESPACE, VMAGENT_SERVICE_ACCOUNT, VMCLUSTER_NAME, VMINSERT_PORT, VMSELECT_PORT,
    VMSINGLE_PORT,
};

use super::split_yaml_documents;

/// Pre-rendered static Istio manifests (base, cni, ztunnel) — no dynamic values.
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
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/ztunnel.yaml"
    ))));
    manifests
});

/// Pre-rendered istiod template with __LATTICE_CLUSTER_NAME__ placeholder.
static ISTIOD_TEMPLATE: &str = include_str!(concat!(env!("OUT_DIR"), "/istiod.yaml"));

/// Istio configuration
#[derive(Debug, Clone)]
pub struct IstioConfig {
    /// Istio version (pinned to Lattice release)
    pub version: &'static str,
    /// Cluster name for trust domain (lattice.{cluster}.local)
    pub cluster_name: String,
}

impl IstioConfig {
    /// Create a new config with the given cluster name
    pub fn new(cluster_name: impl Into<String>) -> Self {
        Self {
            version: env!("ISTIO_VERSION"),
            cluster_name: cluster_name.into(),
        }
    }
}

/// Istio manifest generator
pub struct IstioReconciler {
    config: IstioConfig,
    manifests: OnceLock<Vec<String>>,
}

impl IstioReconciler {
    /// Create with the given cluster name
    pub fn new(cluster_name: impl Into<String>) -> Self {
        Self {
            config: IstioConfig::new(cluster_name),
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

            // Static charts (base, cni, ztunnel)
            all.extend(ISTIO_STATIC_MANIFESTS.iter().cloned());

            // Istiod with cluster-specific trust domain
            let istiod_yaml =
                ISTIOD_TEMPLATE.replace("__LATTICE_CLUSTER_NAME__", &self.config.cluster_name);
            all.extend(split_yaml_documents(&istiod_yaml));

            all
        })
    }

    /// Generate default PeerAuthentication for STRICT mTLS
    pub fn generate_peer_authentication() -> PeerAuthentication {
        PeerAuthentication::new(
            ObjectMeta::new("default", "istio-system"),
            PeerAuthenticationSpec {
                mtls: MtlsConfig {
                    mode: "STRICT".to_string(),
                },
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

    /// Generate AuthorizationPolicies allowing monitoring traffic through the mesh.
    ///
    /// Produces policies for:
    /// - VMAgent → VMSingle/VMInsert (push scraped metrics to storage)
    /// - KEDA → VMSingle/VMSelect (query metrics for autoscaling)
    ///
    /// Note: VMAgent → scrape targets is handled per-service by `VMServiceScrapePhase`.
    pub fn generate_monitoring_allow_policies(
        cluster_name: &str,
        ha: bool,
    ) -> Vec<AuthorizationPolicy> {
        // VMAgent → storage (write path)
        let (write_service, write_port) = if ha {
            (format!("vminsert-{}", VMCLUSTER_NAME), VMINSERT_PORT)
        } else {
            (format!("vmsingle-{}", VMCLUSTER_NAME), VMSINGLE_PORT)
        };

        let vmagent_principal = mesh::trust_domain::principal(
            cluster_name,
            MONITORING_NAMESPACE,
            VMAGENT_SERVICE_ACCOUNT,
        );

        // KEDA → query (read path)
        let (read_service, read_port) = if ha {
            (format!("vmselect-{}", VMCLUSTER_NAME), VMSELECT_PORT)
        } else {
            (format!("vmsingle-{}", VMCLUSTER_NAME), VMSINGLE_PORT)
        };

        let keda_principal =
            mesh::trust_domain::principal(cluster_name, KEDA_NAMESPACE, KEDA_SERVICE_ACCOUNT);

        // Monitoring namespace has no waypoint — use selector-based policies
        // enforced by ztunnel directly.
        let write_labels = BTreeMap::from([("app.kubernetes.io/name".to_string(), write_service)]);
        let read_labels = BTreeMap::from([("app.kubernetes.io/name".to_string(), read_service)]);

        vec![
            AuthorizationPolicy::allow_to_workload(
                "allow-vmagent-write",
                MONITORING_NAMESPACE,
                write_labels,
                vec![vmagent_principal],
                vec![write_port.to_string()],
            ),
            AuthorizationPolicy::allow_to_workload(
                "allow-keda-query",
                MONITORING_NAMESPACE,
                read_labels,
                vec![keda_principal],
                vec![read_port.to_string()],
            ),
        ]
    }

    /// Generate AuthorizationPolicy allowing traffic to lattice-operator
    ///
    /// The lattice-operator needs to accept connections from:
    /// - Workload cluster bootstrap (postKubeadmCommands calling webhook on 8443)
    /// - Workload cluster agents (gRPC on 50051)
    ///
    /// These connections come from outside the mesh, so we allow any source.
    pub fn generate_operator_allow_policy() -> AuthorizationPolicy {
        AuthorizationPolicy::new(
            ObjectMeta::new("lattice-operator-allow", LATTICE_SYSTEM_NAMESPACE),
            AuthorizationPolicySpec {
                target_refs: vec![],
                selector: Some(WorkloadSelector {
                    match_labels: BTreeMap::from([(
                        "app".to_string(),
                        "lattice-operator".to_string(),
                    )]),
                }),
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![],
                    to: vec![AuthorizationOperation {
                        operation: OperationSpec {
                            ports: vec!["8443".to_string(), "50051".to_string()],
                            hosts: vec![],
                        },
                    }],
                }],
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_with_cluster_name() {
        let config = IstioConfig::new("test-cluster");
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
        let reconciler = IstioReconciler::new("test-cluster");
        assert_eq!(reconciler.version(), env!("ISTIO_VERSION"));
    }

    #[test]
    fn test_manifest_rendering() {
        let reconciler = IstioReconciler::new("test-cluster");
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

        // Should contain the cluster-specific trust domain
        let has_trust = manifests
            .iter()
            .any(|m| m.contains("lattice.test-cluster.local"));
        assert!(has_trust, "Should contain cluster-specific trust domain");
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
    }

    #[test]
    fn test_monitoring_allow_policies_single_node() {
        let policies = IstioReconciler::generate_monitoring_allow_policies("test-cluster", false);
        assert_eq!(policies.len(), 2);

        // VMAgent → VMSingle (ztunnel-enforced via selector)
        let vmagent = &policies[0];
        assert_eq!(vmagent.metadata.name, "allow-vmagent-write");
        assert_eq!(vmagent.metadata.namespace, MONITORING_NAMESPACE);
        assert_eq!(vmagent.spec.action, "ALLOW");
        assert!(vmagent.spec.target_refs.is_empty());
        let selector = vmagent.spec.selector.as_ref().unwrap();
        assert_eq!(
            selector.match_labels.get("app.kubernetes.io/name"),
            Some(&format!("vmsingle-{}", VMCLUSTER_NAME))
        );
        let principal = &vmagent.spec.rules[0].from[0].source.principals[0];
        assert!(principal.contains(VMAGENT_SERVICE_ACCOUNT));
        assert_eq!(
            vmagent.spec.rules[0].to[0].operation.ports,
            vec![VMSINGLE_PORT.to_string()]
        );

        // KEDA → VMSingle (ztunnel-enforced via selector)
        let keda = &policies[1];
        assert_eq!(keda.metadata.name, "allow-keda-query");
        assert!(keda.spec.target_refs.is_empty());
        let selector = keda.spec.selector.as_ref().unwrap();
        assert_eq!(
            selector.match_labels.get("app.kubernetes.io/name"),
            Some(&format!("vmsingle-{}", VMCLUSTER_NAME))
        );
        let principal = &keda.spec.rules[0].from[0].source.principals[0];
        assert!(principal.contains(KEDA_SERVICE_ACCOUNT));
        assert_eq!(
            keda.spec.rules[0].to[0].operation.ports,
            vec![VMSINGLE_PORT.to_string()]
        );
    }

    #[test]
    fn test_monitoring_allow_policies_ha() {
        let policies = IstioReconciler::generate_monitoring_allow_policies("test-cluster", true);
        assert_eq!(policies.len(), 2);

        // VMAgent → VMInsert (HA write path, ztunnel-enforced)
        assert!(policies[0].spec.target_refs.is_empty());
        let selector = policies[0].spec.selector.as_ref().unwrap();
        assert_eq!(
            selector.match_labels.get("app.kubernetes.io/name"),
            Some(&format!("vminsert-{}", VMCLUSTER_NAME))
        );
        assert_eq!(
            policies[0].spec.rules[0].to[0].operation.ports,
            vec![VMINSERT_PORT.to_string()]
        );

        // KEDA → VMSelect (HA read path, ztunnel-enforced)
        assert!(policies[1].spec.target_refs.is_empty());
        let selector = policies[1].spec.selector.as_ref().unwrap();
        assert_eq!(
            selector.match_labels.get("app.kubernetes.io/name"),
            Some(&format!("vmselect-{}", VMCLUSTER_NAME))
        );
        assert_eq!(
            policies[1].spec.rules[0].to[0].operation.ports,
            vec![VMSELECT_PORT.to_string()]
        );
    }
}
