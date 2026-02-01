//! Istio service mesh manifest generation
//!
//! Generates Istio manifests using Helm charts with ambient mesh mode.
//! Installs four charts: base (CRDs), istiod (control plane), istio-cni, and ztunnel.

use std::collections::BTreeMap;

use lattice_common::policy::{
    AuthorizationOperation, AuthorizationPolicy, AuthorizationPolicySpec, AuthorizationRule,
    MtlsConfig, OperationSpec, PeerAuthentication, PeerAuthenticationSpec, PolicyMetadata,
    TargetRef, WorkloadSelector,
};
use lattice_common::LATTICE_SYSTEM_NAMESPACE;
use tokio::sync::OnceCell;
use tracing::info;

use super::{charts_dir, run_helm_template};

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
    manifests: OnceCell<Result<Vec<String>, String>>,
}

impl IstioReconciler {
    /// Create with the given cluster name
    pub fn new(cluster_name: impl Into<String>) -> Self {
        Self {
            config: IstioConfig::new(cluster_name),
            manifests: OnceCell::new(),
        }
    }

    /// Get the expected version
    pub fn version(&self) -> &str {
        self.config.version
    }

    /// Get manifests (lazily rendered, async)
    ///
    /// This is an async function to avoid blocking the tokio runtime during
    /// helm template execution.
    pub async fn manifests(&self) -> Result<&[String], String> {
        let result = self
            .manifests
            .get_or_init(|| async { Self::render_manifests(&self.config).await })
            .await;
        match result {
            Ok(m) => Ok(m),
            Err(e) => Err(e.clone()),
        }
    }

    /// Generate default PeerAuthentication for STRICT mTLS
    pub fn generate_peer_authentication() -> PeerAuthentication {
        PeerAuthentication::new(
            PolicyMetadata::new("default", "istio-system"),
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
            PolicyMetadata::new("mesh-default-deny", "istio-system"),
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
    /// waypoint→target is allowed, the waypoint becomes permissive to all sources.
    ///
    /// See: https://github.com/istio/istio/issues/54696
    pub fn generate_waypoint_default_deny() -> AuthorizationPolicy {
        AuthorizationPolicy::new(
            PolicyMetadata::new("waypoint-default-deny", "istio-system"),
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

    /// Generate AuthorizationPolicy allowing traffic to lattice-operator
    ///
    /// The lattice-operator needs to accept connections from:
    /// - Workload cluster bootstrap (postKubeadmCommands calling webhook on 8443)
    /// - Workload cluster agents (gRPC on 50051)
    ///
    /// These connections come from outside the mesh, so we allow any source.
    pub fn generate_operator_allow_policy() -> AuthorizationPolicy {
        AuthorizationPolicy::new(
            PolicyMetadata::new("lattice-operator-allow", LATTICE_SYSTEM_NAMESPACE),
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

    async fn render_manifests(config: &IstioConfig) -> Result<Vec<String>, String> {
        let mut all_manifests = Vec::new();

        // Use local chart tarballs (pulled at Docker build time or by build.rs)
        let charts = charts_dir();
        let base_chart = format!("{}/base-{}.tgz", charts, config.version);
        let istiod_chart = format!("{}/istiod-{}.tgz", charts, config.version);
        let cni_chart = format!("{}/cni-{}.tgz", charts, config.version);
        let ztunnel_chart = format!("{}/ztunnel-{}.tgz", charts, config.version);

        // 1. Render istio base chart (CRDs)
        info!(version = config.version, "Rendering Istio base chart");
        all_manifests.extend(run_helm_template("istio-base", &base_chart, "istio-system", &[]).await?);

        // 2. Render istio-cni chart (must be installed before ztunnel)
        info!(version = config.version, "Rendering Istio CNI chart");
        all_manifests.extend(
            run_helm_template(
                "istio-cni",
                &cni_chart,
                "istio-system",
                &[
                    "--set",
                    "profile=ambient",
                    // Chain with Cilium CNI
                    "--set",
                    "cni.cniConfFileName=05-cilium.conflist",
                ],
            )
            .await?,
        );

        // 3. Render istiod chart (control plane with ambient mode)
        info!(
            version = config.version,
            "Rendering Istiod chart with ambient mode"
        );
        // Configure trust domain to match Lattice SPIFFE identity format
        // Each cluster gets its own trust domain: lattice.{cluster}.local
        let trust_domain_arg = format!("meshConfig.trustDomain=lattice.{}.local", config.cluster_name);
        all_manifests.extend(
            run_helm_template(
                "istiod",
                &istiod_chart,
                "istio-system",
                &[
                    "--set",
                    "profile=ambient",
                    "--set",
                    &trust_domain_arg,
                    "--set",
                    "pilot.resources.requests.cpu=100m",
                    "--set",
                    "pilot.resources.requests.memory=128Mi",
                ],
            )
            .await?,
        );

        // 4. Render ztunnel chart (L4 data plane for ambient mode)
        info!(version = config.version, "Rendering ztunnel chart");
        all_manifests.extend(run_helm_template("ztunnel", &ztunnel_chart, "istio-system", &[]).await?);

        info!(count = all_manifests.len(), "Rendered Istio manifests");
        Ok(all_manifests)
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

    #[tokio::test]
    async fn test_manifest_rendering() {
        // Only runs if helm is available with istio repo
        let reconciler = IstioReconciler::new("test-cluster");
        if let Ok(manifests) = reconciler.manifests().await {
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
    fn test_split_yaml_documents_single() {
        use crate::bootstrap::split_yaml_documents;
        let yaml = "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test";
        let docs = split_yaml_documents(yaml);
        assert_eq!(docs.len(), 1);
        assert!(docs[0].starts_with("---"));
        assert!(docs[0].contains("kind: ConfigMap"));
    }

    #[test]
    fn test_split_yaml_documents_multiple() {
        use crate::bootstrap::split_yaml_documents;
        let yaml = "---\napiVersion: v1\nkind: ConfigMap\n---\napiVersion: v1\nkind: Secret\n---\napiVersion: v1\nkind: Service";
        let docs = split_yaml_documents(yaml);
        assert_eq!(docs.len(), 3);
    }

    #[test]
    fn test_split_yaml_documents_filters_empty() {
        use crate::bootstrap::split_yaml_documents;
        let yaml = "---\napiVersion: v1\nkind: ConfigMap\n---\n\n---\n# comment\n---\napiVersion: v1\nkind: Secret";
        let docs = split_yaml_documents(yaml);
        assert_eq!(docs.len(), 2);
    }

    #[test]
    fn test_split_yaml_documents_adds_separator() {
        use crate::bootstrap::split_yaml_documents;
        let yaml = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test";
        let docs = split_yaml_documents(yaml);
        assert_eq!(docs.len(), 1);
        assert!(docs[0].starts_with("---"));
    }
}
