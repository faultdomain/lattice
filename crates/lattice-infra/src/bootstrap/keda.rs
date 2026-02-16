//! KEDA manifest generation
//!
//! Embeds pre-rendered KEDA manifests from build time.
//! KEDA provides event-driven autoscaling via ScaledObject triggers.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use lattice_common::crd::{
    CallerRef, LatticeMeshMember, LatticeMeshMemberSpec, MeshMemberPort, MeshMemberTarget,
    PeerAuth, ServiceRef,
};

use super::prometheus::MONITORING_NAMESPACE;
use super::{kube_apiserver_egress, lmm, namespace_yaml_ambient, split_yaml_documents};

/// Namespace for KEDA components.
pub const KEDA_NAMESPACE: &str = "keda";

/// VM read target LMM name, referenced by KEDA operator's dependency.
pub const VM_READ_TARGET_LMM_NAME: &str = "vm-read-target";

static KEDA_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml_ambient(KEDA_NAMESPACE)];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/keda.yaml"
    ))));
    manifests
});

pub fn keda_version() -> &'static str {
    env!("KEDA_VERSION")
}

pub fn generate_keda() -> &'static [String] {
    &KEDA_MANIFESTS
}

/// Generate LatticeMeshMember CRDs for KEDA components.
///
/// Produces 3 LMMs:
/// 1. **keda-metrics-apiserver** — webhook called by kube-apiserver (Webhook mTLS)
/// 2. **keda-admission-webhooks** — webhook called by kube-apiserver (Webhook mTLS)
/// 3. **keda-operator** — receives gRPC from metrics-apiserver, queries VictoriaMetrics
pub fn generate_keda_mesh_members() -> Vec<LatticeMeshMember> {
    vec![
        // keda-metrics-apiserver — webhook called by kube-apiserver, aggregates metrics
        lmm(
            "keda-metrics-apiserver",
            KEDA_NAMESPACE,
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(BTreeMap::from([(
                    "app".to_string(),
                    "keda-operator-metrics-apiserver".to_string(),
                )])),
                ports: vec![MeshMemberPort {
                    port: 6443,
                    name: "metrics-api".to_string(),
                    peer_auth: PeerAuth::Webhook,
                }],
                allowed_callers: vec![],
                dependencies: vec![ServiceRef::new(KEDA_NAMESPACE, "keda-operator")],
                egress: vec![kube_apiserver_egress()],
                allow_peer_traffic: false,
                ingress: None,
                service_account: Some("keda-metrics-server".to_string()),
            },
        ),
        // keda-admission-webhooks — webhook called by kube-apiserver
        lmm(
            "keda-admission-webhooks",
            KEDA_NAMESPACE,
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(BTreeMap::from([(
                    "app".to_string(),
                    "keda-admission-webhooks".to_string(),
                )])),
                ports: vec![MeshMemberPort {
                    port: 9443,
                    name: "webhook".to_string(),
                    peer_auth: PeerAuth::Webhook,
                }],
                allowed_callers: vec![],
                dependencies: vec![],
                egress: vec![kube_apiserver_egress()],
                allow_peer_traffic: false,
                ingress: None,
                service_account: None,
            },
        ),
        // keda-operator — receives gRPC from metrics-apiserver, scales workloads
        lmm(
            "keda-operator",
            KEDA_NAMESPACE,
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(BTreeMap::from([(
                    "app".to_string(),
                    "keda-operator".to_string(),
                )])),
                ports: vec![MeshMemberPort {
                    port: 9666,
                    name: "grpc".to_string(),
                    peer_auth: PeerAuth::Strict,
                }],
                allowed_callers: vec![CallerRef {
                    name: "keda-metrics-apiserver".to_string(),
                    namespace: Some(KEDA_NAMESPACE.to_string()),
                }],
                dependencies: vec![ServiceRef::new(
                    MONITORING_NAMESPACE,
                    VM_READ_TARGET_LMM_NAME,
                )],
                egress: vec![kube_apiserver_egress()],
                allow_peer_traffic: false,
                ingress: None,
                service_account: None,
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!keda_version().is_empty());
    }

    #[test]
    fn manifests_are_embedded() {
        let manifests = generate_keda();
        assert!(!manifests.is_empty());
        assert!(manifests[0].contains("kind: Namespace"));
        assert!(
            manifests[0].contains("istio.io/dataplane-mode: ambient"),
            "KEDA namespace must be enrolled in ambient mesh for mTLS identity"
        );
    }

    #[test]
    fn keda_mesh_members() {
        let members = generate_keda_mesh_members();
        assert_eq!(members.len(), 3);

        // All must be in the keda namespace and pass validation
        for m in &members {
            assert_eq!(m.metadata.namespace.as_deref(), Some(KEDA_NAMESPACE));
            assert!(m.spec.validate().is_ok());
        }

        // metrics-apiserver
        let m = &members[0];
        assert_eq!(m.metadata.name.as_deref(), Some("keda-metrics-apiserver"));
        assert_eq!(m.spec.ports[0].port, 6443);
        assert_eq!(m.spec.ports[0].peer_auth, PeerAuth::Webhook);
        assert!(m.spec.allowed_callers.is_empty());
        assert_eq!(m.spec.dependencies[0].name, "keda-operator");

        // admission-webhooks
        let m = &members[1];
        assert_eq!(m.metadata.name.as_deref(), Some("keda-admission-webhooks"));
        assert_eq!(m.spec.ports[0].port, 9443);
        assert_eq!(m.spec.ports[0].peer_auth, PeerAuth::Webhook);

        // operator
        let m = &members[2];
        assert_eq!(m.metadata.name.as_deref(), Some("keda-operator"));
        assert_eq!(m.spec.ports[0].port, 9666);
        assert_eq!(m.spec.ports[0].peer_auth, PeerAuth::Strict);
        assert_eq!(m.spec.allowed_callers[0].name, "keda-metrics-apiserver");
        assert_eq!(m.spec.dependencies[0].name, VM_READ_TARGET_LMM_NAME);
        assert_eq!(
            m.spec.dependencies[0].namespace.as_deref(),
            Some(MONITORING_NAMESPACE)
        );
    }
}
