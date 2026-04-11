//! External Secrets Operator (ESO) manifest generation
//!
//! Embeds pre-rendered ESO manifests from build time.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use lattice_common::{LABEL_NAME, OPERATOR_NAME};
use lattice_core::LATTICE_SYSTEM_NAMESPACE;
use lattice_crd::crd::{
    LatticeMeshMember, LatticeMeshMemberSpec, MeshMemberPort, MeshMemberTarget, PeerAuth,
    ServiceRef,
};

use super::{kube_apiserver_egress, lmm, namespace_yaml_ambient, split_yaml_documents};

static ESO_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml_ambient("external-secrets")];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/external-secrets.yaml"
    ))));
    manifests
});

pub fn eso_version() -> &'static str {
    env!("EXTERNAL_SECRETS_VERSION")
}

pub fn generate_eso() -> &'static [String] {
    &ESO_MANIFESTS
}

/// Generate LatticeMeshMembers for ESO components.
///
/// - **external-secrets-webhook**: admission webhook called by kube-apiserver (port 10250, Webhook mTLS)
/// - **external-secrets**: main operator, egress-only (K8s API + secret store backends)
/// - **external-secrets-cert-controller**: cert management, egress-only (K8s API)
pub fn generate_eso_mesh_members() -> Vec<LatticeMeshMember> {
    vec![
        lmm(
            "external-secrets-webhook",
            "external-secrets",
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(BTreeMap::from([(
                    LABEL_NAME.to_string(),
                    "external-secrets-webhook".to_string(),
                )])),
                ports: vec![MeshMemberPort {
                    port: 10250,
                    service_port: None,
                    name: "webhook".to_string(),
                    peer_auth: PeerAuth::Webhook,
                }],
                allowed_callers: vec![],
                dependencies: vec![],
                egress: vec![kube_apiserver_egress()],
                allow_peer_traffic: false,
                ingress: None,
                service_account: None,
                depends_all: false,
                ambient: true, advertise: None,
            },
        ),
        lmm(
            "external-secrets",
            "external-secrets",
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(BTreeMap::from([(
                    LABEL_NAME.to_string(),
                    "external-secrets".to_string(),
                )])),
                ports: vec![],
                allowed_callers: vec![],
                dependencies: vec![ServiceRef::new(LATTICE_SYSTEM_NAMESPACE, OPERATOR_NAME)],
                egress: vec![kube_apiserver_egress()],
                allow_peer_traffic: false,
                ingress: None,
                service_account: None,
                depends_all: false,
                ambient: true, advertise: None,
            },
        ),
        lmm(
            "external-secrets-cert-controller",
            "external-secrets",
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(BTreeMap::from([(
                    LABEL_NAME.to_string(),
                    "external-secrets-cert-controller".to_string(),
                )])),
                ports: vec![],
                allowed_callers: vec![],
                dependencies: vec![],
                egress: vec![kube_apiserver_egress()],
                allow_peer_traffic: false,
                ingress: None,
                service_account: None,
                depends_all: false,
                ambient: true, advertise: None,
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!eso_version().is_empty());
    }

    #[test]
    fn manifests_are_embedded() {
        let manifests = generate_eso();
        assert!(!manifests.is_empty());
        assert!(manifests[0].contains("kind: Namespace"));
        assert!(
            manifests[0].contains("istio.io/dataplane-mode: ambient"),
            "ESO namespace must be enrolled in ambient mesh"
        );
    }

    #[test]
    fn eso_mesh_members_generated() {
        let members = generate_eso_mesh_members();
        assert_eq!(
            members.len(),
            3,
            "should have webhook + operator + cert-controller"
        );

        for m in &members {
            assert_eq!(m.metadata.namespace.as_deref(), Some("external-secrets"));
            assert!(m.spec.validate().is_ok());
            assert!(
                m.spec.ambient,
                "{} should be ambient",
                m.metadata.name.as_deref().unwrap()
            );
        }

        // webhook
        let wh = members
            .iter()
            .find(|m| m.metadata.name.as_deref() == Some("external-secrets-webhook"))
            .expect("webhook member should exist");
        assert_eq!(wh.spec.ports.len(), 1);
        assert_eq!(wh.spec.ports[0].port, 10250);
        assert_eq!(wh.spec.ports[0].peer_auth, PeerAuth::Webhook);

        // operator (bilateral dependency on lattice-operator for local-secrets webhook)
        let op = members
            .iter()
            .find(|m| m.metadata.name.as_deref() == Some("external-secrets"))
            .expect("operator member should exist");
        assert!(op.spec.ports.is_empty(), "operator is egress-only");
        assert_eq!(
            op.spec.egress.len(),
            1,
            "operator needs kube-apiserver egress"
        );
        assert_eq!(
            op.spec.dependencies.len(),
            1,
            "operator should depend on lattice-operator"
        );
        assert_eq!(op.spec.dependencies[0].name, "lattice-operator");
        assert_eq!(
            op.spec.dependencies[0].namespace.as_deref(),
            Some(LATTICE_SYSTEM_NAMESPACE)
        );

        // cert-controller (egress-only)
        let cc = members
            .iter()
            .find(|m| m.metadata.name.as_deref() == Some("external-secrets-cert-controller"))
            .expect("cert-controller member should exist");
        assert!(cc.spec.ports.is_empty(), "cert-controller is egress-only");
    }
}
