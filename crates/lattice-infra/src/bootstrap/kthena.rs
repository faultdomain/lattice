//! Kthena Helm chart embedding for disaggregated model serving
//!
//! Provides pre-rendered Kthena manifests for model serving workloads.
//! Kthena is always installed as core infrastructure (required for LatticeModel).

use std::collections::BTreeMap;
use std::sync::LazyLock;

use lattice_common::{
    KTHENA_AUTOSCALER_SA, KTHENA_CONTROLLER_MANAGER_SA, KTHENA_NAMESPACE, KTHENA_ROUTER_SA,
};
use lattice_crd::crd::{
    LatticeMeshMember, LatticeMeshMemberSpec, MeshMemberPort, MeshMemberTarget, PeerAuth,
    ServiceRef,
};

use super::{kube_apiserver_egress, lmm, namespace_yaml_ambient, split_yaml_documents};

static KTHENA_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml_ambient("kthena-system")];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/kthena.yaml"
    ))));
    manifests
});

pub fn kthena_version() -> &'static str {
    env!("KTHENA_VERSION")
}

/// Pre-rendered Kthena Helm chart manifests
pub fn generate_kthena() -> &'static [String] {
    &KTHENA_MANIFESTS
}

/// Generate LatticeMeshMembers for all kthena components.
///
/// kthena-router: `depends_all: true` (outbound to models) + `allowed_callers: [*]`
/// (any service can send inference requests). Port 80 is the router's HTTP service port.
///
/// kthena-controller-manager: webhook port 8443 with `PeerAuth::Webhook` so the
/// API server can reach admission webhooks through ztunnel without mTLS.
///
/// kthena-autoscaler: `depends_all: true` (outbound to model metrics).
///
/// All are `ambient: true` for real SPIFFE identities and mTLS bilateral agreement.
pub fn generate_kthena_mesh_members() -> Vec<LatticeMeshMember> {
    vec![
        lmm(
            "kthena-router",
            KTHENA_NAMESPACE,
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(BTreeMap::from([(
                    "app.kubernetes.io/component".to_string(),
                    "kthena-router".to_string(),
                )])),
                ports: vec![
                    MeshMemberPort {
                        port: 8080,
                        service_port: Some(80),
                        name: "http".to_string(),
                        peer_auth: PeerAuth::Strict,
                    },
                    MeshMemberPort {
                        port: 8443,
                        service_port: Some(443),
                        name: "webhook".to_string(),
                        peer_auth: PeerAuth::Webhook,
                    },
                ],
                allowed_callers: vec![ServiceRef::local("*")],
                dependencies: vec![],
                egress: vec![kube_apiserver_egress()],
                allow_peer_traffic: false,
                depends_all: true,
                ingress: None,
                service_account: Some(KTHENA_ROUTER_SA.to_string()),
                ambient: true, advertise: None,
            },
        ),
        lmm(
            "kthena-controller-manager",
            KTHENA_NAMESPACE,
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(BTreeMap::from([(
                    "app.kubernetes.io/component".to_string(),
                    "kthena-controller-manager".to_string(),
                )])),
                ports: vec![MeshMemberPort {
                    port: 8443,
                    service_port: None,
                    name: "webhook".to_string(),
                    peer_auth: PeerAuth::Webhook,
                }],
                allowed_callers: vec![],
                dependencies: vec![],
                egress: vec![kube_apiserver_egress()],
                allow_peer_traffic: false,
                depends_all: false,
                ingress: None,
                service_account: Some(KTHENA_CONTROLLER_MANAGER_SA.to_string()),
                ambient: true, advertise: None,
            },
        ),
        lmm(
            "kthena-autoscaler",
            KTHENA_NAMESPACE,
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(BTreeMap::from([(
                    "app.kubernetes.io/component".to_string(),
                    "kthena-autoscaler".to_string(),
                )])),
                ports: vec![],
                allowed_callers: vec![],
                dependencies: vec![],
                egress: vec![kube_apiserver_egress()],
                allow_peer_traffic: false,
                depends_all: true,
                ingress: None,
                service_account: Some(KTHENA_AUTOSCALER_SA.to_string()),
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
        assert!(!kthena_version().is_empty());
    }

    #[test]
    fn manifests_are_embedded() {
        let m = generate_kthena();
        assert!(!m.is_empty());
    }

    #[test]
    fn namespace_is_first_manifest() {
        let m = generate_kthena();
        assert!(
            m[0].contains("kthena-system"),
            "First manifest should create the kthena-system namespace"
        );
    }

    #[test]
    fn kthena_mesh_members_generated() {
        let members = generate_kthena_mesh_members();
        assert_eq!(
            members.len(),
            3,
            "should have router + controller-manager + autoscaler"
        );

        let router = members
            .iter()
            .find(|m| m.metadata.name.as_deref() == Some("kthena-router"))
            .expect("kthena-router member should exist");
        assert!(router.spec.depends_all, "router should have depends_all");
        assert!(router.spec.ambient, "router should be ambient");
        assert_eq!(
            router.spec.service_account.as_deref(),
            Some(KTHENA_ROUTER_SA)
        );
        assert_eq!(
            router.spec.ports.len(),
            2,
            "router should expose http + webhook"
        );
        assert_eq!(router.spec.ports[0].port, 8080);
        assert_eq!(router.spec.ports[0].service_port, Some(80));
        assert_eq!(router.spec.ports[0].name, "http");
        assert_eq!(router.spec.ports[0].peer_auth, PeerAuth::Strict);
        assert_eq!(router.spec.ports[1].port, 8443);
        assert_eq!(router.spec.ports[1].service_port, Some(443));
        assert_eq!(router.spec.ports[1].name, "webhook");
        assert_eq!(router.spec.ports[1].peer_auth, PeerAuth::Webhook);
        assert_eq!(
            router.spec.allowed_callers.len(),
            1,
            "router should allow all callers"
        );
        assert_eq!(router.spec.allowed_callers[0].name, "*");

        let cm = members
            .iter()
            .find(|m| m.metadata.name.as_deref() == Some("kthena-controller-manager"))
            .expect("kthena-controller-manager member should exist");
        assert!(
            !cm.spec.depends_all,
            "controller-manager has no outbound deps"
        );
        assert!(cm.spec.ambient, "controller-manager should be ambient");
        assert_eq!(
            cm.spec.service_account.as_deref(),
            Some(KTHENA_CONTROLLER_MANAGER_SA)
        );
        assert_eq!(cm.spec.ports.len(), 1, "should expose webhook port");
        assert_eq!(cm.spec.ports[0].port, 8443);
        assert_eq!(cm.spec.ports[0].peer_auth, PeerAuth::Webhook);

        let autoscaler = members
            .iter()
            .find(|m| m.metadata.name.as_deref() == Some("kthena-autoscaler"))
            .expect("kthena-autoscaler member should exist");
        assert!(
            autoscaler.spec.depends_all,
            "autoscaler should have depends_all"
        );
        assert!(autoscaler.spec.ambient, "autoscaler should be ambient");
        assert_eq!(
            autoscaler.spec.service_account.as_deref(),
            Some(KTHENA_AUTOSCALER_SA)
        );
    }
}
