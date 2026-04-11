//! Velero manifest generation
//!
//! Embeds pre-rendered Velero manifests from build time.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use lattice_common::LABEL_NAME;
use lattice_crd::crd::{LatticeMeshMember, LatticeMeshMemberSpec, MeshMemberTarget};

use super::{kube_apiserver_egress, lmm, namespace_yaml_ambient, split_yaml_documents};

static VELERO_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml_ambient("velero")];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/velero.yaml"
    ))));
    manifests
});

pub fn velero_version() -> &'static str {
    env!("VELERO_VERSION")
}

pub fn generate_velero() -> &'static [String] {
    &VELERO_MANIFESTS
}

/// Generate LatticeMeshMembers for Velero components.
///
/// - **velero**: backup controller, egress-only (K8s API + cloud storage)
pub fn generate_velero_mesh_members() -> Vec<LatticeMeshMember> {
    vec![lmm(
        "velero",
        "velero",
        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                LABEL_NAME.to_string(),
                "velero".to_string(),
            )])),
            ports: vec![],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: vec![kube_apiserver_egress()],
            allow_peer_traffic: false,
            ingress: None,
            service_account: Some("velero-server".to_string()),
            depends_all: false,
            ambient: true, advertise: None,
        },
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!velero_version().is_empty());
    }

    #[test]
    fn manifests_are_embedded() {
        let manifests = generate_velero();
        assert!(!manifests.is_empty());
        assert!(manifests[0].contains("kind: Namespace"));
        assert!(
            manifests[0].contains("istio.io/dataplane-mode: ambient"),
            "Velero namespace must be enrolled in ambient mesh"
        );
    }

    #[test]
    fn velero_mesh_members_generated() {
        let members = generate_velero_mesh_members();
        assert_eq!(members.len(), 1, "should have velero only");

        let v = &members[0];
        assert_eq!(v.metadata.name.as_deref(), Some("velero"));
        assert_eq!(v.metadata.namespace.as_deref(), Some("velero"));
        assert!(v.spec.validate().is_ok());
        assert!(v.spec.ambient, "velero should be ambient");
        assert!(v.spec.ports.is_empty(), "velero is egress-only");
        assert_eq!(v.spec.service_account.as_deref(), Some("velero-server"));
    }
}
