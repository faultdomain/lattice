//! Mesh member generation for LatticePackage
//!
//! Converts `PackageMeshConfig` into a `LatticeMeshMember` CR that the
//! mesh-member controller reconciles into Cilium + Istio policies.

use lattice_crd::crd::{
    LatticeMeshMember, LatticeMeshMemberSpec, MeshMemberPort, MeshMemberTarget, PackageMeshConfig,
    PeerAuth,
};

/// Build a `LatticeMeshMember` from a package's mesh config.
///
/// The generated member targets pods by the selector labels and exposes
/// the declared ports with bilateral agreement rules.
pub fn build_mesh_member(
    package_name: &str,
    namespace: &str,
    mesh: &PackageMeshConfig,
) -> LatticeMeshMember {
    let ports: Vec<MeshMemberPort> = mesh
        .ports
        .iter()
        .map(|p| MeshMemberPort {
            port: p.port,
            service_port: None,
            name: p.name.clone(),
            peer_auth: PeerAuth::default(),
        })
        .collect();

    let spec = LatticeMeshMemberSpec {
        target: MeshMemberTarget::Selector(mesh.selector.clone()),
        ports,
        allowed_callers: mesh.allowed_callers.clone(),
        dependencies: mesh.dependencies.clone(),
        egress: mesh.egress.clone(),
        allow_peer_traffic: false,
        depends_all: false,
        ingress: None,
        service_account: None,
        ambient: true, advertise: None,
    };

    let mut member = LatticeMeshMember::new(package_name, spec);
    member.metadata.namespace = Some(namespace.to_string());
    // Label with owning package for cleanup
    member
        .metadata
        .labels
        .get_or_insert_with(Default::default)
        .insert(
            lattice_common::LABEL_SERVICE_OWNER.to_string(),
            package_name.to_string(),
        );
    member
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use lattice_crd::crd::{PackageMeshPort, ServiceRef};

    #[test]
    fn builds_mesh_member_from_config() {
        let mesh = PackageMeshConfig {
            selector: BTreeMap::from([("app".to_string(), "redis".to_string())]),
            ports: vec![PackageMeshPort {
                name: "redis".to_string(),
                port: 6379,
                protocol: "TCP".to_string(),
            }],
            allowed_callers: vec![ServiceRef::local("checkout")],
            dependencies: vec![],
            egress: vec![],
        };

        let member = build_mesh_member("redis-prod", "payments", &mesh);

        assert_eq!(member.metadata.namespace, Some("payments".to_string()));
        assert_eq!(member.spec.ports.len(), 1);
        assert_eq!(member.spec.ports[0].port, 6379);
        assert_eq!(member.spec.allowed_callers.len(), 1);
        assert!(member.spec.ambient);
        match &member.spec.target {
            MeshMemberTarget::Selector(labels) => {
                assert_eq!(labels.get("app"), Some(&"redis".to_string()));
            }
            _ => panic!("expected Selector target"),
        }
    }

    #[test]
    fn includes_egress_rules() {
        use lattice_crd::crd::{EgressRule, EgressTarget, NetworkProtocol};

        let mesh = PackageMeshConfig {
            selector: BTreeMap::from([("app".to_string(), "redis".to_string())]),
            ports: vec![],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: vec![EgressRule {
                target: EgressTarget::Fqdn("sentinel.external.com".to_string()),
                ports: vec![26379],
                protocol: NetworkProtocol::Tcp,
            }],
        };

        let member = build_mesh_member("redis-prod", "payments", &mesh);
        assert_eq!(member.spec.egress.len(), 1);
        assert_eq!(member.spec.egress[0].ports, vec![26379]);
    }
}
