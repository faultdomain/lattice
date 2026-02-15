//! VictoriaMetrics K8s Stack manifest generation
//!
//! Embeds pre-rendered VictoriaMetrics manifests from build time.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use lattice_common::crd::{
    CallerRef, LatticeMeshMember, LatticeMeshMemberSpec, MeshMemberPort, MeshMemberTarget,
    PeerAuth, ServiceRef,
};

use super::keda::{KEDA_NAMESPACE, VM_READ_TARGET_LMM_NAME};
use super::{lmm, namespace_yaml_ambient, split_yaml_documents};

/// Well-known service name for the VMCluster components.
/// Used as `fullnameOverride` so all downstream consumers
/// reference a stable integration point.
pub const VMCLUSTER_NAME: &str = "lattice-metrics";

/// Namespace for monitoring components.
pub const MONITORING_NAMESPACE: &str = "monitoring";

/// VMAgent service account name (derived from chart fullnameOverride).
/// Used to construct SPIFFE identity for AuthorizationPolicy.
pub const VMAGENT_SERVICE_ACCOUNT: &str = "vmagent-lattice-metrics";

/// VMSelect query port (Prometheus-compatible read path, HA mode).
pub const VMSELECT_PORT: u16 = 8481;

/// VMSelect URL path prefix for Prometheus-compatible queries (HA mode).
pub const VMSELECT_PATH: &str = "/select/0/prometheus";

/// VMInsert write port (HA mode).
pub const VMINSERT_PORT: u16 = 8480;

/// VMSingle query port (Prometheus-compatible read path, single-node mode).
pub const VMSINGLE_PORT: u16 = 8428;

/// VMSingle URL path prefix for Prometheus-compatible queries (single-node mode).
pub const VMSINGLE_PATH: &str = "/prometheus";

/// Build the VMSelect service URL from well-known constants (HA mode).
pub fn vmselect_url() -> String {
    format!(
        "http://vmselect-{}.{}.svc",
        VMCLUSTER_NAME, MONITORING_NAMESPACE
    )
}

/// Build the VMSingle service URL from well-known constants (single-node mode).
pub fn vmsingle_url() -> String {
    format!(
        "http://vmsingle-{}.{}.svc",
        VMCLUSTER_NAME, MONITORING_NAMESPACE
    )
}

/// Return the Prometheus-compatible query port for the given HA mode.
pub fn query_port(ha: bool) -> u16 {
    if ha {
        VMSELECT_PORT
    } else {
        VMSINGLE_PORT
    }
}

/// Return the Prometheus-compatible query path for the given HA mode.
pub fn query_path(ha: bool) -> &'static str {
    if ha {
        VMSELECT_PATH
    } else {
        VMSINGLE_PATH
    }
}

/// Return the full Prometheus-compatible query base URL for the given HA mode.
pub fn query_url(ha: bool) -> String {
    if ha {
        vmselect_url()
    } else {
        vmsingle_url()
    }
}

/// Pre-rendered VictoriaMetrics HA manifests with namespace prepended.
static PROMETHEUS_HA_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml_ambient(MONITORING_NAMESPACE)];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/victoria-metrics-ha.yaml"
    ))));
    manifests
});

/// Pre-rendered VictoriaMetrics single-node manifests with namespace prepended.
static PROMETHEUS_SINGLE_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml_ambient(MONITORING_NAMESPACE)];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/victoria-metrics-single.yaml"
    ))));
    manifests
});

/// VictoriaMetrics K8s Stack version (pinned at build time)
pub fn victoria_metrics_version() -> &'static str {
    env!("VICTORIA_METRICS_VERSION")
}

/// Generate VictoriaMetrics K8s Stack manifests.
///
/// When `ha` is true, returns the HA VMCluster manifests (2 replicas each).
/// When `ha` is false, returns the single-node VMSingle manifests.
pub fn generate_prometheus(ha: bool) -> &'static [String] {
    if ha {
        &PROMETHEUS_HA_MANIFESTS
    } else {
        &PROMETHEUS_SINGLE_MANIFESTS
    }
}

/// Build VM component label selector.
fn vm_instance_labels(component: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("app.kubernetes.io/name".to_string(), component.to_string()),
        (
            "app.kubernetes.io/instance".to_string(),
            VMCLUSTER_NAME.to_string(),
        ),
    ])
}

/// Generate LatticeMeshMember CRDs for monitoring components.
///
/// Produces LMMs for:
/// - **VM write target** (vmsingle or vminsert) — receives scraped metrics from vmagent
/// - **VM read target** (vmsingle or vmselect) — queried by KEDA for autoscaling
/// - **vmagent** — scrapes targets and pushes to VM storage
/// - **victoria-metrics-operator** — webhook called by kube-apiserver
///
/// In single-node mode, write and read targets are the same workload (vmsingle),
/// so they are merged into a single LMM with both callers.
pub fn generate_monitoring_mesh_members(ha: bool) -> Vec<LatticeMeshMember> {
    let mut members = Vec::new();

    let vmagent_caller = CallerRef {
        name: "vmagent".to_string(),
        namespace: Some(MONITORING_NAMESPACE.to_string()),
    };

    let keda_caller = CallerRef {
        name: "keda-operator".to_string(),
        namespace: Some(KEDA_NAMESPACE.to_string()),
    };

    if ha {
        // HA mode: separate write (vminsert) and read (vmselect) targets
        members.push(lmm(
            "vm-write-target",
            MONITORING_NAMESPACE,
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(vm_instance_labels("vminsert")),
                ports: vec![MeshMemberPort {
                    port: VMINSERT_PORT,
                    name: "write".to_string(),
                    peer_auth: PeerAuth::Strict,
                }],
                allowed_callers: vec![vmagent_caller],
                dependencies: vec![],
                egress: vec![],
                allow_peer_traffic: false,
                ingress: None,
            },
        ));

        members.push(lmm(
            VM_READ_TARGET_LMM_NAME,
            MONITORING_NAMESPACE,
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(vm_instance_labels("vmselect")),
                ports: vec![MeshMemberPort {
                    port: VMSELECT_PORT,
                    name: "read".to_string(),
                    peer_auth: PeerAuth::Strict,
                }],
                allowed_callers: vec![keda_caller],
                dependencies: vec![],
                egress: vec![],
                allow_peer_traffic: false,
                ingress: None,
            },
        ));
    } else {
        // Single-node mode: vmsingle serves both write and read
        members.push(lmm(
            VM_READ_TARGET_LMM_NAME,
            MONITORING_NAMESPACE,
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(vm_instance_labels("vmsingle")),
                ports: vec![MeshMemberPort {
                    port: VMSINGLE_PORT,
                    name: "http".to_string(),
                    peer_auth: PeerAuth::Strict,
                }],
                allowed_callers: vec![vmagent_caller, keda_caller],
                dependencies: vec![],
                egress: vec![],
                allow_peer_traffic: false,
                ingress: None,
            },
        ));
    }

    // vmagent — scrapes targets and writes to VM storage
    let write_dep = if ha {
        ServiceRef::new(MONITORING_NAMESPACE, "vm-write-target")
    } else {
        ServiceRef::new(MONITORING_NAMESPACE, VM_READ_TARGET_LMM_NAME)
    };
    members.push(lmm(
        "vmagent",
        MONITORING_NAMESPACE,
        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(vm_instance_labels("vmagent")),
            ports: vec![MeshMemberPort {
                port: 8429,
                name: "http".to_string(),
                peer_auth: PeerAuth::Strict,
            }],
            allowed_callers: vec![],
            dependencies: vec![write_dep],
            egress: vec![],
            allow_peer_traffic: false,
            ingress: None,
        },
    ));

    // victoria-metrics-operator — webhook called by kube-apiserver
    members.push(lmm(
        "victoria-metrics-operator",
        MONITORING_NAMESPACE,
        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                "app.kubernetes.io/name".to_string(),
                "victoria-metrics-operator".to_string(),
            )])),
            ports: vec![MeshMemberPort {
                port: 9443,
                name: "webhook".to_string(),
                peer_auth: PeerAuth::Permissive,
            }],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: vec![],
            allow_peer_traffic: false,
            ingress: None,
        },
    ));

    members
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        let version = victoria_metrics_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn test_namespace_is_correct() {
        let ns = namespace_yaml_ambient("monitoring");
        assert!(ns.contains("kind: Namespace"));
        assert!(ns.contains("name: monitoring"));
        assert!(ns.contains("istio.io/dataplane-mode: ambient"));
    }

    #[test]
    fn ha_manifests_are_embedded() {
        let manifests = generate_prometheus(true);
        assert!(!manifests.is_empty());
        assert!(manifests[0].contains("kind: Namespace"));
        assert!(manifests[0].contains("istio.io/dataplane-mode: ambient"));
    }

    #[test]
    fn single_manifests_are_embedded() {
        let manifests = generate_prometheus(false);
        assert!(!manifests.is_empty());
        assert!(manifests[0].contains("kind: Namespace"));
        assert!(manifests[0].contains("istio.io/dataplane-mode: ambient"));
    }

    #[test]
    fn query_helpers_return_correct_values() {
        assert_eq!(query_port(true), VMSELECT_PORT);
        assert_eq!(query_port(false), VMSINGLE_PORT);
        assert_eq!(query_path(true), VMSELECT_PATH);
        assert_eq!(query_path(false), VMSINGLE_PATH);
        assert!(query_url(true).contains("vmselect"));
        assert!(query_url(false).contains("vmsingle"));
    }

    #[test]
    fn monitoring_mesh_members_single_node() {
        let members = generate_monitoring_mesh_members(false);
        // single-node: 1 merged vmsingle + 1 vmagent + 1 vm-operator = 3
        assert_eq!(members.len(), 3);

        // vmsingle (merged read+write target)
        let single = &members[0];
        assert_eq!(single.metadata.name.as_deref(), Some(VM_READ_TARGET_LMM_NAME));
        assert_eq!(single.metadata.namespace.as_deref(), Some(MONITORING_NAMESPACE));
        assert_eq!(single.spec.ports[0].port, VMSINGLE_PORT);
        assert_eq!(single.spec.ports[0].peer_auth, PeerAuth::Strict);
        assert_eq!(single.spec.allowed_callers.len(), 2); // vmagent + keda
        assert!(single.spec.validate().is_ok());

        // vmagent
        let agent = &members[1];
        assert_eq!(agent.metadata.name.as_deref(), Some("vmagent"));
        assert_eq!(agent.spec.dependencies[0].name, VM_READ_TARGET_LMM_NAME);
        assert!(agent.spec.validate().is_ok());

        // vm-operator webhook
        let op = &members[2];
        assert_eq!(op.metadata.name.as_deref(), Some("victoria-metrics-operator"));
        assert_eq!(op.spec.ports[0].port, 9443);
        assert_eq!(op.spec.ports[0].peer_auth, PeerAuth::Permissive);
        assert!(op.spec.allowed_callers.is_empty());
        assert!(op.spec.validate().is_ok());
    }

    #[test]
    fn monitoring_mesh_members_ha() {
        let members = generate_monitoring_mesh_members(true);
        // HA: 1 vminsert + 1 vmselect + 1 vmagent + 1 vm-operator = 4
        assert_eq!(members.len(), 4);

        let write = &members[0];
        assert_eq!(write.metadata.name.as_deref(), Some("vm-write-target"));
        assert_eq!(write.spec.ports[0].port, VMINSERT_PORT);
        assert_eq!(write.spec.allowed_callers[0].name, "vmagent");

        let read = &members[1];
        assert_eq!(read.metadata.name.as_deref(), Some(VM_READ_TARGET_LMM_NAME));
        assert_eq!(read.spec.ports[0].port, VMSELECT_PORT);

        let agent = &members[2];
        assert_eq!(agent.metadata.name.as_deref(), Some("vmagent"));
        assert_eq!(agent.spec.dependencies[0].name, "vm-write-target");

        let op = &members[3];
        assert_eq!(op.metadata.name.as_deref(), Some("victoria-metrics-operator"));

        for m in &members {
            assert!(m.spec.validate().is_ok());
        }
    }
}
