//! East-west gateway and multi-cluster infrastructure for Istio ambient.
//!
//! Generates:
//! - East-west Gateway (HBONE port 15008, `istio-east-west` class)
//! - Dedicated ServiceAccount + RBAC for istiod remote secret proxy access
//!   (loaded from `manifests/` directory)

use lattice_common::mesh::HBONE_PORT;

use super::split_yaml_documents;

/// Static SA manifest for the istiod proxy identity.
static ISTIOD_PROXY_SA: &str = include_str!("../../manifests/istiod-proxy-sa.yaml");

/// Static RBAC manifests (ClusterRole + ClusterRoleBinding) for istiod proxy.
static ISTIOD_PROXY_RBAC: &str = include_str!("../../manifests/istiod-proxy-rbac.yaml");

/// Generate the east-west Gateway resource for cross-cluster traffic.
pub fn generate_eastwest_gateway(cluster_name: &str) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": {
            "name": "istio-eastwestgateway",
            "namespace": "istio-system",
            "labels": {
                "topology.istio.io/network": cluster_name,
                "app.kubernetes.io/managed-by": "lattice"
            }
        },
        "spec": {
            "gatewayClassName": "istio-east-west",
            "listeners": [{
                "name": "mesh",
                "port": HBONE_PORT,
                "protocol": "HBONE",
                "tls": {
                    "mode": "Terminate",
                    "options": {
                        "gateway.istio.io/tls-terminate-mode": "ISTIO_MUTUAL"
                    }
                }
            }]
        }
    }))
    .expect("serialize eastwest gateway")
}

/// Load ServiceAccount + RBAC manifests for the istiod proxy identity.
pub fn generate_istiod_proxy_rbac() -> Vec<String> {
    let mut manifests = split_yaml_documents(ISTIOD_PROXY_SA);
    manifests.extend(split_yaml_documents(ISTIOD_PROXY_RBAC));
    manifests
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eastwest_gateway() {
        let manifest = generate_eastwest_gateway("workload-1");
        let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();

        assert_eq!(parsed["metadata"]["name"], "istio-eastwestgateway");
        assert_eq!(
            parsed["metadata"]["labels"]["topology.istio.io/network"],
            "workload-1"
        );
        assert_eq!(parsed["spec"]["gatewayClassName"], "istio-east-west");
        assert_eq!(parsed["spec"]["listeners"][0]["port"], HBONE_PORT);
        assert_eq!(parsed["spec"]["listeners"][0]["protocol"], "HBONE");
        assert_eq!(
            parsed["spec"]["listeners"][0]["tls"]["options"]["gateway.istio.io/tls-terminate-mode"],
            "ISTIO_MUTUAL"
        );
    }

    #[test]
    fn test_istiod_proxy_rbac_loads() {
        let manifests = generate_istiod_proxy_rbac();
        assert_eq!(manifests.len(), 3, "SA + ClusterRole + ClusterRoleBinding");
        let combined = manifests.join("\n");
        assert!(combined.contains("kind: ServiceAccount"));
        assert!(combined.contains("lattice-istiod-proxy"));
        assert!(combined.contains("kind: ClusterRole"));
        assert!(combined.contains("endpointslices"));
        assert!(combined.contains("kind: ClusterRoleBinding"));
    }
}
