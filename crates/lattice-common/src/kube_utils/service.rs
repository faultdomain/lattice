//! Kubernetes Service and ServiceAccount construction utilities.

use std::collections::BTreeMap;

/// Build the cell LoadBalancer Service object with all required ports and selectors.
///
/// This is the single source of truth for the cell service definition, used by
/// both operator startup and cluster controller reconciliation.
///
/// The service routes traffic only to the leader pod via label selector, exposes
/// all 4 cell ports (bootstrap, gRPC, proxy, auth-proxy), and includes
/// cloud-specific LoadBalancer annotations.
pub fn build_cell_service(
    bootstrap_port: u16,
    grpc_port: u16,
    proxy_port: u16,
    provider_type: &crate::crd::ProviderType,
) -> k8s_openapi::api::core::v1::Service {
    use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

    let auth_proxy_port = crate::DEFAULT_AUTH_PROXY_PORT;

    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "lattice-operator".to_string());

    // Selector requires both the app label AND the leader label.
    // Only the leader pod will have lattice.dev/leader=true.
    let mut selector = BTreeMap::new();
    selector.insert("app".to_string(), "lattice-operator".to_string());
    selector.insert(
        crate::leader_election::LEADER_LABEL_KEY.to_string(),
        crate::leader_election::LEADER_LABEL_VALUE.to_string(),
    );

    let annotations = provider_type.load_balancer_annotations();

    Service {
        metadata: kube::core::ObjectMeta {
            name: Some(crate::CELL_SERVICE_NAME.to_string()),
            namespace: Some(lattice_core::LATTICE_SYSTEM_NAMESPACE.to_string()),
            labels: Some(labels),
            annotations: if annotations.is_empty() {
                None
            } else {
                Some(annotations)
            },
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            type_: Some("LoadBalancer".to_string()),
            selector: Some(selector),
            ports: Some(vec![
                ServicePort {
                    name: Some("bootstrap".to_string()),
                    port: bootstrap_port as i32,
                    target_port: Some(IntOrString::Int(bootstrap_port as i32)),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                },
                ServicePort {
                    name: Some("grpc".to_string()),
                    port: grpc_port as i32,
                    target_port: Some(IntOrString::Int(grpc_port as i32)),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                },
                ServicePort {
                    name: Some("proxy".to_string()),
                    port: proxy_port as i32,
                    target_port: Some(IntOrString::Int(proxy_port as i32)),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                },
                ServicePort {
                    name: Some("auth-proxy".to_string()),
                    port: auth_proxy_port as i32,
                    target_port: Some(IntOrString::Int(auth_proxy_port as i32)),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Compile a minimal ServiceAccount JSON for server-side apply.
///
/// Produces a JSON value with `automountServiceAccountToken: false` and
/// standard metadata. Callers can extend the result (e.g., add ownerReferences).
pub fn compile_service_account(name: &str, namespace: &str) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {
            "name": name,
            "namespace": namespace
        },
        "automountServiceAccountToken": false
    })
}
