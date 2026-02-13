//! L7 policy compilation: Istio AuthorizationPolicy, ServiceEntry
//!
//! Generates mTLS identity-based access control using SPIFFE principals
//! within the Istio ambient mesh.
//!
//! ## Policy enforcement points
//!
//! - **Waypoint-enforced** (`targetRefs: Service`): evaluated by the waypoint proxy.
//!   Uses the K8s **service port** (what clients connect to).
//! - **Ztunnel-enforced** (`selector`): evaluated by ztunnel on the destination node.
//!   Uses the **container target port** (what the pod listens on after HBONE delivery).

use std::collections::BTreeMap;

use crate::graph::{ActiveEdge, ServiceNode};
use lattice_common::kube_utils::ObjectMeta;
use lattice_common::mesh;
use lattice_common::policy::{
    AuthorizationOperation, AuthorizationPolicy, AuthorizationPolicySpec, AuthorizationRule,
    AuthorizationSource, OperationSpec, ServiceEntry, ServiceEntryPort, ServiceEntrySpec,
    SourceSpec, TargetRef, WorkloadSelector,
};
use lattice_common::LABEL_NAME;

use super::PolicyCompiler;

impl<'a> PolicyCompiler<'a> {
    /// Compile a waypoint-enforced AuthorizationPolicy (caller → service).
    ///
    /// Uses `targetRefs` pointing at the K8s Service, so the waypoint evaluates
    /// this policy. Port matching uses the **service port**.
    pub(super) fn compile_authorization_policy(
        &self,
        service: &ServiceNode,
        namespace: &str,
        inbound_edges: &[ActiveEdge],
    ) -> Option<AuthorizationPolicy> {
        if inbound_edges.is_empty() {
            return None;
        }

        let principals: Vec<String> = inbound_edges
            .iter()
            .map(|edge| {
                mesh::trust_domain::principal(
                    &self.cluster_name,
                    &edge.caller_namespace,
                    &edge.caller_name,
                )
            })
            .collect();

        let ports: Vec<String> = service
            .ports
            .values()
            .map(|pm| pm.service_port.to_string())
            .collect();

        if ports.is_empty() {
            return None;
        }

        Some(AuthorizationPolicy::new(
            ObjectMeta::new(format!("allow-to-{}", service.name), namespace),
            AuthorizationPolicySpec {
                target_refs: vec![TargetRef {
                    group: String::new(),
                    kind: "Service".to_string(),
                    name: service.name.clone(),
                }],
                selector: None,
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![AuthorizationSource {
                        source: SourceSpec { principals },
                    }],
                    to: vec![AuthorizationOperation {
                        operation: OperationSpec {
                            ports,
                            hosts: vec![],
                        },
                    }],
                }],
            },
        ))
    }

    /// Compile a ztunnel-enforced AuthorizationPolicy (waypoint → pod).
    ///
    /// Uses `selector` matching the pod labels, so ztunnel evaluates this policy
    /// on the destination node. Port matching uses the **container target port**
    /// because ztunnel delivers traffic directly to the pod after HBONE decap.
    pub(super) fn compile_ztunnel_allow_policy(
        &self,
        service: &ServiceNode,
        namespace: &str,
    ) -> Option<AuthorizationPolicy> {
        let ports: Vec<String> = service
            .ports
            .values()
            .map(|pm| pm.target_port.to_string())
            .collect();

        if ports.is_empty() {
            return None;
        }

        let mut match_labels = BTreeMap::new();
        match_labels.insert(LABEL_NAME.to_string(), service.name.clone());

        Some(AuthorizationPolicy::new(
            ObjectMeta::new(format!("allow-waypoint-to-{}", service.name), namespace),
            AuthorizationPolicySpec {
                target_refs: vec![],
                selector: Some(WorkloadSelector { match_labels }),
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![AuthorizationSource {
                        source: SourceSpec {
                            principals: vec![mesh::trust_domain::waypoint_principal(
                                &self.cluster_name,
                                namespace,
                            )],
                        },
                    }],
                    to: vec![AuthorizationOperation {
                        operation: OperationSpec {
                            ports,
                            hosts: vec![],
                        },
                    }],
                }],
            },
        ))
    }

    pub(super) fn compile_service_entry(
        &self,
        service: &ServiceNode,
        namespace: &str,
    ) -> Option<ServiceEntry> {
        if service.endpoints.is_empty() {
            return None;
        }

        let hosts: Vec<String> = service
            .endpoints
            .values()
            .map(|ep| ep.host.clone())
            .collect();

        let ports: Vec<ServiceEntryPort> = service
            .endpoints
            .iter()
            .map(|(name, ep)| ServiceEntryPort {
                number: ep.port,
                name: name.clone(),
                protocol: ep.protocol.to_uppercase(),
            })
            .collect();

        let metadata = ObjectMeta::new(&service.name, namespace)
            .with_label(mesh::USE_WAYPOINT_LABEL, mesh::waypoint_name(namespace));

        let resolution = service
            .resolution
            .as_ref()
            .map(|r| r.to_istio_format())
            .unwrap_or("DNS")
            .to_string();

        Some(ServiceEntry::new(
            metadata,
            ServiceEntrySpec {
                hosts,
                ports,
                location: "MESH_EXTERNAL".to_string(),
                resolution,
            },
        ))
    }

    pub(super) fn compile_external_access_policy(
        &self,
        caller: &str,
        external_service: &ServiceNode,
        namespace: &str,
    ) -> AuthorizationPolicy {
        let ports: Vec<String> = external_service
            .endpoints
            .values()
            .map(|ep| ep.port.to_string())
            .collect();

        AuthorizationPolicy::new(
            ObjectMeta::new(
                format!("allow-{}-to-{}", caller, external_service.name),
                namespace,
            ),
            AuthorizationPolicySpec {
                target_refs: vec![TargetRef {
                    group: "networking.istio.io".to_string(),
                    kind: "ServiceEntry".to_string(),
                    name: external_service.name.clone(),
                }],
                selector: None,
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![AuthorizationSource {
                        source: SourceSpec {
                            principals: vec![mesh::trust_domain::principal(
                                &self.cluster_name,
                                namespace,
                                caller,
                            )],
                        },
                    }],
                    to: if ports.is_empty() {
                        vec![]
                    } else {
                        vec![AuthorizationOperation {
                            operation: OperationSpec {
                                ports,
                                hosts: vec![],
                            },
                        }]
                    },
                }],
            },
        )
    }

    /// Compile an AuthorizationPolicy to allow the Istio gateway proxy to reach a service
    pub(crate) fn compile_gateway_allow_policy(
        &self,
        service_name: &str,
        namespace: &str,
        ports: &[u16],
    ) -> AuthorizationPolicy {
        let gateway_principal =
            mesh::trust_domain::gateway_principal(&self.cluster_name, namespace);
        let port_strings: Vec<String> = ports.iter().map(|p| p.to_string()).collect();

        AuthorizationPolicy::new(
            ObjectMeta::new(format!("allow-gateway-to-{}", service_name), namespace),
            AuthorizationPolicySpec {
                target_refs: vec![TargetRef {
                    group: String::new(),
                    kind: "Service".to_string(),
                    name: service_name.to_string(),
                }],
                selector: None,
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![AuthorizationSource {
                        source: SourceSpec {
                            principals: vec![gateway_principal],
                        },
                    }],
                    to: if port_strings.is_empty() {
                        vec![]
                    } else {
                        vec![AuthorizationOperation {
                            operation: OperationSpec {
                                ports: port_strings,
                                hosts: vec![],
                            },
                        }]
                    },
                }],
            },
        )
    }
}
