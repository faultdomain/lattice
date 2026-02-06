//! L7 policy compilation: Istio AuthorizationPolicy, ServiceEntry
//!
//! Generates mTLS identity-based access control using SPIFFE principals
//! within the Istio ambient mesh.
//!
//! # Future: Trait Extraction
//!
//! These methods form the `L7Provider` trait interface:
//! ```ignore
//! trait L7Provider {
//!     fn compile_authorization_policy(&self, service: &ServiceNode, namespace: &str,
//!         inbound_edges: &[ActiveEdge]) -> Option<AuthorizationPolicy>;
//!     fn compile_waypoint_policy(&self, service: &ServiceNode, namespace: &str)
//!         -> Option<AuthorizationPolicy>;
//!     fn compile_service_entry(&self, service: &ServiceNode, namespace: &str)
//!         -> Option<ServiceEntry>;
//!     fn compile_external_access_policy(&self, caller: &str, external_service: &ServiceNode,
//!         namespace: &str) -> AuthorizationPolicy;
//!     fn compile_gateway_allow_policy(&self, service_name: &str, namespace: &str,
//!         ports: &[u16]) -> AuthorizationPolicy;
//! }
//! ```

use std::collections::BTreeMap;

use crate::graph::{ActiveEdge, ServiceNode};
use lattice_common::mesh;
use lattice_common::policy::{
    AuthorizationOperation, AuthorizationPolicy, AuthorizationPolicySpec, AuthorizationRule,
    AuthorizationSource, OperationSpec, PolicyMetadata, ServiceEntry, ServiceEntryPort,
    ServiceEntrySpec, SourceSpec, TargetRef, WorkloadSelector,
};
use lattice_common::LABEL_NAME;

use super::PolicyCompiler;

impl<'a> PolicyCompiler<'a> {
    /// Generate SPIFFE principal for AuthorizationPolicy
    pub(super) fn spiffe_principal(&self, namespace: &str, service_name: &str) -> String {
        mesh::trust_domain::principal(&self.cluster_name, namespace, service_name)
    }

    pub(super) fn waypoint_principal(&self, namespace: &str) -> String {
        mesh::trust_domain::waypoint_principal(&self.cluster_name, namespace)
    }

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
            .map(|edge| self.spiffe_principal(&edge.caller_namespace, &edge.caller_name))
            .collect();

        let ports: Vec<String> = service.ports.values().map(|p| p.to_string()).collect();

        if ports.is_empty() {
            return None;
        }

        Some(AuthorizationPolicy::new(
            PolicyMetadata::new(format!("allow-to-{}", service.name), namespace),
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

    pub(super) fn compile_waypoint_policy(
        &self,
        service: &ServiceNode,
        namespace: &str,
    ) -> Option<AuthorizationPolicy> {
        let ports: Vec<String> = service.ports.values().map(|p| p.to_string()).collect();

        if ports.is_empty() {
            return None;
        }

        let mut match_labels = BTreeMap::new();
        match_labels.insert(LABEL_NAME.to_string(), service.name.clone());

        Some(AuthorizationPolicy::new(
            PolicyMetadata::new(format!("allow-waypoint-to-{}", service.name), namespace),
            AuthorizationPolicySpec {
                target_refs: vec![],
                selector: Some(WorkloadSelector { match_labels }),
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![AuthorizationSource {
                        source: SourceSpec {
                            principals: vec![self.waypoint_principal(namespace)],
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

        let mut metadata = PolicyMetadata::new(&service.name, namespace);
        metadata.labels.insert(
            mesh::USE_WAYPOINT_LABEL.to_string(),
            mesh::waypoint_name(namespace),
        );

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
            PolicyMetadata::new(
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
                            principals: vec![self.spiffe_principal(namespace, caller)],
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

    /// Compile an AuthorizationPolicy to allow Envoy Gateway to reach a service
    pub fn compile_gateway_allow_policy(
        &self,
        service_name: &str,
        namespace: &str,
        ports: &[u16],
    ) -> AuthorizationPolicy {
        let gateway_principal = mesh::trust_domain::gateway_principal(&self.cluster_name);
        let port_strings: Vec<String> = ports.iter().map(|p| p.to_string()).collect();

        AuthorizationPolicy::new(
            PolicyMetadata::new(format!("allow-gateway-to-{}", service_name), namespace),
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
