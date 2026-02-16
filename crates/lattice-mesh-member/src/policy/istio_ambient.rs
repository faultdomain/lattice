//! L7 policy compilation: Istio AuthorizationPolicy, ServiceEntry
//!
//! Generates mTLS identity-based access control using SPIFFE principals
//! within the Istio ambient mesh.
//!
//! ## Ztunnel-first enforcement model
//!
//! By default, policies are enforced by ztunnel directly (no waypoint in the traffic path).
//! A waypoint is only deployed for services that need L7 features (currently: external
//! outbound dependencies via ServiceEntry; future: rate limiting, header matching).
//!
//! ## Policy enforcement points
//!
//! - **Ztunnel-enforced** (`selector`): evaluated by ztunnel on the destination node.
//!   Uses the **container target port**. This is the default path.
//! - **Waypoint-enforced** (`targetRefs: Service`): evaluated by the waypoint proxy.
//!   Uses the K8s **service port**. Only used when the service has external dependencies.

use std::collections::BTreeMap;

use lattice_common::crd::derived_name;
use lattice_common::graph::{ActiveEdge, ServiceNode};
use lattice_common::kube_utils::ObjectMeta;
use lattice_common::mesh;
use lattice_common::policy::istio::{
    AuthorizationOperation, AuthorizationPolicy, AuthorizationPolicySpec, AuthorizationRule,
    AuthorizationSource, OperationSpec, PeerAuthentication, SourceSpec, TargetRef,
    WorkloadSelector,
};
use lattice_common::policy::service_entry::{ServiceEntry, ServiceEntryPort, ServiceEntrySpec};
use lattice_common::LABEL_NAME;

use super::PolicyCompiler;

impl<'a> PolicyCompiler<'a> {
    /// Compile an AuthorizationPolicy for inbound traffic.
    ///
    /// Always ztunnel-enforced (selector-based). Uses the node's custom selector
    /// labels if available, otherwise falls back to `LABEL_NAME`.
    /// If `allow_peer_traffic` is set on the node, adds own SPIFFE principal.
    pub(super) fn compile_inbound_policy(
        &self,
        service: &ServiceNode,
        namespace: &str,
        inbound_edges: &[ActiveEdge],
    ) -> Option<AuthorizationPolicy> {
        let has_infra_callers = self.has_infrastructure_callers(service, inbound_edges);

        if inbound_edges.is_empty() && !service.allow_peer_traffic && !has_infra_callers {
            return None;
        }

        let mut principals: Vec<String> = inbound_edges
            .iter()
            .filter_map(|edge| {
                let caller = self
                    .graph
                    .get_service(&edge.caller_namespace, &edge.caller_name)?;
                Some(mesh::trust_domain::principal(
                    &self.cluster_name,
                    &edge.caller_namespace,
                    caller.sa_name(),
                ))
            })
            .collect();

        // Add principals for infrastructure callers (e.g. vmagent) that are in
        // allowed_callers but don't participate in bilateral agreement edges.
        // Their CallerRef name is used directly as the service account name.
        self.add_infrastructure_caller_principals(service, inbound_edges, &mut principals);

        // If allow_peer_traffic, add own principal so pods can talk to each other
        if service.allow_peer_traffic {
            principals.push(mesh::trust_domain::principal(
                &self.cluster_name,
                namespace,
                service.sa_name(),
            ));
        }

        let ports: Vec<String> = service
            .ports
            .values()
            .map(|pm| pm.target_port.to_string())
            .collect();

        // Need both principals and ports to generate a meaningful policy
        if principals.is_empty() || ports.is_empty() {
            return None;
        }

        let match_labels = service.istio_match_labels();

        Some(AuthorizationPolicy::allow_to_workload(
            derived_name("allow-to-", &[namespace, &service.name]),
            namespace,
            match_labels,
            principals,
            ports,
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
            ObjectMeta::new(
                derived_name("allow-wp-to-", &[namespace, &service.name]),
                namespace,
            ),
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

        let caller_sa = self
            .graph
            .get_service(namespace, caller)
            .map(|n| n.sa_name().to_string())
            .unwrap_or_else(|| caller.to_string());

        AuthorizationPolicy::new(
            ObjectMeta::new(
                derived_name("allow-ext-", &[namespace, caller, &external_service.name]),
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
                                &caller_sa,
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

    /// Compile permissive mTLS policies for non-strict ports.
    ///
    /// - PeerAuthentication: STRICT default with PERMISSIVE overrides per port
    /// - AuthorizationPolicy: ALLOW with empty `from` (any plaintext caller)
    ///
    /// Both `Permissive` and `Webhook` ports need these Istio-level policies;
    /// the kube-apiserver restriction for `Webhook` is enforced at L4 by Cilium.
    pub(super) fn compile_permissive_policies(
        &self,
        service: &ServiceNode,
        namespace: &str,
    ) -> (Vec<PeerAuthentication>, Vec<AuthorizationPolicy>) {
        let non_strict_ports = service.all_non_strict_port_numbers();
        if non_strict_ports.is_empty() {
            return (vec![], vec![]);
        }

        let match_labels = service.istio_match_labels();

        let peer_auth = PeerAuthentication::with_permissive_ports(
            derived_name("permissive-", &[namespace, &service.name]),
            namespace,
            match_labels.clone(),
            &non_strict_ports,
        );

        let port_strings: Vec<String> = non_strict_ports.iter().map(|p| p.to_string()).collect();
        let auth_policy = AuthorizationPolicy::new(
            ObjectMeta::new(
                derived_name("allow-plaintext-", &[namespace, &service.name]),
                namespace,
            ),
            AuthorizationPolicySpec {
                target_refs: vec![],
                selector: Some(WorkloadSelector { match_labels }),
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![],
                    to: vec![AuthorizationOperation {
                        operation: OperationSpec {
                            ports: port_strings,
                            hosts: vec![],
                        },
                    }],
                }],
            },
        );

        (vec![peer_auth], vec![auth_policy])
    }

    /// Check if the service has infrastructure callers — allowed_callers that don't
    /// exist in the service graph. These are external components (e.g. vmagent) that
    /// bypass bilateral agreement. Graph services that failed bilateral agreement
    /// are NOT included (they must declare the outbound dep).
    pub(super) fn has_infrastructure_callers(
        &self,
        service: &ServiceNode,
        _inbound_edges: &[ActiveEdge],
    ) -> bool {
        service
            .allowed_callers
            .iter()
            .any(|(caller_ns, caller_name)| {
                self.graph.get_service(caller_ns, caller_name).is_none()
            })
    }

    /// Add SPIFFE principals for infrastructure callers that don't exist in the
    /// service graph. The CallerRef name is used directly as the service account
    /// name since these callers have no graph node.
    fn add_infrastructure_caller_principals(
        &self,
        service: &ServiceNode,
        _inbound_edges: &[ActiveEdge],
        principals: &mut Vec<String>,
    ) {
        for (caller_ns, caller_name) in &service.allowed_callers {
            if self.graph.get_service(caller_ns, caller_name).is_none() {
                principals.push(mesh::trust_domain::principal(
                    &self.cluster_name,
                    caller_ns,
                    caller_name,
                ));
            }
        }
    }
}
