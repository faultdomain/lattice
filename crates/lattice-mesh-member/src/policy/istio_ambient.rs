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
use lattice_common::crd::NetworkProtocol;
use lattice_common::graph::{ActiveEdge, ServiceNode};
use lattice_common::kube_utils::ObjectMeta;
use lattice_common::mesh;
use lattice_common::policy::istio::{
    AuthorizationOperation, AuthorizationPolicy, AuthorizationPolicySpec, AuthorizationRule,
    AuthorizationSource, OperationSpec, PeerAuthentication, SourceSpec, TargetRef,
    WorkloadSelector,
};
use lattice_common::policy::service_entry::{
    ServiceEntry, ServiceEntryEndpoint, ServiceEntryPort, ServiceEntrySpec,
};
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
        if inbound_edges.is_empty() && !service.allow_peer_traffic && !service.advertised_open {
            return None;
        }

        let mut principals: Vec<String> = inbound_edges
            .iter()
            .filter_map(|edge| {
                let caller = self
                    .graph
                    .get_service(&edge.caller_namespace, &edge.caller_name)?;
                Some(lattice_core::trust_domain::principal(
                    self.graph.trust_domain(),
                    &edge.caller_namespace,
                    caller.sa_name(),
                ))
            })
            .collect();

        // If allow_peer_traffic, add own principal so pods can talk to each other
        if service.allow_peer_traffic {
            principals.push(lattice_core::trust_domain::principal(
                self.graph.trust_domain(),
                namespace,
                service.sa_name(),
            ));
        }

        let ports: Vec<String> = service
            .ports
            .values()
            .map(|pm| pm.target_port.to_string())
            .collect();

        // Advertised services with open callers allow any authenticated identity.
        // Cross-cluster callers arrive via the east-west gateway with their original
        // SPIFFE identity — we can't enumerate them, so allow from any source.
        // Uses empty `from` (omitted in serialization) = any authenticated caller.
        if service.advertised_open {
            let match_labels = service.istio_match_labels();
            return Some(AuthorizationPolicy::new(
                ObjectMeta::new(
                    derived_name("allow-to-", &[namespace, &service.name]),
                    namespace,
                ),
                AuthorizationPolicySpec {
                    target_refs: vec![],
                    selector: Some(WorkloadSelector { match_labels }),
                    action: "ALLOW".to_string(),
                    rules: vec![AuthorizationRule {
                        from: vec![], // omitted = any authenticated source
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
            ));
        }

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
                            principals: vec![lattice_common::mesh::trust_domain::waypoint_principal(
                                self.graph.trust_domain(),
                                namespace,
                            )],
                            not_principals: vec![],
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

    /// Compile a ServiceEntry for an egress target (FQDN or IP).
    ///
    /// ServiceEntry names are derived from (namespace, host) only — NOT per-service.
    /// This ensures one ServiceEntry per unique host per namespace, preventing Istio
    /// from merging duplicate hosts and losing AuthorizationPolicy targetRef bindings.
    /// Each service creates its own AuthorizationPolicy targeting the shared SE.
    ///
    /// For IPs: uses `resolution: STATIC` with explicit endpoints (Istio rejects
    /// bare IPs with DNS resolution). For FQDNs: uses `resolution: DNS`.
    pub(super) fn compile_egress_service_entry(
        &self,
        namespace: &str,
        host: &str,
        ports: &[u16],
        is_ip: bool,
        network_protocol: &NetworkProtocol,
    ) -> ServiceEntry {
        let se_ports: Vec<ServiceEntryPort> = ports
            .iter()
            .map(|&p| {
                let protocol = match network_protocol {
                    NetworkProtocol::Udp => "UDP",
                    NetworkProtocol::Tcp | _ => match p {
                        443 => "HTTPS",
                        80 => "HTTP",
                        _ => "TCP",
                    },
                };
                ServiceEntryPort {
                    number: p,
                    name: format!("{}-{}", protocol.to_lowercase(), p),
                    protocol: protocol.to_string(),
                }
            })
            .collect();

        let metadata = ObjectMeta::new(derived_name("se-auto-", &[namespace, host]), namespace)
            .with_label(mesh::USE_WAYPOINT_LABEL, mesh::waypoint_name(namespace));

        // Istio rejects bare IPs in the hosts field. For IP targets, use
        // resolution: STATIC with the IP in endpoints and a synthetic hostname
        // in hosts (dashes instead of dots so it's a valid DNS name).
        let (se_host, resolution, endpoints) = if is_ip {
            let synthetic = format!("ip-{}.svc.external", host.replace('.', "-"));
            (
                synthetic,
                "STATIC".to_string(),
                vec![ServiceEntryEndpoint {
                    address: host.to_string(),
                }],
            )
        } else {
            (host.to_string(), "DNS".to_string(), vec![])
        };

        ServiceEntry::new(
            metadata,
            ServiceEntrySpec {
                hosts: vec![se_host],
                endpoints,
                ports: se_ports,
                location: "MESH_EXTERNAL".to_string(),
                resolution,
            },
        )
    }

    /// Compile an AuthorizationPolicy granting a service access to an inline FQDN egress target.
    pub(super) fn compile_fqdn_egress_access_policy(
        &self,
        service: &ServiceNode,
        namespace: &str,
        fqdn: &str,
        ports: &[u16],
    ) -> AuthorizationPolicy {
        let se_name = derived_name("se-auto-", &[namespace, fqdn]);
        let port_strings: Vec<String> = ports.iter().map(|p| p.to_string()).collect();

        AuthorizationPolicy::new(
            ObjectMeta::new(
                derived_name("allow-fqdn-", &[namespace, &service.name, fqdn]),
                namespace,
            ),
            AuthorizationPolicySpec {
                target_refs: vec![TargetRef {
                    group: "networking.istio.io".to_string(),
                    kind: "ServiceEntry".to_string(),
                    name: se_name,
                }],
                selector: None,
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![AuthorizationSource {
                        source: SourceSpec {
                            principals: vec![lattice_core::trust_domain::principal(
                                self.graph.trust_domain(),
                                namespace,
                                service.sa_name(),
                            )],
                            not_principals: vec![],
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
}
