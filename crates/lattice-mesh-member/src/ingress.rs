//! Ingress and Waypoint compilation for MeshMember resources
//!
//! - **IngressCompiler**: Compiles Gateway, HTTPRoute, GRPCRoute, TCPRoute, Certificate from `IngressSpec`
//! - **WaypointCompiler**: Compiles istio-waypoint Gateway + allow-to-waypoint AuthorizationPolicy

use std::collections::BTreeMap;

use lattice_common::crd::{
    derived_name, IngressSpec, IngressTls, LatticeMeshMemberSpec, MeshMemberPort, MeshMemberTarget,
    PathMatchType, RouteKind,
};
use lattice_common::kube_utils::ObjectMeta;
use lattice_common::mesh;
use lattice_common::network::gateway_api::*;
use lattice_common::policy::cilium::{
    CiliumIngressRule, CiliumNetworkPolicy, CiliumNetworkPolicySpec, EndpointSelector,
};
use lattice_common::policy::istio::{
    AuthorizationOperation, AuthorizationPolicy, AuthorizationPolicySpec, AuthorizationRule,
    OperationSpec, WorkloadSelector,
};
use lattice_common::policy::tetragon::{
    KprobeArg, KprobeSpec, MatchArg, PodSelector, Selector, TracingPolicyNamespaced,
    TracingPolicySpec,
};

use crate::policy::cilium::{
    build_tcp_port_rules, dns_egress_rule, hbone_egress_rule, hbone_ingress_rule,
};

/// K8s label for the gateway name on gateway proxy pods (raw, without Cilium `k8s:` prefix).
const GATEWAY_NAME_LABEL: &str = "gateway.networking.k8s.io/gateway-name";

/// Deduplicated, sorted listener ports from a set of gateway listeners.
fn unique_listener_ports(listeners: &[GatewayListener]) -> Vec<u16> {
    let mut ports: Vec<u16> = listeners.iter().map(|l| l.port).collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

// =============================================================================
// Generated Resources
// =============================================================================

/// Graph registration for an external workload created by a compilation step.
///
/// When a compiler creates resources for a workload managed by an external
/// controller (e.g. Istio gateway pods), it produces a graph registration so
/// the workload participates in bilateral agreement.
#[derive(Clone, Debug)]
pub struct GraphRegistration {
    pub name: String,
    pub spec: LatticeMeshMemberSpec,
}

/// Generated ingress resources (north-south traffic)
#[derive(Clone, Debug, Default)]
pub struct GeneratedIngress {
    pub gateway: Option<Gateway>,
    pub gateway_policy: Option<CiliumNetworkPolicy>,
    pub gateway_auth_policy: Option<AuthorizationPolicy>,
    /// AuthorizationPolicy restricting Gateway access to specific SPIFFE identities
    /// for cross-cluster routes with allowedServices configured.
    pub cross_cluster_auth_policy: Option<AuthorizationPolicy>,
    pub http_routes: Vec<HttpRoute>,
    pub grpc_routes: Vec<GrpcRoute>,
    pub tcp_routes: Vec<TcpRoute>,
    pub certificates: Vec<Certificate>,
    /// Graph registration for the gateway proxy workload (managed by Istio).
    pub gateway_graph_registration: Option<GraphRegistration>,
}

impl GeneratedIngress {
    pub fn is_empty(&self) -> bool {
        self.gateway.is_none()
            && self.gateway_policy.is_none()
            && self.gateway_auth_policy.is_none()
            && self.cross_cluster_auth_policy.is_none()
            && self.http_routes.is_empty()
            && self.grpc_routes.is_empty()
            && self.tcp_routes.is_empty()
            && self.certificates.is_empty()
    }

    pub fn total_count(&self) -> usize {
        usize::from(self.gateway.is_some())
            + usize::from(self.gateway_policy.is_some())
            + usize::from(self.gateway_auth_policy.is_some())
            + usize::from(self.cross_cluster_auth_policy.is_some())
            + self.http_routes.len()
            + self.grpc_routes.len()
            + self.tcp_routes.len()
            + self.certificates.len()
    }
}

/// Generated waypoint resources (east-west L7 policy)
#[derive(Clone, Debug, Default)]
pub struct GeneratedWaypoint {
    pub gateway: Option<Gateway>,
    pub allow_to_waypoint_policy: Option<AuthorizationPolicy>,
    pub runtime_policy: Option<TracingPolicyNamespaced>,
}

impl GeneratedWaypoint {
    pub fn is_empty(&self) -> bool {
        self.gateway.is_none()
            && self.allow_to_waypoint_policy.is_none()
            && self.runtime_policy.is_none()
    }

    pub fn total_count(&self) -> usize {
        usize::from(self.gateway.is_some())
            + usize::from(self.allow_to_waypoint_policy.is_some())
            + usize::from(self.runtime_policy.is_some())
    }
}

// =============================================================================
// Waypoint Compiler (Istio Native)
// =============================================================================

/// Compiler for generating Istio-native waypoint Gateway and associated policies
pub struct WaypointCompiler;

/// Binaries allowed to execute in waypoint/ingress gateway pods.
/// Istio's distroless image contains only these entrypoints.
const ALLOWED_PROXY_BINARIES: &[&str] = &["/usr/local/bin/envoy", "/usr/local/bin/pilot-agent"];

impl WaypointCompiler {
    /// Compile waypoint Gateway and policies for a namespace
    pub fn compile(namespace: &str) -> GeneratedWaypoint {
        let gateway_name = mesh::waypoint_name(namespace);
        GeneratedWaypoint {
            gateway: Some(Self::compile_gateway(namespace)),
            allow_to_waypoint_policy: Some(Self::compile_allow_to_waypoint_policy(namespace)),
            runtime_policy: Some(Self::compile_runtime_policy(namespace, &gateway_name)),
        }
    }

    fn compile_gateway(namespace: &str) -> Gateway {
        let gateway_name = mesh::waypoint_name(namespace);
        let metadata = ObjectMeta::new(&gateway_name, namespace)
            .with_label(mesh::WAYPOINT_FOR_LABEL, mesh::WAYPOINT_FOR_SERVICE);

        Gateway::new(
            metadata,
            GatewaySpec {
                gateway_class_name: mesh::WAYPOINT_GATEWAY_CLASS.to_string(),
                listeners: vec![GatewayListener {
                    name: "mesh".to_string(),
                    hostname: None,
                    port: mesh::HBONE_PORT,
                    protocol: "HBONE".to_string(),
                    tls: None,
                    allowed_routes: Some(AllowedRoutes::same_namespace()),
                }],
                tls: None,
            },
        )
    }

    fn compile_allow_to_waypoint_policy(namespace: &str) -> AuthorizationPolicy {
        let mut match_labels = BTreeMap::new();
        match_labels.insert(
            mesh::WAYPOINT_FOR_LABEL.to_string(),
            mesh::WAYPOINT_FOR_SERVICE.to_string(),
        );

        AuthorizationPolicy::new(
            ObjectMeta::new("allow-to-waypoint", namespace),
            AuthorizationPolicySpec {
                target_refs: vec![],
                selector: Some(WorkloadSelector { match_labels }),
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![],
                    to: vec![AuthorizationOperation {
                        operation: OperationSpec {
                            ports: vec![mesh::HBONE_PORT.to_string()],
                            hosts: vec![],
                        },
                    }],
                }],
            },
        )
    }

    /// Tetragon runtime policy restricting waypoint pods to only Envoy/pilot-agent.
    /// Kills any other binary execution via security_bprm_check kprobe.
    fn compile_runtime_policy(namespace: &str, gateway_name: &str) -> TracingPolicyNamespaced {
        TracingPolicyNamespaced::new(
            format!("waypoint-runtime-{}", derived_name("", &[namespace])),
            namespace,
            TracingPolicySpec {
                pod_selector: Some(PodSelector::for_gateway(gateway_name)),
                kprobes: vec![KprobeSpec::with_args(
                    "security_bprm_check",
                    vec![KprobeArg {
                        index: 0,
                        type_: "file".to_string(),
                        label: Some("binary".to_string()),
                    }],
                    vec![Selector {
                        match_args: vec![MatchArg {
                            index: 0,
                            operator: "NotEqual".to_string(),
                            values: ALLOWED_PROXY_BINARIES
                                .iter()
                                .map(|s| s.to_string())
                                .collect(),
                        }],
                        match_actions: vec![lattice_common::policy::tetragon::MatchAction {
                            action: lattice_common::policy::tetragon::TracingAction::Sigkill,
                        }],
                        ..Default::default()
                    }],
                )],
            },
        )
    }
}

// =============================================================================
// Ingress Compiler
// =============================================================================

/// Compiler for generating Gateway API resources from ingress config
pub struct IngressCompiler;

impl IngressCompiler {
    const DEFAULT_GATEWAY_CLASS: &'static str = mesh::INGRESS_GATEWAY_CLASS;

    /// Compile ingress resources for a mesh member.
    ///
    /// Returns an error if any route's port cannot be resolved against the member ports.
    pub fn compile(
        service_name: &str,
        namespace: &str,
        ingress: &IngressSpec,
        ports: &[MeshMemberPort],
        trust_domain: &str,
    ) -> Result<GeneratedIngress, String> {
        let mut output = GeneratedIngress::default();
        let mut all_listeners = Vec::new();

        let gateway_class = ingress
            .gateway_class
            .as_deref()
            .unwrap_or(Self::DEFAULT_GATEWAY_CLASS);
        let gateway_name = mesh::ingress_gateway_name(namespace);

        for (route_name, route_spec) in &ingress.routes {
            let backend_port = route_spec.resolve_port(ports).map_err(|e| {
                format!(
                    "route '{}' for service '{}': {}",
                    route_name, service_name, e
                )
            })?;

            match route_spec.kind {
                RouteKind::HTTPRoute => {
                    let (listeners, http_route, certificate) = Self::compile_http_route(
                        service_name,
                        namespace,
                        route_name,
                        route_spec,
                        &gateway_name,
                        backend_port,
                    );
                    all_listeners.extend(listeners);
                    output.http_routes.push(http_route);
                    if let Some(cert) = certificate {
                        output.certificates.push(cert);
                    }
                }
                RouteKind::GRPCRoute => {
                    let (listeners, grpc_route, certificate) = Self::compile_grpc_route(
                        service_name,
                        namespace,
                        route_name,
                        route_spec,
                        &gateway_name,
                        backend_port,
                    );
                    all_listeners.extend(listeners);
                    output.grpc_routes.push(grpc_route);
                    if let Some(cert) = certificate {
                        output.certificates.push(cert);
                    }
                }
                RouteKind::TCPRoute => {
                    let (listeners, tcp_route, certificate) = Self::compile_tcp_route(
                        service_name,
                        namespace,
                        route_name,
                        route_spec,
                        &gateway_name,
                        backend_port,
                    );
                    all_listeners.extend(listeners);
                    output.tcp_routes.push(tcp_route);
                    if let Some(cert) = certificate {
                        output.certificates.push(cert);
                    }
                }
                _ => {}
            }
        }

        if !all_listeners.is_empty() {
            output.gateway_policy = Some(Self::compile_gateway_policy(
                service_name,
                namespace,
                &gateway_name,
                &all_listeners,
            ));
            output.gateway_auth_policy = Some(Self::compile_gateway_auth_policy(
                service_name,
                namespace,
                &gateway_name,
                &all_listeners,
            ));
            // Enable frontend mTLS if any route is advertised for cross-cluster access.
            // This ensures only clusters sharing the Lattice CA can connect.
            let has_advertised_routes = ingress.routes.values().any(|r| r.advertise.is_some());

            let frontend_tls = if has_advertised_routes {
                Some(GatewayFrontendMtls {
                    frontend: GatewayFrontendTls {
                        default: GatewayFrontendTlsDefault {
                            validation: GatewayFrontendValidation {
                                ca_certificate_refs: vec![CaCertificateRef {
                                    group: String::new(),
                                    kind: "ConfigMap".to_string(),
                                    name: mesh::LATTICE_CA_CONFIGMAP.to_string(),
                                }],
                            },
                        },
                    },
                })
            } else {
                None
            };

            output.gateway = Some(Gateway::new(
                ObjectMeta::new(&gateway_name, namespace),
                GatewaySpec {
                    gateway_class_name: gateway_class.to_string(),
                    listeners: all_listeners,
                    tls: frontend_tls,
                },
            ));

            // Generate DENY AuthorizationPolicy for cross-cluster SPIFFE identity enforcement.
            //
            // When advertised routes have restricted allowedServices, we need to deny
            // traffic from identities NOT in the allowed list. Using DENY (evaluated
            // before ALLOW in Istio) ensures this works even with the permissive
            // gateway_auth_policy that allows all sources on listener ports.
            //
            // The policy uses notPrincipals: traffic from any principal NOT in the
            // allowed list is denied. Traffic from allowed principals passes through
            // to the normal ALLOW evaluation.
            // Check if any route has restricted (non-wildcard) advertise config.
            // If so, generate a DENY policy — even if all allowedServices entries
            // are malformed and parse to zero principals. An empty notPrincipals
            // list in a DENY policy means "deny all" which is correct fail-closed.
            let has_restricted_advertise = ingress
                .routes
                .values()
                .any(|r| r.advertise.as_ref().map(|a| !a.is_open()).unwrap_or(false));

            if has_restricted_advertise {
                let principals: Vec<String> = ingress
                    .routes
                    .values()
                    .filter_map(|r| r.advertise.as_ref())
                    .filter(|a| !a.is_open())
                    .flat_map(|a| a.to_spiffe_principals(trust_domain))
                    .collect();

                output.cross_cluster_auth_policy =
                    Some(AuthorizationPolicy::new_deny_not_principals(
                        &format!("{}-cross-cluster-deny", service_name),
                        namespace,
                        &gateway_name,
                        &principals,
                    ));
            }

            output.gateway_graph_registration = Some(GraphRegistration {
                name: mesh::ingress_gateway_sa_name(namespace),
                spec: LatticeMeshMemberSpec {
                    target: MeshMemberTarget::Selector(BTreeMap::from([(
                        GATEWAY_NAME_LABEL.to_string(),
                        gateway_name,
                    )])),
                    ports: vec![],
                    allowed_callers: vec![],
                    dependencies: vec![],
                    egress: vec![],
                    allow_peer_traffic: false,
                    depends_all: true,
                    ingress: None,
                    service_account: Some(mesh::ingress_gateway_sa_name(namespace)),
                    ambient: true,
                },
            });
        }

        Ok(output)
    }

    /// Compile a per-service CiliumNetworkPolicy for the gateway proxy pod.
    ///
    /// Each service with ingress creates its own CNP. Cilium unions multiple CNPs
    /// targeting the same endpoint, so per-service policies compose correctly.
    /// This avoids SSA conflicts — CRD lists are atomic, so a shared CNP would
    /// lose ports when the last service to reconcile overwrites the list.
    fn compile_gateway_policy(
        service_name: &str,
        namespace: &str,
        gateway_name: &str,
        listeners: &[GatewayListener],
    ) -> CiliumNetworkPolicy {
        let endpoint_labels = BTreeMap::from([(
            mesh::CILIUM_GATEWAY_NAME_LABEL.to_string(),
            gateway_name.to_string(),
        )]);

        // HBONE ingress (mesh pods reaching gateway via ztunnel)
        let mut ingress_rules = vec![hbone_ingress_rule()];

        // Direct TCP ingress on each unique listener port from any source.
        let listener_ports = unique_listener_ports(listeners);
        if !listener_ports.is_empty() {
            ingress_rules.push(CiliumIngressRule {
                to_ports: build_tcp_port_rules(&listener_ports),
                ..Default::default()
            });
        }

        // HBONE egress (gateway forwarding to backends via ztunnel) + DNS to kube-dns.
        let egress_rules = vec![dns_egress_rule(None), hbone_egress_rule()];

        CiliumNetworkPolicy::new(
            ObjectMeta::new(
                derived_name("cnp-gw-", &[namespace, gateway_name, service_name]),
                namespace,
            ),
            CiliumNetworkPolicySpec {
                endpoint_selector: EndpointSelector::from_labels(endpoint_labels),
                ingress: ingress_rules,
                egress: egress_rules,
            },
        )
    }

    /// Compile a per-service Istio ALLOW AuthorizationPolicy for the gateway proxy.
    ///
    /// Each service with ingress creates its own ALLOW policy. Istio unions
    /// multiple ALLOW policies — a request is permitted if ANY policy matches.
    /// This avoids SSA conflicts on the shared atomic `spec.rules` list.
    fn compile_gateway_auth_policy(
        service_name: &str,
        namespace: &str,
        gateway_name: &str,
        listeners: &[GatewayListener],
    ) -> AuthorizationPolicy {
        let listener_ports = unique_listener_ports(listeners);

        let match_labels =
            BTreeMap::from([(GATEWAY_NAME_LABEL.to_string(), gateway_name.to_string())]);

        AuthorizationPolicy::new(
            ObjectMeta::new(
                derived_name("allow-gw-", &[namespace, gateway_name, service_name]),
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
                            ports: listener_ports.iter().map(|p| p.to_string()).collect(),
                            hosts: vec![],
                        },
                    }],
                }],
            },
        )
    }

    fn build_host_listeners(
        service_name: &str,
        route_name: &str,
        route_spec: &lattice_common::crd::RouteSpec,
        gateway_name: &str,
        namespace: &str,
        tls_secret_name: &str,
    ) -> (Vec<GatewayListener>, Vec<ParentRef>) {
        let has_tls = route_spec.tls.is_some();
        let mut listeners = Vec::new();
        let mut parent_refs = Vec::new();

        for (i, host) in route_spec.hosts.iter().enumerate() {
            let http_listener_name = format!("{}-{}-http-{}", service_name, route_name, i);
            listeners.push(GatewayListener {
                name: http_listener_name.clone(),
                hostname: Some(host.clone()),
                port: 80,
                protocol: "HTTP".to_string(),
                tls: None,
                allowed_routes: Some(AllowedRoutes::same_namespace()),
            });
            parent_refs.push(ParentRef::gateway(
                gateway_name,
                namespace,
                &http_listener_name,
            ));

            if has_tls {
                let https_listener_name = format!("{}-{}-https-{}", service_name, route_name, i);
                listeners.push(GatewayListener {
                    name: https_listener_name.clone(),
                    hostname: Some(host.clone()),
                    port: 443,
                    protocol: "HTTPS".to_string(),
                    tls: Some(GatewayTlsConfig {
                        mode: "Terminate".to_string(),
                        certificate_refs: vec![CertificateRef {
                            kind: Some("Secret".to_string()),
                            name: tls_secret_name.to_string(),
                        }],
                    }),
                    allowed_routes: Some(AllowedRoutes::same_namespace()),
                });
                parent_refs.push(ParentRef::gateway(
                    gateway_name,
                    namespace,
                    &https_listener_name,
                ));
            }
        }

        (listeners, parent_refs)
    }

    fn compile_http_route(
        service_name: &str,
        namespace: &str,
        route_name: &str,
        route_spec: &lattice_common::crd::RouteSpec,
        gateway_name: &str,
        backend_port: u16,
    ) -> (Vec<GatewayListener>, HttpRoute, Option<Certificate>) {
        let tls_secret_name =
            Self::tls_secret_name(service_name, route_name, route_spec.tls.as_ref());

        let (listeners, parent_refs) = Self::build_host_listeners(
            service_name,
            route_name,
            route_spec,
            gateway_name,
            namespace,
            &tls_secret_name,
        );

        let matches = Self::build_http_matches(route_spec);

        let http_route = HttpRoute::new(
            ObjectMeta::new(format!("{}-{}-route", service_name, route_name), namespace),
            HttpRouteSpec {
                parent_refs,
                hostnames: route_spec.hosts.clone(),
                rules: vec![HttpRouteRule {
                    matches,
                    backend_refs: vec![BackendRef {
                        kind: Some("Service".to_string()),
                        name: service_name.to_string(),
                        port: backend_port,
                    }],
                }],
            },
        );

        let certificate =
            Self::compile_certificate_for_route(service_name, namespace, route_name, route_spec);

        (listeners, http_route, certificate)
    }

    fn compile_grpc_route(
        service_name: &str,
        namespace: &str,
        route_name: &str,
        route_spec: &lattice_common::crd::RouteSpec,
        gateway_name: &str,
        backend_port: u16,
    ) -> (Vec<GatewayListener>, GrpcRoute, Option<Certificate>) {
        let tls_secret_name =
            Self::tls_secret_name(service_name, route_name, route_spec.tls.as_ref());

        let (listeners, parent_refs) = Self::build_host_listeners(
            service_name,
            route_name,
            route_spec,
            gateway_name,
            namespace,
            &tls_secret_name,
        );

        let grpc_matches = Self::build_grpc_matches(route_spec);

        let grpc_route = GrpcRoute::new(
            ObjectMeta::new(format!("{}-{}-route", service_name, route_name), namespace),
            GrpcRouteSpec {
                parent_refs,
                hostnames: route_spec.hosts.clone(),
                rules: vec![GrpcRouteRule {
                    matches: grpc_matches,
                    backend_refs: vec![BackendRef {
                        kind: Some("Service".to_string()),
                        name: service_name.to_string(),
                        port: backend_port,
                    }],
                }],
            },
        );

        let certificate =
            Self::compile_certificate_for_route(service_name, namespace, route_name, route_spec);

        (listeners, grpc_route, certificate)
    }

    fn compile_tcp_route(
        service_name: &str,
        namespace: &str,
        route_name: &str,
        route_spec: &lattice_common::crd::RouteSpec,
        gateway_name: &str,
        backend_port: u16,
    ) -> (Vec<GatewayListener>, TcpRoute, Option<Certificate>) {
        let listen_port = route_spec.listen_port.unwrap_or(backend_port);
        let has_tls = route_spec.tls.is_some();
        let tls_secret_name =
            Self::tls_secret_name(service_name, route_name, route_spec.tls.as_ref());

        let tcp_listener_name = format!("{}-{}-tcp", service_name, route_name);

        let tls_config = if has_tls {
            Some(GatewayTlsConfig {
                mode: "Terminate".to_string(),
                certificate_refs: vec![CertificateRef {
                    kind: Some("Secret".to_string()),
                    name: tls_secret_name,
                }],
            })
        } else {
            None
        };

        let listeners = vec![GatewayListener {
            name: tcp_listener_name.clone(),
            hostname: None,
            port: listen_port,
            protocol: "TCP".to_string(),
            tls: tls_config,
            allowed_routes: Some(AllowedRoutes::same_namespace()),
        }];

        let parent_refs = vec![ParentRef::gateway(
            gateway_name,
            namespace,
            &tcp_listener_name,
        )];

        let tcp_route = TcpRoute::new(
            ObjectMeta::new(format!("{}-{}-route", service_name, route_name), namespace),
            TcpRouteSpec {
                parent_refs,
                rules: vec![TcpRouteRule {
                    backend_refs: vec![BackendRef {
                        kind: Some("Service".to_string()),
                        name: service_name.to_string(),
                        port: backend_port,
                    }],
                }],
            },
        );

        // TCPRoute doesn't support auto TLS (cert-manager); only manual (secretName)
        (listeners, tcp_route, None)
    }

    fn tls_secret_name(service_name: &str, route_name: &str, tls: Option<&IngressTls>) -> String {
        tls.and_then(|t| t.secret_name.clone())
            .unwrap_or_else(|| format!("{}-{}-tls", service_name, route_name))
    }

    fn build_http_matches(route_spec: &lattice_common::crd::RouteSpec) -> Vec<HttpRouteMatch> {
        if let Some(ref rules) = route_spec.rules {
            rules
                .iter()
                .flat_map(|rule| {
                    rule.matches.iter().map(|m| HttpRouteMatch {
                        path: m.path.as_ref().map(|p| HttpPathMatch {
                            type_: match p.type_ {
                                PathMatchType::Exact => "Exact",
                                PathMatchType::PathPrefix => "PathPrefix",
                                _ => "PathPrefix",
                            }
                            .to_string(),
                            value: p.value.clone(),
                        }),
                        headers: if m.headers.is_empty() {
                            None
                        } else {
                            Some(
                                m.headers
                                    .iter()
                                    .map(|h| HttpHeaderMatch {
                                        name: h.name.clone(),
                                        value: h.value.clone(),
                                        type_: h.type_.as_ref().map(|t| match t {
                                            lattice_common::crd::HeaderMatchType::Exact => {
                                                "Exact".to_string()
                                            }
                                            lattice_common::crd::HeaderMatchType::RegularExpression => {
                                                "RegularExpression".to_string()
                                            }
                                            _ => "Exact".to_string(),
                                        }),
                                    })
                                    .collect(),
                            )
                        },
                        method: m.method.clone(),
                    })
                })
                .collect()
        } else {
            vec![HttpRouteMatch {
                path: Some(HttpPathMatch {
                    type_: "PathPrefix".to_string(),
                    value: "/".to_string(),
                }),
                headers: None,
                method: None,
            }]
        }
    }

    fn build_grpc_matches(route_spec: &lattice_common::crd::RouteSpec) -> Vec<GrpcRouteMatch> {
        if let Some(ref rules) = route_spec.rules {
            rules
                .iter()
                .flat_map(|rule| {
                    rule.matches.iter().map(|m| GrpcRouteMatch {
                        method: m.grpc_method.as_ref().map(|gm| GrpcMethodMatchSpec {
                            service: gm.service.clone(),
                            method: gm.method.clone(),
                        }),
                    })
                })
                .collect()
        } else {
            vec![]
        }
    }

    fn compile_certificate_for_route(
        service_name: &str,
        namespace: &str,
        route_name: &str,
        route_spec: &lattice_common::crd::RouteSpec,
    ) -> Option<Certificate> {
        let tls = route_spec.tls.as_ref()?;
        let issuer_ref = tls.issuer_ref.as_ref()?;

        Some(Certificate::new(
            ObjectMeta::new(format!("{}-{}-cert", service_name, route_name), namespace),
            CertificateSpec {
                secret_name: format!("{}-{}-tls", service_name, route_name),
                dns_names: route_spec.hosts.clone(),
                issuer_ref: IssuerRef {
                    name: issuer_ref.name.clone(),
                    kind: issuer_ref
                        .kind
                        .clone()
                        .unwrap_or_else(|| "ClusterIssuer".to_string()),
                    group: Some("cert-manager.io".to_string()),
                },
            },
        ))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{
        CertIssuerRef, HeaderMatch as CrdHeaderMatch, HeaderMatchType as CrdHeaderMatchType,
        PathMatch as CrdPathMatch, PeerAuth, RouteKind, RouteMatch as CrdRouteMatch,
        RouteRule as CrdRouteRule, RouteSpec as CrdRouteSpec,
    };

    fn single_port() -> Vec<MeshMemberPort> {
        vec![MeshMemberPort {
            port: 8080,
            service_port: None,
            name: "http".to_string(),
            peer_auth: PeerAuth::Strict,
        }]
    }

    fn make_ingress_spec(hosts: Vec<&str>, with_tls: bool) -> IngressSpec {
        let tls = if with_tls {
            Some(IngressTls {
                secret_name: None,
                issuer_ref: Some(CertIssuerRef {
                    name: "letsencrypt-prod".to_string(),
                    kind: None,
                }),
            })
        } else {
            None
        };

        IngressSpec {
            gateway_class: None,
            routes: BTreeMap::from([(
                "public".to_string(),
                CrdRouteSpec {
                    kind: RouteKind::HTTPRoute,
                    hosts: hosts.into_iter().map(|s| s.to_string()).collect(),
                    port: None,
                    listen_port: None,
                    rules: None,
                    tls,
                    advertise: None,
                },
            )]),
        }
    }

    #[test]
    fn generates_gateway_with_http_listener() {
        let ingress = make_ingress_spec(vec!["api.example.com"], false);
        let output = IngressCompiler::compile(
            "api",
            "prod",
            &ingress,
            &single_port(),
            "lattice.abcd1234",
        )
        .unwrap();

        let gateway = output.gateway.expect("should have gateway");
        assert_eq!(gateway.metadata.name, "prod-ingress");
        assert_eq!(gateway.metadata.namespace, "prod");
        assert_eq!(gateway.spec.gateway_class_name, "istio");
        assert_eq!(gateway.spec.listeners.len(), 1);

        let listener = &gateway.spec.listeners[0];
        assert_eq!(listener.name, "api-public-http-0");
        assert_eq!(listener.hostname, Some("api.example.com".to_string()));
        assert_eq!(listener.port, 80);
        assert_eq!(listener.protocol, "HTTP");
        assert!(listener.tls.is_none());
    }

    #[test]
    fn generates_gateway_with_https_listener() {
        let ingress = make_ingress_spec(vec!["api.example.com"], true);
        let output = IngressCompiler::compile(
            "api",
            "prod",
            &ingress,
            &single_port(),
            "lattice.abcd1234",
        )
        .unwrap();

        let gateway = output.gateway.expect("should have gateway");
        assert_eq!(gateway.spec.listeners.len(), 2);

        let http_listener = &gateway.spec.listeners[0];
        assert_eq!(http_listener.name, "api-public-http-0");

        let https_listener = &gateway.spec.listeners[1];
        assert_eq!(https_listener.name, "api-public-https-0");
        assert_eq!(https_listener.port, 443);
        assert_eq!(https_listener.protocol, "HTTPS");
        assert!(https_listener.tls.is_some());
    }

    #[test]
    fn generates_http_route() {
        let ingress = make_ingress_spec(vec!["api.example.com"], false);
        let output = IngressCompiler::compile(
            "api",
            "prod",
            &ingress,
            &single_port(),
            "lattice.abcd1234",
        )
        .unwrap();

        assert_eq!(output.http_routes.len(), 1);
        let route = &output.http_routes[0];
        assert_eq!(route.metadata.name, "api-public-route");
        assert_eq!(route.spec.hostnames, vec!["api.example.com"]);
        assert_eq!(route.spec.rules.len(), 1);

        assert_eq!(route.spec.parent_refs.len(), 1);
        assert_eq!(route.spec.parent_refs[0].name, "prod-ingress");
        assert_eq!(
            route.spec.parent_refs[0].section_name,
            Some("api-public-http-0".to_string())
        );

        let backend = &route.spec.rules[0].backend_refs[0];
        assert_eq!(backend.name, "api");
        assert_eq!(backend.port, 8080);
    }

    #[test]
    fn generates_certificate_for_auto_tls() {
        let ingress = make_ingress_spec(vec!["api.example.com"], true);
        let output = IngressCompiler::compile(
            "api",
            "prod",
            &ingress,
            &single_port(),
            "lattice.abcd1234",
        )
        .unwrap();

        assert_eq!(output.certificates.len(), 1);
        let cert = &output.certificates[0];
        assert_eq!(cert.metadata.name, "api-public-cert");
        assert_eq!(cert.spec.secret_name, "api-public-tls");
        assert_eq!(cert.spec.dns_names, vec!["api.example.com"]);
        assert_eq!(cert.spec.issuer_ref.name, "letsencrypt-prod");
    }

    #[test]
    fn custom_path_matches() {
        let ingress = IngressSpec {
            gateway_class: None,
            routes: BTreeMap::from([(
                "api".to_string(),
                CrdRouteSpec {
                    kind: RouteKind::HTTPRoute,
                    hosts: vec!["api.example.com".to_string()],
                    port: None,
                    listen_port: None,
                    rules: Some(vec![CrdRouteRule {
                        matches: vec![
                            CrdRouteMatch {
                                path: Some(CrdPathMatch {
                                    type_: PathMatchType::PathPrefix,
                                    value: "/v1".to_string(),
                                }),
                                headers: vec![],
                                method: None,
                                grpc_method: None,
                            },
                            CrdRouteMatch {
                                path: Some(CrdPathMatch {
                                    type_: PathMatchType::Exact,
                                    value: "/health".to_string(),
                                }),
                                headers: vec![],
                                method: None,
                                grpc_method: None,
                            },
                        ],
                    }]),
                    tls: None,
                    advertise: None,
                },
            )]),
        };

        let output = IngressCompiler::compile(
            "api",
            "prod",
            &ingress,
            &single_port(),
            "lattice.abcd1234",
        )
        .unwrap();
        let route = &output.http_routes[0];
        let matches = &route.spec.rules[0].matches;

        assert_eq!(matches.len(), 2);
        assert_eq!(
            matches[0].path.as_ref().expect("path should be set").value,
            "/v1"
        );
        assert_eq!(
            matches[1].path.as_ref().expect("path should be set").type_,
            "Exact"
        );
    }

    #[test]
    fn header_and_method_matches() {
        let ingress = IngressSpec {
            gateway_class: None,
            routes: BTreeMap::from([(
                "api".to_string(),
                CrdRouteSpec {
                    kind: RouteKind::HTTPRoute,
                    hosts: vec!["api.example.com".to_string()],
                    port: None,
                    listen_port: None,
                    rules: Some(vec![CrdRouteRule {
                        matches: vec![CrdRouteMatch {
                            path: Some(CrdPathMatch {
                                type_: PathMatchType::PathPrefix,
                                value: "/api".to_string(),
                            }),
                            headers: vec![CrdHeaderMatch {
                                name: "x-version".to_string(),
                                value: "2".to_string(),
                                type_: Some(CrdHeaderMatchType::Exact),
                            }],
                            method: Some("POST".to_string()),
                            grpc_method: None,
                        }],
                    }]),
                    tls: None,
                    advertise: None,
                },
            )]),
        };

        let output = IngressCompiler::compile(
            "api",
            "prod",
            &ingress,
            &single_port(),
            "lattice.abcd1234",
        )
        .unwrap();
        let route = &output.http_routes[0];
        let m = &route.spec.rules[0].matches[0];

        assert_eq!(m.method, Some("POST".to_string()));
        let headers = m.headers.as_ref().expect("should have headers");
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].name, "x-version");
        assert_eq!(headers[0].value, "2");
        assert_eq!(headers[0].type_, Some("Exact".to_string()));
    }

    #[test]
    fn multi_host_generates_per_host_listeners() {
        let ingress = make_ingress_spec(vec!["api.example.com", "api.internal.example.com"], true);
        let output = IngressCompiler::compile(
            "api",
            "prod",
            &ingress,
            &single_port(),
            "lattice.abcd1234",
        )
        .unwrap();

        let gateway = output.gateway.expect("should have gateway");
        assert_eq!(gateway.spec.listeners.len(), 4);
        assert_eq!(gateway.spec.listeners[0].name, "api-public-http-0");
        assert_eq!(gateway.spec.listeners[1].name, "api-public-https-0");
        assert_eq!(gateway.spec.listeners[2].name, "api-public-http-1");
        assert_eq!(gateway.spec.listeners[3].name, "api-public-https-1");

        let route = &output.http_routes[0];
        assert_eq!(route.spec.parent_refs.len(), 4);
    }

    #[test]
    fn manual_tls_uses_provided_secret_name() {
        let ingress = IngressSpec {
            gateway_class: None,
            routes: BTreeMap::from([(
                "api".to_string(),
                CrdRouteSpec {
                    kind: RouteKind::HTTPRoute,
                    hosts: vec!["api.example.com".to_string()],
                    port: None,
                    listen_port: None,
                    rules: None,
                    tls: Some(IngressTls {
                        secret_name: Some("my-custom-cert".to_string()),
                        issuer_ref: None,
                    }),
                    advertise: None,
                },
            )]),
        };
        let output = IngressCompiler::compile(
            "api",
            "prod",
            &ingress,
            &single_port(),
            "lattice.abcd1234",
        )
        .unwrap();

        let gateway = output.gateway.expect("should have gateway");
        let https_listener = &gateway.spec.listeners[1];
        let tls = https_listener.tls.as_ref().expect("should have tls");
        assert_eq!(tls.certificate_refs[0].name, "my-custom-cert");

        assert!(output.certificates.is_empty());
    }

    #[test]
    fn grpc_route_generates_correctly() {
        let ingress = IngressSpec {
            gateway_class: None,
            routes: BTreeMap::from([(
                "inference".to_string(),
                CrdRouteSpec {
                    kind: RouteKind::GRPCRoute,
                    hosts: vec!["model.example.com".to_string()],
                    port: None,
                    listen_port: None,
                    rules: None,
                    tls: None,
                    advertise: None,
                },
            )]),
        };
        let output = IngressCompiler::compile(
            "model",
            "prod",
            &ingress,
            &single_port(),
            "lattice.abcd1234",
        )
        .unwrap();

        assert!(output.http_routes.is_empty());
        assert_eq!(output.grpc_routes.len(), 1);
        assert!(output.tcp_routes.is_empty());

        let grpc = &output.grpc_routes[0];
        assert_eq!(grpc.metadata.name, "model-inference-route");
        assert_eq!(grpc.spec.hostnames, vec!["model.example.com"]);
        assert_eq!(grpc.spec.rules[0].backend_refs[0].port, 8080);
    }

    #[test]
    fn tcp_route_generates_correctly() {
        let ingress = IngressSpec {
            gateway_class: None,
            routes: BTreeMap::from([(
                "metrics".to_string(),
                CrdRouteSpec {
                    kind: RouteKind::TCPRoute,
                    hosts: vec![],
                    port: Some("http".to_string()),
                    listen_port: Some(9090),
                    rules: None,
                    tls: None,
                    advertise: None,
                },
            )]),
        };
        let output =
            IngressCompiler::compile("db", "prod", &ingress, &single_port(), "lattice.abcd1234")
                .unwrap();

        assert!(output.http_routes.is_empty());
        assert!(output.grpc_routes.is_empty());
        assert_eq!(output.tcp_routes.len(), 1);

        let tcp = &output.tcp_routes[0];
        assert_eq!(tcp.metadata.name, "db-metrics-route");
        assert_eq!(tcp.spec.rules[0].backend_refs[0].port, 8080);

        let gateway = output.gateway.expect("should have gateway");
        assert_eq!(gateway.spec.listeners[0].port, 9090);
        assert_eq!(gateway.spec.listeners[0].protocol, "TCP");
    }

    #[test]
    fn mixed_routes() {
        let ingress = IngressSpec {
            gateway_class: Some("custom-gateway".to_string()),
            routes: BTreeMap::from([
                (
                    "api".to_string(),
                    CrdRouteSpec {
                        kind: RouteKind::HTTPRoute,
                        hosts: vec!["api.example.com".to_string()],
                        port: None,
                        listen_port: None,
                        rules: None,
                        tls: None,
                        advertise: None,
                    },
                ),
                (
                    "inference".to_string(),
                    CrdRouteSpec {
                        kind: RouteKind::GRPCRoute,
                        hosts: vec!["model.example.com".to_string()],
                        port: None,
                        listen_port: None,
                        rules: None,
                        tls: None,
                        advertise: None,
                    },
                ),
                (
                    "metrics".to_string(),
                    CrdRouteSpec {
                        kind: RouteKind::TCPRoute,
                        hosts: vec![],
                        port: None,
                        listen_port: Some(9090),
                        rules: None,
                        tls: None,
                        advertise: None,
                    },
                ),
            ]),
        };

        let output = IngressCompiler::compile(
            "svc",
            "prod",
            &ingress,
            &single_port(),
            "lattice.abcd1234",
        )
        .unwrap();

        assert_eq!(output.http_routes.len(), 1);
        assert_eq!(output.grpc_routes.len(), 1);
        assert_eq!(output.tcp_routes.len(), 1);

        let gateway = output.gateway.expect("should have gateway");
        assert_eq!(gateway.spec.gateway_class_name, "custom-gateway");
        assert_eq!(gateway.spec.listeners.len(), 3);
    }

    #[test]
    fn total_count_and_is_empty() {
        let empty = GeneratedIngress::default();
        assert!(empty.is_empty());
        assert_eq!(empty.total_count(), 0);

        let ingress = make_ingress_spec(vec!["api.example.com"], true);
        let output = IngressCompiler::compile(
            "api",
            "prod",
            &ingress,
            &single_port(),
            "lattice.abcd1234",
        )
        .unwrap();

        assert!(!output.is_empty());
        // gateway + gateway_policy + gateway_auth_policy + http_route + certificate = 5
        assert_eq!(output.total_count(), 5);
    }

    #[test]
    fn waypoint_uses_istio_gateway_class() {
        let output = WaypointCompiler::compile("mesh-test");

        let gateway = output.gateway.expect("should have gateway");
        assert_eq!(gateway.spec.gateway_class_name, "istio-waypoint");
        assert_eq!(gateway.metadata.name, "mesh-test-waypoint");
    }

    #[test]
    fn waypoint_has_correct_labels() {
        let output = WaypointCompiler::compile("mesh-test");

        let gateway = output.gateway.expect("should have gateway");
        assert_eq!(
            gateway.metadata.labels.get("istio.io/waypoint-for"),
            Some(&"service".to_string())
        );
    }

    #[test]
    fn waypoint_gateway_has_hbone_listener() {
        let output = WaypointCompiler::compile("mesh-test");

        let gateway = output.gateway.expect("should have gateway");
        assert_eq!(gateway.spec.listeners.len(), 1);

        let listener = &gateway.spec.listeners[0];
        assert_eq!(listener.port, 15008);
        assert_eq!(listener.protocol, "HBONE");
    }

    #[test]
    fn waypoint_generates_allow_to_waypoint_policy() {
        let output = WaypointCompiler::compile("mesh-test");

        let policy = output
            .allow_to_waypoint_policy
            .expect("should have allow-to-waypoint policy");
        assert_eq!(policy.metadata.name, "allow-to-waypoint");
        assert_eq!(policy.metadata.namespace, "mesh-test");
        assert_eq!(policy.spec.action, "ALLOW");
    }

    #[test]
    fn waypoint_policy_targets_waypoint_pods() {
        let output = WaypointCompiler::compile("prod");

        let policy = output.allow_to_waypoint_policy.expect("should have policy");
        let selector = policy.spec.selector.as_ref().expect("should have selector");
        assert_eq!(
            selector.match_labels.get("istio.io/waypoint-for"),
            Some(&"service".to_string())
        );
    }

    #[test]
    fn waypoint_policy_allows_hbone_port() {
        let output = WaypointCompiler::compile("test-ns");

        let policy = output.allow_to_waypoint_policy.expect("should have policy");
        assert_eq!(policy.spec.rules.len(), 1);

        let rule = &policy.spec.rules[0];
        assert!(rule.from.is_empty());
        assert_eq!(rule.to.len(), 1);
        assert_eq!(
            rule.to[0].operation.ports,
            vec![mesh::HBONE_PORT.to_string()]
        );
    }

    #[test]
    fn waypoint_total_count_includes_all_resources() {
        let output = WaypointCompiler::compile("mesh-test");

        assert_eq!(output.total_count(), 3);
        assert!(output.gateway.is_some());
        assert!(output.allow_to_waypoint_policy.is_some());
        assert!(output.runtime_policy.is_some());
        assert!(!output.is_empty());
    }

    #[test]
    fn waypoint_runtime_policy_targets_gateway_pods() {
        let output = WaypointCompiler::compile("prod");
        let policy = output.runtime_policy.unwrap();

        assert_eq!(policy.metadata.namespace, "prod");
        let ps = policy.spec.pod_selector.unwrap();
        assert_eq!(
            ps.match_labels
                .get("gateway.networking.k8s.io/gateway-name")
                .unwrap(),
            "prod-waypoint"
        );
    }

    #[test]
    fn waypoint_runtime_policy_blocks_non_envoy_binaries() {
        let output = WaypointCompiler::compile("test-ns");
        let policy = output.runtime_policy.unwrap();

        assert_eq!(policy.spec.kprobes.len(), 1);
        let kprobe = &policy.spec.kprobes[0];
        assert_eq!(kprobe.call, "security_bprm_check");

        let selector = &kprobe.selectors[0];
        let arg = &selector.match_args[0];
        assert_eq!(arg.operator, "NotEqual");
        assert!(arg.values.contains(&"/usr/local/bin/envoy".to_string()));
        assert!(arg
            .values
            .contains(&"/usr/local/bin/pilot-agent".to_string()));

        assert_eq!(
            selector.match_actions[0].action,
            lattice_common::policy::tetragon::TracingAction::Sigkill
        );
    }

    // =========================================================================
    // Gateway CiliumNetworkPolicy tests
    // =========================================================================

    #[test]
    fn gateway_generates_cnp_with_correct_selector() {
        let ingress = make_ingress_spec(vec!["api.example.com"], false);
        let output = IngressCompiler::compile(
            "api",
            "prod",
            &ingress,
            &single_port(),
            "lattice.abcd1234",
        )
        .unwrap();

        let cnp = output.gateway_policy.expect("should have gateway CNP");
        assert_eq!(cnp.metadata.namespace, "prod");
        assert_eq!(
            cnp.spec
                .endpoint_selector
                .match_labels
                .get("k8s:gateway.networking.k8s.io/gateway-name"),
            Some(&"prod-ingress".to_string())
        );
    }

    #[test]
    fn gateway_cnp_has_listener_port_ingress() {
        let ingress = make_ingress_spec(vec!["api.example.com"], true);
        let output = IngressCompiler::compile(
            "api",
            "prod",
            &ingress,
            &single_port(),
            "lattice.abcd1234",
        )
        .unwrap();

        let cnp = output.gateway_policy.expect("should have gateway CNP");

        // Should have direct TCP ingress rule for listener ports (80, 443)
        let tcp_rule = cnp
            .spec
            .ingress
            .iter()
            .find(|r| {
                r.from_entities.is_empty()
                    && r.from_endpoints.is_empty()
                    && r.to_ports.iter().any(|pr| {
                        pr.ports.iter().any(|p| p.port == "80")
                            && pr.ports.iter().any(|p| p.port == "443")
                    })
            })
            .expect("should have direct TCP ingress for listener ports");
        assert_eq!(tcp_rule.to_ports[0].ports.len(), 2);
    }

    #[test]
    fn gateway_cnp_has_hbone_ingress_and_egress() {
        let ingress = make_ingress_spec(vec!["api.example.com"], false);
        let output = IngressCompiler::compile(
            "api",
            "prod",
            &ingress,
            &single_port(),
            "lattice.abcd1234",
        )
        .unwrap();

        let cnp = output.gateway_policy.expect("should have gateway CNP");
        let hbone_port = mesh::HBONE_PORT.to_string();

        // HBONE ingress
        let hbone_in = cnp.spec.ingress.iter().find(|r| {
            r.from_entities.contains(&"cluster".to_string())
                && r.to_ports
                    .iter()
                    .any(|pr| pr.ports.iter().any(|p| p.port == hbone_port))
        });
        assert!(hbone_in.is_some(), "should have HBONE ingress rule");

        // HBONE egress
        let hbone_out = cnp.spec.egress.iter().find(|r| {
            r.to_entities.contains(&"cluster".to_string())
                && r.to_ports
                    .iter()
                    .any(|pr| pr.ports.iter().any(|p| p.port == hbone_port))
        });
        assert!(hbone_out.is_some(), "should have HBONE egress rule");

        // DNS egress
        let dns_out = cnp.spec.egress.iter().find(|r| {
            r.to_ports
                .iter()
                .any(|pr| pr.ports.iter().any(|p| p.port == "53"))
        });
        assert!(dns_out.is_some(), "should have DNS egress rule");
    }

    #[test]
    fn no_gateway_cnp_when_no_listeners() {
        let ingress = IngressSpec {
            gateway_class: None,
            routes: BTreeMap::new(),
        };
        let output = IngressCompiler::compile(
            "api",
            "prod",
            &ingress,
            &single_port(),
            "lattice.abcd1234",
        )
        .unwrap();

        assert!(output.gateway.is_none());
        assert!(output.gateway_policy.is_none());
    }

    #[test]
    fn per_service_cnp_and_auth_have_distinct_names() {
        let ingress_a = make_ingress_spec(vec!["a.example.com"], false);
        let ingress_b = make_ingress_spec(vec!["b.example.com"], true);

        let out_a = IngressCompiler::compile(
            "svc-a",
            "prod",
            &ingress_a,
            &single_port(),
            "lattice.abcd1234",
        )
        .unwrap();
        let out_b = IngressCompiler::compile(
            "svc-b",
            "prod",
            &ingress_b,
            &single_port(),
            "lattice.abcd1234",
        )
        .unwrap();

        let cnp_a = out_a.gateway_policy.unwrap();
        let cnp_b = out_b.gateway_policy.unwrap();
        assert_ne!(cnp_a.metadata.name, cnp_b.metadata.name);

        let auth_a = out_a.gateway_auth_policy.unwrap();
        let auth_b = out_b.gateway_auth_policy.unwrap();
        assert_ne!(auth_a.metadata.name, auth_b.metadata.name);
    }

    #[test]
    fn produces_gateway_graph_registration() {
        let ingress = make_ingress_spec(vec!["api.example.com"], false);
        let output = IngressCompiler::compile(
            "api",
            "prod",
            &ingress,
            &single_port(),
            "lattice.abcd1234",
        )
        .unwrap();

        let reg = output
            .gateway_graph_registration
            .expect("should produce graph registration for gateway");
        assert_eq!(reg.name, "prod-ingress-istio");
        assert_eq!(
            reg.spec.service_account.as_deref(),
            Some("prod-ingress-istio")
        );
        assert!(reg.spec.depends_all, "gateway should use depends_all");
        assert!(reg.spec.ambient, "gateway should be ambient");
        assert!(reg.spec.ports.is_empty(), "gateway has no service ports");
        assert!(
            reg.spec.allowed_callers.is_empty(),
            "gateway is not called by other graph participants"
        );

        let selector = match &reg.spec.target {
            MeshMemberTarget::Selector(s) => s,
            _ => panic!("expected selector target"),
        };
        assert_eq!(
            selector.get("gateway.networking.k8s.io/gateway-name"),
            Some(&"prod-ingress".to_string())
        );
    }
}
