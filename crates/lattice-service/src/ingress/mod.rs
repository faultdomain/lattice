//! Ingress module for Gateway API resources
//!
//! This module provides types and compilation logic for:
//! - **Gateway API**: Gateway, HTTPRoute, GRPCRoute, TCPRoute for north-south ingress traffic
//! - **Istio Waypoint**: Gateway for ambient mesh L7 policy enforcement
//!
//! # Waypoint Architecture
//!
//! Uses Istio's native waypoint proxy (`istio-waypoint` GatewayClass) which:
//! - Speaks HBONE natively (no ztunnel conflicts)
//! - Integrates with AuthorizationPolicy for L7 enforcement
//!
//! All resource types implement `HasApiResource` for consistent API version handling.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use lattice_common::crd::{IngressSpec, IngressTls, PathMatchType, RouteKind, ServicePortsSpec};
use lattice_common::kube_utils::HasApiResource;
use lattice_common::kube_utils::ObjectMeta;
use lattice_common::mesh;
use lattice_common::policy::{
    AuthorizationOperation, AuthorizationPolicy, AuthorizationPolicySpec, AuthorizationRule,
    OperationSpec, WorkloadSelector,
};

// =============================================================================
// Macro for default serde functions
// =============================================================================

/// Macro to implement default_api_version() and default_kind() for types
/// implementing HasApiResource. This reduces boilerplate for serde defaults.
macro_rules! impl_api_defaults {
    ($type:ty) => {
        impl $type {
            fn default_api_version() -> String {
                <Self as HasApiResource>::API_VERSION.to_string()
            }
            fn default_kind() -> String {
                <Self as HasApiResource>::KIND.to_string()
            }
        }
    };
}

// =============================================================================
// Gateway API Types
// =============================================================================

/// Kubernetes Gateway API Gateway resource
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Gateway {
    /// API version (gateway.networking.k8s.io/v1)
    #[serde(default = "Gateway::default_api_version")]
    pub api_version: String,
    /// Resource kind (Gateway)
    #[serde(default = "Gateway::default_kind")]
    pub kind: String,
    /// Resource metadata
    pub metadata: ObjectMeta,
    /// Gateway specification
    pub spec: GatewaySpec,
}

impl HasApiResource for Gateway {
    const API_VERSION: &'static str = "gateway.networking.k8s.io/v1";
    const KIND: &'static str = "Gateway";
}

impl_api_defaults!(Gateway);

impl Gateway {
    /// Create a new Gateway
    pub fn new(metadata: ObjectMeta, spec: GatewaySpec) -> Self {
        Self {
            api_version: Self::default_api_version(),
            kind: Self::default_kind(),
            metadata,
            spec,
        }
    }
}

/// Gateway spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GatewaySpec {
    /// GatewayClass name (e.g., "istio" or "istio-waypoint")
    pub gateway_class_name: String,
    /// Listener configurations
    pub listeners: Vec<GatewayListener>,
}

/// Gateway listener configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GatewayListener {
    /// Listener name
    pub name: String,
    /// Optional hostname filter
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Port number
    pub port: u16,
    /// Protocol (HTTP, HTTPS, HBONE, TCP, etc.)
    pub protocol: String,
    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<GatewayTlsConfig>,
    /// Allowed routes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_routes: Option<AllowedRoutes>,
}

/// Gateway TLS configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GatewayTlsConfig {
    /// TLS mode (Terminate, Passthrough)
    pub mode: String,
    /// Certificate references
    pub certificate_refs: Vec<CertificateRef>,
}

/// Reference to a TLS certificate secret
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CertificateRef {
    /// Resource kind (default: Secret)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Secret name
    pub name: String,
}

/// Allowed routes for a gateway listener
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AllowedRoutes {
    /// Namespace selector
    pub namespaces: RouteNamespaces,
}

impl AllowedRoutes {
    /// Routes allowed only from the same namespace as the Gateway
    fn same_namespace() -> Self {
        Self {
            namespaces: RouteNamespaces {
                from: "Same".to_string(),
            },
        }
    }
}

/// Route namespace selector
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RouteNamespaces {
    /// Namespace selection mode (Same, All, Selector)
    pub from: String,
}

// =============================================================================
// HTTPRoute Types
// =============================================================================

/// Kubernetes Gateway API HTTPRoute resource
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpRoute {
    /// API version (gateway.networking.k8s.io/v1)
    #[serde(default = "HttpRoute::default_api_version")]
    pub api_version: String,
    /// Resource kind (HTTPRoute)
    #[serde(default = "HttpRoute::default_kind")]
    pub kind: String,
    /// Resource metadata
    pub metadata: ObjectMeta,
    /// HTTPRoute specification
    pub spec: HttpRouteSpec,
}

impl HasApiResource for HttpRoute {
    const API_VERSION: &'static str = "gateway.networking.k8s.io/v1";
    const KIND: &'static str = "HTTPRoute";
}

impl_api_defaults!(HttpRoute);

impl HttpRoute {
    /// Create a new HTTPRoute
    pub fn new(metadata: ObjectMeta, spec: HttpRouteSpec) -> Self {
        Self {
            api_version: Self::default_api_version(),
            kind: Self::default_kind(),
            metadata,
            spec,
        }
    }
}

/// HTTPRoute spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpRouteSpec {
    /// Parent gateway references
    pub parent_refs: Vec<ParentRef>,
    /// Hostnames to match
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,
    /// Routing rules
    pub rules: Vec<HttpRouteRule>,
}

/// Parent reference for route resources
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ParentRef {
    /// API group (gateway.networking.k8s.io)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Resource kind (Gateway)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Gateway name
    pub name: String,
    /// Gateway namespace
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Listener section name to bind to
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_name: Option<String>,
}

impl ParentRef {
    /// Create a reference to a specific listener on a Gateway
    fn gateway(name: &str, namespace: &str, section_name: impl Into<String>) -> Self {
        Self {
            group: Some("gateway.networking.k8s.io".to_string()),
            kind: Some("Gateway".to_string()),
            name: name.to_string(),
            namespace: Some(namespace.to_string()),
            section_name: Some(section_name.into()),
        }
    }
}

/// HTTPRoute rule
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpRouteRule {
    /// Request matches
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matches: Vec<HttpRouteMatch>,
    /// Backend references
    pub backend_refs: Vec<BackendRef>,
}

/// HTTP route match
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpRouteMatch {
    /// Path match
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<HttpPathMatch>,
    /// Header matches
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<Vec<HttpHeaderMatch>>,
    /// HTTP method match (GET, POST, etc.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

/// HTTP path match
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpPathMatch {
    /// Match type (PathPrefix, Exact)
    #[serde(rename = "type")]
    pub type_: String,
    /// Path value
    pub value: String,
}

/// HTTP header match
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpHeaderMatch {
    /// Header name
    pub name: String,
    /// Header value
    pub value: String,
    /// Match type (Exact or RegularExpression)
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

/// Backend reference
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackendRef {
    /// Resource kind (Service)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Service name
    pub name: String,
    /// Service port
    pub port: u16,
}

// =============================================================================
// GRPCRoute Types
// =============================================================================

/// Kubernetes Gateway API GRPCRoute resource
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GrpcRoute {
    /// API version (gateway.networking.k8s.io/v1)
    #[serde(default = "GrpcRoute::default_api_version")]
    pub api_version: String,
    /// Resource kind (GRPCRoute)
    #[serde(default = "GrpcRoute::default_kind")]
    pub kind: String,
    /// Resource metadata
    pub metadata: ObjectMeta,
    /// GRPCRoute specification
    pub spec: GrpcRouteSpec,
}

impl HasApiResource for GrpcRoute {
    const API_VERSION: &'static str = "gateway.networking.k8s.io/v1";
    const KIND: &'static str = "GRPCRoute";
}

impl_api_defaults!(GrpcRoute);

impl GrpcRoute {
    /// Create a new GRPCRoute
    pub fn new(metadata: ObjectMeta, spec: GrpcRouteSpec) -> Self {
        Self {
            api_version: Self::default_api_version(),
            kind: Self::default_kind(),
            metadata,
            spec,
        }
    }
}

/// GRPCRoute spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GrpcRouteSpec {
    /// Parent gateway references
    pub parent_refs: Vec<ParentRef>,
    /// Hostnames to match
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,
    /// Routing rules
    pub rules: Vec<GrpcRouteRule>,
}

/// GRPCRoute rule
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GrpcRouteRule {
    /// gRPC method matches
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matches: Vec<GrpcRouteMatch>,
    /// Backend references
    pub backend_refs: Vec<BackendRef>,
}

/// gRPC route match
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GrpcRouteMatch {
    /// gRPC method match
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<GrpcMethodMatchSpec>,
}

/// gRPC method match specification
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GrpcMethodMatchSpec {
    /// gRPC service name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// gRPC method name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

// =============================================================================
// TCPRoute Types
// =============================================================================

/// Kubernetes Gateway API TCPRoute resource
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TcpRoute {
    /// API version (gateway.networking.k8s.io/v1alpha2)
    #[serde(default = "TcpRoute::default_api_version")]
    pub api_version: String,
    /// Resource kind (TCPRoute)
    #[serde(default = "TcpRoute::default_kind")]
    pub kind: String,
    /// Resource metadata
    pub metadata: ObjectMeta,
    /// TCPRoute specification
    pub spec: TcpRouteSpec,
}

impl HasApiResource for TcpRoute {
    const API_VERSION: &'static str = "gateway.networking.k8s.io/v1alpha2";
    const KIND: &'static str = "TCPRoute";
}

impl_api_defaults!(TcpRoute);

impl TcpRoute {
    /// Create a new TCPRoute
    pub fn new(metadata: ObjectMeta, spec: TcpRouteSpec) -> Self {
        Self {
            api_version: Self::default_api_version(),
            kind: Self::default_kind(),
            metadata,
            spec,
        }
    }
}

/// TCPRoute spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TcpRouteSpec {
    /// Parent gateway references
    pub parent_refs: Vec<ParentRef>,
    /// Routing rules (typically one with backend refs)
    pub rules: Vec<TcpRouteRule>,
}

/// TCPRoute rule
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TcpRouteRule {
    /// Backend references
    pub backend_refs: Vec<BackendRef>,
}

// =============================================================================
// Certificate Types (cert-manager)
// =============================================================================

/// cert-manager Certificate resource
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Certificate {
    /// API version (cert-manager.io/v1)
    #[serde(default = "Certificate::default_api_version")]
    pub api_version: String,
    /// Resource kind (Certificate)
    #[serde(default = "Certificate::default_kind")]
    pub kind: String,
    /// Resource metadata
    pub metadata: ObjectMeta,
    /// Certificate specification
    pub spec: CertificateSpec,
}

impl HasApiResource for Certificate {
    const API_VERSION: &'static str = "cert-manager.io/v1";
    const KIND: &'static str = "Certificate";
}

impl_api_defaults!(Certificate);

impl Certificate {
    /// Create a new Certificate
    pub fn new(metadata: ObjectMeta, spec: CertificateSpec) -> Self {
        Self {
            api_version: Self::default_api_version(),
            kind: Self::default_kind(),
            metadata,
            spec,
        }
    }
}

/// Certificate spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CertificateSpec {
    /// Name of the Secret to store the certificate
    pub secret_name: String,
    /// DNS names for the certificate
    pub dns_names: Vec<String>,
    /// Reference to the issuer
    pub issuer_ref: IssuerRef,
}

/// Issuer reference for Certificate
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IssuerRef {
    /// Issuer name
    pub name: String,
    /// Issuer kind (Issuer or ClusterIssuer)
    pub kind: String,
    /// API group (cert-manager.io)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

// =============================================================================
// Generated Resources
// =============================================================================

/// Generated ingress resources (north-south traffic)
#[derive(Clone, Debug, Default)]
pub struct GeneratedIngress {
    /// Gateway resource
    pub gateway: Option<Gateway>,
    /// HTTPRoute resources
    pub http_routes: Vec<HttpRoute>,
    /// GRPCRoute resources
    pub grpc_routes: Vec<GrpcRoute>,
    /// TCPRoute resources
    pub tcp_routes: Vec<TcpRoute>,
    /// Certificate resources
    pub certificates: Vec<Certificate>,
}

impl GeneratedIngress {
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.gateway.is_none()
            && self.http_routes.is_empty()
            && self.grpc_routes.is_empty()
            && self.tcp_routes.is_empty()
            && self.certificates.is_empty()
    }

    /// Total resource count
    pub fn total_count(&self) -> usize {
        let gateway_count = if self.gateway.is_some() { 1 } else { 0 };
        gateway_count
            + self.http_routes.len()
            + self.grpc_routes.len()
            + self.tcp_routes.len()
            + self.certificates.len()
    }
}

/// Generated waypoint resources (east-west L7 policy)
#[derive(Clone, Debug, Default)]
pub struct GeneratedWaypoint {
    /// Waypoint Gateway (uses istio-waypoint GatewayClass)
    pub gateway: Option<Gateway>,
    /// AuthorizationPolicy allowing traffic TO the waypoint on HBONE port
    pub allow_to_waypoint_policy: Option<AuthorizationPolicy>,
}

impl GeneratedWaypoint {
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.gateway.is_none() && self.allow_to_waypoint_policy.is_none()
    }

    /// Total resource count
    pub fn total_count(&self) -> usize {
        let gateway_count = if self.gateway.is_some() { 1 } else { 0 };
        let policy_count = if self.allow_to_waypoint_policy.is_some() {
            1
        } else {
            0
        };
        gateway_count + policy_count
    }
}

// =============================================================================
// Waypoint Compiler (Istio Native)
// =============================================================================

/// Compiler for generating Istio-native waypoint Gateway and associated policies
pub struct WaypointCompiler;

impl WaypointCompiler {
    /// Compile waypoint Gateway and policies for a namespace
    pub fn compile(namespace: &str) -> GeneratedWaypoint {
        GeneratedWaypoint {
            gateway: Some(Self::compile_gateway(namespace)),
            allow_to_waypoint_policy: Some(Self::compile_allow_to_waypoint_policy(namespace)),
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
}

// =============================================================================
// Ingress Compiler
// =============================================================================

/// Compiler for generating Gateway API resources from LatticeService ingress config
pub struct IngressCompiler;

impl IngressCompiler {
    /// Default GatewayClass for ingress (Istio for north-south)
    const DEFAULT_GATEWAY_CLASS: &'static str = mesh::INGRESS_GATEWAY_CLASS;

    /// Compile ingress resources for a service.
    ///
    /// Iterates named routes and generates the appropriate Gateway API resources
    /// (HTTPRoute, GRPCRoute, TCPRoute) with listeners, certificates, and TLS config.
    pub fn compile(
        service_name: &str,
        namespace: &str,
        ingress: &IngressSpec,
        service_ports: Option<&ServicePortsSpec>,
    ) -> GeneratedIngress {
        let mut output = GeneratedIngress::default();
        let mut all_listeners = Vec::new();

        let gateway_class = ingress
            .gateway_class
            .as_deref()
            .unwrap_or(Self::DEFAULT_GATEWAY_CLASS);
        let gateway_name = mesh::ingress_gateway_name(namespace);

        for (route_name, route_spec) in &ingress.routes {
            let backend_port = route_spec.resolve_port(service_ports).unwrap_or(80);

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
            }
        }

        if !all_listeners.is_empty() {
            output.gateway = Some(Gateway::new(
                ObjectMeta::new(&gateway_name, namespace),
                GatewaySpec {
                    gateway_class_name: gateway_class.to_string(),
                    listeners: all_listeners,
                },
            ));
        }

        output
    }

    /// Build HTTP/HTTPS listeners and parent refs for host-based routes.
    ///
    /// Shared by HTTPRoute and GRPCRoute (both use HTTP/HTTPS listeners).
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

    /// Compile an HTTPRoute and its Gateway listeners.
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

    /// Compile a GRPCRoute and its Gateway listeners.
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

    /// Compile a TCPRoute and its Gateway listener.
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

    // ─── Helpers ───────────────────────────────────────────────────────────

    /// Determine TLS secret name for a route
    fn tls_secret_name(service_name: &str, route_name: &str, tls: Option<&IngressTls>) -> String {
        tls.and_then(|t| t.secret_name.clone())
            .unwrap_or_else(|| format!("{}-{}-tls", service_name, route_name))
    }

    /// Build HTTP route matches from a route spec
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
            // Default: catch-all PathPrefix /
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

    /// Build gRPC route matches from a route spec
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
            // Default: match all gRPC services/methods
            vec![]
        }
    }

    /// Compile a cert-manager Certificate for a route (auto TLS only)
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
        PathMatch as CrdPathMatch, PortSpec, RouteKind, RouteMatch as CrdRouteMatch,
        RouteRule as CrdRouteRule, RouteSpec as CrdRouteSpec,
    };

    fn single_port_spec() -> ServicePortsSpec {
        let mut ports = BTreeMap::new();
        ports.insert(
            "http".to_string(),
            PortSpec {
                port: 8080,
                target_port: None,
                protocol: None,
            },
        );
        ServicePortsSpec { ports }
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
                },
            )]),
        }
    }

    // =========================================================================
    // Ingress Compiler Tests
    // =========================================================================

    #[test]
    fn generates_gateway_with_http_listener() {
        let ingress = make_ingress_spec(vec!["api.example.com"], false);
        let output = IngressCompiler::compile("api", "prod", &ingress, Some(&single_port_spec()));

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
        let output = IngressCompiler::compile("api", "prod", &ingress, Some(&single_port_spec()));

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
        let output = IngressCompiler::compile("api", "prod", &ingress, Some(&single_port_spec()));

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
        let output = IngressCompiler::compile("api", "prod", &ingress, Some(&single_port_spec()));

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
                },
            )]),
        };

        let output = IngressCompiler::compile("api", "prod", &ingress, Some(&single_port_spec()));
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
                },
            )]),
        };

        let output = IngressCompiler::compile("api", "prod", &ingress, Some(&single_port_spec()));
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
        // Verify the route name is "public"
        assert!(ingress.routes.contains_key("public"));

        let output = IngressCompiler::compile("api", "prod", &ingress, Some(&single_port_spec()));

        let gateway = output.gateway.expect("should have gateway");
        // 2 hosts × (HTTP + HTTPS) = 4 listeners
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
                },
            )]),
        };
        let output = IngressCompiler::compile("api", "prod", &ingress, Some(&single_port_spec()));

        let gateway = output.gateway.expect("should have gateway");
        let https_listener = &gateway.spec.listeners[1];
        let tls = https_listener.tls.as_ref().expect("should have tls");
        assert_eq!(tls.certificate_refs[0].name, "my-custom-cert");

        // No Certificate generated for manual mode
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
                },
            )]),
        };
        let output = IngressCompiler::compile("model", "prod", &ingress, Some(&single_port_spec()));

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
                },
            )]),
        };
        let output = IngressCompiler::compile("db", "prod", &ingress, Some(&single_port_spec()));

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
                    },
                ),
            ]),
        };

        let output = IngressCompiler::compile("svc", "prod", &ingress, Some(&single_port_spec()));

        assert_eq!(output.http_routes.len(), 1);
        assert_eq!(output.grpc_routes.len(), 1);
        assert_eq!(output.tcp_routes.len(), 1);

        let gateway = output.gateway.expect("should have gateway");
        assert_eq!(gateway.spec.gateway_class_name, "custom-gateway");
        // api HTTP (1) + inference HTTP (1) + metrics TCP (1) = 3
        assert_eq!(gateway.spec.listeners.len(), 3);
    }

    #[test]
    fn total_count_and_is_empty() {
        let empty = GeneratedIngress::default();
        assert!(empty.is_empty());
        assert_eq!(empty.total_count(), 0);

        let ingress = make_ingress_spec(vec!["api.example.com"], true);
        let output = IngressCompiler::compile("api", "prod", &ingress, Some(&single_port_spec()));

        assert!(!output.is_empty());
        // Gateway + HTTPRoute + Certificate = 3
        assert_eq!(output.total_count(), 3);
    }

    // =========================================================================
    // Waypoint Compiler Tests
    // =========================================================================

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
    fn waypoint_total_count_includes_both_resources() {
        let output = WaypointCompiler::compile("mesh-test");

        assert_eq!(output.total_count(), 2);
        assert!(!output.is_empty());
    }
}
