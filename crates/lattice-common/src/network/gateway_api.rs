//! Gateway API types and cert-manager Certificate resources
//!
//! This module provides types for north-south ingress traffic:
//! - **Gateway API**: Gateway, HTTPRoute, GRPCRoute, TCPRoute
//! - **Certificates**: cert-manager Certificate resources for TLS
//!
//! All resource types implement `HasApiResource` for consistent API version handling.

use serde::{Deserialize, Serialize};

use crate::kube_utils::{HasApiResource, ObjectMeta};

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

/// external-dns annotation key for automatic DNS record creation
pub const EXTERNAL_DNS_HOSTNAME_ANNOTATION: &str =
    "external-dns.alpha.kubernetes.io/hostname";

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

    /// Add external-dns annotation for automatic DNS record creation.
    pub fn with_external_dns(mut self, hosts: &[String]) -> Self {
        if !hosts.is_empty() {
            self.metadata.annotations.insert(
                EXTERNAL_DNS_HOSTNAME_ANNOTATION.to_string(),
                hosts.join(","),
            );
        }
        self
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
    /// TLS configuration for the gateway (frontend mTLS, client cert validation)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<GatewayFrontendMtls>,
}

/// Gateway-level TLS configuration for frontend mTLS (client cert validation)
///
/// Distinct from per-listener `GatewayTlsConfig` — this is `spec.tls.frontend`
/// per the Gateway API spec for client certificate validation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GatewayFrontendMtls {
    /// Frontend TLS settings (client certificate validation)
    pub frontend: GatewayFrontendTls,
}

/// Frontend TLS configuration for client certificate validation
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GatewayFrontendTls {
    /// Default validation settings applied to all listeners
    pub default: GatewayFrontendTlsDefault,
}

/// Default frontend TLS validation settings
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GatewayFrontendTlsDefault {
    /// Validation configuration
    pub validation: GatewayFrontendValidation,
}

/// Frontend TLS validation — CA certificate references for client cert verification
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GatewayFrontendValidation {
    /// References to ConfigMaps containing PEM-encoded CA certificate bundles
    pub ca_certificate_refs: Vec<CaCertificateRef>,
}

/// Reference to a CA certificate for client verification
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CaCertificateRef {
    /// API group (empty string for core group)
    pub group: String,
    /// Kind of the referenced resource
    pub kind: String,
    /// Name of the ConfigMap containing the CA certificate bundle
    pub name: String,
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
    pub fn same_namespace() -> Self {
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
    pub fn gateway(name: &str, namespace: &str, section_name: impl Into<String>) -> Self {
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
