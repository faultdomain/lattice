//! Ingress module for Gateway API resources
//!
//! This module provides types and compilation logic for:
//! - **Gateway API**: Gateway, HTTPRoute for north-south ingress traffic
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

use lattice_common::crd::{IngressSpec, IngressTls, PathMatchType, TlsMode};
use lattice_common::kube_utils::HasApiResource;
use lattice_common::mesh;
use lattice_common::policy::{
    AuthorizationOperation, AuthorizationPolicy, AuthorizationPolicySpec, AuthorizationRule,
    OperationSpec, PolicyMetadata, WorkloadSelector,
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
    pub metadata: GatewayMetadata,
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
    pub fn new(metadata: GatewayMetadata, spec: GatewaySpec) -> Self {
        Self {
            api_version: Self::default_api_version(),
            kind: Self::default_kind(),
            metadata,
            spec,
        }
    }
}

/// Metadata for Gateway resources
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GatewayMetadata {
    /// Resource name
    pub name: String,
    /// Resource namespace
    pub namespace: String,
    /// Labels
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

impl GatewayMetadata {
    /// Create new metadata with standard Lattice labels
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        let mut labels = BTreeMap::new();
        labels.insert(
            lattice_common::LABEL_MANAGED_BY.to_string(),
            lattice_common::LABEL_MANAGED_BY_LATTICE.to_string(),
        );
        Self {
            name: name.into(),
            namespace: namespace.into(),
            labels,
        }
    }
}

/// Gateway spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GatewaySpec {
    /// GatewayClass name (e.g., "eg" or "istio-waypoint")
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
    /// Protocol (HTTP, HTTPS, HBONE, etc.)
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
    pub metadata: GatewayMetadata,
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
    pub fn new(metadata: GatewayMetadata, spec: HttpRouteSpec) -> Self {
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

/// Parent reference for HTTPRoute
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
    pub metadata: GatewayMetadata,
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
    pub fn new(metadata: GatewayMetadata, spec: CertificateSpec) -> Self {
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
    /// HTTPRoute resource
    pub http_route: Option<HttpRoute>,
    /// Certificate resource
    pub certificate: Option<Certificate>,
}

impl GeneratedIngress {
    /// Create empty generated ingress
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.gateway.is_none() && self.http_route.is_none() && self.certificate.is_none()
    }

    /// Total resource count
    pub fn total_count(&self) -> usize {
        [
            self.gateway.is_some(),
            self.http_route.is_some(),
            self.certificate.is_some(),
        ]
        .iter()
        .filter(|&&x| x)
        .count()
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
    /// Create empty generated waypoint
    pub fn new() -> Self {
        Self::default()
    }

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
// Waypoint AuthorizationPolicy Types
// =============================================================================

// =============================================================================
// Waypoint Compiler (Istio Native)
// =============================================================================

/// Compiler for generating Istio-native waypoint Gateway and associated policies
///
/// Uses `istio-waypoint` GatewayClass which:
/// - Speaks HBONE natively (no ztunnel port conflicts)
/// - Handles ambient mesh L7 policy enforcement
///
/// Generates:
/// - Waypoint Gateway for L7 policy enforcement
/// - `allow-to-waypoint` AuthorizationPolicy allowing traffic TO the waypoint
pub struct WaypointCompiler;

impl WaypointCompiler {
    /// Compile waypoint Gateway and policies for a namespace
    ///
    /// Generates:
    /// - Waypoint Gateway using istio-waypoint GatewayClass
    /// - `allow-to-waypoint` AuthorizationPolicy allowing any authenticated
    ///   traffic to reach the waypoint on port 15008 (HBONE)
    pub fn compile(namespace: &str) -> GeneratedWaypoint {
        GeneratedWaypoint {
            gateway: Some(Self::compile_gateway(namespace)),
            allow_to_waypoint_policy: Some(Self::compile_allow_to_waypoint_policy(namespace)),
        }
    }

    /// Compile waypoint Gateway
    ///
    /// Creates a namespace-scoped waypoint using Istio's native GatewayClass.
    /// Required labels:
    /// - `istio.io/waypoint-for: service` - handles service-destined traffic
    fn compile_gateway(namespace: &str) -> Gateway {
        let gateway_name = mesh::waypoint_name(namespace);
        let mut metadata = GatewayMetadata::new(&gateway_name, namespace);

        // Required label for Istio to recognize as service waypoint
        metadata.labels.insert(
            mesh::WAYPOINT_FOR_LABEL.to_string(),
            mesh::WAYPOINT_FOR_SERVICE.to_string(),
        );

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
                    allowed_routes: Some(AllowedRoutes {
                        namespaces: RouteNamespaces {
                            from: "Same".to_string(),
                        },
                    }),
                }],
            },
        )
    }

    /// Compile policy allowing traffic TO the waypoint on HBONE port
    ///
    /// This namespace-level policy allows any authenticated traffic to reach
    /// waypoint pods on port 15008 (HBONE). Without this, the mesh-default-deny
    /// policy would block traffic from services to the waypoint before L7
    /// policies can be evaluated.
    ///
    /// Traffic flow in ambient mode:
    /// 1. Source pod → ztunnel → waypoint:15008 (this policy allows this)
    /// 2. Waypoint evaluates L7 AuthorizationPolicy (allow-to-{service})
    /// 3. Waypoint → ztunnel → destination pod (allow-waypoint-to-{service})
    fn compile_allow_to_waypoint_policy(namespace: &str) -> AuthorizationPolicy {
        let mut match_labels = BTreeMap::new();
        match_labels.insert(
            mesh::WAYPOINT_FOR_LABEL.to_string(),
            mesh::WAYPOINT_FOR_SERVICE.to_string(),
        );

        AuthorizationPolicy::new(
            PolicyMetadata::new("allow-to-waypoint", namespace),
            AuthorizationPolicySpec {
                target_refs: vec![],
                selector: Some(WorkloadSelector { match_labels }),
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![], // Empty = any authenticated source
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
    /// Default GatewayClass for ingress (Envoy Gateway for north-south)
    const DEFAULT_GATEWAY_CLASS: &'static str = "eg";

    /// Compile ingress resources for a service
    pub fn compile(
        service_name: &str,
        namespace: &str,
        ingress: &IngressSpec,
        backend_port: u16,
    ) -> GeneratedIngress {
        let mut output = GeneratedIngress::new();

        output.gateway = Some(Self::compile_gateway(service_name, namespace, ingress));
        output.http_route = Some(Self::compile_http_route(
            service_name,
            namespace,
            ingress,
            backend_port,
        ));

        if let Some(ref tls) = ingress.tls {
            if tls.mode == TlsMode::Auto {
                output.certificate =
                    Self::compile_certificate(service_name, namespace, ingress, tls);
            }
        }

        output
    }

    fn compile_gateway(service_name: &str, namespace: &str, ingress: &IngressSpec) -> Gateway {
        let gateway_class = ingress
            .gateway_class
            .as_deref()
            .unwrap_or(Self::DEFAULT_GATEWAY_CLASS);

        let has_tls = ingress.tls.is_some();
        let secret_name = format!("{}-tls", service_name);

        let mut listeners = vec![GatewayListener {
            name: "http".to_string(),
            hostname: ingress.hosts.first().cloned(),
            port: 80,
            protocol: "HTTP".to_string(),
            tls: None,
            allowed_routes: Some(AllowedRoutes {
                namespaces: RouteNamespaces {
                    from: "Same".to_string(),
                },
            }),
        }];

        if has_tls {
            listeners.push(GatewayListener {
                name: "https".to_string(),
                hostname: ingress.hosts.first().cloned(),
                port: 443,
                protocol: "HTTPS".to_string(),
                tls: Some(GatewayTlsConfig {
                    mode: "Terminate".to_string(),
                    certificate_refs: vec![CertificateRef {
                        kind: Some("Secret".to_string()),
                        name: secret_name,
                    }],
                }),
                allowed_routes: Some(AllowedRoutes {
                    namespaces: RouteNamespaces {
                        from: "Same".to_string(),
                    },
                }),
            });
        }

        Gateway::new(
            GatewayMetadata::new(format!("{}-gateway", service_name), namespace),
            GatewaySpec {
                gateway_class_name: gateway_class.to_string(),
                listeners,
            },
        )
    }

    fn compile_http_route(
        service_name: &str,
        namespace: &str,
        ingress: &IngressSpec,
        backend_port: u16,
    ) -> HttpRoute {
        let matches: Vec<HttpRouteMatch> = if let Some(ref paths) = ingress.paths {
            paths
                .iter()
                .map(|p| HttpRouteMatch {
                    path: Some(HttpPathMatch {
                        type_: match p.path_type {
                            Some(PathMatchType::Exact) => "Exact",
                            Some(PathMatchType::PathPrefix) | None => "PathPrefix",
                        }
                        .to_string(),
                        value: p.path.clone(),
                    }),
                })
                .collect()
        } else {
            vec![HttpRouteMatch {
                path: Some(HttpPathMatch {
                    type_: "PathPrefix".to_string(),
                    value: "/".to_string(),
                }),
            }]
        };

        let parent_refs = vec![ParentRef {
            group: Some("gateway.networking.k8s.io".to_string()),
            kind: Some("Gateway".to_string()),
            name: format!("{}-gateway", service_name),
            namespace: Some(namespace.to_string()),
        }];

        HttpRoute::new(
            GatewayMetadata::new(format!("{}-route", service_name), namespace),
            HttpRouteSpec {
                parent_refs,
                hostnames: ingress.hosts.clone(),
                rules: vec![HttpRouteRule {
                    matches,
                    backend_refs: vec![BackendRef {
                        kind: Some("Service".to_string()),
                        name: service_name.to_string(),
                        port: backend_port,
                    }],
                }],
            },
        )
    }

    fn compile_certificate(
        service_name: &str,
        namespace: &str,
        ingress: &IngressSpec,
        tls: &IngressTls,
    ) -> Option<Certificate> {
        let issuer_ref = tls.issuer_ref.as_ref()?;

        Some(Certificate::new(
            GatewayMetadata::new(format!("{}-cert", service_name), namespace),
            CertificateSpec {
                secret_name: format!("{}-tls", service_name),
                dns_names: ingress.hosts.clone(),
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
    use lattice_common::crd::{CertIssuerRef, IngressPath};

    fn make_ingress_spec(hosts: Vec<&str>, with_tls: bool) -> IngressSpec {
        IngressSpec {
            hosts: hosts.into_iter().map(|s| s.to_string()).collect(),
            paths: None,
            tls: if with_tls {
                Some(IngressTls {
                    mode: TlsMode::Auto,
                    secret_name: None,
                    issuer_ref: Some(CertIssuerRef {
                        name: "letsencrypt-prod".to_string(),
                        kind: None,
                    }),
                })
            } else {
                None
            },
            gateway_class: None,
            rate_limit: None,
        }
    }

    // =========================================================================
    // Ingress Compiler Tests
    // =========================================================================

    #[test]
    fn generates_gateway_with_http_listener() {
        let ingress = make_ingress_spec(vec!["api.example.com"], false);
        let output = IngressCompiler::compile("api", "prod", &ingress, 8080);

        let gateway = output.gateway.expect("should have gateway");
        assert_eq!(gateway.metadata.name, "api-gateway");
        assert_eq!(gateway.metadata.namespace, "prod");
        assert_eq!(gateway.spec.gateway_class_name, "eg");
        assert_eq!(gateway.spec.listeners.len(), 1);

        let listener = &gateway.spec.listeners[0];
        assert_eq!(listener.name, "http");
        assert_eq!(listener.port, 80);
        assert_eq!(listener.protocol, "HTTP");
        assert!(listener.tls.is_none());
    }

    #[test]
    fn generates_gateway_with_https_listener() {
        let ingress = make_ingress_spec(vec!["api.example.com"], true);
        let output = IngressCompiler::compile("api", "prod", &ingress, 8080);

        let gateway = output.gateway.expect("should have gateway");
        assert_eq!(gateway.spec.listeners.len(), 2);

        let https_listener = &gateway.spec.listeners[1];
        assert_eq!(https_listener.name, "https");
        assert_eq!(https_listener.port, 443);
        assert_eq!(https_listener.protocol, "HTTPS");
        assert!(https_listener.tls.is_some());
    }

    #[test]
    fn generates_http_route() {
        let ingress = make_ingress_spec(vec!["api.example.com"], false);
        let output = IngressCompiler::compile("api", "prod", &ingress, 8080);

        let route = output.http_route.expect("should have route");
        assert_eq!(route.metadata.name, "api-route");
        assert_eq!(route.spec.hostnames, vec!["api.example.com"]);
        assert_eq!(route.spec.rules.len(), 1);

        let backend = &route.spec.rules[0].backend_refs[0];
        assert_eq!(backend.name, "api");
        assert_eq!(backend.port, 8080);
    }

    #[test]
    fn generates_certificate_for_auto_tls() {
        let ingress = make_ingress_spec(vec!["api.example.com"], true);
        let output = IngressCompiler::compile("api", "prod", &ingress, 8080);

        let cert = output.certificate.expect("should have certificate");
        assert_eq!(cert.metadata.name, "api-cert");
        assert_eq!(cert.spec.secret_name, "api-tls");
        assert_eq!(cert.spec.dns_names, vec!["api.example.com"]);
        assert_eq!(cert.spec.issuer_ref.name, "letsencrypt-prod");
    }

    #[test]
    fn custom_path_matches() {
        let mut ingress = make_ingress_spec(vec!["api.example.com"], false);
        ingress.paths = Some(vec![
            IngressPath {
                path: "/v1".to_string(),
                path_type: Some(PathMatchType::PathPrefix),
            },
            IngressPath {
                path: "/health".to_string(),
                path_type: Some(PathMatchType::Exact),
            },
        ]);

        let output = IngressCompiler::compile("api", "prod", &ingress, 8080);
        let route = output.http_route.expect("should have route");
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
        // from is empty = any authenticated source
        assert!(rule.from.is_empty());
        // to allows HBONE port
        assert_eq!(rule.to.len(), 1);
        assert_eq!(
            rule.to[0].operation.ports,
            vec![mesh::HBONE_PORT.to_string()]
        );
    }

    #[test]
    fn waypoint_total_count_includes_both_resources() {
        let output = WaypointCompiler::compile("mesh-test");

        // Gateway + AuthorizationPolicy = 2
        assert_eq!(output.total_count(), 2);
        assert!(!output.is_empty());
    }
}
