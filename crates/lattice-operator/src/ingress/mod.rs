//! Ingress module for Gateway API resources
//!
//! This module provides types and compilation logic for Kubernetes Gateway API
//! resources (Gateway, HTTPRoute) and cert-manager Certificates for TLS.
//!
//! # Overview
//!
//! When a LatticeService specifies an `ingress` configuration, this module generates:
//! - **Gateway**: Per-service gateway with HTTP/HTTPS listeners
//! - **HTTPRoute**: Routes traffic from the gateway to the backend service
//! - **Certificate**: (Optional) cert-manager Certificate for automatic TLS provisioning
//!
//! # Example
//!
//! ```yaml
//! apiVersion: lattice.dev/v1alpha1
//! kind: LatticeService
//! metadata:
//!   name: api
//! spec:
//!   environment: prod
//!   ingress:
//!     hosts:
//!       - api.example.com
//!     tls:
//!       mode: auto
//!       issuerRef:
//!         name: letsencrypt-prod
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use lattice_common::crd::{IngressPath, IngressSpec, IngressTls, PathMatchType, TlsMode};

// =============================================================================
// Gateway API Types
// =============================================================================

/// Kubernetes Gateway API Gateway resource
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Gateway {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: GatewayMetadata,
    /// Spec
    pub spec: GatewaySpec,
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
            "app.kubernetes.io/managed-by".to_string(),
            "lattice".to_string(),
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
    /// GatewayClass name (e.g., "istio")
    pub gateway_class_name: String,
    /// Listeners for the gateway
    pub listeners: Vec<GatewayListener>,
}

/// Gateway listener configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GatewayListener {
    /// Listener name
    pub name: String,
    /// Hostname to match
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Port number
    pub port: u16,
    /// Protocol (HTTP, HTTPS)
    pub protocol: String,
    /// TLS configuration (for HTTPS)
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
    /// Kind (Secret)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Secret name
    pub name: String,
}

/// Allowed routes for a gateway listener
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AllowedRoutes {
    /// Namespaces that can attach routes
    pub namespaces: RouteNamespaces,
}

/// Route namespace selector
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RouteNamespaces {
    /// From selector: Same, All, or Selector
    pub from: String,
}

// =============================================================================
// HTTPRoute Types
// =============================================================================

/// Kubernetes Gateway API HTTPRoute resource
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpRoute {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: GatewayMetadata,
    /// Spec
    pub spec: HttpRouteSpec,
}

/// HTTPRoute spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpRouteSpec {
    /// Parent references (Gateway)
    pub parent_refs: Vec<ParentRef>,
    /// Hostnames to match
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,
    /// Routing rules
    pub rules: Vec<HttpRouteRule>,
}

/// Reference to a parent Gateway
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ParentRef {
    /// Group (gateway.networking.k8s.io)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Kind (Gateway)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Gateway name
    pub name: String,
    /// Namespace
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// HTTPRoute routing rule
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpRouteRule {
    /// Match conditions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matches: Vec<HttpRouteMatch>,
    /// Backend references
    pub backend_refs: Vec<BackendRef>,
}

/// HTTPRoute match condition
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpRouteMatch {
    /// Path match
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<HttpPathMatch>,
}

/// HTTP path match configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpPathMatch {
    /// Match type (Exact, PathPrefix)
    #[serde(rename = "type")]
    pub type_: String,
    /// Path value
    pub value: String,
}

/// Reference to a backend service
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackendRef {
    /// Kind (Service)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Service name
    pub name: String,
    /// Port
    pub port: u16,
}

// =============================================================================
// cert-manager Certificate
// =============================================================================

/// cert-manager Certificate resource
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Certificate {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: GatewayMetadata,
    /// Spec
    pub spec: CertificateSpec,
}

/// Certificate spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CertificateSpec {
    /// Secret name to store the certificate
    pub secret_name: String,
    /// DNS names for the certificate
    pub dns_names: Vec<String>,
    /// Issuer reference
    pub issuer_ref: IssuerRef,
}

/// Reference to a cert-manager issuer
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IssuerRef {
    /// Issuer name
    pub name: String,
    /// Issuer kind (Issuer or ClusterIssuer)
    pub kind: String,
    /// Issuer group
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

// =============================================================================
// Generated Ingress Container
// =============================================================================

/// Collection of all ingress resources generated for a service
#[derive(Clone, Debug, Default)]
pub struct GeneratedIngress {
    /// Gateway resource
    pub gateway: Option<Gateway>,
    /// HTTPRoute resource
    pub http_route: Option<HttpRoute>,
    /// cert-manager Certificate resource
    pub certificate: Option<Certificate>,
}

impl GeneratedIngress {
    /// Create empty ingress collection
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if any resources were generated
    pub fn is_empty(&self) -> bool {
        self.gateway.is_none() && self.http_route.is_none() && self.certificate.is_none()
    }

    /// Total count of all generated resources
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

// =============================================================================
// Ingress Compiler
// =============================================================================

/// Compiler for generating Gateway API resources from LatticeService ingress config
pub struct IngressCompiler;

impl IngressCompiler {
    /// Default GatewayClass for Istio
    const DEFAULT_GATEWAY_CLASS: &'static str = "istio";

    /// Compile ingress resources for a service
    ///
    /// # Arguments
    /// * `service_name` - Name of the LatticeService
    /// * `namespace` - Target namespace
    /// * `ingress` - Ingress specification from the service
    /// * `backend_port` - Primary service port for routing
    ///
    /// # Returns
    /// Generated Gateway API resources
    pub fn compile(
        service_name: &str,
        namespace: &str,
        ingress: &IngressSpec,
        backend_port: u16,
    ) -> GeneratedIngress {
        let mut output = GeneratedIngress::new();

        // Compile Gateway
        output.gateway = Some(Self::compile_gateway(service_name, namespace, ingress));

        // Compile HTTPRoute
        output.http_route = Some(Self::compile_http_route(
            service_name,
            namespace,
            ingress,
            backend_port,
        ));

        // Compile Certificate if TLS auto mode
        if let Some(ref tls) = ingress.tls {
            if tls.mode == TlsMode::Auto {
                output.certificate =
                    Self::compile_certificate(service_name, namespace, ingress, tls);
            }
        }

        output
    }

    /// Compile a Gateway resource
    fn compile_gateway(service_name: &str, namespace: &str, ingress: &IngressSpec) -> Gateway {
        let gateway_name = format!("{}-gateway", service_name);
        let gateway_class = ingress
            .gateway_class
            .as_deref()
            .unwrap_or(Self::DEFAULT_GATEWAY_CLASS);

        let mut listeners: Vec<GatewayListener> = Vec::new();

        // Create listeners for each host
        for (idx, host) in ingress.hosts.iter().enumerate() {
            let host_str: String = host.to_string();
            let listener_name = if idx == 0 {
                "http".to_string()
            } else {
                format!("http-{}", idx)
            };

            // HTTP listener
            listeners.push(GatewayListener {
                name: listener_name.clone(),
                hostname: Some(host_str.clone()),
                port: 80,
                protocol: "HTTP".to_string(),
                tls: None,
                allowed_routes: Some(AllowedRoutes {
                    namespaces: RouteNamespaces {
                        from: "Same".to_string(),
                    },
                }),
            });

            // HTTPS listener if TLS is configured
            if let Some(ref tls) = ingress.tls {
                let https_listener_name = if idx == 0 {
                    "https".to_string()
                } else {
                    format!("https-{}", idx)
                };

                let secret_name = Self::get_tls_secret_name(service_name, tls);

                listeners.push(GatewayListener {
                    name: https_listener_name,
                    hostname: Some(host_str.clone()),
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
        }

        Gateway {
            api_version: "gateway.networking.k8s.io/v1".to_string(),
            kind: "Gateway".to_string(),
            metadata: GatewayMetadata::new(gateway_name, namespace),
            spec: GatewaySpec {
                gateway_class_name: gateway_class.to_string(),
                listeners,
            },
        }
    }

    /// Compile an HTTPRoute resource
    fn compile_http_route(
        service_name: &str,
        namespace: &str,
        ingress: &IngressSpec,
        backend_port: u16,
    ) -> HttpRoute {
        let route_name = format!("{}-route", service_name);
        let gateway_name = format!("{}-gateway", service_name);

        // Build path matches
        let matches: Vec<HttpRouteMatch> = ingress
            .paths
            .as_ref()
            .map(|paths: &Vec<IngressPath>| {
                paths
                    .iter()
                    .map(|p| HttpRouteMatch {
                        path: Some(HttpPathMatch {
                            type_: match p.path_type.as_ref().unwrap_or(&PathMatchType::PathPrefix)
                            {
                                PathMatchType::Exact => "Exact".to_string(),
                                PathMatchType::PathPrefix => "PathPrefix".to_string(),
                            },
                            value: p.path.clone(),
                        }),
                    })
                    .collect()
            })
            .unwrap_or_else(|| {
                // Default to "/" prefix match
                vec![HttpRouteMatch {
                    path: Some(HttpPathMatch {
                        type_: "PathPrefix".to_string(),
                        value: "/".to_string(),
                    }),
                }]
            });

        HttpRoute {
            api_version: "gateway.networking.k8s.io/v1".to_string(),
            kind: "HTTPRoute".to_string(),
            metadata: GatewayMetadata::new(route_name, namespace),
            spec: HttpRouteSpec {
                parent_refs: vec![ParentRef {
                    group: Some("gateway.networking.k8s.io".to_string()),
                    kind: Some("Gateway".to_string()),
                    name: gateway_name,
                    namespace: Some(namespace.to_string()),
                }],
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
        }
    }

    /// Compile a cert-manager Certificate resource
    fn compile_certificate(
        service_name: &str,
        namespace: &str,
        ingress: &IngressSpec,
        tls: &IngressTls,
    ) -> Option<Certificate> {
        let issuer_ref = tls.issuer_ref.as_ref()?;

        let cert_name = format!("{}-tls", service_name);
        let secret_name = Self::get_tls_secret_name(service_name, tls);

        Some(Certificate {
            api_version: "cert-manager.io/v1".to_string(),
            kind: "Certificate".to_string(),
            metadata: GatewayMetadata::new(cert_name, namespace),
            spec: CertificateSpec {
                secret_name,
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
        })
    }

    /// Get the TLS secret name for a service
    fn get_tls_secret_name(service_name: &str, tls: &IngressTls) -> String {
        tls.secret_name
            .clone()
            .unwrap_or_else(|| format!("{}-tls", service_name))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::CertIssuerRef;

    fn sample_ingress_spec() -> IngressSpec {
        IngressSpec {
            hosts: vec!["api.example.com".to_string()],
            paths: None,
            tls: None,
            gateway_class: None,
        }
    }

    fn sample_ingress_with_tls() -> IngressSpec {
        IngressSpec {
            hosts: vec!["api.example.com".to_string()],
            paths: None,
            tls: Some(IngressTls {
                mode: TlsMode::Auto,
                secret_name: None,
                issuer_ref: Some(CertIssuerRef {
                    name: "letsencrypt-prod".to_string(),
                    kind: None,
                }),
            }),
            gateway_class: None,
        }
    }

    // =========================================================================
    // Gateway Compilation Tests
    // =========================================================================

    #[test]
    fn story_gateway_without_tls() {
        let ingress = sample_ingress_spec();
        let gateway = IngressCompiler::compile_gateway("my-api", "prod", &ingress);

        assert_eq!(gateway.metadata.name, "my-api-gateway");
        assert_eq!(gateway.metadata.namespace, "prod");
        assert_eq!(gateway.spec.gateway_class_name, "istio");
        assert_eq!(gateway.spec.listeners.len(), 1);

        let listener = &gateway.spec.listeners[0];
        assert_eq!(listener.name, "http");
        assert_eq!(listener.port, 80);
        assert_eq!(listener.protocol, "HTTP");
        assert!(listener.tls.is_none());
    }

    #[test]
    fn story_gateway_with_tls() {
        let ingress = sample_ingress_with_tls();
        let gateway = IngressCompiler::compile_gateway("my-api", "prod", &ingress);

        assert_eq!(gateway.spec.listeners.len(), 2);

        let http_listener = &gateway.spec.listeners[0];
        assert_eq!(http_listener.name, "http");
        assert_eq!(http_listener.port, 80);

        let https_listener = &gateway.spec.listeners[1];
        assert_eq!(https_listener.name, "https");
        assert_eq!(https_listener.port, 443);
        assert_eq!(https_listener.protocol, "HTTPS");
        assert!(https_listener.tls.is_some());

        let tls = https_listener.tls.as_ref().unwrap();
        assert_eq!(tls.mode, "Terminate");
        assert_eq!(tls.certificate_refs[0].name, "my-api-tls");
    }

    #[test]
    fn story_gateway_with_multiple_hosts() {
        let ingress = IngressSpec {
            hosts: vec!["api.example.com".to_string(), "api.example.org".to_string()],
            paths: None,
            tls: None,
            gateway_class: None,
        };
        let gateway = IngressCompiler::compile_gateway("my-api", "prod", &ingress);

        assert_eq!(gateway.spec.listeners.len(), 2);
        assert_eq!(gateway.spec.listeners[0].name, "http");
        assert_eq!(gateway.spec.listeners[1].name, "http-1");
    }

    #[test]
    fn story_gateway_custom_gateway_class() {
        let ingress = IngressSpec {
            hosts: vec!["api.example.com".to_string()],
            paths: None,
            tls: None,
            gateway_class: Some("nginx".to_string()),
        };
        let gateway = IngressCompiler::compile_gateway("my-api", "prod", &ingress);

        assert_eq!(gateway.spec.gateway_class_name, "nginx");
    }

    // =========================================================================
    // HTTPRoute Compilation Tests
    // =========================================================================

    #[test]
    fn story_http_route_default_path() {
        let ingress = sample_ingress_spec();
        let route = IngressCompiler::compile_http_route("my-api", "prod", &ingress, 8080);

        assert_eq!(route.metadata.name, "my-api-route");
        assert_eq!(route.metadata.namespace, "prod");
        assert_eq!(route.spec.hostnames, vec!["api.example.com"]);

        let parent = &route.spec.parent_refs[0];
        assert_eq!(parent.name, "my-api-gateway");

        let rule = &route.spec.rules[0];
        let path_match = rule.matches[0].path.as_ref().unwrap();
        assert_eq!(path_match.type_, "PathPrefix");
        assert_eq!(path_match.value, "/");

        let backend = &rule.backend_refs[0];
        assert_eq!(backend.name, "my-api");
        assert_eq!(backend.port, 8080);
    }

    #[test]
    fn story_http_route_custom_paths() {
        let ingress = IngressSpec {
            hosts: vec!["api.example.com".to_string()],
            paths: Some(vec![
                IngressPath {
                    path: "/v1".to_string(),
                    path_type: Some(PathMatchType::PathPrefix),
                },
                IngressPath {
                    path: "/health".to_string(),
                    path_type: Some(PathMatchType::Exact),
                },
            ]),
            tls: None,
            gateway_class: None,
        };
        let route = IngressCompiler::compile_http_route("my-api", "prod", &ingress, 8080);

        let matches = &route.spec.rules[0].matches;
        assert_eq!(matches.len(), 2);

        let path1 = matches[0].path.as_ref().unwrap();
        assert_eq!(path1.type_, "PathPrefix");
        assert_eq!(path1.value, "/v1");

        let path2 = matches[1].path.as_ref().unwrap();
        assert_eq!(path2.type_, "Exact");
        assert_eq!(path2.value, "/health");
    }

    // =========================================================================
    // Certificate Compilation Tests
    // =========================================================================

    #[test]
    fn story_certificate_auto_mode() {
        let ingress = sample_ingress_with_tls();
        let tls = ingress.tls.as_ref().unwrap();
        let cert = IngressCompiler::compile_certificate("my-api", "prod", &ingress, tls);

        let cert = cert.unwrap();
        assert_eq!(cert.metadata.name, "my-api-tls");
        assert_eq!(cert.metadata.namespace, "prod");
        assert_eq!(cert.spec.secret_name, "my-api-tls");
        assert_eq!(cert.spec.dns_names, vec!["api.example.com"]);

        let issuer = &cert.spec.issuer_ref;
        assert_eq!(issuer.name, "letsencrypt-prod");
        assert_eq!(issuer.kind, "ClusterIssuer");
    }

    #[test]
    fn story_certificate_with_custom_secret() {
        let ingress = IngressSpec {
            hosts: vec!["api.example.com".to_string()],
            paths: None,
            tls: Some(IngressTls {
                mode: TlsMode::Auto,
                secret_name: Some("custom-tls-secret".to_string()),
                issuer_ref: Some(CertIssuerRef {
                    name: "letsencrypt-prod".to_string(),
                    kind: Some("Issuer".to_string()),
                }),
            }),
            gateway_class: None,
        };
        let tls = ingress.tls.as_ref().unwrap();
        let cert = IngressCompiler::compile_certificate("my-api", "prod", &ingress, tls);

        let cert = cert.unwrap();
        assert_eq!(cert.spec.secret_name, "custom-tls-secret");
        assert_eq!(cert.spec.issuer_ref.kind, "Issuer");
    }

    #[test]
    fn story_no_certificate_for_manual_mode() {
        let ingress = IngressSpec {
            hosts: vec!["api.example.com".to_string()],
            paths: None,
            tls: Some(IngressTls {
                mode: TlsMode::Manual,
                secret_name: Some("my-tls-secret".to_string()),
                issuer_ref: None,
            }),
            gateway_class: None,
        };

        let output = IngressCompiler::compile("my-api", "prod", &ingress, 8080);

        // Should have gateway and route, but no certificate
        assert!(output.gateway.is_some());
        assert!(output.http_route.is_some());
        assert!(output.certificate.is_none());
    }

    // =========================================================================
    // Full Compilation Tests
    // =========================================================================

    #[test]
    fn story_full_compilation() {
        let ingress = sample_ingress_with_tls();
        let output = IngressCompiler::compile("my-api", "prod", &ingress, 8080);

        assert!(output.gateway.is_some());
        assert!(output.http_route.is_some());
        assert!(output.certificate.is_some());
        assert_eq!(output.total_count(), 3);
    }

    #[test]
    fn story_minimal_compilation() {
        let ingress = sample_ingress_spec();
        let output = IngressCompiler::compile("my-api", "prod", &ingress, 8080);

        assert!(output.gateway.is_some());
        assert!(output.http_route.is_some());
        assert!(output.certificate.is_none());
        assert_eq!(output.total_count(), 2);
    }

    // =========================================================================
    // Utility Method Tests
    // =========================================================================

    #[test]
    fn test_generated_ingress_is_empty() {
        let empty = GeneratedIngress::new();
        assert!(empty.is_empty());

        let ingress = sample_ingress_spec();
        let output = IngressCompiler::compile("my-api", "prod", &ingress, 8080);
        assert!(!output.is_empty());
    }

    #[test]
    fn test_metadata_labels() {
        let metadata = GatewayMetadata::new("test", "prod");
        assert_eq!(
            metadata.labels.get("app.kubernetes.io/managed-by"),
            Some(&"lattice".to_string())
        );
    }
}
