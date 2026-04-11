//! Ingress and Gateway API types.

use std::collections::BTreeMap;

use crate::crd::MeshMemberPort;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Ingress specification for exposing services externally via Gateway API.
///
/// Uses a named-routes map for multi-route support (HTTP, gRPC, TCP).
/// Happy-path: a single route with just `hosts` inherits everything else from
/// defaults or policy.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IngressSpec {
    /// GatewayClass name (default: "istio")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_class: Option<String>,

    /// Named routes — each key is a logical route name
    pub routes: BTreeMap<String, RouteSpec>,
}


/// Route kind — which Gateway API route resource to generate.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub enum RouteKind {
    /// Gateway API HTTPRoute (default)
    #[default]
    HTTPRoute,
    /// Gateway API GRPCRoute
    GRPCRoute,
    /// Gateway API TCPRoute
    TCPRoute,
}

/// A single named route within the ingress specification.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RouteSpec {
    /// Route kind — defaults to HTTPRoute when omitted
    #[serde(default)]
    pub kind: RouteKind,

    /// Hostnames for the route (required for HTTP/gRPC, forbidden for TCP)
    #[serde(default)]
    pub hosts: Vec<String>,

    /// Service port name to route to. Optional when service has exactly 1 port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,

    /// Listener port on the Gateway LB (required for TCP, optional otherwise)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,

    /// Routing rules — defaults to catch-all when omitted
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<RouteRule>>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<IngressTls>,
}

/// Configuration for advertising a route across clusters.
///
/// Presence of this struct means the route is advertised. Use `allowedServices`
/// to control which remote services can depend on it. `["*"]` allows all
/// (same pattern as bilateral agreement wildcards).
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AdvertiseConfig {
    /// Services allowed to reach this service from other clusters.
    ///
    /// Each entry is "namespace/name" (e.g., "edge/haproxy-fw") or "*" for all.
    /// Maps to SPIFFE principal: `{trust_domain}/ns/{namespace}/sa/{name}`.
    pub allowed_services: Vec<String>,
}

impl AdvertiseConfig {
    /// Returns true if all services are allowed (wildcard)
    pub fn is_open(&self) -> bool {
        self.allowed_services.iter().any(|s| s == "*")
    }

    /// Returns true if a specific service is allowed
    pub fn allows_service(&self, namespace: &str, name: &str) -> bool {
        if self.is_open() {
            return true;
        }
        let qualified = format!("{namespace}/{name}");
        self.allowed_services.iter().any(|s| s == &qualified)
    }

    /// Convert allowedServices to SPIFFE principals for AuthorizationPolicy.
    ///
    /// Each "namespace/name" entry becomes
    /// `{trust_domain}/ns/{namespace}/sa/{name}`.
    /// Wildcard entries are skipped (use is_open() to check).
    /// Malformed entries are logged as warnings and skipped.
    pub fn to_spiffe_principals(&self, trust_domain: &str) -> Vec<String> {
        self.allowed_services
            .iter()
            .filter(|s| *s != "*")
            .filter_map(|s| {
                let parts: Vec<&str> = s.splitn(2, '/').collect();
                if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
                    Some(crate::trust_domain::principal(
                        trust_domain, parts[0], parts[1],
                    ))
                } else {
                    tracing::warn!(
                        entry = %s,
                        "malformed allowedServices entry (expected namespace/name), skipping"
                    );
                    None
                }
            })
            .collect()
    }

    /// Validate the advertise config. Returns an error for malformed entries.
    pub fn validate(&self) -> Result<(), String> {
        for entry in &self.allowed_services {
            if entry == "*" {
                continue;
            }
            let parts: Vec<&str> = entry.splitn(2, '/').collect();
            if parts.len() != 2 || parts.iter().any(|p| p.is_empty()) {
                return Err(format!(
                    "invalid allowedServices entry '{}': must be 'namespace/name' or '*'",
                    entry
                ));
            }
        }
        Ok(())
    }
}

/// TLS configuration for ingress — mode is inferred from which fields are set.
///
/// | Fields present         | Behavior                                       |
/// |------------------------|------------------------------------------------|
/// | `issuerRef`            | Auto — cert-manager provisions certificate     |
/// | `secretName`           | Manual — user-provided TLS secret              |
/// | `tls: {}` (empty)      | Auto — inherit issuerRef from policy           |
/// | No `tls` field         | No TLS (unless policy provides it)             |
/// | Both fields            | Validation error                               |
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IngressTls {
    /// Secret name containing TLS certificate (manual mode)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,

    /// Cert-manager issuer reference (auto mode)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_ref: Option<CertIssuerRef>,
}

impl IngressTls {
    /// Returns true if this TLS config specifies auto mode (has issuer_ref)
    pub fn is_auto(&self) -> bool {
        self.issuer_ref.is_some()
    }

    /// Returns true if this TLS config specifies manual mode (has secret_name)
    pub fn is_manual(&self) -> bool {
        self.secret_name.is_some()
    }

    /// Returns true if both fields are empty (inherit from policy)
    pub fn is_empty_inherit(&self) -> bool {
        self.secret_name.is_none() && self.issuer_ref.is_none()
    }
}

/// Reference to a cert-manager issuer
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CertIssuerRef {
    /// Name of the issuer
    pub name: String,

    /// Kind of issuer (default: ClusterIssuer)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// A routing rule containing match conditions
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RouteRule {
    /// Match conditions — traffic must match at least one
    pub matches: Vec<RouteMatch>,
}

/// Match condition for a route rule
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RouteMatch {
    /// Path match (HTTPRoute only)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathMatch>,

    /// Header matches (HTTPRoute only)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<HeaderMatch>,

    /// HTTP method match (HTTPRoute only — GET, POST, etc.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// gRPC method match (GRPCRoute only)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_method: Option<GrpcMethodMatch>,
}

/// Path match for HTTPRoute
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PathMatch {
    /// Match type (PathPrefix or Exact)
    #[serde(rename = "type", default)]
    pub type_: PathMatchType,

    /// Path value
    pub value: String,
}

/// Path match type for Gateway API HTTPRoute
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathMatchType {
    /// Exact path match
    Exact,
    /// Prefix-based path match (default)
    #[default]
    PathPrefix,
}

/// Header match for HTTPRoute
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HeaderMatch {
    /// Header name
    pub name: String,
    /// Header value
    pub value: String,
    /// Match type (default: Exact)
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<HeaderMatchType>,
}

/// Header match type
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeaderMatchType {
    /// Exact header value match (default)
    Exact,
    /// Regular expression match
    RegularExpression,
}

/// gRPC method match for GRPCRoute
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GrpcMethodMatch {
    /// gRPC service name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// gRPC method name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

// =============================================================================
// Validation
// =============================================================================

impl IngressSpec {
    /// Validate the ingress spec against the service's ports.
    ///
    /// # Errors
    ///
    /// Returns an error string if validation fails.
    pub fn validate(&self, ports: &[MeshMemberPort]) -> Result<(), String> {
        if self.routes.is_empty() {
            return Err("ingress.routes must not be empty".to_string());
        }

        for (route_name, route) in &self.routes {
            lattice_core::validate_dns_label(route_name, "route name")?;
            route.validate(route_name, ports)?;
        }

        Ok(())
    }
}

impl RouteSpec {
    fn validate(&self, route_name: &str, ports: &[MeshMemberPort]) -> Result<(), String> {
        match self.kind {
            RouteKind::HTTPRoute | RouteKind::GRPCRoute => {
                if self.hosts.is_empty() {
                    return Err(format!(
                        "route '{}': hosts required for {:?}",
                        route_name, self.kind
                    ));
                }
                if self.listen_port.is_some() {
                    return Err(format!(
                        "route '{}': listenPort not allowed for {:?}",
                        route_name, self.kind
                    ));
                }
            }
            RouteKind::TCPRoute => {
                if !self.hosts.is_empty() {
                    return Err(format!(
                        "route '{}': hosts not allowed for TCPRoute",
                        route_name
                    ));
                }
                if self.listen_port.is_none() {
                    return Err(format!(
                        "route '{}': listenPort required for TCPRoute",
                        route_name
                    ));
                }
            }
        }

        // Port resolution validation
        let port_names: Vec<&str> = ports.iter().map(|p| p.name.as_str()).collect();
        if let Some(ref port_name) = self.port {
            if !ports.iter().any(|p| p.name == *port_name) {
                return Err(format!(
                    "route '{}': port '{}' not found in member ports (available: {:?})",
                    route_name, port_name, port_names
                ));
            }
        } else if ports.len() > 1 {
            return Err(format!(
                "route '{}': port must be specified when member has multiple ports (available: {:?})",
                route_name, port_names
            ));
        }

        // TLS validation
        if let Some(ref tls) = self.tls {
            if tls.issuer_ref.is_some() && tls.secret_name.is_some() {
                return Err(format!(
                    "route '{}': cannot specify both issuerRef and secretName in tls",
                    route_name
                ));
            }
            // TCPRoute + auto TLS (issuerRef) not supported
            if self.kind == RouteKind::TCPRoute && tls.is_auto() {
                return Err(format!(
                    "route '{}': TCPRoute only supports manual TLS (secretName), not auto (issuerRef)",
                    route_name
                ));
            }
        }

        // Match field consistency
        if let Some(ref rules) = self.rules {
            for rule in rules {
                for m in &rule.matches {
                    match self.kind {
                        RouteKind::HTTPRoute => {
                            if m.grpc_method.is_some() {
                                return Err(format!(
                                    "route '{}': grpcMethod not allowed on HTTPRoute matches",
                                    route_name
                                ));
                            }
                        }
                        RouteKind::GRPCRoute => {
                            if m.path.is_some() || !m.headers.is_empty() || m.method.is_some() {
                                return Err(format!(
                                    "route '{}': path/headers/method not allowed on GRPCRoute matches",
                                    route_name
                                ));
                            }
                        }
                        RouteKind::TCPRoute => {
                            if m.path.is_some()
                                || !m.headers.is_empty()
                                || m.method.is_some()
                                || m.grpc_method.is_some()
                            {
                                return Err(format!(
                                    "route '{}': match fields not allowed on TCPRoute",
                                    route_name
                                ));
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

// =============================================================================
// Port resolution helper
// =============================================================================

impl RouteSpec {
    /// Resolve the Service port number from mesh member ports.
    ///
    /// Returns `service_port` when available (port mapping case), otherwise `port`.
    /// Gateway API backendRefs reference the Kubernetes Service port, not the
    /// container target port.
    pub fn resolve_port(&self, ports: &[MeshMemberPort]) -> Result<u16, String> {
        if let Some(ref port_name) = self.port {
            ports
                .iter()
                .find(|p| p.name == *port_name)
                .map(|p| p.service_port.unwrap_or(p.port))
                .ok_or_else(|| format!("port '{}' not found in member ports", port_name))
        } else if ports.len() == 1 {
            Ok(ports[0].service_port.unwrap_or(ports[0].port))
        } else {
            Err(format!(
                "cannot infer port: member has {} ports, specify route.port explicitly",
                ports.len()
            ))
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::PeerAuth;

    fn single_port() -> Vec<MeshMemberPort> {
        vec![MeshMemberPort {
            port: 8080,
            service_port: None,
            name: "http".to_string(),
            peer_auth: PeerAuth::Strict,
        }]
    }

    fn multi_port() -> Vec<MeshMemberPort> {
        vec![
            MeshMemberPort {
                port: 8080,
                service_port: None,
                name: "http".to_string(),
                peer_auth: PeerAuth::Strict,
            },
            MeshMemberPort {
                port: 9090,
                service_port: None,
                name: "grpc".to_string(),
                peer_auth: PeerAuth::Strict,
            },
        ]
    }

    fn http_route(hosts: Vec<&str>) -> RouteSpec {
        RouteSpec {
            kind: RouteKind::HTTPRoute,
            hosts: hosts.into_iter().map(|s| s.to_string()).collect(),
            port: None,
            listen_port: None,
            rules: None,
            tls: None,
            advertise: None,
        }
    }

    #[test]
    fn valid_minimal_http_route() {
        let spec = IngressSpec {
            gateway_class: None,
            routes: BTreeMap::from([("public".to_string(), http_route(vec!["api.example.com"]))]),
        };
        assert!(spec.validate(&single_port()).is_ok());
    }

    #[test]
    fn empty_routes_fails() {
        let spec = IngressSpec {
            gateway_class: None,
            routes: BTreeMap::new(),
        };
        assert!(spec.validate(&[]).is_err());
    }

    #[test]
    fn http_route_missing_hosts_fails() {
        let spec = IngressSpec {
            gateway_class: None,
            routes: BTreeMap::from([("r".to_string(), http_route(vec![]))]),
        };
        assert!(spec.validate(&[]).is_err());
    }

    #[test]
    fn tcp_route_missing_listen_port_fails() {
        let spec = IngressSpec {
            gateway_class: None,
            routes: BTreeMap::from([(
                "tcp".to_string(),
                RouteSpec {
                    kind: RouteKind::TCPRoute,
                    hosts: vec![],
                    port: None,
                    listen_port: None,
                    rules: None,
                    tls: None,
                    advertise: None,
                },
            )]),
        };
        assert!(spec.validate(&single_port()).is_err());
    }

    #[test]
    fn tcp_route_with_hosts_fails() {
        let spec = IngressSpec {
            gateway_class: None,
            routes: BTreeMap::from([(
                "tcp".to_string(),
                RouteSpec {
                    kind: RouteKind::TCPRoute,
                    hosts: vec!["bad.example.com".to_string()],
                    port: None,
                    listen_port: Some(9090),
                    rules: None,
                    tls: None,
                    advertise: None,
                },
            )]),
        };
        assert!(spec.validate(&single_port()).is_err());
    }

    #[test]
    fn valid_tcp_route() {
        let spec = IngressSpec {
            gateway_class: None,
            routes: BTreeMap::from([(
                "metrics".to_string(),
                RouteSpec {
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
        assert!(spec.validate(&single_port()).is_ok());
    }

    #[test]
    fn port_required_with_multiple_ports() {
        let spec = IngressSpec {
            gateway_class: None,
            routes: BTreeMap::from([("r".to_string(), http_route(vec!["a.example.com"]))]),
        };
        assert!(spec.validate(&multi_port()).is_err());
    }

    #[test]
    fn port_inferred_with_single_port() {
        let spec = IngressSpec {
            gateway_class: None,
            routes: BTreeMap::from([("r".to_string(), http_route(vec!["a.example.com"]))]),
        };
        assert!(spec.validate(&single_port()).is_ok());
    }

    #[test]
    fn invalid_port_name_fails() {
        let mut route = http_route(vec!["a.example.com"]);
        route.port = Some("nonexistent".to_string());
        let spec = IngressSpec {
            gateway_class: None,
            routes: BTreeMap::from([("r".to_string(), route)]),
        };
        assert!(spec.validate(&single_port()).is_err());
    }

    #[test]
    fn tls_both_fields_fails() {
        let mut route = http_route(vec!["a.example.com"]);
        route.tls = Some(IngressTls {
            secret_name: Some("my-secret".to_string()),
            issuer_ref: Some(CertIssuerRef {
                name: "letsencrypt".to_string(),
                kind: None,
            }),
        });
        let spec = IngressSpec {
            gateway_class: None,
            routes: BTreeMap::from([("r".to_string(), route)]),
        };
        assert!(spec.validate(&single_port()).is_err());
    }

    #[test]
    fn tcp_auto_tls_fails() {
        let spec = IngressSpec {
            gateway_class: None,
            routes: BTreeMap::from([(
                "tcp".to_string(),
                RouteSpec {
                    kind: RouteKind::TCPRoute,
                    hosts: vec![],
                    port: None,
                    listen_port: Some(9090),
                    rules: None,
                    tls: Some(IngressTls {
                        secret_name: None,
                        issuer_ref: Some(CertIssuerRef {
                            name: "letsencrypt".to_string(),
                            kind: None,
                        }),
                    }),
                    advertise: None,
                },
            )]),
        };
        assert!(spec.validate(&single_port()).is_err());
    }

    #[test]
    fn grpc_method_on_http_route_fails() {
        let mut route = http_route(vec!["a.example.com"]);
        route.rules = Some(vec![RouteRule {
            matches: vec![RouteMatch {
                path: None,
                headers: vec![],
                method: None,
                grpc_method: Some(GrpcMethodMatch {
                    service: Some("Greeter".to_string()),
                    method: None,
                }),
            }],
        }]);
        let spec = IngressSpec {
            gateway_class: None,
            routes: BTreeMap::from([("r".to_string(), route)]),
        };
        assert!(spec.validate(&single_port()).is_err());
    }

    #[test]
    fn path_on_grpc_route_fails() {
        let spec = IngressSpec {
            gateway_class: None,
            routes: BTreeMap::from([(
                "grpc".to_string(),
                RouteSpec {
                    kind: RouteKind::GRPCRoute,
                    hosts: vec!["grpc.example.com".to_string()],
                    port: None,
                    listen_port: None,
                    rules: Some(vec![RouteRule {
                        matches: vec![RouteMatch {
                            path: Some(PathMatch {
                                type_: PathMatchType::PathPrefix,
                                value: "/".to_string(),
                            }),
                            headers: vec![],
                            method: None,
                            grpc_method: None,
                        }],
                    }]),
                    tls: None,
                    advertise: None,
                },
            )]),
        };
        assert!(spec.validate(&single_port()).is_err());
    }

    #[test]
    fn resolve_port_single() {
        let route = http_route(vec!["a.example.com"]);
        assert_eq!(route.resolve_port(&single_port()).unwrap(), 8080);
    }

    #[test]
    fn resolve_port_by_name() {
        let mut route = http_route(vec!["a.example.com"]);
        route.port = Some("grpc".to_string());
        assert_eq!(route.resolve_port(&multi_port()).unwrap(), 9090);
    }

    #[test]
    fn resolve_port_returns_service_port_when_set() {
        let route = http_route(vec!["a.example.com"]);
        let ports = vec![MeshMemberPort {
            port: 8080,
            service_port: Some(80),
            name: "http".to_string(),
            peer_auth: PeerAuth::Strict,
        }];
        assert_eq!(route.resolve_port(&ports).unwrap(), 80);
    }

    #[test]
    fn resolve_port_ambiguous() {
        let route = http_route(vec!["a.example.com"]);
        assert!(route.resolve_port(&multi_port()).is_err());
    }

    #[test]
    fn resolve_port_missing_name() {
        let mut route = http_route(vec!["a.example.com"]);
        route.port = Some("nonexistent".to_string());
        assert!(route.resolve_port(&single_port()).is_err());
    }

    #[test]
    fn tls_mode_inference() {
        let auto = IngressTls {
            secret_name: None,
            issuer_ref: Some(CertIssuerRef {
                name: "letsencrypt".to_string(),
                kind: None,
            }),
        };
        assert!(auto.is_auto());
        assert!(!auto.is_manual());

        let manual = IngressTls {
            secret_name: Some("my-cert".to_string()),
            issuer_ref: None,
        };
        assert!(!manual.is_auto());
        assert!(manual.is_manual());

        let empty = IngressTls::default();
        assert!(empty.is_empty_inherit());
    }

    #[test]
    fn route_name_with_underscores_fails() {
        let spec = IngressSpec {
            gateway_class: None,
            routes: BTreeMap::from([("my_route".to_string(), http_route(vec!["api.example.com"]))]),
        };
        let err = spec.validate(&single_port()).unwrap_err();
        assert!(err.contains("route name"));
    }

    #[test]
    fn valid_route_name_accepted() {
        let spec = IngressSpec {
            gateway_class: None,
            routes: BTreeMap::from([("public".to_string(), http_route(vec!["api.example.com"]))]),
        };
        assert!(spec.validate(&single_port()).is_ok());
    }

    #[test]
    fn advertise_defaults_to_none() {
        let json = r#"{ "hosts": ["api.example.com"] }"#;
        let route: RouteSpec = serde_json::from_str(json).unwrap();
        assert!(route.advertise.is_none());
    }

    #[test]
    fn advertise_wildcard_roundtrips() {
        let route = RouteSpec {
            kind: RouteKind::HTTPRoute,
            hosts: vec!["api.example.com".to_string()],
            port: None,
            listen_port: None,
            rules: None,
            tls: None,
            advertise: Some(AdvertiseConfig {
                allowed_services: vec!["*".to_string()],
            }),
        };
        let json = serde_json::to_string(&route).unwrap();
        let parsed: RouteSpec = serde_json::from_str(&json).unwrap();
        assert!(parsed.advertise.unwrap().is_open());
    }

    #[test]
    fn advertise_restricted_allows_listed_service() {
        let config = AdvertiseConfig {
            allowed_services: vec!["edge/haproxy-fw".to_string()],
        };
        assert!(config.allows_service("edge", "haproxy-fw"));
        assert!(!config.allows_service("other", "service"));
        assert!(!config.is_open());
    }

    #[test]
    fn advertise_wildcard_allows_all() {
        let config = AdvertiseConfig {
            allowed_services: vec!["*".to_string()],
        };
        assert!(config.is_open());
        assert!(config.allows_service("ns", "service"));
    }

    #[test]
    fn advertise_to_spiffe_principals() {
        let config = AdvertiseConfig {
            allowed_services: vec!["edge/haproxy-fw".to_string(), "*".to_string()],
        };
        let principals = config.to_spiffe_principals("lattice.abcd1234.local");
        assert_eq!(principals.len(), 1); // wildcard skipped
        assert_eq!(
            principals[0],
            "lattice.abcd1234.local/ns/edge/sa/haproxy-fw"
        );
    }
}
