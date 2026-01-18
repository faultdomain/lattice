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

use lattice_common::crd::{
    IngressPath, IngressSpec, IngressTls, PathMatchType, RateLimitSpec, TlsMode,
};

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
// kgateway TrafficPolicy (for rate limiting)
// =============================================================================

/// kgateway TrafficPolicy resource for rate limiting and traffic control
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TrafficPolicy {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: GatewayMetadata,
    /// Spec
    pub spec: TrafficPolicySpec,
}

/// TrafficPolicy spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TrafficPolicySpec {
    /// Target references (HTTPRoute or Service)
    pub target_refs: Vec<PolicyTargetRef>,
    /// Rate limit configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<PolicyRateLimit>,
    /// Retry configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<PolicyRetry>,
    /// Timeout configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<PolicyTimeout>,
    /// Circuit breaker configuration (via connection_limits)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_limits: Option<PolicyConnectionLimits>,
    /// Request header modification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_header_modifier: Option<PolicyHeaderModifier>,
}

/// Target reference for policy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyTargetRef {
    /// Group
    pub group: String,
    /// Kind
    pub kind: String,
    /// Name
    pub name: String,
}

/// Rate limit configuration in TrafficPolicy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRateLimit {
    /// Local rate limiting (in-proxy, no external service)
    pub local: LocalRateLimit,
}

/// Local rate limit using token bucket
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LocalRateLimit {
    /// Token bucket configuration
    pub token_bucket: TokenBucket,
}

/// Token bucket rate limiting configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TokenBucket {
    /// Maximum tokens in bucket (burst capacity)
    pub max_tokens: u32,
    /// Tokens added per fill
    pub tokens_per_fill: u32,
    /// Fill interval (e.g., "60s")
    pub fill_interval: String,
}

/// Retry policy for TrafficPolicy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRetry {
    /// Number of retries
    pub num_retries: u32,
    /// Per-try timeout
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_try_timeout: Option<String>,
    /// Retry on specific conditions (e.g., "5xx", "reset", "connect-failure")
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retry_on: Vec<String>,
}

/// Timeout configuration for TrafficPolicy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyTimeout {
    /// Request timeout
    pub request: String,
    /// Idle timeout
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle: Option<String>,
}

/// Connection limits for circuit breaking
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyConnectionLimits {
    /// Maximum pending requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_pending_requests: Option<u32>,
    /// Maximum concurrent requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests: Option<u32>,
    /// Maximum concurrent retries
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_retries: Option<u32>,
}

/// Header modification for TrafficPolicy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyHeaderModifier {
    /// Headers to add
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add: Vec<PolicyHeader>,
    /// Headers to remove
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<String>,
}

/// Header key-value pair
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyHeader {
    /// Header name
    pub name: String,
    /// Header value
    pub value: String,
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
    /// kgateway TrafficPolicy for rate limiting
    pub traffic_policy: Option<TrafficPolicy>,
}

impl GeneratedIngress {
    /// Create empty ingress collection
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if any resources were generated
    pub fn is_empty(&self) -> bool {
        self.gateway.is_none()
            && self.http_route.is_none()
            && self.certificate.is_none()
            && self.traffic_policy.is_none()
    }

    /// Total count of all generated resources
    pub fn total_count(&self) -> usize {
        [
            self.gateway.is_some(),
            self.http_route.is_some(),
            self.certificate.is_some(),
            self.traffic_policy.is_some(),
        ]
        .iter()
        .filter(|&&x| x)
        .count()
    }
}

// =============================================================================
// Generated Waypoint Policies Container
// =============================================================================

/// Collection of waypoint TrafficPolicy resources for east-west L7 traffic
#[derive(Clone, Debug, Default)]
pub struct GeneratedWaypointPolicies {
    /// Outbound policies (caller-side: retries, timeouts, circuit breakers)
    pub outbound_policies: Vec<TrafficPolicy>,
    /// Inbound policies (callee-side: rate limits, headers)
    pub inbound_policies: Vec<TrafficPolicy>,
}

impl GeneratedWaypointPolicies {
    /// Create empty waypoint policies collection
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if any policies were generated
    pub fn is_empty(&self) -> bool {
        self.outbound_policies.is_empty() && self.inbound_policies.is_empty()
    }

    /// Total count of all generated policies
    pub fn total_count(&self) -> usize {
        self.outbound_policies.len() + self.inbound_policies.len()
    }
}

// =============================================================================
// Ingress Compiler
// =============================================================================

/// Compiler for generating Gateway API resources from LatticeService ingress config
pub struct IngressCompiler;

impl IngressCompiler {
    /// Default GatewayClass for kgateway
    const DEFAULT_GATEWAY_CLASS: &'static str = "kgateway";

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

        // Compile TrafficPolicy if rate limiting is configured
        if let Some(ref rate_limit) = ingress.rate_limit {
            output.traffic_policy =
                Some(Self::compile_traffic_policy(service_name, namespace, rate_limit));
        }

        output
    }

    /// Compile a kgateway TrafficPolicy for rate limiting
    fn compile_traffic_policy(
        service_name: &str,
        namespace: &str,
        rate_limit: &RateLimitSpec,
    ) -> TrafficPolicy {
        let policy_name = format!("{}-rate-limit", service_name);
        let route_name = format!("{}-route", service_name);

        // Use burst if specified, otherwise default to requests_per_interval
        let burst = rate_limit.burst.unwrap_or(rate_limit.requests_per_interval);

        TrafficPolicy {
            api_version: "gateway.kgateway.dev/v1alpha1".to_string(),
            kind: "TrafficPolicy".to_string(),
            metadata: GatewayMetadata::new(policy_name, namespace),
            spec: TrafficPolicySpec {
                target_refs: vec![PolicyTargetRef {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    name: route_name,
                }],
                rate_limit: Some(PolicyRateLimit {
                    local: LocalRateLimit {
                        token_bucket: TokenBucket {
                            max_tokens: burst,
                            tokens_per_fill: rate_limit.requests_per_interval,
                            fill_interval: format!("{}s", rate_limit.interval_seconds),
                        },
                    },
                }),
                retry: None,
                timeout: None,
                connection_limits: None,
                request_header_modifier: None,
            },
        }
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
// Waypoint Policy Compiler
// =============================================================================

use lattice_common::crd::{
    CircuitBreakerPolicy, HeaderPolicy, InboundTrafficPolicy, OutboundTrafficPolicy, ResourceSpec,
    RetryPolicy, TimeoutPolicy,
};

/// Compiler for generating kgateway waypoint TrafficPolicy from ResourceSpec L7 policies
pub struct WaypointPolicyCompiler;

impl WaypointPolicyCompiler {
    /// Compile waypoint policies for a service's resource dependencies
    ///
    /// # Arguments
    /// * `service_name` - Name of the source LatticeService
    /// * `namespace` - Target namespace
    /// * `resources` - Map of resource name to ResourceSpec
    ///
    /// # Returns
    /// Generated waypoint TrafficPolicy resources for east-west traffic
    pub fn compile(
        service_name: &str,
        namespace: &str,
        resources: &std::collections::BTreeMap<String, ResourceSpec>,
    ) -> GeneratedWaypointPolicies {
        let mut output = GeneratedWaypointPolicies::new();

        for (resource_name, resource) in resources {
            // Only process service resources
            if !matches!(
                resource.type_,
                lattice_common::crd::ResourceType::Service
            ) {
                continue;
            }

            // Compile outbound policy (caller-side)
            if let Some(ref outbound) = resource.outbound {
                if let Some(policy) = Self::compile_outbound_policy(
                    service_name,
                    resource_name,
                    namespace,
                    outbound,
                ) {
                    output.outbound_policies.push(policy);
                }
            }

            // Compile inbound policy (callee-side)
            if let Some(ref inbound) = resource.inbound {
                if let Some(policy) = Self::compile_inbound_policy(
                    service_name,
                    resource_name,
                    namespace,
                    inbound,
                ) {
                    output.inbound_policies.push(policy);
                }
            }
        }

        output
    }

    /// Compile outbound TrafficPolicy (retries, timeouts, circuit breakers)
    fn compile_outbound_policy(
        caller: &str,
        callee: &str,
        namespace: &str,
        outbound: &OutboundTrafficPolicy,
    ) -> Option<TrafficPolicy> {
        // Skip if no policies configured
        if outbound.retries.is_none()
            && outbound.timeout.is_none()
            && outbound.circuit_breaker.is_none()
        {
            return None;
        }

        let policy_name = format!("{}-to-{}-outbound", caller, callee);

        Some(TrafficPolicy {
            api_version: "gateway.kgateway.dev/v1alpha1".to_string(),
            kind: "TrafficPolicy".to_string(),
            metadata: GatewayMetadata::new(policy_name, namespace),
            spec: TrafficPolicySpec {
                target_refs: vec![PolicyTargetRef {
                    group: String::new(),
                    kind: "Service".to_string(),
                    name: callee.to_string(),
                }],
                rate_limit: None,
                retry: outbound.retries.as_ref().map(Self::convert_retry_policy),
                timeout: outbound.timeout.as_ref().map(Self::convert_timeout_policy),
                connection_limits: outbound
                    .circuit_breaker
                    .as_ref()
                    .map(Self::convert_circuit_breaker),
                request_header_modifier: None,
            },
        })
    }

    /// Compile inbound TrafficPolicy (rate limits, headers)
    fn compile_inbound_policy(
        caller: &str,
        callee: &str,
        namespace: &str,
        inbound: &InboundTrafficPolicy,
    ) -> Option<TrafficPolicy> {
        // Skip if no policies configured
        if inbound.rate_limit.is_none() && inbound.headers.is_none() {
            return None;
        }

        let policy_name = format!("{}-from-{}-inbound", callee, caller);

        Some(TrafficPolicy {
            api_version: "gateway.kgateway.dev/v1alpha1".to_string(),
            kind: "TrafficPolicy".to_string(),
            metadata: GatewayMetadata::new(policy_name, namespace),
            spec: TrafficPolicySpec {
                target_refs: vec![PolicyTargetRef {
                    group: String::new(),
                    kind: "Service".to_string(),
                    name: callee.to_string(),
                }],
                rate_limit: inbound.rate_limit.as_ref().map(|rl| PolicyRateLimit {
                    local: LocalRateLimit {
                        token_bucket: TokenBucket {
                            max_tokens: rl.burst.unwrap_or(rl.requests_per_interval),
                            tokens_per_fill: rl.requests_per_interval,
                            fill_interval: format!("{}s", rl.interval_seconds),
                        },
                    },
                }),
                retry: None,
                timeout: None,
                connection_limits: None,
                request_header_modifier: inbound.headers.as_ref().map(Self::convert_header_policy),
            },
        })
    }

    fn convert_retry_policy(retry: &RetryPolicy) -> PolicyRetry {
        PolicyRetry {
            num_retries: retry.attempts,
            per_try_timeout: retry.per_try_timeout.clone(),
            retry_on: retry.retry_on.clone(),
        }
    }

    fn convert_timeout_policy(timeout: &TimeoutPolicy) -> PolicyTimeout {
        PolicyTimeout {
            request: timeout.request.clone(),
            idle: timeout.idle.clone(),
        }
    }

    fn convert_circuit_breaker(cb: &CircuitBreakerPolicy) -> PolicyConnectionLimits {
        PolicyConnectionLimits {
            max_pending_requests: cb.max_pending_requests,
            max_requests: cb.max_requests,
            max_retries: cb.max_retries,
        }
    }

    fn convert_header_policy(headers: &HeaderPolicy) -> PolicyHeaderModifier {
        PolicyHeaderModifier {
            add: headers
                .add
                .iter()
                .map(|(k, v)| PolicyHeader {
                    name: k.clone(),
                    value: v.clone(),
                })
                .collect(),
            remove: headers.remove.clone(),
        }
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
            rate_limit: None,
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
            rate_limit: None,
            gateway_class: None,
        }
    }

    fn sample_ingress_with_rate_limit() -> IngressSpec {
        IngressSpec {
            hosts: vec!["api.example.com".to_string()],
            paths: None,
            tls: None,
            rate_limit: Some(RateLimitSpec {
                requests_per_interval: 100,
                interval_seconds: 60,
                burst: Some(150),
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
        assert_eq!(gateway.spec.gateway_class_name, "kgateway");
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
            rate_limit: None,
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
            rate_limit: None,
            gateway_class: Some("custom-gateway".to_string()),
        };
        let gateway = IngressCompiler::compile_gateway("my-api", "prod", &ingress);

        assert_eq!(gateway.spec.gateway_class_name, "custom-gateway");
    }

    // =========================================================================
    // TrafficPolicy (Rate Limiting) Tests
    // =========================================================================

    #[test]
    fn story_traffic_policy_rate_limiting() {
        let rate_limit = RateLimitSpec {
            requests_per_interval: 100,
            interval_seconds: 60,
            burst: Some(150),
        };
        let policy = IngressCompiler::compile_traffic_policy("my-api", "prod", &rate_limit);

        assert_eq!(policy.metadata.name, "my-api-rate-limit");
        assert_eq!(policy.metadata.namespace, "prod");
        assert_eq!(policy.api_version, "gateway.kgateway.dev/v1alpha1");
        assert_eq!(policy.kind, "TrafficPolicy");

        let target = &policy.spec.target_refs[0];
        assert_eq!(target.kind, "HTTPRoute");
        assert_eq!(target.name, "my-api-route");

        let bucket = &policy.spec.rate_limit.as_ref().unwrap().local.token_bucket;
        assert_eq!(bucket.max_tokens, 150);
        assert_eq!(bucket.tokens_per_fill, 100);
        assert_eq!(bucket.fill_interval, "60s");
    }

    #[test]
    fn story_traffic_policy_defaults_burst_to_requests() {
        let rate_limit = RateLimitSpec {
            requests_per_interval: 50,
            interval_seconds: 30,
            burst: None,
        };
        let policy = IngressCompiler::compile_traffic_policy("my-api", "prod", &rate_limit);

        let bucket = &policy.spec.rate_limit.as_ref().unwrap().local.token_bucket;
        assert_eq!(bucket.max_tokens, 50); // defaults to requests_per_interval
        assert_eq!(bucket.tokens_per_fill, 50);
        assert_eq!(bucket.fill_interval, "30s");
    }

    #[test]
    fn story_full_compilation_with_rate_limit() {
        let ingress = sample_ingress_with_rate_limit();
        let output = IngressCompiler::compile("my-api", "prod", &ingress, 8080);

        assert!(output.gateway.is_some());
        assert!(output.http_route.is_some());
        assert!(output.traffic_policy.is_some());
        assert!(output.certificate.is_none());
        assert_eq!(output.total_count(), 3);
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
            rate_limit: None,
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
            rate_limit: None,
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
            rate_limit: None,
            gateway_class: None,
        };

        let output = IngressCompiler::compile("my-api", "prod", &ingress, 8080);

        // Should have gateway and route, but no certificate or traffic policy
        assert!(output.gateway.is_some());
        assert!(output.http_route.is_some());
        assert!(output.certificate.is_none());
        assert!(output.traffic_policy.is_none());
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

    // =========================================================================
    // Waypoint Policy Compiler Tests
    // =========================================================================

    use lattice_common::crd::{
        CircuitBreakerPolicy, DependencyDirection, HeaderPolicy, InboundTrafficPolicy,
        OutboundTrafficPolicy, ResourceType, RetryPolicy, TimeoutPolicy,
    };

    fn make_resource_with_outbound() -> ResourceSpec {
        ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Outbound,
            id: None,
            class: None,
            metadata: None,
            params: None,
            outbound: Some(OutboundTrafficPolicy {
                retries: Some(RetryPolicy {
                    attempts: 3,
                    per_try_timeout: Some("5s".to_string()),
                    retry_on: vec!["5xx".to_string(), "reset".to_string()],
                }),
                timeout: Some(TimeoutPolicy {
                    request: "30s".to_string(),
                    idle: Some("5m".to_string()),
                }),
                circuit_breaker: Some(CircuitBreakerPolicy {
                    max_pending_requests: Some(100),
                    max_requests: Some(1000),
                    max_retries: Some(10),
                    consecutive_5xx_errors: None,
                    base_ejection_time: None,
                    max_ejection_percent: None,
                }),
            }),
            inbound: None,
        }
    }

    fn make_resource_with_inbound() -> ResourceSpec {
        ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Inbound,
            id: None,
            class: None,
            metadata: None,
            params: None,
            outbound: None,
            inbound: Some(InboundTrafficPolicy {
                rate_limit: Some(RateLimitSpec {
                    requests_per_interval: 100,
                    interval_seconds: 60,
                    burst: Some(150),
                }),
                headers: Some(HeaderPolicy {
                    add: std::collections::BTreeMap::from([
                        ("X-Caller".to_string(), "frontend".to_string()),
                    ]),
                    remove: vec!["X-Internal".to_string()],
                }),
            }),
        }
    }

    #[test]
    fn story_waypoint_outbound_policy() {
        let mut resources = std::collections::BTreeMap::new();
        resources.insert("backend".to_string(), make_resource_with_outbound());

        let output = WaypointPolicyCompiler::compile("frontend", "prod", &resources);

        assert_eq!(output.outbound_policies.len(), 1);
        assert!(output.inbound_policies.is_empty());

        let policy = &output.outbound_policies[0];
        assert_eq!(policy.metadata.name, "frontend-to-backend-outbound");
        assert_eq!(policy.metadata.namespace, "prod");

        // Check target ref
        assert_eq!(policy.spec.target_refs[0].kind, "Service");
        assert_eq!(policy.spec.target_refs[0].name, "backend");

        // Check retry
        let retry = policy.spec.retry.as_ref().unwrap();
        assert_eq!(retry.num_retries, 3);
        assert_eq!(retry.per_try_timeout, Some("5s".to_string()));
        assert_eq!(retry.retry_on, vec!["5xx", "reset"]);

        // Check timeout
        let timeout = policy.spec.timeout.as_ref().unwrap();
        assert_eq!(timeout.request, "30s");
        assert_eq!(timeout.idle, Some("5m".to_string()));

        // Check circuit breaker
        let limits = policy.spec.connection_limits.as_ref().unwrap();
        assert_eq!(limits.max_pending_requests, Some(100));
        assert_eq!(limits.max_requests, Some(1000));
        assert_eq!(limits.max_retries, Some(10));
    }

    #[test]
    fn story_waypoint_inbound_policy() {
        let mut resources = std::collections::BTreeMap::new();
        resources.insert("api".to_string(), make_resource_with_inbound());

        let output = WaypointPolicyCompiler::compile("frontend", "prod", &resources);

        assert!(output.outbound_policies.is_empty());
        assert_eq!(output.inbound_policies.len(), 1);

        let policy = &output.inbound_policies[0];
        assert_eq!(policy.metadata.name, "api-from-frontend-inbound");
        assert_eq!(policy.metadata.namespace, "prod");

        // Check rate limit
        let rate_limit = policy.spec.rate_limit.as_ref().unwrap();
        assert_eq!(rate_limit.local.token_bucket.max_tokens, 150);
        assert_eq!(rate_limit.local.token_bucket.tokens_per_fill, 100);
        assert_eq!(rate_limit.local.token_bucket.fill_interval, "60s");

        // Check headers
        let headers = policy.spec.request_header_modifier.as_ref().unwrap();
        assert_eq!(headers.add.len(), 1);
        assert_eq!(headers.add[0].name, "X-Caller");
        assert_eq!(headers.add[0].value, "frontend");
        assert_eq!(headers.remove, vec!["X-Internal"]);
    }

    #[test]
    fn story_waypoint_no_policy_for_empty_config() {
        let resource = ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Outbound,
            id: None,
            class: None,
            metadata: None,
            params: None,
            outbound: None,
            inbound: None,
        };

        let mut resources = std::collections::BTreeMap::new();
        resources.insert("backend".to_string(), resource);

        let output = WaypointPolicyCompiler::compile("frontend", "prod", &resources);

        assert!(output.is_empty());
    }

    #[test]
    fn story_waypoint_skips_non_service_resources() {
        let resource = ResourceSpec {
            type_: ResourceType::ExternalService,
            direction: DependencyDirection::Outbound,
            id: None,
            class: None,
            metadata: None,
            params: None,
            outbound: Some(OutboundTrafficPolicy {
                retries: Some(RetryPolicy {
                    attempts: 3,
                    per_try_timeout: None,
                    retry_on: vec![],
                }),
                timeout: None,
                circuit_breaker: None,
            }),
            inbound: None,
        };

        let mut resources = std::collections::BTreeMap::new();
        resources.insert("external".to_string(), resource);

        let output = WaypointPolicyCompiler::compile("frontend", "prod", &resources);

        // External services should be skipped
        assert!(output.is_empty());
    }

    #[test]
    fn story_waypoint_policies_serialization() {
        let mut resources = std::collections::BTreeMap::new();
        resources.insert("backend".to_string(), make_resource_with_outbound());

        let output = WaypointPolicyCompiler::compile("frontend", "prod", &resources);
        let policy = &output.outbound_policies[0];

        // Verify it can be serialized to JSON (for Kubernetes API)
        let json = serde_json::to_string_pretty(policy).unwrap();
        assert!(json.contains("gateway.kgateway.dev/v1alpha1"));
        assert!(json.contains("TrafficPolicy"));
        assert!(json.contains("frontend-to-backend-outbound"));
    }
}
