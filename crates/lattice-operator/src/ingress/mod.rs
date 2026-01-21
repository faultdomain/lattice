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
    CircuitBreakerPolicy, InboundTrafficPolicy, IngressSpec, IngressTls, OutboundTrafficPolicy,
    PathMatchType, RateLimitSpec, ResourceSpec, ResourceType, RetryPolicy, TimeoutPolicy, TlsMode,
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
    /// Request timeouts (Gateway API native)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeouts: Option<HttpRouteTimeouts>,
    /// Retry policy (Gateway API native)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<HttpRouteRetry>,
}

/// HTTPRoute timeout configuration (Gateway API native)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpRouteTimeouts {
    /// Request timeout - total time for request including retries
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    /// Backend request timeout - timeout for each individual backend request
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_request: Option<String>,
}

/// HTTPRoute retry configuration (Gateway API native)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpRouteRetry {
    /// HTTP status codes to retry (e.g., 500, 502, 503, 504)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub codes: Vec<u16>,
    /// Maximum number of retry attempts
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u32>,
    /// Backoff duration between retries (e.g., "100ms")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backoff: Option<String>,
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
// Envoy Gateway Types (for Waypoint)
// =============================================================================

/// Envoy Gateway EnvoyProxy resource for waypoint configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvoyProxy {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: GatewayMetadata,
    /// Spec
    pub spec: EnvoyProxySpec,
}

/// EnvoyProxy spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvoyProxySpec {
    /// Provider configuration
    pub provider: EnvoyProxyProvider,
}

/// EnvoyProxy provider configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvoyProxyProvider {
    /// Provider type (Kubernetes)
    #[serde(rename = "type")]
    pub type_: String,
    /// Kubernetes-specific configuration
    pub kubernetes: EnvoyProxyKubernetes,
}

/// Kubernetes provider configuration for EnvoyProxy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvoyProxyKubernetes {
    /// Service configuration
    pub envoy_service: EnvoyProxyService,
}

/// EnvoyProxy service configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvoyProxyService {
    /// Service type (ClusterIP for waypoints)
    #[serde(rename = "type")]
    pub type_: String,
    /// Strategic merge patch for service
    pub patch: EnvoyProxyPatch,
}

/// EnvoyProxy patch configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvoyProxyPatch {
    /// Patch type
    #[serde(rename = "type")]
    pub type_: String,
    /// Patch value
    pub value: EnvoyProxyPatchValue,
}

/// EnvoyProxy patch value
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvoyProxyPatchValue {
    /// Service spec patch
    pub spec: EnvoyProxyPatchSpec,
}

/// EnvoyProxy patch spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvoyProxyPatchSpec {
    /// Ports to add
    pub ports: Vec<EnvoyProxyPort>,
}

/// EnvoyProxy port configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvoyProxyPort {
    /// Port name
    pub name: String,
    /// Port number
    pub port: u16,
    /// Protocol
    pub protocol: String,
    /// Target port
    pub target_port: u16,
}

/// Gateway API GatewayClass resource
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GatewayClass {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: GatewayClassMetadata,
    /// Spec
    pub spec: GatewayClassSpec,
}

/// GatewayClass metadata (no namespace - cluster-scoped)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GatewayClassMetadata {
    /// Resource name
    pub name: String,
    /// Labels
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

/// GatewayClass spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GatewayClassSpec {
    /// Controller name
    pub controller_name: String,
    /// Parameters reference
    pub parameters_ref: GatewayClassParametersRef,
}

/// GatewayClass parameters reference
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GatewayClassParametersRef {
    /// API group
    pub group: String,
    /// Kind
    pub kind: String,
    /// Name
    pub name: String,
    /// Namespace
    pub namespace: String,
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
// Waypoint Resources (East-West L7 Policies)
// =============================================================================

/// Waypoint resources for east-west mesh traffic L7 policy enforcement
///
/// Uses Envoy Gateway as waypoint proxy integrated with Istio Ambient mesh.
/// The waypoint Gateway handles L7 traffic between ztunnel endpoints.
#[derive(Clone, Debug, Default)]
pub struct GeneratedWaypoint {
    /// EnvoyProxy configuration (one per namespace, configures HBONE port on Service)
    pub envoy_proxy: Option<EnvoyProxy>,
    /// GatewayClass for this namespace (references namespace-local EnvoyProxy)
    pub gateway_class: Option<GatewayClass>,
    /// Waypoint Gateway (one per namespace, includes HTTP and HBONE listeners)
    pub gateway: Option<Gateway>,
    /// HTTPRoute for service (routes traffic through waypoint)
    pub http_route: Option<HttpRoute>,
}

impl GeneratedWaypoint {
    /// Create empty waypoint collection
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if any resources were generated
    pub fn is_empty(&self) -> bool {
        self.envoy_proxy.is_none()
            && self.gateway_class.is_none()
            && self.gateway.is_none()
            && self.http_route.is_none()
    }
}

/// Compiler for generating waypoint Gateway and HTTPRoute resources
///
/// Creates the infrastructure needed for Envoy Gateway to act as an
/// Istio Ambient waypoint proxy for L7 policy enforcement.
pub struct WaypointCompiler;

impl WaypointCompiler {
    /// HBONE port for ztunnel tunnel termination
    const HBONE_PORT: u16 = 15008;
    /// HTTP port for L7 traffic processing
    const WAYPOINT_HTTP_PORT: u16 = 9080;

    /// Get the GatewayClass name for a namespace
    fn gateway_class_name(namespace: &str) -> String {
        format!("{}-waypoint", namespace)
    }

    /// Compile waypoint resources for a service
    ///
    /// # Arguments
    /// * `service_name` - Name of the LatticeService
    /// * `namespace` - Target namespace
    /// * `service_port` - Primary service port
    /// * `resources` - Resource dependencies with traffic policies
    pub fn compile(
        service_name: &str,
        namespace: &str,
        service_port: u16,
        resources: &BTreeMap<String, ResourceSpec>,
    ) -> GeneratedWaypoint {
        let mut output = GeneratedWaypoint::new();

        // Generate namespace-local EnvoyProxy (configures HBONE port on Service)
        output.envoy_proxy = Some(Self::compile_envoy_proxy(namespace));

        // Generate namespace-specific GatewayClass (references local EnvoyProxy)
        output.gateway_class = Some(Self::compile_gateway_class(namespace));

        // Generate waypoint Gateway for this namespace (one per namespace)
        output.gateway = Some(Self::compile_waypoint_gateway(namespace));

        // Generate HTTPRoute for this service through the waypoint
        output.http_route = Some(Self::compile_waypoint_http_route(
            service_name,
            namespace,
            service_port,
            resources,
        ));

        output
    }

    /// Compile EnvoyProxy for a namespace
    ///
    /// Must be in the same namespace as the Gateway for GatewayNamespace mode.
    /// Configures the HBONE port (15008) on the Envoy Service for ztunnel compatibility.
    fn compile_envoy_proxy(namespace: &str) -> EnvoyProxy {
        let mut labels = BTreeMap::new();
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            "lattice".to_string(),
        );

        EnvoyProxy {
            api_version: "gateway.envoyproxy.io/v1alpha1".to_string(),
            kind: "EnvoyProxy".to_string(),
            metadata: GatewayMetadata {
                name: "waypoint".to_string(),
                namespace: namespace.to_string(),
                labels,
            },
            spec: EnvoyProxySpec {
                provider: EnvoyProxyProvider {
                    type_: "Kubernetes".to_string(),
                    kubernetes: EnvoyProxyKubernetes {
                        envoy_service: EnvoyProxyService {
                            type_: "ClusterIP".to_string(),
                            patch: EnvoyProxyPatch {
                                type_: "StrategicMerge".to_string(),
                                value: EnvoyProxyPatchValue {
                                    spec: EnvoyProxyPatchSpec {
                                        ports: vec![EnvoyProxyPort {
                                            // HACK: ztunnel expects HBONE port on waypoint Service
                                            name: "fake-hbone-port".to_string(),
                                            port: Self::HBONE_PORT,
                                            protocol: "TCP".to_string(),
                                            target_port: Self::HBONE_PORT,
                                        }],
                                    },
                                },
                            },
                        },
                    },
                },
            },
        }
    }

    /// Compile GatewayClass for a namespace
    ///
    /// Each namespace gets its own GatewayClass that references the namespace-local EnvoyProxy.
    /// This is required because GatewayClass.parametersRef.namespace must match where
    /// the EnvoyProxy lives.
    fn compile_gateway_class(namespace: &str) -> GatewayClass {
        let class_name = Self::gateway_class_name(namespace);
        let mut labels = BTreeMap::new();
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            "lattice".to_string(),
        );

        GatewayClass {
            api_version: "gateway.networking.k8s.io/v1".to_string(),
            kind: "GatewayClass".to_string(),
            metadata: GatewayClassMetadata {
                name: class_name,
                labels,
            },
            spec: GatewayClassSpec {
                controller_name: "gateway.envoyproxy.io/gatewayclass-controller".to_string(),
                parameters_ref: GatewayClassParametersRef {
                    group: "gateway.envoyproxy.io".to_string(),
                    kind: "EnvoyProxy".to_string(),
                    name: "waypoint".to_string(),
                    namespace: namespace.to_string(),
                },
            },
        }
    }

    /// Compile waypoint Gateway for a namespace
    ///
    /// ONE waypoint per namespace with both HTTP and HBONE listeners:
    /// - HTTP listener on port 9080 for L7 traffic processing
    /// - TCP listener on port 15008 for HBONE tunnel termination
    ///
    /// - `istio.io/dataplane-mode: ambient` label required for Istio recognition
    fn compile_waypoint_gateway(namespace: &str) -> Gateway {
        let gateway_name = format!("{}-waypoint", namespace);
        let gateway_class = Self::gateway_class_name(namespace);
        let mut metadata = GatewayMetadata::new(&gateway_name, namespace);
        // Required for Istio Ambient to recognize this as a waypoint
        metadata
            .labels
            .insert("istio.io/dataplane-mode".to_string(), "ambient".to_string());

        Gateway {
            api_version: "gateway.networking.k8s.io/v1".to_string(),
            kind: "Gateway".to_string(),
            metadata,
            spec: GatewaySpec {
                gateway_class_name: gateway_class,
                listeners: vec![
                    // HTTP listener for L7 traffic processing
                    GatewayListener {
                        name: "mesh".to_string(),
                        hostname: None,
                        port: Self::WAYPOINT_HTTP_PORT,
                        protocol: "HTTP".to_string(),
                        tls: None,
                        allowed_routes: Some(AllowedRoutes {
                            namespaces: RouteNamespaces {
                                from: "Same".to_string(),
                            },
                        }),
                    }
                ],
            },
        }
    }

    /// Compile HTTPRoute for a service through the waypoint
    ///
    /// Routes traffic to the service via the waypoint Gateway.
    /// Hostnames include all DNS variants for the service.
    /// Includes native Gateway API timeout/retry from outbound policies.
    fn compile_waypoint_http_route(
        service_name: &str,
        namespace: &str,
        port: u16,
        resources: &BTreeMap<String, ResourceSpec>,
    ) -> HttpRoute {
        let route_name = format!("{}-waypoint", service_name);
        let gateway_name = format!("{}-waypoint", namespace);

        // Extract timeout/retry from outbound policies in resources
        // These are policies for when THIS service calls other services
        let (timeouts, retry) = Self::extract_route_policies(resources);

        HttpRoute {
            api_version: "gateway.networking.k8s.io/v1".to_string(),
            kind: "HTTPRoute".to_string(),
            metadata: GatewayMetadata::new(&route_name, namespace),
            spec: HttpRouteSpec {
                parent_refs: vec![ParentRef {
                    group: Some("gateway.networking.k8s.io".to_string()),
                    kind: Some("Gateway".to_string()),
                    name: gateway_name,
                    namespace: None, // Same namespace
                }],
                hostnames: vec![
                    service_name.to_string(),
                    format!("{}.{}", service_name, namespace),
                    format!("{}.{}.svc.cluster.local", service_name, namespace),
                ],
                rules: vec![HttpRouteRule {
                    matches: vec![],
                    backend_refs: vec![BackendRef {
                        kind: Some("Service".to_string()),
                        name: service_name.to_string(),
                        port,
                    }],
                    timeouts,
                    retry,
                }],
            },
        }
    }

    /// Extract timeout and retry policies from resource specs
    ///
    /// Looks for INBOUND policies that define timeout or retry settings.
    /// Waypoints process INBOUND traffic, so policies come from inbound resources.
    /// Returns the first timeout/retry found (could be enhanced to merge or select).
    fn extract_route_policies(
        resources: &BTreeMap<String, ResourceSpec>,
    ) -> (Option<HttpRouteTimeouts>, Option<HttpRouteRetry>) {
        let mut timeouts = None;
        let mut retry = None;

        for resource in resources.values() {
            // Only look at inbound resources - waypoints process inbound traffic
            if resource.direction != crate::crd::DependencyDirection::Inbound {
                continue;
            }

            if let Some(ref inbound) = resource.inbound {
                // Extract timeout from inbound policy
                if timeouts.is_none() {
                    if let Some(ref timeout_policy) = inbound.timeout {
                        timeouts = Some(HttpRouteTimeouts {
                            request: Some(timeout_policy.request.clone()),
                            backend_request: timeout_policy.idle.clone(),
                        });
                    }
                }

                // Extract retry from inbound policy
                if retry.is_none() {
                    if let Some(ref retry_policy) = inbound.retries {
                        // Convert retry_on conditions to HTTP status codes
                        let codes: Vec<u16> = retry_policy
                            .retry_on
                            .iter()
                            .flat_map(|condition| match condition.as_str() {
                                "5xx" => vec![500, 502, 503, 504],
                                "gateway-error" => vec![502, 503, 504],
                                s => s.parse::<u16>().map(|c| vec![c]).unwrap_or_default(),
                            })
                            .collect();

                        retry = Some(HttpRouteRetry {
                            codes,
                            attempts: Some(retry_policy.attempts),
                            backoff: retry_policy.per_try_timeout.clone(),
                        });
                    }
                }
            }
        }

        (timeouts, retry)
    }
}

// =============================================================================
// Ingress Compiler
// =============================================================================

/// Compiler for generating Gateway API resources from LatticeService ingress config
pub struct IngressCompiler;

impl IngressCompiler {
    /// Default GatewayClass for Envoy Gateway
    const DEFAULT_GATEWAY_CLASS: &'static str = "eg";

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
        let gateway_class = ingress
            .gateway_class
            .as_deref()
            .unwrap_or(Self::DEFAULT_GATEWAY_CLASS);

        let has_tls = ingress.tls.is_some();
        let secret_name = format!("{}-tls", service_name);

        let mut listeners = Vec::new();

        // HTTP listener (port 80)
        listeners.push(GatewayListener {
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
        });

        // HTTPS listener (port 443) if TLS configured
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

        Gateway {
            api_version: "gateway.networking.k8s.io/v1".to_string(),
            kind: "Gateway".to_string(),
            metadata: GatewayMetadata::new(format!("{}-gateway", service_name), namespace),
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
        // Build path matches
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
            // Default to "/" prefix match
            vec![HttpRouteMatch {
                path: Some(HttpPathMatch {
                    type_: "PathPrefix".to_string(),
                    value: "/".to_string(),
                }),
            }]
        };

        // Build parent refs - reference both HTTP and HTTPS if TLS is configured
        let mut parent_refs = vec![ParentRef {
            group: Some("gateway.networking.k8s.io".to_string()),
            kind: Some("Gateway".to_string()),
            name: format!("{}-gateway", service_name),
            namespace: Some(namespace.to_string()),
        }];

        // For HTTPS, add a separate parent ref for the HTTPS listener
        if ingress.tls.is_some() {
            parent_refs.push(ParentRef {
                group: Some("gateway.networking.k8s.io".to_string()),
                kind: Some("Gateway".to_string()),
                name: format!("{}-gateway", service_name),
                namespace: Some(namespace.to_string()),
            });
        }

        HttpRoute {
            api_version: "gateway.networking.k8s.io/v1".to_string(),
            kind: "HTTPRoute".to_string(),
            metadata: GatewayMetadata::new(format!("{}-route", service_name), namespace),
            spec: HttpRouteSpec {
                parent_refs,
                hostnames: ingress.hosts.clone(),
                rules: vec![HttpRouteRule {
                    matches,
                    backend_refs: vec![BackendRef {
                        kind: Some("Service".to_string()),
                        name: service_name.to_string(),
                        port: backend_port,
                    }],
                    timeouts: None,
                    retry: None,
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

        Some(Certificate {
            api_version: "cert-manager.io/v1".to_string(),
            kind: "Certificate".to_string(),
            metadata: GatewayMetadata::new(format!("{}-cert", service_name), namespace),
            spec: CertificateSpec {
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
        })
    }
}

// =============================================================================
// Envoy Gateway BackendTrafficPolicy
// =============================================================================

/// Envoy Gateway BackendTrafficPolicy for traffic shaping
///
/// Used for retries, timeouts, circuit breaking, and rate limiting on
/// east-west service-to-service traffic.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackendTrafficPolicy {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: GatewayMetadata,
    /// Spec
    pub spec: BackendTrafficPolicySpec,
}

/// BackendTrafficPolicy spec
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackendTrafficPolicySpec {
    /// Target references (Service or HTTPRoute)
    pub target_refs: Vec<PolicyTargetRef>,
    /// Retry configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<PolicyRetry>,
    /// Timeout configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<PolicyTimeout>,
    /// Circuit breaker configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_breaker: Option<PolicyCircuitBreaker>,
    /// Rate limit configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<PolicyRateLimit>,
}

/// Policy target reference
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyTargetRef {
    /// API group
    pub group: String,
    /// Kind (Service, HTTPRoute)
    pub kind: String,
    /// Resource name
    pub name: String,
}

/// Retry configuration for BackendTrafficPolicy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRetry {
    /// Number of retries
    pub num_retries: u32,
    /// Per-retry settings
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_retry: Option<PerRetryPolicy>,
    /// Retry conditions
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_on: Option<RetryOn>,
}

/// Per-retry configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PerRetryPolicy {
    /// Timeout per retry attempt
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
    /// Backoff configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub back_off: Option<BackOffPolicy>,
}

/// Backoff configuration for retries
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackOffPolicy {
    /// Base interval for backoff
    pub base_interval: String,
    /// Maximum interval for backoff
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_interval: Option<String>,
}

/// Retry trigger conditions
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RetryOn {
    /// HTTP status codes to retry on
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http_status_codes: Vec<u16>,
    /// Trigger conditions (connect-failure, retriable-status-codes, etc.)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub triggers: Vec<String>,
}

/// Timeout configuration for BackendTrafficPolicy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyTimeout {
    /// HTTP request timeout
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpTimeout>,
}

/// HTTP timeout settings
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpTimeout {
    /// Request timeout
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_timeout: Option<String>,
    /// Idle timeout
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<String>,
}

/// Circuit breaker configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyCircuitBreaker {
    /// Maximum pending requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_pending_requests: Option<u32>,
    /// Maximum parallel requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_parallel_requests: Option<u32>,
    /// Maximum parallel retries
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_parallel_retries: Option<u32>,
}

/// Rate limit configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRateLimit {
    /// Local rate limiting (in-proxy)
    pub local: LocalRateLimit,
}

/// Local rate limit configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LocalRateLimit {
    /// Rate limit rules
    pub rules: Vec<RateLimitRule>,
}

/// Rate limit rule
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitRule {
    /// Rate limit
    pub limit: RateLimitValue,
}

/// Rate limit value
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitValue {
    /// Number of requests
    pub requests: u32,
    /// Time unit (Second, Minute, Hour)
    pub unit: String,
}

// =============================================================================
// Generated Traffic Policies
// =============================================================================

/// Collection of traffic policies generated for a service
#[derive(Clone, Debug, Default)]
pub struct GeneratedTrafficPolicies {
    /// Outbound policies (caller-side: retries, timeouts, circuit breaker)
    pub outbound: Vec<BackendTrafficPolicy>,
    /// Inbound policies (callee-side: rate limits)
    pub inbound: Vec<BackendTrafficPolicy>,
}

impl GeneratedTrafficPolicies {
    /// Create empty collection
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if any policies were generated
    pub fn is_empty(&self) -> bool {
        self.outbound.is_empty() && self.inbound.is_empty()
    }

    /// Total count of all policies
    pub fn total_count(&self) -> usize {
        self.outbound.len() + self.inbound.len()
    }
}

// =============================================================================
// Traffic Policy Compiler
// =============================================================================

/// Compiler for generating Envoy Gateway BackendTrafficPolicy resources
pub struct TrafficPolicyCompiler;

impl TrafficPolicyCompiler {
    /// Compile traffic policies for a service's resource dependencies
    ///
    /// # Arguments
    /// * `service_name` - Name of the source LatticeService
    /// * `namespace` - Target namespace
    /// * `resources` - Map of resource name to ResourceSpec
    ///
    /// # Returns
    /// Generated BackendTrafficPolicy resources
    pub fn compile(
        service_name: &str,
        namespace: &str,
        resources: &std::collections::BTreeMap<String, ResourceSpec>,
    ) -> GeneratedTrafficPolicies {
        let mut output = GeneratedTrafficPolicies::new();

        for (resource_name, resource) in resources {
            // Only process service resources
            if !matches!(resource.type_, ResourceType::Service) {
                continue;
            }

            // Compile outbound policy (caller-side)
            if let Some(ref outbound) = resource.outbound {
                if let Some(policy) =
                    Self::compile_outbound_policy(service_name, resource_name, namespace, outbound)
                {
                    output.outbound.push(policy);
                }
            }

            // Compile inbound policy (callee-side)
            if let Some(ref inbound) = resource.inbound {
                if let Some(policy) =
                    Self::compile_inbound_policy(service_name, resource_name, namespace, inbound)
                {
                    output.inbound.push(policy);
                }
            }
        }

        output
    }

    /// Compile outbound BackendTrafficPolicy (retries, timeouts, circuit breaker)
    fn compile_outbound_policy(
        caller: &str,
        callee: &str,
        namespace: &str,
        outbound: &OutboundTrafficPolicy,
    ) -> Option<BackendTrafficPolicy> {
        // Skip if no policies configured
        if outbound.retries.is_none()
            && outbound.timeout.is_none()
            && outbound.circuit_breaker.is_none()
        {
            return None;
        }

        let policy_name = format!("{}-to-{}-traffic", caller, callee);

        // Target the waypoint HTTPRoute for the callee service
        let http_route_name = format!("{}-waypoint", callee);

        Some(BackendTrafficPolicy {
            api_version: "gateway.envoyproxy.io/v1alpha1".to_string(),
            kind: "BackendTrafficPolicy".to_string(),
            metadata: GatewayMetadata::new(policy_name, namespace),
            spec: BackendTrafficPolicySpec {
                target_refs: vec![PolicyTargetRef {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    name: http_route_name,
                }],
                retry: outbound.retries.as_ref().map(Self::convert_retry),
                timeout: outbound.timeout.as_ref().map(Self::convert_timeout),
                circuit_breaker: outbound
                    .circuit_breaker
                    .as_ref()
                    .map(Self::convert_circuit_breaker),
                rate_limit: None,
            },
        })
    }

    /// Compile inbound BackendTrafficPolicy (rate limits)
    ///
    /// # Arguments
    /// * `service_name` - The service being compiled (receiving traffic)
    /// * `caller_name` - The resource name representing the caller
    fn compile_inbound_policy(
        service_name: &str,
        caller_name: &str,
        namespace: &str,
        inbound: &InboundTrafficPolicy,
    ) -> Option<BackendTrafficPolicy> {
        // Skip if no rate limit configured
        let rate_limit = inbound.rate_limit.as_ref()?;

        let policy_name = format!("{}-from-{}-ratelimit", service_name, caller_name);

        // Target the waypoint HTTPRoute for the service
        let http_route_name = format!("{}-waypoint", service_name);

        Some(BackendTrafficPolicy {
            api_version: "gateway.envoyproxy.io/v1alpha1".to_string(),
            kind: "BackendTrafficPolicy".to_string(),
            metadata: GatewayMetadata::new(policy_name, namespace),
            spec: BackendTrafficPolicySpec {
                target_refs: vec![PolicyTargetRef {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "HTTPRoute".to_string(),
                    name: http_route_name,
                }],
                retry: None,
                timeout: None,
                circuit_breaker: None,
                rate_limit: Some(Self::convert_rate_limit(rate_limit)),
            },
        })
    }

    /// Convert CRD retry policy to Envoy Gateway format
    fn convert_retry(retry: &RetryPolicy) -> PolicyRetry {
        // Convert retry_on conditions to status codes and triggers
        let mut http_status_codes = Vec::new();
        let mut triggers = Vec::new();

        for condition in &retry.retry_on {
            match condition.as_str() {
                "5xx" => http_status_codes.extend([500, 502, 503, 504]),
                "gateway-error" => http_status_codes.extend([502, 503, 504]),
                "reset"
                | "connect-failure"
                | "retriable-4xx"
                | "refused-stream"
                | "retriable-status-codes"
                | "retriable-headers" => {
                    triggers.push(condition.clone());
                }
                // Try to parse as status code
                s if s.parse::<u16>().is_ok() => {
                    if let Ok(code) = s.parse() {
                        http_status_codes.push(code);
                    }
                }
                _ => triggers.push(condition.clone()),
            }
        }

        PolicyRetry {
            num_retries: retry.attempts,
            per_retry: retry
                .per_try_timeout
                .as_ref()
                .map(|timeout| PerRetryPolicy {
                    timeout: Some(timeout.clone()),
                    back_off: Some(BackOffPolicy {
                        base_interval: "100ms".to_string(),
                        max_interval: Some("10s".to_string()),
                    }),
                }),
            retry_on: if http_status_codes.is_empty() && triggers.is_empty() {
                None
            } else {
                Some(RetryOn {
                    http_status_codes,
                    triggers,
                })
            },
        }
    }

    /// Convert CRD timeout policy to Envoy Gateway format
    fn convert_timeout(timeout: &TimeoutPolicy) -> PolicyTimeout {
        PolicyTimeout {
            http: Some(HttpTimeout {
                request_timeout: Some(timeout.request.clone()),
                idle_timeout: timeout.idle.clone(),
            }),
        }
    }

    /// Convert CRD circuit breaker to Envoy Gateway format
    fn convert_circuit_breaker(cb: &CircuitBreakerPolicy) -> PolicyCircuitBreaker {
        PolicyCircuitBreaker {
            max_pending_requests: cb.max_pending_requests,
            max_parallel_requests: cb.max_requests,
            max_parallel_retries: cb.max_retries,
        }
    }

    /// Convert CRD rate limit to Envoy Gateway format
    fn convert_rate_limit(rate_limit: &RateLimitSpec) -> PolicyRateLimit {
        // Convert interval_seconds to unit
        let (requests, unit) = match rate_limit.interval_seconds {
            1 => (rate_limit.requests_per_interval, "Second"),
            60 => (rate_limit.requests_per_interval, "Minute"),
            3600 => (rate_limit.requests_per_interval, "Hour"),
            // For non-standard intervals, convert to per-minute
            secs => {
                let per_minute =
                    (rate_limit.requests_per_interval as f64 * 60.0 / secs as f64).round() as u32;
                (per_minute.max(1), "Minute")
            }
        };

        PolicyRateLimit {
            local: LocalRateLimit {
                rules: vec![RateLimitRule {
                    limit: RateLimitValue {
                        requests,
                        unit: unit.to_string(),
                    },
                }],
            },
        }
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
    // Story: Basic Gateway Generation
    // =========================================================================

    #[test]
    fn story_generates_gateway_with_http_listener() {
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
    fn story_generates_gateway_with_https_listener() {
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

    // =========================================================================
    // Story: HTTPRoute Generation
    // =========================================================================

    #[test]
    fn story_generates_http_route() {
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
    fn story_default_path_match() {
        let ingress = make_ingress_spec(vec!["api.example.com"], false);
        let output = IngressCompiler::compile("api", "prod", &ingress, 8080);

        let route = output.http_route.expect("should have route");
        let match_ = &route.spec.rules[0].matches[0];
        let path = match_.path.as_ref().expect("should have path");
        assert_eq!(path.type_, "PathPrefix");
        assert_eq!(path.value, "/");
    }

    #[test]
    fn story_custom_path_matches() {
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
        assert_eq!(matches[0].path.as_ref().unwrap().value, "/v1");
        assert_eq!(matches[0].path.as_ref().unwrap().type_, "PathPrefix");
        assert_eq!(matches[1].path.as_ref().unwrap().value, "/health");
        assert_eq!(matches[1].path.as_ref().unwrap().type_, "Exact");
    }

    // =========================================================================
    // Story: Certificate Generation
    // =========================================================================

    #[test]
    fn story_generates_certificate_for_auto_tls() {
        let ingress = make_ingress_spec(vec!["api.example.com"], true);
        let output = IngressCompiler::compile("api", "prod", &ingress, 8080);

        let cert = output.certificate.expect("should have certificate");
        assert_eq!(cert.metadata.name, "api-cert");
        assert_eq!(cert.spec.secret_name, "api-tls");
        assert_eq!(cert.spec.dns_names, vec!["api.example.com"]);
        assert_eq!(cert.spec.issuer_ref.name, "letsencrypt-prod");
        assert_eq!(cert.spec.issuer_ref.kind, "ClusterIssuer");
    }

    #[test]
    fn story_no_certificate_without_tls() {
        let ingress = make_ingress_spec(vec!["api.example.com"], false);
        let output = IngressCompiler::compile("api", "prod", &ingress, 8080);

        assert!(output.certificate.is_none());
    }

    // =========================================================================
    // Story: Custom Gateway Class
    // =========================================================================

    #[test]
    fn story_custom_gateway_class() {
        let mut ingress = make_ingress_spec(vec!["api.example.com"], false);
        ingress.gateway_class = Some("custom-class".to_string());

        let output = IngressCompiler::compile("api", "prod", &ingress, 8080);
        let gateway = output.gateway.expect("should have gateway");

        assert_eq!(gateway.spec.gateway_class_name, "custom-class");
    }

    // =========================================================================
    // Story: GeneratedIngress Helpers
    // =========================================================================

    #[test]
    fn story_is_empty() {
        let empty = GeneratedIngress::new();
        assert!(empty.is_empty());
        assert_eq!(empty.total_count(), 0);

        let ingress = make_ingress_spec(vec!["api.example.com"], true);
        let output = IngressCompiler::compile("api", "prod", &ingress, 8080);
        assert!(!output.is_empty());
        assert_eq!(output.total_count(), 3); // gateway + route + cert
    }

    // =========================================================================
    // Story: Traffic Policy Compilation
    // =========================================================================

    use lattice_common::crd::DependencyDirection;

    fn make_service_resource(
        direction: DependencyDirection,
        outbound: Option<OutboundTrafficPolicy>,
        inbound: Option<InboundTrafficPolicy>,
    ) -> ResourceSpec {
        ResourceSpec {
            type_: ResourceType::Service,
            direction,
            id: None,
            class: None,
            metadata: None,
            params: None,
            outbound,
            inbound,
        }
    }

    #[test]
    fn story_compiles_outbound_retry_policy() {
        let mut resources = std::collections::BTreeMap::new();
        resources.insert(
            "backend".to_string(),
            make_service_resource(
                DependencyDirection::Outbound,
                Some(OutboundTrafficPolicy {
                    retries: Some(RetryPolicy {
                        attempts: 3,
                        per_try_timeout: Some("500ms".to_string()),
                        retry_on: vec!["5xx".to_string(), "connect-failure".to_string()],
                    }),
                    timeout: None,
                    circuit_breaker: None,
                }),
                None,
            ),
        );

        let output = TrafficPolicyCompiler::compile("frontend", "prod", &resources);

        assert_eq!(output.outbound.len(), 1);
        assert!(output.inbound.is_empty());

        let policy = &output.outbound[0];
        assert_eq!(policy.metadata.name, "frontend-to-backend-traffic");
        assert_eq!(policy.metadata.namespace, "prod");
        assert_eq!(policy.api_version, "gateway.envoyproxy.io/v1alpha1");
        assert_eq!(policy.kind, "BackendTrafficPolicy");

        let retry = policy.spec.retry.as_ref().expect("should have retry");
        assert_eq!(retry.num_retries, 3);
        assert!(retry.per_retry.is_some());
        assert!(retry.retry_on.is_some());

        let retry_on = retry.retry_on.as_ref().unwrap();
        assert!(retry_on.http_status_codes.contains(&500));
        assert!(retry_on.triggers.contains(&"connect-failure".to_string()));
    }

    #[test]
    fn story_compiles_outbound_timeout_policy() {
        let mut resources = std::collections::BTreeMap::new();
        resources.insert(
            "backend".to_string(),
            make_service_resource(
                DependencyDirection::Outbound,
                Some(OutboundTrafficPolicy {
                    retries: None,
                    timeout: Some(TimeoutPolicy {
                        request: "30s".to_string(),
                        idle: Some("5m".to_string()),
                    }),
                    circuit_breaker: None,
                }),
                None,
            ),
        );

        let output = TrafficPolicyCompiler::compile("frontend", "prod", &resources);

        assert_eq!(output.outbound.len(), 1);
        let policy = &output.outbound[0];

        let timeout = policy.spec.timeout.as_ref().expect("should have timeout");
        let http = timeout.http.as_ref().expect("should have http timeout");
        assert_eq!(http.request_timeout.as_deref(), Some("30s"));
        assert_eq!(http.idle_timeout.as_deref(), Some("5m"));
    }

    #[test]
    fn story_compiles_outbound_circuit_breaker() {
        let mut resources = std::collections::BTreeMap::new();
        resources.insert(
            "backend".to_string(),
            make_service_resource(
                DependencyDirection::Outbound,
                Some(OutboundTrafficPolicy {
                    retries: None,
                    timeout: None,
                    circuit_breaker: Some(CircuitBreakerPolicy {
                        max_pending_requests: Some(100),
                        max_requests: Some(1000),
                        max_retries: Some(10),
                        consecutive_5xx_errors: None,
                        base_ejection_time: None,
                        max_ejection_percent: None,
                    }),
                }),
                None,
            ),
        );

        let output = TrafficPolicyCompiler::compile("frontend", "prod", &resources);

        assert_eq!(output.outbound.len(), 1);
        let policy = &output.outbound[0];

        let cb = policy
            .spec
            .circuit_breaker
            .as_ref()
            .expect("should have circuit breaker");
        assert_eq!(cb.max_pending_requests, Some(100));
        assert_eq!(cb.max_parallel_requests, Some(1000));
        assert_eq!(cb.max_parallel_retries, Some(10));
    }

    #[test]
    fn story_compiles_inbound_rate_limit() {
        let mut resources = std::collections::BTreeMap::new();
        resources.insert(
            "caller".to_string(),
            make_service_resource(
                DependencyDirection::Inbound,
                None,
                Some(InboundTrafficPolicy {
                    rate_limit: Some(RateLimitSpec {
                        requests_per_interval: 100,
                        interval_seconds: 60,
                        burst: None,
                    }),
                    headers: None,
                    timeout: None,
                    retries: None,
                }),
            ),
        );

        let output = TrafficPolicyCompiler::compile("api", "prod", &resources);

        assert!(output.outbound.is_empty());
        assert_eq!(output.inbound.len(), 1);

        let policy = &output.inbound[0];
        assert_eq!(policy.metadata.name, "api-from-caller-ratelimit");

        let rate_limit = policy
            .spec
            .rate_limit
            .as_ref()
            .expect("should have rate limit");
        assert_eq!(rate_limit.local.rules.len(), 1);
        assert_eq!(rate_limit.local.rules[0].limit.requests, 100);
        assert_eq!(rate_limit.local.rules[0].limit.unit, "Minute");
    }

    #[test]
    fn story_skips_empty_policies() {
        let mut resources = std::collections::BTreeMap::new();
        resources.insert(
            "backend".to_string(),
            make_service_resource(
                DependencyDirection::Outbound,
                Some(OutboundTrafficPolicy {
                    retries: None,
                    timeout: None,
                    circuit_breaker: None,
                }),
                None,
            ),
        );

        let output = TrafficPolicyCompiler::compile("frontend", "prod", &resources);

        assert!(output.outbound.is_empty());
        assert!(output.inbound.is_empty());
    }

    #[test]
    fn story_skips_non_service_resources() {
        let mut resources = std::collections::BTreeMap::new();
        resources.insert(
            "database".to_string(),
            ResourceSpec {
                type_: ResourceType::Volume,
                direction: DependencyDirection::default(),
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
            },
        );

        let output = TrafficPolicyCompiler::compile("frontend", "prod", &resources);

        assert!(output.is_empty());
    }
}
