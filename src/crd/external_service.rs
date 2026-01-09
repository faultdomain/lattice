//! LatticeExternalService Custom Resource Definition
//!
//! The LatticeExternalService CRD represents an external service (outside the cluster)
//! that internal services can depend on. It defines endpoints and access control.

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::types::Condition;

/// Resolution strategy for external service endpoints
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Resolution {
    /// Resolve via DNS
    #[default]
    Dns,
    /// Use static IP addresses
    Static,
}

/// External service lifecycle phase
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExternalServicePhase {
    /// Waiting to be processed
    #[default]
    Pending,
    /// External service is configured and ready
    Ready,
    /// External service configuration failed
    Failed,
}

impl std::fmt::Display for ExternalServicePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Ready => write!(f, "Ready"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Parsed endpoint information from a URL
#[derive(Clone, Debug, PartialEq)]
pub struct ParsedEndpoint {
    /// Protocol (http, https, tcp, grpc, etc.)
    pub protocol: String,
    /// Hostname or IP
    pub host: String,
    /// Port number
    pub port: u16,
    /// Original URL
    pub url: String,
}

impl ParsedEndpoint {
    /// Parse an endpoint URL into its components
    pub fn parse(url: &str) -> Option<Self> {
        // Handle simple formats: host:port, protocol://host:port
        if let Some(stripped) = url.strip_prefix("tcp://") {
            return Self::parse_host_port(stripped, "tcp");
        }
        if let Some(stripped) = url.strip_prefix("https://") {
            return Self::parse_host_port(stripped, "https").or_else(|| {
                // Default port 443 for https
                Some(Self {
                    protocol: "https".to_string(),
                    host: stripped.split('/').next()?.to_string(),
                    port: 443,
                    url: url.to_string(),
                })
            });
        }
        if let Some(stripped) = url.strip_prefix("http://") {
            return Self::parse_host_port(stripped, "http").or_else(|| {
                // Default port 80 for http
                Some(Self {
                    protocol: "http".to_string(),
                    host: stripped.split('/').next()?.to_string(),
                    port: 80,
                    url: url.to_string(),
                })
            });
        }
        if let Some(stripped) = url.strip_prefix("grpc://") {
            return Self::parse_host_port(stripped, "grpc");
        }

        // Fallback: try host:port format
        Self::parse_host_port(url, "tcp")
    }

    fn parse_host_port(s: &str, protocol: &str) -> Option<Self> {
        // Remove any path component
        let host_port = s.split('/').next()?;
        let parts: Vec<&str> = host_port.rsplitn(2, ':').collect();
        if parts.len() == 2 {
            let port = parts[0].parse().ok()?;
            let host = parts[1].to_string();
            Some(Self {
                protocol: protocol.to_string(),
                host,
                port,
                url: format!("{}://{}:{}", protocol, parts[1], port),
            })
        } else {
            None
        }
    }
}

/// Specification for a LatticeExternalService
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "LatticeExternalService",
    plural = "latticeexternalservices",
    shortname = "lext",
    status = "LatticeExternalServiceStatus",
    namespaced = false,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LatticeExternalServiceSpec {
    /// Named endpoints as URLs (e.g., api: https://api.stripe.com)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub endpoints: BTreeMap<String, String>,

    /// Services allowed to access this external service
    /// Use "*" to allow all services
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_requesters: Vec<String>,

    /// How to resolve the external service endpoints
    #[serde(default)]
    pub resolution: Resolution,

    /// Human-readable description
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl LatticeExternalServiceSpec {
    /// Check if a service is allowed to access this external service
    pub fn allows(&self, service_name: &str) -> bool {
        self.allowed_requesters.iter().any(|r| r == "*" || r == service_name)
    }

    /// Parse all endpoints into structured format
    pub fn parsed_endpoints(&self) -> BTreeMap<String, Option<ParsedEndpoint>> {
        self.endpoints
            .iter()
            .map(|(name, url)| (name.clone(), ParsedEndpoint::parse(url)))
            .collect()
    }

    /// Get valid parsed endpoints (filtering out parse failures)
    pub fn valid_endpoints(&self) -> BTreeMap<String, ParsedEndpoint> {
        self.endpoints
            .iter()
            .filter_map(|(name, url)| ParsedEndpoint::parse(url).map(|p| (name.clone(), p)))
            .collect()
    }

    /// Validate the external service specification
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.endpoints.is_empty() {
            return Err(crate::Error::validation(
                "external service must have at least one endpoint",
            ));
        }

        // Validate that all URLs can be parsed
        for (name, url) in &self.endpoints {
            if ParsedEndpoint::parse(url).is_none() {
                return Err(crate::Error::validation(format!(
                    "invalid endpoint URL for '{}': {}",
                    name, url
                )));
            }
        }

        Ok(())
    }
}

/// Status for a LatticeExternalService
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatticeExternalServiceStatus {
    /// Current phase
    #[serde(default)]
    pub phase: ExternalServicePhase,

    /// Human-readable message
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Conditions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    /// Observed generation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

impl LatticeExternalServiceStatus {
    /// Create a new status with the given phase
    pub fn with_phase(phase: ExternalServicePhase) -> Self {
        Self {
            phase,
            ..Default::default()
        }
    }

    /// Set the phase and return self for chaining
    pub fn phase(mut self, phase: ExternalServicePhase) -> Self {
        self.phase = phase;
        self
    }

    /// Set the message and return self for chaining
    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }

    /// Add a condition and return self for chaining
    pub fn condition(mut self, condition: Condition) -> Self {
        self.conditions.retain(|c| c.type_ != condition.type_);
        self.conditions.push(condition);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::types::ConditionStatus;

    // =========================================================================
    // Endpoint Parsing Tests
    // =========================================================================

    #[test]
    fn test_parse_https_url() {
        let endpoint = ParsedEndpoint::parse("https://api.stripe.com").unwrap();
        assert_eq!(endpoint.protocol, "https");
        assert_eq!(endpoint.host, "api.stripe.com");
        assert_eq!(endpoint.port, 443);
    }

    #[test]
    fn test_parse_https_url_with_port() {
        let endpoint = ParsedEndpoint::parse("https://api.example.com:8443").unwrap();
        assert_eq!(endpoint.protocol, "https");
        assert_eq!(endpoint.host, "api.example.com");
        assert_eq!(endpoint.port, 8443);
    }

    #[test]
    fn test_parse_http_url() {
        let endpoint = ParsedEndpoint::parse("http://internal.service.local").unwrap();
        assert_eq!(endpoint.protocol, "http");
        assert_eq!(endpoint.host, "internal.service.local");
        assert_eq!(endpoint.port, 80);
    }

    #[test]
    fn test_parse_tcp_url() {
        let endpoint = ParsedEndpoint::parse("tcp://10.0.0.5:5432").unwrap();
        assert_eq!(endpoint.protocol, "tcp");
        assert_eq!(endpoint.host, "10.0.0.5");
        assert_eq!(endpoint.port, 5432);
    }

    #[test]
    fn test_parse_grpc_url() {
        let endpoint = ParsedEndpoint::parse("grpc://grpc.service.local:9090").unwrap();
        assert_eq!(endpoint.protocol, "grpc");
        assert_eq!(endpoint.host, "grpc.service.local");
        assert_eq!(endpoint.port, 9090);
    }

    #[test]
    fn test_parse_host_port_only() {
        let endpoint = ParsedEndpoint::parse("redis.default.svc:6379").unwrap();
        assert_eq!(endpoint.protocol, "tcp");
        assert_eq!(endpoint.host, "redis.default.svc");
        assert_eq!(endpoint.port, 6379);
    }

    // =========================================================================
    // Access Control Tests
    // =========================================================================

    #[test]
    fn test_allows_specific_service() {
        let spec = LatticeExternalServiceSpec {
            endpoints: BTreeMap::from([("api".to_string(), "https://api.example.com".to_string())]),
            allowed_requesters: vec!["my-service".to_string()],
            resolution: Resolution::Dns,
            description: None,
        };

        assert!(spec.allows("my-service"));
        assert!(!spec.allows("other-service"));
    }

    #[test]
    fn test_allows_wildcard() {
        let spec = LatticeExternalServiceSpec {
            endpoints: BTreeMap::from([("api".to_string(), "https://api.example.com".to_string())]),
            allowed_requesters: vec!["*".to_string()],
            resolution: Resolution::Dns,
            description: None,
        };

        assert!(spec.allows("any-service"));
        assert!(spec.allows("another-service"));
    }

    #[test]
    fn test_allows_empty_denies_all() {
        let spec = LatticeExternalServiceSpec {
            endpoints: BTreeMap::from([("api".to_string(), "https://api.example.com".to_string())]),
            allowed_requesters: vec![],
            resolution: Resolution::Dns,
            description: None,
        };

        assert!(!spec.allows("any-service"));
    }

    // =========================================================================
    // Validation Tests
    // =========================================================================

    #[test]
    fn test_valid_spec_passes() {
        let spec = LatticeExternalServiceSpec {
            endpoints: BTreeMap::from([
                ("api".to_string(), "https://api.stripe.com".to_string()),
                ("db".to_string(), "tcp://10.0.0.5:5432".to_string()),
            ]),
            allowed_requesters: vec!["payment-service".to_string()],
            resolution: Resolution::Dns,
            description: Some("Stripe API".to_string()),
        };

        assert!(spec.validate().is_ok());
    }

    #[test]
    fn test_empty_endpoints_fails() {
        let spec = LatticeExternalServiceSpec {
            endpoints: BTreeMap::new(),
            allowed_requesters: vec!["my-service".to_string()],
            resolution: Resolution::Dns,
            description: None,
        };

        let result = spec.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least one endpoint"));
    }

    #[test]
    fn test_invalid_url_fails() {
        let spec = LatticeExternalServiceSpec {
            endpoints: BTreeMap::from([("bad".to_string(), "not-a-valid-url".to_string())]),
            allowed_requesters: vec![],
            resolution: Resolution::Dns,
            description: None,
        };

        let result = spec.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid endpoint URL"));
    }

    // =========================================================================
    // YAML Serialization Tests
    // =========================================================================

    #[test]
    fn test_yaml_external_service() {
        let yaml = r#"
endpoints:
  api: https://api.stripe.com
  webhook: https://hooks.stripe.com:443
allowedRequesters:
  - payment-service
  - checkout-service
resolution: dns
description: Stripe payment API
"#;
        let spec: LatticeExternalServiceSpec = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(spec.endpoints.len(), 2);
        assert_eq!(spec.allowed_requesters.len(), 2);
        assert!(spec.allows("payment-service"));
        assert!(spec.allows("checkout-service"));
        assert!(!spec.allows("random-service"));
        assert_eq!(spec.resolution, Resolution::Dns);
    }

    #[test]
    fn test_yaml_wildcard_access() {
        let yaml = r#"
endpoints:
  main: https://api.google.com
allowedRequesters:
  - "*"
"#;
        let spec: LatticeExternalServiceSpec = serde_yaml::from_str(yaml).unwrap();

        assert!(spec.allows("any-service"));
    }

    #[test]
    fn test_spec_survives_yaml_roundtrip() {
        let spec = LatticeExternalServiceSpec {
            endpoints: BTreeMap::from([("api".to_string(), "https://api.example.com".to_string())]),
            allowed_requesters: vec!["service-a".to_string(), "service-b".to_string()],
            resolution: Resolution::Static,
            description: Some("Test service".to_string()),
        };

        let yaml = serde_yaml::to_string(&spec).unwrap();
        let parsed: LatticeExternalServiceSpec = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(spec, parsed);
    }

    // =========================================================================
    // Status Builder Tests
    // =========================================================================

    #[test]
    fn test_status_builder() {
        let condition = Condition::new(
            "Ready",
            ConditionStatus::True,
            "EndpointsResolved",
            "All endpoints are reachable",
        );

        let status = LatticeExternalServiceStatus::default()
            .phase(ExternalServicePhase::Ready)
            .message("External service is configured")
            .condition(condition);

        assert_eq!(status.phase, ExternalServicePhase::Ready);
        assert_eq!(
            status.message.as_deref(),
            Some("External service is configured")
        );
        assert_eq!(status.conditions.len(), 1);
    }

    #[test]
    fn test_phase_display() {
        assert_eq!(ExternalServicePhase::Pending.to_string(), "Pending");
        assert_eq!(ExternalServicePhase::Ready.to_string(), "Ready");
        assert_eq!(ExternalServicePhase::Failed.to_string(), "Failed");
    }
}
