//! External endpoint parsing utilities
//!
//! Contains ParsedEndpoint and Resolution types used across Lattice for
//! external service endpoint handling.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Resolution strategy for external service endpoints
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Resolution {
    /// Resolve via DNS
    #[default]
    Dns,
    /// Use static IP addresses
    Static,
}

impl Resolution {
    /// Convert to Istio ServiceEntry resolution format (uppercase)
    pub fn to_istio_format(&self) -> &'static str {
        match self {
            Self::Dns => "DNS",
            Self::Static => "STATIC",
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
    /// Network-level protocol for Cilium policy generation.
    pub fn network_protocol(&self) -> crate::crd::NetworkProtocol {
        if self.protocol == "udp" {
            crate::crd::NetworkProtocol::Udp
        } else {
            crate::crd::NetworkProtocol::Tcp
        }
    }

    /// Returns true if the host is a cluster-local Kubernetes address.
    ///
    /// Cluster-local addresses (ending in `.svc` or `.svc.cluster.local`) resolve
    /// inside the cluster and don't need external egress policies.
    pub fn is_cluster_local(&self) -> bool {
        self.host.ends_with(".svc") || self.host.ends_with(".svc.cluster.local")
    }

    /// Parse an endpoint URL into its components
    pub fn parse(url: &str) -> Option<Self> {
        if let Some(stripped) = url.strip_prefix("udp://") {
            return Self::parse_host_port(stripped, "udp");
        }
        if let Some(stripped) = url.strip_prefix("tcp://") {
            return Self::parse_host_port(stripped, "tcp");
        }
        if let Some(stripped) = url.strip_prefix("https://") {
            if Self::has_explicit_port(stripped) {
                return Self::parse_host_port(stripped, "https");
            }
            let host = Self::extract_host(stripped)?;
            if host.is_empty() {
                return None;
            }
            return Some(Self {
                protocol: "https".to_string(),
                host,
                port: 443,
                url: url.to_string(),
            });
        }
        if let Some(stripped) = url.strip_prefix("http://") {
            if Self::has_explicit_port(stripped) {
                return Self::parse_host_port(stripped, "http");
            }
            let host = Self::extract_host(stripped)?;
            if host.is_empty() {
                return None;
            }
            return Some(Self {
                protocol: "http".to_string(),
                host,
                port: 80,
                url: url.to_string(),
            });
        }
        if let Some(stripped) = url.strip_prefix("grpc://") {
            return Self::parse_host_port(stripped, "grpc");
        }

        // Fallback: try host:port format
        Self::parse_host_port(url, "tcp")
    }

    /// Check if the URL portion has an explicit port (excluding IPv6 colons)
    fn has_explicit_port(s: &str) -> bool {
        let without_auth = s.split('@').next_back().unwrap_or(s);
        let host_port = without_auth.split('/').next().unwrap_or(without_auth);

        if host_port.starts_with('[') {
            if let Some(bracket_pos) = host_port.find(']') {
                return host_port[bracket_pos..].contains(':');
            }
            return false;
        }

        host_port.contains(':')
    }

    /// Extract host from URL, handling IPv6 brackets and stripping auth/path
    fn extract_host(s: &str) -> Option<String> {
        let without_auth = s.split('@').next_back()?;
        let host_port = without_auth.split('/').next()?;

        if host_port.starts_with('[') {
            if let Some(end_bracket) = host_port.find(']') {
                return Some(host_port[1..end_bracket].to_string());
            }
            return None;
        }

        Some(host_port.split(':').next()?.to_string())
    }

    fn parse_host_port(s: &str, protocol: &str) -> Option<Self> {
        let without_auth = s.split('@').next_back()?;
        let host_port = without_auth.split('/').next()?;

        if host_port.starts_with('[') {
            return Self::parse_ipv6_host_port(host_port, protocol);
        }

        let parts: Vec<&str> = host_port.rsplitn(2, ':').collect();
        if parts.len() == 2 {
            let port: u16 = parts[0].parse().ok()?;
            if port == 0 {
                return None;
            }
            let host = parts[1].to_string();
            if host.is_empty() {
                return None;
            }
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

    /// Parse IPv6 host:port format like [::1]:8080
    fn parse_ipv6_host_port(s: &str, protocol: &str) -> Option<Self> {
        let end_bracket = s.find(']')?;
        let host = s[1..end_bracket].to_string();

        if host.is_empty() {
            return None;
        }

        let after_bracket = &s[end_bracket + 1..];
        if let Some(port_str) = after_bracket.strip_prefix(':') {
            let port: u16 = port_str.parse().ok()?;
            if port == 0 {
                return None;
            }
            Some(Self {
                protocol: protocol.to_string(),
                host: host.clone(),
                port,
                url: format!("{}://[{}]:{}", protocol, host, port),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_https_url() {
        let endpoint =
            ParsedEndpoint::parse("https://api.stripe.com").expect("should parse HTTPS URL");
        assert_eq!(endpoint.protocol, "https");
        assert_eq!(endpoint.host, "api.stripe.com");
        assert_eq!(endpoint.port, 443);
    }

    #[test]
    fn test_parse_https_url_with_port() {
        let endpoint = ParsedEndpoint::parse("https://api.example.com:8443")
            .expect("should parse HTTPS URL with port");
        assert_eq!(endpoint.protocol, "https");
        assert_eq!(endpoint.host, "api.example.com");
        assert_eq!(endpoint.port, 8443);
    }

    #[test]
    fn test_parse_http_url() {
        let endpoint =
            ParsedEndpoint::parse("http://internal.service.local").expect("should parse HTTP URL");
        assert_eq!(endpoint.protocol, "http");
        assert_eq!(endpoint.host, "internal.service.local");
        assert_eq!(endpoint.port, 80);
    }

    #[test]
    fn test_parse_tcp_url() {
        let endpoint = ParsedEndpoint::parse("tcp://10.0.0.5:5432").expect("should parse TCP URL");
        assert_eq!(endpoint.protocol, "tcp");
        assert_eq!(endpoint.host, "10.0.0.5");
        assert_eq!(endpoint.port, 5432);
    }

    #[test]
    fn test_parse_udp_url() {
        let endpoint =
            ParsedEndpoint::parse("udp://vpn.example.com:51820").expect("should parse UDP URL");
        assert_eq!(endpoint.protocol, "udp");
        assert_eq!(endpoint.host, "vpn.example.com");
        assert_eq!(endpoint.port, 51820);
        assert_eq!(
            endpoint.network_protocol(),
            crate::crd::NetworkProtocol::Udp
        );
    }

    #[test]
    fn test_tcp_network_protocol() {
        let endpoint = ParsedEndpoint::parse("https://api.stripe.com").unwrap();
        assert_eq!(
            endpoint.network_protocol(),
            crate::crd::NetworkProtocol::Tcp
        );
    }

    #[test]
    fn test_parse_grpc_url() {
        let endpoint =
            ParsedEndpoint::parse("grpc://grpc.service.local:9090").expect("should parse gRPC URL");
        assert_eq!(endpoint.protocol, "grpc");
        assert_eq!(endpoint.host, "grpc.service.local");
        assert_eq!(endpoint.port, 9090);
    }

    #[test]
    fn test_parse_host_port_only() {
        let endpoint =
            ParsedEndpoint::parse("redis.default.svc:6379").expect("should parse host:port format");
        assert_eq!(endpoint.protocol, "tcp");
        assert_eq!(endpoint.host, "redis.default.svc");
        assert_eq!(endpoint.port, 6379);
    }

    #[test]
    fn test_parse_ipv6_address() {
        let endpoint =
            ParsedEndpoint::parse("tcp://[::1]:8080").expect("should parse IPv6 localhost");
        assert_eq!(endpoint.protocol, "tcp");
        assert_eq!(endpoint.host, "::1");
        assert_eq!(endpoint.port, 8080);
    }

    #[test]
    fn test_parse_ipv6_full_address() {
        let endpoint = ParsedEndpoint::parse("tcp://[2001:db8:85a3::8a2e:370:7334]:5432")
            .expect("should parse full IPv6 address");
        assert_eq!(endpoint.protocol, "tcp");
        assert_eq!(endpoint.host, "2001:db8:85a3::8a2e:370:7334");
        assert_eq!(endpoint.port, 5432);
    }

    #[test]
    fn test_parse_ipv6_https() {
        let endpoint =
            ParsedEndpoint::parse("https://[::1]:8443").expect("should parse IPv6 HTTPS");
        assert_eq!(endpoint.protocol, "https");
        assert_eq!(endpoint.host, "::1");
        assert_eq!(endpoint.port, 8443);
    }

    #[test]
    fn test_parse_ipv6_without_port_fails() {
        assert!(ParsedEndpoint::parse("tcp://[::1]").is_none());
    }

    #[test]
    fn test_parse_ipv6_malformed_fails() {
        assert!(ParsedEndpoint::parse("tcp://[::1:8080").is_none());
        assert!(ParsedEndpoint::parse("tcp://[]:8080").is_none());
    }

    #[test]
    fn test_parse_url_with_auth() {
        let endpoint = ParsedEndpoint::parse("https://user:pass@api.example.com:8443")
            .expect("should parse URL with auth");
        assert_eq!(endpoint.protocol, "https");
        assert_eq!(endpoint.host, "api.example.com");
        assert_eq!(endpoint.port, 8443);
    }

    #[test]
    fn test_parse_url_with_user_only() {
        let endpoint = ParsedEndpoint::parse("tcp://admin@db.example.com:5432")
            .expect("should parse URL with user only");
        assert_eq!(endpoint.protocol, "tcp");
        assert_eq!(endpoint.host, "db.example.com");
        assert_eq!(endpoint.port, 5432);
    }

    #[test]
    fn test_port_zero_fails() {
        assert!(ParsedEndpoint::parse("tcp://example.com:0").is_none());
        assert!(ParsedEndpoint::parse("https://example.com:0").is_none());
        assert!(ParsedEndpoint::parse("tcp://[::1]:0").is_none());
    }

    #[test]
    fn test_port_max_valid() {
        let endpoint =
            ParsedEndpoint::parse("tcp://example.com:65535").expect("max valid port should parse");
        assert_eq!(endpoint.port, 65535);
    }

    #[test]
    fn test_port_overflow_fails() {
        assert!(ParsedEndpoint::parse("tcp://example.com:65536").is_none());
    }

    #[test]
    fn test_empty_host_fails() {
        assert!(ParsedEndpoint::parse("tcp://:8080").is_none());
        assert!(ParsedEndpoint::parse(":8080").is_none());
    }

    #[test]
    fn test_protocol_only_fails() {
        assert!(ParsedEndpoint::parse("https://").is_none());
        assert!(ParsedEndpoint::parse("tcp://").is_none());
    }

    #[test]
    fn test_url_with_path_extracts_host() {
        let endpoint = ParsedEndpoint::parse("https://api.stripe.com/v1/charges")
            .expect("should parse URL with path");
        assert_eq!(endpoint.host, "api.stripe.com");
        assert_eq!(endpoint.port, 443);
    }

    #[test]
    fn test_url_with_port_and_path() {
        let endpoint = ParsedEndpoint::parse("https://api.example.com:8443/api/v1")
            .expect("should parse URL with port and path");
        assert_eq!(endpoint.host, "api.example.com");
        assert_eq!(endpoint.port, 8443);
    }

    #[test]
    fn test_resolution_to_istio_format() {
        assert_eq!(Resolution::Dns.to_istio_format(), "DNS");
        assert_eq!(Resolution::Static.to_istio_format(), "STATIC");
    }

    #[test]
    fn test_is_cluster_local_svc_suffix() {
        let ep = ParsedEndpoint::parse("http://my-service.default.svc:8080").expect("should parse");
        assert!(ep.is_cluster_local());
    }

    #[test]
    fn test_is_cluster_local_fqdn_suffix() {
        let ep = ParsedEndpoint::parse("https://my-service.default.svc.cluster.local:443")
            .expect("should parse");
        assert!(ep.is_cluster_local());
    }

    #[test]
    fn test_is_not_cluster_local_external() {
        let ep = ParsedEndpoint::parse("https://vault.example.com:8200").expect("should parse");
        assert!(!ep.is_cluster_local());
    }

    #[test]
    fn test_is_not_cluster_local_ip() {
        let ep = ParsedEndpoint::parse("http://172.18.0.9:8200").expect("should parse");
        assert!(!ep.is_cluster_local());
    }
}
