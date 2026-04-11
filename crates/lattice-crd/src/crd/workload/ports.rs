//! Service port specifications shared across all Lattice workload CRDs.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Service port specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PortSpec {
    /// Service port
    pub port: u16,

    /// Target port (defaults to port)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_port: Option<u16>,

    /// Protocol (TCP or UDP)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

/// Service exposure specification
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct ServicePortsSpec {
    /// Named network ports
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ports: BTreeMap<String, PortSpec>,
}

impl ServicePortsSpec {
    /// Validate service port specification
    pub fn validate(&self) -> Result<(), crate::ValidationError> {
        let mut seen_ports: std::collections::HashSet<u16> = std::collections::HashSet::new();

        for (name, port_spec) in &self.ports {
            // Validate port name is a valid DNS label (max 15 chars for IANA compliance)
            lattice_core::validate_dns_label(name, "port name")
                .map_err(crate::ValidationError::new)?;
            if name.len() > 15 {
                return Err(crate::ValidationError::new(format!(
                    "port name '{}' exceeds 15 character IANA service name limit",
                    name
                )));
            }

            // Validate port is not zero
            if port_spec.port == 0 {
                return Err(crate::ValidationError::new(format!(
                    "service port '{}': port cannot be 0",
                    name
                )));
            }

            // Validate target_port is not zero
            if let Some(target_port) = port_spec.target_port {
                if target_port == 0 {
                    return Err(crate::ValidationError::new(format!(
                        "service port '{}': target_port cannot be 0",
                        name
                    )));
                }
            }

            // Check for duplicate port numbers
            if !seen_ports.insert(port_spec.port) {
                return Err(crate::ValidationError::new(format!(
                    "duplicate service port number: {}",
                    port_spec.port
                )));
            }
        }

        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duplicate_service_ports_fail() {
        let mut ports = BTreeMap::new();
        ports.insert(
            "http".to_string(),
            PortSpec {
                port: 80,
                target_port: None,
                protocol: None,
            },
        );
        ports.insert(
            "http2".to_string(),
            PortSpec {
                port: 80,
                target_port: None,
                protocol: None,
            },
        );

        let svc = ServicePortsSpec { ports };
        assert!(svc.validate().is_err());
    }

    #[test]
    fn test_port_zero_fails() {
        let mut ports = BTreeMap::new();
        ports.insert(
            "http".to_string(),
            PortSpec {
                port: 0,
                target_port: None,
                protocol: None,
            },
        );

        let svc = ServicePortsSpec { ports };
        assert!(svc.validate().is_err());
    }

    #[test]
    fn test_port_name_with_underscores_fails() {
        let mut ports = BTreeMap::new();
        ports.insert(
            "my_port".to_string(),
            PortSpec {
                port: 80,
                target_port: None,
                protocol: None,
            },
        );
        let svc = ServicePortsSpec { ports };
        let err = svc.validate().unwrap_err().to_string();
        assert!(err.contains("port name"));
    }

    #[test]
    fn test_port_name_exceeding_15_chars_fails() {
        let mut ports = BTreeMap::new();
        ports.insert(
            "ab".repeat(8), // 16 chars
            PortSpec {
                port: 80,
                target_port: None,
                protocol: None,
            },
        );
        let svc = ServicePortsSpec { ports };
        let err = svc.validate().unwrap_err().to_string();
        assert!(err.contains("15 character"));
    }

    #[test]
    fn test_valid_port_name_accepted() {
        let mut ports = BTreeMap::new();
        ports.insert(
            "http".to_string(),
            PortSpec {
                port: 80,
                target_port: None,
                protocol: None,
            },
        );
        let svc = ServicePortsSpec { ports };
        assert!(svc.validate().is_ok());
    }
}
