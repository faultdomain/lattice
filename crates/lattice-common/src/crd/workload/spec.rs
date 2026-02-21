//! `WorkloadSpec` — the Score-compatible workload specification shared across all Lattice CRDs.
//!
//! `WorkloadSpec` contains only Score-standard fields: containers, resources, and service.
//! Lattice-specific runtime extensions live in `RuntimeSpec`, composed by CRDs that need them.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::crd::types::ServiceRef;

use super::container::{ContainerSpec, SidecarSpec};
use super::ports::ServicePortsSpec;
use super::resources::ResourceSpec;

/// Score-compatible workload specification.
///
/// Contains the container/resource/service core shared across all Lattice
/// workload types: LatticeService, LatticeJob, LatticeModel.
///
/// Lattice-specific pod-level settings (sidecars, sysctls, backup, etc.)
/// live in `RuntimeSpec`, composed separately by each CRD.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadSpec {
    /// Named container specifications (Score-compatible)
    pub containers: BTreeMap<String, ContainerSpec>,

    /// External dependencies (service, route, postgres, redis, etc.)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resources: BTreeMap<String, ResourceSpec>,

    /// Service port configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<ServicePortsSpec>,
}

/// Lattice runtime extensions beyond the Score spec.
///
/// Contains runtime settings shared across Lattice CRDs but NOT part of
/// the Score workload specification. Composed into each CRD's spec via
/// `#[serde(flatten)]` for flat YAML representation.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSpec {
    /// Sidecar containers (VPN, logging, metrics, etc.)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sidecars: BTreeMap<String, SidecarSpec>,

    /// Pod-level sysctls (e.g., net.ipv4.conf.all.src_valid_mark)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sysctls: BTreeMap<String, String>,

    /// Use host network namespace
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_network: Option<bool>,

    /// Share PID namespace between containers
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_process_namespace: Option<bool>,

    /// Image pull secrets — resource names referencing `type: secret` resources
    ///
    /// Each entry is a resource name from `resources` that must have `type: secret`.
    /// The compiled K8s Secret name is resolved at compile time and added to the
    /// pod's `imagePullSecrets` field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub image_pull_secrets: Vec<String>,
}

impl RuntimeSpec {
    /// Validate the runtime specification (sidecar names and specs)
    pub fn validate(&self) -> Result<(), crate::Error> {
        for (name, sidecar) in &self.sidecars {
            super::super::validate_dns_label(name, "sidecar name")
                .map_err(crate::Error::validation)?;
            sidecar.validate(name)?;
        }
        Ok(())
    }
}

impl WorkloadSpec {
    /// Collect ServiceRefs from resources matching a filter predicate.
    ///
    /// Shared helper for dependency/caller extraction. Handles namespace resolution
    /// (defaults to `own_namespace`) and id resolution (defaults to resource name).
    fn collect_service_refs(
        &self,
        own_namespace: &str,
        filter: impl Fn(&ResourceSpec) -> bool,
    ) -> Vec<ServiceRef> {
        self.resources
            .iter()
            .filter(|(_, spec)| filter(spec))
            .map(|(name, spec)| {
                let ns = spec.namespace.as_deref().unwrap_or(own_namespace);
                let svc_name = spec.id.as_deref().unwrap_or(name);
                ServiceRef::new(ns, svc_name)
            })
            .collect()
    }

    /// Extract all service dependencies (outbound) with namespace resolution
    ///
    /// Returns ServiceRefs for both internal and external services.
    /// If a resource doesn't specify a namespace, it defaults to `own_namespace`.
    pub fn dependencies(&self, own_namespace: &str) -> Vec<ServiceRef> {
        self.collect_service_refs(own_namespace, |spec| {
            spec.direction.is_outbound() && spec.type_.is_service_like()
        })
    }

    /// Extract services allowed to call this service (inbound) with namespace resolution
    ///
    /// Returns ServiceRefs for callers. If a resource doesn't specify a namespace,
    /// it defaults to `own_namespace`.
    pub fn allowed_callers(&self, own_namespace: &str) -> Vec<ServiceRef> {
        self.collect_service_refs(own_namespace, |spec| {
            spec.direction.is_inbound() && spec.type_.is_service()
        })
    }

    /// Extract external service dependencies with namespace resolution
    pub fn external_dependencies(&self, own_namespace: &str) -> Vec<ServiceRef> {
        self.collect_service_refs(own_namespace, |spec| {
            spec.direction.is_outbound() && spec.type_.is_external_service()
        })
    }

    /// Extract internal service dependencies with namespace resolution
    pub fn internal_dependencies(&self, own_namespace: &str) -> Vec<ServiceRef> {
        self.collect_service_refs(own_namespace, |spec| {
            spec.direction.is_outbound() && spec.type_.is_service()
        })
    }

    /// Get the primary container image
    pub fn primary_image(&self) -> Option<&str> {
        self.containers
            .get("main")
            .or_else(|| self.containers.values().next())
            .map(|c| c.image.as_str())
    }

    /// Get shared volume IDs that this workload owns (has size defined)
    /// Returns: Vec<(resource_name, volume_id)>
    pub fn owned_volume_ids(&self) -> Vec<(&str, &str)> {
        self.resources
            .iter()
            .filter(|(_, spec)| spec.is_volume_owner() && spec.id.is_some())
            .filter_map(|(name, spec)| spec.id.as_ref().map(|id| (name.as_str(), id.as_str())))
            .collect()
    }

    /// Get shared volume IDs that this workload references (no size, just id)
    /// Returns: Vec<(resource_name, volume_id)>
    pub fn referenced_volume_ids(&self) -> Vec<(&str, &str)> {
        self.resources
            .iter()
            .filter(|(_, spec)| spec.is_volume_reference())
            .filter_map(|(name, spec)| spec.id.as_ref().map(|id| (name.as_str(), id.as_str())))
            .collect()
    }

    /// Get the service-facing ports (what clients connect to).
    pub fn ports(&self) -> BTreeMap<&str, u16> {
        self.service
            .as_ref()
            .map(|s| {
                s.ports
                    .iter()
                    .map(|(name, spec)| (name.as_str(), spec.port))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Validate the workload specification
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.containers.is_empty() {
            return Err(crate::Error::validation(
                "service must have at least one container",
            ));
        }

        // Validate container names are valid DNS labels
        for name in self.containers.keys() {
            super::super::validate_dns_label(name, "container name")
                .map_err(crate::Error::validation)?;
        }

        // Validate resource names are valid DNS labels
        for name in self.resources.keys() {
            super::super::validate_dns_label(name, "resource name")
                .map_err(crate::Error::validation)?;
        }

        // Validate containers
        for (name, container) in &self.containers {
            container.validate(name)?;
        }

        // Validate service ports
        if let Some(ref svc) = self.service {
            svc.validate()?;
        }

        // Validate resource fields
        for (name, resource) in &self.resources {
            // Volume ids flow into K8s names: "vol-{id}" PVC and "volume-owner-{id}" labels.
            // Secret ids are Vault paths (e.g., "database/prod/creds") — no DNS validation.
            // Service ids override the target service name — validated by K8s API.
            if let Some(ref id) = resource.id {
                if id != "*" && resource.type_.is_volume() {
                    if id.len() > 50 {
                        return Err(crate::Error::validation(format!(
                            "resource '{}': id '{}' exceeds 50 character limit \
                             (used in label name with 13-char prefix)",
                            name, id
                        )));
                    }
                    super::super::validate_dns_identifier(id, false).map_err(|e| {
                        crate::Error::validation(format!("resource '{}': id: {}", name, e))
                    })?;
                }
            }

            if resource.type_.is_gpu() {
                resource
                    .gpu_params()
                    .map_err(|e| crate::Error::validation(format!("resource '{}': {}", name, e)))?;
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
    use super::super::container::ContainerSpec;
    use super::super::resources::{
        DependencyDirection, ResourceQuantity, ResourceRequirements, ResourceSpec, ResourceType,
    };
    use super::*;

    fn simple_container() -> ContainerSpec {
        ContainerSpec {
            image: "nginx:latest".to_string(),
            command: Some(vec!["/usr/sbin/nginx".to_string()]),
            resources: Some(ResourceRequirements {
                limits: Some(ResourceQuantity {
                    memory: Some("256Mi".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn sample_workload() -> WorkloadSpec {
        let mut containers = BTreeMap::new();
        containers.insert("main".to_string(), simple_container());
        WorkloadSpec {
            containers,
            ..Default::default()
        }
    }

    #[test]
    fn valid_service_passes_validation() {
        let spec = sample_workload();
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn service_without_containers_fails() {
        let spec = WorkloadSpec {
            containers: BTreeMap::new(),
            ..Default::default()
        };
        let result = spec.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at least one container"));
    }

    #[test]
    fn test_primary_image() {
        let spec = sample_workload();
        assert_eq!(spec.primary_image(), Some("nginx:latest"));
    }

    #[test]
    fn test_primary_image_without_main() {
        let mut containers = BTreeMap::new();
        containers.insert("worker".to_string(), simple_container());
        let spec = WorkloadSpec {
            containers,
            ..Default::default()
        };
        assert_eq!(spec.primary_image(), Some("nginx:latest"));
    }

    #[test]
    fn service_declares_outbound_dependencies() {
        let mut resources = BTreeMap::new();
        resources.insert(
            "redis".to_string(),
            ResourceSpec {
                type_: ResourceType::ExternalService,
                direction: DependencyDirection::Outbound,
                ..Default::default()
            },
        );
        resources.insert(
            "api-gateway".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Outbound,
                ..Default::default()
            },
        );

        let mut spec = sample_workload();
        spec.resources = resources;

        let deps = spec.dependencies("test");
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|r| r.name == "redis"));
        assert!(deps.iter().any(|r| r.name == "api-gateway"));
    }

    #[test]
    fn service_declares_allowed_callers() {
        let mut resources = BTreeMap::new();
        resources.insert(
            "curl-tester".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Inbound,
                ..Default::default()
            },
        );
        resources.insert(
            "frontend".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Inbound,
                ..Default::default()
            },
        );

        let mut spec = sample_workload();
        spec.resources = resources;

        let callers = spec.allowed_callers("test");
        assert_eq!(callers.len(), 2);
        assert!(callers.iter().any(|r| r.name == "curl-tester"));
        assert!(callers.iter().any(|r| r.name == "frontend"));
    }

    #[test]
    fn bidirectional_relationships() {
        let mut resources = BTreeMap::new();
        resources.insert(
            "cache".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Both,
                ..Default::default()
            },
        );

        let mut spec = sample_workload();
        spec.resources = resources;

        assert!(spec.dependencies("test").iter().any(|r| r.name == "cache"));
        assert!(spec
            .allowed_callers("test")
            .iter()
            .any(|r| r.name == "cache"));
    }

    #[test]
    fn external_vs_internal_dependencies() {
        let mut resources = BTreeMap::new();
        resources.insert(
            "google".to_string(),
            ResourceSpec {
                type_: ResourceType::ExternalService,
                direction: DependencyDirection::Outbound,
                ..Default::default()
            },
        );
        resources.insert(
            "backend".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Outbound,
                ..Default::default()
            },
        );

        let mut spec = sample_workload();
        spec.resources = resources;

        let external = spec.external_dependencies("test");
        let internal = spec.internal_dependencies("test");

        assert_eq!(external.len(), 1);
        assert_eq!(external[0].name, "google");
        assert_eq!(internal.len(), 1);
        assert_eq!(internal[0].name, "backend");
    }

    #[test]
    fn test_volume_owner_detection() {
        let mut spec = sample_workload();
        spec.resources.insert(
            "data".to_string(),
            ResourceSpec {
                type_: ResourceType::Volume,
                id: Some("shared-data".to_string()),
                params: Some(BTreeMap::from([(
                    "size".to_string(),
                    serde_json::json!("10Gi"),
                )])),
                ..Default::default()
            },
        );
        let owned = spec.owned_volume_ids();
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0], ("data", "shared-data"));
    }

    #[test]
    fn test_volume_reference_detection() {
        let mut spec = sample_workload();
        spec.resources.insert(
            "data".to_string(),
            ResourceSpec {
                type_: ResourceType::Volume,
                id: Some("shared-data".to_string()),
                ..Default::default()
            },
        );
        let refs = spec.referenced_volume_ids();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0], ("data", "shared-data"));
    }

    #[test]
    fn container_name_too_long_fails() {
        let long_name = "a".repeat(64);
        let mut containers = BTreeMap::new();
        containers.insert(long_name, simple_container());
        let spec = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let result = spec.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("exceeds 63 character"));
    }

    #[test]
    fn resource_name_too_long_fails() {
        let mut spec = sample_workload();
        let long_name = "a".repeat(64);
        spec.resources.insert(
            long_name,
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Outbound,
                ..Default::default()
            },
        );
        let result = spec.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("exceeds 63 character"));
    }

    #[test]
    fn container_name_with_underscores_fails() {
        let mut containers = BTreeMap::new();
        containers.insert("my_container".to_string(), simple_container());
        let spec = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let err = spec.validate().unwrap_err().to_string();
        assert!(err.contains("container name"));
        assert!(err.contains("lowercase alphanumeric"));
    }

    #[test]
    fn volume_id_too_long_fails() {
        let mut spec = sample_workload();
        spec.resources.insert(
            "vol".to_string(),
            ResourceSpec {
                type_: ResourceType::Volume,
                id: Some("a".repeat(51)),
                ..Default::default()
            },
        );
        let err = spec.validate().unwrap_err().to_string();
        assert!(err.contains("exceeds 50 character limit"));
    }

    #[test]
    fn volume_id_with_underscores_fails() {
        let mut spec = sample_workload();
        spec.resources.insert(
            "vol".to_string(),
            ResourceSpec {
                type_: ResourceType::Volume,
                id: Some("my_volume".to_string()),
                ..Default::default()
            },
        );
        let err = spec.validate().unwrap_err().to_string();
        assert!(err.contains("resource 'vol': id"));
    }

    #[test]
    fn secret_id_with_vault_path_is_valid() {
        let mut spec = sample_workload();
        spec.resources.insert(
            "db-creds".to_string(),
            ResourceSpec {
                type_: ResourceType::Secret,
                id: Some("database/prod/creds".to_string()),
                ..Default::default()
            },
        );
        spec.validate()
            .expect("secret id with vault path should be valid");
    }

    #[test]
    fn service_id_not_dns_validated() {
        let mut spec = sample_workload();
        spec.resources.insert(
            "backend".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Outbound,
                id: Some("my-service".to_string()),
                ..Default::default()
            },
        );
        spec.validate().expect("service id should be valid");
    }

    #[test]
    fn resource_id_wildcard_is_valid() {
        let mut spec = sample_workload();
        spec.resources.insert(
            "any-caller".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Inbound,
                id: Some("*".to_string()),
                ..Default::default()
            },
        );
        spec.validate().expect("wildcard id '*' should be valid");
    }

    #[test]
    fn container_name_with_uppercase_fails() {
        let mut containers = BTreeMap::new();
        containers.insert("MyContainer".to_string(), simple_container());
        let spec = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let err = spec.validate().unwrap_err().to_string();
        assert!(err.contains("container name"));
    }

    #[test]
    fn container_name_starting_with_digit_fails() {
        let mut containers = BTreeMap::new();
        containers.insert("1container".to_string(), simple_container());
        let spec = WorkloadSpec {
            containers,
            ..Default::default()
        };
        let err = spec.validate().unwrap_err().to_string();
        assert!(err.contains("container name"));
        assert!(err.contains("start with lowercase letter"));
    }

    #[test]
    fn ports_returns_service_ports() {
        use super::super::ports::{PortSpec, ServicePortsSpec};

        let mut ports = BTreeMap::new();
        ports.insert(
            "http".to_string(),
            PortSpec {
                port: 8080,
                target_port: Some(80),
                protocol: None,
            },
        );
        ports.insert(
            "grpc".to_string(),
            PortSpec {
                port: 9090,
                target_port: None,
                protocol: Some("TCP".to_string()),
            },
        );

        let mut spec = sample_workload();
        spec.service = Some(ServicePortsSpec { ports });

        let result = spec.ports();
        assert_eq!(result.len(), 2);
        assert_eq!(result["http"], 8080);
        assert_eq!(result["grpc"], 9090);
    }

    #[test]
    fn ports_returns_empty_when_no_service() {
        let spec = sample_workload();
        assert!(spec.ports().is_empty());
    }

    #[test]
    fn gpu_resource_validation_wired_into_spec() {
        let mut spec = sample_workload();
        let mut params = BTreeMap::new();
        params.insert("count".to_string(), serde_json::json!(0));
        spec.resources.insert(
            "my-gpu".to_string(),
            ResourceSpec {
                type_: ResourceType::Gpu,
                params: Some(params),
                ..Default::default()
            },
        );
        assert!(spec.validate().is_err());
    }
}
