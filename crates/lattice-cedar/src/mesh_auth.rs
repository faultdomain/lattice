//! Mesh wildcard authorization
//!
//! Evaluates Cedar policies to authorize a service's wildcard inbound (`allows_all`)
//! or wildcard outbound (`depends_all`). Default-deny: no policies = no wildcards.
//!
//! Cedar model:
//! - Action: `Lattice::Action::"AllowWildcard"`
//! - Resource: `Lattice::Mesh::"inbound"` or `Lattice::Mesh::"outbound"`

use std::fmt;

use crate::engine::{DenialReason, PolicyEngine};
use crate::entities::{build_entity_uid, build_mesh_wildcard_entity, build_service_entity};

/// Action name for mesh wildcard authorization
const ACTION_NAME: &str = "AllowWildcard";

// =============================================================================
// Types
// =============================================================================

/// Direction of the wildcard being authorized
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WildcardDirection {
    /// Wildcard inbound: allows all callers (`allows_all`)
    Inbound,
    /// Wildcard outbound: depends on all services that allow it (`depends_all`)
    Outbound,
}

impl WildcardDirection {
    /// Cedar resource id for this direction (used in `Mesh::"inbound"` / `Mesh::"outbound"`)
    pub fn resource_id(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

impl fmt::Display for WildcardDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inbound => write!(f, "allows_all (wildcard inbound)"),
            Self::Outbound => write!(f, "depends_all (wildcard outbound)"),
        }
    }
}

/// Request to authorize a mesh wildcard
pub struct MeshWildcardRequest {
    /// Service name
    pub service_name: String,
    /// Service namespace
    pub namespace: String,
    /// Which wildcard direction
    pub direction: WildcardDirection,
}

/// Result of a mesh wildcard authorization
pub struct MeshWildcardResult {
    /// Whether the wildcard was allowed
    pub allowed: bool,
    /// Reason for denial (if denied)
    pub reason: Option<DenialReason>,
}

impl MeshWildcardResult {
    /// Check if the wildcard was allowed
    pub fn is_allowed(&self) -> bool {
        self.allowed
    }
}

// =============================================================================
// Implementation
// =============================================================================

impl PolicyEngine {
    /// Authorize a mesh wildcard (allows_all or depends_all).
    ///
    /// Default-deny: no Cedar engine or no policies = wildcard denied.
    pub async fn authorize_mesh_wildcard(
        &self,
        request: &MeshWildcardRequest,
    ) -> MeshWildcardResult {
        let deny = |reason| MeshWildcardResult {
            allowed: false,
            reason: Some(reason),
        };

        let policy_set = self.read_policy_set().await;
        let action_uid = match build_entity_uid("Action", ACTION_NAME) {
            Ok(uid) => uid,
            Err(_) => return deny(DenialReason::NoPermitPolicy),
        };
        let service_entity = match build_service_entity(&request.namespace, &request.service_name) {
            Ok(e) => e,
            Err(_) => return deny(DenialReason::NoPermitPolicy),
        };
        let resource_entity = match build_mesh_wildcard_entity(request.direction.resource_id()) {
            Ok(e) => e,
            Err(_) => return deny(DenialReason::NoPermitPolicy),
        };

        match self.evaluate_service_action(
            &service_entity,
            &resource_entity,
            &action_uid,
            &policy_set,
            ACTION_NAME,
        ) {
            Ok(()) => MeshWildcardResult {
                allowed: true,
                reason: None,
            },
            Err(reason) => deny(reason),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn inbound_request(ns: &str, name: &str) -> MeshWildcardRequest {
        MeshWildcardRequest {
            service_name: name.to_string(),
            namespace: ns.to_string(),
            direction: WildcardDirection::Inbound,
        }
    }

    fn outbound_request(ns: &str, name: &str) -> MeshWildcardRequest {
        MeshWildcardRequest {
            service_name: name.to_string(),
            namespace: ns.to_string(),
            direction: WildcardDirection::Outbound,
        }
    }

    #[tokio::test]
    async fn test_default_deny_inbound() {
        let engine = PolicyEngine::new();
        let result = engine
            .authorize_mesh_wildcard(&inbound_request("prod", "api"))
            .await;
        assert!(!result.is_allowed());
        assert_eq!(result.reason, Some(DenialReason::NoPermitPolicy));
    }

    #[tokio::test]
    async fn test_default_deny_outbound() {
        let engine = PolicyEngine::new();
        let result = engine
            .authorize_mesh_wildcard(&outbound_request("prod", "scraper"))
            .await;
        assert!(!result.is_allowed());
        assert_eq!(result.reason, Some(DenialReason::NoPermitPolicy));
    }

    #[tokio::test]
    async fn test_permit_inbound() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal == Lattice::Service::"monitoring/vmagent",
                action == Lattice::Action::"AllowWildcard",
                resource == Lattice::Mesh::"inbound"
            );
            "#,
        )
        .unwrap();

        let result = engine
            .authorize_mesh_wildcard(&inbound_request("monitoring", "vmagent"))
            .await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_permit_outbound() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal == Lattice::Service::"monitoring/vmagent",
                action == Lattice::Action::"AllowWildcard",
                resource == Lattice::Mesh::"outbound"
            );
            "#,
        )
        .unwrap();

        let result = engine
            .authorize_mesh_wildcard(&outbound_request("monitoring", "vmagent"))
            .await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_permit_inbound_does_not_grant_outbound() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal == Lattice::Service::"monitoring/vmagent",
                action == Lattice::Action::"AllowWildcard",
                resource == Lattice::Mesh::"inbound"
            );
            "#,
        )
        .unwrap();

        let result = engine
            .authorize_mesh_wildcard(&outbound_request("monitoring", "vmagent"))
            .await;
        assert!(!result.is_allowed());
    }

    #[tokio::test]
    async fn test_wrong_service_denied() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal == Lattice::Service::"monitoring/vmagent",
                action == Lattice::Action::"AllowWildcard",
                resource == Lattice::Mesh::"inbound"
            );
            "#,
        )
        .unwrap();

        let result = engine
            .authorize_mesh_wildcard(&inbound_request("monitoring", "other"))
            .await;
        assert!(!result.is_allowed());
    }

    #[tokio::test]
    async fn test_namespace_scoped_permit() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal,
                action == Lattice::Action::"AllowWildcard",
                resource == Lattice::Mesh::"inbound"
            ) when {
                principal.namespace == "monitoring"
            };
            "#,
        )
        .unwrap();

        let ok = engine
            .authorize_mesh_wildcard(&inbound_request("monitoring", "any-svc"))
            .await;
        assert!(ok.is_allowed());

        let denied = engine
            .authorize_mesh_wildcard(&inbound_request("prod", "any-svc"))
            .await;
        assert!(!denied.is_allowed());
    }

    #[tokio::test]
    async fn test_forbid_overrides_permit() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal,
                action == Lattice::Action::"AllowWildcard",
                resource == Lattice::Mesh::"inbound"
            ) when {
                principal.namespace == "monitoring"
            };
            forbid(
                principal == Lattice::Service::"monitoring/untrusted",
                action == Lattice::Action::"AllowWildcard",
                resource == Lattice::Mesh::"inbound"
            );
            "#,
        )
        .unwrap();

        let ok = engine
            .authorize_mesh_wildcard(&inbound_request("monitoring", "vmagent"))
            .await;
        assert!(ok.is_allowed());

        let denied = engine
            .authorize_mesh_wildcard(&inbound_request("monitoring", "untrusted"))
            .await;
        assert!(!denied.is_allowed());
        assert_eq!(denied.reason, Some(DenialReason::ExplicitForbid));
    }

    #[tokio::test]
    async fn test_unscoped_resource_grants_both_directions() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal == Lattice::Service::"monitoring/vmagent",
                action == Lattice::Action::"AllowWildcard",
                resource
            );
            "#,
        )
        .unwrap();

        assert!(engine
            .authorize_mesh_wildcard(&inbound_request("monitoring", "vmagent"))
            .await
            .is_allowed());
        assert!(engine
            .authorize_mesh_wildcard(&outbound_request("monitoring", "vmagent"))
            .await
            .is_allowed());
    }
}
