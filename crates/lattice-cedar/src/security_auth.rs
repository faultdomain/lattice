//! Security override authorization
//!
//! Evaluates Cedar policies to authorize a service's security overrides
//! (capabilities, privileged mode, host networking, etc.). Default-deny:
//! no policies = no security relaxations allowed.

use crate::engine::{DenialReason, Error, PolicyEngine};
use crate::entities::{build_entity_uid, build_security_override_entity, build_service_entity};

// =============================================================================
// Types
// =============================================================================

/// Request to authorize a service's security overrides
pub struct SecurityAuthzRequest {
    /// Service name
    pub service_name: String,
    /// Service namespace
    pub namespace: String,
    /// Security overrides to authorize
    pub overrides: Vec<SecurityOverrideRequest>,
}

/// A single security override that requires authorization
pub struct SecurityOverrideRequest {
    /// Override identifier (e.g. "capability:NET_ADMIN", "privileged", "hostNetwork")
    pub override_id: String,
    /// Category of override (e.g. "capability", "pod", "container", "profile")
    pub category: String,
    /// Which container requested it (for error messages); None for pod-level
    pub container: Option<String>,
}

/// Result of authorizing a service's security overrides
pub struct SecurityAuthzResult {
    /// Denied overrides (empty if all allowed)
    pub denied: Vec<SecurityDenial>,
}

impl SecurityAuthzResult {
    /// Check if all overrides were allowed
    pub fn is_allowed(&self) -> bool {
        self.denied.is_empty()
    }
}

/// A denied security override with reason
pub struct SecurityDenial {
    /// Override identifier that was denied
    pub override_id: String,
    /// Which container requested it (None for pod-level)
    pub container: Option<String>,
    /// Why the override was denied
    pub reason: DenialReason,
}

// =============================================================================
// Implementation
// =============================================================================

impl PolicyEngine {
    /// Authorize a service's security overrides.
    ///
    /// Evaluates all overrides in a single call (batch, not per-override awaits).
    /// Default-deny: no policies = all overrides denied.
    ///
    /// Reads the `RwLock<PolicySet>` once for the batch, then evaluates each
    /// override synchronously against the same snapshot.
    pub async fn authorize_security_overrides(
        &self,
        request: &SecurityAuthzRequest,
    ) -> SecurityAuthzResult {
        let policy_set = self.read_policy_set().await;
        let action_uid = match build_entity_uid("Action", "OverrideSecurity") {
            Ok(uid) => uid,
            Err(e) => {
                return deny_all(request, e);
            }
        };

        let mut denied = Vec::new();

        for override_req in &request.overrides {
            let eval = SecurityEvalContext {
                engine: self,
                namespace: &request.namespace,
                service_name: &request.service_name,
                override_req,
                action_uid: &action_uid,
                policy_set: &policy_set,
            };
            match eval.evaluate() {
                Ok(()) => {} // allowed
                Err(denial) => denied.push(denial),
            }
        }

        SecurityAuthzResult { denied }
    }
}

/// Context for evaluating a single security override authorization.
struct SecurityEvalContext<'a> {
    engine: &'a PolicyEngine,
    namespace: &'a str,
    service_name: &'a str,
    override_req: &'a SecurityOverrideRequest,
    action_uid: &'a cedar_policy::EntityUid,
    policy_set: &'a cedar_policy::PolicySet,
}

impl SecurityEvalContext<'_> {
    fn evaluate(&self) -> std::result::Result<(), SecurityDenial> {
        let service_entity = build_service_entity(self.namespace, self.service_name)
            .map_err(|_| self.denial(DenialReason::NoPermitPolicy))?;
        let override_entity = build_security_override_entity(
            &self.override_req.override_id,
            &self.override_req.category,
        )
        .map_err(|_| self.denial(DenialReason::NoPermitPolicy))?;

        self.engine
            .evaluate_service_action(
                &service_entity,
                &override_entity,
                self.action_uid,
                self.policy_set,
                "OverrideSecurity",
            )
            .map_err(|reason| self.denial(reason))
    }

    fn denial(&self, reason: DenialReason) -> SecurityDenial {
        SecurityDenial {
            override_id: self.override_req.override_id.clone(),
            container: self.override_req.container.clone(),
            reason,
        }
    }
}

/// Deny all overrides when we can't even build basic Cedar entities
fn deny_all(request: &SecurityAuthzRequest, error: Error) -> SecurityAuthzResult {
    tracing::warn!(%error, "Cedar entity construction failed, denying all security overrides");
    let denied = request
        .overrides
        .iter()
        .map(|o| SecurityDenial {
            override_id: o.override_id.clone(),
            container: o.container.clone(),
            reason: DenialReason::NoPermitPolicy,
        })
        .collect();
    SecurityAuthzResult { denied }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(
        namespace: &str,
        service: &str,
        overrides: Vec<(&str, &str, Option<&str>)>,
    ) -> SecurityAuthzRequest {
        SecurityAuthzRequest {
            service_name: service.to_string(),
            namespace: namespace.to_string(),
            overrides: overrides
                .into_iter()
                .map(|(id, category, container)| SecurityOverrideRequest {
                    override_id: id.to_string(),
                    category: category.to_string(),
                    container: container.map(|s| s.to_string()),
                })
                .collect(),
        }
    }

    // ========================================================================
    // Default-Deny Tests
    // ========================================================================

    #[tokio::test]
    async fn test_default_deny_no_policies() {
        let engine = PolicyEngine::new();
        let request = make_request(
            "media",
            "nzbget",
            vec![("capability:NET_ADMIN", "capability", Some("vpn"))],
        );

        let result = engine.authorize_security_overrides(&request).await;

        assert!(!result.is_allowed());
        assert_eq!(result.denied.len(), 1);
        assert_eq!(result.denied[0].reason, DenialReason::NoPermitPolicy);
    }

    // ========================================================================
    // Permit Tests
    // ========================================================================

    #[tokio::test]
    async fn test_permit_specific_override() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal == Lattice::Service::"media/nzbget",
                action == Lattice::Action::"OverrideSecurity",
                resource == Lattice::SecurityOverride::"capability:NET_ADMIN"
            );
            "#,
        )
        .unwrap();

        let request = make_request(
            "media",
            "nzbget",
            vec![("capability:NET_ADMIN", "capability", Some("vpn"))],
        );

        let result = engine.authorize_security_overrides(&request).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_permit_by_namespace() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal,
                action == Lattice::Action::"OverrideSecurity",
                resource
            ) when {
                principal.namespace == "legacy"
            };
            "#,
        )
        .unwrap();

        // legacy namespace — allowed
        let ok_request = make_request(
            "legacy",
            "old-app",
            vec![("runAsRoot", "container", Some("main"))],
        );
        assert!(engine
            .authorize_security_overrides(&ok_request)
            .await
            .is_allowed());

        // production namespace — denied
        let denied_request = make_request(
            "production",
            "app",
            vec![("runAsRoot", "container", Some("main"))],
        );
        assert!(!engine
            .authorize_security_overrides(&denied_request)
            .await
            .is_allowed());
    }

    #[tokio::test]
    async fn test_permit_by_category() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal,
                action == Lattice::Action::"OverrideSecurity",
                resource
            ) when {
                principal.namespace == "monitoring" &&
                resource.category == "capability"
            };
            "#,
        )
        .unwrap();

        // monitoring namespace, capability category — allowed
        let ok_request = make_request(
            "monitoring",
            "agent",
            vec![("capability:NET_ADMIN", "capability", Some("main"))],
        );
        assert!(engine
            .authorize_security_overrides(&ok_request)
            .await
            .is_allowed());

        // monitoring namespace, non-capability — denied
        let denied_request = make_request(
            "monitoring",
            "agent",
            vec![("privileged", "container", Some("main"))],
        );
        assert!(!engine
            .authorize_security_overrides(&denied_request)
            .await
            .is_allowed());
    }

    // ========================================================================
    // Forbid Tests
    // ========================================================================

    #[tokio::test]
    async fn test_forbid_overrides_permit() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal,
                action == Lattice::Action::"OverrideSecurity",
                resource
            ) when {
                principal.namespace == "legacy"
            };
            forbid(
                principal,
                action == Lattice::Action::"OverrideSecurity",
                resource == Lattice::SecurityOverride::"privileged"
            );
            "#,
        )
        .unwrap();

        // legacy namespace, runAsRoot — allowed
        let ok_request = make_request(
            "legacy",
            "app",
            vec![("runAsRoot", "container", Some("main"))],
        );
        assert!(engine
            .authorize_security_overrides(&ok_request)
            .await
            .is_allowed());

        // legacy namespace, privileged — denied by forbid
        let denied_request = make_request(
            "legacy",
            "app",
            vec![("privileged", "container", Some("main"))],
        );
        let result = engine
            .authorize_security_overrides(&denied_request)
            .await;
        assert!(!result.is_allowed());
        assert_eq!(result.denied[0].reason, DenialReason::ExplicitForbid);
    }

    // ========================================================================
    // Partial Deny Tests
    // ========================================================================

    #[tokio::test]
    async fn test_partial_deny() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal == Lattice::Service::"media/nzbget",
                action == Lattice::Action::"OverrideSecurity",
                resource == Lattice::SecurityOverride::"capability:NET_ADMIN"
            );
            "#,
        )
        .unwrap();

        let request = make_request(
            "media",
            "nzbget",
            vec![
                ("capability:NET_ADMIN", "capability", Some("vpn")),   // allowed
                ("capability:SYS_MODULE", "capability", Some("vpn")),  // denied
            ],
        );

        let result = engine.authorize_security_overrides(&request).await;
        assert!(!result.is_allowed());
        assert_eq!(result.denied.len(), 1);
        assert_eq!(result.denied[0].override_id, "capability:SYS_MODULE");
        assert_eq!(result.denied[0].reason, DenialReason::NoPermitPolicy);
    }

    // ========================================================================
    // Empty Overrides Tests
    // ========================================================================

    #[tokio::test]
    async fn test_no_overrides_always_allowed() {
        let engine = PolicyEngine::new(); // default-deny
        let request = make_request("any", "any", vec![]);

        let result = engine.authorize_security_overrides(&request).await;
        assert!(result.is_allowed()); // empty overrides = nothing to deny
    }

    // ========================================================================
    // Pod-Level Override Tests
    // ========================================================================

    #[tokio::test]
    async fn test_pod_level_overrides() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal == Lattice::Service::"infra/vpn-gateway",
                action == Lattice::Action::"OverrideSecurity",
                resource
            );
            "#,
        )
        .unwrap();

        let request = make_request(
            "infra",
            "vpn-gateway",
            vec![
                ("hostNetwork", "pod", None),
                ("shareProcessNamespace", "pod", None),
            ],
        );

        let result = engine.authorize_security_overrides(&request).await;
        assert!(result.is_allowed());
    }
}
