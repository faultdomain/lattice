//! External endpoint access authorization
//!
//! Evaluates Cedar policies to authorize a service's access to external endpoints.
//! Default-deny: no policies = no external endpoint access.

use crate::engine::{DenialReason, Error, PolicyEngine};
use crate::entities::{build_entity_uid, build_external_endpoint_entity, build_service_entity};

// =============================================================================
// Types
// =============================================================================

/// Request to authorize a service's access to external endpoints
pub struct ExternalEndpointAuthzRequest {
    /// Service name
    pub service_name: String,
    /// Service namespace
    pub namespace: String,
    /// (resource_name, host, port, protocol)
    pub endpoints: Vec<(String, String, u16, String)>,
}

/// Result of authorizing a service's external endpoint access
pub struct ExternalEndpointAuthzResult {
    /// Denied endpoints (empty if all allowed)
    pub denied: Vec<ExternalEndpointDenial>,
}

impl ExternalEndpointAuthzResult {
    /// Check if all external endpoints were allowed
    pub fn is_allowed(&self) -> bool {
        self.denied.is_empty()
    }
}

/// A denied external endpoint with reason
pub struct ExternalEndpointDenial {
    /// LatticeService resource name
    pub resource_name: String,
    /// Denied host
    pub host: String,
    /// Denied port
    pub port: u16,
    /// Why access was denied
    pub reason: DenialReason,
}

// =============================================================================
// Implementation
// =============================================================================

impl PolicyEngine {
    /// Authorize a service's access to its declared external endpoints.
    ///
    /// Evaluates all endpoints in a single call (batch, not per-endpoint awaits).
    /// Default-deny: no policies = all access denied.
    ///
    /// Reads the `RwLock<PolicySet>` once for the batch, then evaluates each
    /// endpoint synchronously against the same snapshot.
    pub async fn authorize_external_endpoints(
        &self,
        request: &ExternalEndpointAuthzRequest,
    ) -> ExternalEndpointAuthzResult {
        let policy_set = self.read_policy_set().await;
        let action_uid = match build_entity_uid("Action", "AccessExternalEndpoint") {
            Ok(uid) => uid,
            Err(e) => {
                return deny_all(request, e);
            }
        };

        let mut denied = Vec::new();

        for (resource_name, host, port, protocol) in &request.endpoints {
            let eval = EndpointEvalContext {
                engine: self,
                namespace: &request.namespace,
                service_name: &request.service_name,
                resource_name,
                host,
                port: *port,
                protocol,
                action_uid: &action_uid,
                policy_set: &policy_set,
            };
            match eval.evaluate() {
                Ok(()) => {}
                Err(denial) => denied.push(denial),
            }
        }

        ExternalEndpointAuthzResult { denied }
    }
}

/// Context for evaluating a single external endpoint authorization.
struct EndpointEvalContext<'a> {
    engine: &'a PolicyEngine,
    namespace: &'a str,
    service_name: &'a str,
    resource_name: &'a str,
    host: &'a str,
    port: u16,
    protocol: &'a str,
    action_uid: &'a cedar_policy::EntityUid,
    policy_set: &'a cedar_policy::PolicySet,
}

impl EndpointEvalContext<'_> {
    fn evaluate(&self) -> std::result::Result<(), ExternalEndpointDenial> {
        let service_entity =
            build_service_entity(self.namespace, self.service_name).map_err(|e| {
                self.denial(DenialReason::InternalError(format!(
                    "service entity: {}",
                    e
                )))
            })?;
        let endpoint_entity = build_external_endpoint_entity(self.host, self.port, self.protocol)
            .map_err(|e| {
            self.denial(DenialReason::InternalError(format!(
                "endpoint entity: {}",
                e
            )))
        })?;

        self.engine
            .evaluate_service_action(
                &service_entity,
                &endpoint_entity,
                self.action_uid,
                self.policy_set,
                "AccessExternalEndpoint",
            )
            .map_err(|reason| self.denial(reason))
    }

    fn denial(&self, reason: DenialReason) -> ExternalEndpointDenial {
        ExternalEndpointDenial {
            resource_name: self.resource_name.to_string(),
            host: self.host.to_string(),
            port: self.port,
            reason,
        }
    }
}

/// Deny all endpoints when we can't even build basic Cedar entities
fn deny_all(request: &ExternalEndpointAuthzRequest, error: Error) -> ExternalEndpointAuthzResult {
    tracing::warn!(%error, "Cedar entity construction failed, denying all external endpoints");
    let reason = DenialReason::InternalError(format!("Cedar entity construction: {error}"));
    let denied = request
        .endpoints
        .iter()
        .map(
            |(resource_name, host, port, _protocol)| ExternalEndpointDenial {
                resource_name: resource_name.clone(),
                host: host.clone(),
                port: *port,
                reason: reason.clone(),
            },
        )
        .collect();
    ExternalEndpointAuthzResult { denied }
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
        endpoints: Vec<(&str, &str, u16, &str)>,
    ) -> ExternalEndpointAuthzRequest {
        ExternalEndpointAuthzRequest {
            service_name: service.to_string(),
            namespace: namespace.to_string(),
            endpoints: endpoints
                .into_iter()
                .map(|(name, host, port, proto)| {
                    (name.to_string(), host.to_string(), port, proto.to_string())
                })
                .collect(),
        }
    }

    #[tokio::test]
    async fn test_default_deny_no_policies() {
        let engine = PolicyEngine::new();
        let request = make_request(
            "payments",
            "checkout",
            vec![("stripe", "api.stripe.com", 443, "https")],
        );

        let result = engine.authorize_external_endpoints(&request).await;

        assert!(!result.is_allowed());
        assert_eq!(result.denied.len(), 1);
        assert_eq!(result.denied[0].reason, DenialReason::NoPermitPolicy);
    }

    #[tokio::test]
    async fn test_permit_specific_endpoint() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal == Lattice::Service::"payments/checkout",
                action == Lattice::Action::"AccessExternalEndpoint",
                resource == Lattice::ExternalEndpoint::"api.stripe.com:443"
            );
            "#,
        )
        .unwrap();

        let request = make_request(
            "payments",
            "checkout",
            vec![("stripe", "api.stripe.com", 443, "https")],
        );

        let result = engine.authorize_external_endpoints(&request).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_permit_by_host_pattern() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal,
                action == Lattice::Action::"AccessExternalEndpoint",
                resource
            ) when {
                principal.namespace == "payments" &&
                resource.host like "*.stripe.com"
            };
            "#,
        )
        .unwrap();

        let request = make_request(
            "payments",
            "checkout",
            vec![("stripe", "api.stripe.com", 443, "https")],
        );

        let result = engine.authorize_external_endpoints(&request).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_permit_namespace_denies_other_namespace() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal,
                action == Lattice::Action::"AccessExternalEndpoint",
                resource
            ) when {
                principal.namespace == "payments" &&
                resource.host like "*.stripe.com"
            };
            "#,
        )
        .unwrap();

        let request = make_request(
            "web",
            "frontend",
            vec![("stripe", "api.stripe.com", 443, "https")],
        );

        let result = engine.authorize_external_endpoints(&request).await;
        assert!(!result.is_allowed());
        assert_eq!(result.denied[0].reason, DenialReason::NoPermitPolicy);
    }

    #[tokio::test]
    async fn test_forbid_overrides_permit() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal,
                action == Lattice::Action::"AccessExternalEndpoint",
                resource
            ) when {
                principal.namespace == "payments"
            };
            forbid(
                principal,
                action == Lattice::Action::"AccessExternalEndpoint",
                resource
            ) when {
                resource.host like "*.evil.com"
            };
            "#,
        )
        .unwrap();

        let ok_request = make_request(
            "payments",
            "checkout",
            vec![("stripe", "api.stripe.com", 443, "https")],
        );
        assert!(engine
            .authorize_external_endpoints(&ok_request)
            .await
            .is_allowed());

        let denied_request = make_request(
            "payments",
            "checkout",
            vec![("bad", "api.evil.com", 443, "https")],
        );
        let result = engine.authorize_external_endpoints(&denied_request).await;
        assert!(!result.is_allowed());
        assert_eq!(result.denied[0].reason, DenialReason::ExplicitForbid);
    }

    #[tokio::test]
    async fn test_no_endpoints_always_allowed() {
        let engine = PolicyEngine::new();
        let request = make_request("any", "any", vec![]);

        let result = engine.authorize_external_endpoints(&request).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_partial_deny_multiple_endpoints() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal == Lattice::Service::"payments/checkout",
                action == Lattice::Action::"AccessExternalEndpoint",
                resource == Lattice::ExternalEndpoint::"api.stripe.com:443"
            );
            "#,
        )
        .unwrap();

        let request = make_request(
            "payments",
            "checkout",
            vec![
                ("stripe", "api.stripe.com", 443, "https"),
                ("unknown", "api.evil.com", 443, "https"),
            ],
        );

        let result = engine.authorize_external_endpoints(&request).await;
        assert!(!result.is_allowed());
        assert_eq!(result.denied.len(), 1);
        assert_eq!(result.denied[0].resource_name, "unknown");
    }
}
