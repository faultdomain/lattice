//! Secret access authorization
//!
//! Evaluates Cedar policies to authorize a service's access to its declared
//! secret paths. Default-deny: no policies = no secrets.

use crate::engine::{DenialReason, Error, PolicyEngine};
use crate::entities::{build_entity_uid, build_secret_path_entity, build_service_entity};

// =============================================================================
// Types
// =============================================================================

/// Request to authorize a service's access to its declared secret paths
pub struct SecretAuthzRequest {
    /// Service name
    pub service_name: String,
    /// Service namespace
    pub namespace: String,
    /// (resource_name, remote_key, provider_name)
    pub secret_paths: Vec<(String, String, String)>,
}

/// Result of authorizing a service's secret access
pub struct SecretAuthzResult {
    /// Denied paths (empty if all allowed)
    pub denied: Vec<SecretDenial>,
}

impl SecretAuthzResult {
    /// Check if all secret paths were allowed
    pub fn is_allowed(&self) -> bool {
        self.denied.is_empty()
    }
}

/// A denied secret path with reason
pub struct SecretDenial {
    /// LatticeService resource name
    pub resource_name: String,
    /// Vault path that was denied
    pub remote_key: String,
    /// Provider name
    pub provider: String,
    /// Why access was denied
    pub reason: DenialReason,
}

// =============================================================================
// Implementation
// =============================================================================

impl PolicyEngine {
    /// Authorize a service's access to its declared secret paths.
    ///
    /// Evaluates all paths in a single call (batch, not per-secret awaits).
    /// Default-deny: no policies = all access denied.
    ///
    /// Reads the `RwLock<PolicySet>` once for the batch, then evaluates each
    /// path synchronously against the same snapshot.
    pub async fn authorize_secrets(&self, request: &SecretAuthzRequest) -> SecretAuthzResult {
        let policy_set = self.read_policy_set().await;
        let action_uid = match build_entity_uid("Action", "AccessSecret") {
            Ok(uid) => uid,
            Err(e) => {
                // If we can't even build the action UID, deny everything
                return deny_all(request, e);
            }
        };

        let mut denied = Vec::new();

        for (resource_name, remote_key, provider) in &request.secret_paths {
            let eval = SecretEvalContext {
                engine: self,
                namespace: &request.namespace,
                service_name: &request.service_name,
                resource_name,
                remote_key,
                provider,
                action_uid: &action_uid,
                policy_set: &policy_set,
            };
            match eval.evaluate() {
                Ok(()) => {} // allowed
                Err(denial) => denied.push(denial),
            }
        }

        SecretAuthzResult { denied }
    }
}

/// Context for evaluating a single secret path authorization.
struct SecretEvalContext<'a> {
    engine: &'a PolicyEngine,
    namespace: &'a str,
    service_name: &'a str,
    resource_name: &'a str,
    remote_key: &'a str,
    provider: &'a str,
    action_uid: &'a cedar_policy::EntityUid,
    policy_set: &'a cedar_policy::PolicySet,
}

impl SecretEvalContext<'_> {
    fn evaluate(&self) -> std::result::Result<(), SecretDenial> {
        let service_entity = build_service_entity(self.namespace, self.service_name)
            .map_err(|_| self.denial(DenialReason::NoPermitPolicy))?;
        let secret_entity = build_secret_path_entity(self.provider, self.remote_key)
            .map_err(|_| self.denial(DenialReason::NoPermitPolicy))?;

        self.engine
            .evaluate_service_action(
                &service_entity,
                &secret_entity,
                self.action_uid,
                self.policy_set,
                "AccessSecret",
            )
            .map_err(|reason| self.denial(reason))
    }

    fn denial(&self, reason: DenialReason) -> SecretDenial {
        SecretDenial {
            resource_name: self.resource_name.to_string(),
            remote_key: self.remote_key.to_string(),
            provider: self.provider.to_string(),
            reason,
        }
    }
}

/// Deny all paths when we can't even build basic Cedar entities
fn deny_all(request: &SecretAuthzRequest, error: Error) -> SecretAuthzResult {
    tracing::warn!(%error, "Cedar entity construction failed, denying all secret paths");
    let denied = request
        .secret_paths
        .iter()
        .map(|(resource_name, remote_key, provider)| SecretDenial {
            resource_name: resource_name.clone(),
            remote_key: remote_key.clone(),
            provider: provider.clone(),
            reason: DenialReason::NoPermitPolicy,
        })
        .collect();
    SecretAuthzResult { denied }
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
        paths: Vec<(&str, &str, &str)>,
    ) -> SecretAuthzRequest {
        SecretAuthzRequest {
            service_name: service.to_string(),
            namespace: namespace.to_string(),
            secret_paths: paths
                .into_iter()
                .map(|(name, path, provider)| {
                    (name.to_string(), path.to_string(), provider.to_string())
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
            "payments",
            "checkout",
            vec![("db-creds", "database/prod/creds", "vault-prod")],
        );

        let result = engine.authorize_secrets(&request).await;

        assert!(!result.is_allowed());
        assert_eq!(result.denied.len(), 1);
        assert_eq!(result.denied[0].reason, DenialReason::NoPermitPolicy);
    }

    // ========================================================================
    // Permit Tests
    // ========================================================================

    #[tokio::test]
    async fn test_permit_specific_path() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal == Lattice::Service::"payments/checkout",
                action == Lattice::Action::"AccessSecret",
                resource == Lattice::SecretPath::"vault-prod:database/prod/checkout-creds"
            );
            "#,
        )
        .unwrap();

        let request = make_request(
            "payments",
            "checkout",
            vec![("db-creds", "database/prod/checkout-creds", "vault-prod")],
        );

        let result = engine.authorize_secrets(&request).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_permit_by_namespace_with_path_like() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal,
                action == Lattice::Action::"AccessSecret",
                resource
            ) when {
                principal.namespace == "payments" &&
                resource.path like "secret/data/payments/*"
            };
            "#,
        )
        .unwrap();

        let request = make_request(
            "payments",
            "checkout",
            vec![("api-key", "secret/data/payments/api-key", "vault-prod")],
        );

        let result = engine.authorize_secrets(&request).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_permit_namespace_denies_other_namespace() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal,
                action == Lattice::Action::"AccessSecret",
                resource
            ) when {
                principal.namespace == "payments" &&
                resource.path like "secret/data/payments/*"
            };
            "#,
        )
        .unwrap();

        // web namespace trying to access payments secrets
        let request = make_request(
            "web",
            "frontend",
            vec![("stolen", "secret/data/payments/api-key", "vault-prod")],
        );

        let result = engine.authorize_secrets(&request).await;
        assert!(!result.is_allowed());
        assert_eq!(result.denied[0].reason, DenialReason::NoPermitPolicy);
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
                action == Lattice::Action::"AccessSecret",
                resource
            ) when {
                principal.namespace == "staging"
            };
            forbid(
                principal,
                action == Lattice::Action::"AccessSecret",
                resource
            ) when {
                principal.namespace == "staging" &&
                resource.path like "*/prod/*"
            };
            "#,
        )
        .unwrap();

        // staging accessing staging secrets — allowed
        let ok_request = make_request(
            "staging",
            "app",
            vec![("key", "secret/data/staging/key", "vault")],
        );
        assert!(engine.authorize_secrets(&ok_request).await.is_allowed());

        // staging accessing prod secrets — denied by forbid
        let denied_request = make_request(
            "staging",
            "app",
            vec![("key", "secret/data/prod/key", "vault")],
        );
        let result = engine.authorize_secrets(&denied_request).await;
        assert!(!result.is_allowed());
        assert_eq!(result.denied[0].reason, DenialReason::ExplicitForbid);
    }

    // ========================================================================
    // Partial Deny Tests
    // ========================================================================

    #[tokio::test]
    async fn test_partial_deny_multiple_paths() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal == Lattice::Service::"payments/checkout",
                action == Lattice::Action::"AccessSecret",
                resource == Lattice::SecretPath::"vault-prod:database/prod/checkout-creds"
            );
            "#,
        )
        .unwrap();

        let request = make_request(
            "payments",
            "checkout",
            vec![
                ("db-creds", "database/prod/checkout-creds", "vault-prod"), // allowed
                ("admin-creds", "database/prod/admin-creds", "vault-prod"), // denied
            ],
        );

        let result = engine.authorize_secrets(&request).await;
        assert!(!result.is_allowed());
        assert_eq!(result.denied.len(), 1);
        assert_eq!(result.denied[0].resource_name, "admin-creds");
        assert_eq!(result.denied[0].reason, DenialReason::NoPermitPolicy);
    }

    // ========================================================================
    // Provider Attribute Tests
    // ========================================================================

    #[tokio::test]
    async fn test_provider_attribute_matching() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal,
                action == Lattice::Action::"AccessSecret",
                resource
            ) when {
                principal.namespace == "platform" &&
                resource.provider == "vault-admin"
            };
            "#,
        )
        .unwrap();

        // platform namespace using vault-admin — allowed
        let ok_request = make_request(
            "platform",
            "infra-tool",
            vec![("secret", "admin/key", "vault-admin")],
        );
        assert!(engine.authorize_secrets(&ok_request).await.is_allowed());

        // platform namespace using vault-prod — denied
        let denied_request = make_request(
            "platform",
            "infra-tool",
            vec![("secret", "admin/key", "vault-prod")],
        );
        assert!(!engine.authorize_secrets(&denied_request).await.is_allowed());
    }

    #[tokio::test]
    async fn test_provider_uid_stability() {
        // Same path, different providers = different UIDs = different authorization
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal,
                action == Lattice::Action::"AccessSecret",
                resource == Lattice::SecretPath::"vault-a:secret/foo"
            );
            "#,
        )
        .unwrap();

        // vault-a provider — allowed
        let ok_request = make_request("ns", "svc", vec![("s", "secret/foo", "vault-a")]);
        assert!(engine.authorize_secrets(&ok_request).await.is_allowed());

        // vault-b provider — denied (different UID)
        let denied_request = make_request("ns", "svc", vec![("s", "secret/foo", "vault-b")]);
        assert!(!engine.authorize_secrets(&denied_request).await.is_allowed());
    }

    // ========================================================================
    // Empty Paths Tests
    // ========================================================================

    #[tokio::test]
    async fn test_no_secrets_always_allowed() {
        let engine = PolicyEngine::new(); // default-deny
        let request = make_request("any", "any", vec![]);

        let result = engine.authorize_secrets(&request).await;
        assert!(result.is_allowed()); // empty paths = nothing to deny
    }
}
