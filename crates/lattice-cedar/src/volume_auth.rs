//! Volume access authorization
//!
//! Evaluates Cedar policies to authorize a service's access to shared volumes.

use cedar_policy::{Context, Decision, Entities, EntityUid, PolicySet};

use crate::engine::{DenialReason, Error, PolicyEngine};
use crate::entities::{build_entity_uid, build_service_entity, build_volume_entity};

// =============================================================================
// Types
// =============================================================================

/// Request to authorize a service's volume access
pub struct VolumeAuthzRequest {
    /// Service name
    pub service_name: String,
    /// Service namespace
    pub namespace: String,
    /// Workload kind ("service", "job", "model")
    pub kind: String,
    /// Volume references to authorize: (resource_name, volume_namespace, volume_id)
    pub volume_refs: Vec<(String, String, String)>,
    /// When true, an explicit `permit` policy is required (default-deny).
    /// When false, no-policies-matched is treated as allowed (permissive default).
    ///
    /// Use `require_explicit_permit = false` when owner consent has already been
    /// verified as a first authorization layer. Use `true` when Cedar is the sole
    /// authorization gate.
    pub require_explicit_permit: bool,
}

/// Result of authorizing a service's volume access
pub struct VolumeAuthzResult {
    /// Denied volumes (empty if all allowed)
    pub denied: Vec<VolumeDenial>,
}

impl VolumeAuthzResult {
    /// Check if all volume accesses were allowed
    pub fn is_allowed(&self) -> bool {
        self.denied.is_empty()
    }
}

/// A denied volume access with reason
pub struct VolumeDenial {
    /// Resource name in the service spec
    pub resource_name: String,
    /// Volume ID that was denied
    pub volume_id: String,
    /// Why the access was denied
    pub reason: DenialReason,
}

// =============================================================================
// Implementation
// =============================================================================

impl PolicyEngine {
    /// Authorize a service's volume access.
    ///
    /// Evaluates all volume references in a single call (batch).
    /// Behavior depends on `request.require_explicit_permit`:
    /// - `false` (permissive): no policies = allowed (owner consent is the primary gate)
    /// - `true` (strict): no policies = denied (Cedar is the sole gate)
    ///
    /// Reads the `RwLock<PolicySet>` once for the batch, then evaluates each
    /// volume synchronously against the same snapshot.
    pub async fn authorize_volumes(&self, request: &VolumeAuthzRequest) -> VolumeAuthzResult {
        let policy_set = self.read_policy_set();

        let action_uid = match build_entity_uid("Action", "AccessVolume") {
            Ok(uid) => uid,
            Err(e) => {
                return deny_all(request, e);
            }
        };

        let mut denied = Vec::new();

        for (resource_name, vol_ns, volume_id) in &request.volume_refs {
            let eval = VolumeEvalContext {
                engine: self,
                namespace: &request.namespace,
                service_name: &request.service_name,
                kind: &request.kind,
                resource_name,
                vol_ns,
                volume_id,
                action_uid: &action_uid,
                policy_set: &policy_set,
                require_explicit_permit: request.require_explicit_permit,
            };
            match eval.evaluate() {
                Ok(()) => {} // allowed
                Err(denial) => denied.push(denial),
            }
        }

        VolumeAuthzResult { denied }
    }
}

/// Context for evaluating a single volume access authorization.
struct VolumeEvalContext<'a> {
    engine: &'a PolicyEngine,
    namespace: &'a str,
    service_name: &'a str,
    kind: &'a str,
    resource_name: &'a str,
    vol_ns: &'a str,
    volume_id: &'a str,
    action_uid: &'a EntityUid,
    policy_set: &'a PolicySet,
    require_explicit_permit: bool,
}

impl VolumeEvalContext<'_> {
    fn evaluate(&self) -> std::result::Result<(), VolumeDenial> {
        let service_entity = build_service_entity(self.namespace, self.service_name, self.kind)
            .map_err(|e| {
                self.denial(DenialReason::InternalError(format!(
                    "service entity: {}",
                    e
                )))
            })?;
        let volume_entity = build_volume_entity(self.vol_ns, self.volume_id).map_err(|e| {
            self.denial(DenialReason::InternalError(format!("volume entity: {}", e)))
        })?;

        let principal_uid = service_entity.uid().clone();
        let resource_uid = volume_entity.uid().clone();
        let entities = Entities::from_entities(vec![service_entity, volume_entity], None)
            .map_err(|e| self.denial(DenialReason::InternalError(format!("entities: {}", e))))?;

        let response = self
            .engine
            .evaluate_raw(
                &principal_uid,
                self.action_uid,
                &resource_uid,
                Context::empty(),
                &entities,
                self.policy_set,
            )
            .map_err(|e| self.denial(DenialReason::InternalError(format!("evaluation: {}", e))))?;

        match response.decision() {
            Decision::Allow => {
                lattice_common::metrics::record_cedar_decision(
                    lattice_common::metrics::AuthDecision::Allow,
                    "AccessVolume",
                );
                Ok(())
            }
            Decision::Deny => {
                let has_determining_policies = response.diagnostics().reason().next().is_some();

                if has_determining_policies {
                    // Explicit forbid policy matched — always deny
                    lattice_common::metrics::record_cedar_decision(
                        lattice_common::metrics::AuthDecision::Deny,
                        "AccessVolume",
                    );
                    Err(self.denial(DenialReason::ExplicitForbid))
                } else if self.require_explicit_permit {
                    // No policies matched and we require explicit permit — deny
                    lattice_common::metrics::record_cedar_decision(
                        lattice_common::metrics::AuthDecision::Deny,
                        "AccessVolume",
                    );
                    Err(self.denial(DenialReason::NoPermitPolicy))
                } else {
                    // No policies matched, permissive mode — allow.
                    // Log at warn level: if this appears in production it means
                    // Cedar is providing zero protection for this volume access.
                    tracing::warn!(
                        principal = %format!("{}/{}", self.namespace, self.service_name),
                        resource = %format!("{}/{}", self.vol_ns, self.volume_id),
                        "Volume access allowed in permissive mode with no Cedar policies — Cedar provides no protection"
                    );
                    Ok(())
                }
            }
        }
    }

    fn denial(&self, reason: DenialReason) -> VolumeDenial {
        VolumeDenial {
            resource_name: self.resource_name.to_string(),
            volume_id: self.volume_id.to_string(),
            reason,
        }
    }
}

/// Deny all volumes when we can't even build basic Cedar entities
fn deny_all(request: &VolumeAuthzRequest, error: Error) -> VolumeAuthzResult {
    tracing::warn!(%error, "Cedar entity construction failed, denying all volume access");
    let denied = request
        .volume_refs
        .iter()
        .map(|(resource_name, _, volume_id)| VolumeDenial {
            resource_name: resource_name.clone(),
            volume_id: volume_id.clone(),
            reason: DenialReason::InternalError(format!("Cedar entity construction: {}", error)),
        })
        .collect();
    VolumeAuthzResult { denied }
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
        refs: Vec<(&str, &str, &str)>,
    ) -> VolumeAuthzRequest {
        VolumeAuthzRequest {
            service_name: service.to_string(),
            namespace: namespace.to_string(),
            kind: "service".to_string(),
            volume_refs: refs
                .into_iter()
                .map(|(name, ns, id)| (name.to_string(), ns.to_string(), id.to_string()))
                .collect(),
            require_explicit_permit: false,
        }
    }

    fn make_strict_request(
        namespace: &str,
        service: &str,
        refs: Vec<(&str, &str, &str)>,
    ) -> VolumeAuthzRequest {
        VolumeAuthzRequest {
            service_name: service.to_string(),
            namespace: namespace.to_string(),
            kind: "service".to_string(),
            volume_refs: refs
                .into_iter()
                .map(|(name, ns, id)| (name.to_string(), ns.to_string(), id.to_string()))
                .collect(),
            require_explicit_permit: true,
        }
    }

    // ========================================================================
    // Permissive Default Tests
    // ========================================================================

    #[tokio::test]
    async fn test_no_policies_allows_all_permissive() {
        let engine = PolicyEngine::new();
        let request = make_request(
            "media",
            "plex",
            vec![("downloads", "media", "media-storage")],
        );

        let result = engine.authorize_volumes(&request).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_empty_refs_always_allowed() {
        let engine = PolicyEngine::new();
        let request = make_request("any", "any", vec![]);

        let result = engine.authorize_volumes(&request).await;
        assert!(result.is_allowed());
    }

    // ========================================================================
    // Strict Mode (require_explicit_permit) Tests
    // ========================================================================

    #[tokio::test]
    async fn test_no_policies_denies_in_strict_mode() {
        let engine = PolicyEngine::new();
        let request = make_strict_request(
            "media",
            "plex",
            vec![("downloads", "media", "media-storage")],
        );

        let result = engine.authorize_volumes(&request).await;
        assert!(!result.is_allowed());
        assert_eq!(result.denied.len(), 1);
        assert_eq!(result.denied[0].reason, DenialReason::NoPermitPolicy);
    }

    #[tokio::test]
    async fn test_explicit_permit_allows_in_strict_mode() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal == Lattice::Service::"media/plex",
                action == Lattice::Action::"AccessVolume",
                resource == Lattice::Volume::"media/media-storage"
            );
            "#,
        )
        .unwrap();

        let request = make_strict_request(
            "media",
            "plex",
            vec![("downloads", "media", "media-storage")],
        );

        let result = engine.authorize_volumes(&request).await;
        assert!(result.is_allowed());
    }

    // ========================================================================
    // Forbid Tests
    // ========================================================================

    #[tokio::test]
    async fn test_forbid_denies_volume_access() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal,
                action == Lattice::Action::"AccessVolume",
                resource
            );
            forbid(
                principal == Lattice::Service::"media/plex",
                action == Lattice::Action::"AccessVolume",
                resource == Lattice::Volume::"media/media-storage"
            );
            "#,
        )
        .unwrap();

        let request = make_request(
            "media",
            "plex",
            vec![("downloads", "media", "media-storage")],
        );

        let result = engine.authorize_volumes(&request).await;
        assert!(!result.is_allowed());
        assert_eq!(result.denied.len(), 1);
        assert_eq!(result.denied[0].reason, DenialReason::ExplicitForbid);
    }

    // ========================================================================
    // Permit with Forbid Override Tests
    // ========================================================================

    #[tokio::test]
    async fn test_unrelated_secret_policies_dont_block_volumes() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal == Lattice::Service::"media/plex",
                action == Lattice::Action::"AccessSecret",
                resource == Lattice::SecretPath::"vault:secrets/media/plex"
            );
            "#,
        )
        .unwrap();

        let request = make_request(
            "media",
            "plex",
            vec![("downloads", "media", "media-storage")],
        );

        let result = engine.authorize_volumes(&request).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_permit_allows_volume_access() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal == Lattice::Service::"media/plex",
                action == Lattice::Action::"AccessVolume",
                resource == Lattice::Volume::"media/media-storage"
            );
            "#,
        )
        .unwrap();

        let request = make_request(
            "media",
            "plex",
            vec![("downloads", "media", "media-storage")],
        );

        let result = engine.authorize_volumes(&request).await;
        assert!(result.is_allowed());
    }
}
