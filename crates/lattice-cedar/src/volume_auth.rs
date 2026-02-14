//! Volume access authorization
//!
//! Evaluates Cedar policies to authorize a service's access to shared volumes.
//! Permissive by default: no policies = all volume access allowed (owner consent
//! is the primary gate, Cedar is the secondary layer).

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
    /// Volume references to authorize: (resource_name, volume_namespace, volume_id)
    pub volume_refs: Vec<(String, String, String)>,
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
    /// **Permissive by default**: no policies = all access allowed.
    /// Only an explicit `forbid` policy will deny access.
    ///
    /// Reads the `RwLock<PolicySet>` once for the batch, then evaluates each
    /// volume synchronously against the same snapshot.
    pub async fn authorize_volumes(&self, request: &VolumeAuthzRequest) -> VolumeAuthzResult {
        let policy_set = self.read_policy_set().await;

        // If no policies are loaded, permit everything (permissive by default)
        if policy_set.is_empty() {
            return VolumeAuthzResult { denied: Vec::new() };
        }

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
                resource_name,
                vol_ns,
                volume_id,
                action_uid: &action_uid,
                policy_set: &policy_set,
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
    resource_name: &'a str,
    vol_ns: &'a str,
    volume_id: &'a str,
    action_uid: &'a cedar_policy::EntityUid,
    policy_set: &'a cedar_policy::PolicySet,
}

impl VolumeEvalContext<'_> {
    fn evaluate(&self) -> std::result::Result<(), VolumeDenial> {
        let service_entity = build_service_entity(self.namespace, self.service_name)
            .map_err(|_| self.denial(DenialReason::NoPermitPolicy))?;
        let volume_entity = build_volume_entity(self.vol_ns, self.volume_id)
            .map_err(|_| self.denial(DenialReason::NoPermitPolicy))?;

        self.engine
            .evaluate_service_action(
                &service_entity,
                &volume_entity,
                self.action_uid,
                self.policy_set,
                "AccessVolume",
            )
            .map_err(|reason| self.denial(reason))
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
            reason: DenialReason::NoPermitPolicy,
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
            volume_refs: refs
                .into_iter()
                .map(|(name, ns, id)| (name.to_string(), ns.to_string(), id.to_string()))
                .collect(),
        }
    }

    // ========================================================================
    // Permissive Default Tests
    // ========================================================================

    #[tokio::test]
    async fn test_no_policies_allows_all() {
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
