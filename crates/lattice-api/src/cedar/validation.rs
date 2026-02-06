//! CedarPolicy validation controller
//!
//! Watches CedarPolicy CRDs and validates their Cedar policy syntax,
//! updating status fields (phase, permit_count, forbid_count, validation_errors).

use std::sync::Arc;
use std::time::Duration;

use cedar_policy::{Effect, PolicySet};
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::ResourceExt;
use tracing::{debug, info, warn};

use lattice_common::crd::{CedarPolicy, CedarPolicyPhase, CedarPolicyStatus};
use lattice_common::{ControllerContext, ReconcileError, LATTICE_SYSTEM_NAMESPACE};

/// Requeue interval for successful reconciliation
const REQUEUE_SUCCESS_SECS: u64 = 300;
/// Requeue interval on error
const REQUEUE_ERROR_SECS: u64 = 60;

/// Reconcile a CedarPolicy — validate syntax and update status
pub async fn reconcile(
    policy: Arc<CedarPolicy>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = policy.name_any();
    let client = &ctx.client;

    info!(cedar_policy = %name, "Reconciling CedarPolicy");

    let new_status = validate_policy(&policy);

    // Check if status already matches — avoid update loop
    if let Some(ref current_status) = policy.status {
        if current_status.phase == new_status.phase
            && current_status.permit_count == new_status.permit_count
            && current_status.forbid_count == new_status.forbid_count
            && current_status.validation_errors == new_status.validation_errors
        {
            debug!(cedar_policy = %name, "Status unchanged, skipping update");
            return Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)));
        }
    }

    // Update status
    let namespace = policy
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());

    let patch = serde_json::json!({
        "status": new_status
    });

    let api: Api<CedarPolicy> = Api::namespaced(client.clone(), &namespace);
    api.patch_status(
        &name,
        &PatchParams::apply("lattice-cedar-validation"),
        &Patch::Merge(&patch),
    )
    .await
    .map_err(|e| ReconcileError::Kube(format!("failed to update CedarPolicy status: {e}")))?;

    let requeue = if new_status.phase == CedarPolicyPhase::Valid {
        REQUEUE_SUCCESS_SECS
    } else {
        REQUEUE_ERROR_SECS
    };

    info!(
        cedar_policy = %name,
        phase = ?new_status.phase,
        permits = new_status.permit_count,
        forbids = new_status.forbid_count,
        errors = new_status.validation_errors.len(),
        "CedarPolicy status updated"
    );

    Ok(Action::requeue(Duration::from_secs(requeue)))
}

/// Validate a CedarPolicy and produce the new status
fn validate_policy(policy: &CedarPolicy) -> CedarPolicyStatus {
    let now = chrono::Utc::now().to_rfc3339();

    // Disabled policies are always valid (no evaluation)
    if !policy.spec.enabled {
        return CedarPolicyStatus {
            phase: CedarPolicyPhase::Valid,
            message: Some("Policy is disabled".to_string()),
            permit_count: 0,
            forbid_count: 0,
            last_validated: Some(now),
            validation_errors: vec![],
        };
    }

    match policy.spec.policies.parse::<PolicySet>() {
        Ok(parsed) => {
            let mut permit_count: u32 = 0;
            let mut forbid_count: u32 = 0;

            for p in parsed.policies() {
                match p.effect() {
                    Effect::Permit => permit_count += 1,
                    Effect::Forbid => forbid_count += 1,
                }
            }

            CedarPolicyStatus {
                phase: CedarPolicyPhase::Valid,
                message: Some(format!(
                    "{} permit, {} forbid statements",
                    permit_count, forbid_count
                )),
                permit_count,
                forbid_count,
                last_validated: Some(now),
                validation_errors: vec![],
            }
        }
        Err(parse_errors) => {
            let errors: Vec<String> = parse_errors.iter().map(|e| e.to_string()).collect();

            warn!(
                cedar_policy = ?policy.metadata.name,
                error_count = errors.len(),
                "CedarPolicy has parse errors"
            );

            CedarPolicyStatus {
                phase: CedarPolicyPhase::Invalid,
                message: Some(format!("{} parse error(s)", errors.len())),
                permit_count: 0,
                forbid_count: 0,
                last_validated: Some(now),
                validation_errors: errors,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::CedarPolicySpec;

    fn make_policy(name: &str, policies: &str, enabled: bool) -> CedarPolicy {
        let mut cp = CedarPolicy::new(
            name,
            CedarPolicySpec {
                description: None,
                policies: policies.to_string(),
                priority: 0,
                enabled,
                propagate: true,
            },
        );
        cp.metadata.namespace = Some("lattice-system".to_string());
        cp
    }

    #[test]
    fn valid_permit_policy() {
        let cp = make_policy("test", "permit(principal, action, resource);", true);
        let status = validate_policy(&cp);

        assert_eq!(status.phase, CedarPolicyPhase::Valid);
        assert_eq!(status.permit_count, 1);
        assert_eq!(status.forbid_count, 0);
        assert!(status.validation_errors.is_empty());
        assert!(status.last_validated.is_some());
    }

    #[test]
    fn valid_forbid_policy() {
        let cp = make_policy(
            "test",
            r#"forbid(principal, action, resource == Lattice::Cluster::"prod");"#,
            true,
        );
        let status = validate_policy(&cp);

        assert_eq!(status.phase, CedarPolicyPhase::Valid);
        assert_eq!(status.permit_count, 0);
        assert_eq!(status.forbid_count, 1);
        assert!(status.validation_errors.is_empty());
    }

    #[test]
    fn mixed_permit_forbid() {
        let cp = make_policy(
            "test",
            r#"
            permit(principal, action, resource);
            forbid(principal, action, resource == Lattice::Cluster::"prod");
            permit(principal in Lattice::Group::"admins", action, resource);
            "#,
            true,
        );
        let status = validate_policy(&cp);

        assert_eq!(status.phase, CedarPolicyPhase::Valid);
        assert_eq!(status.permit_count, 2);
        assert_eq!(status.forbid_count, 1);
    }

    #[test]
    fn invalid_syntax() {
        let cp = make_policy("test", "this is not valid cedar syntax;", true);
        let status = validate_policy(&cp);

        assert_eq!(status.phase, CedarPolicyPhase::Invalid);
        assert_eq!(status.permit_count, 0);
        assert_eq!(status.forbid_count, 0);
        assert!(!status.validation_errors.is_empty());
        assert!(status.message.unwrap().contains("parse error"));
    }

    #[test]
    fn disabled_policy_always_valid() {
        let cp = make_policy("test", "this is not valid cedar syntax;", false);
        let status = validate_policy(&cp);

        assert_eq!(status.phase, CedarPolicyPhase::Valid);
        assert_eq!(status.permit_count, 0);
        assert_eq!(status.forbid_count, 0);
        assert!(status.validation_errors.is_empty());
        assert_eq!(status.message.unwrap(), "Policy is disabled");
    }

    #[test]
    fn empty_policy_text() {
        let cp = make_policy("test", "", true);
        let status = validate_policy(&cp);

        // Empty string parses as valid with 0 policies
        assert_eq!(status.phase, CedarPolicyPhase::Valid);
        assert_eq!(status.permit_count, 0);
        assert_eq!(status.forbid_count, 0);
    }

    #[test]
    fn requeue_constants() {
        assert_eq!(REQUEUE_SUCCESS_SECS, 300);
        assert_eq!(REQUEUE_ERROR_SECS, 60);
    }
}
