//! LatticeServicePolicy controller
//!
//! Watches LatticeServicePolicy CRDs and updates their status with matched
//! service counts. When a policy changes, triggers re-reconciliation of
//! affected services so their backup annotations are updated.

use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::ResourceExt;
use tracing::{debug, info, warn};

use lattice_common::crd::{
    LatticeService, LatticeServicePolicy, LatticeServicePolicyStatus, ServicePolicyPhase,
};
use lattice_common::{ControllerContext, ReconcileError};

/// Reconcile a LatticeServicePolicy
///
/// Lists all services, checks which match the policy's selector, and updates
/// the policy status with the match count and service refs.
pub async fn reconcile(
    policy: Arc<LatticeServicePolicy>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = policy.name_any();
    let namespace = policy.namespace().unwrap_or_default();
    let client = &ctx.client;

    info!(policy = %name, namespace = %namespace, "Reconciling LatticeServicePolicy");

    // List all services to find matches
    let services: Api<LatticeService> = Api::all(client.clone());
    let service_list = services
        .list(&ListParams::default())
        .await
        .map_err(|e| ReconcileError::Kube(format!("failed to list services: {}", e)))?;

    // Check which services match this policy's selector
    let mut matched_refs = Vec::new();
    for svc in &service_list.items {
        let svc_name = ResourceExt::name_any(svc);
        let svc_namespace = ResourceExt::namespace(svc).unwrap_or_default();
        let svc_labels = ResourceExt::labels(svc);

        // Use empty labels for namespace (we don't have namespace objects here)
        let ns_labels = std::collections::BTreeMap::new();

        if policy
            .spec
            .selector
            .matches(svc_labels, &ns_labels, &namespace, &svc_namespace)
        {
            matched_refs.push(format!("{}/{}", svc_namespace, svc_name));
        }
    }

    let matched_count = matched_refs.len() as u32;

    debug!(
        policy = %name,
        matched = matched_count,
        "Policy selector matched services"
    );

    // Update status
    let status = LatticeServicePolicyStatus {
        phase: ServicePolicyPhase::Active,
        matched_services: matched_count,
        matched_service_refs: matched_refs,
        conditions: vec![],
        message: Some(format!("Matching {} services", matched_count)),
        observed_generation: policy.metadata.generation,
    };

    let status_patch = serde_json::json!({ "status": status });
    let policies: Api<LatticeServicePolicy> = Api::namespaced(client.clone(), &namespace);
    policies
        .patch_status(
            &name,
            &PatchParams::apply("lattice-controller"),
            &Patch::Merge(&status_patch),
        )
        .await
        .map_err(|e| {
            warn!(policy = %name, error = %e, "Failed to update policy status");
            ReconcileError::Kube(format!("status update failed: {}", e))
        })?;

    // Requeue periodically
    Ok(Action::requeue(Duration::from_secs(120)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{LatticeServicePolicySpec, ServiceSelector};

    #[test]
    fn test_policy_spec_with_backup() {
        use lattice_common::crd::{
            BackupHook, BackupHooksSpec, HookErrorAction, ServiceBackupSpec,
        };

        let spec = LatticeServicePolicySpec {
            selector: ServiceSelector::default(),
            description: Some("Database backup policy".to_string()),
            priority: 100,
            backup: Some(ServiceBackupSpec {
                hooks: Some(BackupHooksSpec {
                    pre: vec![BackupHook {
                        name: "freeze".to_string(),
                        container: "main".to_string(),
                        command: vec!["/bin/sh".to_string(), "-c".to_string(), "sync".to_string()],
                        timeout: Some("60s".to_string()),
                        on_error: HookErrorAction::Fail,
                    }],
                    post: vec![],
                }),
                volumes: None,
            }),
        };

        assert_eq!(spec.priority, 100);
        assert!(spec.backup.is_some());
        assert_eq!(
            spec.backup.as_ref().unwrap().hooks.as_ref().unwrap().pre[0].name,
            "freeze"
        );
    }
}
