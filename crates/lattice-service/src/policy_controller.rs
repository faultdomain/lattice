//! LatticeServicePolicy controller
//!
//! Watches LatticeServicePolicy CRDs and updates their status with matched
//! service counts. When a policy changes, triggers re-reconciliation of
//! affected services so their backup annotations are updated.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, ListParams};
use kube::runtime::controller::Action;
use kube::ResourceExt;
use tracing::{debug, info, warn};

use crate::controller::fetch_namespace_labels;

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
        .map_err(|e| ReconcileError::kube("failed to list services", e))?;

    // Fetch namespace labels for selector matching (cache to avoid refetching)
    let mut ns_label_cache: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();

    // Check which services match this policy's selector
    let mut matched_refs = Vec::new();
    for svc in &service_list.items {
        let svc_name = ResourceExt::name_any(svc);
        let svc_namespace = ResourceExt::namespace(svc).unwrap_or_default();
        let svc_labels = ResourceExt::labels(svc);

        // Look up namespace labels from cache or fetch
        let ns_labels = if let Some(cached) = ns_label_cache.get(&svc_namespace) {
            cached.clone()
        } else {
            let labels = fetch_namespace_labels(client, &svc_namespace)
                .await
                .unwrap_or_default();
            ns_label_cache.insert(svc_namespace.clone(), labels.clone());
            labels
        };

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

    // Build new status
    let status = LatticeServicePolicyStatus {
        phase: ServicePolicyPhase::Active,
        matched_services: matched_count,
        matched_service_refs: matched_refs,
        conditions: vec![],
        message: Some(format!("Matching {} services", matched_count)),
        observed_generation: policy.metadata.generation,
    };

    // Idempotency guard: skip if phase, count, and refs already match
    if let Some(ref current) = policy.status {
        if current.phase == status.phase
            && current.matched_services == status.matched_services
            && current.matched_service_refs == status.matched_service_refs
        {
            debug!(policy = %name, "status unchanged, skipping update");
            return Ok(Action::requeue(Duration::from_secs(120)));
        }
    }

    lattice_common::kube_utils::patch_resource_status::<LatticeServicePolicy>(
        client,
        &name,
        &namespace,
        &status,
        "lattice-service-policy-controller",
    )
    .await
    .map_err(|e| {
        warn!(policy = %name, error = %e, "Failed to update policy status");
        ReconcileError::kube("status update failed", e)
    })?;

    // Requeue periodically
    Ok(Action::requeue(Duration::from_secs(120)))
}

#[cfg(test)]
mod tests {
    use lattice_common::crd::{
        LatticeServicePolicySpec, LatticeServicePolicyStatus, ServicePolicyPhase, ServiceSelector,
    };

    #[test]
    fn policy_spec_with_backup() {
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
                ..Default::default()
            }),
            ingress: None,
        };

        assert_eq!(spec.priority, 100);
        assert!(spec.backup.is_some());
        assert_eq!(
            spec.backup.as_ref().unwrap().hooks.as_ref().unwrap().pre[0].name,
            "freeze"
        );
    }

    #[test]
    fn status_idempotency_guard() {
        let status_a = LatticeServicePolicyStatus {
            phase: ServicePolicyPhase::Active,
            matched_services: 3,
            matched_service_refs: vec![
                "ns/svc-a".to_string(),
                "ns/svc-b".to_string(),
                "ns/svc-c".to_string(),
            ],
            conditions: vec![],
            message: Some("Matching 3 services".to_string()),
            observed_generation: Some(1),
        };

        let status_b = LatticeServicePolicyStatus {
            phase: ServicePolicyPhase::Active,
            matched_services: 3,
            matched_service_refs: vec![
                "ns/svc-a".to_string(),
                "ns/svc-b".to_string(),
                "ns/svc-c".to_string(),
            ],
            conditions: vec![],
            message: Some("Matching 3 services".to_string()),
            observed_generation: Some(1),
        };

        // Same phase, count, and refs → skip update
        assert_eq!(status_a.phase, status_b.phase);
        assert_eq!(status_a.matched_services, status_b.matched_services);
        assert_eq!(status_a.matched_service_refs, status_b.matched_service_refs);

        // Different count → update needed
        let status_c = LatticeServicePolicyStatus {
            matched_services: 2,
            ..status_a.clone()
        };
        assert_ne!(status_a.matched_services, status_c.matched_services);
    }

    #[test]
    fn status_message_reflects_count() {
        let matched_count = 5u32;
        let message = format!("Matching {} services", matched_count);
        assert_eq!(message, "Matching 5 services");
    }
}
