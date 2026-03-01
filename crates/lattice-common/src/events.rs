//! Kubernetes Event recording for Lattice controllers.
//!
//! Provides a trait-based abstraction over `kube::runtime::events::Recorder`
//! so that controllers can emit standard Kubernetes Events visible via
//! `kubectl describe` and `kubectl get events`.
//!
//! Events are **fire-and-forget**: failures are logged as warnings and never
//! propagate errors. A failed event must never break reconciliation.

use async_trait::async_trait;
use k8s_openapi::api::core::v1::ObjectReference;
use kube::runtime::events::{EventType, Recorder, Reporter};
use kube::Client;
use tracing::warn;

/// Trait for publishing Kubernetes Events.
///
/// Implementations are expected to be fire-and-forget: `publish()` logs a
/// warning on failure but never returns an error.
#[async_trait]
pub trait EventPublisher: Send + Sync {
    /// Publish a Kubernetes Event on the given resource.
    ///
    /// # Arguments
    ///
    /// * `resource_ref` - The Kubernetes object this event is about
    /// * `type_` - Normal or Warning
    /// * `reason` - Machine-readable reason string (e.g. "ProvisioningStarted")
    /// * `action` - What action was taken (e.g. "Reconcile")
    /// * `note` - Optional human-readable message
    async fn publish(
        &self,
        resource_ref: &ObjectReference,
        type_: EventType,
        reason: &str,
        action: &str,
        note: Option<String>,
    );
}

/// Production implementation wrapping `kube::runtime::events::Recorder`.
pub struct KubeEventPublisher {
    recorder: Recorder,
}

impl KubeEventPublisher {
    /// Create a new publisher for the given controller name.
    ///
    /// The controller name appears as the "reportingComponent" on Events
    /// (e.g. "lattice-cluster-controller").
    pub fn new(client: Client, controller_name: &str) -> Self {
        let reporter = Reporter {
            controller: controller_name.to_string(),
            instance: None,
        };
        Self {
            recorder: Recorder::new(client, reporter),
        }
    }
}

#[async_trait]
impl EventPublisher for KubeEventPublisher {
    async fn publish(
        &self,
        resource_ref: &ObjectReference,
        type_: EventType,
        reason: &str,
        action: &str,
        note: Option<String>,
    ) {
        let event = kube::runtime::events::Event {
            type_,
            reason: reason.to_string(),
            note,
            action: action.to_string(),
            secondary: None,
        };
        if let Err(e) = self.recorder.publish(&event, resource_ref).await {
            warn!(
                reason,
                action,
                error = %e,
                "Failed to publish Kubernetes event"
            );
        }
    }
}

/// No-op implementation for tests.
///
/// All calls are silently ignored — no Kubernetes API interaction.
pub struct NoopEventPublisher;

#[async_trait]
impl EventPublisher for NoopEventPublisher {
    async fn publish(
        &self,
        _resource_ref: &ObjectReference,
        _type_: EventType,
        _reason: &str,
        _action: &str,
        _note: Option<String>,
    ) {
        // intentionally empty
    }
}

/// Well-known event reason strings.
///
/// These appear in `kubectl get events` under the REASON column.
pub mod reasons {
    // Cluster lifecycle events
    /// CAPI manifests applied, provisioning has begun
    pub const PROVISIONING_STARTED: &str = "ProvisioningStarted";
    /// CAPI infrastructure reports ready
    pub const INFRASTRUCTURE_READY: &str = "InfrastructureReady";
    /// Pivot from parent to child cluster started
    pub const PIVOT_STARTED: &str = "PivotStarted";
    /// Pivot completed, cluster is self-managing
    pub const PIVOT_COMPLETE: &str = "PivotComplete";
    /// Cluster is fully ready
    pub const CLUSTER_READY: &str = "ClusterReady";
    /// Cluster entered Failed phase
    pub const CLUSTER_FAILED: &str = "ClusterFailed";
    /// Cluster deletion initiated
    pub const DELETION_STARTED: &str = "DeletionStarted";
    /// Unpivot (export CAPI to parent) started
    pub const UNPIVOT_STARTED: &str = "UnpivotStarted";
    /// Worker pool scaling triggered
    pub const WORKER_SCALING: &str = "WorkerScaling";
    /// Kubernetes version upgrade started
    pub const VERSION_UPGRADE_STARTED: &str = "VersionUpgradeStarted";
    /// Spec validation failed
    pub const VALIDATION_FAILED: &str = "ValidationFailed";

    // Service lifecycle events
    /// Service compilation succeeded
    pub const COMPILATION_SUCCESS: &str = "CompilationSuccess";
    /// Service compilation failed
    pub const COMPILATION_FAILED: &str = "CompilationFailed";
    /// Cedar denied secret access
    pub const SECRET_ACCESS_DENIED: &str = "SecretAccessDenied";
    /// Cedar denied security override
    pub const SECURITY_OVERRIDE_DENIED: &str = "SecurityOverrideDenied";
    /// Volume access denied (owner consent or Cedar policy)
    pub const VOLUME_ACCESS_DENIED: &str = "VolumeAccessDenied";
}

/// Well-known event action strings.
///
/// These appear in `kubectl get events` under the ACTION column.
pub mod actions {
    /// Standard reconciliation loop
    pub const RECONCILE: &str = "Reconcile";
    /// Provisioning infrastructure
    pub const PROVISION: &str = "Provision";
    /// Pivoting cluster ownership
    pub const PIVOT: &str = "Pivot";
    /// Deleting cluster resources
    pub const DELETE: &str = "Delete";
    /// Scaling worker pools
    pub const SCALE: &str = "Scale";
    /// Upgrading Kubernetes version
    pub const UPGRADE: &str = "Upgrade";
    /// Compiling service resources
    pub const COMPILE: &str = "Compile";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_publisher_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NoopEventPublisher>();
    }

    #[test]
    fn reason_constants_are_pascal_case() {
        // Verify constants exist and have expected values
        assert_eq!(reasons::PROVISIONING_STARTED, "ProvisioningStarted");
        assert_eq!(reasons::CLUSTER_READY, "ClusterReady");
        assert_eq!(reasons::COMPILATION_SUCCESS, "CompilationSuccess");
    }

    #[test]
    fn action_constants_are_defined() {
        assert_eq!(actions::RECONCILE, "Reconcile");
        assert_eq!(actions::COMPILE, "Compile");
    }

    #[tokio::test]
    async fn noop_publisher_does_not_panic() {
        let publisher = NoopEventPublisher;
        let obj_ref = ObjectReference::default();
        publisher
            .publish(
                &obj_ref,
                EventType::Normal,
                reasons::CLUSTER_READY,
                actions::RECONCILE,
                Some("test".to_string()),
            )
            .await;
    }
}
