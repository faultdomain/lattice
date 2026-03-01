//! Status change detection for CRD controllers.
//!
//! Prevents redundant status patches that trigger self-reconcile storms.
//! Each merge patch generates a watch event (especially because `Condition::new()`
//! stamps a fresh `lastTransitionTime`), so controllers must skip no-op updates.

use crate::crd::{
    CloudProviderPhase, CloudProviderStatus, JobPhase, LatticeJobStatus,
    LatticeMeshMemberStatus, LatticeModelStatus, LatticeServiceStatus,
    MeshMemberPhase, ModelServingPhase, SecretProviderPhase, SecretProviderStatus, ServicePhase,
};

/// Trait for CRD status structs that carry phase, message, and observed generation.
///
/// Implement this for each CRD status type to enable generic `is_status_unchanged` checks.
pub trait StatusFields {
    /// The phase enum type for this CRD.
    type Phase: PartialEq;

    /// Current phase of the resource.
    fn phase(&self) -> &Self::Phase;

    /// Human-readable status message.
    fn message(&self) -> Option<&str>;

    /// Generation of the spec that was last reconciled.
    fn observed_generation(&self) -> Option<i64>;
}

/// Check if a resource's status already matches the desired state.
///
/// Returns `true` when the status phase, message, and observed generation all match,
/// meaning a status patch would be a no-op and should be skipped.
pub fn is_status_unchanged<S: StatusFields>(
    status: Option<&S>,
    phase: &S::Phase,
    message: Option<&str>,
    observed_generation: Option<i64>,
) -> bool {
    status
        .map(|s| {
            s.phase() == phase
                && s.message() == message
                && s.observed_generation() == observed_generation
        })
        .unwrap_or(false)
}

impl StatusFields for CloudProviderStatus {
    type Phase = CloudProviderPhase;
    fn phase(&self) -> &Self::Phase {
        &self.phase
    }
    fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
    fn observed_generation(&self) -> Option<i64> {
        self.observed_generation
    }
}

impl StatusFields for LatticeServiceStatus {
    type Phase = ServicePhase;
    fn phase(&self) -> &Self::Phase {
        &self.phase
    }
    fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
    fn observed_generation(&self) -> Option<i64> {
        self.observed_generation
    }
}

impl StatusFields for LatticeMeshMemberStatus {
    type Phase = MeshMemberPhase;
    fn phase(&self) -> &Self::Phase {
        &self.phase
    }
    fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
    fn observed_generation(&self) -> Option<i64> {
        self.observed_generation
    }
}

impl StatusFields for SecretProviderStatus {
    type Phase = SecretProviderPhase;
    fn phase(&self) -> &Self::Phase {
        &self.phase
    }
    fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
    fn observed_generation(&self) -> Option<i64> {
        self.observed_generation
    }
}

impl StatusFields for LatticeJobStatus {
    type Phase = JobPhase;
    fn phase(&self) -> &Self::Phase {
        &self.phase
    }
    fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
    fn observed_generation(&self) -> Option<i64> {
        self.observed_generation
    }
}

impl StatusFields for LatticeModelStatus {
    type Phase = ModelServingPhase;
    fn phase(&self) -> &Self::Phase {
        &self.phase
    }
    fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
    fn observed_generation(&self) -> Option<i64> {
        self.observed_generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchanged_when_all_fields_match() {
        let status = CloudProviderStatus {
            phase: CloudProviderPhase::Ready,
            message: None,
            observed_generation: Some(1),
            ..Default::default()
        };
        assert!(is_status_unchanged(
            Some(&status),
            &CloudProviderPhase::Ready,
            None,
            Some(1),
        ));
    }

    #[test]
    fn changed_when_phase_differs() {
        let status = CloudProviderStatus {
            phase: CloudProviderPhase::Ready,
            message: None,
            observed_generation: Some(1),
            ..Default::default()
        };
        assert!(!is_status_unchanged(
            Some(&status),
            &CloudProviderPhase::Failed,
            None,
            Some(1),
        ));
    }

    #[test]
    fn changed_when_generation_differs() {
        let status = CloudProviderStatus {
            phase: CloudProviderPhase::Ready,
            message: None,
            observed_generation: Some(1),
            ..Default::default()
        };
        assert!(!is_status_unchanged(
            Some(&status),
            &CloudProviderPhase::Ready,
            None,
            Some(2),
        ));
    }

    #[test]
    fn changed_when_message_differs() {
        let status = CloudProviderStatus {
            phase: CloudProviderPhase::Ready,
            message: Some("all good".to_string()),
            observed_generation: Some(1),
            ..Default::default()
        };
        assert!(!is_status_unchanged(
            Some(&status),
            &CloudProviderPhase::Ready,
            None,
            Some(1),
        ));
    }

    #[test]
    fn changed_when_status_is_none() {
        assert!(!is_status_unchanged::<CloudProviderStatus>(
            None,
            &CloudProviderPhase::Ready,
            None,
            Some(1),
        ));
    }

    #[test]
    fn works_with_service_status() {
        let status = LatticeServiceStatus {
            phase: ServicePhase::Failed,
            message: Some("validation error".to_string()),
            observed_generation: None,
            ..Default::default()
        };
        assert!(is_status_unchanged(
            Some(&status),
            &ServicePhase::Failed,
            Some("validation error"),
            None,
        ));
    }
}
