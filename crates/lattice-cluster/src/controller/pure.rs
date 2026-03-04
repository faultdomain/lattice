//! Pure decision functions with no I/O.
//!
//! These functions contain stateless decision logic that can be thoroughly
//! unit tested without mocking Kubernetes or network connections.

use lattice_common::crd::WorkerPoolSpec;

/// Check if the cluster being reconciled is the cluster we're running on.
///
/// When true, we skip provisioning since we ARE this cluster.
pub fn is_self_cluster(cluster_name: &str, self_cluster_name: Option<&str>) -> bool {
    self_cluster_name
        .map(|self_name| self_name == cluster_name)
        .unwrap_or(false)
}

pub(crate) use lattice_common::resources::is_control_plane_node;
pub(crate) use lattice_common::resources::is_node_ready;

/// Actions that can be taken during the pivot phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PivotAction {
    /// Pivot is complete, transition to Ready
    Complete,
    /// Trigger pivot (trigger_pivot blocks until MoveCompleteAck)
    TriggerPivot,
    /// Wait for agent to connect
    WaitForAgent,
}

/// Determine what pivot action to take based on current state.
///
/// This encapsulates the pivot state machine logic in a pure function.
/// Note: trigger_pivot() is synchronous - it blocks until MoveCompleteAck.
pub fn determine_pivot_action(is_pivot_complete: bool, is_agent_connected: bool) -> PivotAction {
    if is_pivot_complete {
        PivotAction::Complete
    } else if is_agent_connected {
        PivotAction::TriggerPivot
    } else {
        PivotAction::WaitForAgent
    }
}

/// Action to take for pool scaling
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScalingAction {
    /// No action needed - replicas match desired or autoscaler manages the pool
    NoOp {
        /// Desired replicas (for status reporting)
        desired: u32,
        /// Whether autoscaling is enabled
        autoscaling: bool,
    },
    /// Scale the pool to the specified replica count
    Scale {
        /// Current replica count
        current: u32,
        /// Target replica count
        target: u32,
    },
    /// MachineDeployment not found - wait for it to be created
    WaitForMachineDeployment,
}

impl ScalingAction {
    /// Returns the desired replica count for status reporting
    pub fn desired_replicas(&self) -> u32 {
        match self {
            ScalingAction::NoOp { desired, .. } => *desired,
            ScalingAction::Scale { target, .. } => *target,
            ScalingAction::WaitForMachineDeployment => 0,
        }
    }

    /// Returns whether autoscaling is enabled
    pub fn is_autoscaling(&self) -> bool {
        matches!(
            self,
            ScalingAction::NoOp {
                autoscaling: true,
                ..
            }
        )
    }
}

/// Determine what scaling action to take for a worker pool.
///
/// This encapsulates the scaling decision logic in a pure function.
/// Uses `WorkerPoolSpec::is_autoscaling_enabled()` to check autoscaling status.
pub fn determine_scaling_action(
    pool_spec: &WorkerPoolSpec,
    current_replicas: Option<u32>,
) -> ScalingAction {
    if pool_spec.is_autoscaling_enabled() {
        // Autoscaling: use current replicas or fall back to min
        let desired = current_replicas.unwrap_or_else(|| pool_spec.min.unwrap_or(0));
        return ScalingAction::NoOp {
            desired,
            autoscaling: true,
        };
    }

    // Static scaling
    match current_replicas {
        Some(current) if current == pool_spec.replicas => ScalingAction::NoOp {
            desired: pool_spec.replicas,
            autoscaling: false,
        },
        Some(current) => ScalingAction::Scale {
            current,
            target: pool_spec.replicas,
        },
        None if pool_spec.replicas > 0 => ScalingAction::WaitForMachineDeployment,
        None => ScalingAction::NoOp {
            desired: 0,
            autoscaling: false,
        },
    }
}

/// Generate a warning message if spec.replicas is outside autoscaling bounds.
///
/// Returns None if autoscaling is disabled or replicas is within bounds.
pub fn autoscaling_warning(pool_spec: &WorkerPoolSpec) -> Option<String> {
    match (pool_spec.min, pool_spec.max) {
        (Some(min), Some(max)) if pool_spec.replicas < min || pool_spec.replicas > max => {
            Some(format!(
                "replicas ({}) ignored, autoscaler manages within [{}, {}]",
                pool_spec.replicas, min, max
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{Node, NodeCondition, NodeSpec, NodeStatus, Taint};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use lattice_common::crd::WorkerPoolSpec;

    // --- is_self_cluster tests ---

    #[test]
    fn is_self_cluster_returns_true_when_names_match() {
        assert!(is_self_cluster("mgmt", Some("mgmt")));
    }

    #[test]
    fn is_self_cluster_returns_false_when_names_differ() {
        assert!(!is_self_cluster("workload", Some("mgmt")));
    }

    #[test]
    fn is_self_cluster_returns_false_when_no_self_name() {
        assert!(!is_self_cluster("mgmt", None));
    }

    // --- Node helper function tests ---

    fn make_node(name: &str, is_control_plane: bool, is_ready: bool, has_taint: bool) -> Node {
        let mut labels = std::collections::BTreeMap::new();
        if is_control_plane {
            labels.insert(
                "node-role.kubernetes.io/control-plane".to_string(),
                "".to_string(),
            );
        }

        let conditions = if is_ready {
            Some(vec![NodeCondition {
                type_: "Ready".to_string(),
                status: "True".to_string(),
                ..Default::default()
            }])
        } else {
            Some(vec![NodeCondition {
                type_: "Ready".to_string(),
                status: "False".to_string(),
                ..Default::default()
            }])
        };

        let taints = if has_taint {
            Some(vec![Taint {
                key: "node-role.kubernetes.io/control-plane".to_string(),
                effect: "NoSchedule".to_string(),
                ..Default::default()
            }])
        } else {
            None
        };

        Node {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                labels: Some(labels),
                ..Default::default()
            },
            spec: Some(NodeSpec {
                taints,
                ..Default::default()
            }),
            status: Some(NodeStatus {
                conditions,
                ..Default::default()
            }),
        }
    }

    #[test]
    fn is_control_plane_node_detects_control_plane_label() {
        let cp_node = make_node("cp-0", true, true, true);
        let worker = make_node("worker-0", false, true, false);

        assert!(is_control_plane_node(&cp_node));
        assert!(!is_control_plane_node(&worker));
    }

    #[test]
    fn is_node_ready_checks_ready_condition() {
        let ready_node = make_node("ready", false, true, false);
        let not_ready = make_node("not-ready", false, false, false);

        assert!(is_node_ready(&ready_node));
        assert!(!is_node_ready(&not_ready));
    }

    // --- determine_pivot_action tests ---

    #[test]
    fn pivot_action_complete_when_pivot_done() {
        assert_eq!(determine_pivot_action(true, false), PivotAction::Complete);
    }

    #[test]
    fn pivot_action_trigger_pivot_when_agent_connected() {
        assert_eq!(
            determine_pivot_action(false, true),
            PivotAction::TriggerPivot
        );
    }

    #[test]
    fn pivot_action_wait_for_agent_when_nothing_ready() {
        assert_eq!(
            determine_pivot_action(false, false),
            PivotAction::WaitForAgent
        );
    }

    // --- determine_scaling_action tests ---

    fn pool_spec(replicas: u32, min: Option<u32>, max: Option<u32>) -> WorkerPoolSpec {
        WorkerPoolSpec {
            replicas,
            min,
            max,
            ..Default::default()
        }
    }

    #[test]
    fn scaling_action_static_uses_spec_replicas() {
        let spec = pool_spec(3, None, None);
        let action = determine_scaling_action(&spec, Some(2));

        assert_eq!(action.desired_replicas(), 3);
        assert!(!action.is_autoscaling());
        assert!(matches!(action, ScalingAction::Scale { target: 3, .. }));
    }

    #[test]
    fn scaling_action_noop_when_replicas_match() {
        let spec = pool_spec(3, None, None);
        let action = determine_scaling_action(&spec, Some(3));

        assert_eq!(action.desired_replicas(), 3);
        assert!(!action.is_autoscaling());
        assert!(matches!(action, ScalingAction::NoOp { .. }));
    }

    #[test]
    fn scaling_action_autoscaling_uses_current_when_available() {
        let spec = pool_spec(3, Some(1), Some(10));
        let action = determine_scaling_action(&spec, Some(7));

        assert_eq!(action.desired_replicas(), 7); // Uses current
        assert!(action.is_autoscaling());
        assert!(matches!(action, ScalingAction::NoOp { .. }));
    }

    #[test]
    fn scaling_action_autoscaling_falls_back_to_min() {
        let spec = pool_spec(3, Some(2), Some(10));
        let action = determine_scaling_action(&spec, None);

        assert_eq!(action.desired_replicas(), 2); // Falls back to min
        assert!(action.is_autoscaling());
    }

    #[test]
    fn scaling_action_scales_up() {
        let spec = pool_spec(5, None, None);
        let action = determine_scaling_action(&spec, Some(2));

        assert_eq!(
            action,
            ScalingAction::Scale {
                current: 2,
                target: 5
            }
        );
    }

    #[test]
    fn scaling_action_scales_down() {
        let spec = pool_spec(3, None, None);
        let action = determine_scaling_action(&spec, Some(10));

        assert_eq!(
            action,
            ScalingAction::Scale {
                current: 10,
                target: 3
            }
        );
    }

    #[test]
    fn scaling_action_waits_when_deployment_missing_and_replicas_wanted() {
        let spec = pool_spec(3, None, None);
        let action = determine_scaling_action(&spec, None);

        assert_eq!(action, ScalingAction::WaitForMachineDeployment);
    }

    #[test]
    fn scaling_action_noop_when_deployment_missing_and_zero_replicas() {
        let spec = pool_spec(0, None, None);
        let action = determine_scaling_action(&spec, None);

        assert!(matches!(action, ScalingAction::NoOp { .. }));
        assert_eq!(action.desired_replicas(), 0);
    }

    // --- autoscaling_warning tests ---

    #[test]
    fn autoscaling_warning_none_for_static_scaling() {
        let spec = pool_spec(5, None, None);
        assert!(autoscaling_warning(&spec).is_none());
    }

    #[test]
    fn autoscaling_warning_none_when_spec_in_bounds() {
        let spec = pool_spec(5, Some(1), Some(10));
        assert!(autoscaling_warning(&spec).is_none());
    }

    #[test]
    fn autoscaling_warning_when_spec_below_min() {
        let spec = pool_spec(1, Some(3), Some(10));
        let warning = autoscaling_warning(&spec);

        assert!(warning.is_some());
        assert!(warning.unwrap().contains("replicas (1) ignored"));
    }

    #[test]
    fn autoscaling_warning_when_spec_above_max() {
        let spec = pool_spec(15, Some(1), Some(10));
        let warning = autoscaling_warning(&spec);

        assert!(warning.is_some());
        assert!(warning.unwrap().contains("replicas (15) ignored"));
    }
}
