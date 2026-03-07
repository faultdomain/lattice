//! Pure decision functions with no I/O.
//!
//! These functions contain stateless decision logic that can be thoroughly
//! unit tested without mocking Kubernetes or network connections.

use lattice_common::crd::WorkerPoolSpec;
use lattice_common::gpu::{
    ANNOTATION_GPU_HEALTH, ANNOTATION_GPU_LOSS, ANNOTATION_HEARTBEAT,
};

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

/// Action to take based on GPU health annotations on a node.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GpuAction {
    /// No GPU-related action needed.
    NoOp,
    /// Anomaly detected or GPU loss — prevent new scheduling but let current
    /// jobs finish. Existing workloads checkpoint/complete naturally while the
    /// node is blocked from new work. Human operators decide whether to drain.
    Cordon,
}

/// Determine what GPU action to take based on node annotations.
///
/// Reads `lattice.dev/gpu-health`, `lattice.dev/gpu-loss-detected`, and
/// `lattice.dev/gpu-monitor-heartbeat` to decide whether to cordon.
///
/// Policy:
/// - GPU loss detected → Cordon (prevent new scheduling, existing jobs finish naturally)
/// - Warning or unhealthy anomaly score → Cordon
/// - Draining is intentionally not automated — if GPUs are truly gone, workloads
///   will fail on their own. If our view is wrong, draining would lose work.
///   Human operators can drain manually after investigating.
///
/// Staleness: if the heartbeat is older than `staleness_threshold_secs`,
/// returns `NoOp` — don't act on stale data.
pub fn determine_gpu_action(
    annotations: &std::collections::BTreeMap<String, String>,
    staleness_threshold_secs: i64,
) -> GpuAction {
    // Check heartbeat staleness first
    if let Some(heartbeat) = annotations.get(ANNOTATION_HEARTBEAT) {
        if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(heartbeat) {
            let age = chrono::Utc::now().signed_duration_since(ts);
            if age.num_seconds() > staleness_threshold_secs {
                return GpuAction::NoOp;
            }
        } else {
            // Unparseable heartbeat — treat as stale
            return GpuAction::NoOp;
        }
    } else {
        // No heartbeat annotation — GPU monitor not running on this node
        return GpuAction::NoOp;
    }

    // GPU loss — cordon to prevent new scheduling
    if annotations.get(ANNOTATION_GPU_LOSS).map(|v| v.as_str()) == Some("true") {
        return GpuAction::Cordon;
    }

    // Health-based: both warning and unhealthy → cordon.
    // Cordoning prevents new work while letting current jobs checkpoint/finish.
    match annotations
        .get(ANNOTATION_GPU_HEALTH)
        .map(|v| v.as_str())
    {
        Some("unhealthy") | Some("warning") => GpuAction::Cordon,
        _ => GpuAction::NoOp,
    }
}

/// Maximum fraction of GPU nodes that can be cordoned before we stop cordoning more.
/// Beyond this threshold, the cluster risks scheduling starvation.
pub const MAX_CORDON_FRACTION: f64 = 0.5;

/// Represents a GPU node's cordon eligibility state.
#[derive(Debug, Clone)]
pub struct GpuNodeState {
    pub node_name: String,
    pub action: GpuAction,
    pub anomaly_score: f32,
    pub is_cordoned: bool,
}

/// Cluster-level GPU cordon plan after applying the cordon threshold.
#[derive(Debug, Clone)]
pub struct GpuCordonPlan {
    /// Nodes to cordon (may be fewer than requested if threshold exceeded).
    pub to_cordon: Vec<String>,
    /// Nodes to selectively uncordon (lowest confidence, when pending pods exist).
    pub to_uncordon: Vec<String>,
    /// Whether the cordon threshold was hit.
    pub threshold_hit: bool,
}

/// Build a cluster-level GPU cordon plan respecting the maximum cordon threshold.
///
/// Cordons are subject to the threshold: if >50% of GPU nodes are already cordoned,
/// new cordons are suppressed. If pending GPU pods exist and we're at the threshold,
/// we selectively uncordon the lowest-confidence node (lowest anomaly score).
///
/// Nodes that have recovered (action == NoOp but still cordoned) are automatically
/// uncordoned.
pub fn build_gpu_cordon_plan(
    nodes: &[GpuNodeState],
    has_pending_gpu_pods: bool,
) -> GpuCordonPlan {
    let total_gpu_nodes = nodes.len();
    if total_gpu_nodes == 0 {
        return GpuCordonPlan {
            to_cordon: vec![],
            to_uncordon: vec![],
            threshold_hit: false,
        };
    }

    let already_cordoned = nodes.iter().filter(|n| n.is_cordoned).count();
    let max_cordoned = ((total_gpu_nodes as f64) * MAX_CORDON_FRACTION).ceil() as usize;

    // Cordon candidates (nodes not already cordoned that need cordoning)
    let mut cordon_candidates: Vec<&GpuNodeState> = nodes
        .iter()
        .filter(|n| n.action == GpuAction::Cordon && !n.is_cordoned)
        .collect();

    // Sort by anomaly score descending — cordon highest-confidence problems first
    debug_assert!(
        cordon_candidates.iter().all(|n| n.anomaly_score.is_finite()),
        "NaN/Inf anomaly scores should be rejected upstream"
    );
    cordon_candidates.sort_by(|a, b| b.anomaly_score.partial_cmp(&a.anomaly_score).unwrap_or(std::cmp::Ordering::Equal));

    let budget = max_cordoned.saturating_sub(already_cordoned);
    let threshold_hit = cordon_candidates.len() > budget;
    let to_cordon: Vec<String> = cordon_candidates
        .iter()
        .take(budget)
        .map(|n| n.node_name.clone())
        .collect();

    // Recovery uncordon: nodes that are cordoned but have recovered (NoOp action)
    // should be uncordoned.
    let mut to_uncordon: Vec<String> = nodes
        .iter()
        .filter(|n| n.is_cordoned && n.action == GpuAction::NoOp)
        .map(|n| n.node_name.clone())
        .collect();

    // Selective uncordon: if at threshold AND pending GPU pods exist,
    // uncordon the lowest-confidence warning node (closest to normal).
    if has_pending_gpu_pods && already_cordoned + to_cordon.len() >= max_cordoned {
        let mut uncordon_candidates: Vec<&GpuNodeState> = nodes
            .iter()
            .filter(|n| n.is_cordoned && n.action == GpuAction::Cordon)
            .filter(|n| !to_uncordon.contains(&n.node_name))
            .collect();
        debug_assert!(
            uncordon_candidates.iter().all(|n| n.anomaly_score.is_finite()),
            "NaN/Inf anomaly scores should be rejected upstream"
        );
        uncordon_candidates.sort_by(|a, b| a.anomaly_score.partial_cmp(&b.anomaly_score).unwrap_or(std::cmp::Ordering::Equal));

        if let Some(best) = uncordon_candidates.first() {
            to_uncordon.push(best.node_name.clone());
        }
    }

    GpuCordonPlan {
        to_cordon,
        to_uncordon,
        threshold_hit,
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

    // --- determine_gpu_action tests ---

    fn gpu_annotations(
        health: &str,
        loss: &str,
        heartbeat: &str,
    ) -> std::collections::BTreeMap<String, String> {
        std::collections::BTreeMap::from([
            (ANNOTATION_GPU_HEALTH.to_string(), health.to_string()),
            (ANNOTATION_GPU_LOSS.to_string(), loss.to_string()),
            (ANNOTATION_HEARTBEAT.to_string(), heartbeat.to_string()),
        ])
    }

    fn fresh_heartbeat() -> String {
        chrono::Utc::now().to_rfc3339()
    }

    #[test]
    fn gpu_action_normal_is_noop() {
        let ann = gpu_annotations("normal", "false", &fresh_heartbeat());
        assert_eq!(determine_gpu_action(&ann, 120), GpuAction::NoOp);
    }

    #[test]
    fn gpu_action_warning_is_cordon() {
        let ann = gpu_annotations("warning", "false", &fresh_heartbeat());
        assert_eq!(determine_gpu_action(&ann, 120), GpuAction::Cordon);
    }

    #[test]
    fn gpu_action_unhealthy_is_cordon() {
        // Unhealthy anomaly scores cordon only — never drain based on model output
        let ann = gpu_annotations("unhealthy", "false", &fresh_heartbeat());
        assert_eq!(determine_gpu_action(&ann, 120), GpuAction::Cordon);
    }

    #[test]
    fn gpu_action_loss_is_cordon() {
        // GPU loss detected — cordon only, never drain automatically
        let ann = gpu_annotations("normal", "true", &fresh_heartbeat());
        assert_eq!(determine_gpu_action(&ann, 120), GpuAction::Cordon);
    }

    #[test]
    fn gpu_action_loss_overrides_normal_health() {
        // GPU loss takes priority over "normal" health status
        let ann = gpu_annotations("normal", "true", &fresh_heartbeat());
        assert_eq!(determine_gpu_action(&ann, 120), GpuAction::Cordon);
    }

    #[test]
    fn gpu_action_stale_heartbeat_is_noop() {
        let old = (chrono::Utc::now() - chrono::Duration::seconds(300)).to_rfc3339();
        let ann = gpu_annotations("unhealthy", "true", &old);
        assert_eq!(determine_gpu_action(&ann, 120), GpuAction::NoOp);
    }

    #[test]
    fn gpu_action_no_heartbeat_is_noop() {
        let ann = std::collections::BTreeMap::from([
            (ANNOTATION_GPU_HEALTH.to_string(), "unhealthy".to_string()),
        ]);
        assert_eq!(determine_gpu_action(&ann, 120), GpuAction::NoOp);
    }

    #[test]
    fn gpu_action_no_annotations_is_noop() {
        let ann = std::collections::BTreeMap::new();
        assert_eq!(determine_gpu_action(&ann, 120), GpuAction::NoOp);
    }

    #[test]
    fn gpu_action_bad_heartbeat_format_is_noop() {
        let ann = gpu_annotations("unhealthy", "true", "not-a-timestamp");
        assert_eq!(determine_gpu_action(&ann, 120), GpuAction::NoOp);
    }

    // --- build_gpu_cordon_plan tests ---

    fn gpu_node(name: &str, action: GpuAction, score: f32, cordoned: bool) -> GpuNodeState {
        GpuNodeState {
            node_name: name.to_string(),
            action,
            anomaly_score: score,
            is_cordoned: cordoned,
        }
    }

    #[test]
    fn cordon_plan_empty_nodes() {
        let plan = build_gpu_cordon_plan(&[], false);
        assert!(plan.to_cordon.is_empty());
        assert!(plan.to_uncordon.is_empty());
        assert!(!plan.threshold_hit);
    }

    #[test]
    fn cordon_plan_all_healthy() {
        let nodes = vec![
            gpu_node("n1", GpuAction::NoOp, 0.1, false),
            gpu_node("n2", GpuAction::NoOp, 0.2, false),
        ];
        let plan = build_gpu_cordon_plan(&nodes, false);
        assert!(plan.to_cordon.is_empty());
    }

    #[test]
    fn cordon_plan_single_warning() {
        let nodes = vec![
            gpu_node("n1", GpuAction::Cordon, 0.6, false),
            gpu_node("n2", GpuAction::NoOp, 0.1, false),
        ];
        let plan = build_gpu_cordon_plan(&nodes, false);
        assert_eq!(plan.to_cordon, vec!["n1"]);
        assert!(!plan.threshold_hit);
    }

    #[test]
    fn cordon_plan_gpu_loss_cordons() {
        // GPU loss nodes get cordoned (within threshold budget)
        let nodes = vec![
            gpu_node("n1", GpuAction::Cordon, 0.9, false),
            gpu_node("n2", GpuAction::Cordon, 0.95, false),
            gpu_node("n3", GpuAction::NoOp, 0.1, false),
            gpu_node("n4", GpuAction::NoOp, 0.1, false),
        ];
        let plan = build_gpu_cordon_plan(&nodes, false);
        assert_eq!(plan.to_cordon.len(), 2);
    }

    #[test]
    fn cordon_plan_threshold_suppresses_cordons() {
        // 4 GPU nodes, 2 already cordoned (50%). New cordon should be suppressed.
        let nodes = vec![
            gpu_node("n1", GpuAction::NoOp, 0.1, true),  // already cordoned
            gpu_node("n2", GpuAction::NoOp, 0.1, true),  // already cordoned
            gpu_node("n3", GpuAction::Cordon, 0.6, false), // wants cordon
            gpu_node("n4", GpuAction::NoOp, 0.1, false),
        ];
        let plan = build_gpu_cordon_plan(&nodes, false);
        // max_cordoned = ceil(4 * 0.5) = 2, already 2 cordoned, budget = 0
        assert!(plan.to_cordon.is_empty());
        assert!(plan.threshold_hit);
    }

    #[test]
    fn cordon_plan_highest_score_cordoned_first() {
        // 4 nodes, 0 cordoned, 2 want cordon. Both fit in budget.
        let nodes = vec![
            gpu_node("n1", GpuAction::Cordon, 0.5, false),
            gpu_node("n2", GpuAction::Cordon, 0.8, false),
            gpu_node("n3", GpuAction::NoOp, 0.1, false),
            gpu_node("n4", GpuAction::NoOp, 0.1, false),
        ];
        let plan = build_gpu_cordon_plan(&nodes, false);
        assert_eq!(plan.to_cordon.len(), 2);
        // Highest score first
        assert_eq!(plan.to_cordon[0], "n2");
        assert_eq!(plan.to_cordon[1], "n1");
    }

    #[test]
    fn cordon_plan_selective_uncordon_on_pending() {
        // 4 nodes, 2 cordoned (at threshold), pending GPU pods exist
        // Should uncordon the lowest-confidence node
        let nodes = vec![
            gpu_node("n1", GpuAction::Cordon, 0.5, true),  // cordoned, lower score
            gpu_node("n2", GpuAction::Cordon, 0.7, true),  // cordoned, higher score
            gpu_node("n3", GpuAction::NoOp, 0.1, false),
            gpu_node("n4", GpuAction::NoOp, 0.1, false),
        ];
        let plan = build_gpu_cordon_plan(&nodes, true);
        // Should uncordon n1 (lowest anomaly score)
        assert_eq!(plan.to_uncordon, vec!["n1"]);
    }

    #[test]
    fn cordon_plan_no_uncordon_without_pending() {
        let nodes = vec![
            gpu_node("n1", GpuAction::Cordon, 0.5, true),
            gpu_node("n2", GpuAction::Cordon, 0.7, true),
            gpu_node("n3", GpuAction::NoOp, 0.1, false),
            gpu_node("n4", GpuAction::NoOp, 0.1, false),
        ];
        let plan = build_gpu_cordon_plan(&nodes, false);
        assert!(plan.to_uncordon.is_empty());
    }

    #[test]
    fn cordon_plan_recovery_uncordons_noop_nodes() {
        // n1 was cordoned for a warning, but has since recovered (NoOp).
        // It should be uncordoned automatically.
        let nodes = vec![
            gpu_node("n1", GpuAction::NoOp, 0.1, true), // recovered, still cordoned
            gpu_node("n2", GpuAction::NoOp, 0.1, false),
        ];
        let plan = build_gpu_cordon_plan(&nodes, false);
        assert_eq!(plan.to_uncordon, vec!["n1"]);
    }

    #[test]
    fn cordon_plan_already_cordoned_does_not_consume_budget() {
        // n1 already cordoned — doesn't consume new budget
        let nodes = vec![
            gpu_node("n1", GpuAction::Cordon, 0.9, true),
            gpu_node("n2", GpuAction::Cordon, 0.6, false),
            gpu_node("n3", GpuAction::NoOp, 0.1, false),
            gpu_node("n4", GpuAction::NoOp, 0.1, false),
        ];
        let plan = build_gpu_cordon_plan(&nodes, false);
        // Budget: max=2, already cordoned=1 (n1), budget=1
        assert_eq!(plan.to_cordon, vec!["n2"]);
    }
}
