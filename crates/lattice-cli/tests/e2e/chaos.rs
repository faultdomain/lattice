//! Chaos monkey for E2E tests - randomly kills pods and cuts network to test resilience
//!
//! Supports both random single-cluster attacks and coordinated parent-child attacks
//! that target critical phases like pivoting and unpivoting.
//!
//! # Provider-Aware Configuration
//!
//! Use `ChaosConfig::for_provider()` to get appropriate settings:
//! - Docker/kind: Fast intervals (30-90s) since no LB delays
//! - AWS/cloud: Slow intervals (90-150s) to account for NLB target registration

use std::sync::Arc;
use std::time::Duration;

use kube::Api;
use parking_lot::RwLock;
use rand::Rng;
use tokio_util::sync::CancellationToken;
use tracing::info;

use lattice_common::LATTICE_SYSTEM_NAMESPACE;
use lattice_operator::crd::{ClusterPhase, LatticeCluster};

use super::helpers::{client_from_kubeconfig, run_cmd_allow_fail};
use super::providers::InfraProvider;

const OPERATOR_NS: &str = LATTICE_SYSTEM_NAMESPACE;
const OPERATOR_LABEL: &str = "app=lattice-operator";

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for chaos monkey behavior
#[derive(Clone, Copy)]
pub struct ChaosConfig {
    /// Min/max seconds between pod kills
    pub pod_interval: (u64, u64),
    /// Min/max seconds between network cuts
    pub net_interval: (u64, u64),
    /// Duration of network blackouts in seconds
    pub net_blackout_secs: u64,
    /// Enable coordinated parent-child attacks
    pub enable_coordinated: bool,
    /// Probability of coordinated attack when opportunity exists (0.0-1.0)
    pub coordinated_probability: f32,
    /// Extended blackout duration during critical phases (pivot/unpivot)
    pub critical_blackout_secs: u64,
}

impl Default for ChaosConfig {
    fn default() -> Self {
        Self {
            pod_interval: (30, 90),
            net_interval: (60, 120),
            net_blackout_secs: 3,
            enable_coordinated: false,
            coordinated_probability: 0.0,
            critical_blackout_secs: 3,
        }
    }
}

impl ChaosConfig {
    /// Get appropriate chaos config for a provider
    ///
    /// - Docker/kind: Fast intervals since no LB delays
    /// - AWS/cloud: Slow intervals to account for NLB target registration (30-90s)
    pub fn for_provider(provider: InfraProvider) -> Self {
        match provider {
            InfraProvider::Docker => Self::default(),
            InfraProvider::Aws | InfraProvider::OpenStack | InfraProvider::Proxmox => Self {
                pod_interval: (90, 150),   // 90-150s between pod kills
                net_interval: (120, 180),  // 120-180s between network cuts
                net_blackout_secs: 5,
                enable_coordinated: false,
                coordinated_probability: 0.0,
                critical_blackout_secs: 5,
            },
        }
    }

    /// Enable coordinated attacks that target parent-child relationships
    pub fn with_coordinated(mut self, probability: f32) -> Self {
        self.enable_coordinated = true;
        self.coordinated_probability = probability;
        self.critical_blackout_secs = match self.pod_interval.0 {
            0..=60 => 15,   // Docker: shorter critical blackout
            _ => 20,        // AWS/cloud: longer critical blackout
        };
        self
    }

    /// Set custom pod kill interval
    pub fn with_pod_interval(mut self, min_secs: u64, max_secs: u64) -> Self {
        self.pod_interval = (min_secs, max_secs);
        self
    }

    /// Set custom network cut interval
    pub fn with_net_interval(mut self, min_secs: u64, max_secs: u64) -> Self {
        self.net_interval = (min_secs, max_secs);
        self
    }
}

// =============================================================================
// Target Management
// =============================================================================

/// A cluster target for chaos testing
#[derive(Clone, Debug)]
pub struct ClusterTarget {
    /// Cluster name
    pub name: String,
    /// Path to kubeconfig file
    pub kubeconfig: String,
    /// Parent cluster's kubeconfig (for hierarchy awareness)
    pub parent_kubeconfig: Option<String>,
}

/// Context about a cluster's current state (queried from parent's view)
#[derive(Clone, Debug, Default)]
pub struct ClusterContext {
    /// Current cluster phase
    pub phase: ClusterPhase,
    /// Whether pivot has completed
    pub pivot_complete: bool,
    /// Whether unpivot is pending (deletion in progress)
    pub unpivot_pending: bool,
}

impl ClusterContext {
    /// Returns true if the cluster is in a critical phase that's ideal for stress testing
    pub fn is_critical(&self) -> bool {
        matches!(
            self.phase,
            ClusterPhase::Pivoting | ClusterPhase::Unpivoting
        ) || self.unpivot_pending
    }
}

/// Thread-safe collection of cluster targets with their state
pub struct ChaosTargets {
    targets: RwLock<Vec<ClusterTarget>>,
    contexts: RwLock<std::collections::HashMap<String, ClusterContext>>,
}

impl ChaosTargets {
    pub fn new() -> Self {
        Self {
            targets: RwLock::new(Vec::new()),
            contexts: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Add a cluster target with optional parent relationship
    pub fn add(&self, name: &str, kubeconfig: &str, parent_kubeconfig: Option<&str>) {
        let mut targets = self.targets.write();
        if !targets.iter().any(|t| t.name == name) {
            info!(
                "[Chaos] Target added: {} (parent: {})",
                name,
                parent_kubeconfig.unwrap_or("none")
            );
            targets.push(ClusterTarget {
                name: name.to_string(),
                kubeconfig: kubeconfig.to_string(),
                parent_kubeconfig: parent_kubeconfig.map(String::from),
            });
        }
    }

    /// Remove a cluster target
    pub fn remove(&self, name: &str) {
        let mut targets = self.targets.write();
        if let Some(idx) = targets.iter().position(|t| t.name == name) {
            targets.remove(idx);
            info!("[Chaos] Target removed: {}", name);
        }
        self.contexts.write().remove(name);
    }

    /// Get a random target for single-cluster attacks
    pub fn random(&self) -> Option<ClusterTarget> {
        let targets = self.targets.read();
        if targets.is_empty() {
            return None;
        }
        let idx = rand::thread_rng().gen_range(0..targets.len());
        Some(targets[idx].clone())
    }

    /// Get all targets as a snapshot
    pub fn snapshot(&self) -> Vec<ClusterTarget> {
        self.targets.read().clone()
    }

    /// Update context for a cluster
    pub fn update_context(&self, name: &str, ctx: ClusterContext) {
        self.contexts.write().insert(name.to_string(), ctx);
    }

    /// Get context for a cluster
    pub fn get_context(&self, name: &str) -> Option<ClusterContext> {
        self.contexts.read().get(name).cloned()
    }

    /// Find a coordinated attack opportunity
    ///
    /// Looks for parent-child pairs where the child is in a critical phase.
    pub fn find_coordinated_attack(&self) -> Option<CoordinatedAttack> {
        let targets = self.targets.read();
        let contexts = self.contexts.read();

        for target in targets.iter() {
            if let Some(ref parent_kc) = target.parent_kubeconfig {
                if let Some(ctx) = contexts.get(&target.name) {
                    // Find the parent target
                    if let Some(parent) = targets.iter().find(|t| t.kubeconfig == *parent_kc) {
                        if ctx.is_critical() {
                            let attack = if ctx.unpivot_pending
                                || matches!(ctx.phase, ClusterPhase::Unpivoting)
                            {
                                CoordinatedAttack::UnpivotStress {
                                    parent: parent.clone(),
                                    child: target.clone(),
                                    child_context: ctx.clone(),
                                }
                            } else {
                                CoordinatedAttack::PivotStress {
                                    parent: parent.clone(),
                                    child: target.clone(),
                                    child_context: ctx.clone(),
                                }
                            };
                            return Some(attack);
                        }
                    }
                }
            }
        }
        None
    }
}

// =============================================================================
// Coordinated Attacks
// =============================================================================

/// Types of coordinated parent-child attacks
#[derive(Debug)]
pub enum CoordinatedAttack {
    /// Attack parent while child is pivoting (receiving CAPI resources)
    PivotStress {
        parent: ClusterTarget,
        child: ClusterTarget,
        child_context: ClusterContext,
    },
    /// Attack parent while child is unpivoting (sending CAPI resources back)
    UnpivotStress {
        parent: ClusterTarget,
        child: ClusterTarget,
        child_context: ClusterContext,
    },
}

impl CoordinatedAttack {
    pub fn description(&self) -> String {
        match self {
            CoordinatedAttack::PivotStress {
                parent,
                child,
                child_context,
            } => {
                format!(
                    "PivotStress: parent={} child={} (phase: {:?})",
                    parent.name, child.name, child_context.phase
                )
            }
            CoordinatedAttack::UnpivotStress {
                parent,
                child,
                child_context,
            } => {
                format!(
                    "UnpivotStress: parent={} child={} (unpivot_pending: {})",
                    parent.name, child.name, child_context.unpivot_pending
                )
            }
        }
    }

    pub fn parent(&self) -> &ClusterTarget {
        match self {
            CoordinatedAttack::PivotStress { parent, .. } => parent,
            CoordinatedAttack::UnpivotStress { parent, .. } => parent,
        }
    }
}

// =============================================================================
// Network Policy
// =============================================================================

const NETWORK_BLACKOUT_POLICY: &str = r#"apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: chaos-blackout
  namespace: lattice-system
spec:
  endpointSelector:
    matchLabels:
      app: lattice-operator
  ingressDeny:
    - fromEntities: [all]
  egressDeny:
    - toEntities: [all]
"#;

// =============================================================================
// Chaos Monkey
// =============================================================================

pub struct ChaosMonkey {
    pod_task: tokio::task::JoinHandle<()>,
    net_task: tokio::task::JoinHandle<()>,
    poll_task: Option<tokio::task::JoinHandle<()>>,
    cancel: CancellationToken,
}

impl ChaosMonkey {
    /// Start chaos monkey with default configuration
    pub fn start(targets: Arc<ChaosTargets>) -> Self {
        Self::start_with_config(targets, ChaosConfig::default())
    }

    /// Start chaos monkey with custom configuration
    pub fn start_with_config(targets: Arc<ChaosTargets>, config: ChaosConfig) -> Self {
        info!(
            "[Chaos] Started (pod: {}-{}s, net: {}-{}s/{}s, coordinated: {})",
            config.pod_interval.0,
            config.pod_interval.1,
            config.net_interval.0,
            config.net_interval.1,
            config.net_blackout_secs,
            config.enable_coordinated
        );

        let cancel = CancellationToken::new();

        let pod_task = tokio::spawn(pod_chaos_loop(targets.clone(), cancel.clone(), config));
        let net_task = tokio::spawn(net_chaos_loop(targets.clone(), cancel.clone(), config));

        // Start phase polling if coordinated attacks are enabled
        let poll_task = if config.enable_coordinated {
            Some(tokio::spawn(phase_poll_loop(targets, cancel.clone())))
        } else {
            None
        };

        Self {
            pod_task,
            net_task,
            poll_task,
            cancel,
        }
    }

    pub async fn stop(self) {
        self.cancel.cancel();
        self.pod_task.abort();
        self.net_task.abort();
        if let Some(poll) = self.poll_task {
            poll.abort();
        }
        info!("[Chaos] Stopped");
    }
}

// =============================================================================
// Chaos Loops
// =============================================================================

async fn pod_chaos_loop(
    targets: Arc<ChaosTargets>,
    cancel: CancellationToken,
    config: ChaosConfig,
) {
    loop {
        let delay = rand::thread_rng().gen_range(config.pod_interval.0..=config.pod_interval.1);
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(delay)) => {}
        }

        // Try coordinated attack first if enabled
        if config.enable_coordinated {
            if let Some(attack) = targets.find_coordinated_attack() {
                if rand::random::<f32>() < config.coordinated_probability {
                    info!("[Chaos] Coordinated pod attack: {}", attack.description());
                    kill_pod(&attack.parent().name, &attack.parent().kubeconfig);
                    continue;
                }
            }
        }

        // Fall back to random single-cluster attack
        if let Some(target) = targets.random() {
            kill_pod(&target.name, &target.kubeconfig);
        }
    }
}

async fn net_chaos_loop(
    targets: Arc<ChaosTargets>,
    cancel: CancellationToken,
    config: ChaosConfig,
) {
    loop {
        let delay = rand::thread_rng().gen_range(config.net_interval.0..=config.net_interval.1);
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(delay)) => {}
        }

        // Try coordinated attack first if enabled
        if config.enable_coordinated {
            if let Some(attack) = targets.find_coordinated_attack() {
                if rand::random::<f32>() < config.coordinated_probability {
                    info!("[Chaos] Coordinated net attack: {}", attack.description());
                    cut_network(
                        &attack.parent().name,
                        &attack.parent().kubeconfig,
                        &cancel,
                        config.critical_blackout_secs,
                    )
                    .await;
                    continue;
                }
            }
        }

        // Fall back to random single-cluster attack
        if let Some(target) = targets.random() {
            cut_network(
                &target.name,
                &target.kubeconfig,
                &cancel,
                config.net_blackout_secs,
            )
            .await;
        }
    }
}

/// Background task that polls cluster phases for coordinated attack opportunities
async fn phase_poll_loop(targets: Arc<ChaosTargets>, cancel: CancellationToken) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
        }

        for target in targets.snapshot() {
            // Query parent's view of this child cluster
            if let Some(ref parent_kc) = target.parent_kubeconfig {
                if let Ok(ctx) = query_cluster_context(parent_kc, &target.name).await {
                    targets.update_context(&target.name, ctx);
                }
            }
        }
    }
}

/// Query a cluster's context from its parent's perspective
async fn query_cluster_context(
    parent_kubeconfig: &str,
    cluster_name: &str,
) -> Result<ClusterContext, String> {
    let client = client_from_kubeconfig(parent_kubeconfig).await?;
    let api: Api<LatticeCluster> = Api::all(client);

    let cluster = api
        .get(cluster_name)
        .await
        .map_err(|e| format!("Failed to get cluster {}: {}", cluster_name, e))?;

    let status = cluster.status.unwrap_or_default();
    Ok(ClusterContext {
        phase: status.phase,
        pivot_complete: status.pivot_complete,
        unpivot_pending: status.unpivot_pending,
    })
}

// =============================================================================
// Attack Implementations
// =============================================================================

fn kill_pod(cluster: &str, kubeconfig: &str) {
    let output = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "delete",
            "pod",
            "-n",
            OPERATOR_NS,
            "-l",
            OPERATOR_LABEL,
            "--wait=false",
        ],
    );

    let msg = if output.contains("deleted") {
        "killed"
    } else if output.contains("No resources found") {
        "no pod (restarting)"
    } else if is_unreachable(&output) {
        "unreachable"
    } else {
        output.trim()
    };
    info!("[Chaos] Pod on {}: {}", cluster, msg);
}

async fn cut_network(
    cluster: &str,
    kubeconfig: &str,
    cancel: &CancellationToken,
    blackout_secs: u64,
) {
    let policy_file = format!("/tmp/chaos-{}.yaml", cluster);

    if std::fs::write(&policy_file, NETWORK_BLACKOUT_POLICY).is_err() {
        return;
    }

    let output = run_cmd_allow_fail(
        "kubectl",
        &["--kubeconfig", kubeconfig, "apply", "-f", &policy_file],
    );

    let policy_applied =
        output.contains("created") || output.contains("configured") || output.contains("unchanged");

    if !policy_applied {
        let _ = std::fs::remove_file(&policy_file);
        if !is_unreachable(&output) {
            info!("[Chaos] Network on {}: {}", cluster, output.trim());
        }
        return;
    }

    let status = if output.contains("unchanged") {
        "cut (clearing stale policy)"
    } else {
        "cut"
    };
    info!(
        "[Chaos] Network on {}: {} for {}s",
        cluster, status, blackout_secs
    );

    tokio::select! {
        _ = cancel.cancelled() => {}
        _ = tokio::time::sleep(Duration::from_secs(blackout_secs)) => {}
    }

    // Restore network with retries
    for attempt in 1..=5 {
        let output = run_cmd_allow_fail(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig,
                "delete",
                "-f",
                &policy_file,
                "--ignore-not-found",
            ],
        );

        if output.contains("deleted") || output.contains("not found") || output.is_empty() {
            break;
        }

        if is_unreachable(&output) && attempt < 5 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            continue;
        }

        if !is_unreachable(&output) {
            info!(
                "[Chaos] Network restore on {} failed: {}",
                cluster,
                output.trim()
            );
        }
        break;
    }

    let _ = std::fs::remove_file(&policy_file);
    info!("[Chaos] Network on {}: restored", cluster);
}

fn is_unreachable(output: &str) -> bool {
    output.contains("refused") || output.contains("unreachable") || output.contains("no such host")
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cluster_context_critical_phases() {
        let pivoting = ClusterContext {
            phase: ClusterPhase::Pivoting,
            pivot_complete: false,
            unpivot_pending: false,
        };
        assert!(pivoting.is_critical());

        let unpivoting = ClusterContext {
            phase: ClusterPhase::Unpivoting,
            pivot_complete: true,
            unpivot_pending: false,
        };
        assert!(unpivoting.is_critical());

        let unpivot_pending = ClusterContext {
            phase: ClusterPhase::Pivoted,
            pivot_complete: true,
            unpivot_pending: true,
        };
        assert!(unpivot_pending.is_critical());

        let pivoted = ClusterContext {
            phase: ClusterPhase::Pivoted,
            pivot_complete: true,
            unpivot_pending: false,
        };
        assert!(!pivoted.is_critical());
    }

    #[test]
    fn test_chaos_targets_add_remove() {
        let targets = ChaosTargets::new();

        targets.add("cluster1", "/tmp/kc1", None);
        targets.add("cluster2", "/tmp/kc2", Some("/tmp/kc1"));

        let snapshot = targets.snapshot();
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot[0].name, "cluster1");
        assert!(snapshot[0].parent_kubeconfig.is_none());
        assert_eq!(snapshot[1].name, "cluster2");
        assert_eq!(snapshot[1].parent_kubeconfig.as_deref(), Some("/tmp/kc1"));

        targets.remove("cluster1");
        assert_eq!(targets.snapshot().len(), 1);
    }

    #[test]
    fn test_find_coordinated_attack() {
        let targets = ChaosTargets::new();

        targets.add("parent", "/tmp/parent-kc", None);
        targets.add("child", "/tmp/child-kc", Some("/tmp/parent-kc"));

        // No attack when child is Pivoted (stable state)
        targets.update_context(
            "child",
            ClusterContext {
                phase: ClusterPhase::Pivoted,
                pivot_complete: true,
                unpivot_pending: false,
            },
        );
        assert!(targets.find_coordinated_attack().is_none());

        // Attack when child is Pivoting
        targets.update_context(
            "child",
            ClusterContext {
                phase: ClusterPhase::Pivoting,
                pivot_complete: false,
                unpivot_pending: false,
            },
        );
        let attack = targets.find_coordinated_attack();
        assert!(attack.is_some());
        assert!(matches!(
            attack.unwrap(),
            CoordinatedAttack::PivotStress { .. }
        ));

        // UnpivotStress when unpivot_pending
        targets.update_context(
            "child",
            ClusterContext {
                phase: ClusterPhase::Pivoted,
                pivot_complete: true,
                unpivot_pending: true,
            },
        );
        let attack = targets.find_coordinated_attack();
        assert!(attack.is_some());
        assert!(matches!(
            attack.unwrap(),
            CoordinatedAttack::UnpivotStress { .. }
        ));
    }

    #[test]
    fn test_chaos_config_for_provider() {
        use super::InfraProvider;

        // Docker uses fast intervals (no LB delays)
        let docker = ChaosConfig::for_provider(InfraProvider::Docker);
        assert!(!docker.enable_coordinated);
        assert!(docker.pod_interval.0 <= 60);

        // AWS uses slow intervals (NLB registration takes 30-90s)
        let aws = ChaosConfig::for_provider(InfraProvider::Aws);
        assert!(!aws.enable_coordinated);
        assert!(aws.pod_interval.0 >= 90);
        assert!(aws.pod_interval.0 > docker.pod_interval.0);
    }

    #[test]
    fn test_chaos_config_builder() {
        let config = ChaosConfig::default()
            .with_pod_interval(120, 180)
            .with_net_interval(60, 90)
            .with_coordinated(0.3);

        assert_eq!(config.pod_interval, (120, 180));
        assert_eq!(config.net_interval, (60, 90));
        assert!(config.enable_coordinated);
        assert!((config.coordinated_probability - 0.3).abs() < 0.001);
    }

    #[test]
    fn test_chaos_config_coordinated_by_provider() {
        use super::InfraProvider;

        // Docker coordinated has shorter critical blackout
        let docker_coord = ChaosConfig::for_provider(InfraProvider::Docker).with_coordinated(0.5);
        assert!(docker_coord.enable_coordinated);
        assert_eq!(docker_coord.critical_blackout_secs, 15);

        // AWS coordinated has longer critical blackout
        let aws_coord = ChaosConfig::for_provider(InfraProvider::Aws).with_coordinated(0.5);
        assert!(aws_coord.enable_coordinated);
        assert_eq!(aws_coord.critical_blackout_secs, 20);
    }
}
