//! Chaos monkey for E2E tests - randomly kills pods and cuts network to test resilience
//!
//! Supports both random single-cluster attacks and coordinated parent-child attacks
//! that target critical phases like pivoting and unpivoting.
//!
//! # Deterministic Randomness
//!
//! All randomness is seeded from the run_id, making chaos events reproducible.
//! If a test fails, rerun with the same run_id to get identical chaos timing.
//!
//! # Provider-Aware Configuration
//!
//! Use `ChaosConfig::for_provider()` to get appropriate settings:
//! - Docker/kind: Fast intervals (60-120s) since no LB delays
//! - AWS/cloud: Slow intervals (90-150s) to account for NLB target registration

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;

use kube::Api;
use parking_lot::{Mutex, RwLock};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tokio_util::sync::CancellationToken;
use tracing::info;

use lattice_common::crd::{ClusterPhase, LatticeCluster};
use lattice_common::LATTICE_SYSTEM_NAMESPACE;

use super::helpers::{client_from_kubeconfig, run_cmd, OPERATOR_LABEL};
use super::providers::InfraProvider;

/// Create a seeded RNG from a string (typically run_id).
fn seeded_rng(seed_str: &str) -> StdRng {
    let mut hasher = DefaultHasher::new();
    seed_str.hash(&mut hasher);
    StdRng::seed_from_u64(hasher.finish())
}

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
            pod_interval: (60, 120),
            net_interval: (90, 150),
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
                pod_interval: (90, 150),  // 90-150s between pod kills
                net_interval: (120, 180), // 120-180s between network cuts
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
            0..=60 => 15, // Docker: shorter critical blackout
            _ => 20,      // AWS/cloud: longer critical blackout
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
}

impl ClusterContext {
    /// Returns true if the cluster is in a critical phase that's ideal for stress testing
    pub fn is_critical(&self) -> bool {
        matches!(
            self.phase,
            ClusterPhase::Pivoting | ClusterPhase::Unpivoting
        )
    }
}

/// Thread-safe collection of cluster targets with their state
pub struct ChaosTargets {
    targets: RwLock<Vec<ClusterTarget>>,
    contexts: RwLock<std::collections::HashMap<String, ClusterContext>>,
    rng: Mutex<StdRng>,
}

impl ChaosTargets {
    /// Create new chaos targets with seeded RNG for reproducibility.
    pub fn new(seed: &str) -> Self {
        Self {
            targets: RwLock::new(Vec::new()),
            contexts: RwLock::new(std::collections::HashMap::new()),
            rng: Mutex::new(seeded_rng(seed)),
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

    /// Get a random target for single-cluster attacks (uses seeded RNG)
    pub fn random(&self) -> Option<ClusterTarget> {
        let targets = self.targets.read();
        if targets.is_empty() {
            return None;
        }
        let idx = self.rng.lock().gen_range(0..targets.len());
        Some(targets[idx].clone())
    }

    /// Generate a random delay within the given range (uses seeded RNG)
    pub fn random_delay(&self, min: u64, max: u64) -> u64 {
        self.rng.lock().gen_range(min..=max)
    }

    /// Generate a random probability check (uses seeded RNG)
    pub fn random_probability(&self) -> f32 {
        self.rng.lock().gen::<f32>()
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
                            let attack = if matches!(ctx.phase, ClusterPhase::Unpivoting) {
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
                    "UnpivotStress: parent={} child={} (phase: {:?})",
                    parent.name, child.name, child_context.phase
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
// Network Blackout Job
// =============================================================================

/// Generate a Job manifest that applies a network blackout policy, waits, then deletes it.
///
/// The Job runs inside the cluster with direct API access, so cleanup succeeds even
/// when the blackout breaks external connectivity (e.g. proxy tunnels). The blackout
/// policy only targets `app: lattice-operator` pods, so the Job pod is unaffected.
fn network_blackout_job_manifest(blackout_secs: u64) -> String {
    format!(
        r#"apiVersion: v1
kind: ServiceAccount
metadata:
  name: chaos-blackout
  namespace: lattice-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: chaos-blackout
rules:
- apiGroups: ["cilium.io"]
  resources: ["ciliumnetworkpolicies"]
  verbs: ["create", "delete", "get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: chaos-blackout
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: chaos-blackout
subjects:
- kind: ServiceAccount
  name: chaos-blackout
  namespace: lattice-system
---
apiVersion: batch/v1
kind: Job
metadata:
  name: chaos-blackout
  namespace: lattice-system
spec:
  ttlSecondsAfterFinished: 30
  backoffLimit: 0
  template:
    spec:
      serviceAccountName: chaos-blackout
      restartPolicy: Never
      tolerations:
      - operator: Exists
      containers:
      - name: blackout
        image: bitnami/kubectl:latest
        command: ["/bin/sh", "-c"]
        args:
        - |
          cat <<'POLICY' | kubectl apply -f -
          apiVersion: cilium.io/v2
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
          POLICY
          echo "Blackout applied, sleeping {secs}s..."
          sleep {secs}
          kubectl delete ciliumnetworkpolicy chaos-blackout -n lattice-system --ignore-not-found
          echo "Blackout removed"
"#,
        secs = blackout_secs,
    )
}

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
        let delay = targets.random_delay(config.pod_interval.0, config.pod_interval.1);
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(delay)) => {}
        }

        // Try coordinated attack first if enabled
        if config.enable_coordinated {
            if let Some(attack) = targets.find_coordinated_attack() {
                if targets.random_probability() < config.coordinated_probability {
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
        let delay = targets.random_delay(config.net_interval.0, config.net_interval.1);
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(delay)) => {}
        }

        // Try coordinated attack first if enabled
        if config.enable_coordinated {
            if let Some(attack) = targets.find_coordinated_attack() {
                if targets.random_probability() < config.coordinated_probability {
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
    })
}

// =============================================================================
// Attack Implementations
// =============================================================================

fn kill_pod(cluster: &str, kubeconfig: &str) {
    let msg = match run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "delete",
            "pod",
            "-n",
            LATTICE_SYSTEM_NAMESPACE,
            "-l",
            OPERATOR_LABEL,
            "--wait=false",
        ],
    ) {
        Ok(output) if output.contains("deleted") => "killed operator pod".to_string(),
        Ok(_) => "no pod found (may be restarting)".to_string(),
        Err(e) if is_unreachable(&e) => "cluster unreachable".to_string(),
        Err(_) => "no pod found or not accessible".to_string(),
    };
    info!("[Chaos] Pod kill on {}: {}", cluster, msg);
}

async fn cut_network(
    cluster: &str,
    kubeconfig: &str,
    _cancel: &CancellationToken,
    blackout_secs: u64,
) {
    let job_file = format!("/tmp/chaos-job-{}.yaml", cluster);
    let manifest = network_blackout_job_manifest(blackout_secs);

    if std::fs::write(&job_file, &manifest).is_err() {
        return;
    }

    // Delete any previous job first (in case ttl hasn't cleaned it up yet)
    let _ = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "delete",
            "job",
            "chaos-blackout",
            "-n",
            LATTICE_SYSTEM_NAMESPACE,
            "--ignore-not-found",
        ],
    );

    // Deploy the self-cleaning blackout job
    match run_cmd(
        "kubectl",
        &["--kubeconfig", kubeconfig, "apply", "-f", &job_file],
    ) {
        Ok(_) => {
            info!(
                "[Chaos] Network cut on {}: blackout job deployed for {}s",
                cluster, blackout_secs
            );
        }
        Err(e) if is_unreachable(&e) => {
            info!(
                "[Chaos] Network cut on {} failed: cluster unreachable",
                cluster
            );
        }
        Err(_) => {
            info!(
                "[Chaos] Network cut on {} failed: job deploy failed",
                cluster
            );
        }
    }

    let _ = std::fs::remove_file(&job_file);
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
        };
        assert!(pivoting.is_critical());

        let unpivoting = ClusterContext {
            phase: ClusterPhase::Unpivoting,
            pivot_complete: true,
        };
        assert!(unpivoting.is_critical());

        let pivoted = ClusterContext {
            phase: ClusterPhase::Pivoted,
            pivot_complete: true,
        };
        assert!(!pivoted.is_critical());
    }

    #[test]
    fn test_chaos_targets_add_remove() {
        let targets = ChaosTargets::new("test-seed");

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
        let targets = ChaosTargets::new("test-seed");

        targets.add("parent", "/tmp/parent-kc", None);
        targets.add("child", "/tmp/child-kc", Some("/tmp/parent-kc"));

        // No attack when child is Pivoted (stable state)
        targets.update_context(
            "child",
            ClusterContext {
                phase: ClusterPhase::Pivoted,
                pivot_complete: true,
            },
        );
        assert!(targets.find_coordinated_attack().is_none());

        // PivotStress when child is Pivoting
        targets.update_context(
            "child",
            ClusterContext {
                phase: ClusterPhase::Pivoting,
                pivot_complete: false,
            },
        );
        let attack = targets.find_coordinated_attack();
        assert!(attack.is_some());
        assert!(matches!(
            attack.unwrap(),
            CoordinatedAttack::PivotStress { .. }
        ));

        // UnpivotStress when child is Unpivoting
        targets.update_context(
            "child",
            ClusterContext {
                phase: ClusterPhase::Unpivoting,
                pivot_complete: true,
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

    #[test]
    fn test_seeded_rng_is_deterministic() {
        // Same seed should produce same sequence
        let targets1 = ChaosTargets::new("test-run-12345");
        let targets2 = ChaosTargets::new("test-run-12345");

        // Add same clusters to both
        targets1.add("a", "/tmp/a", None);
        targets1.add("b", "/tmp/b", None);
        targets2.add("a", "/tmp/a", None);
        targets2.add("b", "/tmp/b", None);

        // Should produce identical sequences
        let delays1: Vec<u64> = (0..5).map(|_| targets1.random_delay(60, 120)).collect();
        let delays2: Vec<u64> = (0..5).map(|_| targets2.random_delay(60, 120)).collect();
        assert_eq!(delays1, delays2, "Same seed should produce same delays");

        // Different seed should produce different sequence
        let targets3 = ChaosTargets::new("different-seed");
        targets3.add("a", "/tmp/a", None);
        targets3.add("b", "/tmp/b", None);
        let delays3: Vec<u64> = (0..5).map(|_| targets3.random_delay(60, 120)).collect();
        assert_ne!(
            delays1, delays3,
            "Different seed should produce different delays"
        );
    }
}
