//! Capacity solver — translates aggregate quota demands into pool node counts.
//!
//! Uses LP relaxation with ceiling rounding to find the minimum-cost node
//! allocation that satisfies all quota constraints. Solves in microseconds
//! even with hundreds of pool types.
//!
//! # Architecture
//!
//! The solver is a pipeline:
//! 1. Build pool shapes from specs + cost rates
//! 2. Collect constraints from demand (each resource type = one constraint)
//! 3. Feed constraints into the LP solver
//! 4. Ceil fractional results to whole nodes
//! 5. Clamp by pool spec min/max
//!
//! New constraint types (taints, priority classes, affinity) are added by
//! implementing `SolverConstraint` — no changes to the core solver needed.

use std::collections::BTreeMap;

use good_lp::{
    constraint, variable, Expression, ProblemVariables, Solution, SolverModel, Variable,
};
use tracing::warn;

use lattice_common::crd::{LatticeQuota, WorkerPoolSpec};
use lattice_common::resources::{
    parse_cpu_millis_str, parse_memory_bytes_str, parse_resource_by_key, CPU_RESOURCE,
    GPU_RESOURCE, MEMORY_RESOURCE,
};
use lattice_cost::CostRates;

// =============================================================================
// Output types
// =============================================================================

/// Complete solver output.
#[derive(Clone, Debug)]
pub struct SolverResult {
    /// Per-pool capacity plans
    pub plans: Vec<PoolCapacityPlan>,
    /// Minimum hourly cost (hard quotas — guaranteed reserved capacity)
    pub min_hourly_cost: f64,
    /// Maximum hourly cost (soft quotas — burst ceiling)
    pub max_hourly_cost: f64,
}

/// Per-pool capacity plan computed by the solver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolCapacityPlan {
    /// Pool identifier
    pub pool_id: String,
    /// Desired minimum nodes (from hard quotas, clamped by pool spec)
    pub min_nodes: u32,
    /// Desired maximum nodes (from soft quotas, clamped by pool spec)
    pub max_nodes: u32,
}

// =============================================================================
// Node shape
// =============================================================================

/// What one node in a pool provides.
#[derive(Clone, Debug)]
pub struct NodeShape {
    /// CPU in millicores per node
    pub cpu_millis: i64,
    /// Memory in bytes per node
    pub memory_bytes: i64,
    /// GPU count per node (0 for non-GPU pools)
    pub gpu_count: u32,
    /// Hourly cost per node (USD)
    pub hourly_cost: f64,
}

impl NodeShape {
    /// Derive node shape from a WorkerPoolSpec and cost rates.
    pub fn from_pool_spec(spec: &WorkerPoolSpec, rates: &CostRates) -> Option<Self> {
        let (cpu_millis, memory_bytes, gpu_count) = extract_capacity(spec)?;

        let cpu_cost = (cpu_millis as f64 / 1000.0) * rates.cpu;
        let mem_cost = (memory_bytes as f64 / (1024.0 * 1024.0 * 1024.0)) * rates.memory;
        let gpu_cost: f64 = spec
            .instance_type
            .as_ref()
            .and_then(|it| it.gpu.as_ref())
            .and_then(|g| rates.gpu.get(&g.model))
            .map(|rate| rate * gpu_count as f64)
            .unwrap_or(0.0);

        Some(Self {
            cpu_millis,
            memory_bytes,
            gpu_count,
            hourly_cost: cpu_cost + mem_cost + gpu_cost,
        })
    }
}

fn extract_capacity(spec: &WorkerPoolSpec) -> Option<(i64, i64, u32)> {
    let gpu = spec
        .instance_type
        .as_ref()
        .and_then(|it| it.gpu.as_ref())
        .map(|g| g.count)
        .unwrap_or(0);

    if let Some(ref capacity) = spec.capacity {
        let cpu = parse_cpu_millis_str(&capacity.cpu).ok()?;
        let mem = parse_memory_bytes_str(&capacity.memory).ok()?;
        return Some((cpu, mem, gpu));
    }

    if let Some(ref it) = spec.instance_type {
        if let Some(res) = it.as_resources() {
            return Some((
                res.cores as i64 * 1000,
                res.memory_gib as i64 * 1024 * 1024 * 1024,
                gpu,
            ));
        }
    }

    None
}

// =============================================================================
// Constraints (vertical slice — each new constraint type is a new impl)
// =============================================================================

/// A constraint that can be applied to the ILP problem.
///
/// Each constraint type extracts a per-node coefficient from the node shape
/// and a minimum demand value. The solver builds `Σ(coeff[i] * nodes[i]) >= demand`.
pub trait SolverConstraint {
    /// Per-node coefficient for each pool (e.g., CPU millis per node).
    /// Returns None for pools that don't participate in this constraint.
    fn coefficient(&self, shape: &NodeShape) -> f64;

    /// Minimum total demand that must be satisfied.
    fn demand(&self) -> f64;

    /// Whether this is an upper-bound constraint (<=) instead of lower-bound (>=).
    fn is_upper_bound(&self) -> bool {
        false
    }
}

/// Constraint: total CPU across all nodes must meet demand.
struct CpuConstraint(i64);

impl SolverConstraint for CpuConstraint {
    fn coefficient(&self, shape: &NodeShape) -> f64 {
        shape.cpu_millis as f64
    }
    fn demand(&self) -> f64 {
        self.0 as f64
    }
}

/// Constraint: total memory across all nodes must meet demand.
struct MemoryConstraint(i64);

impl SolverConstraint for MemoryConstraint {
    fn coefficient(&self, shape: &NodeShape) -> f64 {
        shape.memory_bytes as f64
    }
    fn demand(&self) -> f64 {
        self.0 as f64
    }
}

/// Constraint: total GPUs across all nodes must meet demand.
struct GpuConstraint(u32);

impl SolverConstraint for GpuConstraint {
    fn coefficient(&self, shape: &NodeShape) -> f64 {
        shape.gpu_count as f64
    }
    fn demand(&self) -> f64 {
        self.0 as f64
    }
}

/// Constraint: total hourly cost must not exceed budget.
struct CostBudgetConstraint(f64);

impl SolverConstraint for CostBudgetConstraint {
    fn coefficient(&self, shape: &NodeShape) -> f64 {
        shape.hourly_cost
    }
    fn demand(&self) -> f64 {
        self.0
    }
    fn is_upper_bound(&self) -> bool {
        true
    }
}

// =============================================================================
// Demand aggregation
// =============================================================================

/// Aggregate quota demand — sum of all quota limits.
#[derive(Clone, Debug, Default)]
pub struct AggregateDemand {
    /// Sum of hard quota CPU (millis)
    pub hard_cpu_millis: i64,
    /// Sum of hard quota memory (bytes)
    pub hard_memory_bytes: i64,
    /// Sum of hard quota GPUs
    pub hard_gpu_count: u32,
    /// Sum of hard quota hourly cost budget (USD, 0 = no constraint)
    pub hard_cost_budget: f64,
    /// Sum of soft quota CPU (millis)
    pub soft_cpu_millis: i64,
    /// Sum of soft quota memory (bytes)
    pub soft_memory_bytes: i64,
    /// Sum of soft quota GPUs
    pub soft_gpu_count: u32,
    /// Sum of soft quota hourly cost budget (USD, 0 = no constraint)
    pub soft_cost_budget: f64,
}

impl AggregateDemand {
    /// Build constraint list for hard demands (guaranteed capacity).
    fn hard_constraints(&self) -> Vec<Box<dyn SolverConstraint>> {
        build_constraints(
            self.hard_cpu_millis,
            self.hard_memory_bytes,
            self.hard_gpu_count,
            self.hard_cost_budget,
        )
    }

    /// Build constraint list for soft demands (burst ceiling).
    fn soft_constraints(&self) -> Vec<Box<dyn SolverConstraint>> {
        build_constraints(
            self.soft_cpu_millis,
            self.soft_memory_bytes,
            self.soft_gpu_count,
            self.soft_cost_budget,
        )
    }
}

fn build_constraints(cpu: i64, memory: i64, gpu: u32, cost: f64) -> Vec<Box<dyn SolverConstraint>> {
    let mut constraints: Vec<Box<dyn SolverConstraint>> = Vec::new();
    if cpu > 0 {
        constraints.push(Box::new(CpuConstraint(cpu)));
    }
    if memory > 0 {
        constraints.push(Box::new(MemoryConstraint(memory)));
    }
    if gpu > 0 {
        constraints.push(Box::new(GpuConstraint(gpu)));
    }
    if cost > 0.0 {
        constraints.push(Box::new(CostBudgetConstraint(cost)));
    }
    constraints
}

/// Aggregate demands from all enabled quotas.
pub fn aggregate_quotas(quotas: &[LatticeQuota]) -> AggregateDemand {
    let mut demand = AggregateDemand::default();

    for quota in quotas {
        if !quota.spec.enabled {
            continue;
        }

        demand.soft_cpu_millis += parse_quantity(&quota.spec.soft, CPU_RESOURCE);
        demand.soft_memory_bytes += parse_quantity(&quota.spec.soft, MEMORY_RESOURCE);
        demand.soft_gpu_count += parse_quantity(&quota.spec.soft, GPU_RESOURCE) as u32;
        demand.soft_cost_budget += parse_cost(&quota.spec.soft);

        if let Some(ref hard) = quota.spec.hard {
            demand.hard_cpu_millis += parse_quantity(hard, CPU_RESOURCE);
            demand.hard_memory_bytes += parse_quantity(hard, MEMORY_RESOURCE);
            demand.hard_gpu_count += parse_quantity(hard, GPU_RESOURCE) as u32;
            demand.hard_cost_budget += parse_cost(hard);
        }
    }

    demand
}

// =============================================================================
// Core solver
// =============================================================================

/// Solve pool capacity plans from aggregate demand, pool specs, and cost rates.
///
/// Runs ILP twice:
/// - Hard demands → min_nodes (guaranteed reserved capacity)
/// - Soft demands → max_nodes (autoscaler ceiling)
///
/// Both minimize total hourly cost. Pool spec min/max clamp the result.
pub fn solve(
    pools: &BTreeMap<String, WorkerPoolSpec>,
    demand: &AggregateDemand,
    rates: &CostRates,
) -> SolverResult {
    let pool_shapes: Vec<(&str, &WorkerPoolSpec, NodeShape)> = pools
        .iter()
        .filter_map(|(id, spec)| {
            NodeShape::from_pool_spec(spec, rates).map(|shape| (id.as_str(), spec, shape))
        })
        .collect();

    if pool_shapes.is_empty() {
        return SolverResult {
            plans: Vec::new(),
            min_hourly_cost: 0.0,
            max_hourly_cost: 0.0,
        };
    }

    let hard_solution = solve_lp(&pool_shapes, &demand.hard_constraints());
    let soft_solution = solve_lp(&pool_shapes, &demand.soft_constraints());

    let plans: Vec<PoolCapacityPlan> = pool_shapes
        .iter()
        .enumerate()
        .map(|(i, (pool_id, spec, _))| {
            let quota_min = hard_solution.get(i).copied().unwrap_or(0);
            let quota_max = soft_solution.get(i).copied().unwrap_or(0);
            clamp_plan(pool_id, spec, quota_min, quota_max)
        })
        .collect();

    let min_hourly_cost: f64 = plans
        .iter()
        .zip(pool_shapes.iter())
        .map(|(plan, (_, _, shape))| plan.min_nodes as f64 * shape.hourly_cost)
        .sum();

    let max_hourly_cost: f64 = plans
        .iter()
        .zip(pool_shapes.iter())
        .map(|(plan, (_, _, shape))| plan.max_nodes as f64 * shape.hourly_cost)
        .sum();

    SolverResult {
        plans,
        min_hourly_cost,
        max_hourly_cost,
    }
}

/// Core LP solver: minimize cost subject to constraints, then ceil() for whole nodes.
///
/// Uses continuous LP relaxation instead of integer programming. Rounding up
/// is always safe (provides >= demanded resources) and the LP solves in
/// microseconds vs milliseconds for MIP at 100+ variables.
fn solve_lp(
    pools: &[(&str, &WorkerPoolSpec, NodeShape)],
    constraints: &[Box<dyn SolverConstraint>],
) -> Vec<u32> {
    if constraints.is_empty() || constraints.iter().all(|c| c.demand() <= 0.0) {
        return vec![0; pools.len()];
    }

    let mut vars = ProblemVariables::new();
    let node_vars: Vec<Variable> = pools.iter().map(|_| vars.add(variable().min(0))).collect();

    let cost_expr: Expression = node_vars
        .iter()
        .zip(pools.iter())
        .map(|(var, (_, _, shape))| shape.hourly_cost * *var)
        .sum();

    let mut model = vars
        .minimise(&cost_expr)
        .using(good_lp::solvers::microlp::microlp);

    for c in constraints {
        let expr: Expression = node_vars
            .iter()
            .zip(pools.iter())
            .map(|(var, (_, _, shape))| c.coefficient(shape) * *var)
            .sum();

        if c.is_upper_bound() {
            model = model.with(constraint!(expr <= c.demand()));
        } else {
            model = model.with(constraint!(expr >= c.demand()));
        }
    }

    match model.solve() {
        Ok(solution) => node_vars
            .iter()
            .map(|var| solution.value(*var).ceil() as u32)
            .collect(),
        Err(e) => {
            warn!(error = %e, "LP solver failed, falling back to zero nodes");
            vec![0; pools.len()]
        }
    }
}

fn clamp_plan(
    pool_id: &str,
    spec: &WorkerPoolSpec,
    quota_min: u32,
    quota_max: u32,
) -> PoolCapacityPlan {
    let min_nodes = match spec.min {
        Some(pool_min) => pool_min.max(quota_min),
        None => quota_min,
    };
    // Pool spec max is the autoscaler ceiling — quotas raise min but don't
    // reduce max. The autoscaler only scales to meet pending pods anyway;
    // capping max to 0 just prevents it from ever working.
    let max_nodes = match spec.max {
        Some(pool_max) => pool_max.max(min_nodes),
        None => quota_max.max(min_nodes),
    };
    PoolCapacityPlan {
        pool_id: pool_id.to_string(),
        min_nodes,
        max_nodes,
    }
}

fn parse_quantity(map: &BTreeMap<String, String>, key: &str) -> i64 {
    map.get(key)
        .and_then(|v| parse_resource_by_key(key, v).ok())
        .unwrap_or(0)
}

fn parse_cost(map: &BTreeMap<String, String>) -> f64 {
    map.get("cost")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{GpuCapacity, InstanceType, LatticeQuotaSpec, NodeCapacityHint};

    fn test_rates() -> CostRates {
        CostRates {
            cpu: 0.031,
            memory: 0.004,
            gpu: BTreeMap::from([
                ("NVIDIA-H100-SXM".to_string(), 3.50),
                ("NVIDIA-L4".to_string(), 0.81),
            ]),
        }
    }

    fn gpu_pool(gpu_count: u32, cpu_cores: u32, mem_gib: u32, model: &str) -> WorkerPoolSpec {
        WorkerPoolSpec {
            instance_type: Some(InstanceType {
                cores: Some(cpu_cores),
                memory_gib: Some(mem_gib),
                disk_gib: Some(100),
                gpu: Some(GpuCapacity {
                    count: gpu_count,
                    model: model.to_string(),
                    memory_gib: Some(80),
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn cpu_pool(cpu_cores: u32, mem_gib: u32) -> WorkerPoolSpec {
        WorkerPoolSpec {
            instance_type: Some(InstanceType {
                cores: Some(cpu_cores),
                memory_gib: Some(mem_gib),
                disk_gib: Some(100),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn solve_no_demand() {
        let mut pools = BTreeMap::new();
        pools.insert("compute".to_string(), cpu_pool(16, 64));
        let result = solve(&pools, &AggregateDemand::default(), &test_rates());
        assert_eq!(result.plans[0].min_nodes, 0);
        assert_eq!(result.plans[0].max_nodes, 0);
        assert_eq!(result.min_hourly_cost, 0.0);
        assert_eq!(result.max_hourly_cost, 0.0);
    }

    #[test]
    fn solve_cpu_only() {
        let mut pools = BTreeMap::new();
        pools.insert("compute".to_string(), cpu_pool(16, 64));
        let demand = AggregateDemand {
            soft_cpu_millis: 64_000,
            soft_memory_bytes: 128 * 1024 * 1024 * 1024,
            ..Default::default()
        };
        let result = solve(&pools, &demand, &test_rates());
        let plans = &result.plans;
        assert_eq!(plans[0].max_nodes, 4);
        assert_eq!(plans[0].min_nodes, 0);
    }

    #[test]
    fn solve_gpu_demand() {
        let mut pools = BTreeMap::new();
        pools.insert("gpu".to_string(), gpu_pool(8, 192, 2048, "NVIDIA-H100-SXM"));
        pools.insert("compute".to_string(), cpu_pool(32, 128));
        let demand = AggregateDemand {
            soft_gpu_count: 16,
            soft_cpu_millis: 100_000,
            soft_memory_bytes: 256 * 1024 * 1024 * 1024,
            ..Default::default()
        };
        let result = solve(&pools, &demand, &test_rates());
        let plans = &result.plans;
        let gpu_plan = plans.iter().find(|p| p.pool_id == "gpu").unwrap();
        assert_eq!(gpu_plan.max_nodes, 2);
        let cpu_plan = plans.iter().find(|p| p.pool_id == "compute").unwrap();
        assert_eq!(cpu_plan.max_nodes, 0);
    }

    #[test]
    fn solve_hard_vs_soft() {
        let mut pools = BTreeMap::new();
        pools.insert("compute".to_string(), cpu_pool(16, 64));
        let demand = AggregateDemand {
            hard_cpu_millis: 32_000,
            soft_cpu_millis: 80_000,
            ..Default::default()
        };
        let result = solve(&pools, &demand, &test_rates());
        let plans = &result.plans;
        assert_eq!(plans[0].min_nodes, 2);
        assert_eq!(plans[0].max_nodes, 5);
    }

    #[test]
    fn solve_pool_clamp_floor() {
        let mut pools = BTreeMap::new();
        let mut spec = cpu_pool(16, 64);
        spec.min = Some(3);
        pools.insert("compute".to_string(), spec);
        let demand = AggregateDemand {
            hard_cpu_millis: 16_000,
            soft_cpu_millis: 32_000,
            ..Default::default()
        };
        let result = solve(&pools, &demand, &test_rates());
        let plans = &result.plans;
        assert_eq!(plans[0].min_nodes, 3);
        assert_eq!(plans[0].max_nodes, 3);
    }

    #[test]
    fn solve_pool_clamp_ceiling() {
        let mut pools = BTreeMap::new();
        let mut spec = cpu_pool(16, 64);
        spec.max = Some(5);
        pools.insert("compute".to_string(), spec);
        let demand = AggregateDemand {
            soft_cpu_millis: 160_000,
            ..Default::default()
        };
        let result = solve(&pools, &demand, &test_rates());
        let plans = &result.plans;
        assert_eq!(plans[0].max_nodes, 5);
    }

    #[test]
    fn solve_cost_optimizes_across_pool_types() {
        // With LP relaxation + ceil, the solver may pick a fractional large node
        // (0.25 * 64 = 16 cores) and ceil to 1, which is valid. The key invariant:
        // total provisioned CPU >= demanded CPU.
        let mut pools = BTreeMap::new();
        pools.insert("small".to_string(), cpu_pool(4, 16));
        pools.insert("large".to_string(), cpu_pool(64, 256));
        let demand = AggregateDemand {
            soft_cpu_millis: 16_000,
            ..Default::default()
        };
        let result = solve(&pools, &demand, &test_rates());
        let plans = &result.plans;
        let small = plans.iter().find(|p| p.pool_id == "small").unwrap();
        let large = plans.iter().find(|p| p.pool_id == "large").unwrap();
        // Either 4 small or 1 large satisfies 16 cores — solver picks cheapest
        let total_cpu = small.max_nodes as i64 * 4000 + large.max_nodes as i64 * 64000;
        assert!(
            total_cpu >= 16_000,
            "provisioned {total_cpu}m < demanded 16000m"
        );
    }

    #[test]
    fn solve_memory_bottleneck() {
        let mut pools = BTreeMap::new();
        pools.insert("compute".to_string(), cpu_pool(32, 64));
        let demand = AggregateDemand {
            soft_cpu_millis: 32_000,
            soft_memory_bytes: 256 * 1024 * 1024 * 1024,
            ..Default::default()
        };
        let result = solve(&pools, &demand, &test_rates());
        let plans = &result.plans;
        assert_eq!(plans[0].max_nodes, 4);
    }

    #[test]
    fn solve_rounds_up() {
        let mut pools = BTreeMap::new();
        pools.insert("compute".to_string(), cpu_pool(16, 64));
        let demand = AggregateDemand {
            soft_cpu_millis: 17_000,
            ..Default::default()
        };
        let result = solve(&pools, &demand, &test_rates());
        let plans = &result.plans;
        assert_eq!(plans[0].max_nodes, 2);
    }

    #[test]
    fn solve_empty_pools() {
        let result = solve(&BTreeMap::new(), &AggregateDemand::default(), &test_rates());
        assert!(result.plans.is_empty());
    }

    #[test]
    fn solve_pool_without_shape_skipped() {
        let mut pools = BTreeMap::new();
        pools.insert(
            "unknown".to_string(),
            WorkerPoolSpec {
                instance_type: Some(InstanceType::named("m5.xlarge")),
                ..Default::default()
            },
        );
        let demand = AggregateDemand {
            soft_cpu_millis: 100_000,
            ..Default::default()
        };
        let result = solve(&pools, &demand, &test_rates());
        let plans = &result.plans;
        assert!(plans.is_empty());
    }

    #[test]
    fn solve_cost_budget_constraint() {
        let mut pools = BTreeMap::new();
        pools.insert("gpu".to_string(), gpu_pool(8, 192, 2048, "NVIDIA-H100-SXM"));
        let demand = AggregateDemand {
            soft_gpu_count: 32,
            soft_cost_budget: 60.0,
            ..Default::default()
        };
        let result = solve(&pools, &demand, &test_rates());
        let plans = &result.plans;
        let gpu = plans.iter().find(|p| p.pool_id == "gpu").unwrap();
        assert!(gpu.max_nodes < 4);
    }

    #[test]
    fn solve_prefers_cheaper_gpu() {
        let mut pools = BTreeMap::new();
        pools.insert(
            "h100".to_string(),
            gpu_pool(8, 192, 2048, "NVIDIA-H100-SXM"),
        );
        pools.insert("l4".to_string(), gpu_pool(4, 48, 256, "NVIDIA-L4"));
        let demand = AggregateDemand {
            soft_gpu_count: 4,
            ..Default::default()
        };
        let result = solve(&pools, &demand, &test_rates());
        let plans = &result.plans;
        let l4 = plans.iter().find(|p| p.pool_id == "l4").unwrap();
        let h100 = plans.iter().find(|p| p.pool_id == "h100").unwrap();
        assert_eq!(l4.max_nodes, 1);
        assert_eq!(h100.max_nodes, 0);
    }

    #[test]
    fn solve_gpu_absorbs_cpu_memory() {
        let mut pools = BTreeMap::new();
        pools.insert("gpu".to_string(), gpu_pool(8, 192, 2048, "NVIDIA-H100-SXM"));
        pools.insert("compute".to_string(), cpu_pool(32, 128));
        let demand = AggregateDemand {
            soft_gpu_count: 8,
            soft_cpu_millis: 100_000,
            soft_memory_bytes: 500 * 1024 * 1024 * 1024,
            ..Default::default()
        };
        let result = solve(&pools, &demand, &test_rates());
        let plans = &result.plans;
        let gpu = plans.iter().find(|p| p.pool_id == "gpu").unwrap();
        let compute = plans.iter().find(|p| p.pool_id == "compute").unwrap();
        assert_eq!(gpu.max_nodes, 1);
        assert_eq!(compute.max_nodes, 0);
    }

    #[test]
    fn aggregate_quotas_basic() {
        let q1 = LatticeQuota::new(
            "team-a",
            LatticeQuotaSpec {
                principal: "Lattice::Group::\"team-a\"".to_string(),
                soft: BTreeMap::from([
                    ("cpu".into(), "64".into()),
                    ("nvidia.com/gpu".into(), "8".into()),
                ]),
                hard: Some(BTreeMap::from([
                    ("cpu".into(), "32".into()),
                    ("nvidia.com/gpu".into(), "4".into()),
                ])),
                max_per_workload: None,
                enabled: true,
            },
        );
        let q2 = LatticeQuota::new(
            "team-b",
            LatticeQuotaSpec {
                principal: "Lattice::Group::\"team-b\"".to_string(),
                soft: BTreeMap::from([
                    ("cpu".into(), "32".into()),
                    ("nvidia.com/gpu".into(), "8".into()),
                ]),
                hard: None,
                max_per_workload: None,
                enabled: true,
            },
        );
        let agg = aggregate_quotas(&[q1, q2]);
        assert_eq!(agg.soft_cpu_millis, 96_000);
        assert_eq!(agg.soft_gpu_count, 16);
        assert_eq!(agg.hard_cpu_millis, 32_000);
        assert_eq!(agg.hard_gpu_count, 4);
    }

    #[test]
    fn aggregate_skips_disabled() {
        let mut q = LatticeQuota::new(
            "disabled",
            LatticeQuotaSpec {
                principal: "Lattice::Group::\"x\"".to_string(),
                soft: BTreeMap::from([("cpu".into(), "100".into())]),
                hard: None,
                max_per_workload: None,
                enabled: false,
            },
        );
        q.spec.enabled = false;
        assert_eq!(aggregate_quotas(&[q]).soft_cpu_millis, 0);
    }

    #[test]
    fn aggregate_quotas_with_cost() {
        let q = LatticeQuota::new(
            "team-a",
            LatticeQuotaSpec {
                principal: "Lattice::Group::\"team-a\"".to_string(),
                soft: BTreeMap::from([("cpu".into(), "64".into()), ("cost".into(), "100".into())]),
                hard: Some(BTreeMap::from([("cost".into(), "50".into())])),
                max_per_workload: None,
                enabled: true,
            },
        );
        let agg = aggregate_quotas(&[q]);
        assert!((agg.soft_cost_budget - 100.0).abs() < f64::EPSILON);
        assert!((agg.hard_cost_budget - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn node_shape_includes_cost() {
        let spec = cpu_pool(16, 64);
        let shape = NodeShape::from_pool_spec(&spec, &test_rates()).unwrap();
        assert!((shape.hourly_cost - 0.752).abs() < 0.001);
    }

    #[test]
    fn node_shape_from_capacity_hint() {
        let spec = WorkerPoolSpec {
            capacity: Some(NodeCapacityHint {
                cpu: "96".into(),
                memory: "768Gi".into(),
            }),
            instance_type: Some(InstanceType {
                name: Some("p5.48xlarge".into()),
                gpu: Some(GpuCapacity {
                    count: 8,
                    model: "NVIDIA-H100-SXM".into(),
                    memory_gib: None,
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let shape = NodeShape::from_pool_spec(&spec, &test_rates()).unwrap();
        assert_eq!(shape.cpu_millis, 96000);
        assert_eq!(shape.memory_bytes, 768 * 1024 * 1024 * 1024);
        assert_eq!(shape.gpu_count, 8);
        assert!(shape.hourly_cost > 28.0);
    }

    #[test]
    fn constraint_trait_cpu() {
        let c = CpuConstraint(32_000);
        let shape = NodeShape {
            cpu_millis: 16_000,
            memory_bytes: 0,
            gpu_count: 0,
            hourly_cost: 1.0,
        };
        assert_eq!(c.coefficient(&shape), 16_000.0);
        assert_eq!(c.demand(), 32_000.0);
        assert!(!c.is_upper_bound());
    }

    #[test]
    fn constraint_trait_cost_budget() {
        let c = CostBudgetConstraint(100.0);
        let shape = NodeShape {
            cpu_millis: 0,
            memory_bytes: 0,
            gpu_count: 0,
            hourly_cost: 25.0,
        };
        assert_eq!(c.coefficient(&shape), 25.0);
        assert_eq!(c.demand(), 100.0);
        assert!(c.is_upper_bound());
    }

    #[test]
    fn solve_reports_cost_range() {
        let mut pools = BTreeMap::new();
        pools.insert("compute".to_string(), cpu_pool(16, 64));
        let demand = AggregateDemand {
            hard_cpu_millis: 32_000,   // 2 nodes
            soft_cpu_millis: 80_000,   // 5 nodes
            ..Default::default()
        };
        let result = solve(&pools, &demand, &test_rates());
        // 16-core, 64Gi node @ $0.031/core + $0.004/GiB = $0.752/hr
        let node_cost = 0.752;
        assert!((result.min_hourly_cost - 2.0 * node_cost).abs() < 0.01);
        assert!((result.max_hourly_cost - 5.0 * node_cost).abs() < 0.01);
    }

    #[test]
    fn solve_cost_range_with_gpu() {
        let mut pools = BTreeMap::new();
        pools.insert("gpu".to_string(), gpu_pool(8, 192, 2048, "NVIDIA-H100-SXM"));
        pools.insert("compute".to_string(), cpu_pool(32, 128));
        let demand = AggregateDemand {
            hard_gpu_count: 8,         // 1 GPU node hard
            soft_gpu_count: 16,        // 2 GPU nodes soft
            soft_cpu_millis: 100_000,  // absorbed by GPU nodes
            ..Default::default()
        };
        let result = solve(&pools, &demand, &test_rates());
        // GPU nodes are expensive, compute nodes may be zero
        assert!(result.min_hourly_cost > 0.0);
        assert!(result.max_hourly_cost >= result.min_hourly_cost);
    }
}
