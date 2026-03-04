# Capacity Pools & Workload-Driven Cluster Provisioning

## Problem

Lattice provisions and manages Kubernetes clusters via LatticeCluster CRDs, but the provisioning model is manually driven. Platform engineers must create individual LatticeCluster resources, choose instance types, set worker pool sizes, and configure provider settings for each cluster. Application developers must then deploy workloads to specific clusters by hand. There is no aggregate capacity tracking, no automatic cluster lifecycle management, and no workload placement intelligence.

This creates three concrete problems:

- **Platform engineers manage clusters as cattle, but they should manage capacity as a utility.** Creating and sizing individual clusters for GPU training workloads requires deep knowledge of instance types, node pools, and provider-specific configuration. A platform engineer who wants "200 H100 GPUs available for training" must translate that into specific LatticeCluster resources, worker pool sizes, and autoscaler bounds — then keep them updated as demand shifts.

- **Workload developers have no placement abstraction.** A developer deploying a LatticeModel that needs 8x H100 GPUs must know which cluster has H100 nodes, whether there is capacity, and manually target that cluster. If the cluster is full, they must coordinate with the platform team.

- **No capacity governance.** There is no mechanism to set upper bounds on resource consumption per pool or per purpose, no warm capacity guarantees for fast placement, and no visibility into aggregate utilization across clusters.

## Goals

- Introduce a `CapacityPool` CRD that lets platform engineers declare pools of cloud capacity with resource limits, warm capacity floors, and capability declarations
- Build a capacity planner that watches workload CRDs and CapacityPool resources, then automatically creates, scales, and drains LatticeCluster resources to satisfy demand
- Push placed workloads to target clusters via the existing K8s API proxy over gRPC — developers submit to the management cluster and the planner handles distribution
- Add optional placement fields to existing workload CRDs so workloads can express pool preferences, co-placement affinity, and blast radius requirements
- Report aggregate utilization, pending demand, and cluster inventory in CapacityPool status
- Preserve LatticeCluster as an escape hatch for users who want manual cluster management

## Non-Goals

- Dollar-cost calculation or cloud billing integration (the `budget` field is a placeholder for future work)
- Cross-region networking or multi-cluster service mesh (workloads are placed, not federated)
- Replacing Volcano's intra-cluster scheduling (the planner does inter-cluster placement; Volcano handles intra-cluster GPU/topology scheduling)
- Real-time bin-packing optimization (the planner operates on reconciliation cycles, not per-request)
- Automatic migration of running workloads between clusters (placement is at creation time)

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Platform Engineer UX                             │
│                                                                     │
│   InfraProvider         CapacityPool                                │
│   (credentials)    ───► (capacity limits, warm floor, capabilities) │
│                                                                     │
│   "I have an AWS account     "Keep 16 H100 GPUs warm.               │
│    in us-east-1"              Max 64 GPUs total.                    │
│                               Use p5.48xlarge instances."           │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                    Capacity Planner watches both
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  Capacity Planner (Management Cluster)              │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  Inputs:                                                      │ │
│  │  - CapacityPool specs (limits, warm capacity, capabilities)   │ │
│  │  - Unplaced workloads (LatticeService, LatticeJob, LatticeModel)│
│  │  - Current LatticeCluster inventory + utilization             │ │
│  │                                                               │ │
│  │  Outputs:                                                     │ │
│  │  - Create/scale/drain LatticeCluster resources                │ │
│  │  - Push workload CRDs to target clusters via K8s API proxy    │ │
│  │  - Update placement status on management-side workloads       │ │
│  └───────────────────────────────────────────────────────────────┘ │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ creates / scales / drains
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     LatticeCluster Resources                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                │
│  │ pool-a-001  │  │ pool-a-002  │  │ pool-b-001  │                │
│  │ H100 x 16   │  │ H100 x 16   │  │ L4 x 8      │                │
│  │ (warm)      │  │ (demand)    │  │ (demand)    │                │
│  └─────────────┘  └─────────────┘  └─────────────┘                │
│                                                                     │
│  Labels:                                                            │
│    lattice.dev/capacity-pool: pool-a                                │
│    lattice.dev/managed-by: capacity-planner                         │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
            Existing provisioning pipeline (CAPI → pivot)
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Running Clusters (Self-Managing)                │
│                                                                     │
│  Workloads pushed via K8s API proxy over gRPC.                      │
│  Each cluster's Lattice operator compiles workloads locally.        │
│  Volcano handles intra-cluster GPU/topology scheduling.             │
│  Cluster autoscaler handles node-level scaling within pool bounds.  │
└─────────────────────────────────────────────────────────────────────┘
```

### Workload Placement Flow

```
┌──────────────────────────────────────────────────────────────────┐
│  Developer applies LatticeModel to management cluster            │
│                                                                  │
│  spec:                                                          │
│    placement:                                                    │
│      gpu: { model: H100, count: 32 }                            │
│      affinity:                                                   │
│        - workload: training-data-pipeline                        │
│      reliability:                                                │
│        blastRadius: zone                                         │
│                                                                  │
│  No cluster specified. Workload enters "Unplaced" phase.         │
└──────────────────────┬───────────────────────────────────────────┘
                       │
         Planner reconciliation loop
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  Planner evaluates placement:                                    │
│                                                                  │
│  - Filter pools: which pools have H100 capability?               │
│  - Filter clusters: which clusters have H100 nodes with capacity?│
│  - Score candidates:                                             │
│    - Affinity: training-data-pipeline is on pool-a-001 → prefer  │
│    - Bin-packing: pool-a-001 has 8 free GPUs (need 32) → skip    │
│    - Bin-packing: pool-a has room for new cluster → score high   │
│  - Decision: create pool-a-003 with 32 H100 GPUs                │
│  - Push workload CRD to pool-a-003 via K8s API proxy             │
│  - Update management-side status: assigned_cluster = pool-a-003  │
└──────────────────────────────────────────────────────────────────┘
```

### Workload Deployment via API Proxy

```
┌───────────────────────────────────────────────────────────────────┐
│                    Management Cluster                              │
│                                                                   │
│  LatticeModel (submitted by developer)                            │
│    status:                                                        │
│      phase: Placed                                                │
│      assignedCluster: pool-a-003                                  │
│      assignedPool: gpu-training-us-east                           │
│                                                                   │
│  Capacity Planner ──── K8s API Proxy ──── gRPC stream ────┐      │
│                         (existing)         (outbound)      │      │
└────────────────────────────────────────────────────────────┼──────┘
                                                             │
                                                             ▼
┌───────────────────────────────────────────────────────────────────┐
│                    Child Cluster (pool-a-003)                     │
│                                                                   │
│  LatticeModel (pushed by planner)                                │
│    → Compiled by local Lattice operator                           │
│    → Volcano schedules pods with topology awareness               │
│    → GPU Operator provides H100 device access                     │
└───────────────────────────────────────────────────────────────────┘
```

The planner uses the same K8s API proxy that already exists for parent-to-child cluster communication. It creates the workload CRD on the target cluster via `POST /clusters/{name}/apis/lattice.dev/v1alpha1/...`. The child cluster's Lattice operator then compiles and runs the workload using existing controller logic.

The management-side workload CRD is retained as a placement record. Its status tracks which cluster the workload was pushed to and mirrors health from the child cluster.

## Detailed Design

### CRD: CapacityPool

```rust
/// CapacityPool declares a pool of cloud capacity available for workload placement.
///
/// Platform engineers create CapacityPool resources to register capacity that
/// the planner can draw from. Each pool references a InfraProvider for credentials
/// and declares resource limits, warm capacity, and hardware capabilities.
///
/// Example:
/// ```yaml
/// apiVersion: lattice.dev/v1alpha1
/// kind: CapacityPool
/// metadata:
///   name: gpu-training-us-east
/// spec:
///   providerRef: aws-prod
///   region: us-east-1
///   zones: [us-east-1a, us-east-1b]
///   limits:
///     maxGpus: 64
///     maxCpuCores: 512
///     maxMemoryGib: 2048
///   warmCapacity:
///     gpus: 16
///     cpuCores: 32
///   capabilities:
///     gpuModels: [H100]
///     interconnects: [nvlink, infiniband]
///   clusterTemplate:
///     controlPlane:
///       replicas: 3
///       instanceType: { name: m5.xlarge }
///     workerPoolTemplates:
///       gpu:
///         instanceType: { name: p5.48xlarge }
///         gpusPerNode: 8
///         gpuModel: H100
///         labels:
///           nvidia.com/gpu.product: NVIDIA-H100-80GB-HBM3
///         taints:
///           - key: nvidia.com/gpu
///             value: "true"
///             effect: NoSchedule
///       general:
///         instanceType: { name: m5.2xlarge }
/// ```
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "CapacityPool",
    plural = "capacitypools",
    shortname = "cp",
    status = "CapacityPoolStatus",
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Provider","type":"string","jsonPath":".spec.providerRef"}"#,
    printcolumn = r#"{"name":"Region","type":"string","jsonPath":".spec.region"}"#,
    printcolumn = r#"{"name":"Clusters","type":"integer","jsonPath":".status.clusterCount"}"#,
    printcolumn = r#"{"name":"GPUs","type":"string","jsonPath":".status.utilization.gpusAllocated"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct CapacityPoolSpec {
    /// Reference to a InfraProvider for credentials and account config.
    /// The InfraProvider must exist and be in Ready phase.
    pub provider_ref: String,

    /// Region for clusters created in this pool.
    /// Overrides the InfraProvider's region if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// Allowed availability zones within the region.
    /// When empty, the planner may use any zone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<String>,

    /// Resource limits for this pool. The planner will not provision
    /// clusters whose aggregate resources exceed these limits.
    pub limits: PoolResourceLimits,

    /// Minimum warm capacity to maintain even without workload demand.
    /// Warm clusters are kept provisioned and ready for fast placement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warm_capacity: Option<WarmCapacitySpec>,

    /// Budget ceiling for this pool. Placeholder for future cost tracking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<BudgetSpec>,

    /// Hardware capabilities available in this pool.
    /// Used for workload-to-pool matching.
    pub capabilities: PoolCapabilities,

    /// Template for clusters created by the planner in this pool.
    pub cluster_template: ClusterTemplate,

    /// Maximum number of clusters the planner may create in this pool.
    /// Guards against runaway cluster creation. Default: 10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_clusters: Option<u32>,

    /// Whether this pool is paused. Paused pools do not create new clusters
    /// but existing clusters continue operating.
    #[serde(default)]
    pub paused: bool,

    /// Labels applied to all LatticeCluster resources created from this pool.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}
```

### Supporting Types

```rust
/// Resource limits governing total capacity in a pool.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PoolResourceLimits {
    /// Maximum total GPU count across all clusters in this pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_gpus: Option<u32>,

    /// Maximum total CPU cores across all clusters in this pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cpu_cores: Option<u32>,

    /// Maximum total memory (GiB) across all clusters in this pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_memory_gib: Option<u32>,

    /// Maximum total worker nodes across all clusters in this pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_nodes: Option<u32>,
}

/// Minimum resources to keep provisioned at all times.
///
/// The planner maintains at least this much capacity in ready clusters,
/// even when no workloads are pending. This provides fast placement
/// for new workloads without waiting for cluster provisioning.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WarmCapacitySpec {
    /// Minimum GPUs to keep warm (provisioned and idle).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpus: Option<u32>,

    /// Minimum CPU cores to keep warm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_cores: Option<u32>,

    /// Minimum memory (GiB) to keep warm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_gib: Option<u32>,
}

/// Budget ceiling for the pool.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BudgetSpec {
    /// Monthly budget ceiling (e.g., "10000").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monthly_limit: Option<String>,

    /// Currency code (e.g., "USD"). Informational only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
}

/// Hardware capabilities available in a pool.
///
/// Used by the planner to match workload requirements to pools. A workload
/// that needs H100 GPUs will only be placed in pools that declare H100
/// in their gpu_models list.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PoolCapabilities {
    /// GPU models available in this pool (e.g., ["H100", "A100", "L4"]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gpu_models: Vec<String>,

    /// Interconnect types available (e.g., ["nvlink", "infiniband", "ethernet"]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interconnects: Vec<String>,

    /// Accelerator types beyond GPUs (e.g., ["tpu-v5", "inferentia2"]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accelerators: Vec<String>,
}
```

### Cluster Template

```rust
/// Template for clusters created by the planner.
///
/// The planner uses this template to generate LatticeCluster specs.
/// Worker pools are scaled dynamically — the template defines instance
/// types and node configuration, but replica counts are set by the planner.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ClusterTemplate {
    /// Kubernetes version for clusters in this pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes_version: Option<String>,

    /// Control plane configuration (replicas, instance type).
    pub control_plane: ControlPlaneSpec,

    /// Named worker pool templates. The planner creates worker pools
    /// matching these templates and scales their replica counts.
    pub worker_pool_templates: BTreeMap<String, WorkerPoolTemplate>,

    /// Enable GPU infrastructure on clusters in this pool.
    /// Auto-set to true when capabilities.gpu_models is non-empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<bool>,

    /// Enable LatticeService support on clusters in this pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services: Option<bool>,

    /// Network topology configuration for clusters in this pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_topology: Option<NetworkTopologyConfig>,

    /// Monitoring configuration override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitoring: Option<MonitoringConfig>,

    /// Provider-specific cluster configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_config: Option<ProviderConfig>,
}

/// Worker pool template used by the planner to create cluster worker pools.
///
/// Unlike WorkerPoolSpec (which has a fixed replica count), a template
/// defines the shape of nodes but lets the planner set replica counts.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkerPoolTemplate {
    /// Instance type for nodes in this pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_type: Option<InstanceType>,

    /// Number of GPUs per node in this pool. Used by the planner to
    /// calculate how many nodes are needed for a given GPU request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpus_per_node: Option<u32>,

    /// GPU model for nodes in this pool (e.g., "H100").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_model: Option<String>,

    /// Root volume configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_volume: Option<RootVolume>,

    /// Labels applied to nodes in this pool.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,

    /// Taints applied to nodes in this pool.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taints: Vec<NodeTaint>,

    /// Autoscaling bounds per cluster. The planner sets initial replicas;
    /// the cluster autoscaler scales within these bounds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autoscaling: Option<PoolAutoscalingBounds>,
}

/// Per-cluster autoscaling bounds for a worker pool template.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PoolAutoscalingBounds {
    /// Minimum nodes in this pool per cluster.
    pub min: u32,
    /// Maximum nodes in this pool per cluster.
    pub max: u32,
}
```

### CapacityPool Status

```rust
/// Status of a CapacityPool, updated by the capacity planner.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapacityPoolStatus {
    /// Current phase of the pool.
    #[serde(default)]
    pub phase: CapacityPoolPhase,

    /// Human-readable status message.
    #[serde(default)]
    pub message: Option<String>,

    /// Generation of the spec last reconciled.
    #[serde(default)]
    pub observed_generation: Option<i64>,

    /// Aggregate resource utilization across all clusters in this pool.
    #[serde(default)]
    pub utilization: PoolUtilization,

    /// Number of clusters currently managed by this pool.
    #[serde(default)]
    pub cluster_count: u32,

    /// Names of clusters managed by this pool.
    #[serde(default)]
    pub clusters: Vec<String>,

    /// Next cluster sequence number (monotonically increasing, never reused).
    #[serde(default)]
    pub next_cluster_seq: u32,

    /// Pending workload demand that cannot yet be satisfied.
    #[serde(default)]
    pub pending_demand: Option<PendingDemand>,

    /// Cost tracking (populated when budget integration is available).
    #[serde(default)]
    pub cost: Option<PoolCostStatus>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub enum CapacityPoolPhase {
    /// Pool is being validated (InfraProvider check).
    #[default]
    Pending,
    /// Pool is active and accepting workload placement.
    Ready,
    /// Pool is paused (no new clusters, existing continue).
    Paused,
    /// Pool has a configuration error.
    Failed,
}

/// Aggregate resource utilization across all clusters in this pool.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PoolUtilization {
    /// Total GPUs allocated (scheduled) across all clusters.
    #[serde(default)]
    pub gpus_allocated: u32,
    /// Total GPUs available (provisioned but not scheduled).
    #[serde(default)]
    pub gpus_available: u32,
    /// Total CPU cores allocated.
    #[serde(default)]
    pub cpu_cores_allocated: u32,
    /// Total CPU cores available.
    #[serde(default)]
    pub cpu_cores_available: u32,
    /// Total memory allocated (GiB).
    #[serde(default)]
    pub memory_gib_allocated: u32,
    /// Total memory available (GiB).
    #[serde(default)]
    pub memory_gib_available: u32,
    /// Total worker nodes across all clusters.
    #[serde(default)]
    pub total_nodes: u32,
    /// Total ready worker nodes across all clusters.
    #[serde(default)]
    pub ready_nodes: u32,
}

/// Pending demand that cannot be satisfied by current capacity.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PendingDemand {
    /// Number of workloads waiting for placement.
    #[serde(default)]
    pub workload_count: u32,
    /// Total GPUs requested by pending workloads.
    #[serde(default)]
    pub gpus_requested: u32,
    /// Total CPU cores requested by pending workloads.
    #[serde(default)]
    pub cpu_cores_requested: u32,
    /// Total memory (GiB) requested by pending workloads.
    #[serde(default)]
    pub memory_gib_requested: u32,
}

/// Cost tracking status (placeholder for future billing integration).
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PoolCostStatus {
    /// Estimated monthly cost at current utilization.
    #[serde(default)]
    pub estimated_monthly: Option<String>,
    /// Currency code.
    #[serde(default)]
    pub currency: Option<String>,
}
```

### Workload Placement Spec

A new `PlacementSpec` is added as an optional field to `LatticeServiceSpec`, `LatticeJobSpec`, and `LatticeModelSpec`. Workloads without it behave exactly as they do today (manual deployment to a specific cluster).

```rust
/// Workload placement preferences for the capacity planner.
///
/// When present on a workload submitted to the management cluster, the
/// capacity planner evaluates this spec to determine which CapacityPool
/// and cluster should host the workload. The planner then pushes the
/// workload CRD to the target cluster via the K8s API proxy.
///
/// When absent, the workload must be deployed to a specific cluster manually.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PlacementSpec {
    /// Preferred pool name(s). The planner tries these pools first.
    /// If empty, the planner considers all pools that match requirements.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pool_refs: Vec<String>,

    /// Required GPU model. Filters pools to those declaring this model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_model: Option<String>,

    /// Total GPU count needed for this workload (across all pods/tasks).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_count: Option<u32>,

    /// Co-placement affinity with other workloads.
    /// The planner prefers placing this workload in the same cluster
    /// as the referenced workloads. Soft constraint (best-effort).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affinity: Vec<WorkloadAffinityTerm>,

    /// Anti-affinity: avoid placing in the same cluster as these workloads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anti_affinity: Vec<WorkloadAffinityTerm>,

    /// Reliability and fault isolation requirements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reliability: Option<ReliabilitySpec>,

    /// Region preference. Overrides pool region selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// Zone preference. Limits placement to specific zones.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<String>,
}

/// Reference to another workload for affinity/anti-affinity.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadAffinityTerm {
    /// Name of the workload to co-place with.
    pub workload: String,
    /// Namespace of the workload (defaults to same namespace).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// Reliability and fault isolation requirements.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReliabilitySpec {
    /// Blast radius scope. Determines how workload replicas are spread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blast_radius: Option<BlastRadius>,

    /// Minimum availability target (e.g., "99.99").
    /// Informational for the planner; used for future SLO integration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub availability: Option<String>,
}

/// Blast radius scope for replica spreading.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum BlastRadius {
    /// Spread within a single cluster across nodes (default).
    Node,
    /// Spread across availability zones. May use clusters in different zones.
    Zone,
    /// Spread across regions. Requires pools in multiple regions.
    Region,
    /// Spread across cloud providers. Requires pools with different provider types.
    Provider,
}
```

### Adding Placement to Existing CRDs

```rust
// Added to LatticeServiceSpec, LatticeJobSpec, LatticeModelSpec:

/// Placement preferences for the capacity planner.
/// When set, the planner automatically assigns this workload to a cluster.
/// When absent, the workload must be deployed to a specific cluster.
#[serde(default, skip_serializing_if = "Option::is_none")]
pub placement: Option<PlacementSpec>,
```

Workload status types gain two new fields:

```rust
/// Cluster assigned by the capacity planner.
#[serde(default)]
pub assigned_cluster: Option<String>,

/// Pool that provided the cluster.
#[serde(default)]
pub assigned_pool: Option<String>,
```

### Capacity Planner Algorithm

The planner runs as a controller in the Lattice operator on the management cluster. It reconciles on changes to CapacityPool, LatticeCluster, and workload resources.

#### Reconciliation Phases

**Phase 1: Inventory Collection**

```rust
/// Snapshot of all capacity and demand in the system.
struct PlannerSnapshot {
    /// All CapacityPool resources indexed by name.
    pools: BTreeMap<String, CapacityPool>,

    /// All LatticeCluster resources grouped by pool.
    clusters_by_pool: BTreeMap<String, Vec<LatticeCluster>>,

    /// Manually-created clusters (no pool label).
    manual_clusters: Vec<LatticeCluster>,

    /// Unplaced workloads: have placement spec but no assigned_cluster.
    unplaced: Vec<WorkloadDemand>,

    /// Placed workloads grouped by cluster for utilization tracking.
    placed_by_cluster: BTreeMap<String, Vec<WorkloadDemand>>,
}

/// Normalized resource demand from a single workload.
struct WorkloadDemand {
    /// Workload kind (Service, Job, Model).
    kind: CrdKind,
    /// Workload name.
    name: String,
    /// Workload namespace.
    namespace: String,
    /// Placement spec from the workload.
    placement: PlacementSpec,
    /// Computed resource requirements.
    resources: DemandResources,
}

/// Computed resource requirements for a workload.
struct DemandResources {
    /// Total GPUs needed.
    gpus: u32,
    /// GPU model required.
    gpu_model: Option<String>,
    /// Total CPU cores.
    cpu_cores: u32,
    /// Total memory (GiB).
    memory_gib: u32,
}
```

**Phase 2: Pool Matching**

For each unplaced workload, filter eligible pools:

```rust
fn filter_eligible_pools(
    demand: &WorkloadDemand,
    pools: &BTreeMap<String, CapacityPool>,
) -> Vec<String> {
    pools.iter()
        .filter(|(_, pool)| {
            !pool.spec.paused
            && demand.resources.gpu_model.as_ref().map_or(true, |model|
                pool.spec.capabilities.gpu_models.contains(model)
            )
            && demand.placement.region.as_ref().map_or(true, |r|
                pool.spec.region.as_ref() == Some(r)
            )
            && (demand.placement.zones.is_empty()
                || demand.placement.zones.iter().any(|z| pool.spec.zones.contains(z)))
            && (demand.placement.pool_refs.is_empty()
                || demand.placement.pool_refs.iter().any(|p|
                    pool.name_any() == *p
                ))
            && has_headroom(pool, &demand.resources)
        })
        .map(|(name, _)| name.clone())
        .collect()
}
```

**Phase 3: Cluster Selection (Best-Fit Scoring)**

```rust
/// Placement decision made by the planner.
enum PlacementDecision {
    /// Place workload in an existing cluster.
    ExistingCluster { cluster_name: String, pool: String },
    /// Create a new cluster in the pool, then place once ready.
    NewCluster { pool: String },
    /// Cannot place: no eligible pool or all pools at capacity.
    Unplaceable { reason: String },
}

/// Score a candidate cluster for a workload. Higher is better.
fn score_cluster(
    cluster: &LatticeCluster,
    demand: &WorkloadDemand,
    placed_workloads: &[WorkloadDemand],
) -> i64 {
    let mut score: i64 = 0;

    // Capacity fit: cluster has enough free resources
    let free_gpus = cluster_free_gpus(cluster, placed_workloads);
    if free_gpus < demand.resources.gpus {
        return -1; // does not fit
    }
    score += 100;

    // Affinity: co-place with specified workloads
    for affinity in &demand.placement.affinity {
        if placed_workloads.iter().any(|w| w.name == affinity.workload) {
            score += 50;
        }
    }

    // Anti-affinity: avoid clusters with specified workloads
    for anti in &demand.placement.anti_affinity {
        if placed_workloads.iter().any(|w| w.name == anti.workload) {
            score -= 1000;
        }
    }

    // Bin-packing: prefer fuller clusters (minimize waste)
    let utilization_pct = cluster_utilization_pct(cluster, placed_workloads);
    score += utilization_pct as i64;

    score
}
```

**Phase 4: Cluster Lifecycle**

```
Create:
  - Generate LatticeCluster from pool's ClusterTemplate
  - Name: {pool-name}-{seq} (seq from pool status, monotonically increasing)
  - Labels: lattice.dev/capacity-pool={pool}, lattice.dev/managed-by=capacity-planner
  - Owner reference to CapacityPool
  - Worker pool replicas sized by demand + autoscaling bounds from template

Scale:
  - Patch WorkerPoolSpec.replicas on existing LatticeCluster
  - Stay within pool limits and per-cluster autoscaling bounds

Drain:
  - When a cluster has no placed workloads for 30 minutes
  - AND the pool is above warm capacity floor
  - Delete the LatticeCluster (existing cleanup flow handles infrastructure)
```

**Phase 5: Warm Capacity**

```rust
fn reconcile_warm_capacity(
    pool: &CapacityPool,
    clusters: &[LatticeCluster],
) -> Vec<ClusterAction> {
    let mut actions = Vec::new();
    let current = aggregate_available_resources(clusters);

    if let Some(ref warm) = pool.spec.warm_capacity {
        if let Some(target_gpus) = warm.gpus {
            if current.available_gpus < target_gpus {
                let deficit = target_gpus - current.available_gpus;
                let gpus_per_cluster = pool_gpus_per_cluster(pool);
                let clusters_needed = deficit.div_ceil(gpus_per_cluster);
                for _ in 0..clusters_needed {
                    actions.push(ClusterAction::Create);
                }
            }
        }
        // Same pattern for cpu_cores and memory_gib
    }

    actions
}
```

**Phase 6: Workload Push**

After the planner selects a target cluster:

```rust
async fn push_workload(
    proxy: &KubeApiProxy,
    cluster_name: &str,
    workload: &WorkloadDemand,
    original_manifest: &serde_json::Value,
) -> Result<()> {
    // Strip the placement field from the pushed copy (the child cluster
    // doesn't need it — it's a placement directive for the management cluster)
    let mut manifest = original_manifest.clone();
    manifest["spec"].as_object_mut()
        .map(|spec| spec.remove("placement"));

    // Push to target cluster via existing K8s API proxy
    proxy.create(cluster_name, &manifest).await?;

    Ok(())
}
```

The management-side workload retains its placement spec and tracks status:

```yaml
status:
  phase: Placed
  assignedCluster: gpu-training-us-east-003
  assignedPool: gpu-training-us-east
```

### Multi-Pool Reliability (Blast Radius)

```
blast_radius: node
  → Default. All replicas in one cluster. Kubernetes pod anti-affinity
    handles node spread.

blast_radius: zone
  → Planner creates/uses clusters in different zones within the same pool.
    Stateless services: replicas split across zonal clusters.
    Jobs/models: entire workload in one zone (gang scheduling requires it).

blast_radius: region
  → Planner places replicas across pools in different regions.
    Only applicable to stateless LatticeService workloads.

blast_radius: provider
  → Planner places replicas across pools backed by different InfraProvider types.
    Only applicable to stateless LatticeService workloads.
```

Jobs and Models require gang scheduling and cannot be split across clusters. `blast_radius` above `node` is rejected at admission for these workload types.

### Naming Convention

Clusters created by the planner:

```
{pool-name}-{seq}

Example: gpu-training-us-east-001, gpu-training-us-east-002
```

The sequence number monotonically increases per pool (tracked in `status.next_cluster_seq`). Deleted cluster names are not reused to avoid CAPI namespace collisions.

### CRD Relationships

```
InfraProvider (existing, unchanged)
     │
     │ credentials + account config
     ▼
CapacityPool (NEW, cluster-scoped)
     │
     │ creates / owns (ownerReference)
     ▼
LatticeCluster (existing, unchanged — now also auto-created)
     │
     │ provisions via CAPI (existing pipeline)
     ▼
Running Cluster
     ▲
     │ workloads pushed via K8s API proxy
     │
LatticeService / LatticeJob / LatticeModel (new optional placement field)

Manual escape hatch:
  Users CAN still create LatticeCluster directly.
  Users CAN still deploy workloads to specific clusters directly.
  The planner ignores clusters without the capacity-pool label.
  The planner ignores workloads without the placement field.
```

## Implementation Plan

### Phase 1: CRD Types

**Crate: `lattice-common`**

- Add `crd/capacity_pool.rs` with `CapacityPoolSpec`, `CapacityPoolStatus`, and all supporting types
- Add `crd/workload/placement.rs` with `PlacementSpec`, `WorkloadAffinityTerm`, `ReliabilitySpec`, `BlastRadius`
- Add `placement: Option<PlacementSpec>` to `LatticeServiceSpec`, `LatticeJobSpec`, `LatticeModelSpec`
- Add `assigned_cluster` and `assigned_pool` to workload status types
- Register `CapacityPool` in `crd/mod.rs` and `CrdKind` enum

### Phase 2: Planner Controller Skeleton

**New crate: `lattice-capacity`**

- Controller watching CapacityPool and workload CRDs
- Validate CapacityPool specs (InfraProvider exists and is Ready, limits are consistent)
- Set CapacityPool phase to Ready when validated
- `PlannerSnapshot` construction from cluster state
- Aggregate utilization calculation and CapacityPool status updates

### Phase 3: Pool Matching and Cluster Creation

**Crate: `lattice-capacity`**

- `WorkloadDemand` extraction from workload CRDs
- Pool filtering (capability, region, zone, headroom matching)
- Best-fit scoring for existing clusters
- `ClusterTemplate` → `LatticeClusterSpec` conversion
- New cluster creation when no existing cluster fits
- Owner references from CapacityPool to created LatticeClusters

### Phase 4: Workload Push

**Crate: `lattice-capacity`**

- Push workload CRDs to target clusters via K8s API proxy
- Strip placement field from pushed copy
- Update management-side workload status (assigned_cluster, assigned_pool)
- Health mirroring from child cluster workload status

### Phase 5: Warm Capacity and Drain

**Crate: `lattice-capacity`**

- Warm capacity reconciliation (ensure minimum resources provisioned)
- Drain detection (cluster empty for configurable timeout)
- Cluster deletion for drained clusters (respects warm floor)
- Worker pool scaling (patch replicas on existing clusters)

### Phase 6: Blast Radius

**Crate: `lattice-capacity`**

- Multi-zone placement for `blast_radius: zone` (LatticeService only)
- Multi-region and multi-provider placement
- Admission validation rejecting `blast_radius > node` for Jobs/Models

### Phase 7: Testing

**Unit tests in `lattice-capacity`:**

- Pool filtering correctness (GPU model, region, zone, headroom)
- Cluster scoring (affinity, anti-affinity, bin-packing)
- ClusterTemplate → LatticeClusterSpec conversion
- Warm capacity deficit calculation
- Drain detection logic

**Integration tests:**

- Create CapacityPool → verify LatticeCluster created
- Submit workload with placement → verify pushed to cluster
- Warm capacity → clusters pre-provisioned
- Scale up → new cluster created when existing full
- Scale down → empty cluster drained

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Runaway cluster creation (cost) | `max_clusters` hard limit per pool; `paused` field for emergency stop; pool resource limits cap aggregate capacity |
| Placement scoring too naive | Start with best-fit score-based; algorithm is isolated in pure functions, easy to swap; add histogram metrics on placement latency and score distribution |
| Demand extraction imprecise (unit mismatches) | Normalize all units in `WorkloadDemand` construction; conservative estimates (round up) |
| Cluster provisioning latency (10-30 min) | Warm capacity ensures pre-provisioned clusters; status shows pending demand so users understand the wait |
| Planner vs cluster autoscaler conflict | Clear split: planner manages cluster count and initial worker pool size; autoscaler manages node count within template bounds |
| Pool deletion with active clusters | Finalizer prevents deletion while clusters exist; status shows cluster count |
| Gang-scheduled workloads with blast_radius > node | Admission validation rejects invalid combinations |
| Multiple planners racing | Single controller with leader election (existing operator pattern); optimistic concurrency via `observedGeneration` |
| Workload status sync between management and child | Periodic polling via K8s API proxy; stale status is acceptable (eventually consistent) |
