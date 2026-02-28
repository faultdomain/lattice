# Network Topology-Aware Scheduling

## Problem

Distributed GPU workloads (training jobs, disaggregated inference) are highly sensitive to inter-node network topology. Two H100 nodes under the same Top-of-Rack (ToR) switch communicate over NVLink/InfiniBand at 400 Gb/s, while nodes across spine switches may only achieve 100 Gb/s. A naive scheduler that ignores topology can place workers across switch boundaries, degrading collective operations (AllReduce, AllGather) by 2-4x and wasting GPU-hours on communication stalls.

Volcano v1.13+ provides network topology-aware scheduling via HyperNode CRDs, but Lattice doesn't use it. The `network_topology` field in `ModelServingSpec` is a `Option<serde_json::Value>` placeholder set to `None`. The current Volcano scheduler config enables `gang`, `deviceshare`, `binpack`, and `nodeorder` — but not `network-topology-aware`.

## Goals

- Enable Volcano's `network-topology-aware` scheduler plugin in Lattice-managed clusters
- Automatic HyperNode discovery for InfiniBand (UFM) and label-based topologies
- Typed `NetworkTopology` spec on all workload CRDs: `LatticeService`, `LatticeModel`, `LatticeTrainingJob`, `LatticeJob`
- Support both hard (strict) and soft (best-effort) topology constraints
- Integrate with existing GPU node pools and NFD labels
- Generic enough for non-GPU use cases (high-performance storage, low-latency data pipelines)

## Non-Goals

- Custom scheduler implementation (we use Volcano's built-in plugin)
- Multi-cluster topology (topology is per-cluster)
- Application-level topology awareness (NCCL handles intra-job communication; we handle placement)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Physical Network                            │
│                                                                 │
│              ┌──── Spine Switch (tier 3) ────┐                  │
│              │                               │                  │
│        ┌─ ToR-0 (tier 2) ─┐          ┌─ ToR-1 (tier 2) ─┐     │
│        │                   │          │                   │     │
│   ┌─ Leaf-0 ─┐       ┌─ Leaf-1 ─┐  ┌─ Leaf-2 ─┐   ┌─ Leaf-3 ─┐
│   │ (tier 1) │       │ (tier 1) │  │ (tier 1) │   │ (tier 1) │
│   │          │       │          │  │          │   │          │
│   node-0  node-1   node-2  node-3  node-4  node-5  node-6  node-7
│   H100×8  H100×8   H100×8  H100×8  H100×8  H100×8  H100×8  H100×8
└─────────────────────────────────────────────────────────────────┘
                             │
            Volcano HyperNode discoverer maps this to:
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    HyperNode Tree (CRDs)                        │
│                                                                 │
│                    spine-0 (tier: 3)                             │
│                   ╱              ╲                               │
│            tor-0 (tier: 2)    tor-1 (tier: 2)                   │
│           ╱         ╲         ╱         ╲                       │
│     leaf-0 (1)  leaf-1 (1)  leaf-2 (1)  leaf-3 (1)             │
│     ╱    ╲      ╱    ╲      ╱    ╲      ╱    ╲                 │
│   n-0  n-1   n-2  n-3   n-4  n-5   n-6  n-7                   │
└─────────────────────────────────────────────────────────────────┘
                             │
            Training job requests: highestTierAllowed: 2
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│               Scheduling Decision                               │
│                                                                 │
│  Job needs 4 nodes × 8 GPUs = 32 GPUs                          │
│  highestTierAllowed: 2 → must fit under a single ToR            │
│  tor-0 has 4 nodes → schedule {node-0, node-1, node-2, node-3} │
│  All workers communicate via ToR-0 at full bandwidth            │
└─────────────────────────────────────────────────────────────────┘
```

## Detailed Design

### Step 1: Enable Scheduler Plugin

The Volcano scheduler ConfigMap in `build.rs` needs the `network-topology-aware` plugin added to the scoring tier:

**Current config** (build.rs lines 680-706):
```yaml
actions: "enqueue, allocate, backfill"
tiers:
- plugins:
  - name: priority
  - name: gang
  - name: conformance
- plugins:
  - name: drf
  - name: deviceshare
    arguments:
      deviceshare.VGPUEnable: true
  - name: predicates
  - name: proportion
  - name: nodeorder
  - name: binpack
```

**Updated config:**
```yaml
actions: "enqueue, allocate, backfill"
tiers:
- plugins:
  - name: priority
  - name: gang
  - name: conformance
- plugins:
  - name: drf
  - name: deviceshare
    arguments:
      deviceshare.VGPUEnable: true
  - name: predicates
  - name: proportion
  - name: nodeorder
  - name: binpack
  - name: network-topology-aware
```

The plugin is a no-op when no HyperNodes exist and no jobs specify `networkTopology`, so it's safe to enable unconditionally.

### Step 2: HyperNode Discovery

Lattice supports three discovery modes, configured per-cluster in `LatticeClusterSpec`:

#### Mode A: UFM Discovery (InfiniBand Clusters)

For clusters with Unified Fabric Manager (common in HPC/AI GPU clusters with InfiniBand):

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: gpu-cluster
spec:
  gpu: true
  networkTopology:
    discovery:
      source: ufm
      interval: 10m
      ufm:
        endpoint: https://ufm-server:8080
        credentialSecretRef: ufm-credentials
        insecureSkipVerify: false
```

The controller generates the Volcano controller ConfigMap entry:

```yaml
networkTopologyDiscovery:
  - source: ufm
    enabled: true
    interval: 10m
    credentials:
      secretRef:
        name: ufm-credentials
        namespace: volcano-system
    config:
      endpoint: https://ufm-server:8080
      insecureSkipVerify: false
```

UFM automatically discovers the full switch fabric and creates HyperNode CRDs representing the physical network topology. No manual node labeling required.

#### Mode B: Label Discovery (Generic Topology)

For clusters without UFM (cloud instances, PCIe-only clusters), topology is inferred from node labels. Lattice auto-generates topology labels from worker pool configuration:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: cloud-gpu-cluster
spec:
  gpu: true
  networkTopology:
    discovery:
      source: label
      interval: 10m
      label:
        tiers:
          - nodeLabel: "topology.kubernetes.io/zone"     # tier 2: availability zone
          - nodeLabel: "kubernetes.io/hostname"           # tier 1: individual node
```

For cloud providers, Lattice can auto-configure label tiers based on `InfraProvider`:

| Provider | Tier 3 | Tier 2 | Tier 1 |
|----------|--------|--------|--------|
| AWS | `topology.kubernetes.io/region` | `topology.kubernetes.io/zone` | `kubernetes.io/hostname` |
| GCP | `topology.kubernetes.io/region` | `topology.kubernetes.io/zone` | `kubernetes.io/hostname` |
| Proxmox | — | `volcano.sh/rack` (from pool labels) | `kubernetes.io/hostname` |
| OpenStack | — | `topology.kubernetes.io/zone` | `kubernetes.io/hostname` |

#### Mode C: Manual HyperNodes

For custom topologies (lab environments, non-standard switch fabrics), users create HyperNode CRDs directly. Lattice doesn't manage them but the scheduler plugin still uses them.

### Step 3: CRD Types

#### NetworkTopology on LatticeCluster

```rust
/// Network topology configuration for a cluster.
pub struct NetworkTopologyConfig {
    /// Discovery mode for building the HyperNode tree.
    pub discovery: Option<TopologyDiscoverySpec>,
}

pub struct TopologyDiscoverySpec {
    /// Discovery source type.
    pub source: TopologySource,

    /// How often to re-discover topology.
    pub interval: Option<String>,  // default: "10m"

    /// UFM-specific configuration.
    pub ufm: Option<UfmDiscoveryConfig>,

    /// Label-based discovery configuration.
    pub label: Option<LabelDiscoveryConfig>,
}

pub enum TopologySource {
    Ufm,
    Label,
    Manual,  // no discovery, user manages HyperNodes
}

pub struct UfmDiscoveryConfig {
    /// UFM API endpoint.
    pub endpoint: String,

    /// Secret containing UFM credentials (username/password keys).
    pub credential_secret_ref: String,

    /// Skip TLS verification for UFM endpoint.
    pub insecure_skip_verify: bool,  // default: false
}

pub struct LabelDiscoveryConfig {
    /// Ordered list of node labels forming the topology tiers.
    /// First entry = highest tier (spine), last = lowest (leaf/node).
    pub tiers: Vec<LabelTier>,
}

pub struct LabelTier {
    /// Node label key used to group nodes at this tier.
    pub node_label: String,
}
```

#### NetworkTopology on Workloads

Replace the `Option<serde_json::Value>` placeholder with a typed struct, shared across all workload CRDs: `LatticeService`, `LatticeModel`, `LatticeTrainingJob`, and `LatticeJob`:

```rust
/// Network topology scheduling constraints for a workload.
pub struct WorkloadNetworkTopology {
    /// Scheduling mode.
    /// - Hard: all pods must be within highestTierAllowed (job pends if impossible)
    /// - Soft: scheduler prefers co-placement but allows cross-tier if necessary
    pub mode: TopologyMode,

    /// Maximum tier level for pod placement (hard mode only).
    /// Lower values = tighter placement (better bandwidth).
    /// Example: tier 1 = same leaf switch, tier 2 = same ToR, tier 3 = same spine
    pub highest_tier_allowed: Option<u32>,
}

pub enum TopologyMode {
    Hard,  // strict constraint, job pends if unsatisfiable
    Soft,  // best-effort, scheduler scores topology but doesn't block
}
```

This type is added to `LatticeServiceSpec`, `LatticeModelSpec`, `LatticeTrainingJobSpec`, and `LatticeJobSpec` as `topology: Option<WorkloadNetworkTopology>`. It defaults to `None` on all workloads — topology-aware scheduling is always opt-in.

### Step 4: Compilation Changes

#### Volcano VCJob NetworkTopology Field

The existing `network_topology: Option<serde_json::Value>` in `ModelServingSpec` and the VCJob spec gets populated from the typed CRD:

```rust
// In training job compiler and model serving compiler:
fn compile_network_topology(spec: &WorkloadNetworkTopology) -> serde_json::Value {
    let mut topo = serde_json::Map::new();
    topo.insert("mode".into(), match spec.mode {
        TopologyMode::Hard => "hard".into(),
        TopologyMode::Soft => "soft".into(),
    });
    if let Some(tier) = spec.highest_tier_allowed {
        topo.insert("highestTierAllowed".into(), tier.into());
    }
    serde_json::Value::Object(topo)
}
```

This produces the Volcano-native format:

```yaml
spec:
  networkTopology:
    mode: hard
    highestTierAllowed: 2
```

#### NCCL Auto-Tuning from Topology

When topology is configured, the training job compiler can make smarter NCCL decisions:

| Constraint | NCCL Impact |
|-----------|-------------|
| `highest_tier_allowed: 1` (same leaf) | `NCCL_NET=IB`, `NCCL_IB_DISABLE=0`, NVSwitch likely available |
| `highest_tier_allowed: 2` (same ToR) | `NCCL_NET=IB`, cross-node but same rack bandwidth |
| `highest_tier_allowed: 3` (same spine) | `NCCL_ALGO=Ring` preferred (tree less efficient across spines) |
| `mode: soft` (no guarantee) | Conservative defaults, `NCCL_ALGO=Ring`, no GDR assumption |

### Step 5: Infrastructure Bootstrap

The cluster controller adds topology discovery configuration to the Volcano controller ConfigMap during bootstrap:

```rust
// In bootstrap/volcano.rs or bootstrap/mod.rs

pub fn generate_topology_discovery_config(
    cluster: &LatticeClusterSpec,
) -> Option<String> {
    let topo = cluster.network_topology.as_ref()?;
    let discovery = topo.discovery.as_ref()?;

    match discovery.source {
        TopologySource::Ufm => {
            let ufm = discovery.ufm.as_ref()?;
            Some(format!(r#"
networkTopologyDiscovery:
  - source: ufm
    enabled: true
    interval: {interval}
    credentials:
      secretRef:
        name: {secret}
        namespace: volcano-system
    config:
      endpoint: {endpoint}
      insecureSkipVerify: {insecure}
"#,
                interval = discovery.interval.as_deref().unwrap_or("10m"),
                secret = ufm.credential_secret_ref,
                endpoint = ufm.endpoint,
                insecure = ufm.insecure_skip_verify,
            ))
        }
        TopologySource::Label => {
            let label = discovery.label.as_ref()?;
            // Build label topology type config
            // ...
        }
        TopologySource::Manual => None,  // no discovery config needed
    }
}
```

### Step 6: Auto-Configuration for Cloud Providers

When `networkTopology.discovery` is omitted but `gpu: true`, Lattice can auto-configure label-based discovery using provider-specific topology labels. This is opt-in via a convenience default:

```rust
impl Default for NetworkTopologyConfig {
    fn default() -> Self {
        // No topology by default; must be explicitly enabled
        Self { discovery: None }
    }
}

// In cluster controller, when gpu=true and no explicit topology config:
fn auto_topology_for_provider(provider: &InfraProvider) -> Option<TopologyDiscoverySpec> {
    match provider {
        InfraProvider::Aws => Some(TopologyDiscoverySpec {
            source: TopologySource::Label,
            interval: Some("10m".into()),
            ufm: None,
            label: Some(LabelDiscoveryConfig {
                tiers: vec![
                    LabelTier { node_label: "topology.kubernetes.io/zone".into() },
                    LabelTier { node_label: "kubernetes.io/hostname".into() },
                ],
            }),
        }),
        // Similar for GCP, OpenStack, Proxmox
        _ => None,
    }
}
```

## Integration with Training Jobs

The `LatticeTrainingJob` CRD from the [training jobs design](training-jobs.md) gets a `topology` field:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeTrainingJob
metadata:
  name: llama-70b-pretraining
spec:
  framework: PyTorch
  topology:
    mode: hard
    highestTierAllowed: 2    # all workers under same ToR switch
  roles:
    master:
      replicas: 1
      workload:
        containers:
          training:
            image: nvcr.io/nvidia/pytorch:24.01-py3
        resources:
          gpu:
            type: gpu
            params:
              count: 8
              model: H100
    worker:
      replicas: 7
      workload:
        containers:
          training:
            image: nvcr.io/nvidia/pytorch:24.01-py3
        resources:
          gpu:
            type: gpu
            params:
              count: 8
              model: H100
  checkpoint:
    interval: 30m
    store_ref: s3-checkpoints
```

The training job compiler combines topology with NCCL auto-tuning: `highestTierAllowed: 2` + `model: H100` produces NCCL env vars optimized for intra-rack InfiniBand communication.

## Integration with Model Serving

The `LatticeModel` CRD's existing `network_topology` placeholder becomes typed:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeModel
metadata:
  name: llm-serving
spec:
  topology:
    mode: soft              # best-effort for serving (availability > locality)
    highestTierAllowed: 2
  roles:
    prefill:
      replicas: 2
      ...
    decode:
      replicas: 4
      ...
  routing:
    kv_connector:
      type: nixl            # PD disaggregation benefits from locality
```

For disaggregated inference with KV-cache transfer (nixl/mooncake/lmcache), topology-aware placement is critical — prefill and decode roles transfer KV-cache over the network, and cross-spine transfers dominate latency.

### Auto-Topology for P/D Disaggregation

When a `LatticeModel` specifies a `kv_connector` but no explicit `topology`, the model serving compiler automatically injects a sensible default. KV-cache transfer bandwidth directly determines disaggregated inference throughput — without topology constraints, the scheduler may place prefill and decode pods across spine boundaries, negating the latency benefits of disaggregation entirely.

**Compiler logic:**

```rust
fn resolve_topology(spec: &LatticeModelSpec) -> Option<WorkloadNetworkTopology> {
    // Explicit topology always wins
    if spec.topology.is_some() {
        return spec.topology.clone();
    }

    // Auto-inject topology when kv_connector is configured
    let routing = spec.routing.as_ref()?;
    let connector = routing.kv_connector.as_ref()?;

    let tier = match connector.type_ {
        // nixl uses GPU Direct RDMA — needs same-rack InfiniBand
        KvConnectorType::Nixl => 2,
        // mooncake uses TCP — still benefits from locality but tolerates cross-rack
        KvConnectorType::Mooncake => 3,
        // lmcache uses shared memory or TCP — same-rack preferred
        KvConnectorType::Lmcache => 2,
    };

    Some(WorkloadNetworkTopology {
        mode: TopologyMode::Soft,  // soft: availability > strict locality for serving
        highest_tier_allowed: Some(tier),
    })
}
```

**Why soft mode:** Serving workloads prioritize availability over strict placement. If tier-2 capacity is exhausted, it's better to serve requests with higher P/D latency than to leave pods pending. The scheduler still _prefers_ co-placement via scoring — soft mode just doesn't block scheduling when the ideal topology is unavailable.

**Why the tier varies by connector type:**

| Connector | Transport | Tier | Rationale |
|-----------|-----------|------|-----------|
| nixl | GPU Direct RDMA (InfiniBand) | 2 (same ToR) | RDMA performance degrades sharply across ToR boundaries; GDR requires same-fabric connectivity |
| mooncake | TCP with zero-copy | 3 (same spine) | TCP tolerates cross-rack hops better than RDMA; still benefits from reduced hop count |
| lmcache | Shared memory / TCP | 2 (same ToR) | Shared memory requires same-node; TCP fallback benefits from same-rack |

**User override:** If the auto-injected topology is too tight or too loose, users set `topology` explicitly and the auto-logic is skipped entirely. The auto-default is documented in the CRD field description so users understand the implicit behavior.

**Status visibility:** When the compiler auto-injects topology, it records this in the LatticeModel status:

```rust
pub struct LatticeModelStatus {
    // ... existing fields ...
    /// Indicates topology was auto-configured due to kv_connector presence.
    pub auto_topology: Option<WorkloadNetworkTopology>,
}
```

This makes the implicit behavior observable — operators can `kubectl get latticemodel -o yaml` and see exactly what topology constraint was applied.

## Integration with Services

`LatticeService` also supports `topology` for long-running workloads where inter-pod network locality matters. This is opt-in — services default to no topology constraint, and the service compiler only generates Volcano scheduling annotations when `topology` is explicitly set.

**Use cases:**

| Workload | Why Topology Matters |
|----------|---------------------|
| Distributed storage (Ceph, MinIO) | Replication traffic between OSDs; cross-rack replication doubles write latency |
| Real-time data pipelines (Kafka, Flink) | Partition replication and shuffle traffic; locality reduces tail latency |
| In-memory caches (Redis Cluster, Dragonfly) | Cluster gossip and replication; cross-spine adds 1-2ms per hop |
| Tightly-coupled microservices | Synchronous RPC chains where cumulative latency matters |

**Example: Distributed storage cluster**

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: minio-cluster
spec:
  replicas: 4
  topology:
    mode: soft
    highestTierAllowed: 2    # prefer same rack for replication traffic
  workload:
    containers:
      minio:
        image: minio/minio:latest
        command: ["minio", "server", "--console-address", ":9001"]
    resources:
      data-volume:
        type: volume
        params:
          size: "500Gi"
          accessMode: ReadWriteOnce
```

**Compiler behavior for services:**

LatticeService currently compiles to a Kubernetes Deployment (via the service compiler). To support topology-aware scheduling, services with a `topology` field switch their scheduler to Volcano:

```rust
fn compile_service_deployment(spec: &LatticeServiceSpec) -> Deployment {
    let mut deployment = build_base_deployment(spec);

    if let Some(topo) = &spec.topology {
        // Use Volcano scheduler instead of default-scheduler
        deployment.spec.template.spec.scheduler_name = Some("volcano".into());

        // Create a PodGroup with networkTopology constraints
        // Volcano's PodGroup-level topology applies to all pods in the group
    }

    deployment
}
```

When `topology` is set, the service compiler generates:

- A Volcano `PodGroup` with `networkTopology` constraints matching the service's `topology` spec
- The Deployment's pod template references the PodGroup via `scheduling.volcano.sh/group-name` annotation
- `schedulerName: volcano` on the pod template

When `topology` is `None` (the default), the service compiles exactly as it does today — standard Kubernetes scheduler, no PodGroup, no Volcano dependency. This keeps the common case simple and avoids pulling in Volcano for services that don't need it.

## Implementation Order

This feature is the foundational primitive that other designs build on. It should be implemented first, before training jobs or inference gateway.

**Dependency graph:**

```
Network Topology Scheduling (this doc)
  ├── Training Jobs (training-jobs.md)
  │     └── uses topology for NCCL auto-tuning + worker placement
  ├── Model Serving (existing LatticeModel)
  │     └── uses topology for P/D disaggregation placement
  ├── Inference Gateway (inference-gateway.md)
  │     └── fronts topology-aware model deployments
  └── GPU Observability (gpu-observability.md)
        └── independent, can be implemented in parallel
```

**Recommended implementation sequence:**

- **Phase 1: Network Topology Scheduling** — scheduler plugin, CRD types, discovery, compilation for LatticeModel and LatticeService
- **Phase 2 (parallel):** GPU Observability — independent, no dependency on topology
- **Phase 3: Training Jobs** — builds on topology types and Volcano integration from Phase 1
- **Phase 4: Inference Gateway** — builds on model serving improvements from Phases 1 and 3

## Implementation Plan

### Step 1: Scheduler Plugin (lattice-infra)

- Add `network-topology-aware` to Volcano scheduler config in `build.rs`
- No-op when no HyperNodes exist, safe to enable unconditionally

### Step 2: CRD Types (lattice-common)

- Add `NetworkTopologyConfig` to `LatticeClusterSpec`
- Add `WorkloadNetworkTopology` as shared type in `crd/workload/`
- Replace `network_topology: Option<serde_json::Value>` in model serving types with `topology: Option<WorkloadNetworkTopology>`
- Add `topology: Option<WorkloadNetworkTopology>` to `LatticeServiceSpec`, `LatticeTrainingJobSpec`, and `LatticeJobSpec`

### Step 3: Discovery Config (lattice-infra)

- Generate Volcano controller ConfigMap entries for UFM and label discovery
- Conditional on `LatticeClusterSpec.network_topology.discovery`
- Auto-configuration for cloud providers when `gpu: true`

### Step 4: Compilation — Model Serving (lattice-volcano)

- Update ModelServing compiler to populate `networkTopology` from typed spec
- Implement auto-topology injection for P/D disaggregation (kv_connector present, no explicit topology)
- Record auto-injected topology in LatticeModel status

### Step 5: Compilation — Services (lattice-service)

- When `topology` is set, switch scheduler to Volcano and generate PodGroup with `networkTopology`
- When `topology` is `None`, compile as today (no Volcano, no PodGroup)

### Step 6: Compilation — Jobs (lattice-volcano)

- Update VCJob compiler to populate `networkTopology` from typed spec
- Wire topology tier into NCCL auto-tuning for training jobs (when `LatticeTrainingJob` is implemented)

### Step 7: Mesh Integration (lattice-infra)

- Add LatticeMeshMember for Volcano controller to access UFM endpoint (if UFM discovery enabled)
- UFM credential Secret must be in `volcano-system` namespace

### Step 8: Testing

- Unit test: topology config compilation to Volcano-native format
- Unit test: auto-topology injection for kv_connector models
- Unit test: service compiler generates PodGroup only when topology is set
- Integration test: HyperNode creation via label discovery on existing cluster
- Integration test: VCJob with `networkTopology.mode: hard` schedules only on correct nodes
- Integration test: LatticeService with topology uses Volcano scheduler

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| HyperNode discovery requires Volcano controller restart | Volcano controller watches its ConfigMap; changes trigger reload without restart |
| UFM endpoint unavailable causes stale topology | Discovery interval is periodic; stale HyperNodes still valid for scheduling; add status condition when discovery fails |
| Hard mode causes jobs to pend indefinitely | Document that hard mode requires sufficient nodes under a single HyperNode; recommend soft mode for smaller clusters |
| Label-based discovery is coarse compared to UFM | Document that label discovery only captures zone/rack boundaries, not switch-level topology; recommend UFM for InfiniBand clusters |
| Plugin adds scheduling latency | Plugin only scores nodes with HyperNode membership; nodes without HyperNodes are scored neutrally; minimal overhead measured by Volcano team |
| Breaking change to network_topology field type | Current field is `Option<serde_json::Value>` set to `None` everywhere; replacing with typed struct is backwards-compatible since no user data exists |
| Volcano as scheduler for services adds complexity | Only activated when `topology` is explicitly set; default path unchanged; PodGroup is the only addition |
