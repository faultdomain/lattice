# Training Job Orchestration

## Problem

Lattice has batch jobs (LatticeJob via Volcano VCJob) and model serving (LatticeModel via Volcano ModelServing), but no first-class distributed training primitive. The gap between "run a batch job" and "run a multi-node PyTorch DDP training run with checkpointing and fault tolerance" is where ML teams burn weeks of engineering time.

A distributed training run requires coordinated multi-node scheduling, NCCL topology configuration, checkpoint lifecycle management, and automatic recovery from node failures — none of which are handled by a generic batch job.

## Goals

- Provide a `LatticeTrainingJob` CRD for distributed training (PyTorch DDP, DeepSpeed, JAX)
- Automatic NCCL environment configuration based on GPU topology
- Checkpoint management with periodic saves to existing backup storage backends
- Fault tolerance with automatic restart from last checkpoint on node failure
- Elastic training support (scale workers without restarting)
- Build on existing Volcano scheduler and GPU infrastructure

## Non-Goals

- Hyperparameter tuning / NAS (use external tools like Optuna)
- Experiment tracking (use MLflow, W&B, etc.)
- Dataset management / feature stores
- Training framework internals (we orchestrate, not implement)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    LatticeTrainingJob CRD                       │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  framework: PyTorch | DeepSpeed | JAX                     │ │
│  │  roles:                                                   │ │
│  │    master: {replicas: 1, workload: ..., gpu: H100 x 8}   │ │
│  │    worker: {replicas: 7, workload: ..., gpu: H100 x 8}   │ │
│  │  checkpoint:                                              │ │
│  │    interval: 30m                                          │ │
│  │    store_ref: s3-checkpoints                              │ │
│  │    max_retained: 3                                        │ │
│  │  elastic: {min: 4, max: 16}                               │ │
│  └───────────────────────────────────────────────────────────┘ │
└────────────────────────────┬────────────────────────────────────┘
                             │ compiles to
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Volcano VCJob                              │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐                  │
│  │ master │ │worker-0│ │worker-1│ │worker-N│    Gang-scheduled │
│  │  GPU×8 │ │  GPU×8 │ │  GPU×8 │ │  GPU×8 │    via PodGroup  │
│  └────┬───┘ └────┬───┘ └────┬───┘ └────┬───┘                  │
│       │          │          │          │                        │
│       └──────────┴──────────┴──────────┘                       │
│                  NCCL / RDMA fabric                             │
└─────────────────────────────────────────────────────────────────┘
                             │
                  periodic checkpoint save
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│               BackupStore (S3 / GCS / Azure Blob)              │
│  checkpoints/                                                   │
│    {job-name}/epoch-10/                                         │
│    {job-name}/epoch-20/                                         │
│    {job-name}/epoch-30/  ← latest                               │
└─────────────────────────────────────────────────────────────────┘
```

## Detailed Design

### CRD: LatticeTrainingJob

```rust
pub struct LatticeTrainingJobSpec {
    /// Training framework. Determines NCCL env, rendezvous method, and
    /// entrypoint wrapper behavior.
    pub framework: TrainingFramework,

    /// Volcano scheduler name (default: "volcano").
    pub scheduler_name: String,

    /// Volcano queue for resource fairness.
    pub queue: Option<String>,

    /// Priority class for preemption ordering.
    pub priority_class_name: Option<String>,

    /// Maximum retry count for the entire job (not per-pod).
    pub max_retry: Option<u32>,

    /// Role definitions. At minimum, "master" is required.
    /// Common patterns: master+worker, or launcher+worker (for MPI-style).
    pub roles: BTreeMap<String, TrainingRoleSpec>,

    /// Checkpoint configuration. If omitted, no automatic checkpointing.
    pub checkpoint: Option<CheckpointSpec>,

    /// Elastic scaling bounds. If omitted, job runs with fixed replica counts.
    pub elastic: Option<ElasticSpec>,

    /// NCCL tuning overrides. Auto-configured by default based on GPU model.
    pub nccl: Option<NcclConfig>,
}

pub enum TrainingFramework {
    PyTorch,    // torchrun / torch.distributed.launch
    DeepSpeed,  // deepspeed launcher
    Jax,        // jax.distributed
}

pub struct TrainingRoleSpec {
    pub replicas: u32,
    pub workload: WorkloadSpec,    // reuses existing Score-compatible spec
    pub runtime: RuntimeSpec,     // sidecars, sysctls, image_pull_secrets
    pub restart_policy: Option<RestartPolicy>,  // default: OnFailure
}

pub struct CheckpointSpec {
    /// How often to trigger a checkpoint save.
    pub interval: String,          // e.g., "30m", "1h"

    /// BackupStore reference for checkpoint storage.
    pub store_ref: String,

    /// Remote path prefix within the store.
    pub path_prefix: Option<String>,  // default: "checkpoints/{job-name}"

    /// Maximum number of checkpoints to retain (oldest pruned first).
    pub max_retained: Option<u32>,    // default: 3

    /// Local path inside the container where checkpoints are written.
    pub local_path: Option<String>,   // default: "/checkpoints"

    /// PVC size for local checkpoint staging.
    pub volume_size: Option<String>,  // default: "50Gi"

    /// Storage class for the checkpoint PVC.
    pub storage_class: Option<String>,
}

pub struct ElasticSpec {
    /// Minimum number of workers (job pauses below this).
    pub min_workers: u32,

    /// Maximum number of workers (job won't scale beyond this).
    pub max_workers: u32,

    /// How long to wait for new workers before continuing without them.
    pub scale_timeout: Option<String>,  // default: "5m"
}

pub struct NcclConfig {
    /// Network interface for NCCL traffic. Auto-detected if omitted.
    pub net_if: Option<String>,

    /// IB/RDMA HCA device. Auto-detected from NFD labels if omitted.
    pub ib_hca: Option<String>,

    /// Enable GDR (GPU Direct RDMA). Default: true if InfiniBand detected.
    pub gdr: Option<bool>,

    /// NCCL debug level. Default: "WARN".
    pub debug: Option<String>,

    /// Additional NCCL env vars (NCCL_ALGO, NCCL_PROTO, etc.).
    pub extra_env: Option<BTreeMap<String, String>>,
}

pub enum TrainingJobPhase {
    Pending,       // waiting for scheduling
    Initializing,  // master up, workers joining
    Running,       // all roles active, training in progress
    Checkpointing, // checkpoint save in progress
    Recovering,    // restarting from checkpoint after failure
    Succeeded,     // training complete
    Failed,        // max retries exceeded or unrecoverable error
}

pub struct LatticeTrainingJobStatus {
    pub phase: TrainingJobPhase,
    pub message: Option<String>,
    pub conditions: Vec<Condition>,
    pub observed_generation: Option<i64>,
    pub start_time: Option<String>,
    pub completion_time: Option<String>,
    pub active_workers: u32,
    pub desired_workers: u32,
    pub last_checkpoint: Option<CheckpointStatus>,
    pub checkpoints: Vec<CheckpointStatus>,
    pub retry_count: u32,
}

pub struct CheckpointStatus {
    pub path: String,             // remote path in backup store
    pub timestamp: String,
    pub size_bytes: Option<u64>,
    pub epoch: Option<u32>,       // training epoch at checkpoint time
    pub step: Option<u64>,        // global step at checkpoint time
}
```

### Compilation: LatticeTrainingJob -> Volcano VCJob

The training job controller compiles `LatticeTrainingJob` into a Volcano `VCJob` with framework-specific environment injection. This follows the same pattern as `LatticeJob` -> `VCJob` compilation.

**Master role pod template additions:**

```yaml
env:
  # PyTorch rendezvous
  - name: MASTER_ADDR
    value: "{job-name}-master-0.{job-name}"
  - name: MASTER_PORT
    value: "29500"
  - name: WORLD_SIZE
    value: "{total_gpus}"          # master_gpus + (worker_replicas * worker_gpus)
  - name: RANK
    value: "0"

  # NCCL configuration (auto-detected from GPU model)
  - name: NCCL_SOCKET_IFNAME
    value: "eth0"                  # or auto-detected
  - name: NCCL_DEBUG
    value: "WARN"
  - name: NCCL_IB_DISABLE
    value: "0"                     # enabled if InfiniBand detected via NFD

  # Checkpoint
  - name: CHECKPOINT_DIR
    value: "/checkpoints"
```

**Worker role pod template additions:**

```yaml
env:
  - name: MASTER_ADDR
    value: "{job-name}-master-0.{job-name}"
  - name: MASTER_PORT
    value: "29500"
  - name: WORLD_SIZE
    value: "{total_gpus}"
  - name: RANK
    valueFrom:
      fieldRef:
        fieldPath: metadata.annotations['volcano.sh/task-spec-rank']
```

**Volcano VCJob structure:**

```yaml
apiVersion: batch.volcano.sh/v1alpha1
kind: Job
metadata:
  name: {training-job-name}
spec:
  schedulerName: volcano
  minAvailable: {master + min_workers}   # gang scheduling threshold
  queue: {queue}
  policies:
    - event: PodEvicted
      action: RestartJob               # restart from checkpoint on eviction
    - event: PodFailed
      action: RestartJob
  plugins:
    env: []                            # Volcano env plugin for RANK injection
    svc: []                            # Headless service for pod DNS
  tasks:
    - name: master
      replicas: 1
      template:
        spec: {compiled pod spec with NCCL env + checkpoint volume}
    - name: worker
      replicas: {worker_replicas}
      template:
        spec: {compiled pod spec with NCCL env}
```

### NCCL Auto-Configuration

The compiler detects GPU topology from the `GpuParams.model` field and NFD node labels to set optimal NCCL parameters:

| GPU Model | NCCL_ALGO | NCCL_NET | GDR | Notes |
|-----------|-----------|----------|-----|-------|
| H100 SXM | Ring,Tree | IB | enabled | NVSwitch + InfiniBand |
| H100 PCIe | Ring | IB/Socket | if available | No NVSwitch |
| A100 | Ring,Tree | IB/Socket | if available | NVSwitch on SXM variants |
| L4/L40/L40S | Ring | Socket | disabled | PCIe only, no IB |
| T4 | Ring | Socket | disabled | Inference-class GPU |

The controller queries NFD labels on scheduled nodes to detect:
- `feature.node.kubernetes.io/pci-10de.present=true` — NVIDIA GPU present
- `feature.node.kubernetes.io/network-sriov.capable=true` — RDMA capable
- `nvidia.com/gpu.product` — exact GPU model for NCCL tuning

### Checkpoint Lifecycle

Checkpointing is decoupled from the training framework — Lattice handles the infrastructure, the user's code handles the save/load logic.

**How it works:**

- The controller creates a PVC mounted at `spec.checkpoint.local_path` (default: `/checkpoints`)
- The user's training code writes checkpoints to this path (standard PyTorch `torch.save()`, DeepSpeed `model.save_checkpoint()`, etc.)
- A sidecar container (`lattice-checkpoint-sync`) watches the local path and syncs new checkpoints to the BackupStore on the configured interval
- On job restart (after failure), the controller injects `RESUME_CHECKPOINT` env var pointing to the latest remote checkpoint path
- The user's code checks `RESUME_CHECKPOINT` and loads state if present

**Checkpoint sync sidecar:**

```yaml
- name: lattice-checkpoint-sync
  image: ghcr.io/evan-hines-js/lattice-checkpoint-sync:latest
  env:
    - name: CHECKPOINT_LOCAL_PATH
      value: "/checkpoints"
    - name: CHECKPOINT_REMOTE_PATH
      value: "s3://backup-bucket/checkpoints/{job-name}"
    - name: SYNC_INTERVAL
      value: "30m"
    - name: MAX_RETAINED
      value: "3"
  volumeMounts:
    - name: checkpoints
      mountPath: /checkpoints
      readOnly: true
```

**Checkpoint retention:** The sync sidecar prunes remote checkpoints exceeding `max_retained`, keeping the most recent. On job completion (Succeeded), all checkpoints are preserved — pruning only applies during active training.

### Fault Tolerance & Recovery

When a worker pod fails or is evicted:

```
1. Volcano detects pod failure
2. VCJob policy triggers RestartJob
3. Training controller updates status.phase = Recovering
4. Controller resolves latest checkpoint from BackupStore
5. New pods start with RESUME_CHECKPOINT={latest_checkpoint_path}
6. Training code loads checkpoint and resumes
7. Controller updates status.phase = Running
```

**Retry budget:** `spec.max_retry` limits total restart attempts. Each restart increments `status.retry_count`. When exhausted, phase transitions to `Failed`.

**Preemption handling:** For spot/preemptible GPU instances, the controller watches for `PodEvicted` events and triggers the same recovery flow. The checkpoint interval should be tuned relative to expected preemption frequency.

### Elastic Training

When `spec.elastic` is set, the controller manages worker count dynamically:

- Creates a KEDA ScaledJob (not ScaledObject — workers are job tasks, not deployments)
- Worker count scales between `elastic.min_workers` and `elastic.max_workers`
- Scaling trigger: GPU availability in the Volcano queue
- On scale-up: new workers join the existing rendezvous (PyTorch elastic `c10d` backend)
- On scale-down: graceful removal after current training step completes

**Requirements for elastic training:**
- Framework must support elastic rendezvous (PyTorch >= 1.10 with `torch.distributed.elastic`)
- User code must use `torch.distributed.elastic.multiprocessing.start_processes` or equivalent
- Master role is never scaled — only workers

### Mesh Integration

Training pods within a job need unrestricted communication (NCCL, parameter server, gradient sync). The controller generates:

- A `LatticeMeshMember` for the training job's headless service
- Bilateral inbound/outbound within the job's pods (self-referencing)
- No external access by default (training jobs are internal)

## Implementation Plan

### Step 1: CRD & Types (lattice-common)

- Add `crd/training_job.rs` with `LatticeTrainingJob` spec/status types
- Add `TrainingJobPhase` enum
- Register in `CrdRegistry`
- Add `CrdKind::TrainingJob` variant

### Step 2: Controller (new crate: lattice-training)

- Create `crates/lattice-training/` with controller watching `LatticeTrainingJob`
- Compile to Volcano VCJob with framework-specific env injection
- NCCL auto-configuration based on GPU model
- Headless service generation for pod DNS

### Step 3: Checkpoint Management

- Checkpoint sidecar container image (simple S3/GCS sync utility)
- PVC generation for local checkpoint staging
- BackupStore integration for remote storage
- Recovery logic: resolve latest checkpoint, inject env var

### Step 4: Elastic Training

- KEDA ScaledJob integration for worker scaling
- Volcano queue-aware scaling triggers
- Elastic rendezvous configuration for PyTorch

### Step 5: Testing

- Integration test: 2-node PyTorch DDP training on CPU (no GPU needed for correctness)
- Integration test: checkpoint save/restore cycle
- Integration test: worker failure and recovery
- E2E test: full training run with GPU (requires GPU nodes)

## CRD Changes

New CRD: `LatticeTrainingJob` (apiVersion: `lattice.io/v1alpha1`, kind: `LatticeTrainingJob`)

No changes to existing CRDs. Reuses existing `WorkloadSpec`, `RuntimeSpec`, `GpuParams`, and `BackupStore` types.

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| NCCL misconfiguration causes silent performance degradation | Default to conservative settings; expose `NCCL_DEBUG=INFO` in status for troubleshooting |
| Checkpoint sidecar adds resource overhead | Minimal container (static binary), read-only volume mount, configurable interval |
| Elastic rendezvous complexity | Only support PyTorch elastic initially; require explicit opt-in via `elastic` field |
| Large checkpoint upload blocks training | Async upload in sidecar; training continues while sync runs in background |
| Gang scheduling deadlock with elastic | Set `minAvailable` to `master + min_workers`, not `max_workers` |
