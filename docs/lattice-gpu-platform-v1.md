# Lattice GPU Platform v1

> **A complete on-prem GPU inference and training platform built on Lattice.**
>
> Clusters with `gpu: enabled` get the full stack automatically. Users deploy
> inference services with `LatticeService` and training workloads with `LatticeJob`.
> Fractional GPU sharing (HAMi), custom autoscaling, gang scheduling (Volcano),
> and model caching — all from simple YAML.

---

## What v1 Delivers

```
┌──────────────────────────────────────────────────────────────────────┐
│                        User-Facing CRDs                              │
│                                                                      │
│  LatticeService (inference)          LatticeJob (training)           │
│  ┌──────────────────────┐            ┌───────────────────────┐       │
│  │ gpu:                 │            │ gpu:                  │       │
│  │   count: 1           │            │   count: 4            │       │
│  │   memory: 20Gi       │            │   model: H100         │       │
│  │ replicas:            │            │ workers: 1            │       │
│  │   min: 1             │            │ completions: 1        │       │
│  │   max: 8             │            │                       │       │
│  │   autoscaling:       │            │                       │       │
│  │     - metric: vllm_  │            │                       │       │
│  │       queue_depth    │            │                       │       │
│  │       target: 5      │            │                       │       │
│  └──────────┬───────────┘            └──────────┬────────────┘       │
│             │ compiles to                       │ compiles to        │
│             ▼                                   ▼                    │
│        Deployment + HPA                    VolcanoJob                │
│        (long-running, autoscaled)          (gang-scheduled,         │
│                                             run-to-completion)      │
└──────────────────────────────────────────────────────────────────────┘
                              │
          deployed on gpu: enabled clusters
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  GPU Cluster Infrastructure (auto-deployed)                          │
│                                                                      │
│  ┌────────────────┐  ┌──────────┐  ┌────────────┐  ┌────────────┐  │
│  │ NVIDIA GPU      │  │ HAMi     │  │ Volcano    │  │ Prometheus │  │
│  │ Operator        │  │ (CNCF)   │  │ (CNCF)     │  │ Adapter    │  │
│  │                 │  │          │  │            │  │            │  │
│  │ Drivers, device │  │ Frac GPU │  │ Gang sched │  │ Custom HPA │  │
│  │ plugin, NFD,    │  │ sharing, │  │ job queues │  │ metrics    │  │
│  │ DCGM, toolkit   │  │ isolation│  │ priority   │  │ (vLLM etc) │  │
│  └────────────────┘  └──────────┘  └────────────┘  └────────────┘  │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ Model Cache DaemonSet                                        │    │
│  │ Pre-pulls model weights to node-local NVMe, pods mount R/O   │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  Already installed by Lattice:                                       │
│  Cilium, Istio ambient, cert-manager, ESO/Vault, Velero, agent      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Inference vs Training: Why Two CRDs

| | LatticeService (inference) | LatticeJob (training) |
|---|---|---|
| K8s primitive | Deployment | VolcanoJob |
| Lifecycle | Long-running, always on | Run-to-completion |
| Scaling | HPA 1→N on custom metrics | Fixed worker count, gang-scheduled |
| GPU pattern | Fractional OK (HAMi sharing) | Usually full GPUs, multi-GPU |
| Networking | Needs ingress (serve requests) | Needs NCCL between workers |
| Storage | Model cache read-only | Read/write (checkpoints, datasets) |
| Scheduler | Volcano (HAMi plugin) | Volcano (gang + HAMi plugin) |

All GPU pods route through Volcano's scheduler (`schedulerName: volcano`) with
HAMi's fractional GPU plugin loaded. This gives one scheduler for all GPU
workloads — inference gets fractional GPU placement, training adds gang semantics
on top. See [HAMi + Volcano Integration](#hami--volcano-integration) below.

Training jobs need gang scheduling — all N workers must start simultaneously or
none of them should. Without this, worker 0 starts, grabs 4 GPUs, waits for
worker 1 which can't schedule because the cluster is full. Deadlock.
Volcano (CNCF Incubating) solves this as its core feature.

---

## 1. LatticeJob CRD

### User-Facing YAML

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeJob
metadata:
  name: finetune-llama
  namespace: ml-team
spec:
  # Container spec (same pattern as LatticeService)
  containers:
    trainer:
      image: my-registry/llama-finetune:v1
      command: ["torchrun", "--nproc_per_node=4", "train.py"]
      args:
        - "--model=/models/meta-llama/Llama-3.3-70B-Instruct"
        - "--output=/output/checkpoints"
        - "--epochs=3"
      resources:
        requests:
          cpu: "32"
          memory: 256Gi

  # GPU spec (shared with LatticeService)
  gpu:
    count: 4
    model: H100

  # Job-specific fields
  workers: 1                    # Number of parallel pods (default: 1)
  completions: 1                # How many workers must complete (default: workers)
  backoffLimit: 3               # Retry count on failure (default: 3)
  timeout: 24h                  # Maximum wall-clock time (default: none)

  # Storage for training artifacts
  storage:
    output:                     # Read-write PVC for checkpoints
      size: 100Gi
      storageClass: local-nvme
      mountPath: /output
```

### Shorthand Forms

```yaml
# Single-node multi-GPU fine-tune (most common)
name: finetune-phi
spec:
  containers:
    trainer:
      image: my-finetune:latest
      command: ["python", "train.py"]
  gpu:
    count: 1
    memory: 20Gi
  # workers defaults to 1, completions defaults to 1

# Multi-node distributed training
name: pretrain-large
spec:
  containers:
    trainer:
      image: my-pretrain:latest
      command: ["torchrun", "--nnodes=4", "--nproc_per_node=8", "train.py"]
  gpu:
    count: 8
    model: H100
  workers: 4                    # 4 pods x 8 GPUs = 32 GPUs total
```

### CRD Struct

```rust
/// A training or batch GPU workload
///
/// Compiles to a VolcanoJob with gang scheduling. All workers start
/// simultaneously or none do — preventing GPU deadlocks on constrained clusters.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "LatticeJob",
    plural = "latticejobs",
    shortname = "lj",
    namespaced,
    status = "LatticeJobStatus",
)]
#[serde(rename_all = "camelCase")]
pub struct LatticeJobSpec {
    /// Named container specifications (same as LatticeService)
    pub containers: BTreeMap<String, ContainerSpec>,

    /// GPU resource requirements (shared GPUSpec type)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<GPUSpec>,

    /// Number of parallel worker pods (default: 1)
    /// All workers start together (gang scheduling via Volcano)
    #[serde(default = "default_one")]
    pub workers: u32,

    /// Number of workers that must complete successfully (default: workers)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completions: Option<u32>,

    /// Number of retries before marking the job as failed (default: 3)
    #[serde(default = "default_three")]
    pub backoff_limit: u32,

    /// Maximum wall-clock time (e.g., "24h", "6h30m")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,

    /// Storage volumes for training data and output
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<JobStorageSpec>,

    /// Include job workers in the Istio ambient mesh (default: true)
    ///
    /// When true, all inter-worker traffic is encrypted via mTLS (ztunnel).
    /// Set to false for performance on non-regulated clusters — NCCL throughput
    /// improves 10-30% without mTLS, but traffic is unencrypted.
    /// CiliumNetworkPolicy L4 isolation is always enforced regardless.
    #[serde(default = "default_true")]
    pub mesh: bool,

    /// External dependencies (same as LatticeService)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resources: BTreeMap<String, ResourceSpec>,
}

/// Storage configuration for training jobs
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JobStorageSpec {
    /// Read-write volume for training output (checkpoints, logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<JobVolumeSpec>,

    /// Read-only volume for input datasets
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset: Option<JobVolumeSpec>,
}

/// A volume attached to a training job
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JobVolumeSpec {
    /// Volume size (e.g., "100Gi")
    pub size: String,

    /// Storage class (e.g., "local-nvme", "gp3")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,

    /// Mount path inside the container (e.g., "/output")
    pub mount_path: String,
}

/// Status of a LatticeJob
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LatticeJobStatus {
    pub phase: JobPhase,
    pub start_time: Option<String>,
    pub completion_time: Option<String>,
    pub succeeded: u32,
    pub failed: u32,
    pub active: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub enum JobPhase {
    #[default]
    Pending,
    Running,
    Succeeded,
    Failed,
}
```

### Compiled Output: VolcanoJob

```yaml
# LatticeJob finetune-llama compiles to:
apiVersion: batch.volcano.sh/v1alpha1
kind: Job
metadata:
  name: finetune-llama
  namespace: ml-team
  labels:
    lattice.dev/job: finetune-llama
spec:
  minAvailable: 1                    # Gang: all workers or none
  schedulerName: volcano
  maxRetry: 3
  plugins:
    svc: ["--publish-not-ready-addresses"]  # Headless svc for NCCL
  tasks:
    - replicas: 1                    # spec.workers
      name: trainer
      template:
        spec:
          runtimeClassName: nvidia
          serviceAccountName: finetune-llama
          containers:
            - name: trainer
              image: my-registry/llama-finetune:v1
              command: ["torchrun", "--nproc_per_node=4", "train.py"]
              args:
                - "--model=/models/meta-llama/Llama-3.3-70B-Instruct"
                - "--output=/output/checkpoints"
                - "--epochs=3"
              resources:
                requests:
                  cpu: "32"
                  memory: 256Gi
                limits:
                  nvidia.com/gpu: "4"
              volumeMounts:
                - name: shm
                  mountPath: /dev/shm
                - name: model-cache
                  mountPath: /models
                  readOnly: true
                - name: output
                  mountPath: /output
              env:
                - name: NCCL_DEBUG
                  value: INFO
          volumes:
            - name: shm
              emptyDir:
                medium: Memory
                sizeLimit: 64Gi
            - name: model-cache
              hostPath:
                path: /var/lattice/models
                type: Directory
            - name: output
              persistentVolumeClaim:
                claimName: finetune-llama-output
          tolerations:
            - key: nvidia.com/gpu
              operator: Exists
              effect: NoSchedule
          nodeSelector:
            nvidia.com/gpu.product: "NVIDIA-H100-80GB-HBM3"
          restartPolicy: OnFailure
```

### Multi-Node Distributed Training

When `workers > 1`, the compiler generates:

1. **VolcanoJob** with `minAvailable: <workers>` (gang scheduling)
2. **Headless Service** via Volcano's `svc` plugin (pod-to-pod NCCL)
3. **Environment variables** injected per worker:

```yaml
env:
  - name: MASTER_ADDR
    value: "finetune-llama-trainer-0.finetune-llama"  # Volcano naming
  - name: MASTER_PORT
    value: "29500"
  - name: WORLD_SIZE
    value: "4"          # spec.workers
  - name: RANK
    valueFrom:
      fieldRef:
        fieldPath: metadata.annotations['volcano.sh/task-index']
```

Users write `torchrun --nnodes=$WORLD_SIZE` and it works. No manual rank management.

### Network Isolation

By default, LatticeJob workers run inside the Istio ambient mesh — all inter-worker
traffic gets mTLS via ztunnel, same as LatticeService. This is the correct default
for FedRAMP and regulated environments where all data in transit must be encrypted
with FIPS-validated cryptography.

**Every LatticeJob gets a `CiliumNetworkPolicy`** for L4 isolation regardless of
mesh participation:

```yaml
# Generated CiliumNetworkPolicy for LatticeJob "finetune-llama"
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: job-finetune-llama
  namespace: ml-team
spec:
  endpointSelector:
    matchLabels:
      lattice.dev/job: finetune-llama

  ingress:
    # Allow from other workers in the same job (NCCL, all ports)
    - fromEndpoints:
        - matchLabels:
            lattice.dev/job: finetune-llama

  egress:
    # Allow to other workers in the same job (NCCL, all ports)
    - toEndpoints:
        - matchLabels:
            lattice.dev/job: finetune-llama

    # DNS
    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP

    # Declared dependencies from spec.resources (same bilateral pattern)
    # e.g., S3 for dataset download, model registry, etc.
```

This gives training jobs:
- **Complete isolation** from everything else on the cluster
- **Intra-job communication** on all ports (NCCL uses dynamic ports)
- **Dependency access** only for explicitly declared resources
- **Same bilateral contract** as LatticeService — if a job declares an outbound
  dependency, the callee must also declare the inbound allowance

#### Opting Out of Istio (explicit, per-job)

For performance-sensitive training where mTLS overhead on NCCL traffic is
unacceptable (10-30% throughput hit on multi-GB/s tensor transfers), users
can explicitly opt out:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeJob
metadata:
  name: pretrain-large
spec:
  mesh: false                   # Opt out of Istio ambient mesh
  containers:
    trainer:
      image: my-pretrain:latest
  gpu:
    count: 8
    model: H100
  workers: 4
```

When `mesh: false`:
- Pods labeled with `istio.io/dataplane-mode: none` (skip ztunnel)
- No Istio `AuthorizationPolicy` generated
- CiliumNetworkPolicy still enforced (L4 isolation always on)
- **WARNING**: inter-worker NCCL traffic is unencrypted — not suitable for
  FedRAMP, HIPAA, or environments requiring encryption in transit

The `mesh` field defaults to `true`. The CRD:

```rust
pub struct LatticeJobSpec {
    // ...

    /// Include job workers in the Istio ambient mesh (default: true)
    ///
    /// When true, all inter-worker traffic is encrypted via mTLS (ztunnel).
    /// Set to false to opt out for performance — NCCL throughput improves
    /// 10-30% without mTLS, but traffic is unencrypted.
    ///
    /// CiliumNetworkPolicy L4 isolation is always enforced regardless of
    /// this setting.
    #[serde(default = "default_true")]
    pub mesh: bool,
}
```

When `mesh: true` (default), the compiler generates both:
- `CiliumNetworkPolicy` (L4, intra-job + declared dependencies)
- `AuthorizationPolicy` (L7, SPIFFE identity for each worker)

#### Cluster-Level FIPS Gate

Setting `mesh: false` on a LatticeJob is a **validation error** unless the cluster
explicitly opts into allowing unencrypted workloads. This prevents accidental
compliance violations.

On `LatticeClusterSpec`:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: gpu-dev-cluster
spec:
  # ...
  gpu:
    enabled: true
  compliance:
    allowUnencryptedTraffic: true   # Required to use mesh: false on jobs
```

```rust
// crates/lattice-common/src/crd/cluster.rs

/// Compliance and security policy for the cluster
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceSpec {
    /// Allow workloads to opt out of service mesh encryption (default: false)
    ///
    /// When false (default), LatticeJob with `mesh: false` is rejected at
    /// admission time. This ensures all data in transit is encrypted with
    /// FIPS-validated mTLS, as required by FedRAMP, HIPAA, etc.
    ///
    /// Set to true only on non-regulated clusters where NCCL performance
    /// is more important than encryption in transit.
    #[serde(default)]
    pub allow_unencrypted_traffic: bool,
}
```

Validation in the LatticeJob controller:

```rust
// In LatticeJob admission / reconcile
if !job.spec.mesh {
    let cluster = get_self_cluster(client).await?;
    let allowed = cluster.spec.compliance
        .as_ref()
        .map(|c| c.allow_unencrypted_traffic)
        .unwrap_or(false);

    if !allowed {
        return Err(anyhow!(
            "mesh: false requires cluster compliance.allowUnencryptedTraffic: true. \
             All traffic must be encrypted on this cluster."
        ));
    }
}
```

This gives you:
- **Default safe**: every cluster enforces mTLS on all traffic
- **Explicit opt-in**: cluster admin must consciously allow unencrypted workloads
- **Per-job granularity**: even on opted-in clusters, individual jobs default to `mesh: true`
- **Audit trail**: `allowUnencryptedTraffic: true` on the cluster spec is visible and reviewable

---

## 2. Generalized Autoscaling (LatticeService)

See [autoscaling-v1.md](autoscaling-v1.md) for full details. Summary:

```yaml
replicas:
  min: 1
  max: 8
  autoscaling:
    - metric: vllm_num_requests_waiting
      target: 5
    - metric: cpu
      target: 70
```

- `cpu`/`memory` → HPA v2 Resource metric (built-in)
- Anything else → HPA v2 Pods metric (via Prometheus Adapter)
- Default: CPU 80% when `autoscaling` is empty (backwards compatible)
- No KEDA, no Knative, no scale-to-zero

---

## 3. GPU Cluster Infrastructure

See [hami-gpu-sharing.md](hami-gpu-sharing.md) for full GPU Operator + HAMi details.

v1 adds **Volcano** (with HAMi scheduler plugin) to the GPU bootstrap stack:

```
Bootstrap sequence for gpu: enabled clusters:
1. Cilium CNI                              (existing)
2. Istio ambient mesh                      (existing)
3. NVIDIA GPU Operator                     (gpu.enabled)
4. HAMi device plugin DaemonSet            (gpu.enabled)
5. Volcano + HAMi scheduler plugin         ← NEW (gpu.enabled)
6. Model Cache DaemonSet                   (gpu.modelCache)
7. Prometheus Adapter + vLLM rules         (gpu.enabled)
```

### HAMi + Volcano Integration

HAMi and Volcano operate at different layers but overlap at the scheduler:

- **HAMi device plugin** (DaemonSet) — runs on every GPU node, virtualizes GPUs
  via CUDA interception, enforces memory/compute limits at runtime
- **HAMi scheduler plugin** — tracks fractional GPU allocations across nodes,
  makes placement decisions (which node has enough free GPU memory)
- **Volcano scheduler** — gang scheduling (all-or-nothing), job queues, priority

The problem: both HAMi and Volcano want to extend the scheduler. Running two
schedulers creates conflicts over GPU placement decisions.

The solution: Volcano supports loading HAMi as an internal scheduler plugin.
One scheduler process handles both fractional GPU placement (HAMi) and gang
scheduling (Volcano). No standalone HAMi scheduler install is needed.

```
┌─────────────────────────────────────────────────────┐
│  Volcano Scheduler (single scheduler for all GPU)   │
│  ┌──────────────┐  ┌────────────────────────────┐   │
│  │ Gang Plugin   │  │ HAMi Plugin                │   │
│  │ (all-or-none) │  │ (fractional GPU placement) │   │
│  └──────────────┘  └────────────────────────────┘   │
└──────────────────────┬──────────────────────────────┘
                       │ schedules
    ┌──────────────────┼──────────────────┐
    ▼                  ▼                  ▼
 Inference          Training          Training
 Deployment         VolcanoJob        VolcanoJob
 (1 replica,        (1 worker,        (4 workers,
  fractional GPU)    4 full GPUs)      8 GPUs each)
```

**All GPU pods** set `schedulerName: volcano` — both LatticeService Deployments
and LatticeJob VolcanoJobs. Volcano handles non-gang workloads fine (it's a
superset of kube-scheduler). A single-replica inference Deployment just schedules
normally through Volcano; the HAMi plugin handles fractional GPU placement. Gang
semantics only activate for VolcanoJobs with `minAvailable > 1`.

This means:
- **No standalone HAMi scheduler** to install or maintain
- **One scheduler** for all GPU workloads (inference and training)
- **HAMi device plugin DaemonSet** still needed on every GPU node (runtime CUDA
  interception is node-level, not scheduler-level)

### Volcano Bootstrap

```rust
// crates/lattice-infra/src/bootstrap/volcano.rs

static VOLCANO_MANIFESTS: OnceCell<Result<Arc<Vec<String>>, String>> = OnceCell::const_new();

pub fn volcano_version() -> &'static str {
    env!("VOLCANO_VERSION")
}

pub async fn generate_volcano() -> Result<Arc<Vec<String>>, String> {
    VOLCANO_MANIFESTS
        .get_or_init(|| async { render_volcano_helm().await.map(Arc::new) })
        .await
        .clone()
}

async fn render_volcano_helm() -> Result<Vec<String>, String> {
    let charts = charts_dir();
    let version = volcano_version();
    let chart = format!("{}/volcano-v{}.tgz", charts, version);

    let mut manifests = vec![namespace_yaml("volcano-system")];

    // Enable HAMi scheduler plugin inside Volcano
    let rendered = run_helm_template(
        "volcano",
        &chart,
        "volcano-system",
        &["custom.scheduler_plugins.hami.enabled=true"],
    ).await?;

    manifests.extend(rendered);
    Ok(manifests)
}
```

### System Namespaces

Add to mesh default-deny exclusions:

```rust
// crates/lattice-infra/src/system_namespaces.rs
pub const GPU: &[&str] = &["gpu-operator", "hami-system", "volcano-system"];
```

---

## 4. LatticeJob Compiler

New compiler module parallel to the existing service workload compiler.

### Architecture

```
crates/lattice-job/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── controller.rs          # Reconcile LatticeJob → VolcanoJob + CiliumNetworkPolicy
│   ├── compiler.rs            # LatticeJobSpec → VolcanoJob YAML
│   ├── policy.rs              # CiliumNetworkPolicy generation (no Istio)
│   └── status.rs              # Watch VolcanoJob status → update LatticeJob status
```

The compiler reuses `GPUSpec` from `lattice-common` and the same GPU compilation
logic (tolerations, node selector, SHM, runtimeClass, model cache mount) as the
service compiler. Extract shared GPU compilation into a helper:

```rust
// crates/lattice-common/src/gpu.rs (or lattice-service/src/workload/gpu.rs)

/// Generate GPU-related pod spec modifications
///
/// Shared between LatticeService compiler and LatticeJob compiler.
/// All GPU pods route through Volcano's scheduler (which has HAMi's
/// fractional GPU plugin loaded), so we always set schedulerName.
pub fn compile_gpu_pod_spec(gpu: &GPUSpec) -> GpuPodSpec {
    GpuPodSpec {
        runtime_class: Some("nvidia".to_string()),
        scheduler_name: Some("volcano".to_string()),
        tolerations: if gpu.tolerations {
            vec![gpu_toleration()]
        } else {
            vec![]
        },
        node_selector: gpu.model.as_ref().map(|m| {
            btreemap! { "nvidia.com/gpu.product".to_string() => gpu_product_label(m) }
        }),
        volumes: gpu_volumes(gpu),
        volume_mounts: gpu_volume_mounts(gpu),
        resource_limits: gpu_resource_limits(gpu),
    }
}
```

### Compilation Matrix (LatticeJob → VolcanoJob)

| LatticeJob Field | VolcanoJob Output |
|---|---|
| (always) | `schedulerName: volcano` (HAMi plugin handles GPU placement) |
| `workers: N` | `tasks[0].replicas: N`, `minAvailable: N` |
| `completions: M` | `minAvailable: M` (if different from workers) |
| `backoffLimit: 3` | `maxRetry: 3` |
| `timeout: 24h` | `activeDeadlineSeconds: 86400` |
| `gpu.count: 4` | `limits.nvidia.com/gpu: 4` |
| `gpu.memory: 20Gi` | `limits.nvidia.com/gpumem: 20480` (HAMi) |
| `gpu.model: H100` | `nodeSelector.nvidia.com/gpu.product: ...` |
| `gpu.count > 1` | SHM volume |
| `workers > 1` | Headless svc plugin, NCCL env vars |
| `storage.output` | PVC + volumeMount (read-write) |
| `storage.dataset` | PVC + volumeMount (read-only) |
| (always) | `CiliumNetworkPolicy` (intra-job + declared dependencies only) |
| `mesh: true` (default) | `AuthorizationPolicy` (L7 mTLS via ztunnel) |
| `mesh: false` (explicit) | `istio.io/dataplane-mode: none` label, no AuthorizationPolicy |
| `resources` (dependencies) | Egress rules in CiliumNetworkPolicy (bilateral) |

> **Note**: LatticeService Deployments with `gpu` also emit `schedulerName: volcano`
> on the pod spec. This routes inference pods through the same Volcano scheduler
> with HAMi's fractional GPU plugin — no separate HAMi scheduler install needed.

---

## 5. Model Cache DaemonSet

Pre-pulls model weights to node-local storage. Both LatticeService and LatticeJob
pods mount the cache read-only.

See [hami-gpu-sharing.md](hami-gpu-sharing.md) for full model cache design.

The cache serves both workload types:
- **Inference**: vLLM loads from `/models/` instead of downloading from HuggingFace
- **Training**: Fine-tune scripts load base model from `/models/`, write checkpoints to `/output/`

Cold start impact:
- Without cache: 5-30 minutes (download 70B model over network)
- With cache: 30-120 seconds (load from local NVMe)

---

## 6. CLI Commands

### `lattice serve`

Generates and applies a LatticeService for inference:

```bash
# Quick deploy
lattice serve llama-3-70b \
  --image vllm/vllm-openai:latest \
  --gpu 4 --gpu-model H100 \
  --namespace ml-team

# With autoscaling
lattice serve phi-3-mini \
  --image vllm/vllm-openai:latest \
  --gpu 1 --gpu-memory 8Gi \
  --min-replicas 1 --max-replicas 8 \
  --scale-on vllm_num_requests_waiting=5 \
  --namespace ml-team
```

Generates a LatticeService YAML and applies it. Users can also `--dry-run` to
get the YAML without applying.

### `lattice train`

Generates and applies a LatticeJob for training:

```bash
# Single-node fine-tune
lattice train finetune-llama \
  --image my-registry/finetune:v1 \
  --gpu 4 --gpu-model H100 \
  --output-size 100Gi \
  --namespace ml-team

# Multi-node distributed
lattice train pretrain-large \
  --image my-registry/pretrain:v1 \
  --gpu 8 --gpu-model H100 \
  --workers 4 \
  --timeout 48h \
  --namespace ml-team
```

### `lattice get jobs`

```bash
lattice get jobs -n ml-team
# NAME              WORKERS  GPU        PHASE      DURATION   AGE
# finetune-llama    1/1      4x H100    Running    2h15m      3h
# pretrain-large    4/4      8x H100    Succeeded  18h42m     1d
# quick-test        1/1      1x 8Gi     Failed     0m12s      2h
```

### `lattice get gpus`

```bash
lattice get gpus --cluster gpu-cluster
# NODE          GPU MODEL     TOTAL    USED     AVAILABLE
# gpu-node-01   H100 80GB     4        3.2      0.8
# gpu-node-02   H100 80GB     4        2.0      2.0
# gpu-node-03   A100 80GB     8        8.0      0.0
# ---
# TOTAL: 16 GPUs, 13.2 allocated, 2.8 available
```

Reads DCGM exporter metrics via the cluster's Prometheus.

---

## 7. Remaining Compiler Gaps

These apply to both LatticeService and LatticeJob GPU compilation:

### runtimeClassName + schedulerName

GPU Operator configures the `nvidia` RuntimeClass. All GPU pods must use it.
All GPU pods also route through Volcano's scheduler (HAMi plugin handles
fractional GPU placement for both inference and training).

```rust
// In compile_deployment / compile_volcano_job (via shared compile_gpu_pod_spec)
if spec.gpu.is_some() {
    pod_spec.runtime_class_name = Some("nvidia".to_string());
    pod_spec.scheduler_name = Some("volcano".to_string());
}
```

### SHM Volume (multi-GPU)

NCCL inter-process communication requires large `/dev/shm`. Default K8s is 64MB.

```rust
// When gpu.count > 1
if gpu.count > 1 {
    volumes.push(shm_volume());       // emptyDir, medium: Memory, 64Gi
    mounts.push(shm_mount());         // /dev/shm
}
```

### Default Startup Probe (inference only)

vLLM/TGI take 30-120s to load models. Without a startup probe, K8s routes
traffic to pods still loading weights.

```rust
// LatticeService compiler, when gpu is set and no startup probe defined
if spec.gpu.is_some() && container.startup_probe.is_none() {
    container.startup_probe = Some(Probe {
        http_get: Some(HttpGet { path: "/health", port: 8000 }),
        period_seconds: 10,
        failure_threshold: 30,    // 5 minutes to load model
    });
}
```

---

## Files Changed (Complete)

### New Files

| File | Description |
|---|---|
| `crates/lattice-common/src/crd/job.rs` | LatticeJob CRD, LatticeJobSpec, JobStorageSpec, LatticeJobStatus |
| `crates/lattice-job/` | New crate: LatticeJob controller + compiler |
| `crates/lattice-job/src/controller.rs` | Reconcile LatticeJob → VolcanoJob + CiliumNetworkPolicy |
| `crates/lattice-job/src/compiler.rs` | LatticeJobSpec → VolcanoJob YAML |
| `crates/lattice-job/src/policy.rs` | CiliumNetworkPolicy for job isolation (no Istio) |
| `crates/lattice-infra/src/bootstrap/volcano.rs` | Volcano helm template generation |
| `crates/lattice-cli/src/commands/serve.rs` | `lattice serve` CLI command |
| `crates/lattice-cli/src/commands/train.rs` | `lattice train` CLI command |
| `crates/lattice-cli/src/commands/get/jobs.rs` | `lattice get jobs` CLI command |
| `crates/lattice-cli/src/commands/get/gpus.rs` | `lattice get gpus` CLI command |

### Modified Files

| File | Change |
|---|---|
| `crates/lattice-common/src/crd/mod.rs` | Add `pub mod job;` |
| `crates/lattice-common/src/crd/cluster.rs` | Add `ComplianceSpec` with `allow_unencrypted_traffic` |
| `crates/lattice-common/src/crd/service.rs` | Add `AutoscalingMetric` to `ReplicaSpec` |
| `crates/lattice-service/src/workload/mod.rs` | Generalize `compile_hpa`, add SHM/runtimeClass/schedulerName, extract shared GPU helpers |
| `crates/lattice-infra/src/bootstrap/mod.rs` | Add `pub mod volcano;`, include in GPU bootstrap |
| `crates/lattice-infra/src/system_namespaces.rs` | Add `volcano-system` to GPU exclusions |
| `crates/lattice-operator/src/startup/crds.rs` | Register LatticeJob CRD |
| `crates/lattice-operator/src/controller.rs` | Start LatticeJob controller |
| `versions.toml` | Pin `VOLCANO_VERSION`, `PROMETHEUS_ADAPTER_VERSION` |

---

## Implementation Phases

### Phase 1: Compiler Gaps + Autoscaling

Fix the known gaps in the existing LatticeService GPU compiler and generalize HPA.

1. Add `runtimeClassName: nvidia` and `schedulerName: volcano` on GPU pods
2. Add SHM volume when `gpu.count > 1`
3. Add `AutoscalingMetric` to `ReplicaSpec`
4. Generalize `compile_hpa` to support custom metrics
5. Update tests

**Result**: LatticeService GPU inference works end-to-end with correct pod specs
and user-configurable autoscaling.

### Phase 2: LatticeJob CRD + Compiler

Build the training workload path.

1. Define `LatticeJobSpec` CRD in `lattice-common`
2. Create `lattice-job` crate with controller + compiler
3. Compile LatticeJob → VolcanoJob with gang scheduling
4. Generate `CiliumNetworkPolicy` per job (intra-job + declared dependencies, no Istio)
5. Label pods with `istio.io/dataplane-mode: none` to opt out of ambient mesh
6. Handle storage (output PVC, dataset mount)
7. Multi-node support (NCCL env vars, headless service)
8. Status reconciliation (VolcanoJob status → LatticeJob status)
9. Tests (including policy verification: workers can reach each other, nothing else can)

**Result**: Users can submit training jobs that are gang-scheduled on GPU clusters
with L4 network isolation and full-speed NCCL between workers.

### Phase 3: Volcano + Prometheus Adapter Bootstrap

Deploy the remaining infrastructure on GPU clusters.

1. Add `volcano.rs` to bootstrap module
2. Add `prometheus_adapter.rs` to bootstrap module
3. Pin versions in `versions.toml`
4. Add `volcano-system` to system namespace exclusions
5. Include both in GPU cluster bootstrap path

**Result**: GPU clusters have gang scheduling and custom metrics out of the box.

### Phase 4: CLI

User-facing commands for GPU workflows.

1. `lattice serve` — generate + apply LatticeService for inference
2. `lattice train` — generate + apply LatticeJob for training
3. `lattice get jobs` — list LatticeJobs with status
4. `lattice get gpus` — show GPU utilization across nodes

**Result**: Complete CLI experience for GPU inference and training.

### Phase 5: Model Cache DaemonSet

Build and deploy the model caching layer.

1. Build model-cache container image (downloads from HuggingFace/S3)
2. Generate DaemonSet manifests from `gpu.modelCache` cluster config
3. ConfigMap-driven model list (updateable without redeploying)
4. Auto-mount `/models` in GPU pods

**Result**: Models pre-warmed on nodes, cold starts drop from minutes to seconds.

---

## What v1 Does NOT Include

| Deferred Feature | Why | When |
|---|---|---|
| **Kueue** | Single-team clusters don't need admission control. Volcano handles scheduling. | v2: multi-tenant quota |
| **Scale-to-zero** | GPU cold starts (30-120s) make it impractical for production. | v2: if customer demand |
| **KEDA** | HPA v2 + Prometheus Adapter is sufficient. | v2: if event-driven needed |
| **Knative** | No scale-to-zero requirement. | v2: if serverless needed |
| **Multi-cluster job placement** | User picks the cluster in v1. | v2: control plane routes |
| **Notebook support** | JupyterHub integration for interactive dev. | v2: developer experience |
| **Pipeline orchestration** | Train → evaluate → deploy workflows. | v2: MLOps |
| **KV-cache-aware routing** | Optimizes inference latency (llm-d). | v2+: advanced inference |
| **GPUTenantQuota** | No multi-tenancy in v1. | v2: with Kueue |

---

## Examples

### Fine-Tune a Small Model (single GPU)

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeJob
metadata:
  name: finetune-phi
  namespace: ml-team
spec:
  containers:
    trainer:
      image: my-registry/phi-finetune:v1
      command: ["python", "finetune.py", "--model=/models/microsoft/Phi-3-mini-4k-instruct"]
      resources:
        requests:
          cpu: "4"
          memory: 16Gi
  gpu:
    count: 1
    memory: 20Gi
  storage:
    output:
      size: 50Gi
      mountPath: /output
```

### Distributed Pre-Training (32 GPUs across 4 nodes)

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeJob
metadata:
  name: pretrain-7b
  namespace: ml-team
spec:
  containers:
    trainer:
      image: my-registry/pretrain:v2
      command:
        - torchrun
        - --nnodes=4
        - --nproc_per_node=8
        - train.py
      resources:
        requests:
          cpu: "64"
          memory: 512Gi
  gpu:
    count: 8
    model: H100
  workers: 4
  timeout: 72h
  storage:
    dataset:
      size: 2Ti
      storageClass: shared-nfs
      mountPath: /data
    output:
      size: 500Gi
      storageClass: local-nvme
      mountPath: /checkpoints
```

### Inference + Training on Same Cluster

```yaml
# Inference: always running, autoscaled
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: llama-70b-serve
spec:
  containers:
    vllm:
      image: vllm/vllm-openai:latest
      args: ["--model=/models/meta-llama/Llama-3.3-70B-Instruct", "--tensor-parallel-size=4"]
  gpu:
    count: 4
    model: H100
  replicas:
    min: 1
    max: 4
    autoscaling:
      - metric: vllm_num_requests_waiting
        target: 10
  service:
    ports:
      http:
        port: 8000
---
# Training: runs to completion, gang-scheduled
apiVersion: lattice.dev/v1alpha1
kind: LatticeJob
metadata:
  name: finetune-llama-customer-data
spec:
  containers:
    trainer:
      image: my-registry/llama-finetune:v3
      command: ["torchrun", "--nproc_per_node=4", "train.py"]
  gpu:
    count: 4
    model: H100
  timeout: 12h
  storage:
    output:
      size: 200Gi
      mountPath: /output
```

Both workload types share the same GPU cluster, same Volcano scheduler (with
HAMi plugin for fractional GPU placement), same model cache, same mesh policies.
Volcano ensures training jobs don't deadlock with inference workloads competing
for GPUs. No standalone HAMi scheduler is installed — the HAMi device plugin
DaemonSet handles runtime GPU isolation, and Volcano's HAMi plugin handles
scheduling decisions for both inference and training.
