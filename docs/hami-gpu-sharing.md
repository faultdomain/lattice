# Lattice GPU Support v1

> **GPU virtualization, fractional sharing, and model caching for LatticeService workloads.**
>
> Clusters with `gpu: enabled` get the full GPU stack automatically: NVIDIA GPU Operator,
> HAMi device virtualization, model caching, and GPU-aware metrics. Any LatticeService on
> these clusters can request full or fractional GPU resources with a single `gpu:` field.

---

## Problem

Lattice's `ResourceQuantity` only supports `cpu` and `memory`:

```rust
// crates/lattice-common/src/crd/service.rs:510-519
pub struct ResourceQuantity {
    pub cpu: Option<String>,
    pub memory: Option<String>,
}
```

A LatticeService cannot request GPU resources. Even if the cluster has NVIDIA GPUs and the device plugin is installed, there's no way to express "give me a GPU" in a LatticeService spec. And even if we added basic `nvidia.com/gpu: 1` support, that claims an entire GPU — wasteful for workloads that need a fraction of one.

## Solution

1. Extend `LatticeService` with a `gpu` field for intuitive GPU targeting
2. On `gpu: enabled` clusters, automatically deploy the full GPU infrastructure stack
3. The service compiler translates the `gpu` spec into the correct K8s primitives — full GPUs, HAMi fractional slices, shared memory, tolerations, model mounts, and runtimeClass

---

## v1 Infrastructure Stack

Everything below is deployed automatically on clusters with `gpu: enabled`. No manual setup.

```
┌─────────────────────────────────────────────────────────┐
│  What the user writes                                    │
│  LatticeService with gpu: {count: 1, memory: 20Gi}     │
└──────────────────────┬──────────────────────────────────┘
                       │ compiled by service compiler
┌──────────────────────▼──────────────────────────────────┐
│  Layer 3: Scheduling + Sharing            ADOPT (CNCF)  │
│  ┌──────────────────────────────────────────────┐       │
│  │ HAMi (CNCF Sandbox)                          │       │
│  │ - Scheduler extender (bin-packing GPU slices)│       │
│  │ - Mutating webhook (device annotations)      │       │
│  │ - In-container CUDA interception (isolation) │       │
│  └──────────────────────────────────────────────┘       │
├─────────────────────────────────────────────────────────┤
│  Layer 2: Observability                   ADOPT + CONFIG│
│  ┌────────────────────┐  ┌──────────────────────┐      │
│  │ DCGM Exporter      │  │ KEDA                  │      │
│  │ (GPU Operator)     │  │ vLLM → ScaledObject    │      │
│  │ GPU util, mem,     │  │ triggers for scaling  │      │
│  │ temp, ECC errors   │  │                       │      │
│  └────────────────────┘  └──────────────────────┘      │
├─────────────────────────────────────────────────────────┤
│  Layer 1: Model Delivery                  BUILD (small) │
│  ┌──────────────────────────────────────────────┐      │
│  │ Model Cache DaemonSet                        │      │
│  │ Pre-pulls model weights to node-local storage│      │
│  │ LatticeService pods mount read-only          │      │
│  └──────────────────────────────────────────────┘      │
├─────────────────────────────────────────────────────────┤
│  Layer 0: Device Management               ADOPT (NVIDIA)│
│  ┌──────────────────────────────────────────────┐      │
│  │ NVIDIA GPU Operator                          │      │
│  │ - Driver Manager (kernel-matched drivers)    │      │
│  │ - Device Plugin (nvidia.com/gpu resource)    │      │
│  │ - Container Toolkit (containerd runtime)     │      │
│  │ - GPU Feature Discovery (node labels)        │      │
│  │ - DCGM (telemetry daemon)                    │      │
│  └──────────────────────────────────────────────┘      │
├─────────────────────────────────────────────────────────┤
│  Already installed by Lattice                            │
│  Cilium, Istio ambient, cert-manager, Lattice agent     │
└─────────────────────────────────────────────────────────┘
```

### Bill of Materials

| Component | Source | What We Do | Effort |
|---|---|---|---|
| **NVIDIA GPU Operator** | Adopt (Helm) | Generate manifests, apply via agent | Manifest generation |
| **HAMi** | Adopt (CNCF Sandbox, Helm) | Generate manifests, apply via agent | Manifest generation |
| **Model Cache DaemonSet** | Build | DaemonSet + config on cluster spec | ~200 lines |
| **KEDA** | Adopt + config | Deploy with vLLM ScaledObject triggers | Helm + ScaledObject |
| **`gpu:` on LatticeServiceSpec** | Build | CRD struct + compiler changes | Core feature |
| **SHM / runtimeClass / mounts** | Build | Compiler generates pod spec correctly | Compiler changes |

---

## What HAMi Does

HAMi (Heterogeneous AI Computing Virtualization Middleware) is a CNCF Sandbox project that virtualizes GPUs at the device level. It consists of:

- **Scheduler extender** — intercepts pod scheduling to bin-pack GPU slices
- **Mutating webhook** — injects device annotations into pod specs
- **In-container virtualization** — LD_PRELOAD interception of CUDA/ROCm calls that enforces memory and compute limits inside the container

The result: a pod requesting 20GB of an 80GB H100 sees only 20GB. It cannot allocate beyond its slice. No application changes. vLLM, PyTorch, TensorRT — all work transparently.

```
Without HAMi:
┌─────────────────────────────────┐
│  H100 80GB                      │
│  Pod A: nvidia.com/gpu: 1       │
│  → Sees 80GB, uses 16GB         │
│  → 64GB wasted                  │
│  → No other pod can schedule    │
└─────────────────────────────────┘

With HAMi:
┌─────────────────────────────────┐
│  H100 80GB                      │
│  Pod A: 20GB / 30% compute      │
│  Pod B: 16GB / 25% compute      │
│  Pod C: 16GB / 25% compute      │
│  (28GB / 20% compute free)      │
│  Each pod sees ONLY its slice   │
└─────────────────────────────────┘
```

---

## LatticeCluster GPU Configuration

Clusters opt into GPU support via the `gpu` field on `LatticeClusterSpec`:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: gpu-cluster
spec:
  providerRef: aws-us-east-1
  nodes:
    controlPlane: 3
    workerPools:
      gpu:
        replicas: 4
        nodeClass: p5.48xlarge
        labels:
          nvidia.com/gpu: "true"
        taints:
          - key: nvidia.com/gpu
            effect: NoSchedule

  gpu:
    enabled: true                       # Install GPU Operator + HAMi
    operatorVersion: "v24.9.0"         # Optional: pin GPU Operator version
    hamiVersion: "v2.5.0"             # Optional: pin HAMi version
    sharing:                            # HAMi defaults
      defaultMemoryLimit: 0             # 0 = no default limit (full GPU)
      defaultComputeLimit: 0            # 0 = no default limit
    modelCache:                         # Optional: pre-warm models
      storage: 500Gi
      storageClass: local-nvme
      models:
        - source: huggingface
          name: meta-llama/Llama-3.3-70B-Instruct
        - source: s3
          uri: s3://my-models/custom-fine-tune/
          secretRef: model-s3-creds
```

### Bootstrap Sequence

When `gpu.enabled: true`, the cluster controller adds GPU infrastructure to the existing provisioning flow. No new protocol messages — it uses the same `ApplyManifestsCommand` the agent already handles.

```
1. Agent connects to cell (existing)
2. Cell sends ApplyManifestsCommand:
   a. Cilium CNI                        (existing)
   b. Istio ambient mesh                (existing)
   c. NVIDIA GPU Operator               ← NEW (gpu.enabled)
   d. HAMi                              ← NEW (gpu.enabled)
   e. Model Cache DaemonSet             ← NEW (gpu.modelCache)
   f. KEDA + vLLM ScaledObject triggers ← NEW (gpu.enabled)
3. Cell sends SyncDistributedResourcesCommand (existing)
4. Pivot CAPI resources (existing)
```

### HAMi Helm Values (generated)

```yaml
scheduler:
  defaultMem: 0                         # From spec.gpu.sharing.defaultMemoryLimit
  defaultCores: 0                       # From spec.gpu.sharing.defaultComputeLimit
devicePlugin:
  nvidia:
    enabled: true
resourceName: "nvidia.com/gpu"
```

### Model Cache DaemonSet

A DaemonSet on GPU nodes that downloads model weights to node-local storage.
LatticeService pods mount the same path read-only.

```
GPU Node
┌────────────────────────────────────────────┐
│  /var/lattice/models/  (hostPath or local PV)
│  ├── meta-llama/Llama-3.3-70B-Instruct/   │
│  ├── microsoft/Phi-3-mini-4k-instruct/     │
│  └── custom/my-fine-tune/                  │
│                                            │
│  model-cache DaemonSet:                    │
│    Watches config, downloads missing models│
│                                            │
│  vLLM pod A: mounts /models (read-only)    │
│  vLLM pod B: mounts /models (read-only)    │
└────────────────────────────────────────────┘
```

### KEDA ScaledObject Config (generated)

Enables scaling on vLLM inference metrics via KEDA Prometheus triggers:

```yaml
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: vllm-scaledobject
spec:
  scaleTargetRef:
    name: <deployment>
  triggers:
    - type: prometheus
      metadata:
        serverAddress: http://prometheus.monitoring.svc:9090
        metricName: vllm_queue_depth
        query: sum(vllm:num_requests_waiting{namespace="<ns>"})
        threshold: "5"
    - type: prometheus
      metadata:
        serverAddress: http://prometheus.monitoring.svc:9090
        metricName: vllm_ttft_seconds
        query: avg(vllm:time_to_first_token_seconds{namespace="<ns>"})
        threshold: "2"
```

---

## LatticeService GPU Spec Design

### User-Facing YAML

The `gpu` field lives at the top level of `LatticeServiceSpec`, alongside `containers`, `resources`, `replicas`, etc. It applies to all containers in the pod (GPUs are a pod-level resource in Kubernetes).

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: llama-8b
  namespace: inference
spec:
  containers:
    vllm:
      image: vllm/vllm-openai:v0.6.6
      args: ["--model", "meta-llama/Llama-3.1-8B-Instruct", "--port", "8000"]
      resources:
        requests:
          cpu: "4"
          memory: 32Gi

  gpu:
    count: 1                         # Number of GPUs (or GPU slices)
    memory: 20Gi                     # GPU memory per GPU (HAMi enforced)
    # compute: 30                    # Optional: % of streaming multiprocessors

  service:
    ports:
      http:
        port: 8000

  replicas:
    min: 1
```

### Shorthand Forms

```yaml
# Full GPU (no sharing) — simplest case
gpu:
  count: 1

# Multiple full GPUs (tensor parallelism)
gpu:
  count: 4

# Fractional GPU (HAMi sharing)
gpu:
  count: 1
  memory: 20Gi

# Fractional with compute limit
gpu:
  count: 1
  memory: 20Gi
  compute: 30

# Specific GPU model (node selector)
gpu:
  count: 2
  model: H100
```

### Advanced Options

```yaml
gpu:
  count: 4
  memory: 80Gi                      # Per-GPU memory (omit = full GPU)
  compute: 100                       # Per-GPU SM% (omit = no limit)
  model: H100                        # GPU model selector (omit = any)
  shared: false                      # Explicitly disable sharing (full GPU only)
  tolerations: true                  # Auto-add nvidia.com/gpu toleration (default: true)
```

---

## CRD Changes

### New Types in `lattice-common/src/crd/service.rs`

```rust
/// GPU resource specification for a LatticeService
///
/// Defines GPU requirements for the workload. When `memory` or `compute` are
/// specified, HAMi handles fractional GPU sharing with hard isolation.
/// When only `count` is specified, full GPUs are allocated via the standard
/// NVIDIA device plugin.
///
/// ## Examples
///
/// ```yaml
/// # Full GPU
/// gpu:
///   count: 1
///
/// # Fractional GPU (HAMi)
/// gpu:
///   count: 1
///   memory: 20Gi
///   compute: 30
///
/// # Multi-GPU with model selection
/// gpu:
///   count: 4
///   model: H100
/// ```
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GPUSpec {
    /// Number of GPUs (or GPU slices when sharing is enabled)
    pub count: u32,

    /// GPU memory limit per GPU (e.g., "20Gi", "40960")
    ///
    /// When specified, HAMi enforces this as a hard memory limit inside the
    /// container. The container's CUDA runtime sees only this much memory.
    /// Omit for full GPU memory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,

    /// Percentage of GPU streaming multiprocessors (0-100) per GPU
    ///
    /// When specified, HAMi limits the container to this percentage of
    /// compute cores. Omit for no compute limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compute: Option<u32>,

    /// GPU model selector (e.g., "H100", "A100", "L40S")
    ///
    /// Maps to a node selector: `nvidia.com/gpu.product: <model>`.
    /// Omit to schedule on any available GPU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,

    /// Explicitly disable GPU sharing (request full dedicated GPUs)
    ///
    /// When `true`, the workload gets `count` full GPUs via the standard
    /// NVIDIA device plugin, bypassing HAMi even if installed.
    /// Default: `false` (HAMi sharing enabled when memory/compute are set).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub shared: Option<bool>,

    /// Automatically add tolerations for GPU node taints (default: true)
    ///
    /// When true, the compiler adds `nvidia.com/gpu: NoSchedule` toleration
    /// so the pod can schedule on GPU-tainted nodes.
    #[serde(default = "default_true")]
    pub tolerations: bool,
}

impl GPUSpec {
    /// Returns true if this spec requires HAMi (fractional sharing)
    pub fn needs_hami(&self) -> bool {
        self.memory.is_some() || self.compute.is_some()
    }

    /// Returns true if full dedicated GPUs are requested (no sharing)
    pub fn is_full_gpu(&self) -> bool {
        !self.needs_hami() || self.shared == Some(true)
    }

    /// Validate the GPU spec
    pub fn validate(&self) -> Result<(), String> {
        if self.count == 0 {
            return Err("gpu.count must be greater than 0".to_string());
        }
        if let Some(compute) = self.compute {
            if compute == 0 || compute > 100 {
                return Err("gpu.compute must be between 1 and 100".to_string());
            }
        }
        if self.shared == Some(true) && (self.memory.is_some() || self.compute.is_some()) {
            return Err(
                "gpu.shared: true is incompatible with gpu.memory/gpu.compute (those require HAMi sharing)"
                    .to_string(),
            );
        }
        Ok(())
    }
}
```

### Extend LatticeServiceSpec

```rust
pub struct LatticeServiceSpec {
    pub containers: BTreeMap<String, ContainerSpec>,
    pub resources: BTreeMap<String, ResourceSpec>,
    pub service: Option<ServicePortsSpec>,
    pub replicas: ReplicaSpec,
    pub deploy: DeploySpec,
    pub ingress: Option<IngressSpec>,
    pub sidecars: BTreeMap<String, SidecarSpec>,
    pub sysctls: BTreeMap<String, String>,
    pub host_network: Option<bool>,
    pub share_process_namespace: Option<bool>,

    // NEW
    /// GPU resource requirements
    ///
    /// When specified, the service compiler adds GPU resources to the pod spec.
    /// If `memory` or `compute` are set, HAMi handles fractional sharing.
    /// Otherwise, full GPUs are allocated via the NVIDIA device plugin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<GPUSpec>,
}
```

### Extend LatticeClusterSpec

```rust
/// GPU infrastructure configuration for a cluster
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GPUClusterSpec {
    /// Enable GPU infrastructure (GPU Operator + HAMi + DCGM + KEDA)
    pub enabled: bool,

    /// NVIDIA GPU Operator version (optional, uses default if omitted)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_version: Option<String>,

    /// HAMi version (optional, uses default if omitted)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hami_version: Option<String>,

    /// HAMi sharing defaults
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sharing: Option<GPUSharingDefaults>,

    /// Model cache configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_cache: Option<ModelCacheSpec>,
}

/// HAMi default sharing limits
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GPUSharingDefaults {
    /// Default GPU memory limit (0 = no limit, full GPU)
    #[serde(default)]
    pub default_memory_limit: u64,

    /// Default GPU compute limit (0 = no limit, 1-100 = % of SMs)
    #[serde(default)]
    pub default_compute_limit: u32,
}

/// Model cache configuration for pre-warming model weights
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelCacheSpec {
    /// Storage size for model cache (e.g., "500Gi")
    pub storage: String,

    /// Storage class for the cache volume
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,

    /// Models to pre-warm
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<CachedModel>,
}

/// A model to pre-warm in the cache
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CachedModel {
    /// Model source: "huggingface" or "s3"
    pub source: String,

    /// Model name (HuggingFace) or URI (S3)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// S3 URI (when source is "s3")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,

    /// HuggingFace revision (default: "main")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,

    /// Secret reference for credentials
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<String>,
}
```

---

## Service Compiler Changes

The `WorkloadCompiler` must generate six things when `gpu:` is present:

### 1. GPU Resource Limits (on primary container)

```yaml
# Full GPU: gpu: {count: 2}
resources:
  limits:
    nvidia.com/gpu: "2"

# HAMi fractional: gpu: {count: 1, memory: 20Gi, compute: 30}
resources:
  limits:
    nvidia.com/gpu: "1"
    nvidia.com/gpumem: "20480"          # MiB (HAMi)
    nvidia.com/gpucores: "30"           # % of SMs (HAMi)
```

### 2. Shared Memory Volume (when count > 1)

Multi-GPU tensor parallelism requires large `/dev/shm` for NCCL inter-process communication. Default K8s gives 64MB. A 70B model needs 16-64GB.

```yaml
# Generated when gpu.count > 1
volumes:
  - name: shm
    emptyDir:
      medium: Memory
      sizeLimit: 64Gi
containers:
  - volumeMounts:
      - name: shm
        mountPath: /dev/shm
```

### 3. RuntimeClass

GPU Operator configures the `nvidia` RuntimeClass. The compiler sets it on GPU pods:

```yaml
spec:
  runtimeClassName: nvidia
```

### 4. Model Cache Mount (when cluster has modelCache)

When the cluster has `gpu.modelCache` configured, the compiler auto-mounts the cache path:

```yaml
volumes:
  - name: model-cache
    hostPath:
      path: /var/lattice/models
      type: Directory
containers:
  - volumeMounts:
      - name: model-cache
        mountPath: /models
        readOnly: true
```

### 5. Tolerations

```yaml
# Generated when gpu.tolerations is true (default)
tolerations:
  - key: nvidia.com/gpu
    operator: Exists
    effect: NoSchedule
```

### 6. Node Selector (when model specified)

```yaml
# Generated when gpu.model is set
nodeSelector:
  nvidia.com/gpu.product: "NVIDIA-H100-80GB-HBM3"
```

### GPU Model Mapping

The `model` field accepts short names. The compiler maps them to NVIDIA's `gpu.product` label values (discovered by GPU Feature Discovery on nodes):

```rust
fn gpu_product_label(model: &str) -> String {
    match model.to_uppercase().as_str() {
        "H100" | "H100-SXM" => "NVIDIA-H100-80GB-HBM3".to_string(),
        "H100-PCIE" => "NVIDIA-H100-80GB-PCIe".to_string(),
        "A100" | "A100-SXM" => "NVIDIA-A100-SXM4-80GB".to_string(),
        "A100-PCIE" | "A100-40GB" => "NVIDIA-A100-PCIe-40GB".to_string(),
        "A100-80GB" => "NVIDIA-A100-PCIe-80GB".to_string(),
        "L40S" => "NVIDIA-L40S".to_string(),
        "L40" => "NVIDIA-L40".to_string(),
        "L4" => "NVIDIA-L4".to_string(),
        "T4" => "NVIDIA-Tesla-T4".to_string(),
        "V100" => "NVIDIA-Tesla-V100-SXM2-32GB".to_string(),
        // Pass through unknown models directly (user can use the full label value)
        other => other.to_string(),
    }
}
```

### Memory Unit Conversion

HAMi's `nvidia.com/gpumem` is in MiB (integers). The `gpu.memory` field accepts Kubernetes quantity format:

```rust
fn parse_gpu_memory_mib(memory: &str) -> Result<u64, String> {
    if let Some(gi) = memory.strip_suffix("Gi") {
        let val: u64 = gi.parse().map_err(|_| format!("invalid gpu memory: {memory}"))?;
        Ok(val * 1024)
    } else if let Some(mi) = memory.strip_suffix("Mi") {
        mi.parse().map_err(|_| format!("invalid gpu memory: {memory}"))
    } else {
        // Bare number = MiB
        memory.parse().map_err(|_| format!("invalid gpu memory: {memory}, use Gi or Mi suffix"))
    }
}
```

### Compiler Integration Points

In `WorkloadCompiler::compile_containers_with_volumes()` (workload/mod.rs:927), after the existing resource conversion:

```rust
// Existing: convert cpu/memory
let resources = container_spec.resources.as_ref().map(|r| ResourceRequirements {
    requests: r.requests.as_ref().map(|req| ResourceQuantity {
        cpu: req.cpu.clone(),
        memory: req.memory.clone(),
    }),
    limits: r.limits.as_ref().map(|lim| ResourceQuantity {
        cpu: lim.cpu.clone(),
        memory: lim.memory.clone(),
    }),
});

// NEW: merge GPU resources into limits (only for the first container)
let resources = if is_primary_container {
    merge_gpu_resources(resources, &spec.gpu)
} else {
    resources
};
```

In `WorkloadCompiler::compile_deployment()` (workload/mod.rs:1209), after building the pod spec:

```rust
if let Some(gpu) = &spec.gpu {
    // RuntimeClass
    pod_spec.runtime_class_name = Some("nvidia".to_string());

    // Tolerations
    if gpu.tolerations {
        pod_spec.tolerations.push(Toleration {
            key: Some("nvidia.com/gpu".to_string()),
            operator: Some("Exists".to_string()),
            effect: Some("NoSchedule".to_string()),
            ..Default::default()
        });
    }

    // Node selector for GPU model
    if let Some(model) = &gpu.model {
        pod_spec.node_selector
            .get_or_insert_with(BTreeMap::new)
            .insert("nvidia.com/gpu.product".to_string(), gpu_product_label(model));
    }

    // Shared memory for multi-GPU
    if gpu.count > 1 {
        pod_spec.volumes.push(Volume {
            name: "shm".to_string(),
            empty_dir: Some(EmptyDirVolumeSource {
                medium: Some("Memory".to_string()),
                size_limit: Some("64Gi".to_string()),
            }),
        });
        // Mount added to primary container in compile_containers_with_volumes
    }

    // Model cache mount (when cluster has modelCache configured)
    if cluster_has_model_cache {
        pod_spec.volumes.push(Volume {
            name: "model-cache".to_string(),
            host_path: Some(HostPathVolumeSource {
                path: "/var/lattice/models".to_string(),
                type_: Some("Directory".to_string()),
            }),
        });
    }
}
```

---

## Compilation Matrix

How the `gpu` spec maps to compiled K8s resources:

| `gpu` Field | K8s Output | Notes |
|---|---|---|
| `count: N` | `limits.nvidia.com/gpu: N` | Always present |
| `memory: XGi` | `limits.nvidia.com/gpumem: X*1024` | HAMi fractional, value in MiB |
| `compute: P` | `limits.nvidia.com/gpucores: P` | HAMi fractional, value is percentage |
| `model: H100` | `nodeSelector.nvidia.com/gpu.product: ...` | Maps short name to NFD label |
| `tolerations: true` | `tolerations: [{key: nvidia.com/gpu, ...}]` | Default behavior |
| `count > 1` | SHM volume (emptyDir Memory 64Gi) | Required for NCCL/tensor parallelism |
| (any gpu) | `runtimeClassName: nvidia` | Required for GPU container runtime |
| (cluster has modelCache) | hostPath `/var/lattice/models` | Read-only model weights mount |

### Decision Tree

```
gpu:
 ├── count only (no memory/compute)
 │   └── Full GPU mode
 │       ├── nvidia.com/gpu: <count>
 │       ├── runtimeClassName: nvidia
 │       ├── tolerations (if enabled)
 │       └── SHM volume (if count > 1)
 │
 ├── memory and/or compute set
 │   └── HAMi fractional mode
 │       ├── nvidia.com/gpu: <count>
 │       ├── nvidia.com/gpumem: <memory in MiB>
 │       ├── nvidia.com/gpucores: <compute %>
 │       ├── runtimeClassName: nvidia
 │       ├── tolerations (if enabled)
 │       └── SHM volume (if count > 1)
 │
 └── model set
     └── Add nodeSelector (either mode)
         └── nvidia.com/gpu.product: <mapped label>
```

---

## Validation Rules

| Rule | Error Message |
|---|---|
| `count == 0` | `gpu.count must be greater than 0` |
| `compute > 100` or `compute == 0` | `gpu.compute must be between 1 and 100` |
| `shared: true` with `memory` or `compute` | `gpu.shared: true is incompatible with gpu.memory/gpu.compute` |
| `memory` parse failure | `invalid gpu memory: <value>, use Gi or Mi suffix` |

Skip compile-time validation for "does this cluster have HAMi." Let Kubernetes reject the pod if HAMi isn't installed. The LatticeService status will reflect the scheduling failure. This avoids coupling the service compiler to cluster state.

---

## Examples

### Small Model Inference (shared GPU)

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: phi-3-mini
  namespace: ml-team
spec:
  containers:
    vllm:
      image: vllm/vllm-openai:v0.6.6
      args: ["--model", "microsoft/Phi-3-mini-4k-instruct", "--port", "8000"]
      resources:
        requests:
          cpu: "2"
          memory: 8Gi

  gpu:
    count: 1
    memory: 8Gi
    compute: 20

  service:
    ports:
      http:
        port: 8000

  replicas:
    min: 1
```

Three of these can share a single 24GB L4 GPU.

### Large Model Inference (full GPUs)

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: llama-70b
  namespace: ml-team
spec:
  containers:
    vllm:
      image: vllm/vllm-openai:v0.6.6
      args:
        - "--model=meta-llama/Llama-3.3-70B-Instruct"
        - "--tensor-parallel-size=4"
        - "--port=8000"
      resources:
        requests:
          cpu: "32"
          memory: 256Gi

  gpu:
    count: 4
    model: H100

  service:
    ports:
      http:
        port: 8000

  replicas:
    min: 1
```

### Embedding Service (tiny GPU slice)

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: embeddings
  namespace: search
spec:
  containers:
    model:
      image: ghcr.io/huggingface/text-embeddings-inference:1.5
      args: ["--model-id", "BAAI/bge-base-en-v1.5", "--port", "8080"]
      resources:
        requests:
          cpu: "1"
          memory: 2Gi

  gpu:
    count: 1
    memory: 2Gi
    compute: 10

  service:
    ports:
      http:
        port: 8080

  replicas:
    min: 2
    max: 8
```

Six of these fit on a single GPU with room to spare.

### GPU Workload with Bilateral Agreements

The `gpu` field composes naturally with all existing Lattice features:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: recommendation-model
  namespace: platform
spec:
  containers:
    model:
      image: my-registry/rec-model:v2
      resources:
        requests:
          cpu: "4"
          memory: 16Gi

  gpu:
    count: 1
    memory: 16Gi
    compute: 40

  resources:
    # Bilateral agreement: frontend can call this model
    frontend:
      type: service
      direction: inbound
      namespace: web

    # This model calls the feature store
    feature-store:
      type: service
      direction: outbound
      namespace: data

    # Model weights from Vault
    model-weights-creds:
      type: secret
      id: ml/model-registry/credentials
      params:
        provider: vault-prod
        keys: ["access_key", "secret_key"]

  service:
    ports:
      grpc:
        port: 50051

  replicas:
    min: 1
    max: 4
```

GPU sharing + bilateral service mesh + secrets management — all in one spec.

---

## Output K8s Manifest Reference

Complete compiled Deployment for a fractional GPU service on a cluster with model caching:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: phi-3-mini
  namespace: ml-team
  labels:
    lattice.dev/service: phi-3-mini
spec:
  replicas: 1
  selector:
    matchLabels:
      lattice.dev/service: phi-3-mini
  template:
    metadata:
      labels:
        lattice.dev/service: phi-3-mini
    spec:
      serviceAccountName: phi-3-mini
      runtimeClassName: nvidia
      containers:
        - name: vllm
          image: vllm/vllm-openai:v0.6.6
          args:
            - "--model"
            - "/models/microsoft/Phi-3-mini-4k-instruct"
            - "--port"
            - "8000"
          ports:
            - name: http
              containerPort: 8000
          resources:
            requests:
              cpu: "2"
              memory: 8Gi
            limits:
              nvidia.com/gpu: "1"
              nvidia.com/gpumem: "8192"
              nvidia.com/gpucores: "20"
          volumeMounts:
            - name: model-cache
              mountPath: /models
              readOnly: true
      volumes:
        - name: model-cache
          hostPath:
            path: /var/lattice/models
            type: Directory
      tolerations:
        - key: nvidia.com/gpu
          operator: Exists
          effect: NoSchedule
```

Complete compiled Deployment for a multi-GPU service (note SHM volume):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: llama-70b
  namespace: ml-team
  labels:
    lattice.dev/service: llama-70b
spec:
  replicas: 1
  selector:
    matchLabels:
      lattice.dev/service: llama-70b
  template:
    metadata:
      labels:
        lattice.dev/service: llama-70b
    spec:
      serviceAccountName: llama-70b
      runtimeClassName: nvidia
      containers:
        - name: vllm
          image: vllm/vllm-openai:v0.6.6
          args:
            - "--model=/models/meta-llama/Llama-3.3-70B-Instruct"
            - "--tensor-parallel-size=4"
            - "--port=8000"
          ports:
            - name: http
              containerPort: 8000
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
      volumes:
        - name: shm
          emptyDir:
            medium: Memory
            sizeLimit: 64Gi
        - name: model-cache
          hostPath:
            path: /var/lattice/models
            type: Directory
      nodeSelector:
        nvidia.com/gpu.product: "NVIDIA-H100-80GB-HBM3"
      tolerations:
        - key: nvidia.com/gpu
          operator: Exists
          effect: NoSchedule
```

---

## Implementation Plan

### Phase A: CRD + Compiler — Full GPUs

Add the `GPUSpec` struct and compiler support for full GPU allocation.
Works immediately on any cluster with the NVIDIA device plugin — no HAMi needed.

**Files to modify:**
1. `crates/lattice-common/src/crd/service.rs` — Add `GPUSpec`, extend `LatticeServiceSpec`
2. `crates/lattice-service/src/workload/mod.rs` — GPU resource limits, SHM volume, runtimeClass, tolerations, node selector, model cache mount

**Tests:**
- Unit: `GPUSpec::validate()` — all validation rules
- Unit: `parse_gpu_memory_mib()` — Gi, Mi, bare number, invalid
- Unit: `gpu_product_label()` — all known models + passthrough
- Compiler: `gpu: {count: 1}` → correct limits + toleration + runtimeClass
- Compiler: `gpu: {count: 4, model: H100}` → node selector + SHM volume
- Compiler: `gpu: {count: 4}` without model → SHM but no node selector

### Phase B: Cluster GPU Bootstrap

Install GPU Operator + HAMi + model cache + KEDA on `gpu: enabled` clusters.

**Files to modify:**
1. `crates/lattice-common/src/crd/cluster.rs` — Add `GPUClusterSpec`, `ModelCacheSpec`
2. `crates/lattice-cluster/src/phases/ready.rs` — Generate GPU Operator, HAMi, model cache, KEDA manifests
3. `crates/lattice-cluster/src/controller.rs` — Conditional manifest generation when `gpu.enabled`

**Tests:**
- Unit: manifest generation includes GPU Operator + HAMi when `gpu.enabled: true`
- Unit: manifest generation includes model cache DaemonSet when `gpu.modelCache` present
- Unit: manifest generation skips GPU infra when `gpu.enabled: false` or absent
- E2E: provision cluster with `gpu: enabled`, verify all GPU pods running

### Phase C: HAMi Fractional Sharing

Extend the compiler to emit HAMi resource annotations for fractional GPUs.

**Files to modify:**
1. `crates/lattice-service/src/workload/mod.rs` — Add `nvidia.com/gpumem` and `nvidia.com/gpucores` to resource limits when `memory`/`compute` are set

**Tests:**
- Compiler: `gpu: {count: 1, memory: 20Gi}` → `gpumem: 20480`
- Compiler: `gpu: {count: 1, memory: 20Gi, compute: 30}` → both HAMi resources
- Compiler: `gpu: {count: 1, memory: 8Gi}` → `gpumem: 8192`
- E2E: deploy two services sharing one GPU, verify memory isolation

### Phase D: CLI

Surface GPU info in CLI output.

**Files to modify:**
1. `crates/lattice-cli/src/commands/get/services.rs` — GPU column in service list
2. `crates/lattice-cli/src/commands/get/cluster.rs` — GPU section in cluster detail

**Output:**
```bash
lattice get services -n ml-team
# NAME                REPLICAS  GPU        PHASE   AGE
# phi-3-mini          1/1       1x 8Gi     Ready   2h
# llama-70b           1/1       4x H100    Ready   1d
# embeddings          2/2       1x 2Gi     Ready   5d

lattice get cluster gpu-cluster
# ...
# GPU:
#   Enabled: true
#   GPU Operator: v24.9.0
#   HAMi: v2.5.0
#   Model Cache: 3 models (287Gi / 500Gi)
```

---

## What v1 Does NOT Include

These are explicitly deferred. They build on v1 but are not required for it to ship.

| Deferred Feature | Why | When |
|---|---|---|
| **Kueue** | Single-team GPU clusters don't need queue management. Pods go Pending if no GPUs available — fine for v1. | v2: when multi-tenancy is needed |
| **GPUTenantQuota CRD** | No multi-tenancy in v1. | v2: with Kueue |
| **Multi-cluster placement** | v1 deploys to a specific cluster. User picks the cluster. | v2: control plane routes workloads |
| **`lattice serve` CLI command** | Convenience shortcut for generating LatticeService YAML from a model name. | v1.1: quality-of-life |
| **GPU health in agent heartbeat** | Nice for fleet visibility but not required for function. | v1.1: observability |
| **KV-cache-aware routing** | Optimizes inference latency across replicas (llm-d). | v2+: advanced inference |
| **OCI Image Volumes for models** | K8s alpha feature for mounting models as OCI artifacts. | When K8s promotes to GA |
