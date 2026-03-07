# Reliability Layer

Feature ideas and relevant code locations for building a reliability layer into Lattice.

---

## GPU Loss Detection and Node Drain

### Problem

When GPUs disappear from a node (cable pulled, hardware failure, driver crash), the NVIDIA device plugin updates the node's `allocatable` resources, but Kubernetes does **not** reschedule already-running pods. The pods continue running with broken GPU access — they get device errors but are never evicted. Kubelet only does pressure-based eviction for memory/disk/PID, not for extended resources like `nvidia.com/gpu`.

### Feature Idea

A controller that watches nodes and compares each node's `allocatable` GPU count against the sum of `nvidia.com/gpu` requests from pods scheduled on that node. If `allocatable < requested`, cordon and drain the node so pods get rescheduled to healthy nodes.

**Core logic:**
```
for each node with nvidia.com/gpu > 0:
    allocatable_gpus = node.status.allocatable["nvidia.com/gpu"]
    requested_gpus   = sum(pod.spec.containers[*].resources.requests["nvidia.com/gpu"])
                       for all non-terminal pods on this node
    if allocatable_gpus < requested_gpus:
        cordon(node)
        drain(node)
```

**Considerations:**
- Should the controller uncordon a node if GPUs come back (e.g., driver recovery)?
- Drain should respect PodDisruptionBudgets to avoid cascading failures in distributed training jobs
- Volcano gang-scheduled jobs (VCJob) may need special handling — draining one pod in a gang could require restarting the entire job
- Emit a Kubernetes Event on the node when GPU loss is detected (visibility)
- Debounce: avoid reacting to transient blips (e.g., require the deficit to persist for N seconds before draining)

### Relevant Code

| File | What's there |
|------|-------------|
| `crates/lattice-common/src/resources.rs` | `GPU_RESOURCE` constant (`nvidia.com/gpu`), `GPU_TYPE_LABEL`, `parse_quantity_int()` for GPU counts, `gather_pool_resources()` which already lists nodes and sums pod GPU requests per pool — but aggregates per-pool, not per-node |
| `crates/lattice-common/src/resources.rs:216` | `gather_pod_allocations()` — builds a `node_name → pool_name` map and sums pod requests per pool. This is the closest existing code to per-node GPU accounting, just needs to track per-node instead of per-pool |
| `crates/lattice-common/src/resources.rs:38` | `is_node_ready()` — checks node Ready condition |
| `crates/lattice-common/src/crd/cluster.rs` | `PoolResourceSummary` — per-pool aggregate, could be extended or a new `NodeResourceSummary` created alongside it |
| `crates/lattice-cluster/src/controller/kube_client.rs` | `KubeClient` trait — would need new methods for cordon (`patch node spec.unschedulable`) and drain (evict pods). `get_ready_node_counts()` already lists all nodes |
| `crates/lattice-cluster/src/controller/pure.rs` | Pure decision functions pattern — GPU drain logic should follow this: a pure `determine_gpu_drain_action(allocatable, requested) -> DrainAction` function with exhaustive unit tests |
| `crates/lattice-operator/src/main.rs` | Controller startup — new controller would be added via `controller_runner` and included in the appropriate `SliceHandle` (likely `Service` slice since it's workload-level, or `All`) |
| `crates/lattice-agent/src/health.rs` | Cluster health gathering for heartbeats — already collects node conditions. GPU deficit could be reported upstream as a new condition |
| `crates/lattice-infra/src/bootstrap/gpu.rs` | GPU Operator + DCGM Exporter deployment — the GPU stack that provides the `nvidia.com/gpu` resource and metrics |
| `crates/lattice-common/src/resources.rs:29` | `is_control_plane_node()` — used to skip control plane nodes (GPU controller should also skip these) |

---

## DCGM Anomaly Detection — GRU Autoencoder with Cross-GPU Correlation

### Problem

GPU hardware failures rarely happen instantly. They develop over seconds to minutes — ECC errors accumulate, thermals creep up, NVLink connections flap, clocks throttle. Threshold-based alerts catch these eventually, but a multivariate anomaly model can detect degradation **5–20 minutes before hard failure**, giving the scheduler time to drain and reschedule cleanly.

DCGM metrics are well-suited for this: multivariate, highly correlated, mostly stationary with occasional spikes/failures.

### Feature Idea

A GRU autoencoder that learns normal GPU behavior per node, produces a continuous anomaly score, and feeds that score to the reliability controller as a drain/cordon signal.

**Architecture:**

```
DCGM metrics (per node)
     ↓
per-node aggregation + relative features
     ↓
time window (60s × N metrics)
     ↓
GRU autoencoder (Burn)
     ↓
reconstruction error → anomaly score
     ↓
EMA smoothing
     ↓
scheduler signal (cordon / drain)
```

### Why Cross-GPU Correlation Matters

Modeling each GPU independently misses the strongest signal: GPUs on the same node running the same workload should behave nearly identically. Deviation between them is often the earliest sign of failure.

**Normal state (8-GPU node, same training job):**

| GPU | Temp | Power | SM util |
|-----|------|-------|---------|
| 0   | 71   | 290W  | 95%     |
| 1   | 70   | 288W  | 94%     |
| 2   | 71   | 292W  | 95%     |
| 3   | 70   | 289W  | 95%     |

**Early degradation (GPU2 failing — absolute thresholds haven't fired yet):**

| GPU | Temp   | Power    | SM util |
|-----|--------|----------|---------|
| 0   | 71     | 290W     | 95%     |
| 1   | 70     | 288W     | 94%     |
| 2   | **78** | **250W** | **81%** |
| 3   | 70     | 289W     | 95%     |

Relative features make this obvious:

```
GPU0: temp_delta = +0.5C
GPU1: temp_delta = -0.3C
GPU2: temp_delta = +7.8C   ← anomaly
GPU3: temp_delta = -0.2C
```

### Feature Pipeline

**Raw DCGM metrics per GPU (~15 features):**

```
DCGM_FI_DEV_GPU_TEMP          (temperature.gpu)
DCGM_FI_DEV_MEMORY_TEMP       (temperature.memory)
DCGM_FI_DEV_POWER_USAGE       (power.draw)
DCGM_FI_DEV_POWER_LIMIT       (power.limit — for derived ratio)
DCGM_FI_DEV_GPU_UTIL          (sm.utilization)
DCGM_FI_DEV_MEM_COPY_UTIL     (mem.copy.util)
DCGM_FI_DEV_FB_USED           (mem.used)
DCGM_FI_DEV_FB_FREE           (mem.free)
DCGM_FI_DEV_PCIE_TX_THROUGHPUT (pcie.tx_bytes)
DCGM_FI_DEV_PCIE_RX_THROUGHPUT (pcie.rx_bytes)
DCGM_FI_DEV_SM_CLOCK          (sm.clock)
DCGM_FI_DEV_MEM_CLOCK         (mem.clock)
DCGM_FI_DEV_ECC_SBE_VOL_TOTAL (ecc.corrected)
DCGM_FI_DEV_ECC_DBE_VOL_TOTAL (ecc.uncorrected)
DCGM_FI_DEV_PCIE_REPLAY_COUNTER (pcie.replay)
```

**Derived features (per GPU):**

```
thermal_margin  = throttle_temp - gpu_temp
power_ratio     = power_draw / power_limit
memory_pressure = fb_used / (fb_used + fb_free)
```

**Relative features (per GPU, relative to node):**

```
temp_delta      = gpu_temp - mean(node_gpu_temps)
power_delta     = gpu_power - mean(node_gpu_powers)
sm_util_delta   = gpu_sm_util - mean(node_sm_utils)
mem_util_delta  = gpu_mem_util - mean(node_mem_utils)
clock_delta     = gpu_sm_clock - mean(node_sm_clocks)
pcie_delta      = gpu_pcie_tx - mean(node_pcie_tx)
```

Total: ~20 features per GPU after transforms.

**Also include node-level metrics** (some GPU anomalies are actually host issues):

```
cpu_util
ram_pressure
pcie_errors (host-level)
nvlink_bandwidth
```

### Model Architecture

**GRU autoencoder** (chosen over LSTM — ~30% less memory, simpler training, similar accuracy for this signal type):

```
input window (60 × ~20 features)
        ↓
GRU encoder (hidden=128, layers=2)
        ↓
latent vector
        ↓
GRU decoder (hidden=128, layers=2)
        ↓
reconstructed window (60 × ~20 features)
        ↓
MSE reconstruction error → anomaly score
```

**Implementation: Burn (Rust ML framework)**

- Native Rust, no Python dependency in the operator binary
- GPU and CPU backends (inference can run on CPU if needed)
- Fits the existing all-Rust codebase

### Windowing

```
sample rate: 1 second
window size: 60 samples (1 minute of history)
```

Most GPU failures develop over seconds to minutes — 60s window captures the temporal signature.

### Anomaly Score

```
score = mean((input - reconstruction)²)
smoothed_score = EMA(score, alpha=0.1)
```

**Thresholds:**

```
score < 0.3 → normal
0.3–0.6    → warning (emit event, log)
> 0.6      → unhealthy (cordon + drain)
```

Scheduler triggers drain when `smoothed_score > threshold` for N consecutive windows (prevents noisy rescheduling).

### Training Strategy

**Train on healthy GPUs only.** The autoencoder learns normal behavior — exclude from training data:

- GPUs with ECC errors during the window
- GPUs during job startup spikes
- GPUs during node reboot

**One model per GPU architecture** (behavior varies across SKUs):

```
A100 model
H100 model
L40 model
```

GPU architecture is available via `nvidia.com/gpu.product` NFD label (already used in `GPU_TYPE_LABEL`).

**Training data:** ~1–2 days of normal metrics per node is sufficient.

### Memory Requirements

For a typical node (8 GPUs, 20 features, 60s window, hidden=128, layers=2):

```
Training:  ~400–700 MB GPU memory
Inference: <50 MB
```

8 GB GPUs are more than sufficient. Inference can run on CPU for nodes without spare GPU capacity.

### Latent Vector Logging

Log the encoder's latent vector — it's a compact embedding of GPU health state. Enables:

- **HDBSCAN clustering** to discover new failure modes automatically
- **Failure mode classification** after the fact
- **Fleet-wide health dashboards** using dimensionality reduction (UMAP/t-SNE on latent vectors)

### Failure Modes Detected

| Failure type | Metric pattern | Detection mechanism |
|-------------|---------------|---------------------|
| Thermal throttling | temperature ↑ then clocks ↓ | Cross-metric correlation breaks |
| Power limit throttling | power cap events, clock reduction | Power/clock ratio anomaly |
| ECC degradation | corrected errors increasing over time | Drift detection in temporal window |
| Memory instability | memory errors + page retirement | ECC features spike |
| PCIe issues | bandwidth drops, replay errors rising | PCIe feature deviation from node mean |
| NVLink degradation | one GPU's NVLink metrics diverge from peers | Cross-GPU correlation breaks |
| Cooling failure | all GPUs on node trending hot together | Node-level thermal drift |
| SM stalls | SM occupancy drops relative to peers | SM util delta from node mean |
| GPU falling off bus | all metrics go to zero or stale | Reconstruction error spikes (learned pattern doesn't include "dead GPU") |

### Considerations

- **Dependency:** Requires the DCGM metrics pipeline from `docs/design/gpu-observability.md` (VMPodScrape → VictoriaMetrics) or direct DCGM Exporter scraping
- **Where to run inference:** As a sidecar on each GPU node (lowest latency, distributed) vs centralized in the operator (simpler deployment). Sidecar is preferred for reaction speed
- **Model updates:** Retrain periodically as workload patterns change. Could run training as a LatticeJob on the cluster itself
- **Interaction with threshold-based reactions:** The anomaly model is complementary to hard thresholds. XID 79 (GPU off bus) and double-bit ECC should still trigger immediate drain regardless of model score. The model catches the cases thresholds miss — subtle degradation and cross-GPU correlation breakdown
- **TCN alternative:** For very large fleets (tens of thousands of GPUs), Temporal CNN may be preferable to GRU — faster inference, better GPU utilization, handles bursts well

### Relevant Code

| File | What's there |
|------|-------------|
| `docs/design/gpu-observability.md` | DCGM metric collection pipeline design — defines which metrics are available and how they flow into VictoriaMetrics |
| `crates/lattice-infra/src/bootstrap/gpu.rs` | GPU Operator + DCGM Exporter deployment. New crate would need to consume metrics from the same DCGM Exporter instances |
| `crates/lattice-common/src/resources.rs` | `GPU_TYPE_LABEL` (`nvidia.com/gpu.product`) — used to select per-architecture model |
| `crates/lattice-common/src/resources.rs:127` | `gather_pool_resources()` — lists all nodes, groups by pool. Similar enumeration needed but per-node with DCGM metric join |
| `crates/lattice-volcano/` | Volcano integration — gang scheduling awareness needed when deciding drain vs pod-delete |
| `crates/lattice-job/src/controller.rs` | VCJob lifecycle — after a drain-triggered failure, the job controller handles resubmission if `maxRetry > 0` |
| `crates/lattice-cluster/src/controller/pure.rs` | Pure decision function pattern — anomaly score → action mapping should be a pure function |
| `crates/lattice-agent/src/health.rs` | Heartbeat enrichment — anomaly scores per node could be reported to parent cluster |
| `Cargo.toml` (new) | New `lattice-reliability` crate with `burn` dependency for GRU autoencoder |
