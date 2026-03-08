# GPU Workloads

Lattice provides GPU infrastructure management including health monitoring, anomaly detection, and intelligent scheduling decisions.

## Enabling GPU Support

Set `gpu: true` in your LatticeCluster spec:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: gpu-cluster
  namespace: lattice-system
spec:
  providerRef: aws-prod
  nodes:
    controlPlane:
      replicas: 3
    workerPools:
      gpu:
        replicas: 4
        instanceType:
          name: p3.8xlarge
        labels:
          workload-type: gpu
          nvidia.com/gpu.product: Tesla-V100
        taints:
          - key: nvidia.com/gpu
            effect: NoSchedule
  gpu: true
```

This installs:
- NVIDIA GPU Operator (includes Node Feature Discovery, device plugin, and DCGM exporter)
- Lattice GPU Monitor DaemonSet on all GPU nodes

## GPU Health Monitoring

The `lattice-gpu-monitor` DaemonSet runs on every node with `nvidia.com/gpu.present: true` and continuously monitors GPU health.

### DCGM Metrics Collection

The monitor scrapes the NVIDIA DCGM exporter every second, collecting 15 raw metrics per GPU:

| Category | Metrics |
|----------|---------|
| Temperature | `gpu_temp`, `memory_temp` |
| Power | `power_usage` |
| Utilization | `gpu_util`, `mem_copy_util` |
| Memory | `fb_used`, `fb_free` |
| PCIe | `pcie_tx`, `pcie_rx`, `pcie_replay` |
| Clocks | `sm_clock`, `mem_clock` |
| Errors | `ecc_sbe`, `ecc_dbe`, `xid_errors` |

### Anomaly Detection Pipeline

Collected metrics pass through a four-stage pipeline:

1. **Feature extraction**: 15 raw metrics + 3 derived features + 6 cross-GPU relative features = 24 features per GPU
2. **Sliding window**: 60-second window of 1-second samples
3. **Online GRU autoencoder**: Trains online, learning normal behavior patterns. Requires ~30 minutes of warmup before scoring starts.
4. **EMA-smoothed scoring**: Reconstruction error is smoothed to prevent false positives from transient spikes

### Health States

| State | Score | Meaning |
|-------|-------|---------|
| `Normal` | < 0.5 | GPU operating within normal parameters |
| `Warning` | 0.5 – 0.8 | Anomalous behavior detected, monitoring closely |
| `Unhealthy` | ≥ 0.8 (3+ consecutive) | Persistent anomaly, cordon recommended |

The hysteresis mechanism requires 3 consecutive unhealthy scores before declaring a GPU unhealthy, preventing flapping from transient spikes.

### GPU Loss Detection

In addition to anomaly detection, the monitor detects complete GPU failures:

- **Hard loss**: Node's `status.allocatable` GPU count drops to 0 (detected via 10-second polling)
- **Ghost GPU**: DCGM-reported GPU count drops mid-session (driver/device plugin instability)

### Node Annotations

The GPU monitor writes these annotations to the node every second:

| Annotation | Example | Purpose |
|-----------|---------|---------|
| `lattice.dev/gpu-anomaly-score` | `"0.3421"` | EMA-smoothed anomaly score |
| `lattice.dev/gpu-health` | `"normal"` | Discrete health state |
| `lattice.dev/gpu-loss-detected` | `"false"` | Hard GPU loss flag |
| `lattice.dev/gpu-monitor-heartbeat` | RFC 3339 timestamp | Monitor liveness |

## Automatic Cordon/Uncordon

The cluster controller monitors GPU node annotations and makes cordoning decisions.

### Cordon Triggers

A node is cordoned (prevented from receiving new pods) when:
- GPU loss is detected (`lattice.dev/gpu-loss-detected: "true"`)
- Health is `"unhealthy"`
- Health is `"warning"`

A node is **not** cordoned when:
- Heartbeat is older than 120 seconds (treated as stale data)
- No heartbeat annotation exists (monitor not yet running)

### Cordon Threshold

A maximum of 50% of GPU nodes can be cordoned at any time. When the threshold is reached:

- New cordons are suppressed
- Cordons are prioritized by anomaly score (highest confidence problems first)
- If pending GPU pods need scheduling, the node with the lowest anomaly score and sufficient GPUs is uncordoned

### Automatic Recovery

Cordoned nodes with health returning to `"normal"` are automatically uncordoned.

### No Automatic Draining

Draining (evicting running pods) is intentionally not automated. If GPUs are truly failed, workloads fail naturally. This prevents unnecessary data loss from false positives. Operators should investigate cordoned nodes and make manual drain decisions.

## GPU Resource Requests

Request GPU resources in your workload spec:

```yaml
workload:
  containers:
    main:
      image: my-registry.io/ml-training:latest
      resources:
        requests:
          nvidia.com/gpu: "4"
          cpu: "16"
          memory: 128Gi
```

GPU nodes should have taints to prevent non-GPU workloads from scheduling:

```yaml
taints:
  - key: nvidia.com/gpu
    effect: NoSchedule
```

GPU workloads must tolerate this taint (handled automatically by Kubernetes when requesting `nvidia.com/gpu` resources).

## Distributed Training with GPUs

For multi-node GPU training, use LatticeJob:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeJob
metadata:
  name: train-model
  namespace: default
spec:
  schedulerName: volcano
  minAvailable: 4
  training:
    framework: PyTorch
    coordinatorTask: master
    nccl:
      netIf: eth0
      gdr: true
      debug: WARN
  tasks:
    master:
      replicas: 1
      workload:
        containers:
          main:
            image: my-registry.io/train:latest
            resources:
              requests:
                nvidia.com/gpu: "8"
                cpu: "32"
                memory: 256Gi
    worker:
      replicas: 3
      workload:
        containers:
          main:
            image: my-registry.io/train:latest
            resources:
              requests:
                nvidia.com/gpu: "8"
                cpu: "32"
                memory: 256Gi
```

The training config automatically injects:
- `MASTER_ADDR`, `MASTER_PORT` for PyTorch distributed
- `WORLD_SIZE`, `RANK`, `LOCAL_RANK`
- NCCL configuration variables (`NCCL_SOCKET_IFNAME`, `NCCL_NET_GDR_ENABLE`, `NCCL_DEBUG`)

## GPU Model Serving

For LLM inference on GPUs, see [Service Deployment — LatticeModel](./service-deployment.md#latticemodel).

## Monitoring GPU Health

Check GPU health across nodes:

```bash
# View GPU annotations on all nodes
kubectl get nodes -l nvidia.com/gpu.present=true \
  -o custom-columns=NAME:.metadata.name,HEALTH:.metadata.annotations.lattice\.dev/gpu-health,SCORE:.metadata.annotations.lattice\.dev/gpu-anomaly-score,LOSS:.metadata.annotations.lattice\.dev/gpu-loss-detected

# Check for cordoned GPU nodes
kubectl get nodes -l nvidia.com/gpu.present=true \
  -o custom-columns=NAME:.metadata.name,SCHEDULABLE:.spec.unschedulable
```
