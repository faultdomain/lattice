# Lattice GPU PaaS: AI Inference Platform Roadmap

> **Building a multi-tenant GPU inference platform on top of Lattice's self-managing multi-cluster architecture.**

---

## Executive Summary

Lattice already solves the hardest problems in multi-cluster Kubernetes: self-managing clusters via CAPI pivoting, outbound-only networking, bilateral service mesh, Cedar-based authorization, and hierarchical API proxying. This document describes a path to extend Lattice into a GPU inference PaaS — a platform where tenants rent GPU capacity, deploy models, and serve inference traffic across a fleet of GPU clusters.

The core thesis: **Lattice manages the clusters. The GPU PaaS manages what runs on them.**

---

## What Lattice Provides Today

| Capability | How It Maps to GPU PaaS |
|---|---|
| **Self-managing clusters** (CAPI pivot) | GPU clusters operate independently; control plane outage doesn't stop inference |
| **Multi-provider** (AWS, Proxmox, OpenStack, Docker) | GPU clusters on any infrastructure with NVIDIA GPUs |
| **Outbound-only networking** (agent gRPC stream) | GPU clusters behind firewalls, no inbound attack surface |
| **Bilateral service mesh** (Cilium L4 + Istio L7) | Inference traffic isolation between tenants |
| **Cedar authorization** | Tenant access control for clusters, models, and secrets |
| **K8s API proxy** (hierarchical routing) | Manage GPU clusters through the hierarchy without direct access |
| **Secrets management** (ESO + Vault + Cedar) | Model registry credentials, API keys, tenant secrets |
| **LatticeService CRD** (Score-compatible workloads) | Foundation for InferenceEndpoint abstraction |
| **CloudProvider CRD** | GPU-specific cloud account configuration |
| **FIPS 140-2 cryptography** | Compliance for regulated industries |

---

## Target Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         CONTROL PLANE (Lattice Cell)                     │
│                                                                          │
│  ┌────────────────────────┐  ┌──────────────────────┐                   │
│  │  Lattice Operator       │  │  GPU PaaS Controller │                   │
│  │  (existing)             │  │  (new)               │                   │
│  │  - LatticeCluster       │  │  - GPUPool           │                   │
│  │  - LatticeService       │  │  - InferenceEndpoint │                   │
│  │  - CloudProvider        │  │  - GPUTenantQuota    │                   │
│  │  - CedarPolicy          │  │  - ModelRegistry     │                   │
│  │  - SecretsProvider      │  │  - Placement Engine  │                   │
│  └────────────────────────┘  └──────────────────────┘                   │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Aggregated GPU Inventory                                           │ │
│  │  - Real-time capacity across all clusters (via agent heartbeats)    │ │
│  │  - DCGM metrics: utilization, memory, temperature, ECC errors      │ │
│  │  - Kueue queue depth per cluster                                    │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
         ▲                    ▲                     ▲
         │ gRPC               │ gRPC                │ gRPC
         │                    │                     │
┌────────┴─────────┐ ┌───────┴──────────┐ ┌───────┴──────────────────────┐
│ GPU Cluster A     │ │ GPU Cluster B     │ │ GPU Cluster C               │
│ 8x H100 SXM      │ │ 8x A100 80GB     │ │ 4x L40S                     │
│                   │ │                   │ │                              │
│ ┌───────────────┐ │ │ ┌───────────────┐ │ │ ┌───────────────┐           │
│ │ NVIDIA GPU Op │ │ │ │ NVIDIA GPU Op │ │ │ │ NVIDIA GPU Op │           │
│ │ Kueue         │ │ │ │ Kueue         │ │ │ │ Kueue         │           │
│ │ DCGM Exporter │ │ │ │ DCGM Exporter │ │ │ │ DCGM Exporter │           │
│ │ vLLM runtime  │ │ │ │ vLLM runtime  │ │ │ │ vLLM runtime  │           │
│ │ Model cache   │ │ │ │ Model cache   │ │ │ │ Model cache   │           │
│ └───────────────┘ │ │ └───────────────┘ │ │ └───────────────┘           │
│                   │ │                   │ │                              │
│ Self-managing     │ │ Self-managing     │ │ Self-managing                │
│ (survives ctrl    │ │ (survives ctrl    │ │ (survives ctrl               │
│  plane outage)    │ │  plane outage)    │ │  plane outage)              │
└───────────────────┘ └───────────────────┘ └──────────────────────────────┘
```

---

## Phase 1: GPU Cluster Provisioning

**Goal:** Lattice can provision self-managing Kubernetes clusters with NVIDIA GPUs, including all device management and monitoring infrastructure.

### 1.1 Extend LatticeCluster Spec for GPU Node Pools

Today's `LatticeClusterSpec` defines worker pools with `count` and `machineRef`. Extend this with GPU-specific fields:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: gpu-cluster-h100
spec:
  providerRef:
    name: aws-us-east-1
  nodes:
    controlPlane:
      count: 3
      machineRef: m6i.xlarge
    workerPools:
      - name: gpu-workers
        count: 4
        machineRef: p5.48xlarge        # 8x H100 SXM per node
        gpu:                            # NEW
          operator:
            enabled: true
            version: "v24.9.0"
            migStrategy: mixed          # none | single | mixed
            migProfiles:                # only if migStrategy != none
              - 3g.40gb
              - 1g.10gb
          dcgmExporter:
            enabled: true
          driverVersion: "550.127.05"
          runtimeClass: nvidia          # containerd runtime class
      - name: cpu-workers
        count: 2
        machineRef: m6i.2xlarge
  parentConfig:
    cellEndpoint: "cell.lattice.internal:8443"
  servicesEnabled: true
```

### 1.2 GPU Operator Bootstrap

During cluster provisioning (the `Provisioning` phase in `crates/lattice-cluster/src/phases/`), inject GPU infrastructure via the existing `ApplyManifestsCommand` sent over the agent gRPC stream:

1. **NVIDIA GPU Operator** — Helm chart applied as manifests post-pivot
2. **DCGM Exporter** — GPU metrics (utilization, memory, temp, ECC) exposed as Prometheus metrics
3. **NVIDIA Device Plugin** — Registers `nvidia.com/gpu` resource with kubelet
4. **GPU Feature Discovery** (NFD)** — Labels nodes with GPU model, driver version, MIG capabilities

The agent already handles `ApplyManifestsCommand` and `SyncDistributedResourcesCommand`. GPU operator installation is a manifest apply — no new protocol messages needed.

### 1.3 GPU Health in Agent Heartbeat

Extend the agent `Heartbeat` and `ClusterHealth` protobuf messages to include GPU telemetry:

```protobuf
message GPUHealth {
  int32 total_gpus = 1;
  int32 healthy_gpus = 2;
  int32 allocated_gpus = 3;
  repeated GPUNodeHealth nodes = 4;
}

message GPUNodeHealth {
  string node_name = 1;
  string gpu_model = 2;           // e.g., "NVIDIA H100 80GB HBM3"
  int32 gpu_count = 3;
  float avg_utilization = 4;      // 0.0 - 1.0
  float avg_memory_used = 5;      // 0.0 - 1.0
  float avg_temperature = 6;      // Celsius
  int32 ecc_errors = 7;
  repeated MIGInstance mig_instances = 8;
}

message MIGInstance {
  string profile = 1;             // e.g., "3g.40gb"
  bool allocated = 2;
  string allocated_to = 3;        // namespace/pod
}
```

The control plane aggregates this into a fleet-wide GPU inventory view, used by the placement engine in Phase 3.

### 1.4 Deliverables

- [ ] `LatticeClusterSpec` GPU worker pool fields
- [ ] GPU Operator manifest generation in cluster controller
- [ ] GPU health in agent heartbeat protobuf
- [ ] `lattice get cluster` displays GPU info
- [ ] `lattice get clusters` shows GPU summary column
- [ ] E2E test: provision GPU cluster (Docker + fake GPU for CI, real GPU for nightly)

---

## Phase 2: Kueue Integration and GPU Scheduling

**Goal:** Every GPU cluster runs Kueue for quota-aware job scheduling. The control plane defines fleet-wide GPU pools that map to Kueue objects on individual clusters.

### 2.1 Why Kueue (Not Volcano)

| Concern | Kueue | Volcano |
|---|---|---|
| Scheduler replacement | No — works with default scheduler | Yes — replaces kube-scheduler |
| Quota management | Native, first-class | Basic fair-share |
| K8s upstream alignment | SIG-Scheduling, part of K8s org | CNCF Incubating, separate project |
| Gang scheduling | Supported via `MultiKueue` | Core feature |
| Preemption | Flexible policies per queue | Basic priority-based |
| Inference workloads | Excellent (single-pod, pipeline-parallel) | Overkill (designed for MPI/batch) |
| Multi-cluster | `MultiKueue` (experimental but active) | None |

For inference workloads, Kueue is the better fit. Inference is typically:
- Single-pod or pipeline-parallel (not gang-scheduled)
- Long-running (not batch)
- Needs fine-grained quota and preemption (reserved vs. spot tiers)

If gang scheduling becomes necessary (e.g., distributed training as a future feature), Kueue's `MultiKueue` or a Volcano sidecar can be added later without rearchitecting.

### 2.2 GPUPool CRD

A fleet-level abstraction that maps to Kueue `ClusterQueue` + `ResourceFlavor` objects on target clusters:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: GPUPool
metadata:
  name: h100-pool
spec:
  # Which clusters participate in this pool
  clusterSelector:
    matchLabels:
      lattice.dev/gpu-type: h100

  # GPU hardware description
  hardware:
    gpuModel: H100-SXM-80GB
    interconnect: nvlink           # nvlink | pcie
    gpuMemory: 80Gi

  # Kueue configuration (synced to each matching cluster)
  scheduling:
    preemption:
      withinPool: LowerPriority
      crossPool: Never
    flavorFungibility: WhenCanPreempt
    fairSharing:
      weight: 1

  # Pricing tiers
  tiers:
    - name: reserved
      priority: 1000
      preemptible: false
      pricePerGPUHour: "3.20"
    - name: on-demand
      priority: 100
      preemptible: true            # preempted by reserved
      pricePerGPUHour: "4.80"
    - name: spot
      priority: 10
      preemptible: true            # preempted by anyone
      pricePerGPUHour: "1.20"

status:
  totalGPUs: 32
  allocatedGPUs: 24
  availableGPUs: 8
  clusters:
    - name: gpu-cluster-h100-east
      totalGPUs: 16
      allocatedGPUs: 12
    - name: gpu-cluster-h100-west
      totalGPUs: 16
      allocatedGPUs: 12
```

### 2.3 GPUPool Controller

The controller runs in the control plane and:

1. **Watches** `GPUPool` CRDs and `LatticeCluster` resources
2. **Selects** clusters matching `clusterSelector`
3. **Syncs** Kueue objects to each cluster via the agent stream:
   - `ResourceFlavor` — describes the GPU type
   - `ClusterQueue` — quota and preemption config
   - `LocalQueue` — per-namespace queues (created when tenants are assigned)
4. **Aggregates** status from agent heartbeats (GPU health + Kueue queue depth)

Sync uses the existing `SyncDistributedResourcesCommand` pattern — the same mechanism used today for distributing `CloudProvider`, `SecretsProvider`, `CedarPolicy`, and `OIDCProvider` resources to child clusters.

### 2.4 Kueue Bootstrap

Kueue is installed alongside the GPU Operator during cluster provisioning (Phase 1). The manifests are applied via `ApplyManifestsCommand`:

```
Cluster Bootstrap Sequence:
1. CAPI provisions nodes
2. Agent connects to cell (gRPC stream)
3. Cell sends ApplyManifestsCommand:
   a. Cilium CNI
   b. Istio ambient mesh
   c. NVIDIA GPU Operator        ← Phase 1
   d. DCGM Exporter              ← Phase 1
   e. Kueue                      ← Phase 2
4. Cell sends SyncDistributedResourcesCommand:
   a. CloudProvider
   b. SecretsProvider
   c. CedarPolicy
   d. OIDCProvider
   e. Kueue ResourceFlavor/ClusterQueue  ← Phase 2
5. Pivot CAPI resources
6. Cluster is self-managing
```

### 2.5 Deliverables

- [ ] `GPUPool` CRD definition in `lattice-common/src/crd/`
- [ ] `GPUPool` controller in new `lattice-gpu` crate (or extend `lattice-cluster`)
- [ ] Kueue manifest generation + bootstrap
- [ ] `SyncDistributedResourcesCommand` extended for Kueue objects
- [ ] `lattice get gpupools` CLI command
- [ ] Integration test: verify Kueue objects created on GPU cluster

---

## Phase 3: Inference Engine and InferenceEndpoint CRD

**Goal:** Tenants declare a model and resource requirements. Lattice deploys it to the right cluster, manages scaling, and routes traffic.

### 3.1 InferenceEndpoint CRD

```yaml
apiVersion: lattice.dev/v1alpha1
kind: InferenceEndpoint
metadata:
  name: llama-3-70b
  namespace: tenant-acme
spec:
  # Model specification
  model:
    source: huggingface              # huggingface | s3 | oci | local
    name: meta-llama/Llama-3.3-70B-Instruct
    revision: main
    # OR for private models:
    # source: s3
    # uri: s3://acme-models/llama-3-70b-ft/
    # secretRef: acme-model-credentials

  # Inference engine
  engine:
    runtime: vllm                    # vllm | trt-llm | ollama
    version: "0.6.6"
    args:                            # Engine-specific args
      - "--tensor-parallel-size=4"
      - "--max-model-len=8192"
      - "--quantization=awq"

  # Resource requirements
  resources:
    gpuPool: h100-pool               # Reference to GPUPool
    gpuCount: 4                      # GPUs per replica
    tier: on-demand                  # reserved | on-demand | spot
    memory: 256Gi
    cpu: "32"

  # Scaling
  scaling:
    minReplicas: 1
    maxReplicas: 8
    metrics:
      - type: requestQueueDepth
        target: 10                   # Scale up when queue > 10
      - type: gpuUtilization
        target: 80                   # Scale up when GPU util > 80%
      - type: timeToFirstToken
        target: 200ms                # Scale up when TTFT exceeds 200ms
    scaleDownDelay: 5m               # Wait before scaling down
    scaleToZero: false               # Keep at least minReplicas

  # Routing
  routing:
    strategy: least-loaded           # least-loaded | round-robin | sticky
    maxConcurrentRequests: 256
    timeout: 120s

  # Ingress (optional - expose externally)
  ingress:
    enabled: true
    hostname: llama-70b.acme.inference.lattice.dev
    tls: true
    rateLimit:
      requestsPerMinute: 1000
    auth:
      type: bearer                   # bearer | api-key | oidc
      secretRef: acme-api-keys

status:
  phase: Running                     # Pending | Downloading | Running | Scaling | Failed
  readyReplicas: 2
  totalReplicas: 2
  placedOn:
    - cluster: gpu-cluster-h100-east
      replicas: 1
      gpuUtilization: 0.72
    - cluster: gpu-cluster-h100-west
      replicas: 1
      gpuUtilization: 0.65
  endpoint: "https://llama-70b.acme.inference.lattice.dev"
  modelLoaded: true
  modelSizeBytes: 38_500_000_000
  conditions:
    - type: ModelCached
      status: "True"
    - type: EndpointReady
      status: "True"
```

### 3.2 InferenceEndpoint Controller

The controller translates an `InferenceEndpoint` into lower-level Lattice and Kubernetes primitives:

```
InferenceEndpoint "llama-3-70b" (tenant-acme)
    │
    ├──► Placement Decision (which clusters?)
    │    - Check GPUPool "h100-pool" for available capacity
    │    - Consider locality, current load, tier priority
    │    - Select gpu-cluster-h100-east (4 GPUs available)
    │
    ├──► LatticeService (on target cluster, via agent stream)
    │    - Deployment: vllm container + model download init container
    │    - Resources: nvidia.com/gpu: 4, memory: 256Gi
    │    - Kueue annotation: kueue.x-k8s.io/queue-name: tenant-acme
    │    - Service: ClusterIP on port 8000
    │    - HPA: custom metrics (queue depth, GPU util, TTFT)
    │
    ├──► Ingress (if enabled)
    │    - Gateway API HTTPRoute
    │    - TLS certificate via cert-manager
    │    - Rate limiting via Istio
    │    - Auth via Lattice's OIDC/Cedar integration
    │
    └──► CiliumNetworkPolicy + AuthorizationPolicy
         - Tenant isolation (bilateral agreement model)
         - Only tenant-acme namespaces can reach this endpoint
```

### 3.3 Model Caching

Large model downloads (70B+ parameters = 35-140GB) are a cold-start bottleneck. Strategy:

1. **Node-local cache**: `hostPath` or `emptyDir` with model files. First replica downloads, subsequent replicas reuse.
2. **Shared PVC**: ReadWriteMany PVC (e.g., EFS on AWS, CephFS on-prem) mounted by all replicas on the same cluster.
3. **Pre-warm**: `ModelCache` CRD that pre-downloads models to clusters before endpoints are created.

```yaml
apiVersion: lattice.dev/v1alpha1
kind: ModelCache
metadata:
  name: popular-models
spec:
  clusterSelector:
    matchLabels:
      lattice.dev/gpu-type: h100
  models:
    - name: meta-llama/Llama-3.3-70B-Instruct
      source: huggingface
    - name: mistralai/Mixtral-8x22B-Instruct-v0.1
      source: huggingface
  storage:
    type: pvc
    storageClass: efs-sc
    size: 500Gi
```

### 3.4 vLLM Integration

vLLM is the default inference runtime. The controller generates a pod spec like:

```yaml
containers:
  - name: vllm
    image: vllm/vllm-openai:v0.6.6
    args:
      - "--model=/models/meta-llama/Llama-3.3-70B-Instruct"
      - "--tensor-parallel-size=4"
      - "--max-model-len=8192"
      - "--port=8000"
      - "--served-model-name=llama-3-70b"
    resources:
      limits:
        nvidia.com/gpu: 4
        memory: 256Gi
      requests:
        cpu: "32"
        memory: 256Gi
    ports:
      - containerPort: 8000
        name: http
    readinessProbe:
      httpGet:
        path: /health
        port: 8000
      initialDelaySeconds: 120     # Model loading takes time
    volumeMounts:
      - name: model-cache
        mountPath: /models
      - name: shm
        mountPath: /dev/shm         # Required for tensor parallelism
  volumes:
    - name: shm
      emptyDir:
        medium: Memory
        sizeLimit: 64Gi
```

### 3.5 Deliverables

- [ ] `InferenceEndpoint` CRD definition
- [ ] `ModelCache` CRD definition
- [ ] `InferenceEndpoint` controller (new `lattice-inference` crate)
- [ ] Placement engine (capacity-aware, tier-aware)
- [ ] vLLM pod spec generation
- [ ] TRT-LLM pod spec generation (stretch)
- [ ] Custom metrics adapter for scaling (queue depth, TTFT)
- [ ] `lattice get endpoints` CLI command
- [ ] `lattice logs <endpoint>` for inference logs
- [ ] Integration test: deploy vLLM endpoint, send inference request

---

## Phase 4: Multi-Tenancy and Quota Management

**Goal:** Tenants get isolated GPU allocations with billing-aware quotas, enforced by Cedar policies and Kueue.

### 4.1 GPUTenantQuota CRD

```yaml
apiVersion: lattice.dev/v1alpha1
kind: GPUTenantQuota
metadata:
  name: acme-quota
spec:
  tenant: acme

  # Namespace isolation
  namespaces:
    - tenant-acme
    - tenant-acme-staging

  # Pool-level quotas
  pools:
    - poolRef: h100-pool
      reserved:
        gpus: 8                     # Always available to this tenant
        pricePerGPUHour: "3.20"
      onDemand:
        maxGPUs: 16                 # Can burst up to 16
        pricePerGPUHour: "4.80"
      spot:
        maxGPUs: 32                 # Preemptible capacity
        pricePerGPUHour: "1.20"
    - poolRef: a100-pool
      onDemand:
        maxGPUs: 8

  # Budget limits
  budget:
    maxMonthlySpend: "50000.00"
    alertThresholds:
      - percent: 80
        notifyEmail: ops@acme.com
      - percent: 100
        action: block               # block | alert-only

  # Priority (higher = more important, used for preemption)
  priority: 100

status:
  currentUsage:
    h100Pool:
      reservedGPUs: 8
      onDemandGPUs: 4
      spotGPUs: 0
    a100Pool:
      onDemandGPUs: 2
  currentMonthSpend: "12,480.00"
  projectedMonthSpend: "31,200.00"
```

### 4.2 Cedar Policies for GPU Access

Extend the existing Cedar policy engine with GPU-specific entity types:

```cedar
// Tenant can deploy to their GPU allocation
permit(
  principal in Lattice::Tenant::"acme",
  action == Lattice::Action::"deploy-inference",
  resource in Lattice::GPUPool::"h100-pool"
) when {
  resource.tier == "on-demand" &&
  principal.quota.remainingGPUs > 0
};

// Admins can manage all pools
permit(
  principal in Lattice::Group::"platform-admins",
  action in [
    Lattice::Action::"manage-pool",
    Lattice::Action::"manage-quota",
    Lattice::Action::"deploy-inference"
  ],
  resource
);

// Block tenant from spot tier (contractual restriction)
forbid(
  principal in Lattice::Tenant::"regulated-corp",
  action == Lattice::Action::"deploy-inference",
  resource
) when {
  resource.tier == "spot"
};
```

### 4.3 Tenant Isolation via Bilateral Agreements

Lattice's existing bilateral service mesh model extends naturally to tenant isolation:

```yaml
# Tenant A's inference endpoint
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: llama-3-70b
  namespace: tenant-acme
spec:
  resources:
    inference-api:
      type: service
      direction: inbound            # Accepts requests
      allowFrom:
        - tenant-acme/*             # Only from own namespace
        - shared-gateway/*          # And from the shared API gateway

# Tenant A's client application
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: acme-app
  namespace: tenant-acme
spec:
  resources:
    llama-inference:
      type: service
      direction: outbound           # Calls inference
      target: tenant-acme/llama-3-70b
```

Both sides must agree. Tenant B cannot reach Tenant A's model endpoint because neither side declares the cross-tenant dependency.

### 4.4 Usage Tracking and Billing

GPU usage is tracked via DCGM metrics flowing through the agent heartbeat:

```
Per-Endpoint Usage Record:
  tenant: acme
  endpoint: llama-3-70b
  cluster: gpu-cluster-h100-east
  gpuCount: 4
  tier: on-demand
  startTime: 2025-01-15T10:00:00Z
  endTime: (running)
  gpuHours: 48.5
  cost: $232.80
```

The control plane aggregates these into `GPUTenantQuota.status` and enforces budget limits. When a tenant hits their budget cap, new `InferenceEndpoint` creation is blocked (existing endpoints continue running).

### 4.5 Deliverables

- [ ] `GPUTenantQuota` CRD definition
- [ ] Tenant quota controller (syncs to Kueue `LocalQueue` quotas)
- [ ] Cedar entity types for GPU resources (`Lattice::Tenant`, `Lattice::GPUPool`)
- [ ] Usage tracking and aggregation from DCGM metrics
- [ ] Budget enforcement (block/alert)
- [ ] `lattice get tenants` and `lattice get quota <tenant>` CLI commands
- [ ] Billing webhook for external billing systems

---

## Phase 5: Multi-Cluster Placement and Routing

**Goal:** The control plane makes intelligent placement decisions across GPU clusters and routes inference traffic to the best available replica.

### 5.1 Placement Engine

When an `InferenceEndpoint` is created, the placement engine decides where to run it:

```
Placement Algorithm:

  1. Filter: clusters in the target GPUPool with sufficient capacity
  2. Filter: clusters where tenant quota allows allocation
  3. Score:
     a. Available GPU capacity (prefer clusters with headroom for scaling)
     b. Model cache hit (prefer clusters where model is already downloaded)
     c. Network locality (prefer clusters close to traffic source)
     d. GPU fragmentation (prefer clusters that don't leave unusable fragments)
     e. Tier cost (prefer cheapest available for spot, closest match for reserved)
  4. Select: highest-scoring cluster(s)
  5. If multi-replica: spread across clusters for HA (anti-affinity)
```

The placement engine is a control plane component. It does NOT run on GPU clusters — they remain self-managing. Placement decisions are sent as `LatticeService` creates via the agent stream.

### 5.2 Inference Gateway

A shared inference gateway runs on the control plane (or on dedicated gateway clusters) and routes requests to backend replicas across the fleet:

```
Client Request
    │
    ▼
┌──────────────────────────────┐
│  Inference Gateway            │
│  (Envoy / Istio Gateway)     │
│                              │
│  1. Authenticate (API key,   │
│     OIDC, bearer token)      │
│  2. Rate limit (per-tenant)  │
│  3. Route to backend         │
│     (least-loaded, sticky,   │
│      round-robin)            │
│  4. Retry on failure         │
│  5. Emit metrics             │
└──────────────────────────────┘
    │               │
    ▼               ▼
 Cluster A       Cluster B
 (replica 1)     (replica 2)
```

For cross-cluster routing, the gateway uses Lattice's existing K8s API proxy to discover endpoints, and Istio's `ServiceEntry` to route to them. Alternatively, a DNS-based approach where each cluster's endpoint is a separate upstream.

### 5.3 Failover and Preemption

When a GPU cluster becomes unhealthy or a spot-tier workload is preempted:

1. Agent heartbeat reports GPU failure or pod eviction
2. Control plane detects `InferenceEndpoint` replica loss
3. Placement engine selects a new cluster
4. New replica deployed (with model cache pre-warm if possible)
5. Gateway drains traffic from failed replica, shifts to healthy replicas
6. Tenant notified via webhook/event

For reserved-tier workloads, the platform guarantees placement. For spot-tier, preemption is expected and tenants should run multiple replicas across clusters.

### 5.4 Deliverables

- [ ] Placement engine (scoring algorithm, cluster selection)
- [ ] Inference gateway configuration (Envoy/Istio)
- [ ] Cross-cluster endpoint discovery
- [ ] Failover automation (detect → replace → reroute)
- [ ] Preemption handling (spot eviction → reschedule)
- [ ] `lattice get placement <endpoint>` CLI command
- [ ] Placement dry-run / simulation mode

---

## Phase 6: Observability and Operations

**Goal:** Fleet-wide visibility into GPU utilization, inference performance, and cost.

### 6.1 Metrics Pipeline

```
GPU Cluster                          Control Plane
┌──────────────────────┐            ┌──────────────────────┐
│ DCGM Exporter        │            │ Prometheus (federated)│
│   → gpu_utilization   │──agent──→ │ Grafana dashboards    │
│   → gpu_memory_used   │  gRPC     │                      │
│   → gpu_temperature   │  stream   │ Metrics:             │
│   → ecc_errors        │           │ - Fleet GPU util     │
│                       │           │ - Per-tenant usage   │
│ vLLM Metrics          │           │ - Queue depth        │
│   → requests_total    │──agent──→ │ - TTFT / TPS         │
│   → queue_depth       │  gRPC     │ - Cost tracking      │
│   → time_to_first_tkn │  stream   │ - Model load times   │
│   → tokens_per_second │           │                      │
│                       │           │ Alerts:              │
│ Kueue Metrics         │           │ - GPU failure        │
│   → pending_workloads │──agent──→ │ - Quota exhaustion   │
│   → admitted_workloads│  gRPC     │ - Budget threshold   │
│   → preemptions       │  stream   │ - SLA violation      │
└──────────────────────┘            └──────────────────────┘
```

Metrics flow through the existing agent gRPC stream — no new network paths needed. The agent scrapes local Prometheus endpoints and includes summaries in heartbeat messages. The control plane federates these into a fleet-wide view.

### 6.2 Key Dashboards

| Dashboard | Audience | Metrics |
|---|---|---|
| Fleet Overview | Platform ops | Total GPUs, utilization, capacity, errors, cost |
| Tenant Usage | Tenant admins | Their GPU hours, spend, active endpoints, quotas |
| Endpoint Detail | Developers | Requests/sec, latency (TTFT, TPS), queue depth, errors |
| Cluster Health | Platform ops | Node status, GPU health, Kueue queue depth |
| Cost Analysis | Finance/ops | Per-tenant spend, tier breakdown, projected costs |

### 6.3 CLI Commands

```bash
# Fleet GPU overview
lattice get gpus
# CLUSTER          GPU MODEL     TOTAL  ALLOC  AVAIL  UTIL%
# h100-east        H100-SXM      32     24     8      72%
# h100-west        H100-SXM      32     28     4      85%
# a100-pool-1      A100-80GB     16     8      8      45%

# Tenant usage
lattice get quota acme
# POOL        RESERVED  ON-DEMAND  SPOT  MONTHLY SPEND
# h100-pool   8/8       4/16       0/32  $12,480 / $50,000

# Endpoint status
lattice get endpoints -n tenant-acme
# NAME           MODEL              GPUS  REPLICAS  STATUS   TTFT    TPS
# llama-3-70b    Llama-3.3-70B      4     2/2       Running  180ms   45

# Inference logs
lattice logs llama-3-70b -n tenant-acme --follow
```

### 6.4 Deliverables

- [ ] Agent heartbeat extended with DCGM + vLLM + Kueue metrics
- [ ] Prometheus federation in control plane
- [ ] Grafana dashboard templates (fleet, tenant, endpoint, cluster, cost)
- [ ] Alert rules (GPU failure, SLA violation, budget threshold)
- [ ] `lattice get gpus`, `lattice get endpoints`, `lattice get quota` CLI commands
- [ ] `lattice logs <endpoint>` streaming via agent proxy

---

## Implementation Sequence

```
Phase 1: GPU Cluster Provisioning          ██████░░░░░░░░░░░░░░
  - LatticeCluster GPU spec extensions     Weeks 1-2
  - GPU Operator bootstrap                 Weeks 2-3
  - GPU health in agent heartbeat          Week 3
  - CLI updates                            Week 4

Phase 2: Kueue Integration                 ░░░░██████░░░░░░░░░░
  - GPUPool CRD + controller               Weeks 4-5
  - Kueue bootstrap on GPU clusters        Week 5
  - Sync Kueue objects via agent stream     Week 6
  - CLI + integration tests                 Weeks 6-7

Phase 3: Inference Engine                   ░░░░░░░░██████████░░
  - InferenceEndpoint CRD + controller     Weeks 7-9
  - vLLM pod spec generation               Week 8
  - Model caching (ModelCache CRD)         Weeks 9-10
  - Custom metrics + autoscaling           Weeks 10-11
  - CLI + integration tests                Week 11

Phase 4: Multi-Tenancy                     ░░░░░░░░░░░░████████
  - GPUTenantQuota CRD                    Weeks 11-12
  - Cedar GPU policy entities              Week 12
  - Usage tracking + billing               Weeks 12-13
  - Budget enforcement                     Week 13

Phase 5: Multi-Cluster Placement           ░░░░░░░░░░░░░░░░████ (+ ongoing)
  - Placement engine                       Weeks 13-15
  - Inference gateway                      Weeks 14-16
  - Failover + preemption                  Weeks 15-17

Phase 6: Observability                     ░░░░░░░░░░░░████████ (parallel)
  - Metrics pipeline                       Weeks 11-13 (parallel with Phase 4)
  - Dashboards + alerts                    Weeks 13-15
  - CLI commands                           Weeks 14-16
```

Phases 1-3 are sequential — each builds on the previous. Phase 4 depends on Phase 2 (Kueue). Phases 5 and 6 can partially overlap with earlier phases.

---

## New Crate Structure

```
crates/
├── lattice-common/src/crd/
│   ├── gpu_pool.rs              # GPUPool CRD
│   ├── inference_endpoint.rs    # InferenceEndpoint CRD
│   ├── model_cache.rs           # ModelCache CRD
│   └── gpu_tenant_quota.rs      # GPUTenantQuota CRD
│
├── lattice-gpu/                 # NEW CRATE
│   ├── src/
│   │   ├── controller.rs        # GPUPool controller
│   │   ├── kueue.rs             # Kueue object generation
│   │   ├── inventory.rs         # Fleet GPU inventory aggregation
│   │   └── placement.rs         # Placement engine
│   └── Cargo.toml
│
├── lattice-inference/           # NEW CRATE
│   ├── src/
│   │   ├── controller.rs        # InferenceEndpoint controller
│   │   ├── engines/
│   │   │   ├── vllm.rs          # vLLM pod spec generation
│   │   │   ├── trt_llm.rs       # TensorRT-LLM pod spec generation
│   │   │   └── mod.rs           # Engine trait
│   │   ├── scaling.rs           # Custom metrics + HPA generation
│   │   ├── cache.rs             # ModelCache controller
│   │   └── routing.rs           # Inference gateway configuration
│   └── Cargo.toml
│
├── lattice-tenant/              # NEW CRATE
│   ├── src/
│   │   ├── controller.rs        # GPUTenantQuota controller
│   │   ├── billing.rs           # Usage tracking + budget enforcement
│   │   └── cedar.rs             # GPU-specific Cedar entity types
│   └── Cargo.toml
│
└── lattice-proto/proto/
    └── agent.proto              # Extended with GPU health messages
```

---

## Risk Analysis

| Risk | Impact | Mitigation |
|---|---|---|
| GPU Operator conflicts with cluster bootstrap | Cluster provisioning fails | Phase 1 E2E test with real GPUs in CI. GPU Operator installed post-pivot, not during CAPI bootstrap. |
| Kueue version incompatibility | Scheduling broken after K8s upgrade | Pin Kueue version per K8s version. Test matrix in CI. |
| vLLM OOM on large models | Inference pod crash loop | Model-aware resource calculation. Validate GPU memory before placement. |
| Model download bottleneck | Slow cold starts (minutes for 70B models) | ModelCache pre-warming. Shared PVC per cluster. Image-baked popular models. |
| Cross-cluster routing latency | Slow inference for distributed replicas | Prefer same-cluster routing. Use locality-aware load balancing. |
| Spot preemption cascades | All replicas evicted simultaneously | Anti-affinity across clusters. Min reserved replicas for critical endpoints. |
| Agent stream bandwidth | GPU metrics flood the gRPC stream | Aggregate metrics on agent side. Send summaries, not raw DCGM output. Configurable scrape interval. |
| Cedar policy complexity | Tenants locked out by policy mistakes | Policy simulation/dry-run mode. Default-allow within tenant namespace. Audit logging. |

---

## Design Principles

1. **Lattice manages clusters. The GPU PaaS manages workloads.** The boundary is clean: `LatticeCluster` handles infrastructure, `InferenceEndpoint` handles applications. No mixing.

2. **Self-managing survives control plane failure.** Running inference workloads must continue if the control plane goes down. No heartbeat-dependent scheduling. Kueue runs locally per cluster.

3. **Outbound-only is non-negotiable.** GPU clusters never accept inbound connections. All management flows through the agent gRPC stream. Inference traffic enters through the gateway, not direct to clusters.

4. **Bilateral agreements for tenant isolation.** The existing service mesh model extends to GPU tenants. Both sides must agree. No implicit cross-tenant access.

5. **Cedar for authorization, Kueue for scheduling.** Cedar decides WHO can use WHAT. Kueue decides WHEN and WHERE it runs. Clean separation.

6. **No new network paths.** GPU metrics, management commands, and status updates all flow through the existing agent gRPC stream. The only new network path is inference traffic through the gateway.
