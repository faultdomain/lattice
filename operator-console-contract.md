# Lattice Operator — Console Contract

What the Rust operator owns, what CRDs it exposes, what it reconciles, and what it ignores. This is the contract the console builds against.

---

## Operator Boundaries

The operator is the **sole owner of infrastructure and workload state**. It reconciles CRDs into running infrastructure. It does not know about orgs, users, quotas, or UI concerns.

**Operator owns:**
- CRD schemas (all spec/status field definitions)
- Reconciliation logic (CRD → infrastructure)
- Status reporting (phase, conditions, observed state)
- Mesh policy generation (Cilium + Istio from bilateral declarations)
- Secret routing (Cedar authz → ESO objects)
- Cluster lifecycle (provision, pivot, self-management)

**Operator ignores:**
- `lattice.io/org` label (passes through, never reads it)
- `lattice.io/created-by` annotation (passes through)
- Quota enforcement (not its problem)
- Who created the CRD (kubectl, console, GitOps — doesn't matter)

**Invariant:** Any CRD the console creates could equally be created by `kubectl apply`. The operator's behavior is identical regardless of source.

---

## CRD Catalog

### LatticePool (new)

Admin intent: "I have this hardware, make it available."

The operator watches LatticePool and reconciles it into one or more LatticeCluster CRDs. Pool is the declaration. Cluster is the implementation.

```yaml
apiVersion: lattice.io/v1alpha1
kind: LatticePool
metadata:
  name: h100-pool-east
spec:
  provider: aws                # aws | gcp | on-prem
  region: us-east-1
  machineProfile:
    gpuType: H100
    gpuPerNode: 8
    cpuPerNode: 96
    memoryPerNodeGB: 768
  nodeCount: 8                 # desired total nodes across clusters backing this pool
  maxNodesPerCluster: 8        # optional, defaults to nodeCount (1:1 pool:cluster for v0)
status:
  phase: Ready                 # Pending | Provisioning | Ready | Degraded | Failed
  conditions:
    - type: ClustersReady
      status: "True"
      lastTransitionTime: "2026-03-03T00:00:00Z"
  totalGPUs: 64
  availableGPUs: 48            # total minus what's allocated to workloads
  allocatedGPUs: 16
  totalNodes: 8
  readyNodes: 8
  clusters:                    # operator-managed, not user-settable
    - name: east-h100-01
      phase: Ready
      readyNodes: 8
      totalNodes: 8
```

**Reconciliation:**
- Pool created → operator creates LatticeCluster(s) sized to fit `maxNodesPerCluster`
- `nodeCount` changed → operator scales existing clusters or creates new ones
- Cluster reports unhealthy → pool status degrades
- `availableGPUs` is computed by subtracting GPU allocations from all workloads scheduled to this pool

**v0 simplification:** `maxNodesPerCluster` defaults to `nodeCount`, giving 1:1 pool:cluster. The schema supports 1:many without migration.

---

### LatticeModel (new)

User intent: "Deploy this model for inference."

```yaml
apiVersion: lattice.io/v1alpha1
kind: LatticeModel
metadata:
  name: qwen3-8b
  labels:
    lattice.io/org: acme-corp        # set by console, ignored by operator
  annotations:
    lattice.io/created-by: console   # optional provenance
spec:
  pool: h100-pool-east               # required, must reference existing LatticePool
  model:
    uri: "hf://Qwen/Qwen3-8B"       # huggingface://, s3://, gs://, oci://
    engine: vllm                     # vllm | tgi | triton | custom
    runtime:                         # optional engine-specific overrides
      tensorParallelism: 4
      maxModelLen: 8192
  resources:
    gpuCount: 4                      # required, no silent defaults
    cpuRequest: "8"                  # optional
    memoryRequest: "64Gi"            # optional
  replicas: 1                        # desired replica count
  endpoint:                          # optional, operator sets defaults
    port: 8000
    path: /v1                        # base path for OpenAI-compatible API
status:
  phase: Serving                     # Pending | Scheduling | Loading | Serving | Failed
  conditions:
    - type: ModelLoaded
      status: "True"
    - type: EndpointReady
      status: "True"
  endpoint:
    url: "https://qwen3-8b.models.lattice.internal"
    port: 8000
  replicas:
    desired: 1
    ready: 1
    unavailable: 0
  resources:
    allocatedGPUs: 4
    pool: h100-pool-east
    cluster: east-h100-01            # which cluster the operator placed it on
    node: ""                         # optional, set if pinned
```

**Reconciliation:**
- Validates `pool` exists and has `availableGPUs >= gpuCount`
- Selects a backing cluster from the pool
- Creates Deployment + Service (or engine-specific equivalents) on the target cluster
- Sets `status.endpoint` once pods are serving
- If the pool has insufficient GPUs: sets phase `Pending` with condition `Unschedulable`

**No silent fallbacks:** If `gpuCount` is missing, the CRD fails validation. The operator does not guess.

---

### LatticeJob (new)

User intent: "Run this training job."

```yaml
apiVersion: lattice.io/v1alpha1
kind: LatticeJob
metadata:
  name: finetune-qwen3
  labels:
    lattice.io/org: acme-corp
spec:
  pool: h100-pool-east
  job:
    image: "registry.example.com/training:latest"
    command: ["torchrun", "--nproc_per_node=8", "train.py"]
    env:
      - name: WANDB_PROJECT
        value: "qwen3-finetune"
    volumes:                          # optional
      - name: data
        source: "s3://datasets/pile"
        mountPath: /data
  resources:
    gpuCount: 8
    cpuRequest: "32"
    memoryRequest: "256Gi"
  timeout: 86400                      # seconds, optional
  retries: 2                          # optional, default 0
status:
  phase: Running                      # Pending | Scheduling | Running | Succeeded | Failed
  conditions:
    - type: Scheduled
      status: "True"
    - type: Running
      status: "True"
  startTime: "2026-03-03T01:00:00Z"
  completionTime: null
  resources:
    allocatedGPUs: 8
    pool: h100-pool-east
    cluster: east-h100-01
  retryCount: 0
```

**Reconciliation:**
- Same pool validation and cluster selection as LatticeModel
- Creates a K8s Job (or PyTorchJob/MPIJob for distributed) on the target cluster
- GPUs are released back to the pool on completion or failure
- `timeout` triggers failure if exceeded

---

### LatticeService (existing, unchanged)

Already exists in the operator. The console will create these the same way it creates Models and Jobs. The existing spec — with `resources` for mesh bilateral agreements, secrets, and Cedar policies — stays as-is.

The console adds `lattice.io/org` label. The operator ignores it.

No changes needed to the LatticeService CRD or its reconciler for console integration.

---

### LatticeCluster (existing, minor addition)

Already exists. The only change: clusters created by the pool reconciler carry a label linking them back.

```yaml
metadata:
  labels:
    lattice.io/pool: h100-pool-east   # set by pool reconciler
```

No other changes. The existing provisioning, pivot, and self-management flow is untouched.

---

## Label and Annotation Contract

These are the labels/annotations the operator defines in its CRD schemas. The console is expected to set them on create. The operator passes them through.

| Key | Set by | Used by | Purpose |
|-----|--------|---------|---------|
| `lattice.io/org` | Console | Console (watcher) | Tenant scoping for UI queries |
| `lattice.io/pool` | Operator | Operator + Console | Links clusters to pools, workloads to pools |
| `lattice.io/created-by` | Console (optional) | Nobody | Provenance annotation |

**The operator MUST NOT filter, validate, or make decisions based on `lattice.io/org`.** It is opaque metadata.

---

## Status Reporting Contract

The console watcher will watch these CRDs and cache their status. The operator must report status consistently so the watcher can build reliable UI state.

### Phase Lifecycles

```
LatticePool:    Pending → Provisioning → Ready → Degraded → Failed
LatticeModel:   Pending → Scheduling → Loading → Serving → Failed
LatticeJob:     Pending → Scheduling → Running → Succeeded / Failed
LatticeCluster: Pending → Provisioning → Pivoting → Ready → Failed
LatticeService: (existing lifecycle, unchanged)
```

**Rules:**
- Phase is a single high-level word. No compound states like "PartiallyReady".
- `conditions` carry the detail. Phase is derived from conditions.
- `lastTransitionTime` is always set on condition changes.
- Terminal phases: `Succeeded` (jobs only), `Failed`. Failed resources stay failed until the user deletes/recreates or edits the spec.
- The operator updates status on every reconcile, even if nothing changed (to keep `observedGeneration` current).

### GPU Accounting

The console needs to show "X of Y GPUs available" per pool. The operator computes this:

```
pool.status.totalGPUs = pool.spec.machineProfile.gpuPerNode * pool.status.totalNodes
pool.status.allocatedGPUs = sum(workload.spec.resources.gpuCount) for all workloads where workload.spec.pool == pool.name AND workload is not terminal
pool.status.availableGPUs = totalGPUs - allocatedGPUs
```

"Terminal" means phase is `Succeeded` or `Failed`. The operator recomputes these on every pool reconcile.

---

## Scheduling

The operator owns all scheduling decisions. The console has no say in which cluster or node a workload lands on.

**v0 scheduling:** Simple first-fit. Scan clusters in the pool, find one with enough free GPUs, place the workload there.

**What the console sees:** `status.resources.cluster` tells the console where the workload ended up. This is informational — the console never uses it to make decisions.

**What happens when there's no capacity:**
- Workload goes to phase `Pending` with condition `type: Unschedulable, status: "True", message: "Pool h100-pool-east has 0 available GPUs, need 4"`
- The operator retries on the next reconcile (if pool capacity changes, the workload gets scheduled)
- The console shows the pending state and the condition message to the user

---

## Validation

The operator validates CRDs at two levels:

### Schema Validation (CEL / OpenAPI)

Built into the CRD schema. Rejects invalid specs before the operator ever sees them.

- `gpuCount` is required and must be > 0
- `pool` is required and must be non-empty
- `engine` must be one of the allowed values
- `model.uri` must match a supported scheme

### Reconciler Validation

Checked during reconciliation. Sets conditions rather than rejecting:

- `pool` references a pool that doesn't exist → condition `PoolNotFound`
- `pool` exists but doesn't have the requested GPU type → condition `IncompatiblePool`
- `gpuCount` exceeds `gpuPerNode * maxNodesPerCluster` → condition `ExceedsPoolCapacity`

The console can read conditions to show specific error messages rather than a generic "Failed".

---

## What the Operator Does NOT Do

These are explicitly out of scope. The console or other systems handle them.

- **Authentication/authorization of API requests.** K8s RBAC handles who can create CRDs. The operator doesn't add another layer.
- **Quota enforcement.** The operator schedules if capacity exists. Whether the org is *allowed* to use that capacity is the console's problem.
- **Org-scoped resource limits.** The operator doesn't know what an org is.
- **UI concerns.** No display names, descriptions, or UI-hint fields in CRD specs.
- **CRD garbage collection by org.** If an org is deleted in the console, the console must delete that org's CRDs. The operator just reconciles what exists.

---

## New Controllers

| Controller | Watches | Creates/Manages | Notes |
|------------|---------|-----------------|-------|
| PoolController | LatticePool | LatticeCluster | New. Provisions clusters to back pools. |
| ModelController | LatticeModel | Deployment, Service (on target cluster) | New. Inference workload lifecycle. |
| JobController | LatticeJob | Job/PyTorchJob (on target cluster) | New. Training workload lifecycle. |
| ClusterController | LatticeCluster | CAPI resources | Existing. No changes. |
| ServiceController | LatticeService | Compiled K8s resources | Existing. No changes. |

### Cross-Cluster Reconciliation

ModelController and JobController create resources on **workload clusters**, not the management cluster where the CRD lives. They use the kubeconfig/proxy from the backing LatticeCluster to reach the target.

```
Management Cluster                    Workload Cluster
┌──────────────┐                     ┌──────────────────┐
│ LatticeModel │──ModelController──→ │ Deployment       │
│   (CRD)      │    (creates)        │ Service          │
│              │                     │ (actual pods)    │
└──────────────┘                     └──────────────────┘
       ▲                                      │
       └────── status updated from ───────────┘
               workload cluster state
```

This mirrors the existing pattern where the management cluster holds declarative intent and workload clusters run the actual infrastructure.

---

## Implementation Order

1. **LatticePool CRD + PoolController** — Pool is the foundation. Models and Jobs need pools to exist.
2. **LatticeModel CRD + ModelController** — Highest user-facing value. Inference is the primary use case.
3. **LatticeJob CRD + JobController** — Same pattern as Model, different lifecycle (run-to-completion vs long-running).
4. **GPU accounting in pool status** — Tie workload allocations back to pool availability numbers.
5. **Scheduling improvements** — Bin-packing, affinity, preemption. Only after the basics work.
