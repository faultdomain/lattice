# Lattice Console — Design Document

## What The Console Is

A multi-tenant UI and API layer on top of the Lattice K8s operator. The console owns **identity, authorization, and intent translation**. It does not own infrastructure state.

```
┌─────────────────────────────────────────────────┐
│  Console (Elixir)                               │
│                                                 │
│  Owns:                                          │
│    Orgs, Users, Auth, Roles                     │
│    Quotas (org → pool allocation)               │
│    UI (forms → CRDs, tables ← watched state)   │
│                                                 │
│  Does NOT own:                                  │
│    Pools, Clusters, Models, Jobs, Services      │
│    (these are CRDs — operator is source of      │
│     truth, console watches + caches)            │
└────────────────────┬────────────────────────────┘
                     │ watch + POST CRDs
                     ▼
┌─────────────────────────────────────────────────┐
│  K8s API                                        │
│                                                 │
│  CRDs (source of truth):                        │
│    LatticePool     → declares hardware          │
│    LatticeCluster  → provisioned from pools     │
│    LatticeModel    → inference deployments      │
│    LatticeJob      → training runs              │
│    LatticeService  → long-running services      │
│                                                 │
│  Rust Operator reconciles all of the above      │
└─────────────────────────────────────────────────┘
```

## What The Console Owns (Postgres)

### Org

The tenant. Everything the console does is scoped to an org.

```
Org
  id, name, slug
```

### User

```
User
  id, email, name, role (admin | member)
  belongs_to :org
```

### Quota

The only infrastructure-adjacent thing the console owns. K8s has no concept of "this org can use 16 GPUs from this pool" — that's a console concern.

```
Quota
  org_id
  pool_name          # references a watched LatticePool
  gpu_limit: 16
  gpu_used: 4        # updated as workloads deploy/terminate
```

Skip for v0 — just validate pool has raw capacity. Add when multi-tenancy matters.

## What The Console Watches (Postgres cache)

These tables mirror CRD state. The watcher syncs them. They exist so the UI can query Postgres (fast, org-scoped) instead of hitting K8s directly.

### WatchedPool

Cached from LatticePool CRDs.

```
WatchedPool
  name               # from metadata.name
  provider           # spec.provider (aws / gcp / on-prem)
  region             # spec.region
  gpu_type           # spec.gpuType
  gpu_per_node       # spec.gpuPerNode
  cpu_per_node       # spec.cpuPerNode
  memory_per_node_gb # spec.memoryPerNodeGB
  node_count         # spec.nodeCount
  status             # status.phase
  raw_spec           # full spec JSONB
  raw_status         # full status JSONB
```

Not org-scoped. All orgs see all pools (filtered by quota in the future).

### WatchedCluster

Cached from LatticeCluster CRDs.

```
WatchedCluster
  name
  pool_name          # which pool this cluster serves
  api_endpoint
  status             # Provisioning | Ready | Degraded | Failed
  ready_nodes
  total_nodes
  k8s_version
  raw_spec, raw_status
```

Not org-scoped. Admin-only visibility.

### WatchedModel

Cached from LatticeModel CRDs.

```
WatchedModel
  name
  org_id             # from CRD label or namespace convention
  pool_name
  model_uri
  engine
  gpu_count
  status             # Pending | Loading | Serving | Failed
  endpoint_url
  raw_spec, raw_status
```

Org-scoped via `org_id`. The CRD carries the org identity (label or namespace).

### WatchedJob, WatchedService

Same pattern. Cached from LatticeJob / LatticeService CRDs. Org-scoped.

## The Two Operations

### 1. Watch (K8s → Postgres)

A GenServer per CRD type watches the K8s API:

```
K8s Watch API
    │  ADDED / MODIFIED / DELETED
    ▼
Watcher GenServer
    │
    ├── upsert/delete in Postgres
    └── PubSub broadcast → LiveView updates
```

On startup: full list to reconcile. Then watch with resourceVersion. On disconnect: re-list and resume.

### 2. Mutate (Console → K8s)

User fills a form. Console builds a CRD. POSTs it.

```
User form submission
    │
    ▼
Validate (quota, capacity)
    │
    ▼
CrdBuilder.build(:model, params) → YAML/JSON
    │
    ▼
POST to K8s API (targeting the cluster that manages the selected pool)
    │
    ▼
Watcher picks it up → cache updates → UI reflects new state
```

The console does **not** insert into Postgres on mutate. It POSTs the CRD and waits for the watcher to sync it back. Single source of truth.

## CRD Design (Rust operator side)

### LatticePool (new)

```yaml
apiVersion: lattice.io/v1alpha1
kind: LatticePool
metadata:
  name: h100-pool-east
spec:
  provider: aws
  region: us-east-1
  gpuType: H100
  gpuPerNode: 8
  cpuPerNode: 96
  memoryPerNodeGB: 768
  nodeCount: 8
status:
  phase: Ready
  totalGPUs: 64
  availableGPUs: 48
  clusters:
    - name: east-h100-01
      readyNodes: 8
```

The operator watches LatticePool and reconciles it into LatticeCluster CRDs. Pool is the admin intent. Cluster is the implementation.

### Compute CRDs (existing, add pool reference)

```yaml
apiVersion: lattice.io/v1alpha1
kind: LatticeModel
metadata:
  name: qwen3-8b
  labels:
    lattice.io/org: acme-corp    # console sets this for tenant scoping
spec:
  pool: h100-pool-east           # which pool to schedule on
  modelURI: "hf://Qwen/Qwen3-8B"
  engine: vllm
  gpuCount: 4
```

The `lattice.io/org` label is how the watcher knows which org a workload belongs to. The console sets it on create. The operator ignores it.

## Console Flows

### Admin: Register capacity

```
Admin creates LatticePool CRD (via console form or kubectl)
    → Operator provisions cluster(s) from pool spec
    → Watcher syncs pool + cluster status into Postgres
    → Admin sees pool as Ready in console
```

### User: Deploy a model

```
1. Console shows available pools (from WatchedPool cache)
   - Filtered by: has the GPU type, has available capacity, user has quota
2. User fills form: name, model_uri, engine, pool, gpu_count
3. Console validates quota
4. CrdBuilder generates LatticeModel CRD with org label
5. POST to K8s API
6. Watcher syncs status → UI updates
```

### User: View their models

```
1. LiveView queries WatchedModel WHERE org_id = current_user.org_id
2. Pure Postgres read — fast, tenant-isolated
3. PubSub subscription for live updates when watcher syncs changes
```

## Navigation

```
LATTICE                                    org: acme-corp

Compute
  Models            Inference endpoints
  Training          Training jobs
  Services          Long-running services

Infrastructure      (admin-only)
  Pools             Hardware capacity declarations
  Clusters          Provisioned K8s clusters

Settings
  Team              Users, roles
  Quotas            Per-org pool allocations (future)
```

## Technology Stack

```
LiveView (tables, forms, real-time status)
    │
Phoenix + Ash + AshJsonApi + AshAuthentication
    │
    ├── Postgres
    │     Owns: orgs, users, quotas
    │     Caches: pools, clusters, models, jobs, services
    │
    └── K8s API
          POST CRDs (mutate)
          Watch CRDs (sync state)
              │
        Lattice Operator (Rust) — reconciles everything
```

## Implementation Order

1. **Watcher infrastructure** — GenServer that watches a CRD type and syncs to Postgres via Ash. This is the foundation everything else depends on.

2. **WatchedPool + WatchedCluster** — cache infra state. Admin UI to view pools and clusters. Form to create LatticePool CRDs.

3. **WatchedModel** — cache compute state. User UI to list models. Form to create LatticeModel CRDs with org label + pool selection.

4. **WatchedJob + WatchedService** — same pattern as Model.

5. **Quotas** — per-org allocation limits against pools. Validation on CRD creation.

## Open Questions

1. **Org identity in CRDs** — Label (`lattice.io/org`) vs namespace (`acme-corp` namespace per org)? Labels are simpler. Namespaces give stronger isolation but complicate multi-cluster.

2. **Pool → Cluster cardinality** — 1:1 for v0. Does the operator need to support 1:many?

3. **Console-only mutations** — Should the console be the only way to create compute CRDs? Or can users kubectl apply and the watcher picks it up? Watcher handles both, but quota enforcement only works through the console.

4. **LatticePool CRD** — Does this already exist in the operator, or does it need to be designed? What fields does the operator need to provision clusters?
