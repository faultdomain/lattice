# Lattice Console: UI/UX Design Document

## The Problem

Lattice today is a collection of CRDs, CLI commands, and kubectl workflows. It works, but operating it requires expertise that doesn't scale. These are the real problems people hit:

**An on-call SRE gets paged at 3AM.** A service is down. They don't know which cluster, which service, or why. Today they start a 30-minute scavenger hunt: cycle through kubectl contexts, grep CRD statuses, check ztunnel logs for RBAC denials, trace bilateral mesh agreements by hand. By the time they find the root cause — a Cedar policy was blocking secret access to the auth service — the incident has been open for 45 minutes.

**A developer deploys a service and it can't reach its dependency.** Is the bilateral agreement wrong? Did they declare outbound but the callee didn't declare inbound? Is it a Cedar policy denial? A ztunnel RBAC rejection? Today there's no way to answer this without reading both services' CRD specs, cross-referencing their `resources` blocks, and manually checking ztunnel logs on the target cluster.

**A platform engineer provisions a new cluster.** It takes 20–30 minutes. They run `kubectl get latticecluster -w` and watch phase transitions: Pending, Provisioning, Pivoting, Ready. If it stalls in Provisioning for 15 minutes, they have no idea if CAPI is creating VMs, waiting for a load balancer, or blocked on a credential issue. They wait, or they go spelunking through CAPI resources.

**An ML engineer wants to run a training job.** How many GPUs are available? Across which pools? Which clusters back those pools? Are other jobs about to finish and free up capacity? Today: `kubectl get latticepools -o yaml` and do mental arithmetic across multiple clusters.

**A security engineer changes a Cedar policy.** What services does this affect? Will it break something in production? Today: apply and find out. There is no dry-run, no blast radius preview, no way to see which service-secret bindings would be permitted or denied under the new policy.

**Nobody has a mental model of the cluster hierarchy.** Lattice's architecture — self-managing clusters, parent-child relationships, outbound-only agents, cross-cluster routing — is powerful but invisible. There is no way to see the topology, which agents are connected, which clusters can survive parent failure, or how routes flow across the hierarchy.

The console exists to make these problems go away.

---

## Who Uses This

Four personas, each with different urgency and depth requirements:

### The On-Call SRE

**Goal:** Find the broken thing and fix it, fast.

They don't care about the architecture. They care about: what's red, why is it red, and what do I do about it. They need the system to surface problems without being asked. They need to go from alert to root cause in under 5 minutes, not 45.

**What they need:**
- A view that immediately shows what's unhealthy across all clusters
- Drill-down from "cluster degraded" to "service failed" to "Cedar policy denied secret access" without losing context
- Actionable next steps at every level (not just "Failed" — but "Failed because X, try Y")
- Exec/log access to any pod in any cluster without context-switching

### The Application Developer

**Goal:** Deploy services that work, debug them when they don't.

They know their service but not the platform internals. Mesh policies, bilateral agreements, and Cedar authorization are things they configure in YAML but can't easily debug. When service A can't talk to service B, they need to understand why in terms they recognize — not in terms of CiliumNetworkPolicy and Istio AuthorizationPolicy.

**What they need:**
- A service-centric view showing their service's dependencies and whether they're healthy
- Clear explanation of mesh connectivity: "You declared outbound to `payments`, but `payments` hasn't declared inbound from you"
- Secret access status: which secrets are authorized, which are denied, and by which Cedar policy
- Logs, metrics, and exec without knowing which cluster their service landed on

### The Platform Engineer

**Goal:** Provision and manage infrastructure reliably.

They think in terms of clusters, pools, providers, and capacity. They need to see the full topology, track provisioning progress, manage GPU pools, and plan capacity.

**What they need:**
- Cluster hierarchy visualization showing parent-child relationships, agent connectivity, and phases
- Provisioning timeline with sub-phase visibility (CAPI progress, not just LatticeCluster phase)
- Pool and GPU capacity dashboard: total, allocated, available, by pool and cluster
- Upgrade orchestration visibility: which clusters are on which versions, cascade status

### The Security Engineer

**Goal:** Manage access policies without breaking production.

They own Cedar policies, OIDC providers, and secret provider configurations. They need to understand the blast radius of policy changes before applying them.

**What they need:**
- Cedar policy editor with syntax validation and dry-run
- "What would this policy change affect?" — list of service-secret bindings that would change
- Audit view: which services accessed which secrets, authorized by which policy
- Cross-cluster policy propagation status (which children have received the latest policies)

---

## User Stories

### S1: Incident Triage — "Something Is Broken, Find It"

**As an on-call SRE, I need to identify the root cause of an incident across a multi-cluster hierarchy in under 5 minutes.**

Flow:

```
Open Console
    │
    ▼
System Map shows cluster topology
    │  One node is red (cluster "prod-east" is Degraded)
    │  The cluster badge shows "2 services unhealthy"
    ▼
Click "prod-east"
    │
    ▼
Cluster Detail opens. Services tab shows:
    │  ✓ api-gateway      Ready
    │  ✓ user-service      Ready
    │  ✕ auth-service      Failed — "Cedar policy denied secret access: vault:auth/signing-key"
    │  ✓ order-service     Ready
    ▼
Click "auth-service"
    │
    ▼
Service Detail shows:
    │  Phase: Failed
    │  Condition: SecretAccessDenied
    │  Secret: vault:auth/signing-key
    │  Policy: "prod-secrets-v2" (priority 10, line 4: forbid principal == Lattice::Service::"default/auth-service")
    │
    │  [View Policy] [Edit Policy] [View Logs] [Exec]
    ▼
Click "Edit Policy"
    │
    ▼
Cedar Editor opens with "prod-secrets-v2" loaded
    │  Error highlighted on line 4 — this forbid was added in last change
    │  Sidebar shows: "This policy affects 3 services, denying 1 secret binding"
    ▼
Fix the policy, save
    │
    ▼
Service phase transitions: Failed → Compiling → Ready
    │  Visible in real-time without refresh
```

**Time to resolution: 2–3 minutes.** The SRE never ran a single kubectl command.

---

### S2: Mesh Debugging — "Why Can't A Talk to B?"

**As a developer, I need to understand why my service can't reach its dependency, without understanding Cilium or Istio internals.**

Flow:

```
Open Console → navigate to service "order-service" on cluster "prod-east"
    │
    ▼
Service Detail → Dependencies section shows:
    │  ✓ user-service     outbound   CONNECTED    (bilateral agreement: both sides agree)
    │  ✕ payment-service  outbound   DENIED       (bilateral agreement: INCOMPLETE)
    │  ✓ notification-svc outbound   CONNECTED    (bilateral agreement: both sides agree)
    ▼
Click the "DENIED" row for payment-service
    │
    ▼
Dependency Detail panel shows:
    │
    │  order-service declares:
    │    resources.payments.type: service
    │    resources.payments.direction: outbound    ✓ Present
    │    resources.payments.id: payment-service
    │
    │  payment-service declares:
    │    (no inbound declaration for order-service) ✕ MISSING
    │
    │  What's needed:
    │    payment-service must add a resource with
    │    direction: inbound referencing order-service
    │
    │  [View payment-service YAML] [Copy suggested fix]
    ▼
Click "Copy suggested fix"
    │
    ▼
Clipboard contains the resource block to add to payment-service's spec
```

The developer never needed to know what a CiliumNetworkPolicy is. The UI translated the bilateral agreement model into cause-and-effect.

---

### S3: Cluster Provisioning — "What's Taking So Long?"

**As a platform engineer, I need to see where a cluster provision is stuck without digging through CAPI resources.**

Flow:

```
Open Console → System Map shows a new cluster "staging-west" as blue (Provisioning)
    │
    ▼
Click "staging-west"
    │
    ▼
Cluster Detail shows:
    │  Phase: Provisioning (12 min elapsed)
    │
    │  Provisioning Timeline:
    │  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    │  ✓ Credentials validated           (0:00)
    │  ✓ CAPI manifests applied           (0:12)
    │  ✓ Infrastructure created           (4:30)
    │  ◌ Waiting for control plane...     (12:00 — expected: 8–15 min)
    │  ○ API server ready
    │  ○ Bootstrap webhook called
    │  ○ Agent connected
    │  ○ Pivot started
    │  ○ Pivot complete
    │  ○ Infrastructure installed (Cilium, Istio, cert-manager...)
    │  ○ Ready
    │
    │  Conditions:
    │    ControlPlaneReady: False — "Waiting for 3 control plane machines (1/3 running)"
    │
    │  [View CAPI Resources] [View InfraProvider] [View Agent Logs]
```

Instead of `kubectl get machines -A` and guessing, the engineer sees exactly which sub-step is in progress and whether the elapsed time is within the expected range.

---

### S4: GPU Capacity Planning — "Can I Run This Job?"

**As an ML engineer, I need to know if there's capacity for my training job before submitting it.**

Flow:

```
Open Console → Pools view
    │
    ▼
Pool Dashboard:
    │
    │  ┌──────────────────────────────────────────────────────────┐
    │  │ h100-pool-east          │ h100-pool-west                │
    │  │ AWS us-east-1           │ AWS us-west-2                 │
    │  │ H100 × 8/node          │ H100 × 8/node                │
    │  │                         │                               │
    │  │ GPUs: 48/64 available   │ GPUs: 16/32 available         │
    │  │ ████████████░░░░ 75%    │ ████████████████ 50%          │
    │  │                         │                               │
    │  │ Nodes: 8/8 ready        │ Nodes: 4/4 ready              │
    │  │ Clusters: 1 (Ready)     │ Clusters: 1 (Ready)           │
    │  │                         │                               │
    │  │ Active workloads:       │ Active workloads:              │
    │  │  qwen3-8b (4 GPU)      │  llama-70b (8 GPU)            │
    │  │  bert-finetune (8 GPU) │  mixtral (8 GPU)              │
    │  │  (completion: ~2h)      │                               │
    │  └──────────────────────────────────────────────────────────┘
    │
    ▼
Engineer sees h100-pool-east has 48 GPUs available.
Their job needs 32 GPUs. It fits.
    │
    ▼
Click [New Job] on h100-pool-east
    │
    ▼
Job form pre-fills pool, shows real-time capacity check:
    │  "32 of 48 available GPUs will be allocated. 16 will remain."
```

---

### S5: Policy Blast Radius — "What Will This Break?"

**As a security engineer, I need to preview the impact of a Cedar policy change before applying it.**

Flow:

```
Open Console → Policies → select "production-secrets"
    │
    ▼
Cedar Editor with current policy loaded
    │
    ▼
Add new forbid statement:
    │  forbid (
    │    principal == Lattice::Service::"default/legacy-adapter",
    │    action == Lattice::Action::"AccessSecret",
    │    resource
    │  );
    ▼
Click [Preview Impact]
    │
    ▼
Impact panel shows:
    │
    │  This change will DENY 3 secret bindings:
    │
    │  ✕ default/legacy-adapter → vault:db/connection-string     (currently: permitted by "base-policy")
    │  ✕ default/legacy-adapter → vault:cache/redis-url          (currently: permitted by "base-policy")
    │  ✕ default/legacy-adapter → vault:auth/api-key             (currently: permitted by "base-policy")
    │
    │  Affected service: legacy-adapter (cluster: prod-east, phase: Ready)
    │  WARNING: This service is currently serving traffic.
    │
    │  [Apply] [Cancel] [Apply to staging first]
```

The security engineer sees exactly what will break. No surprises.

---

### S6: Cross-Cluster Visibility — "Show Me Everything"

**As a platform engineer, I need to see the full cluster hierarchy, agent connectivity, and cross-cluster routes at a glance.**

Flow:

```
Open Console → System Map
    │
    ▼
Topology graph renders the full hierarchy:

    ┌─────────────┐
    │   cell-01    │ ← parent (Cell mode)
    │   AWS/us-e1  │
    │   Ready ●    │
    │   Agent: n/a │
    │   12 svc     │
    └──────┬───────┘
           │
     ┌─────┼──────────────┐
     │     │              │
  ┌──▼──┐ ┌▼────┐   ┌────▼───┐
  │wk-01│ │wk-02│   │wk-03   │
  │Dockr│ │AWS  │   │Proxmox │
  │Rdy ●│ │Rdy ●│   │Prov ◌  │
  │ 8svc│ │ 5svc│   │ 0svc   │
  │conn.│ │conn.│   │conn.   │
  └──┬──┘ └─────┘   └────────┘
     │
  ┌──▼──┐
  │wk-04│ ← grandchild
  │Dockr│
  │Rdy ●│
  │ 3svc│
  │conn.│
  └─────┘

    ── solid line = agent connected
    -- dashed line = agent disconnected (still self-managing)
    ● Ready  ◌ Provisioning  ✕ Failed

    │
    ▼
Click wk-01 → see services, mesh, routes, nodes
Click edge between cell-01 and wk-01 → see gRPC stream health, last heartbeat, latency
Hover wk-04 → tooltip: "Grandchild of cell-01 via wk-01. Self-managing. 3 services, all healthy."
```

Cross-cluster routes are visible too:

```
Routes panel (bottom of System Map):
    │
    │  wk-01/default/api-gateway  →  wk-02/default/payment-service  (HTTP, bilateral: ✓)
    │  wk-01/default/order-svc    →  wk-04/default/inventory-svc    (gRPC, bilateral: ✓)
    │  wk-02/default/analytics    →  wk-01/default/user-service      (HTTP, bilateral: ✕ denied)
```

---

## Design Principles

These are non-negotiable. Every screen, component, and interaction must satisfy them.

### 1. Show the Problem, Not the Data

Never show a CRD status field and expect the user to interpret it. Translate machine state into human meaning:

- Bad: `phase: Failed, conditions: [{type: SecretAccessDenied, status: True}]`
- Good: "auth-service can't access vault:auth/signing-key — denied by Cedar policy 'prod-secrets-v2' (line 4)"

Every failure state in the system has a known set of causes. The UI should enumerate them, not require the user to discover them.

### 2. Progressive Disclosure

The landing page shows 5 things: cluster count, service count, how many are healthy, how many aren't, and a topology. That's it. Everything else is one click deeper.

Depth levels:
1. **System Map** — topology + aggregate health. Answers: "Is anything broken?"
2. **Cluster Detail** — services, nodes, routes, policies for one cluster. Answers: "What's broken in this cluster?"
3. **Resource Detail** — full spec, status, conditions, dependencies, actions for one resource. Answers: "Why is this specific thing broken and how do I fix it?"
4. **Raw View** — YAML/JSON of the CRD, editable. Answers: "Let me just look at the actual object."

Users should never need to go deeper than level 2 for routine operations.

### 3. Every Visualization Is Actionable

If a node in the topology graph is red, clicking it opens the cluster detail with the failure pre-filtered. If a mesh edge is denied, clicking it shows the bilateral agreement gap and offers to copy the fix. If a Cedar policy is invalid, the editor opens with the error highlighted.

No dead-end visualizations. Everything leads somewhere.

### 4. Developer-First Interaction Model

The primary navigation mechanism is `Cmd+K`. A command palette that fuzzy-searches every cluster, service, namespace, policy, pool, and job. Keyboard shortcuts for common actions. Vim-style `j/k` navigation in lists. A raw YAML toggle (`Cmd+J`) on every resource view.

The mouse is a fallback, not the primary input.

### 5. Real-Time Without Polling

Lattice agents already heartbeat every 30 seconds. Phase transitions, health changes, route updates, and policy propagation events already flow through the system. The UI subscribes to these events via WebSocket and re-renders in place. There is no "Refresh" button.

---

## Information Architecture

```
Console
├── System Map (landing page)
│   ├── Cluster topology graph (DAG, parent → child)
│   ├── Aggregate health bar (N healthy, M degraded, K failed)
│   ├── Cross-cluster route overlay (toggle)
│   └── Quick actions: [New Cluster] [New Pool] [Command Palette]
│
├── Clusters
│   ├── List view (table: name, phase, provider, nodes, services, agent status)
│   └── Detail view (tabbed)
│       ├── Overview — phase, conditions, provisioning timeline, K8s version, image
│       ├── Services — service list with phase, dependencies, health
│       ├── Nodes — control plane + worker pools, GPU capacity per pool
│       ├── Mesh — bilateral agreement graph for this cluster's services
│       ├── Routes — cross-cluster routes to/from this cluster
│       ├── Policies — Cedar policies applied to this cluster (local + propagated)
│       ├── Events — real-time event stream from the agent
│       └── YAML — raw CRD, editable
│
├── Services
│   ├── List view (filterable by cluster, namespace, phase)
│   └── Detail view
│       ├── Overview — phase, replicas, cost estimate, conditions
│       ├── Dependencies — bilateral agreements with status (allowed/denied/incomplete)
│       ├── Secrets — secret bindings with Cedar authorization status per binding
│       ├── Compiled Resources — what the ServiceCompiler produced (Deployment, Service, policies)
│       ├── Metrics — from ObservabilitySpec → VictoriaMetrics
│       ├── Pods — replica list with status, [Logs] [Exec] per pod
│       └── YAML — raw CRD, editable
│
├── Mesh (global)
│   ├── Graph view — all services across all clusters, edges = bilateral agreements
│   ├── Filters: cluster, namespace, direction, protocol, status (allowed/denied)
│   └── Edge detail — shows both sides of the agreement, Cilium + Istio policy refs
│
├── Pools
│   ├── Dashboard — cards per pool with GPU utilization bars
│   ├── Detail view — nodes, clusters, active workloads, capacity timeline
│   └── Actions: [Scale Pool] [New Model] [New Job]
│
├── Models
│   ├── List view (pool, phase, GPU count, endpoint URL)
│   └── Detail view — phase timeline, resource allocation, endpoint health, logs
│
├── Jobs
│   ├── List view (pool, phase, GPU count, duration, retries)
│   └── Detail view — phase timeline, resource allocation, logs, retry history
│
├── Policies
│   ├── List view (name, type, priority, phase, affected service count)
│   └── Editor — Monaco with Cedar syntax, live validation, impact preview
│
├── Providers
│   ├── InfraProviders — cloud accounts, credential status
│   ├── SecretProviders — ESO backends, sync status
│   └── OIDCProviders — identity providers, validation status
│
└── Terminal
    ├── Cluster context selector
    ├── Pod selector (namespace → pod → container)
    ├── Exec terminal (xterm.js via WebSocket)
    └── Log viewer (streaming, filterable)
```

---

## Architecture: Ash/Elixir + Rust

### Why Two Stacks

The Rust backend (the Lattice operator) is the sole owner of infrastructure state. It reconciles CRDs, manages cluster lifecycles, generates mesh policies, and handles the agent-cell protocol. It does not know about users, orgs, sessions, or UI concerns. This boundary is defined in `operator-console-contract.md`.

The Elixir/Ash backend owns everything the operator explicitly ignores: authentication, authorization (org-level, not infrastructure-level), session management, quota enforcement, real-time UI state, and user-facing API aggregation. Ash gives us declarative resources with built-in authorization and Phoenix gives us real-time push via LiveView.

The split:

| Concern | Owner | Why |
|---------|-------|-----|
| CRD reconciliation | Rust operator | Already built, battle-tested, performance-critical |
| Cluster lifecycle (CAPI, pivot) | Rust operator | Tight integration with K8s controllers |
| Mesh policy generation | Rust operator | Needs to be atomic with service compilation |
| Agent-cell gRPC protocol | Rust operator | Low-level, latency-sensitive |
| Cedar policy evaluation (infra) | Rust operator | Evaluated during reconciliation |
| User authentication (OIDC) | Elixir/Ash | Session management, token refresh, org mapping |
| Org-scoped authorization | Elixir/Ash | Quota enforcement, resource ownership, RBAC |
| Real-time UI state | Elixir/Phoenix | PubSub + LiveView, natural fit |
| API aggregation for UI | Elixir/Ash | Joins across CRDs, caching, pagination |
| Cedar policy dry-run (UI) | Elixir | UI-specific, calls Rust for evaluation |

### Data Flow

```
┌────────────────────────────────────────────────────────────────────────┐
│                          Browser                                       │
│  Phoenix LiveView (WebSocket) ←→ LiveSvelte islands (topology, mesh)  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ LiveView WebSocket (bidirectional)
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                       Elixir / Ash / Phoenix                           │
│                                                                        │
│  Ash Resources            Phoenix PubSub          LiveView Processes   │
│  ┌─────────────┐         ┌──────────────┐        ┌─────────────────┐  │
│  │ Cluster     │         │ Broadcasts:  │        │ Per-user:       │  │
│  │ Service     │         │  heartbeat   │        │  subscriptions  │  │
│  │ Pool        │         │  phase_change│        │  filtered by    │  │
│  │ Model       │◄────────│  route_update│───────►│  org + role     │  │
│  │ Job         │         │  policy_sync │        │                 │  │
│  │ CedarPolicy │         └──────▲───────┘        └─────────────────┘  │
│  └──────┬──────┘                │                                      │
│         │                       │                                      │
│  ┌──────▼──────────────────┐  ┌─┴─────────────────┐                   │
│  │ KubernetesProxy         │  │ EventBridge        │                   │
│  │ DataLayer               │  │ GenServer          │                   │
│  │ (HTTP → lattice-api)    │  │ (WS → lattice-api) │                   │
│  └──────┬──────────────────┘  └─┬─────────────────┘                   │
└─────────┼───────────────────────┼─────────────────────────────────────┘
          │ HTTPS (mTLS)          │ WebSocket
          │                       │
┌─────────▼───────────────────────▼─────────────────────────────────────┐
│                       Rust / Lattice Operator                          │
│                                                                        │
│  lattice-api (Axum, :8443)                                            │
│  ├── GET  /clusters/{name}/apis/...    K8s API proxy                  │
│  ├── POST /clusters/{name}/apis/...    CRD mutations                  │
│  ├── GET  /kubeconfig                  Multi-cluster kubeconfig        │
│  ├── WS   /clusters/{name}/.../exec    Terminal sessions              │
│  └── WS   /events                      Real-time event stream (NEW)   │
│                                                                        │
│  lattice-cell (gRPC, :9090)                                           │
│  ├── SubtreeRegistry         Cluster hierarchy (DashMap, in-memory)   │
│  ├── Agent heartbeats        30s interval, spec/status hashes         │
│  └── Route reconciler        LatticeClusterRoutes CRD updates        │
└────────────────────────────────────────────────────────────────────────┘
```

### New Rust Endpoint: WebSocket Event Stream

One addition to the Rust backend. The SubtreeRegistry already holds the full cluster hierarchy and receives heartbeats in real-time. We add a WebSocket endpoint that streams these events:

```
WS /events

Client → Server (subscribe):
  {"subscribe": "clusters"}              // all cluster phase/health changes
  {"subscribe": "cluster:prod-east"}     // one cluster's events
  {"subscribe": "services:prod-east"}    // services on one cluster
  {"subscribe": "routes"}               // cross-cluster route changes
  {"subscribe": "policies"}             // Cedar policy propagation status

Server → Client (events):
  {"type": "heartbeat",     "cluster": "prod-east", "health": {...}, "ts": "..."}
  {"type": "phase_change",  "cluster": "prod-east", "phase": "Ready", "ts": "..."}
  {"type": "service_phase", "cluster": "prod-east", "service": "auth-svc", "phase": "Failed", "ts": "..."}
  {"type": "route_update",  "cluster": "wk-01", "routes": [...], "ts": "..."}
  {"type": "policy_sync",   "cluster": "wk-02", "policy": "prod-secrets", "status": "applied", "ts": "..."}
```

Auth is the same as existing endpoints: Bearer token, OIDC or ServiceAccount, Cedar-authorized. The Elixir EventBridge GenServer maintains a single authenticated WebSocket to the Rust backend and fans out to Phoenix PubSub topics.

### Ash Resource Definitions

Each Lattice CRD maps to an Ash Resource. The custom DataLayer translates Ash actions into HTTP calls to the Lattice API proxy:

```elixir
defmodule Lattice.Resources.Cluster do
  use Ash.Resource,
    domain: Lattice.Infrastructure,
    data_layer: Lattice.DataLayer.KubernetesProxy

  attributes do
    attribute :name, :string, primary_key?: true, allow_nil?: false
    attribute :phase, :atom  # :pending, :provisioning, :pivoting, :ready, :failed, ...
    attribute :provider_type, :atom
    attribute :kubernetes_version, :string
    attribute :lattice_image, :string
    attribute :parent_name, :string
    attribute :agent_connected, :boolean
    attribute :node_count, :integer
    attribute :ready_node_count, :integer
    attribute :gpu_total, :integer
    attribute :gpu_available, :integer
    attribute :conditions, {:array, :map}
    attribute :spec, :map    # raw spec for YAML view
    attribute :status, :map  # raw status for YAML view
  end

  relationships do
    has_many :services, Lattice.Resources.Service
    has_many :children, __MODULE__, destination_attribute: :parent_name
    has_many :routes, Lattice.Resources.ClusterRoute
  end

  actions do
    read :list    # GET /apis/lattice.io/v1alpha1/latticeclusters
    read :get     # GET /apis/lattice.io/v1alpha1/latticeclusters/:name
    create :provision
    update :scale
    update :upgrade
    destroy :delete
  end

  policies do
    policy action_type(:read) do
      authorize_if Lattice.Checks.OrgMember
    end
    policy action_type([:create, :update, :destroy]) do
      authorize_if Lattice.Checks.OrgAdmin
    end
  end
end
```

The `KubernetesProxy` DataLayer handles translation:

```elixir
defmodule Lattice.DataLayer.KubernetesProxy do
  @moduledoc """
  Translates Ash CRUD operations into HTTP requests to the
  Lattice API server's K8s API proxy. All requests go through
  the existing Rust auth chain (OIDC -> Cedar).

  list   → GET  /clusters/{cell}/apis/lattice.io/v1alpha1/latticeclusters
  get    → GET  /clusters/{cell}/apis/lattice.io/v1alpha1/latticeclusters/{name}
  create → POST /clusters/{cell}/apis/lattice.io/v1alpha1/latticeclusters
  update → PUT  /clusters/{cell}/apis/lattice.io/v1alpha1/latticeclusters/{name}
  delete → DELETE /clusters/{cell}/apis/lattice.io/v1alpha1/latticeclusters/{name}
  """
  use Ash.DataLayer
  # ...
end
```

This means the Elixir layer never holds K8s credentials directly. All access is proxied through the Rust backend's existing auth and tunnel infrastructure.

---

## Component Strategy

### Stack: Phoenix LiveView + LiveSvelte + Tailwind + Radix

- **Phoenix LiveView** — server-rendered, real-time. Most of the UI is lists, tables, tabs, forms. LiveView handles this natively over its WebSocket.
- **LiveSvelte** — Svelte islands embedded in LiveView for the three components that need client-side rendering: topology graph, mesh graph, exec terminal.
- **Tailwind CSS** — utility classes for compact, high-density layouts. Infrastructure UIs need information density, not whitespace.
- **Radix UI (via Svelte ports)** — accessible, unstyled primitives for dropdowns, dialogs, popovers, tabs. We style them ourselves.

### Key Components

**PhaseIndicator** — used everywhere. Maps every phase enum to a color and icon:

| Phase | Color | Icon | Animation |
|-------|-------|------|-----------|
| Ready, Valid, Succeeded, Serving | Green | Filled circle | None |
| Pending | Gray | Empty circle | None |
| Provisioning, Pivoting, Compiling, Scheduling, Loading, Progressing | Blue | Circle | Pulse |
| Running | Blue | Circle | Spin |
| Degraded | Amber | Warning triangle | None |
| Failed, Invalid | Red | X circle | None |
| Deleting, Unpivoting | Gray | Circle | Fade |

**ResourceTable** — virtualized table (windowed rendering for 1000+ rows). Columns auto-derived from resource attributes. Sortable, filterable, with fuzzy search. Keyboard navigable (j/k/Enter).

**CommandPalette** — `Cmd+K` overlay. Indexes all resources across all clusters. Actions context-sensitive to selection:

```
> prod-east
  ● Cluster: prod-east (Ready) — AWS us-east-1
  ● Service: prod-east/default/auth-service (Ready)
  ● Service: prod-east/default/api-gateway (Ready)
  ⚡ Action: Exec into pod on prod-east
  ⚡ Action: View logs on prod-east
```

**ClusterTopology** (Svelte + D3) — force-directed DAG. Nodes are clusters, edges are parent-child. Real-time updates pushed from LiveView. Zoom, pan, click-to-drill-down.

**MeshGraph** (Svelte + D3) — force-directed graph. Nodes are services, edges are bilateral agreements. Color-coded by status. Filterable. At >200 edges, switches to WebGL rendering and namespace-level aggregation.

**ExecTerminal** (Svelte + xterm.js) — WebSocket terminal. Connects through the Lattice API proxy's existing exec endpoint. Multi-hop aware (shows the routing path in the header).

**CedarEditor** (Svelte + Monaco) — Cedar policy editor with syntax highlighting, live validation (calls CRD validation endpoint), and impact preview panel.

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Cmd+K` | Command palette |
| `Cmd+J` | Toggle JSON/YAML view on current resource |
| `Cmd+E` | Exec into selected pod |
| `Cmd+L` | Stream logs for selected pod |
| `Cmd+/` | Toggle sidebar |
| `g c` | Go to clusters |
| `g s` | Go to services |
| `g m` | Go to mesh |
| `g p` | Go to policies |
| `g o` | Go to pools |
| `/` | Focus search/filter |
| `j` / `k` | Navigate list items |
| `Enter` | Open selected item |
| `Esc` | Close panel / clear filter |
| `e` | Edit current resource YAML |
| `r` | Refresh current view |
| `?` | Show keyboard shortcut help |

---

## State Management

### Real-Time Push via WebSocket

No polling anywhere in the UI. The data flow:

1. **Agent heartbeat** (every 30s) arrives at the Rust Cell via gRPC
2. Rust updates SubtreeRegistry, broadcasts on `/events` WebSocket
3. Elixir EventBridge GenServer receives the event
4. EventBridge broadcasts to Phoenix PubSub topic (e.g., `"cluster:prod-east"`)
5. LiveView processes subscribed to that topic receive the message
6. LiveView updates assigns, re-renders the diff
7. Browser receives the HTML diff over the LiveView WebSocket

For Svelte islands (topology graph, mesh graph), LiveView pushes updated data via `push_event/3`, and Svelte re-renders client-side.

### Caching Strategy

The Elixir layer maintains a local cache (ETS table) of cluster and service states, populated from the `/events` WebSocket stream. This avoids hitting the Rust API on every LiveView mount. Cache entries are invalidated on every event for the corresponding resource.

Fresh LiveView mounts:
1. Read from ETS cache (fast, microseconds)
2. Render immediately
3. Subscribe to PubSub for real-time updates
4. Background refresh from Rust API if cache entry is >60s old

This gives instant page loads with eventual consistency measured in seconds, not minutes.

### Scaling: 5 to 5,000 Resources

| Scale | UI Strategy |
|-------|-------------|
| < 50 clusters | Render everything, no virtualization |
| 50–500 | Virtualized tables, topology graph collapses subtrees by default |
| 500–5,000 | Server-side pagination in Ash, graph shows 2 levels from selected node, search is the primary navigation |
| Services per cluster | Same thresholds, scoped to cluster context |
| Mesh edges > 200 | Aggregate by namespace, WebGL rendering, expand on click |

The SubtreeRegistry already caps at 5,000 clusters (`MAX_CLUSTERS_PER_SUBTREE`), so we have a known upper bound.

---

## Operator Contract Compliance

Per `operator-console-contract.md`, the console:

- Sets `lattice.io/org` label on CRDs it creates (operator ignores it)
- Sets `lattice.io/created-by: console` annotation (optional provenance)
- Reads `status` fields to build UI state (never writes to status)
- Reads `conditions` for specific error messages (not just phase)
- Respects that scheduling decisions are operator-only (displays `status.resources.cluster`, never influences it)
- Handles quota enforcement locally (operator only checks capacity)
- Deletes org's CRDs on org deletion (operator just reconciles what exists)

The console does not:
- Bypass the Rust API to talk to K8s directly
- Duplicate reconciliation logic
- Second-guess operator scheduling
- Add UI-hint fields to CRD specs

---

## Elixir Application Structure

```
lattice_console/
├── lib/
│   ├── lattice/                              # Ash domain layer
│   │   ├── infrastructure.ex                 # Domain: Cluster, Pool, InfraProvider
│   │   ├── workloads.ex                      # Domain: Service, Model, Job
│   │   ├── authorization.ex                  # Domain: CedarPolicy, OIDCProvider
│   │   ├── secrets.ex                        # Domain: SecretProvider
│   │   │
│   │   ├── resources/
│   │   │   ├── cluster.ex                    # Ash.Resource — LatticeCluster
│   │   │   ├── service.ex                    # Ash.Resource — LatticeService
│   │   │   ├── pool.ex                       # Ash.Resource — LatticePool
│   │   │   ├── model.ex                      # Ash.Resource — LatticeModel
│   │   │   ├── job.ex                        # Ash.Resource — LatticeJob
│   │   │   ├── mesh_member.ex                # Ash.Resource — LatticeMeshMember
│   │   │   ├── cedar_policy.ex               # Ash.Resource — CedarPolicy
│   │   │   ├── infra_provider.ex             # Ash.Resource — InfraProvider
│   │   │   ├── secret_provider.ex            # Ash.Resource — SecretProvider
│   │   │   ├── cluster_route.ex              # Ash.Resource — LatticeClusterRoutes
│   │   │   └── oidc_provider.ex              # Ash.Resource — OIDCProvider
│   │   │
│   │   ├── data_layer/
│   │   │   └── kubernetes_proxy.ex           # Custom DataLayer → lattice-api HTTP
│   │   │
│   │   └── checks/
│   │       ├── org_member.ex                 # Ash.Policy.Check — org membership
│   │       └── org_admin.ex                  # Ash.Policy.Check — org admin role
│   │
│   ├── lattice_console/
│   │   ├── accounts/                         # User, Org, Membership (Postgres-backed)
│   │   ├── event_bridge.ex                   # GenServer: WS to Rust → PubSub
│   │   └── cache.ex                          # ETS cache populated from event stream
│   │
│   └── lattice_web/
│       ├── live/
│       │   ├── system_map_live.ex            # Landing page: topology + health
│       │   ├── cluster_live/
│       │   │   ├── index.ex                  # Cluster list
│       │   │   ├── show.ex                   # Cluster detail (tabbed)
│       │   │   └── form_component.ex         # Create/edit cluster form
│       │   ├── service_live/
│       │   │   ├── index.ex                  # Service list
│       │   │   └── show.ex                   # Service detail
│       │   ├── pool_live/
│       │   │   ├── index.ex                  # Pool dashboard
│       │   │   └── show.ex                   # Pool detail
│       │   ├── model_live/
│       │   │   ├── index.ex
│       │   │   └── show.ex
│       │   ├── job_live/
│       │   │   ├── index.ex
│       │   │   └── show.ex
│       │   ├── mesh_live.ex                  # Global mesh visualization
│       │   ├── policy_live/
│       │   │   ├── index.ex
│       │   │   └── editor.ex                # Cedar editor + impact preview
│       │   ├── provider_live/
│       │   │   ├── infra.ex
│       │   │   ├── secret.ex
│       │   │   └── oidc.ex
│       │   └── terminal_live.ex              # Exec + logs
│       │
│       ├── components/
│       │   ├── phase_indicator.ex            # PhaseIndicator (LiveView component)
│       │   ├── resource_table.ex             # Virtualized table
│       │   ├── condition_list.ex             # K8s Condition[] renderer
│       │   ├── command_palette.ex            # Cmd+K fuzzy search
│       │   ├── breadcrumb.ex
│       │   └── yaml_viewer.ex               # Toggle YAML/JSON view
│       │
│       └── svelte/                           # LiveSvelte islands
│           ├── ClusterTopology.svelte        # D3 force-directed DAG
│           ├── MeshGraph.svelte              # D3 bilateral agreement graph
│           ├── ExecTerminal.svelte           # xterm.js WebSocket terminal
│           ├── CedarEditor.svelte            # Monaco editor
│           ├── LogStream.svelte              # Virtualized log viewer
│           ├── ProvisionTimeline.svelte      # Horizontal phase timeline
│           └── GpuCapacityBar.svelte         # GPU utilization visualization
│
├── assets/
│   ├── css/
│   │   └── app.css                           # Tailwind imports
│   └── js/
│       └── app.js                            # LiveView + LiveSvelte hooks
│
└── config/
    └── runtime.exs
        # LATTICE_API_URL      — Rust API server (https://...)
        # LATTICE_API_TOKEN    — Service account token for API access
        # DATABASE_URL         — Postgres for accounts/orgs
        # SECRET_KEY_BASE      — Phoenix session encryption
```

---

## Implementation Order

The order is driven by which user stories deliver value fastest:

### Phase 1: See What's Broken (S1, S6)

Build the System Map and Cluster Detail. This solves the most acute pain — incident triage — and exercises the full stack (Ash DataLayer, WebSocket event bridge, LiveView, topology visualization).

Deliverables:
- Elixir project scaffold with Ash, Phoenix, LiveSvelte
- `KubernetesProxy` DataLayer (read-only initially)
- `Cluster` Ash Resource
- Rust `/events` WebSocket endpoint
- Elixir EventBridge GenServer + PubSub
- System Map LiveView + ClusterTopology Svelte component
- Cluster Detail LiveView (Overview + Events tabs)
- PhaseIndicator component
- Command palette (Cmd+K) with cluster search

### Phase 2: Debug Service Issues (S2)

Build Service Detail and Mesh visualization. This solves the second most common pain — service connectivity debugging.

Deliverables:
- `Service`, `MeshMember` Ash Resources
- Service Detail LiveView (Dependencies + Secrets tabs)
- MeshGraph Svelte component
- Bilateral agreement explanation UI ("A declared outbound, B missing inbound")
- Mesh view (global)

### Phase 3: Manage Infrastructure (S3, S4)

Build provisioning visibility and GPU pool management. This enables platform engineers to self-serve.

Deliverables:
- `Pool`, `Model`, `Job` Ash Resources
- Cluster provisioning timeline (ProvisionTimeline Svelte component)
- Pool dashboard with GPU capacity bars
- Model and Job list/detail views
- Write operations in DataLayer (create, update, delete)

### Phase 4: Secure Safely (S5)

Build the Cedar policy editor with impact preview. This enables security engineers to operate confidently.

Deliverables:
- `CedarPolicy` Ash Resource
- CedarEditor Svelte component (Monaco + Cedar syntax)
- Impact preview (dry-run: evaluate policy change against current bindings)
- Policy propagation status across cluster hierarchy

### Phase 5: Operate In-Browser (Terminal)

Build exec and log streaming. This eliminates the last reason to leave the console.

Deliverables:
- ExecTerminal Svelte component (xterm.js)
- LogStream Svelte component
- Multi-hop cluster context selection
- Terminal LiveView
