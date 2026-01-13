# Lattice Solver & UI Design

## Vision: Pure Service-Level Thinking

Users should never think about clusters, regions, or infrastructure. They declare services and requirements; Lattice derives everything else.

```
"I need service A to talk to service B with <10ms latency"
                          ↓
            Lattice handles everything
```

## What Lattice Solves

```
User declares:                     Lattice derives:
─────────────────────────────────────────────────────────────
frontend → api < 10ms        →    Same cluster (same zone)
api → postgres < 5ms         →    Same cluster (same zone)
api → redis < 2ms            →    Same cluster (same zone)
postgres: SOC2 && HIPAA      →    Cluster in compliant region
postgres: country in [US,EU] →    Cluster in allowed country
api → stripe < 200ms         →    Any cluster (no placement constraint)
```

**Two requirement types:**
1. **Latency** (metrics-based): Services with tight latency get grouped together
2. **Placement** (CEL expressions): Filter which clusters are valid

---

## Data Model

### LatticeService with Requirements

The existing `LatticeService` CRD is extended with a `requirements` field:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: api
spec:
  environment: prod

  containers:
    main:
      image: myapp/api:v1.2
      resources:
        requests:
          cpu: 500m
          memory: 512Mi

  resources:
    # Dependencies (existing)
    postgres:
      type: postgres
      direction: outbound

    redis:
      type: redis
      direction: outbound

    stripe:
      type: external-service
      direction: outbound
      params:
        url: https://api.stripe.com

    frontend:
      type: service
      direction: inbound  # frontend calls me

  # NEW: Requirements block
  requirements:
    # Latency constraints on edges
    latency:
      - from: frontend
        max: 10ms
        percentile: p99
      - to: postgres
        max: 5ms
        percentile: p99
      - to: stripe
        max: 200ms
        percentile: p99

    # Service-level availability
    availability: 99.95%

    # Compliance requirements
    compliance:
      - SOC2

    # Data residency (hard constraint)
    residency:
      allowed: [us, eu]

    # Cost optimization preference
    cost: balanced  # or: optimize | performance

    # Throughput expectations (for sizing)
    throughput:
      requests_per_second: 10000
```

### Requirements: Hard Constraints + Soft Preferences

**Hard constraints** are CEL expressions - solver fails if no cluster satisfies them.
**Soft preferences** are inferred from `resources` - solver scores clusters by proximity to dependencies.

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: api
spec:
  resources:
    # Dependencies are used for soft preference scoring
    postgres:
      type: postgres
      direction: outbound    # Solver prefers cluster near postgres

    redis:
      type: redis
      direction: outbound    # Solver prefers cluster near redis

    frontend:
      type: service
      direction: inbound     # Solver prefers cluster near frontend

  requirements:
    # Hard constraints only - CEL expressions
    placement:
      # Simple: must be in compliant region
      - expr: '"SOC2" in cluster.compliance'

      # AND: must be SOC2 AND in US
      - expr: '"SOC2" in cluster.compliance && cluster.region.startsWith("us-")'

      # OR: must be in EU OR have GDPR compliance
      - expr: 'cluster.region.startsWith("eu-") || "GDPR" in cluster.compliance'

      # NOT: must NOT be in China
      - expr: '!cluster.region.startsWith("cn-")'

      # Complex: (HIPAA AND US) OR (GDPR AND EU)
      - expr: |
          ("HIPAA" in cluster.compliance && cluster.country == "US") ||
          ("GDPR" in cluster.compliance && cluster.country in ["DE", "FR", "NL"])
```

### Solver Algorithm

```
1. FILTER: Find clusters where ALL CEL expressions evaluate to true
   → If none: Unschedulable (hard constraint failed)

2. SCORE: For each valid cluster, calculate proximity score:
   - Same zone as dependency: +100 points
   - Same region as dependency: +50 points
   - Same provider as dependency: +10 points
   - Score is sum across all dependencies (from resources)

3. SELECT: Pick cluster with highest score
   → Ties broken by: existing traffic > cost > alphabetical
```

### Colocation is a Preference, Not a Requirement

By default, the solver *tries* to colocate but doesn't fail:

```yaml
resources:
  postgres:
    type: postgres
    direction: outbound
# Solver prefers same zone as postgres, but will pick another zone
# if that's the only cluster satisfying hard constraints
```

If you **must** be colocated (hard requirement), use CEL:

```yaml
requirements:
  placement:
    # Hard: fail if can't be in same zone as postgres
    - expr: 'cluster.zone == services.postgres.zone'

    # Hard: at least same region as redis
    - expr: 'cluster.region == services.redis.region'
```

### Why CEL?

Kubernetes label selectors only support AND:
```yaml
# K8s matchLabels - implicitly AND, no OR support
matchLabels:
  compliance: SOC2
  region: us-east-1
```

CEL (Common Expression Language) gives us:
- **AND**: `a && b`
- **OR**: `a || b`
- **NOT**: `!a`
- **IN**: `x in [a, b, c]`
- **String ops**: `startsWith`, `endsWith`, `contains`
- **Service references**: `services.postgres.region`, `services.api.zone`
- **Already in K8s**: Used by ValidatingAdmissionPolicy, Gateway API

### CEL Context

```yaml
# Available in CEL expressions:

cluster:                          # The cluster being evaluated
  region: "us-east-1"
  zone: "us-east-1a"
  country: "US"
  provider: "aws"
  compliance: ["SOC2", "HIPAA"]
  labels: { "team": "platform" }

services:                         # Other services' current placements
  postgres:
    region: "us-east-1"
    zone: "us-east-1a"
    cluster: "prod-us-east-1"
  redis:
    region: "us-east-1"
    zone: "us-east-1b"
    cluster: "prod-us-east-1"
```

### CEL Expression Examples

| Requirement | CEL Expression |
|-------------|----------------|
| SOC2 compliant | `"SOC2" in cluster.compliance` |
| Same zone as postgres | `cluster.zone == services.postgres.zone` |
| Same region as postgres | `cluster.region == services.postgres.region` |
| Same cluster as postgres | `cluster.name == services.postgres.cluster` |
| US only | `cluster.country == "US"` |
| NOT China | `!cluster.region.startsWith("cn-")` |
| HIPAA in US | `"HIPAA" in cluster.compliance && cluster.country == "US"` |

### Requirements Types (Rust)

```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct Requirements {
    /// Hard placement constraints as CEL expressions
    ///
    /// All expressions must evaluate to true for a cluster to be valid.
    /// If no cluster satisfies all constraints, service is Unschedulable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub placement: Vec<PlacementRequirement>,
}

impl Requirements {
    pub fn is_empty(&self) -> bool {
        self.placement.is_empty()
    }
}

/// CEL-based placement requirement (hard constraint)
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PlacementRequirement {
    /// CEL expression that must evaluate to true
    ///
    /// Available variables:
    /// - `cluster.region` - Region identifier (e.g., "us-east-1")
    /// - `cluster.zone` - Zone identifier (e.g., "us-east-1a")
    /// - `cluster.country` - ISO country code (e.g., "US", "DE")
    /// - `cluster.provider` - Cloud provider ("aws", "gcp", "azure")
    /// - `cluster.compliance` - List of certs (e.g., ["SOC2", "HIPAA"])
    /// - `cluster.labels` - Arbitrary labels from LatticeCluster
    /// - `services.<name>.region` - Region where service is placed
    /// - `services.<name>.zone` - Zone where service is placed
    /// - `services.<name>.cluster` - Cluster name where service is placed
    pub expr: String,

    /// Human-readable description (shown in UI and error messages)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
```

### Cluster Context for CEL

CEL expressions evaluate against a `cluster` object:

```rust
/// Context available to CEL placement expressions
#[derive(Debug, Clone, Serialize)]
pub struct ClusterContext {
    /// Region identifier (e.g., "us-east-1", "eu-west-1")
    pub region: String,

    /// Zone identifier (e.g., "us-east-1a")
    pub zone: String,

    /// ISO country code (e.g., "US", "DE", "JP")
    pub country: String,

    /// Cloud provider (e.g., "aws", "gcp", "azure")
    pub provider: String,

    /// Compliance certifications this cluster/region has
    pub compliance: Vec<String>,  // ["SOC2", "HIPAA", "ISO27001"]

    /// Arbitrary labels from LatticeCluster
    pub labels: HashMap<String, String>,
}
```

### CEL Expression Examples

| Requirement | CEL Expression |
|-------------|----------------|
| SOC2 compliant | `"SOC2" in cluster.compliance` |
| US region | `cluster.country == "US"` |
| AWS only | `cluster.provider == "aws"` |
| EU data residency | `cluster.country in ["DE", "FR", "NL", "IE", "SE"]` |
| NOT China | `!cluster.region.startsWith("cn-")` |
| HIPAA in US | `"HIPAA" in cluster.compliance && cluster.country == "US"` |
| EU or GDPR | `cluster.region.startsWith("eu-") \|\| "GDPR" in cluster.compliance` |
| Specific zones | `cluster.zone in ["us-east-1a", "us-east-1b"]` |
| Custom label | `cluster.labels.team == "platform"` |

### CEL Evaluation (Rust)

Using the `cel-interpreter` crate:

```rust
use cel_interpreter::{Context, Program};

pub struct PlacementEvaluator {
    /// Pre-compiled CEL programs (for performance)
    programs: HashMap<String, Program>,
}

impl PlacementEvaluator {
    /// Compile a CEL expression
    pub fn compile(&mut self, expr: &str) -> Result<(), CelError> {
        let program = Program::compile(expr)?;
        self.programs.insert(expr.to_string(), program);
        Ok(())
    }

    /// Evaluate placement requirements against a cluster
    pub fn evaluate(
        &self,
        requirements: &[PlacementRequirement],
        cluster: &ClusterContext,
    ) -> Result<bool, CelError> {
        let mut ctx = Context::default();
        ctx.add_variable("cluster", cluster)?;

        for req in requirements {
            let program = self.programs.get(&req.expr)
                .ok_or(CelError::NotCompiled)?;

            let result = program.execute(&ctx)?;

            if !result.as_bool()? {
                return Ok(false);
            }
        }

        Ok(true)  // All requirements satisfied
    }

    /// Find clusters that satisfy all requirements
    pub fn find_valid_clusters(
        &self,
        requirements: &[PlacementRequirement],
        clusters: &[ClusterContext],
    ) -> Vec<&ClusterContext> {
        clusters
            .iter()
            .filter(|c| self.evaluate(requirements, c).unwrap_or(false))
            .collect()
    }
}
```

### Validation at Admission Time

Validate CEL expressions when LatticeService is created:

```rust
impl LatticeService {
    pub fn validate_requirements(&self) -> Result<(), ValidationError> {
        let evaluator = PlacementEvaluator::new();

        for (i, req) in self.spec.requirements.placement.iter().enumerate() {
            // Check CEL syntax
            if let Err(e) = evaluator.compile(&req.expr) {
                return Err(ValidationError::InvalidCel {
                    index: i,
                    expr: req.expr.clone(),
                    error: e.to_string(),
                });
            }

            // Check that expression returns bool
            // (CEL type checking at compile time)
        }

        Ok(())
    }
}
```

---

## Solver Architecture

### Overview (Simplified)

The solver has two jobs:
1. **Filter clusters** by CEL placement constraints
2. **Group services** by latency constraints (services that need low latency go together)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Lattice Solver                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────┐                      ┌─────────────────────────┐  │
│  │ LatticeService  │                      │   Available Clusters    │  │
│  │     CRDs        │                      │   (with ClusterContext) │  │
│  └────────┬────────┘                      └────────────┬────────────┘  │
│           │                                            │               │
│           ▼                                            ▼               │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                    Step 1: Placement Filter                      │  │
│  │                                                                  │  │
│  │   For each service:                                              │  │
│  │     valid_clusters = clusters.filter(|c|                         │  │
│  │       service.requirements.placement.all(|p| CEL(p.expr, c))     │  │
│  │     )                                                            │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                    │                                   │
│                                    ▼                                   │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                    Step 2: Latency Grouping                      │  │
│  │                                                                  │  │
│  │   Build graph: services as nodes, latency requirements as edges  │
│  │   Group services that need < 5ms (same zone)                     │
│  │   Group services that need < 20ms (same region)                  │  │
│  │                                                                  │  │
│  │   Use Istio LatencyMatrix to validate/predict                    │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                    │                                   │
│                                    ▼                                   │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                    Step 3: Assignment                            │  │
│  │                                                                  │  │
│  │   For each service group:                                        │  │
│  │     Find cluster in intersection of all members' valid_clusters  │  │
│  │     If none: UNSATISFIABLE (explain why)                         │  │
│  │     If multiple: pick by preference (cost, existing traffic)     │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                    │                                   │
│                                    ▼                                   │
│                    ┌───────────────────────────────┐                  │
│                    │   Placement Decision          │                  │
│                    │   service → cluster mapping   │                  │
│                    └───────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────────────────┘
```

### Step 1: CEL Filter (Hard Constraints)

```rust
pub struct Solver {
    cel_evaluator: CelEvaluator,
}

impl Solver {
    /// Find clusters where this service CAN run (satisfies all CEL constraints)
    pub fn valid_clusters(
        &self,
        service: &LatticeService,
        clusters: &[ClusterContext],
        service_placements: &HashMap<String, ServicePlacement>,
    ) -> Vec<&ClusterContext> {
        clusters
            .iter()
            .filter(|cluster| {
                // Build eval context with cluster + other services' placements
                let ctx = EvalContext {
                    cluster: (*cluster).clone(),
                    services: service_placements.clone(),
                };

                // All CEL expressions must evaluate to true
                service.spec.requirements.placement
                    .iter()
                    .all(|req| self.cel_evaluator.eval(&req.expr, &ctx).unwrap_or(false))
            })
            .collect()
    }
}
```

### Step 2: Score (Soft Preferences)

```rust
impl Solver {
    /// Score a cluster based on proximity to dependencies
    pub fn score_cluster(
        &self,
        cluster: &ClusterContext,
        service: &LatticeService,
        service_placements: &HashMap<String, ServicePlacement>,
    ) -> i32 {
        let mut score = 0;

        // Get dependencies from resources
        for dep_name in service.spec.dependencies() {
            if let Some(dep_placement) = service_placements.get(dep_name) {
                // Same zone: best score
                if cluster.zone == dep_placement.zone {
                    score += 100;
                }
                // Same region: good score
                else if cluster.region == dep_placement.region {
                    score += 50;
                }
                // Same provider: small bonus
                else if cluster.provider == self.get_provider(&dep_placement.cluster) {
                    score += 10;
                }
            }
        }

        // Also consider inbound callers
        for caller_name in service.spec.allowed_callers() {
            if let Some(caller_placement) = service_placements.get(caller_name) {
                if cluster.zone == caller_placement.zone {
                    score += 100;
                } else if cluster.region == caller_placement.region {
                    score += 50;
                }
            }
        }

        score
    }
}
```

### Step 3: Select Best Cluster

```rust
impl Solver {
    /// Solve placement for a service
    pub fn solve(
        &self,
        service: &LatticeService,
        clusters: &[ClusterContext],
        service_placements: &HashMap<String, ServicePlacement>,
    ) -> Result<SolverResult, SolverError> {
        // 1. Filter by hard constraints (CEL)
        let valid = self.valid_clusters(service, clusters, service_placements);

        if valid.is_empty() {
            return Ok(SolverResult::Unschedulable {
                required: self.extract_required_properties(service),
            });
        }

        // 2. Score by soft preferences (proximity)
        let mut scored: Vec<_> = valid
            .into_iter()
            .map(|c| (c, self.score_cluster(c, service, service_placements)))
            .collect();

        // 3. Sort by score (descending)
        scored.sort_by(|a, b| b.1.cmp(&a.1));

        // 4. Pick best
        let chosen = scored[0].0;

        Ok(SolverResult::Scheduled {
            cluster: chosen.name.clone(),
            score: scored[0].1,
        })
    }
}

pub enum SolverResult {
    Scheduled { cluster: String, score: i32 },
    Unschedulable { required: RequiredClusterProperties },
}
```

### No Z3 Needed

The model is simple:
- **CEL handles boolean logic** for hard constraints
- **Scoring function** handles soft preferences
- **Sort + pick** selects best cluster

Z3 would only be useful later for:
- Multi-service optimization (NP-hard bin packing)
- Cost optimization with budget constraints

### Summary

| Type | How It Works |
|------|--------------|
| Hard constraints | CEL expressions → filter clusters |
| Soft preferences | Score by proximity to deps → sort clusters |
| Colocation | Inferred from `resources` → higher score for same zone |
| Forced colocation | CEL: `cluster.zone == services.postgres.zone` |

### Cluster Registry

Clusters declare their properties via labels/annotations. The solver reads these:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: prod-us-east-1
  labels:
    lattice.dev/region: us-east-1
    lattice.dev/zone: us-east-1a
    lattice.dev/provider: aws
    lattice.dev/country: US
  annotations:
    lattice.dev/compliance: '["SOC2", "HIPAA", "ISO27001"]'
spec:
  # ... cluster spec
status:
  phase: Ready
```

The solver builds `ClusterContext` from this:

```rust
impl ClusterContext {
    pub fn from_cluster(cluster: &LatticeCluster) -> Self {
        let labels = cluster.labels();
        let annotations = cluster.annotations();

        ClusterContext {
            id: cluster.name_any(),
            region: labels.get("lattice.dev/region").cloned().unwrap_or_default(),
            zone: labels.get("lattice.dev/zone").cloned().unwrap_or_default(),
            country: labels.get("lattice.dev/country").cloned().unwrap_or_default(),
            provider: labels.get("lattice.dev/provider").cloned().unwrap_or_default(),
            compliance: annotations
                .get("lattice.dev/compliance")
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default(),
            labels: labels.clone(),
        }
    }
}
```

---

## Hierarchical State Aggregation

Every cluster runs the same control plane and UI. State flows UP the tree.

### Architecture

```
                    ┌─────────────────────────────────┐
                    │           Root Cell             │
                    │  (global: 847 services,        │
                    │   12 clusters)                  │
                    └───────────────┬─────────────────┘
                                    │ stats pushed up
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
        ┌───────────────────────┐       ┌───────────────────────┐
        │      US Region        │       │      EU Region        │
        │  (423 services,       │       │  (424 services,       │
        │   6 clusters)         │       │   6 clusters)         │
        └───────────┬───────────┘       └───────────────────────┘
                    │
            ┌───────┴───────┐
            ▼               ▼
        ┌───────┐       ┌───────┐
        │us-east│       │us-west│
        │(112)  │       │(98)   │
        └───────┘       └───────┘
```

### What Flows Up (via existing gRPC stream)

```rust
/// Pushed from child to parent periodically
struct ClusterStats {
    /// This cluster's identity
    cluster: String,
    timestamp: DateTime<Utc>,

    /// Services in this subtree
    services: Vec<ServiceSummary>,

    /// Resource usage (CPU, memory, pods)
    resources: ResourceUsage,

    /// Health counts (ready/degraded/failed)
    health: HealthSummary,

    /// Observed latencies between services (from Istio)
    latency_edges: Vec<LatencyEdge>,

    /// Recursive: children's aggregated stats
    children_stats: Vec<ClusterStats>,
}

struct ServiceSummary {
    name: String,
    environment: String,
    phase: ServicePhase,
    cluster: String,           // where it's actually running
    replicas_ready: u32,
    replicas_desired: u32,
}
```

### Same UI, Different Scope

| Level | What You See |
|-------|--------------|
| Root | All 847 services, all 12 clusters, global health |
| US Region | 423 services in US, 6 clusters, US health |
| us-east-1 | 112 services in this cluster only |

The React app is identical - it just queries the local API, which returns that node's subtree.

### UX: Always Show Context

Users must always know WHERE they are:

```
┌──────────────────────────────────────────────────────────────────────┐
│  ☰ Lattice    Root › US Region › us-east-1        [Search] [Profile]│
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  📍 Viewing: us-east-1                                              │
│     12 services │ 3 child clusters │ 847 globally                   │
│                                                                      │
│     [↑ US Region (423 svcs)]  [↑ Root (847 svcs)]                   │
│                                                                      │
├──────────────────────────────────────────────────────────────────────┤
│                     (service graph canvas)                           │
```

### Benefits

1. **Natural RBAC** - Teams only see their subtree
2. **Resilience** - Regional UI works even if root is down
3. **Performance** - Queries scoped to subtree, not global
4. **Consistency** - Same UI everywhere, learn once

### API Design

Every cluster exposes the same REST API:

```
GET  /api/v1/services              # Services in this subtree
GET  /api/v1/services/:name        # Single service detail
GET  /api/v1/clusters              # Clusters in this subtree
GET  /api/v1/stats                 # Aggregated stats for subtree
GET  /api/v1/stats/global          # Only at root: full tree
WS   /api/v1/events                # Real-time updates for subtree
```

---

## UI Design: Pure Service Canvas

### Main View

```
┌──────────────────────────────────────────────────────────────────────┐
│  Lattice                                    Environment: [prod ▼]    │
├──────────────────────────────────────────────────────────────────────┤
│  [+ Add Service]  [Import YAML]  [Export]           [Solve ▶]       │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│                        ┌──────────────┐                              │
│                        │   frontend   │                              │
│                        │   React SPA  │                              │
│                        └──────┬───────┘                              │
│                               │                                      │
│                          < 10ms                                      │
│                               ▼                                      │
│    ┌───────────┐       ┌──────────────┐       ╔════════════════╗    │
│    │   redis   │◀──────│     api      │──────▶║     stripe     ║    │
│    │  < 2ms    │       │   99.95% HA  │       ║   (external)   ║    │
│    └───────────┘       │    SOC2      │       ╚════════════════╝    │
│                        └──────┬───────┘                              │
│                               │                                      │
│                           < 5ms                                      │
│                               ▼                                      │
│                        ┌──────────────┐                              │
│                        │   postgres   │                              │
│                        │ SOC2 + HIPAA │                              │
│                        └──────────────┘                              │
│                                                                      │
├──────────────────────────────────────────────────────────────────────┤
│  ✓ Solution found                                                    │
│  Clusters: 2 (us-east-1, us-west-2) │ Est. cost: $847/mo [Details ▶]│
└──────────────────────────────────────────────────────────────────────┘
```

### Visual Elements

| Element | Appearance | Meaning |
|---------|------------|---------|
| `┌─────┐` | Rounded rectangle | Internal LatticeService |
| `╔═════╗` | Double-line rectangle | External service |
| `│ ─── │` | Cylinder | Database (postgres, redis) |
| `< 10ms` | Label on edge | Latency constraint |
| `99.95%` | Badge on node | Availability requirement |
| `SOC2` | Badge on node | Compliance requirement |
| `───▶` | Solid arrow | Outbound dependency |
| `◀───` | Solid arrow | Inbound (allowed caller) |
| `- - ▶` | Dashed arrow | Optional/soft constraint |

### Interaction Patterns

#### Adding a Service
1. Click `[+ Add Service]`
2. Modal: Enter service name, select type (web, api, worker, database)
3. Service appears on canvas
4. Drag to position

#### Creating a Dependency
1. Drag from service edge
2. Drop on target service
3. Bilateral agreement auto-created:
   - Source gets `direction: outbound`
   - Target gets `direction: inbound` (if LatticeService)

#### Setting Requirements
1. Click on edge → Latency popover
   ```
   ┌─────────────────────────────┐
   │ Latency Requirement         │
   ├─────────────────────────────┤
   │ Max: [10] ms                │
   │ Percentile: [p99 ▼]         │
   │                             │
   │ [Remove]           [Apply]  │
   └─────────────────────────────┘
   ```

2. Click on service → Properties panel
   ```
   ┌─────────────────────────────────────────┐
   │ api                              [YAML] │
   ├─────────────────────────────────────────┤
   │ Container                               │
   │   Image: [myapp/api:v1.2        ]      │
   │   CPU:   [500m ▼]  Memory: [512Mi ▼]   │
   │                                         │
   │ Requirements                            │
   │   Availability: [99.95% ▼]             │
   │   Compliance:   [SOC2] [+]             │
   │   Residency:    [us, eu        ]       │
   │   Cost:         [● Balanced    ]       │
   │                                         │
   │ Throughput (optional)                   │
   │   RPS: [10000    ]                     │
   └─────────────────────────────────────────┘
   ```

#### Viewing Solution Details
Click `[Details ▶]` in bottom bar:

```
┌─────────────────────────────────────────────────────────────────────┐
│ Computed Infrastructure                                      [Hide] │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  us-east-1a                          us-west-2a                    │
│  ┌────────────────────────┐          ┌────────────────────────┐    │
│  │ cluster-us-east-1a     │          │ cluster-us-west-2a     │    │
│  │ ├─ frontend (3x)       │          │ ├─ api-replica (2x)    │    │
│  │ ├─ api (3x)            │◀────────▶│ └─ postgres-replica    │    │
│  │ ├─ redis (2x)          │   sync   │                        │    │
│  │ └─ postgres-primary    │          │                        │    │
│  │                        │          │                        │    │
│  │ Est: $623/mo           │          │ Est: $224/mo           │    │
│  └────────────────────────┘          └────────────────────────┘    │
│                                                                     │
│  Why this topology?                                                 │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ • frontend → api < 10ms: colocated in us-east-1a            │   │
│  │ • api → postgres < 5ms: colocated in us-east-1a             │   │
│  │ • api availability 99.95%: 3 replicas + cross-region backup │   │
│  │ • postgres HIPAA: us-east-1, us-west-2 (approved regions)   │   │
│  │ • redis < 2ms: colocated with api                           │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  [Export LatticeCluster YAMLs]                        [Apply ▶]    │
└─────────────────────────────────────────────────────────────────────┘
```

### Conflict Resolution

When constraints conflict, show clear explanation:

```
┌─────────────────────────────────────────────────────────────────────┐
│ ⚠ Unsatisfiable Constraints                                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ The following requirements cannot all be satisfied:                 │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ 1. api → postgres latency < 2ms (requires same zone)        │   │
│  │ 2. postgres requires FedRAMP compliance                     │   │
│  │ 3. No FedRAMP regions have zones with < 2ms latency         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│ Suggested resolutions:                                              │
│                                                                     │
│  ○ Relax latency to < 5ms (enables us-gov-west-1)                  │
│  ○ Remove FedRAMP requirement                                       │
│  ○ Use a FedRAMP-compliant managed database service                │
│                                                                     │
│                                              [Adjust Requirements]  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Implementation Phases

### Milestone 1: Service → Cluster Solver

#### Phase 1.1: Requirements Types
- [ ] Add `Requirements` struct to `src/crd/service.rs`
- [ ] Add `LatencyRequirement` and `PlacementRequirement` types
- [ ] Add CEL expression validation at admission time
- [ ] Unit tests for requirement parsing

#### Phase 1.2: CEL Evaluator
- [ ] Add `cel-interpreter` dependency
- [ ] Implement `PlacementEvaluator` with `ClusterContext`
- [ ] Build `ClusterContext` from `LatticeCluster` labels/annotations
- [ ] Unit tests for all CEL expression patterns

#### Phase 1.3: Latency Data Pipeline
- [ ] Implement `LatencyMatrix` CRD
- [ ] Implement Prometheus query for Istio metrics
- [ ] Create controller to refresh `LatencyMatrix` periodically
- [ ] Integration tests with mock Prometheus

#### Phase 1.4: Service Solver Core
- [ ] Implement `PlacementFilter` (CEL evaluation)
- [ ] Implement `LatencyGrouper` (connected components)
- [ ] Implement `Assigner` (greedy assignment)
- [ ] Implement `explain_failure` with `requiredClusterProperties`
- [ ] Unit tests for solver logic

#### Phase 1.5: Service Solver Controller
- [ ] Create controller watching `LatticeService` changes
- [ ] Trigger re-solve on service add/update/delete
- [ ] Update service status with placement or `Unschedulable`
- [ ] Integration tests with real clusters

### Milestone 2: Cluster → Infrastructure Solver

#### Phase 2.1: Infrastructure Registry
- [ ] Define `InfrastructureRegion` CRD
- [ ] Populate with AWS/GCP/Azure region data
- [ ] Include compliance, capabilities, pricing

#### Phase 2.2: Cluster Requirements
- [ ] Add `requirements` field to `LatticeClusterSpec`
- [ ] Same `PlacementRequirement` type (CEL)
- [ ] Add `InfraContext` for CEL evaluation

#### Phase 2.3: Cluster Solver Core
- [ ] Implement `InfraPlacementFilter` (same pattern as service)
- [ ] Implement `explain_failure` with `requiredInfraProperties`
- [ ] Unit tests

#### Phase 2.4: Auto-Cluster Generation
- [ ] When service solver fails, derive required cluster properties
- [ ] Generate `LatticeCluster` spec from derived requirements
- [ ] Trigger cluster solver automatically
- [ ] CAPI provisions infrastructure

### Milestone 3: Hierarchical API

#### Phase 3.1: Stats Aggregation
- [ ] Define `ClusterStats` protobuf message
- [ ] Push stats up via existing agent gRPC stream
- [ ] Aggregate children stats at each level
- [ ] Store in memory (ETS-like structure)

#### Phase 3.2: REST API
- [ ] `GET /api/v1/services` - services in subtree
- [ ] `GET /api/v1/clusters` - clusters in subtree
- [ ] `GET /api/v1/stats` - aggregated stats
- [ ] `WS /api/v1/events` - real-time updates

### Milestone 4: UI

#### Phase 4.1: UI Foundation
- [ ] React + React Flow setup
- [ ] Service graph visualization (read-only from API)
- [ ] Breadcrumb navigation (Root › Region › Cluster)
- [ ] Scope indicator ("Viewing: us-east-1, 112 services")

#### Phase 4.2: UI Interactivity
- [ ] Add/edit services via canvas
- [ ] Draw dependency edges (creates bilateral agreement)
- [ ] Set requirements via property panel
- [ ] Show solver results (assigned cluster, score)

#### Phase 4.3: Hierarchical Navigation
- [ ] Zoom out to parent (↑ US Region)
- [ ] Drill down to child cluster
- [ ] Global search from any level
- [ ] Cross-cutting queries ("all postgres services")

---

---

## Implementation Sketch: CRD Changes

### New File: `src/crd/requirements.rs`

```rust
//! Service requirements for solver-based placement
//!
//! Requirements are CEL expressions evaluated against cluster properties.
//! All expressions must evaluate to true for a cluster to be valid.
//! Colocation with dependencies is handled as a soft preference (scoring).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Requirements for service placement
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Requirements {
    /// Hard placement constraints as CEL expressions
    ///
    /// Each expression is evaluated against `cluster.*` and `services.*` context.
    /// All expressions must evaluate to true for a cluster to be valid.
    /// If no cluster satisfies all constraints, service becomes Unschedulable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub placement: Vec<PlacementRequirement>,
}

impl Requirements {
    /// Returns true if there are no requirements defined
    pub fn is_empty(&self) -> bool {
        self.placement.is_empty()
    }

    /// Validate all requirements (CEL syntax)
    pub fn validate(&self) -> Result<(), crate::Error> {
        for (i, req) in self.placement.iter().enumerate() {
            req.validate()
                .map_err(|e| crate::Error::validation(format!("placement[{}]: {}", i, e)))?;
        }
        Ok(())
    }
}

/// CEL-based placement requirement (hard constraint)
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PlacementRequirement {
    /// CEL expression that must evaluate to true
    ///
    /// Available variables:
    /// - `cluster.name` - Cluster name
    /// - `cluster.region` - Region identifier (e.g., "us-east-1")
    /// - `cluster.zone` - Zone identifier (e.g., "us-east-1a")
    /// - `cluster.country` - ISO country code (e.g., "US", "DE")
    /// - `cluster.provider` - Cloud provider ("aws", "gcp", "azure")
    /// - `cluster.compliance` - List of certs (e.g., ["SOC2", "HIPAA"])
    /// - `cluster.labels` - Arbitrary labels from LatticeCluster
    /// - `services.<name>.region` - Region where service is placed
    /// - `services.<name>.zone` - Zone where service is placed
    /// - `services.<name>.cluster` - Cluster name where service is placed
    ///
    /// Examples:
    /// - `"SOC2" in cluster.compliance`
    /// - `cluster.region.startsWith("us-")`
    /// - `cluster.zone == services.postgres.zone`
    /// - `"HIPAA" in cluster.compliance && cluster.country == "US"`
    pub expr: String,

    /// Human-readable description (shown in UI and error messages)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl PlacementRequirement {
    /// Validate CEL expression syntax
    pub fn validate(&self) -> Result<(), String> {
        if self.expr.trim().is_empty() {
            return Err("expression cannot be empty".to_string());
        }

        // TODO: Compile CEL expression to validate syntax
        // cel_interpreter::Program::compile(&self.expr)
        //     .map_err(|e| format!("invalid CEL: {}", e))?;

        Ok(())
    }
}

/// Context available to CEL placement expressions
#[derive(Clone, Debug, Default, Serialize)]
pub struct ClusterContext {
    /// Cluster name
    pub name: String,

    /// Region identifier (from label `lattice.dev/region`)
    pub region: String,

    /// Zone identifier (from label `lattice.dev/zone`)
    pub zone: String,

    /// ISO country code (from label `lattice.dev/country`)
    pub country: String,

    /// Cloud provider (from label `lattice.dev/provider`)
    pub provider: String,

    /// Compliance certifications (from annotation `lattice.dev/compliance`)
    pub compliance: Vec<String>,

    /// All labels from the cluster
    pub labels: HashMap<String, String>,
}

impl ClusterContext {
    pub const LABEL_REGION: &'static str = "lattice.dev/region";
    pub const LABEL_ZONE: &'static str = "lattice.dev/zone";
    pub const LABEL_COUNTRY: &'static str = "lattice.dev/country";
    pub const LABEL_PROVIDER: &'static str = "lattice.dev/provider";
    pub const ANNOTATION_COMPLIANCE: &'static str = "lattice.dev/compliance";
}

/// Service placement info available in CEL as `services.<name>`
#[derive(Clone, Debug, Default, Serialize)]
pub struct ServicePlacement {
    /// Region where service is placed
    pub region: String,

    /// Zone where service is placed
    pub zone: String,

    /// Cluster name where service is placed
    pub cluster: String,
}

/// Full CEL evaluation context
#[derive(Clone, Debug, Default, Serialize)]
pub struct EvalContext {
    /// The cluster being evaluated
    pub cluster: ClusterContext,

    /// Other services' current placements
    pub services: HashMap<String, ServicePlacement>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_requirements_default_is_empty() {
        let req = Requirements::default();
        assert!(req.is_empty());
    }

    #[test]
    fn test_placement_requirement_validation() {
        let req = PlacementRequirement {
            expr: r#""SOC2" in cluster.compliance"#.to_string(),
            reason: Some("Requires SOC2 compliance".to_string()),
        };
        assert!(req.validate().is_ok());

        let empty = PlacementRequirement {
            expr: "".to_string(),
            reason: None,
        };
        assert!(empty.validate().is_err());
    }

    #[test]
    fn test_requirements_yaml_parsing() {
        let yaml = r#"
placement:
  - expr: '"SOC2" in cluster.compliance'
    reason: Must be SOC2 compliant
  - expr: 'cluster.country == "US"'
  - expr: 'cluster.zone == services.postgres.zone'
    reason: Must be colocated with postgres
"#;
        let req: Requirements = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(req.placement.len(), 3);
        assert_eq!(req.placement[0].reason, Some("Must be SOC2 compliant".to_string()));
    }

    #[test]
    fn test_service_reference_in_cel() {
        let yaml = r#"
placement:
  - expr: 'cluster.region == services.postgres.region'
  - expr: 'cluster.zone == services.redis.zone'
"#;
        let req: Requirements = serde_yaml::from_str(yaml).unwrap();
        assert!(req.placement[0].expr.contains("services.postgres"));
        assert!(req.placement[1].expr.contains("services.redis"));
    }
}
```

### Changes to `src/crd/service.rs`

Add the `requirements` field to `LatticeServiceSpec`:

```rust
// At top of file, add import:
use super::requirements::Requirements;

// In LatticeServiceSpec struct, add field:
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(/* ... */)]
#[serde(rename_all = "camelCase")]
pub struct LatticeServiceSpec {
    // ... existing fields ...

    /// Deployment strategy configuration
    #[serde(default)]
    pub deploy: DeploySpec,

    /// Requirements for service placement (NEW)
    ///
    /// Defines latency constraints to other services and
    /// placement constraints as CEL expressions.
    #[serde(default, skip_serializing_if = "Requirements::is_empty")]
    pub requirements: Requirements,
}

// Update validate() method:
impl LatticeServiceSpec {
    pub fn validate(&self) -> Result<(), crate::Error> {
        // ... existing validation ...

        // Validate requirements
        self.requirements.validate()?;

        Ok(())
    }
}
```

### Changes to `LatticeServiceStatus`

Add scheduling status:

```rust
// New phase variant
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServicePhase {
    #[default]
    Pending,
    /// Service requirements cannot be satisfied by any cluster (NEW)
    Unschedulable,
    Compiling,
    Ready,
    Failed,
}

// New status fields
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatticeServiceStatus {
    // ... existing fields ...

    /// Cluster this service is scheduled to (NEW)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduled_cluster: Option<String>,

    /// Required cluster properties when Unschedulable (NEW)
    ///
    /// Populated when phase is Unschedulable to help platform team
    /// create a cluster that satisfies requirements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_cluster_properties: Option<RequiredClusterProperties>,

    /// Services this must be colocated with due to latency (NEW)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub colocate_with: Vec<String>,
}

/// Properties required for a cluster to satisfy this service (NEW)
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RequiredClusterProperties {
    /// Compliance frameworks needed
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compliance: Vec<String>,

    /// Required country codes
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub countries: Vec<String>,

    /// Required providers
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<String>,

    /// Required region prefixes
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub region_prefixes: Vec<String>,

    /// Raw CEL expressions that couldn't be simplified
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub placement_expressions: Vec<String>,

    /// Human-readable explanation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
```

### Example YAML: Full Service with Requirements

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: api
spec:
  environment: prod

  containers:
    main:
      image: myapp/api:v1.2
      variables:
        DB_HOST: "${resources.postgres.host}"
        REDIS_URL: "${resources.redis.url}"
      resources:
        requests:
          cpu: 500m
          memory: 512Mi

  resources:
    # Dependencies - solver will PREFER colocating with these
    postgres:
      type: postgres
      direction: outbound

    redis:
      type: redis
      direction: outbound

    frontend:
      type: service
      direction: inbound

    stripe:
      type: external-service
      direction: outbound
      params:
        url: https://api.stripe.com

  service:
    ports:
      http:
        port: 8080

  replicas:
    min: 2
    max: 10

  # Hard constraints only (CEL)
  requirements:
    placement:
      - expr: '"SOC2" in cluster.compliance'
        reason: PCI-DSS requires SOC2 certified infrastructure

      - expr: 'cluster.country in ["US", "CA"]'
        reason: Data must stay in North America

      # Optional: Force colocation with postgres (usually not needed)
      # - expr: 'cluster.zone == services.postgres.zone'
      #   reason: Must be in same zone as database
```

### Example Status: Scheduled

```yaml
status:
  phase: Ready
  scheduledCluster: prod-us-east-1
  colocateWith:
    - postgres
    - redis
  message: "Scheduled to prod-us-east-1 (satisfies all requirements)"
```

### Example Status: Unschedulable

```yaml
status:
  phase: Unschedulable
  message: "No cluster satisfies placement requirements"
  requiredClusterProperties:
    compliance:
      - SOC2
    countries:
      - US
      - CA
    placementExpressions:
      - '"SOC2" in cluster.compliance'
      - 'cluster.country in ["US", "CA"]'
    message: |
      Service requires:
      - SOC2 compliance certification
      - Located in US or Canada
      - Must be colocated with: postgres, redis (< 5ms latency)

      To resolve, create a LatticeCluster with:
        labels:
          lattice.dev/country: US
        annotations:
          lattice.dev/compliance: '["SOC2"]'
  colocateWith:
    - postgres
    - redis
```

### Module Structure

```
src/
├── crd/
│   ├── mod.rs              # Add: pub mod requirements;
│   ├── requirements.rs     # NEW: Requirements, LatencyRequirement, PlacementRequirement
│   ├── service.rs          # MODIFY: Add requirements field to LatticeServiceSpec
│   ├── cluster.rs          # (existing)
│   └── types.rs            # (existing)
│
├── solver/                 # NEW MODULE
│   ├── mod.rs
│   ├── cel.rs              # CEL evaluation with ClusterContext
│   ├── latency.rs          # Latency grouping logic
│   ├── assigner.rs         # Cluster assignment
│   └── error.rs            # SolverError types
│
├── metrics/                # NEW MODULE
│   ├── mod.rs
│   ├── latency_matrix.rs   # LatencyMatrix CRD and controller
│   └── prometheus.rs       # Prometheus client for Istio metrics
│
└── controllers/
    ├── service.rs          # MODIFY: Call solver before compiling
    └── solver.rs           # NEW: Solver controller
```

### Controller Flow

```rust
// In service controller reconcile:
async fn reconcile(service: Arc<LatticeService>, ctx: Arc<Context>) -> Result<Action> {
    // 1. If requirements exist, run solver
    if !service.spec.requirements.is_empty() {
        let solver_result = ctx.solver.solve(&service).await?;

        match solver_result {
            SolverResult::Scheduled { cluster } => {
                // Update status with scheduled cluster
                update_status(&service, |s| {
                    s.phase = ServicePhase::Compiling;
                    s.scheduled_cluster = Some(cluster.clone());
                    s.colocate_with = solver_result.colocate_with;
                }).await?;
            }
            SolverResult::Unschedulable { required } => {
                // Update status with required properties
                update_status(&service, |s| {
                    s.phase = ServicePhase::Unschedulable;
                    s.required_cluster_properties = Some(required);
                    s.message = Some("No cluster satisfies requirements".into());
                }).await?;
                return Ok(Action::requeue(Duration::from_secs(60)));
            }
        }
    }

    // 2. Compile workloads (existing logic)
    // ...
}
```

---

## Repository Structure (Monorepo)

```
lattice/
├── Cargo.toml                    # Workspace root
├── CLAUDE.md
│
├── crates/
│   ├── lattice-operator/         # K8s controllers, CRD reconciliation
│   │   └── src/
│   │       ├── controllers/      # Service, Cluster controllers
│   │       ├── crd/              # CRD definitions (LatticeService, etc.)
│   │       └── main.rs
│   │
│   ├── lattice-solver/           # CEL evaluation, cluster scoring
│   │   └── src/
│   │       ├── cel.rs            # CEL evaluator (wraps cel-interpreter)
│   │       ├── scorer.rs         # Proximity scoring
│   │       └── lib.rs
│   │
│   ├── lattice-api/              # REST/WebSocket API server
│   │   └── src/
│   │       ├── routes/           # /api/v1/services, /api/v1/stats
│   │       ├── ws.rs             # WebSocket event streaming
│   │       └── main.rs
│   │
│   ├── lattice-agent/            # Runs on child clusters, streams to parent
│   │   └── src/
│   │       ├── stats.rs          # Collect and push ClusterStats
│   │       ├── grpc.rs           # gRPC client to parent
│   │       └── main.rs
│   │
│   ├── lattice-proto/            # Protobuf/gRPC definitions
│   │   ├── proto/
│   │   │   ├── agent.proto       # Agent ↔ Cell protocol
│   │   │   └── stats.proto       # ClusterStats message
│   │   ├── build.rs
│   │   └── src/lib.rs
│   │
│   └── lattice-common/           # Shared types, errors, utilities
│       └── src/
│           ├── types.rs
│           ├── error.rs
│           └── lib.rs
│
├── ui/
│   ├── package.json
│   ├── vite.config.ts
│   ├── tsconfig.json
│   └── src/
│       ├── main.tsx
│       ├── App.tsx
│       │
│       ├── components/
│       │   ├── ServiceGraph/     # React Flow canvas
│       │   │   ├── ServiceNode.tsx
│       │   │   ├── DependencyEdge.tsx
│       │   │   └── index.tsx
│       │   ├── RequirementsPanel/
│       │   ├── Breadcrumb/       # Root › US Region › us-east-1
│       │   └── ScopeIndicator/   # "Viewing: us-east-1 (112 services)"
│       │
│       ├── api/
│       │   ├── client.ts         # Fetch wrapper
│       │   ├── services.ts       # GET /api/v1/services
│       │   ├── stats.ts          # GET /api/v1/stats
│       │   └── types.ts          # TypeScript types (generated?)
│       │
│       ├── stores/
│       │   ├── services.ts       # Zustand store for services
│       │   └── navigation.ts     # Current scope (which cluster)
│       │
│       └── hooks/
│           ├── useServices.ts    # TanStack Query hook
│           └── useRealtimeStats.ts  # WebSocket subscription
│
├── proto/                        # Source of truth for protobufs
│   ├── agent.proto
│   └── stats.proto
│
├── deploy/
│   ├── helm/
│   │   └── lattice/
│   │       ├── Chart.yaml
│   │       ├── values.yaml
│   │       └── templates/
│   └── docker/
│       ├── Dockerfile.operator
│       ├── Dockerfile.api
│       └── Dockerfile.agent
│
├── docs/
│   └── design/
│       ├── SOLVER_UI_DESIGN.md   # ← This file
│       └── SCORE_TEMPLATING_PLAN.md
│
└── .github/
    └── workflows/
        ├── rust.yml              # cargo test, clippy, fmt
        ├── ui.yml                # npm test, build
        └── release.yml           # Build + push Docker images
```

### Cargo Workspace

```toml
# Cargo.toml (root)
[workspace]
resolver = "2"
members = [
    "crates/lattice-operator",
    "crates/lattice-solver",
    "crates/lattice-api",
    "crates/lattice-agent",
    "crates/lattice-proto",
    "crates/lattice-common",
]

[workspace.dependencies]
# Shared dependencies with consistent versions
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
kube = { version = "0.98", features = ["runtime", "derive"] }
tonic = "0.12"
prost = "0.13"
cel-interpreter = "0.8"
axum = "0.8"
tracing = "0.1"
```

### Type Generation (Rust → TypeScript)

Generate TypeScript types from Rust structs:

```bash
# Option 1: ts-rs (derive macro)
cargo install ts-rs-cli
# In Rust: #[derive(TS)] on structs
# Generates: ui/src/api/types.ts

# Option 2: From OpenAPI spec
# lattice-api generates openapi.json
# openapi-typescript generates types
npx openapi-typescript ./target/openapi.json -o ./ui/src/api/types.ts
```

---

## Dependencies

### Rust
```toml
# In each crate's Cargo.toml, reference workspace deps:
[dependencies]
tokio.workspace = true
serde.workspace = true
kube.workspace = true

# Crate-specific
cel-interpreter = "0.8"          # lattice-solver
axum = "0.8"                     # lattice-api
tonic = "0.12"                   # lattice-agent, lattice-proto
```

### UI (ui/package.json)
```json
{
  "dependencies": {
    "react": "^18",
    "react-dom": "^18",
    "@xyflow/react": "^12",
    "@tanstack/react-query": "^5",
    "zustand": "^5"
  },
  "devDependencies": {
    "vite": "^6",
    "typescript": "^5",
    "@types/react": "^18"
  }
}
```

---

---

## Sub-Design: Latency Data from Istio

### Overview

Istio already provides service-to-service latency metrics via Prometheus. No additional tooling (Goldpinger, etc.) needed.

### Istio Metrics Available

```promql
# Request duration histogram (p99 latency)
histogram_quantile(0.99,
  sum(rate(istio_request_duration_milliseconds_bucket{
    reporter="source",
    destination_service=~".*"
  }[5m])) by (le, source_workload, destination_service)
)

# Key labels available:
# - source_workload: "api"
# - source_workload_namespace: "prod"
# - destination_service: "postgres.prod.svc.cluster.local"
# - destination_workload: "postgres"
# - response_code: "200"
# - request_protocol: "http" | "grpc"
```

### Latency Data Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Latency Data Pipeline                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────────┐ │
│  │   Istio     │───▶│ Prometheus  │───▶│   Lattice Metrics       │ │
│  │   Envoy     │    │             │    │   Aggregator            │ │
│  │  sidecars   │    │  (scrapes)  │    │                         │ │
│  └─────────────┘    └─────────────┘    └───────────┬─────────────┘ │
│                                                     │               │
│                                                     ▼               │
│                                        ┌─────────────────────────┐ │
│                                        │   LatencyMatrix CRD     │ │
│                                        │   (cluster-scoped)      │ │
│                                        └───────────┬─────────────┘ │
│                                                     │               │
│                                                     ▼               │
│                                        ┌─────────────────────────┐ │
│                                        │      Z3 Solver          │ │
│                                        │  (uses for validation   │ │
│                                        │   and prediction)       │ │
│                                        └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

### LatencyMatrix CRD

Materialized view of Istio metrics for solver consumption:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatencyMatrix
metadata:
  name: prod-latencies
spec:
  environment: prod
  # How often to refresh from Prometheus
  refreshInterval: 5m
status:
  lastRefresh: "2024-01-15T10:30:00Z"

  # Service-to-service observed latencies
  edges:
    - source: frontend
      destination: api
      p50: 2.3ms
      p99: 8.7ms
      sampleCount: 1432567

    - source: api
      destination: postgres
      p50: 1.1ms
      p99: 4.2ms
      sampleCount: 892341

    - source: api
      destination: redis
      p50: 0.3ms
      p99: 1.1ms
      sampleCount: 2341567

  # Zone-to-zone latencies (aggregated from service data)
  zoneLatencies:
    - from: us-east-1a
      to: us-east-1a
      p99: 0.5ms      # Same zone

    - from: us-east-1a
      to: us-east-1b
      p99: 1.2ms      # Same region, different zone

    - from: us-east-1a
      to: us-west-2a
      p99: 67ms       # Cross-region

  # Services without traffic data yet (new deployments)
  unknownServices:
    - new-worker
```

### Metrics Aggregator Controller

```rust
pub struct LatencyAggregator {
    prometheus_client: PrometheusClient,
    refresh_interval: Duration,
}

impl LatencyAggregator {
    /// Query Istio metrics and update LatencyMatrix
    pub async fn refresh(&self, env: &str) -> Result<LatencyMatrixStatus, Error> {
        // Query p99 latencies for all service pairs
        let query = format!(r#"
            histogram_quantile(0.99,
              sum(rate(istio_request_duration_milliseconds_bucket{{
                reporter="source",
                source_workload_namespace="{env}"
              }}[5m])) by (le, source_workload, destination_workload)
            )
        "#);

        let results = self.prometheus_client.query(&query).await?;

        let edges: Vec<LatencyEdge> = results
            .into_iter()
            .map(|r| LatencyEdge {
                source: r.labels["source_workload"].clone(),
                destination: r.labels["destination_workload"].clone(),
                p99: Duration::from_secs_f64(r.value / 1000.0),
                // ... p50, sample_count from separate queries
            })
            .collect();

        // Aggregate to zone-level latencies
        let zone_latencies = self.aggregate_zone_latencies(&edges).await?;

        Ok(LatencyMatrixStatus {
            last_refresh: Utc::now(),
            edges,
            zone_latencies,
            unknown_services: self.find_services_without_traffic(env).await?,
        })
    }

    /// Infer zone-to-zone latency from service pairs in those zones
    async fn aggregate_zone_latencies(
        &self,
        edges: &[LatencyEdge],
    ) -> Result<Vec<ZoneLatency>, Error> {
        // Get service -> zone mapping from pod topology labels
        let service_zones = self.get_service_zones().await?;

        // Group edges by zone pair and take median
        let mut zone_pairs: HashMap<(String, String), Vec<Duration>> = HashMap::new();

        for edge in edges {
            if let (Some(src_zone), Some(dst_zone)) = (
                service_zones.get(&edge.source),
                service_zones.get(&edge.destination),
            ) {
                zone_pairs
                    .entry((src_zone.clone(), dst_zone.clone()))
                    .or_default()
                    .push(edge.p99);
            }
        }

        Ok(zone_pairs
            .into_iter()
            .map(|((from, to), latencies)| ZoneLatency {
                from,
                to,
                p99: median(&latencies),
            })
            .collect())
    }
}
```

### Solver Integration

The solver uses latency data in two modes:

#### 1. Validation Mode (Existing Services)

Check if current placement satisfies requirements:

```rust
impl Solver {
    pub fn validate_latency_requirements(
        &self,
        services: &[LatticeService],
        matrix: &LatencyMatrix,
    ) -> Vec<LatencyViolation> {
        let mut violations = vec![];

        for service in services {
            for constraint in &service.spec.requirements.latency {
                let observed = matrix.get_latency(
                    constraint.from.as_deref().unwrap_or(&service.name_any()),
                    constraint.to.as_deref().unwrap_or(&service.name_any()),
                );

                if let Some(observed) = observed {
                    if observed.p99 > constraint.max {
                        violations.push(LatencyViolation {
                            service: service.name_any(),
                            constraint: constraint.clone(),
                            observed: observed.p99,
                        });
                    }
                }
            }
        }

        violations
    }
}
```

#### 2. Prediction Mode (New Services / Re-placement)

Use zone-level latencies to predict where to place new services:

```rust
impl Solver {
    pub fn predict_latency(
        &self,
        service_a_zone: &str,
        service_b_zone: &str,
        matrix: &LatencyMatrix,
    ) -> Duration {
        // First, try exact zone pair from observed data
        if let Some(latency) = matrix.get_zone_latency(service_a_zone, service_b_zone) {
            return latency.p99;
        }

        // Fall back to heuristics based on zone naming
        match (service_a_zone, service_b_zone) {
            (a, b) if a == b => Duration::from_micros(500),           // Same zone
            (a, b) if same_region(a, b) => Duration::from_millis(2),  // Same region
            _ => Duration::from_millis(70),                            // Cross-region default
        }
    }
}
```

### UI Integration

Show observed vs. required latency on edges:

```
                    ┌──────────────┐
                    │   frontend   │
                    └──────┬───────┘
                           │
              required: < 10ms
              observed: 8.7ms ✓
                           │
                           ▼
                    ┌──────────────┐
                    │     api      │
                    └──────┬───────┘
                           │
              required: < 5ms
              observed: 12.3ms ✗ ← VIOLATION
                           │
                           ▼
                    ┌──────────────┐
                    │   postgres   │
                    └──────────────┘
```

### Handling New Services (No Traffic Data)

For services without historical traffic:

1. **Use zone-level predictions**: If we know the target zone, use aggregated zone latency
2. **Use service-type heuristics**: Database services typically add 1-5ms, caches < 1ms
3. **Mark as "unverified"**: UI shows predicted latency with warning
4. **Re-validate after traffic**: Controller re-checks once real data available

```yaml
# LatencyMatrix shows unknown services
status:
  unknownServices:
    - name: new-api
      predictedLatencies:
        - to: postgres
          predicted: 3ms  # Based on zone placement
          confidence: low
          reason: "No observed traffic; using zone-level estimate"
```

### Prometheus Queries Reference

```promql
# P50 latency
histogram_quantile(0.50, sum(rate(
  istio_request_duration_milliseconds_bucket{reporter="source"}[5m]
)) by (le, source_workload, destination_workload))

# P99 latency
histogram_quantile(0.99, sum(rate(
  istio_request_duration_milliseconds_bucket{reporter="source"}[5m]
)) by (le, source_workload, destination_workload))

# Request rate (for sample count)
sum(rate(
  istio_requests_total{reporter="source"}[5m]
)) by (source_workload, destination_workload)

# Error rate (for health)
sum(rate(
  istio_requests_total{reporter="source", response_code!~"2.."}[5m]
)) by (source_workload, destination_workload)
/
sum(rate(
  istio_requests_total{reporter="source"}[5m]
)) by (source_workload, destination_workload)
```

---

---

## Two-Level Solver Architecture

The same constraint pattern applies at two levels:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│   Level 1: Service → Cluster                                           │
│   ════════════════════════════                                         │
│                                                                         │
│   ┌─────────────┐     requirements      ┌─────────────┐                │
│   │  Service    │ ───────────────────▶  │   Cluster   │                │
│   │             │   - latency (Istio)   │             │                │
│   │  (user)     │   - placement (CEL)   │  (platform) │                │
│   └─────────────┘                       └─────────────┘                │
│                                                                         │
│   If no cluster satisfies → FAIL with required properties              │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   Level 2: Cluster → Infrastructure  (Phase 2)                         │
│   ════════════════════════════════════════════                         │
│                                                                         │
│   ┌─────────────┐     requirements      ┌─────────────┐                │
│   │   Cluster   │ ───────────────────▶  │   Infra     │                │
│   │             │   - placement (CEL)   │  (provider) │                │
│   │  (platform) │   - sizing            │             │                │
│   └─────────────┘                       └─────────────┘                │
│                                                                         │
│   If no infra satisfies → FAIL with required properties                │
│   If satisfied → auto-provision via CAPI                               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Phase 1: Service Solver (User-Facing)

User writes `LatticeService` with requirements. Solver either:
- **SUCCESS**: Places service on existing cluster
- **FAIL**: Returns missing cluster properties

```yaml
# User's service
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: api
spec:
  requirements:
    latency:
      - to: postgres
        max: 5ms
    placement:
      - expr: '"HIPAA" in cluster.compliance && cluster.country == "US"'
```

```yaml
# Solver failure response (in status)
status:
  phase: Unschedulable
  message: "No cluster satisfies placement requirements"
  requiredClusterProperties:
    compliance: ["HIPAA"]
    country: "US"
    mustColocateWith: ["postgres"]  # due to 5ms latency requirement
```

Platform team sees this and either:
1. Labels an existing cluster with required properties
2. Creates a new `LatticeCluster` with those properties

### Phase 2: Cluster Solver (Platform-Facing)

Platform writes `LatticeCluster` with requirements. Solver either:
- **SUCCESS**: Provisions cluster on matching infrastructure
- **FAIL**: Returns missing infrastructure properties

```yaml
# Platform's cluster
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: prod-hipaa-us
spec:
  # NEW: Cluster-level requirements (same CEL pattern!)
  requirements:
    placement:
      # Must be in AWS us-east-1 or us-west-2 (HIPAA approved)
      - expr: |
          infra.provider == "aws" &&
          infra.region in ["us-east-1", "us-west-2"]

      # Must have local SSD for postgres performance
      - expr: 'infra.capabilities.contains("local-ssd")'

    sizing:
      minNodes: 3
      maxNodes: 50
      nodePool:
        instanceTypes: ["m5.xlarge", "m5.2xlarge"]
```

```yaml
# Solver failure response
status:
  phase: Unschedulable
  message: "No infrastructure satisfies placement requirements"
  requiredInfraProperties:
    provider: "aws"
    region: ["us-east-1", "us-west-2"]
    capabilities: ["local-ssd"]
```

### Infrastructure Registry

Just like clusters have properties for services, infrastructure has properties for clusters:

```yaml
# Infrastructure available (could be from cloud provider APIs or manual config)
apiVersion: lattice.dev/v1alpha1
kind: InfrastructureRegion
metadata:
  name: aws-us-east-1
spec:
  provider: aws
  region: us-east-1
  country: US
  zones: ["us-east-1a", "us-east-1b", "us-east-1c"]
  compliance: ["SOC2", "HIPAA", "FedRAMP", "ISO27001"]
  capabilities: ["local-ssd", "gpu", "spot-instances"]
  # Pricing, quotas, etc.
```

### The v10 Goal: Fully Automatic

When both solvers are in place:

```
User creates LatticeService
         │
         ▼
┌─────────────────────────────┐
│   Service Solver            │
│   "Need HIPAA cluster"      │
└──────────────┬──────────────┘
               │ no matching cluster
               ▼
┌─────────────────────────────┐
│   Auto-generate             │
│   LatticeCluster spec       │
│   with derived requirements │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│   Cluster Solver            │
│   "Need AWS us-east-1"      │
└──────────────┬──────────────┘
               │ matching infra found
               ▼
┌─────────────────────────────┐
│   CAPI provisions cluster   │
└──────────────┬──────────────┘
               │ cluster ready
               ▼
┌─────────────────────────────┐
│   Service placed on cluster │
│   User sees: "✓ Running"    │
└─────────────────────────────┘
```

User just wrote a service. Lattice created the cluster automatically.

---

## Open Questions

1. ~~**Latency data source**~~: **RESOLVED** - Use Istio metrics via Prometheus

2. ~~**Placement constraints**~~: **RESOLVED** - Use CEL for AND/OR/NOT logic

3. ~~**Solver complexity**~~: **RESOLVED** - Simple filter + group algorithm, no Z3 needed initially

4. ~~**New cluster creation**~~: **RESOLVED** - Phase 1 fails with required properties, Phase 2 auto-creates

5. **Multi-cluster services**: How to handle services that span clusters?
   - Solver outputs placement per service
   - Service mesh handles cross-cluster routing via Istio multi-cluster

6. **Drift detection**: What happens when actual infra drifts from solution?
   - Option A: Re-solve periodically
   - Option B: Alert + manual re-solve
   - Option C: Continuous reconciliation (K8s controller pattern)
