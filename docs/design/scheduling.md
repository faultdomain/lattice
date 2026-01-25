# Lattice Scheduling Design

## Overview

Platform engineers define **capacity pools** and **placement policies**. Services declare **requirements**. Lattice automatically provisions clusters and places workloads. Clusters are an implementation detail - users never create them directly.

## Design Principles

1. **Clusters are invisible** - Platform engineers think in regions, budgets, and policies
2. **Declarative constraints** - Define what you need, not where to put it
3. **Hierarchical knowledge** - Parents see children, placement quality improves with scope
4. **Same binary everywhere** - Scheduler is integrated into the operator, not separate

## CRD Hierarchy

```
LatticePool (capacity + budget per region)
    │
    ├── LatticeNodeClass (machine templates)
    │
    └── LatticePlacementPolicy (global rules)
            │
            └── LatticeService (workload + requirements)
                    │
                    └── [Auto-created: LatticeCluster]
```

---

## Core CRDs

### LatticePool

Defines available capacity in a region. Platform engineers create these.

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticePool
metadata:
  name: us-east
spec:
  # Provider configuration for this pool
  provider:
    type: aws
    region: us-east-1
    credentials:
      secretRef: aws-creds

  # Capacity constraints
  capacity:
    maxNodes: 100
    maxCores: 2000
    maxMemoryGi: 8000

  # Budget constraints
  budget:
    maxMonthlyCost: 10000
    currency: USD
    alertThreshold: 0.8  # Alert at 80%

  # Node classes available in this pool
  nodeClasses:
    - small
    - medium
    - large
    - gpu

  # Labels for placement matching
  labels:
    compliance: [soc2, hipaa]
    tier: production
    network: low-latency
```

### LatticeNodeClass

Defines machine templates. Referenced by pools.

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeNodeClass
metadata:
  name: medium
spec:
  # Provider-specific mappings
  providers:
    aws:
      instanceType: m5.xlarge
      ami: ami-12345678
    proxmox:
      cores: 4
      memory: 16384
      template: ubuntu-22.04
    docker:
      # For local dev
      memory: 4g
      cpus: 4

  # Abstract resources (used for scheduling)
  resources:
    cores: 4
    memoryGi: 16
    storageGi: 100

  # Cost estimate per hour (for budget calculations)
  costPerHour:
    aws: 0.192
    proxmox: 0.05  # Internal chargeback rate
    docker: 0
```

### LatticePlacementPolicy

Global rules for placement decisions.

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticePlacementPolicy
metadata:
  name: production-policy
spec:
  # Selector for which services this applies to
  selector:
    matchLabels:
      env: production

  # Hard requirements (must satisfy)
  requirements:
    # Minimum replicas across regions for HA
    minRegions: 2

    # Compliance requirements
    compliance:
      - soc2

    # Anti-affinity at region level
    spreadConstraint:
      topologyKey: region
      maxSkew: 1

  # Soft preferences (try to satisfy)
  preferences:
    # Prefer cheaper regions
    - weight: 50
      preference:
        sortBy: cost
        order: ascending

    # Prefer regions with existing capacity
    - weight: 30
      preference:
        sortBy: availableCapacity
        order: descending

  # Cluster sizing rules
  clusterPolicy:
    # Min/max nodes per auto-created cluster
    minNodes: 3
    maxNodes: 20

    # When to create new cluster vs expand existing
    binPackingThreshold: 0.8  # Create new at 80% full

    # Cluster consolidation
    consolidation:
      enabled: true
      minUtilization: 0.3  # Consolidate if under 30%
```

### LatticeService (updated)

Services declare requirements, not locations.

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: api-gateway
  labels:
    env: production
spec:
  containers:
    main:
      image: api-gateway:v1.2.3

  # Placement requirements (replaces explicit cluster targeting)
  placement:
    # Where it CAN run (pool selector)
    pools:
      matchLabels:
        tier: production

    # Where it MUST run (at least one replica)
    requiredRegions:
      - us-east
      - eu-west

    # Resource requirements (for bin packing)
    resources:
      cores: 2
      memoryGi: 4

    # Latency requirements to dependencies
    latency:
      database:
        maxMs: 10
        # Implies: place in same cluster/zone as database

    # Compliance requirements
    compliance:
      - gdpr  # Only eu-west pool has this

  # Service dependencies (unchanged)
  resources:
    database:
      type: Service
      direction: outbound
    cache:
      type: Service
      direction: outbound

  replicas:
    min: 3
    max: 10
```

---

## Scheduling Algorithm

### Phase 1: Constraint Resolution

```
Input: LatticeService with placement requirements
Output: Set of eligible pools

1. Filter pools by label selector (pools.matchLabels)
2. Filter by compliance requirements
3. Filter by capacity (can fit resources)
4. Filter by budget (won't exceed)
5. Result: Candidate pools
```

### Phase 2: Dependency-Aware Placement

```
Input: Candidate pools, service dependencies
Output: Ranked placements

1. For each dependency with latency constraint:
   - Find where dependency is currently placed
   - Score pools by proximity (same cluster > same zone > same region)

2. For dependencies without latency constraints:
   - Any pool is fine, prefer co-location for cost

3. Apply placement policy preferences (cost, capacity)

4. Result: Ranked list of (pool, score) pairs
```

### Phase 3: Cluster Selection/Creation

```
Input: Target pool, service requirements
Output: Cluster to deploy to

1. List existing clusters in pool
2. For each cluster:
   - Check available capacity
   - Check node class availability
   - Score by utilization (prefer bin packing)

3. If suitable cluster exists:
   - Return cluster, possibly scale up nodes

4. If no suitable cluster:
   - Create new LatticeCluster in pool
   - Cluster auto-pivots and self-manages
   - Return new cluster

5. Result: Target cluster for deployment
```

### Phase 4: Deployment

```
Input: Target cluster, LatticeService
Output: Running workload

1. Deploy service to cluster
2. Update service status with placement info
3. Create/update bilateral agreements for cross-cluster deps
4. Done
```

---

## Hierarchical Scheduling

Each operator has a scheduler. Knowledge scope determines placement quality.

```
┌─────────────────────────────────────────────────────────────┐
│ Global Root                                                 │
│ Knows: All pools, all services, all clusters                │
│ Can: Optimal global placement, cross-region migration       │
├─────────────────────────────────────────────────────────────┤
│ Scheduler logic:                                            │
│   1. Receive placement request                              │
│   2. Evaluate all known pools                               │
│   3. Select optimal placement                               │
│   4. Delegate to child (region operator)                    │
└─────────────────────────────────────────────────────────────┘
                            │
          ┌─────────────────┼─────────────────┐
          ▼                 ▼                 ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ US Region       │ │ EU Region       │ │ APAC Region     │
│ Knows: US pools │ │ Knows: EU pools │ │ Knows: APAC     │
│ Can: US-only    │ │ Can: EU-only    │ │ Can: APAC-only  │
│ placement       │ │ placement       │ │ placement       │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

### Escalation Flow

```rust
async fn schedule(&self, svc: &LatticeService) -> Result<Placement> {
    // Try local placement with my knowledge
    let candidates = self.find_candidates(svc);

    if candidates.is_empty() {
        // Escalate to parent for broader view
        if let Some(parent) = &self.parent {
            return parent.schedule(svc).await;
        }
        return Err(NoPlacement);
    }

    // I have candidates, pick best
    let best = self.rank_candidates(candidates, svc);

    // If best candidate is my child, delegate
    if let Some(child) = self.children.get(&best.region) {
        return child.place(svc, &best).await;
    }

    // I own this pool directly, place here
    self.place_local(svc, &best).await
}
```

### Disconnected Operation

When disconnected from parent:

1. Scheduler still works with local knowledge
2. Placement limited to known pools
3. Services requiring unknown regions fail with clear error
4. Reconnection triggers re-evaluation of pending placements

---

## Status and Observability

### LatticeService Status

```yaml
status:
  phase: Running
  placements:
    - pool: us-east
      cluster: us-east-prod-7a3b
      replicas: 2
      node: medium
      cost:
        hourly: 0.384

    - pool: eu-west
      cluster: eu-west-prod-2c1d
      replicas: 1
      node: medium
      cost:
        hourly: 0.192

  totalCost:
    hourly: 0.576
    projected30Day: 414.72

  health:
    available: 3
    ready: 3

  lastScheduled: "2024-01-15T10:30:00Z"
  schedulerDecision:
    reason: "Placed in us-east and eu-west per requiredRegions constraint"
    alternatives:
      - pool: ap-south
        rejected: "No GDPR compliance label"
```

### LatticePool Status

```yaml
status:
  phase: Ready
  capacity:
    allocatedNodes: 45
    allocatedCores: 720
    allocatedMemoryGi: 2880

  utilization:
    nodes: 0.45
    cores: 0.36
    memory: 0.36

  budget:
    currentMonthCost: 4523.50
    projectedMonthCost: 8200.00
    utilizationPercent: 0.82

  clusters:
    - name: us-east-prod-7a3b
      nodes: 15
      services: 23
    - name: us-east-prod-9x2y
      nodes: 12
      services: 18
    - name: us-east-staging-1a2b
      nodes: 8
      services: 12
```

---

## Migration and Rebalancing

### Triggers

1. **Budget exceeded** - Migrate to cheaper pool
2. **Capacity exhausted** - Migrate to pool with room
3. **Consolidation** - Merge underutilized clusters
4. **Compliance change** - Pool loses compliance label
5. **Manual** - Platform engineer requests rebalance

### Migration Flow

```
1. Scheduler detects trigger
2. Find new placement for affected services
3. For each service:
   a. Scale up in new location
   b. Wait for healthy
   c. Update bilateral agreements
   d. Drain from old location
4. If source cluster empty, delete it
```

---

## Future Considerations

### Not in v0

- Spot/preemptible instance support
- GPU scheduling
- Network topology awareness (zone-level latency)
- Cost prediction ML
- Autoscaling based on metrics (just min/max for now)

### v0 Scope

- Pool and NodeClass CRDs
- Basic placement policy
- Constraint-based pool selection
- Automatic cluster creation
- Simple bin packing (first fit)
- Service status with placement info

---

## Open Questions

1. **Cluster naming** - Auto-generated vs user-provided prefix?
2. **Cluster sharing** - One service per cluster or bin pack multiple?
3. **Upgrade coordination** - How to upgrade clusters without service disruption?
4. **Cross-region dependencies** - How to handle services that need low latency across regions?
