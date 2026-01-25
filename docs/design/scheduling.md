# Lattice Scheduling Design

## Overview

Lattice uses distributed, GitOps-native scheduling with **cluster independence** as the core principle. Each cluster runs its own scheduler and can operate autonomously. Conflicts are detected and resolved through git's native conflict mechanisms.

## Architecture

```
                        ┌─────────────────────────┐
                        │     Placement Repo      │
                        │  (shared, conflict-     │
                        │   detection layer)      │
                        │                         │
                        │  placements/            │
                        │    service-a.yaml       │
                        │    service-b.yaml       │
                        └───────────┬─────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
      ┌───────────────┐     ┌───────────────┐     ┌───────────────┐
      │   Cluster A   │     │   Cluster B   │     │   Cluster C   │
      │   Scheduler   │     │   Scheduler   │     │   Scheduler   │
      └───────┬───────┘     └───────┬───────┘     └───────┬───────┘
              │                     │                     │
              ▼                     ▼                     ▼
      ┌───────────────┐     ┌───────────────┐     ┌───────────────┐
      │  Target Repo  │     │  Target Repo  │     │  Target Repo  │
      │  (cluster-a)  │     │  (cluster-b)  │     │  (cluster-c)  │
      └───────┬───────┘     └───────┬───────┘     └───────┬───────┘
              │                     │                     │
              ▼                     ▼                     ▼
          GitOps                GitOps                GitOps
              │                     │                     │
              ▼                     ▼                     ▼
         Cluster A             Cluster B             Cluster C
```

## Three Repositories

### 1. Source Repos (Read-Only, Team-Owned)

Teams define services in their own repos:

```
github.com/team-a/api-service/
└── lattice.yaml
```

### 2. Placement Repo (Shared, Conflict Detection)

Single repo where all clusters compete to claim services. **This is where serialization happens.**

```
github.com/org/lattice-placements/
├── sources.yaml              # Registry of all service sources
└── placements/
    ├── api-service.yaml      # Who owns this service
    ├── ml-inference.yaml
    └── billing.yaml
```

### 3. Target Repos (Per-Cluster, Cluster-Owned)

Each cluster has its own target repo. Only that cluster writes to it. **No conflicts possible.**

```
github.com/org/lattice-cluster-a/
└── services/
    ├── api-service.yaml
    └── billing.yaml

github.com/org/lattice-cluster-b/
└── services/
    └── ml-inference.yaml
```

---

## Placement File Format

Each service has one placement file in the shared placement repo:

```yaml
# placements/api-service.yaml
apiVersion: lattice.dev/v1alpha1
kind: Placement
metadata:
  name: api-service
spec:
  # Copied from source lattice.yaml
  source:
    repo: https://github.com/team-a/api-service
    path: lattice.yaml
    commit: abc123def

  # Placement requirements (from source)
  placement:
    nodeSelector:
      workload-type: general
    clusterSelector:
      matchLabels:
        tier: production
    spread:
      min: 2
      max: 3

status:
  # Current claims - THIS IS THE SERIALIZATION POINT
  claims:
    - cluster: cluster-a
      claimedAt: "2024-01-15T10:00:00Z"
      claimedBy: cluster-a-scheduler
    - cluster: cluster-b
      claimedAt: "2024-01-15T10:00:05Z"
      claimedBy: cluster-b-scheduler
```

---

## Claim Protocol

### Claiming a Service

```
1. Pull placement repo
2. Read placements/{service}.yaml
3. Check eligibility:
   - Do my worker pools match nodeSelector?
   - Do my labels match clusterSelector?
   - Is len(claims) < spread.max?
   - Am I already claiming this?
4. If eligible, add myself to claims[]
5. Commit: "Claim {service} for {cluster}"
6. Push
7. If push succeeds → I own it, write to my target repo
8. If push fails → conflict, goto step 1
```

### Conflict Resolution

Git push rejection IS the conflict detection. When two clusters race:

```
Timeline:
─────────────────────────────────────────────────────────────
t=0    Both clusters pull, see 0 claims
t=1    Cluster A: adds claim, commits
t=2    Cluster B: adds claim, commits
t=3    Cluster A: pushes successfully ✓
t=4    Cluster B: push rejected (conflict) ✗
t=5    Cluster B: pulls, sees A's claim
t=6    Cluster B: if spread allows, re-adds claim and pushes
       OR: if spread.max reached, backs off
```

### Retry Logic

```rust
async fn claim_service(&self, service: &str) -> Result<ClaimResult> {
    for attempt in 0..MAX_RETRIES {
        // Pull latest
        self.pull_placement_repo().await?;

        // Read current placement
        let mut placement = self.read_placement(service)?;

        // Check if already claimed by me
        if placement.has_claim(&self.cluster_name) {
            return Ok(ClaimResult::AlreadyClaimed);
        }

        // Check if I'm eligible
        if !self.is_eligible(&placement) {
            return Ok(ClaimResult::NotEligible);
        }

        // Check spread limit
        if placement.claims.len() >= placement.spec.spread.max {
            return Ok(ClaimResult::SpreadLimitReached);
        }

        // Add my claim
        placement.add_claim(Claim {
            cluster: self.cluster_name.clone(),
            claimed_at: Utc::now(),
            claimed_by: self.scheduler_id.clone(),
        });

        // Try to commit and push
        match self.commit_and_push(&placement).await {
            Ok(_) => return Ok(ClaimResult::Claimed),
            Err(GitError::PushRejected) => {
                // Conflict! Retry after backoff
                sleep(backoff(attempt)).await;
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(ClaimResult::ConflictRetryExhausted)
}
```

---

## Releasing Claims

When a cluster no longer wants a service (scaling down, maintenance, etc.):

```yaml
# Cluster removes itself from claims
status:
  claims:
    # - cluster: cluster-a  ← removed
    - cluster: cluster-b
      claimedAt: "2024-01-15T10:00:05Z"
```

Other clusters see the opening and can claim.

---

## Scheduler Loop

Each cluster's scheduler runs independently:

```rust
loop {
    // 1. Sync source registry
    let sources = pull_sources().await?;

    // 2. For each registered service
    for source in sources {
        let spec = fetch_source_spec(&source).await?;

        // 3. Check if I should run this
        if !matches_my_capabilities(&spec.placement) {
            continue;
        }

        // 4. Try to claim (handles conflicts via git)
        match claim_service(&spec.name).await? {
            ClaimResult::Claimed | ClaimResult::AlreadyClaimed => {
                // 5. Write to my target repo
                write_to_target_repo(&spec).await?;
            }
            ClaimResult::SpreadLimitReached => {
                // Someone else got it, that's fine
            }
            ClaimResult::NotEligible => {
                // I can't run this anyway
            }
        }
    }

    // 6. Clean up services I claimed but are no longer registered
    cleanup_orphaned_claims().await?;

    sleep(reconcile_interval).await;
}
```

---

## Cluster Independence

### Normal Operation

All clusters connected, optimal placement via competition.

### Partition: Cluster Disconnected from Placement Repo

```
Cluster A (disconnected):
- Cannot claim new services
- Cannot see new service registrations
- Existing claims remain valid
- Existing services keep running (GitOps already synced)
- Reconnects → catches up, may need to re-claim

Other clusters:
- Continue operating normally
- Can claim services A would have wanted
- A's existing claims remain (no one removes them)
```

### Partition Recovery

When cluster reconnects:

1. Pull placement repo (may have many changes)
2. Verify my claims still exist
3. If someone released my claim, re-evaluate and re-claim if needed
4. Resume normal loop

---

## Spread Guarantees

| Scenario | Behavior |
|----------|----------|
| `spread.min: 2, max: 3` | At least 2 clusters must claim before service is "placed". First 3 to claim get it. |
| `spread.min: 1, max: 1` | Exactly one cluster. First to push wins. |
| `spread.min: 0` | Optional service, runs wherever it's claimed |

### Enforcing Minimum Spread

Services aren't "ready" until min claims reached:

```yaml
status:
  claims:
    - cluster: cluster-a
      claimedAt: "2024-01-15T10:00:00Z"
  phase: Pending  # Only 1 claim, min is 2
  message: "Waiting for 1 more cluster to claim"
```

Clusters still write to their target repos, but can check phase before marking service Ready.

---

## LatticeService Spec

Minimal additions to existing spec:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: api-service
spec:
  containers:
    main:
      image: api:v2.0.0

  placement:
    # Worker pool requirements
    nodeSelector:
      workload-type: general
    tolerations:
      - key: gpu
        operator: Exists
        effect: NoSchedule

    # Cluster requirements
    clusterSelector:
      matchLabels:
        tier: production
        region: us-east

    # How many clusters
    spread:
      min: 2
      max: 3

  # Existing fields unchanged
  resources:
    database:
      direction: outbound
  replicas:
    min: 2
    max: 10
```

---

## Example Flow

### New Service Registration

```
1. Team pushes lattice.yaml to github.com/team/new-service
2. Platform team adds entry to sources.yaml in placement repo
3. All cluster schedulers see new source on next sync
4. Eligible clusters race to claim:
   - Cluster A: pulls, claims, pushes ✓
   - Cluster B: pulls, claims, pushes ✓ (spread.max: 2)
   - Cluster C: pulls, sees max reached, backs off
5. A and B write to their target repos
6. GitOps syncs to clusters A and B
7. Service running on 2 clusters
```

### Service Needs GPU (Cluster A Has None)

```
1. Service has nodeSelector: workload-type: gpu
2. Cluster A: checks eligibility → no GPU pool → skip
3. Cluster B (GPU): eligible → claims → writes to target
4. Service runs only on B
```

### Cluster B Goes Down

```
1. B stops heartbeating / updating
2. Platform decides to release B's claims (manual or timeout)
3. Other clusters see openings
4. Cluster C claims released services
5. Services migrate via GitOps
```

---

## Configuration

### Cluster Registration

Each cluster registers itself:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: ClusterRegistration
metadata:
  name: cluster-a
spec:
  labels:
    tier: production
    region: us-east

  workerPools:
    general:
      labels:
        workload-type: general
    gpu:
      labels:
        workload-type: gpu
      taints:
        - key: nvidia.com/gpu
          effect: NoSchedule

  targetRepo: git@github.com:org/lattice-cluster-a.git
  placementRepo: git@github.com:org/lattice-placements.git
```

### Scheduler Config

```yaml
apiVersion: lattice.dev/v1alpha1
kind: SchedulerConfig
spec:
  reconcileInterval: 30s
  claimRetries: 5
  claimBackoff:
    initial: 100ms
    max: 5s
    multiplier: 2
```

---

## Observability

### Metrics

| Metric | Description |
|--------|-------------|
| `lattice_claims_total` | Claims attempted by this cluster |
| `lattice_claims_succeeded` | Successful claims |
| `lattice_claims_conflicted` | Claims lost to conflict |
| `lattice_services_owned` | Services this cluster owns |

### Audit Trail

Every claim is a git commit:

```
commit abc123
Author: cluster-a-scheduler
Date:   2024-01-15 10:00:00

    Claim api-service for cluster-a

    Source: github.com/team/api-service@def456
    Eligible: nodeSelector matched, clusterSelector matched
    Spread: 1/2 (need 1 more)
```

---

## Trade-offs

| Aspect | This Design |
|--------|-------------|
| Cluster independence | ✅ Full - each cluster operates alone |
| Conflict detection | ✅ Git push rejection = conflict |
| Global optimization | ⚠️ First-eligible-wins, not best-fit |
| Consistency | ✅ Git is single source of truth |
| Partition tolerance | ✅ Clusters keep running, new scheduling paused |
| Complexity | Medium - git-based CAS |

## Future Considerations

- Weighted claiming (prefer certain clusters)
- Preemption (higher priority service takes claim)
- Affinity hints (prefer clusters with dependencies)
- Automatic claim release on cluster health timeout
