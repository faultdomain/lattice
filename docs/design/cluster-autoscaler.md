# Cluster Autoscaler Integration

## Overview

Integrate the Kubernetes Cluster Autoscaler with CAPI provider into Lattice's self-managing clusters. Because clusters own their own CAPI resources post-pivot, both kubeconfigs point to the same cluster ("Unified Cluster" topology - the simplest).

## Design

### Opt-in via Existing Fields

The `WorkerPoolSpec` already has `min` and `max` fields. When both are set, autoscaling is enabled:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
spec:
  nodes:
    worker_pools:
      general:
        replicas: 3      # Initial count (ignored when autoscaling enabled)
        min: 1           # Enables autoscaling when set with max
        max: 10          # Required if min is set
```

**Behavior Matrix:**

| min | max | replicas | Behavior |
|-----|-----|----------|----------|
| unset | unset | 3 | Static scaling. Operator reconciles to exactly 3. |
| 1 | 10 | 3 | Autoscaling enabled. Operator hands-off, autoscaler manages. |
| 1 | 10 | 0 | Autoscaling enabled. Autoscaler scales to min based on annotations. |

### Implementation (Complete)

1. **`WorkerPoolSpec`** (`types.rs`)
   - `is_autoscaling_enabled()` - returns true when both min and max are set
   - `validate()` - ensures min <= max, min >= 1, both or neither set

2. **Manifest Generation** (`provider/mod.rs`)
   - Adds CAPI autoscaler annotations to MachineDeployment when min/max set:
     - `cluster.x-k8s.io/cluster-api-autoscaler-node-group-min-size`
     - `cluster.x-k8s.io/cluster-api-autoscaler-node-group-max-size`

3. **Reconciliation** (`controller.rs`)
   - When autoscaling enabled: `continue` (hands-off, trust autoscaler)
   - When static: reconcile replicas to match spec (existing behavior)
   - Emits warning when replicas is outside [min, max] bounds

4. **Status** (`cluster.rs`)
   - `WorkerPoolStatus.autoscaling_enabled` - reflects current autoscaling state
   - `desired_replicas` = spec.replicas (static) or current MD replicas (autoscaling)

5. **Autoscaler Deployment** (`bootstrap/autoscaler.rs`)
   - ServiceAccount, ClusterRole, ClusterRoleBinding, Deployment
   - Deployed via `ManifestConfig.autoscaling_enabled` flag
   - Uses typed `k8s_openapi` structs (same pattern as AWS/Docker addons)
   - CAPI namespace auto-discovered from cluster name

### Autoscaler Deployment

Generated via typed `k8s_openapi` structs in `bootstrap/autoscaler.rs`:
- **ServiceAccount**: `cluster-autoscaler` in `lattice-system`
- **ClusterRole**: CAPI resources (machinedeployments, machines), node management, PDB, events, leases
- **ClusterRoleBinding**: Binds role to service account
- **Deployment**: Single replica, `system-cluster-critical` priority class, auto-discovery via `--node-group-auto-discovery=clusterapi:namespace=capi-{cluster-name}`

No kubeconfig files needed - uses in-cluster service account for both CAPI and workload APIs.

## Security

The autoscaler has delete permissions on Nodes and Machines. Mitigations:
- Restricted to `lattice-system` namespace
- Minimum required RBAC permissions
- No secrets access needed
- Audit logging captures node deletions

Post-pivot, the cluster manages its own infrastructure - no cross-cluster credentials.

## Non-Goals

- **Scale-from-zero**: Requires capacity annotations. min must be >= 1.
- **Per-pool autoscaler profiles**: All pools use same scale-down timing.

## Migration

Existing clusters with only `replicas` continue unchanged. Autoscaling is opt-in via `min`/`max`.
