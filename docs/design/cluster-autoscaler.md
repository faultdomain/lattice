# Cluster Autoscaler Integration

## Overview

Integrate the Kubernetes Cluster Autoscaler with CAPI provider into Lattice's self-managing clusters. Because clusters own their own CAPI resources post-pivot, both kubeconfigs point to the same cluster.

## Problem

The Lattice operator currently reconciles `spec.nodes.worker_pools[pool].replicas` against MachineDeployment replicas on every loop (`controller.rs:1964-2008`). If the autoscaler modifies replicas, the operator immediately reverts the change.

## Design

### Opt-in via Existing Fields

The `WorkerPoolSpec` already has `min` and `max` fields (currently ignored). Use these as the autoscaling trigger:

```yaml
apiVersion: lattice.io/v1alpha1
kind: LatticeCluster
spec:
  nodes:
    worker_pools:
      general:
        replicas: 3      # Initial count (also used if autoscaling disabled)
        min: 1           # Enables autoscaling when set
        max: 10          # Required if min is set
```

**Behavior Matrix:**

| min | max | replicas | Behavior |
|-----|-----|----------|----------|
| unset | unset | 3 | Static scaling. Operator reconciles to exactly 3. (current behavior) |
| 1 | 10 | 3 | Autoscaling enabled. Operator applies annotations, does NOT reconcile replicas. |
| 1 | 10 | unset | Autoscaling enabled. Initial replicas = min (see below). |

**Initial Replicas Handling:**

Since `replicas` is `u32` (not `Option<u32>`), it defaults to 0 during deserialization. The autoscaler won't scale up from 0 without scale-from-zero annotations. The operator must set initial replicas to `min` when creating the MachineDeployment:

```rust
// provider/mod.rs - generate_machine_deployment_for_pool()

let initial_replicas = match (pool.min, pool.max) {
    (Some(min), Some(_)) => {
        // Autoscaling: start at min (or replicas if explicitly set and >= min)
        if pool.replicas >= min { pool.replicas } else { min }
    }
    _ => pool.replicas,  // Static scaling
};
```

### Operator Changes

#### 1. Apply Autoscaler Annotations

When generating MachineDeployment manifests, if `min`/`max` are set:

```rust
// provider/mod.rs - generate_machine_deployment_for_pool()

let mut annotations = BTreeMap::new();
if let (Some(min), Some(max)) = (pool.min, pool.max) {
    annotations.insert(
        "cluster.x-k8s.io/cluster-api-autoscaler-node-group-min-size".to_string(),
        min.to_string(),
    );
    annotations.insert(
        "cluster.x-k8s.io/cluster-api-autoscaler-node-group-max-size".to_string(),
        max.to_string(),
    );
}
```

#### 2. Skip Replica Reconciliation for Autoscaled Pools

```rust
// controller.rs - reconcile_worker_pools()

for (pool_id, pool_spec) in &cluster.spec.nodes.worker_pools {
    // If autoscaling is enabled, hands-off - trust the autoscaler
    if pool_spec.min.is_some() && pool_spec.max.is_some() {
        continue;
    }

    // Static scaling: existing behavior
    if let Some(current) = current_replicas {
        if current != pool_spec.replicas {
            ctx.capi.scale_pool(&name, pool_id, &ns, pool_spec.replicas).await?;
        }
    }
}
```

#### 3. Update Annotations on Spec Change

If user changes `min`/`max` on an existing cluster, update the MachineDeployment annotations. Use Server-Side Apply (SSA) for proper field ownership when multiple controllers touch the same object:

```rust
// controller.rs - new function

async fn reconcile_autoscaler_annotations(
    &self,
    cluster: &LatticeCluster,
    pool_id: &str,
    pool_spec: &WorkerPoolSpec,
) -> Result<()> {
    let md_name = format!("{}-pool-{}", cluster.name_any(), pool_id);

    let patch = match (pool_spec.min, pool_spec.max) {
        (Some(min), Some(max)) => json!({
            "apiVersion": "cluster.x-k8s.io/v1beta1",
            "kind": "MachineDeployment",
            "metadata": {
                "name": md_name,
                "annotations": {
                    "cluster.x-k8s.io/cluster-api-autoscaler-node-group-min-size": min.to_string(),
                    "cluster.x-k8s.io/cluster-api-autoscaler-node-group-max-size": max.to_string(),
                }
            }
        }),
        _ => json!({
            "apiVersion": "cluster.x-k8s.io/v1beta1",
            "kind": "MachineDeployment",
            "metadata": {
                "name": md_name,
                "annotations": {
                    "cluster.x-k8s.io/cluster-api-autoscaler-node-group-min-size": null,
                    "cluster.x-k8s.io/cluster-api-autoscaler-node-group-max-size": null,
                }
            }
        }),
    };

    api.patch(
        &md_name,
        &PatchParams::apply("lattice-operator").force(),
        &Patch::Apply(&patch),
    ).await?;

    Ok(())
}
```

#### 4. Handle Autoscaling → Static Transition

When a user removes `min`/`max` to disable autoscaling, the MachineDeployment stays at whatever replica count the autoscaler left it. The operator must re-assert the static `replicas` value:

```rust
// controller.rs - in reconcile loop

// Detect transition: was autoscaling, now static
let was_autoscaling = status.worker_pools
    .get(pool_id)
    .map(|s| s.autoscaling_enabled)
    .unwrap_or(false);

let is_autoscaling = pool_spec.min.is_some() && pool_spec.max.is_some();

if was_autoscaling && !is_autoscaling {
    // Transitioning to static: force scale to spec.replicas
    ctx.capi.scale_pool(&name, pool_id, &ns, pool_spec.replicas).await?;
}
```

### Autoscaler Deployment

Deploy as a standard Deployment in `lattice-system` namespace. Since post-pivot both the workload and CAPI resources are in the same cluster:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cluster-autoscaler
  namespace: lattice-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cluster-autoscaler
  template:
    spec:
      serviceAccountName: cluster-autoscaler
      priorityClassName: system-cluster-critical  # Don't evict during node pressure
      containers:
      - name: cluster-autoscaler
        image: registry.k8s.io/autoscaling/cluster-autoscaler:v1.31.0
        command:
        - /cluster-autoscaler
        - --cloud-provider=clusterapi
        - --node-group-auto-discovery=clusterapi:namespace=capi-system
        - --scale-down-delay-after-add=5m
        - --scale-down-unneeded-time=5m
        - --skip-nodes-with-local-storage=false
        # Both point to local cluster (self-managing)
        # No --cloud-config needed - uses in-cluster config
        # No --kubeconfig needed - uses in-cluster config
        resources:
          requests:
            cpu: 100m
            memory: 300Mi
          limits:
            memory: 600Mi
```

**Notes:**
- No external kubeconfig files needed. The autoscaler uses in-cluster service account for both CAPI and workload APIs.
- `priorityClassName: system-cluster-critical` ensures the autoscaler isn't evicted during heavy node pressure—exactly when scaling is most needed.

### RBAC

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-autoscaler
rules:
# CAPI resources
- apiGroups: [cluster.x-k8s.io]
  resources: [machinedeployments, machinedeployments/scale, machinesets, machinesets/scale, machinepools, machinepools/scale]
  verbs: [get, list, watch, patch, update]
- apiGroups: [cluster.x-k8s.io]
  resources: [machines]
  verbs: [get, list, watch, delete]
# Standard autoscaler permissions
- apiGroups: [""]
  resources: [nodes, pods, services, replicationcontrollers, persistentvolumeclaims, persistentvolumes, namespaces]
  verbs: [get, list, watch]
- apiGroups: [""]
  resources: [nodes]
  verbs: [delete, patch, update]
- apiGroups: [apps]
  resources: [daemonsets, replicasets, statefulsets]
  verbs: [get, list, watch]
- apiGroups: [policy]
  resources: [poddisruptionbudgets]
  verbs: [get, list, watch]
- apiGroups: [""]
  resources: [events]
  verbs: [create, patch]
- apiGroups: [coordination.k8s.io]
  resources: [leases]
  verbs: [get, create, update]
```

### Validation

Add validation for autoscaling configuration:

```rust
// lattice-common/src/crd/types.rs

impl WorkerPoolSpec {
    pub fn validate(&self) -> Result<(), String> {
        match (self.min, self.max) {
            (Some(min), Some(max)) => {
                if min > max {
                    return Err(format!("min ({}) cannot exceed max ({})", min, max));
                }
                if min == 0 {
                    return Err("scale-from-zero not supported (min must be >= 1)".into());
                }
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err("min and max must both be set or both unset".into());
            }
            (None, None) => {}
        }
        Ok(())
    }
}
```

### Warning for Ignored Replicas

When `replicas` is outside `[min, max]`, emit a warning event and set a status message:

```rust
// controller.rs - during reconciliation

if let (Some(min), Some(max)) = (pool_spec.min, pool_spec.max) {
    if pool_spec.replicas < min || pool_spec.replicas > max {
        let msg = format!(
            "pool '{}': replicas ({}) ignored, autoscaler will manage within [{}, {}]",
            pool_id, pool_spec.replicas, min, max
        );

        // Emit warning event
        recorder.publish(Event {
            type_: EventType::Warning,
            reason: "ReplicasIgnored".into(),
            note: Some(msg.clone()),
            action: "Reconciling".into(),
            secondary: None,
        });

        // Set status message
        pool_status.message = Some(msg);
    }
}
```

Users will see:
```
$ kubectl describe latticecluster my-cluster
...
Events:
  Type     Reason           Message
  ----     ------           -------
  Warning  ReplicasIgnored  pool 'general': replicas (100) ignored, autoscaler will manage within [1, 10]
```

### Status Reporting

Extend `WorkerPoolStatus` to reflect autoscaling state:

```rust
pub struct WorkerPoolStatus {
    pub desired_replicas: u32,
    pub current_replicas: u32,
    pub ready_replicas: u32,
    pub autoscaling_enabled: bool,  // NEW
    pub autoscaling_min: Option<u32>,  // NEW
    pub autoscaling_max: Option<u32>,  // NEW
    pub message: Option<String>,
}
```

**Status always reflects reality.** Even though the operator is hands-off for replicas, the status loop still reads from MachineDeployment:

```rust
// controller.rs - update_status()

for (pool_id, pool_spec) in &cluster.spec.nodes.worker_pools {
    let md = ctx.capi.get_machine_deployment(&name, pool_id).await?;

    pool_status.insert(pool_id.clone(), WorkerPoolStatus {
        // Always pull actual values from MachineDeployment
        desired_replicas: md.spec.replicas.unwrap_or(0),
        current_replicas: md.status.as_ref().map(|s| s.replicas).unwrap_or(0),
        ready_replicas: md.status.as_ref().map(|s| s.ready_replicas).unwrap_or(0),
        // Reflect autoscaling config
        autoscaling_enabled: pool_spec.min.is_some() && pool_spec.max.is_some(),
        autoscaling_min: pool_spec.min,
        autoscaling_max: pool_spec.max,
        message: None,
    });
}
```

### Field Ownership

With autoscaling enabled, multiple controllers touch MachineDeployment:

| Field | Owner |
|-------|-------|
| `metadata.annotations` (autoscaler) | Lattice Operator |
| `spec.replicas` | Cluster Autoscaler |
| `spec.template` | Lattice Operator |
| `status.*` | CAPI |

Using Server-Side Apply ensures each controller only manages its owned fields.

## Security Considerations

The cluster-autoscaler is a **high-privilege component** with delete permissions on Nodes and Machines.

1. **Namespace isolation**: Restricted to `lattice-system` namespace
2. **ServiceAccount scoped**: RBAC grants minimum required permissions
3. **No secrets access**: Autoscaler doesn't need access to secrets
4. **Audit logging**: Node deletions are logged via Kubernetes audit

The autoscaler runs inside the workload cluster post-pivot, managing its own infrastructure. This is secure because:
- The cluster already trusts itself (it owns its CAPI resources)
- No cross-cluster credentials are stored
- Outbound-only architecture means no attack surface from parent

## Non-Goals

- **Scale-from-zero**: Requires capacity annotations on MachineDeployments. Deferred to future work.
- **Custom autoscaler profiles**: Use default timing parameters initially.
- **Per-pool autoscaler settings**: All pools use same scale-down delays.

## Migration

Existing clusters with only `replicas` set continue to work unchanged. Autoscaling is purely opt-in by adding `min`/`max`.

## Testing

1. **Unit tests**: Validate annotation generation, reconciliation skip logic
2. **Integration tests**: Verify operator doesn't fight with simulated autoscaler patches
3. **E2E tests**:
   - Deploy workload that triggers scale-up
   - Verify MachineDeployment replicas increase
   - Remove workload, verify scale-down after delay
   - Verify operator doesn't revert autoscaler changes

## Summary

| Component | Change |
|-----------|--------|
| `WorkerPoolSpec` | Use existing `min`/`max` fields |
| Manifest generation | Add autoscaler annotations when `min`/`max` set |
| Reconciliation | Skip exact replica enforcement for autoscaled pools |
| Deployment | Add cluster-autoscaler to lattice-system |
| RBAC | Grant CAPI and node management permissions |
