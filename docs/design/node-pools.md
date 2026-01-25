# Node Pools Design

## Overview

Refactor LatticeCluster from single worker count to named worker pools. Each pool can have different node classes, replica counts, labels, and taints. This enables heterogeneous clusters (e.g., general + GPU nodes) and aligns with the scheduling design where services request specific node capabilities.

## Design Principles

1. **MachineDeployment everywhere** - Uniform behavior across all providers
2. **Backwards compatible** - Single `workers` count still works (implicit "default" pool)
3. **Node class reference** - Pools reference LatticeNodeClass for machine templates
4. **Independent scaling** - Each pool scales independently

---

## Current State

### CRD

```rust
pub struct NodeSpec {
    pub control_plane: u32,
    pub workers: u32,
}
```

### YAML

```yaml
nodes:
  controlPlane: 3
  workers: 5
```

### Generated CAPI Resources

```
Cluster
├── KubeadmControlPlane (replicas: 3)
│   └── DockerMachineTemplate (control-plane)
├── MachineDeployment: {cluster}-md-0 (replicas: 0 → 5 after pivot)
│   └── DockerMachineTemplate (workers)
└── KubeadmConfigTemplate
```

### Limitations

- All workers identical (same instance type)
- No GPU/specialized node support
- No per-pool labels or taints
- Can't mix instance sizes

---

## Target State

### CRD

```rust
/// Node topology specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct NodeSpec {
    /// Number of control plane nodes (must be odd for HA)
    #[serde(rename = "controlPlane")]
    pub control_plane: u32,

    /// Worker node pools (mutually exclusive with `workers`)
    #[serde(rename = "workerPools", default, skip_serializing_if = "Option::is_none")]
    pub worker_pools: Option<BTreeMap<String, WorkerPoolSpec>>,

    /// Simple worker count (legacy, creates implicit "default" pool)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workers: Option<u32>,
}

/// Worker pool specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct WorkerPoolSpec {
    /// Human-readable name for UI/dashboards (mutable)
    /// Pool ID (map key) is immutable and used for CAPI resource naming
    #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Number of nodes in this pool
    pub replicas: u32,

    /// Node class reference (must exist as LatticeNodeClass)
    /// If omitted, uses provider default
    #[serde(rename = "nodeClass", default, skip_serializing_if = "Option::is_none")]
    pub node_class: Option<String>,

    /// Labels applied to nodes in this pool
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,

    /// Taints applied to nodes in this pool
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taints: Vec<NodeTaint>,

    /// Minimum nodes (for autoscaling, future - accepted but not implemented)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<u32>,

    /// Maximum nodes (for autoscaling, future - accepted but not implemented)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<u32>,
}

/// Node taint specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct NodeTaint {
    pub key: String,
    pub value: Option<String>,
    pub effect: TaintEffect,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub enum TaintEffect {
    NoSchedule,
    PreferNoSchedule,
    NoExecute,
}
```

### YAML Examples

**Simple (backwards compatible):**

```yaml
nodes:
  controlPlane: 3
  workers: 5  # Creates implicit "default" pool
```

**Explicit pools:**

```yaml
nodes:
  controlPlane: 3
  workerPools:
    general:                              # ID (immutable)
      displayName: "General Purpose"      # Human-readable (mutable)
      replicas: 3
      nodeClass: medium
      labels:
        workload-type: general

    gpu:                                  # ID (immutable)
      displayName: "GPU Workers (A100)"
      replicas: 2
      nodeClass: gpu-large
      labels:
        workload-type: gpu
        nvidia.com/gpu: "true"
      taints:
        - key: nvidia.com/gpu
          effect: NoSchedule

    highmem:                              # ID (immutable)
      displayName: "High Memory"
      replicas: 1
      nodeClass: memory-optimized
      labels:
        workload-type: highmem
```

### Generated CAPI Resources

```
Cluster
├── KubeadmControlPlane (replicas: 3)
│   └── {Provider}MachineTemplate: {cluster}-control-plane
│
├── MachineDeployment: {cluster}-pool-general
│   ├── {Provider}MachineTemplate: {cluster}-pool-general
│   └── KubeadmConfigTemplate: {cluster}-pool-general
│
├── MachineDeployment: {cluster}-pool-gpu
│   ├── {Provider}MachineTemplate: {cluster}-pool-gpu
│   └── KubeadmConfigTemplate: {cluster}-pool-gpu
│
└── MachineDeployment: {cluster}-pool-highmem
    ├── {Provider}MachineTemplate: {cluster}-pool-highmem
    └── KubeadmConfigTemplate: {cluster}-pool-highmem
```

---

## Implementation

### Phase 1: CRD Changes

**File: `crates/lattice-common/src/crd/types.rs`**

```rust
impl NodeSpec {
    /// Returns resolved worker pools (handles legacy `workers` field)
    pub fn resolved_pools(&self) -> BTreeMap<String, WorkerPoolSpec> {
        if let Some(pools) = &self.worker_pools {
            pools.clone()
        } else if let Some(count) = self.workers {
            let mut pools = BTreeMap::new();
            pools.insert("default".to_string(), WorkerPoolSpec {
                replicas: count,
                node_class: None,
                labels: BTreeMap::new(),
                taints: vec![],
                min: None,
                max: None,
            });
            pools
        } else {
            BTreeMap::new()
        }
    }

    /// Total worker count across all pools
    pub fn total_workers(&self) -> u32 {
        self.resolved_pools().values().map(|p| p.replicas).sum()
    }

    /// Validates the node specification
    pub fn validate(&self) -> Result<(), Error> {
        // Control plane validation (unchanged)
        if self.control_plane == 0 {
            return Err(Error::validation("control plane count must be at least 1"));
        }
        if self.control_plane > 1 && self.control_plane % 2 == 0 {
            return Err(Error::validation("control plane count must be odd for HA"));
        }

        // Mutual exclusivity
        if self.workers.is_some() && self.worker_pools.is_some() {
            return Err(Error::validation(
                "cannot specify both 'workers' and 'workerPools'"
            ));
        }

        // Pool name validation
        if let Some(pools) = &self.worker_pools {
            for (name, _) in pools {
                if !is_valid_pool_name(name) {
                    return Err(Error::validation(format!(
                        "invalid pool name '{}': must be lowercase alphanumeric with hyphens",
                        name
                    )));
                }
            }
        }

        Ok(())
    }
}

fn is_valid_pool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}
```

### Phase 2: CAPI Generation

**File: `crates/lattice-cluster/src/provider/mod.rs`**

```rust
/// Generate MachineDeployments for all worker pools
pub fn generate_machine_deployments(
    config: &ClusterConfig,
    infra: &InfrastructureRef,
    pools: &BTreeMap<String, WorkerPoolSpec>,
    node_classes: &BTreeMap<String, LatticeNodeClass>,
) -> Vec<CAPIManifest> {
    pools
        .iter()
        .flat_map(|(pool_name, pool_spec)| {
            generate_pool_resources(config, infra, pool_name, pool_spec, node_classes)
        })
        .collect()
}

fn generate_pool_resources(
    config: &ClusterConfig,
    infra: &InfrastructureRef,
    pool_name: &str,
    pool_spec: &WorkerPoolSpec,
    node_classes: &BTreeMap<String, LatticeNodeClass>,
) -> Vec<CAPIManifest> {
    let mut manifests = vec![];

    // Resolve node class (or use provider default)
    let node_class = pool_spec
        .node_class
        .as_ref()
        .and_then(|name| node_classes.get(name));

    // MachineDeployment
    let md_name = format!("{}-pool-{}", config.name, pool_name);
    manifests.push(generate_machine_deployment_for_pool(
        config,
        infra,
        &md_name,
        pool_spec,
    ));

    // Provider-specific MachineTemplate
    manifests.push(generate_machine_template_for_pool(
        config,
        infra,
        &md_name,
        node_class,
    ));

    // KubeadmConfigTemplate with labels/taints
    manifests.push(generate_kubeadm_config_for_pool(
        config,
        &md_name,
        pool_spec,
    ));

    manifests
}

fn generate_machine_deployment_for_pool(
    config: &ClusterConfig,
    infra: &InfrastructureRef,
    md_name: &str,
    pool_spec: &WorkerPoolSpec,
) -> CAPIManifest {
    let spec = serde_json::json!({
        "clusterName": config.name,
        "replicas": 0,  // Still 0 initially, scaled after pivot
        "selector": {
            "matchLabels": {}
        },
        "template": {
            "metadata": {
                "labels": pool_spec.labels.clone()
            },
            "spec": {
                "clusterName": config.name,
                "version": format!("v{}", config.k8s_version),
                "bootstrap": {
                    "configRef": {
                        "apiVersion": "bootstrap.cluster.x-k8s.io/v1beta2",
                        "kind": "KubeadmConfigTemplate",
                        "name": md_name
                    }
                },
                "infrastructureRef": {
                    "apiVersion": infra.api_version,
                    "kind": infra.machine_template_kind,
                    "name": md_name
                }
            }
        }
    });

    CAPIManifest::new(
        CAPI_CLUSTER_API_VERSION,
        "MachineDeployment",
        md_name,
        &config.namespace,
    )
    .with_spec(spec)
}

fn generate_kubeadm_config_for_pool(
    config: &ClusterConfig,
    md_name: &str,
    pool_spec: &WorkerPoolSpec,
) -> CAPIManifest {
    // Build node registration with labels and taints
    let mut node_registration = serde_json::json!({
        "kubeletExtraArgs": {}
    });

    // Add labels
    if !pool_spec.labels.is_empty() {
        let labels_str = pool_spec
            .labels
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(",");
        node_registration["kubeletExtraArgs"]["node-labels"] = labels_str.into();
    }

    // Add taints
    if !pool_spec.taints.is_empty() {
        let taints_str = pool_spec
            .taints
            .iter()
            .map(|t| {
                let value = t.value.as_deref().unwrap_or("");
                format!("{}={}:{:?}", t.key, value, t.effect)
            })
            .collect::<Vec<_>>()
            .join(",");
        node_registration["kubeletExtraArgs"]["register-with-taints"] = taints_str.into();
    }

    let spec = serde_json::json!({
        "template": {
            "spec": {
                "joinConfiguration": {
                    "nodeRegistration": node_registration
                }
            }
        }
    });

    CAPIManifest::new(
        "bootstrap.cluster.x-k8s.io/v1beta2",
        "KubeadmConfigTemplate",
        md_name,
        &config.namespace,
    )
    .with_spec(spec)
}
```

### Phase 3: Provider Machine Templates

Each provider generates machine templates based on node class.

**File: `crates/lattice-cluster/src/provider/docker.rs`**

```rust
fn generate_docker_machine_template(
    config: &ClusterConfig,
    name: &str,
    node_class: Option<&LatticeNodeClass>,
) -> CAPIManifest {
    let docker_config = node_class
        .and_then(|nc| nc.spec.providers.get("docker"))
        .cloned()
        .unwrap_or_default();

    let spec = serde_json::json!({
        "template": {
            "spec": {
                "extraMounts": docker_config.extra_mounts.unwrap_or_default(),
                "customImage": docker_config.image.as_deref()
                    .unwrap_or("kindest/node:v1.32.0")
            }
        }
    });

    CAPIManifest::new(
        CAPD_API_VERSION,
        "DockerMachineTemplate",
        name,
        &config.namespace,
    )
    .with_spec(spec)
}
```

**File: `crates/lattice-cluster/src/provider/aws.rs`**

```rust
fn generate_aws_machine_template(
    config: &ClusterConfig,
    name: &str,
    node_class: Option<&LatticeNodeClass>,
    aws_config: &AwsProviderConfig,
) -> CAPIManifest {
    let aws_node_config = node_class
        .and_then(|nc| nc.spec.providers.get("aws"))
        .cloned()
        .unwrap_or_default();

    let instance_type = aws_node_config
        .instance_type
        .as_deref()
        .unwrap_or("t3.medium");

    let spec = serde_json::json!({
        "template": {
            "spec": {
                "instanceType": instance_type,
                "iamInstanceProfile": format!("nodes.cluster-api-provider-aws.sigs.k8s.io"),
                "sshKeyName": aws_config.ssh_key_name,
                "ami": {
                    "id": aws_node_config.ami.as_deref().unwrap_or(&aws_config.ami_id)
                },
                "rootVolume": {
                    "size": aws_node_config.root_volume_size.unwrap_or(100),
                    "type": "gp3"
                }
            }
        }
    });

    CAPIManifest::new(
        CAPA_API_VERSION,
        "AWSMachineTemplate",
        name,
        &config.namespace,
    )
    .with_spec(spec)
}
```

### Phase 4: Reconciliation

**File: `crates/lattice-cluster/src/controller.rs`**

```rust
async fn reconcile_worker_pools(
    &self,
    cluster: &LatticeCluster,
    ctx: &Context,
) -> Result<(), Error> {
    let pools = cluster.spec.nodes.resolved_pools();
    let capi_namespace = format!("capi-{}", cluster.name_any());

    for (pool_name, pool_spec) in &pools {
        let md_name = format!("{}-pool-{}", cluster.name_any(), pool_name);

        // Get current replica count
        let current = ctx
            .capi
            .get_machine_deployment_replicas(&md_name, &capi_namespace)
            .await?
            .unwrap_or(0);

        // Scale if needed
        if current != pool_spec.replicas {
            info!(
                pool = %pool_name,
                current = current,
                desired = pool_spec.replicas,
                "Scaling worker pool"
            );
            ctx.capi
                .scale_machine_deployment(&md_name, &capi_namespace, pool_spec.replicas)
                .await?;
        }
    }

    // TODO: Handle pool deletion (pool removed from spec)

    Ok(())
}
```

### Phase 5: Status

```rust
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Default)]
pub struct LatticeClusterStatus {
    pub phase: ClusterPhase,
    pub message: Option<String>,

    /// Per-pool status
    #[serde(rename = "workerPools", default, skip_serializing_if = "BTreeMap::is_empty")]
    pub worker_pools: BTreeMap<String, WorkerPoolStatus>,

    // ... existing fields
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Default)]
pub struct WorkerPoolStatus {
    /// Desired replicas
    pub desired: u32,
    /// Ready replicas
    pub ready: u32,
    /// Available replicas
    pub available: u32,
    /// Node class in use
    #[serde(rename = "nodeClass", skip_serializing_if = "Option::is_none")]
    pub node_class: Option<String>,
}
```

---

## Migration

### Backwards Compatibility

The `workers` field continues to work:

```yaml
# This still works
nodes:
  controlPlane: 3
  workers: 5
```

Internally converted to:

```yaml
nodes:
  controlPlane: 3
  workerPools:
    default:
      replicas: 5
```

### Existing Clusters

Existing clusters with `{cluster}-md-0` MachineDeployment continue working. The reconciler handles both naming conventions:

```rust
fn get_machine_deployment_names(cluster: &LatticeCluster) -> Vec<String> {
    let pools = cluster.spec.nodes.resolved_pools();

    if pools.len() == 1 && pools.contains_key("default") {
        // Legacy or simple case: check both old and new naming
        vec![
            format!("{}-md-0", cluster.name_any()),        // Legacy
            format!("{}-pool-default", cluster.name_any()), // New
        ]
    } else {
        // Explicit pools: new naming only
        pools
            .keys()
            .map(|name| format!("{}-pool-{}", cluster.name_any(), name))
            .collect()
    }
}
```

### Upgrade Path

1. **No action required** - Existing clusters continue working
2. **Optional migration** - Users can update spec to explicit pools
3. **New clusters** - Can use either format

---

## Integration with Scheduling

The scheduling system uses pools for placement:

```yaml
# LatticeService
spec:
  placement:
    nodeSelector:
      workload-type: gpu
    tolerations:
      - key: nvidia.com/gpu
        operator: Exists
```

Scheduler matches against pool labels/taints to find suitable clusters.

---

## Testing

### Unit Tests

- `NodeSpec::resolved_pools()` - Legacy conversion
- `NodeSpec::validate()` - Mutual exclusivity, name validation
- Pool manifest generation

### Integration Tests

- Multi-pool cluster creation
- Independent pool scaling
- Label/taint propagation to nodes

### E2E Tests

- Create cluster with 2 pools
- Scale each pool independently
- Verify node labels via kubectl

---

## File Changes Summary

| File | Change |
|------|--------|
| `crates/lattice-common/src/crd/types.rs` | Add `WorkerPoolSpec`, `NodeTaint`, update `NodeSpec` |
| `crates/lattice-common/src/crd/cluster.rs` | Add `WorkerPoolStatus` to status |
| `crates/lattice-cluster/src/provider/mod.rs` | Multi-pool MachineDeployment generation |
| `crates/lattice-cluster/src/provider/docker.rs` | Per-pool DockerMachineTemplate |
| `crates/lattice-cluster/src/provider/aws.rs` | Per-pool AWSMachineTemplate |
| `crates/lattice-cluster/src/provider/proxmox.rs` | Per-pool ProxmoxMachineTemplate |
| `crates/lattice-cluster/src/controller.rs` | Multi-pool reconciliation |
| `tests/e2e/fixtures/clusters/*.yaml` | Update fixtures |

---

## Design Decisions

### Pool Deletion: Drain with Timeout

When a pool is removed from spec:

1. Cordon all nodes in pool
2. Drain workloads (default 5min timeout)
3. Delete MachineDeployment
4. If drain fails, surface error in status and block

Configurable via cluster-level policy:

```yaml
spec:
  poolDeletionPolicy: Drain | Orphan | Force
  poolDrainTimeout: 300  # seconds
```

| Policy | Behavior |
|--------|----------|
| `Drain` | Cordon, drain, wait, delete (default) |
| `Orphan` | Delete MachineDeployment, leave pods to be rescheduled |
| `Force` | Immediate delete, no drain |

### Pool Naming: ID vs Display Name

Pool keys are immutable IDs used for CAPI resource naming. Display names are mutable for humans.

```yaml
workerPools:
  general:                    # ID (immutable, lowercase, used in MachineDeployment name)
    displayName: "General Purpose Workers"  # Mutable, for UI/dashboards
    replicas: 5

  gpu-a100:                   # ID
    displayName: "GPU Nodes (A100)"
    replicas: 2
```

Generated resources:
```
{cluster}-pool-general      # Never changes
{cluster}-pool-gpu-a100     # Never changes
```

Benefits:
- Stable CAPI resource names (no rename churn)
- Human-friendly labels in UIs
- Audit trail preserved (ID never changes)

### Min/Max Autoscaling: Schema Now, Implement Later

Fields accepted in v0 but not implemented:

```yaml
workerPools:
  general:
    replicas: 5
    min: 3      # Accepted, logged as warning, ignored
    max: 10     # Accepted, logged as warning, ignored
```

Warning emitted:
```
WARN pool="general": min/max autoscaling not implemented, using fixed replicas=5
```

This ensures forward compatibility without scope creep.

### Control Plane: Single Pool Only

Control plane remains a simple count, not a pool:

```yaml
nodes:
  controlPlane: 3           # Always homogeneous
  workerPools:              # Heterogeneity is for workers
    # ...
```

Rationale:
- CP requires odd numbers for quorum
- Upgrade sequencing is complex
- No concrete use case for heterogeneous CP
- Complexity not justified
