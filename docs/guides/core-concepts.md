# Core Concepts

## Self-Managing Clusters via Pivoting

Lattice's defining feature is that every cluster it provisions becomes fully self-managing. This is achieved through a pivoting architecture where CAPI resources are transferred from the parent cluster to the child cluster after provisioning.

### Why Self-Managing?

Traditional multi-cluster tools create a hub-and-spoke dependency: if the management cluster goes down, managed clusters lose their control plane. Lattice inverts this:

- **Parent failure doesn't affect children.** After pivot, each cluster owns its own CAPI resources and can scale, upgrade, and repair itself independently.
- **No single point of failure.** The parent is only needed during initial provisioning.
- **Scalable.** The parent doesn't become a bottleneck as cluster count grows.
- **Air-gap friendly.** Clusters operate independently once provisioned.

### The Pivot Flow

```
Parent Cluster                          Child Cluster
─────────────                          ─────────────
1. LatticeCluster CRD created
2. CAPI provisions infrastructure
                                       3. kubeadm runs, calls parent's
                                          bootstrap webhook
                                       4. Agent installed, establishes
                                          outbound gRPC stream to parent
5. Parent sends PivotCommand with
   CAPI resources over gRPC stream
                                       6. Agent imports CAPI resources
                                          locally (distributed move)
                                       7. Cluster is now self-managing
```

After step 7, the parent can be deleted without affecting the child.

## Cluster Lifecycle Phases

Every LatticeCluster progresses through a defined set of phases:

| Phase | Description |
|-------|-------------|
| **Pending** | Initial state. The operator validates the InfraProvider, copies credentials, ensures CAPI is installed, generates CAPI manifests, and transitions to Provisioning. |
| **Provisioning** | CAPI is creating infrastructure (VMs, networks, load balancers). The operator waits for the cluster to become reachable and patches the kubeconfig. |
| **Pivoting** | The bootstrap webhook has been called, the agent is connected, and CAPI resources are being transferred to the child cluster. |
| **Pivoted** | CAPI resources have been successfully transferred. The cluster is completing infrastructure setup (installing Cilium, Istio, etc.). |
| **Ready** | The cluster is fully self-managing. The operator reconciles infrastructure, manages Kubernetes version upgrades, and handles worker pool scaling. |
| **Deleting** | The cluster is being torn down. For self-clusters with a parent, this triggers an unpivot (exporting CAPI resources back to the parent). For child clusters, CAPI deletes the infrastructure. |
| **Unpivoting** | CAPI resources are being exported back to the parent or a temporary bootstrap cluster for teardown. |
| **Failed** | An unrecoverable error occurred. Check the status message and conditions for details. |

## Network Architecture: Outbound-Only

Workload clusters never accept inbound connections. All communication is initiated outbound from the child:

```
┌──────────────────────────────────────────────────────┐
│                  Parent Cluster (Cell)                │
│                                                      │
│  Lattice Operator                                    │
│  - gRPC Server: accepts agent connections            │
│  - Bootstrap Webhook: kubeadm target                 │
│  - K8s API Proxy: streams requests to children       │
└──────────────────────────────────────────────────────┘
         ▲                              ▲
         │ kubeadm webhook call         │ persistent gRPC stream
         │ (outbound from child)        │ (outbound from child)
┌────────┴──────────────────────────────┴──────────────┐
│                  Child Cluster                        │
│                                                      │
│  Lattice Operator (Agent mode)                       │
│  - Outbound gRPC stream to parent                    │
│  - Owns CAPI resources post-pivot                    │
│  - Self-manages scaling, upgrades, node replacement  │
└──────────────────────────────────────────────────────┘
```

The gRPC stream is used for:
- Coordination during provisioning and pivot
- Optional health reporting and heartbeats
- K8s API proxy (parent can access child's API through the stream)

The gRPC stream is **not** required for:
- Self-management (scaling, upgrades, node replacement)
- CAPI reconciliation
- Running workloads
- Mesh policy enforcement

## Parent-Child Relationship

The parent cluster runs in **Cell** mode. It provides:

- **gRPC Server**: Accepts persistent outbound connections from child agents
- **Bootstrap Webhook**: Called by kubeadm's `postKubeadmCommands` during child cluster provisioning to trigger agent installation
- **K8s API Proxy**: Allows the parent to access child Kubernetes APIs through the gRPC stream, supporting all verbs (get, list, watch, create, update, delete)

The child cluster runs the Lattice operator in **Agent** mode. It:

- Establishes an outbound gRPC stream to the parent on startup
- Receives and applies CAPI resources during pivot
- Reports health via heartbeats
- Proxies K8s API requests from the parent

## Defense in Depth Security Model

Lattice enforces a default-deny security posture with multiple enforcement layers:

### Layer 1: Cilium (L4 eBPF)

A `CiliumClusterwideNetworkPolicy` denies all ingress by default. Traffic is only allowed when explicit Cilium policies are generated from bilateral mesh agreements.

### Layer 2: Istio (L7 Identity)

An `AuthorizationPolicy` with empty `spec: {}` denies all traffic by default. Service-to-service communication requires matching Istio AuthorizationPolicies generated from bilateral mesh agreements.

### Bilateral Mesh Agreements

Traffic is only allowed when **both sides agree**:

- The **caller** declares an outbound dependency on the callee
- The **callee** allows inbound from the caller

This generates both Cilium (L4) and Istio (L7) allow policies. If either side doesn't agree, traffic is denied.

### Cedar Policy Authorization

Access to secrets and external resources is governed by Cedar policies (default-deny):

- **Principal**: `Lattice::Service::"namespace/name"` (service identity)
- **Action**: `Lattice::Action::"AccessSecret"`
- **Resource**: `Lattice::SecretPath::"provider:remote_key"` (secret identity)
- `forbid` policies always override `permit` policies

### System Namespace Exclusions

The following namespaces are excluded from default-deny policies to avoid breaking system components:

- `kube-system`
- `cilium-system`
- `istio-system`
- `lattice-system`
- `cert-manager`
- `capi-*` (all CAPI namespaces)

## Operator Modes

The Lattice operator binary runs in different modes depending on context:

| Mode | Detected By | Controllers |
|------|-------------|-------------|
| **Cell** | Self-referencing LatticeCluster with `parentConfig` | Cluster controller, Cell gRPC server, Bootstrap webhook, K8s API proxy, Provider controllers |
| **Service** | Self-referencing LatticeCluster without `parentConfig` | Service/Job/Model controllers, Mesh member controller, Secret provider controller |
| **Agent** | Presence of `lattice-parent-config` Secret in `lattice-system` | Agent gRPC client, Pivot handler |

A single cluster can run both Cell and Service mode simultaneously (e.g., a management cluster that also runs workloads).
