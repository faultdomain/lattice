# Cluster Management

## Creating Clusters

Clusters are defined as LatticeCluster CRDs. The `lattice install` command handles the complete provisioning flow, or you can create LatticeCluster resources directly on an existing management cluster to provision child clusters.

### Infrastructure Providers

Before creating a cluster, configure an InfraProvider with your cloud credentials:

**AWS:**

```yaml
apiVersion: lattice.dev/v1alpha1
kind: InfraProvider
metadata:
  name: aws-prod
  namespace: lattice-system
spec:
  type: AWS
  region: us-east-1
  credentialsSecretRef:
    name: aws-credentials
    namespace: lattice-system
  aws:
    sshKeyName: my-ssh-key
    vpcId: vpc-0123456789abcdef0       # optional: use existing VPC
    subnetIds:                          # optional: use existing subnets
      - subnet-0123456789abcdef0
    roleArn: arn:aws:iam::123456:role/lattice  # optional: assume role
```

**Proxmox:**

```yaml
apiVersion: lattice.dev/v1alpha1
kind: InfraProvider
metadata:
  name: proxmox-lab
  namespace: lattice-system
spec:
  type: Proxmox
  credentialsSecretRef:
    name: proxmox-credentials
    namespace: lattice-system
  proxmox:
    serverUrl: https://pve.example.com:8006
    node: pve-node-01
    storage: local-lvm
```

**OpenStack:**

```yaml
apiVersion: lattice.dev/v1alpha1
kind: InfraProvider
metadata:
  name: openstack-prod
  namespace: lattice-system
spec:
  type: OpenStack
  credentialsSecretRef:
    name: openstack-credentials
    namespace: lattice-system
  openstack:
    authUrl: https://identity.cloud.example.com/v3
    networkId: abc123-network-id         # optional: existing network
    floatingIpPool: external             # optional: floating IP pool
```

**Docker (development):**

```yaml
apiVersion: lattice.dev/v1alpha1
kind: InfraProvider
metadata:
  name: docker-dev
  namespace: lattice-system
spec:
  type: Docker
```

The InfraProvider controller validates credentials on creation and transitions to `Ready` when valid. Check status:

```bash
kubectl get infraprovider -n lattice-system
```

### Cluster Specification

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: workload-cluster
  namespace: lattice-system
spec:
  # Reference to InfraProvider for credentials
  providerRef: aws-prod

  # Provider-specific configuration
  provider:
    kubernetes:
      version: "v1.30.2"          # Kubernetes version
      bootstrap: kubeadm          # Kubeadm or Rke2 (FIPS-native)
      certSANs:                    # Additional API server SANs
        - api.example.com
    config:
      aws:
        instanceType: m5.xlarge
        sshKeyName: my-ssh-key

  # Node topology
  nodes:
    controlPlane:
      replicas: 3                  # Must be odd for etcd quorum
      instanceType:
        name: m5.xlarge
      rootVolume:
        sizeGb: 100

    workerPools:
      general:
        replicas: 5
        instanceType:
          name: m5.2xlarge
        rootVolume:
          sizeGb: 200
        labels:
          workload-type: general
        min: 3                     # Autoscaling minimum
        max: 10                    # Autoscaling maximum

      gpu:
        replicas: 2
        instanceType:
          name: p3.8xlarge
        labels:
          workload-type: gpu
          nvidia.com/gpu.product: Tesla-V100
        taints:
          - key: nvidia.com/gpu
            effect: NoSchedule

  # Feature flags
  services: true                   # Enable LatticeService mesh support
  gpu: true                        # Enable GPU infrastructure (NFD + device plugin)

  # Monitoring (VictoriaMetrics + KEDA)
  monitoring:
    enabled: true
    ha: true                       # HA mode for VictoriaMetrics

  # Backup infrastructure (Velero)
  backups:
    enabled: true

  # Parent configuration (enables this cluster to provision children)
  parentConfig:
    grpcPort: 50051
    bootstrapPort: 8443
    proxyPort: 8081
    service:
      type: LoadBalancer

  # Registry mirrors (redirect image pulls)
  registryMirrors:
    - upstream: "docker.io"
      mirror: "mirror.internal.example.com"
    - upstream: "@infra"          # Lattice infrastructure images
      mirror: "registry.internal.example.com"
```

## Worker Pool Scaling

### Manual Scaling

Update the `replicas` field in a worker pool spec:

```bash
kubectl patch latticecluster workload-cluster -n lattice-system \
  --type merge -p '{"spec":{"nodes":{"workerPools":{"general":{"replicas":8}}}}}'
```

The cluster controller reconciles the desired replica count against the current CAPI MachineDeployment and scales up or down.

### Autoscaling

When `min` and `max` are set on a worker pool, the cluster controller enables autoscaling:

```yaml
workerPools:
  general:
    replicas: 5      # Initial count
    min: 3           # Scale-down floor
    max: 20          # Scale-up ceiling
```

The controller uses the current replica count from the MachineDeployment status and respects min/max bounds. Scaling decisions are based on resource pressure detected by KEDA.

### Pool Status

Check per-pool status including resource capacity:

```bash
kubectl get latticecluster workload-cluster -n lattice-system -o jsonpath='{.status.workerPools}' | jq
```

Each pool reports:
- `desiredReplicas` / `currentReplicas` / `readyReplicas`
- `autoscalingEnabled`
- Resource summaries: CPU, memory, GPU count, GPU type per node

## Kubernetes Version Upgrades

To upgrade the Kubernetes version, update the `provider.kubernetes.version` field:

```bash
kubectl patch latticecluster workload-cluster -n lattice-system \
  --type merge -p '{"spec":{"provider":{"kubernetes":{"version":"v1.31.0"}}}}'
```

The controller upgrades in a safe order:
- Control plane nodes first (via KubeadmControlPlane rolling update)
- Worker pools after control plane is healthy (via MachineDeployment rolling update)

Each component's upgrade status is tracked in `status.infrastructure`:

```bash
kubectl get latticecluster workload-cluster -n lattice-system -o jsonpath='{.status.infrastructure}' | jq
```

## Cluster Deletion

### Child Cluster Deletion

Delete a child cluster managed by a parent:

```bash
kubectl delete latticecluster workload-cluster -n lattice-system
```

The deletion controller:
- Sets phase to `Deleting`
- Waits for CAPI to tear down infrastructure (VMs, networks, load balancers)
- Removes the finalizer when complete

### Self-Cluster Deletion (Unpivot)

For clusters created with `lattice install`, use the CLI:

```bash
lattice uninstall -k /path/to/cluster-kubeconfig
```

This triggers an unpivot: CAPI resources are exported back to a temporary bootstrap cluster, then the infrastructure is destroyed.

For self-clusters with a parent, deletion triggers the agent to send `ClusterDeleting` messages to the parent, which re-imports the CAPI resources and handles deletion from its side.

## Bootstrap Providers

Lattice supports two Kubernetes bootstrap providers:

| Provider | Description |
|----------|-------------|
| **Kubeadm** | Standard Kubernetes bootstrap. Default choice. |
| **RKE2** | FIPS-native Kubernetes distribution from Rancher. Uses a different HAProxy configuration and supervisor API on port 9345. |

Set the bootstrap provider in the cluster spec:

```yaml
provider:
  kubernetes:
    version: "v1.30.2"
    bootstrap: rke2    # or Kubeadm
```

## Registry Mirrors

Redirect container image pulls through internal mirrors:

```yaml
registryMirrors:
  - upstream: "docker.io"
    mirror: "mirror.internal.example.com"
  - upstream: "@infra"
    mirror: "registry.internal.example.com"
    credentialsRef:
      name: mirror-credentials
      namespace: lattice-system
```

The special `@infra` upstream redirects Lattice infrastructure images (Cilium, Istio, cert-manager, etc.). Use `*` to redirect all registries.

## Monitoring Child Cluster Health

When running as a parent (Cell mode), the operator tracks child cluster health via the gRPC agent stream:

```bash
kubectl get latticecluster -n lattice-system -o jsonpath='{.items[0].status.childrenHealth}' | jq
```

Each child reports:
- Node counts (ready/total for workers and control plane)
- Agent connection state
- Last heartbeat timestamp
- Per-pool resource summaries (CPU, memory, GPU utilization)
