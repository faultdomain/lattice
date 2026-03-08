# Getting Started with Lattice

Lattice is a Kubernetes operator for multi-cluster lifecycle management. It provisions clusters via Cluster API (CAPI) and makes them fully self-managing through a pivoting architecture. After pivot, each cluster owns its own CAPI resources and operates independently — even if the parent cluster is deleted.

## Prerequisites

- `docker` installed and running
- The `lattice` CLI binary
- Cloud provider credentials (for AWS, Proxmox, OpenStack clusters)

You do **not** need a pre-existing Kubernetes cluster. The `lattice install` command bootstraps everything from scratch — it creates a temporary Kind cluster, provisions your real cluster (on any supported provider), pivots it to self-managing, and deletes the temporary cluster.

## Installing a Cluster

### Step 1: Write a LatticeCluster manifest

Create a file called `cluster.yaml` describing the cluster you want.

**Local development (Docker/CAPD):**

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: my-cluster
  namespace: lattice-system
spec:
  providerRef: docker-provider
  provider:
    kubernetes:
      version: "v1.30.2"
      bootstrap: kubeadm
    config:
      docker: {}
  nodes:
    controlPlane:
      replicas: 1
    workerPools:
      default:
        replicas: 2
  services: true
```

**Production (AWS):**

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: prod-cluster
  namespace: lattice-system
spec:
  providerRef: aws-provider
  provider:
    kubernetes:
      version: "v1.30.2"
      bootstrap: kubeadm
    config:
      aws:
        instanceType: m5.xlarge
        sshKeyName: my-ssh-key
  nodes:
    controlPlane:
      replicas: 3
    workerPools:
      general:
        replicas: 5
        instanceType:
          name: m5.2xlarge
      gpu:
        replicas: 2
        instanceType:
          name: p3.2xlarge
        labels:
          workload-type: gpu
        taints:
          - key: nvidia.com/gpu
            effect: NoSchedule
  services: true
  gpu: true
  monitoring:
    enabled: true
    ha: true
```

### Step 2: Run `lattice install`

```bash
lattice install -f cluster.yaml
```

This single command:

- Creates a temporary Kind bootstrap cluster
- Installs all required infrastructure (CAPI, Cilium, Istio, cert-manager, ESO, Volcano, and the Lattice operator)
- Provisions your cluster on the target infrastructure provider
- Pivots CAPI resources so the cluster is fully self-managing
- Deletes the temporary bootstrap cluster

The process works the same regardless of provider — Docker for development, AWS/Proxmox/OpenStack for production.

**CLI options:**

| Flag | Description |
|------|-------------|
| `-f, --file` | Path to LatticeCluster YAML file (required) |
| `--image` | Lattice container image (default: `ghcr.io/evan-hines-js/lattice:latest`, env: `LATTICE_IMAGE`) |
| `--registry-credentials-file` | Path to dockerconfigjson for private registry auth |
| `--bootstrap` | Override bootstrap provider (`kubeadm` or `rke2`) |
| `--validate` | Dry-run: validate config and show plan without making changes |
| `--kubeconfig-out` | Write the resulting kubeconfig to this path |
| `--keep-bootstrap-on-failure` | Don't delete the Kind cluster on failure (for debugging) |
| `--run-id` | Unique ID for parallel installs (auto-generated if omitted, env: `LATTICE_RUN_ID`) |

### Step 3: Uninstall

To tear down a cluster created with `lattice install`:

```bash
lattice uninstall -k /path/to/cluster-kubeconfig
```

This reverses the pivot (unpivot), exports CAPI resources back to a temporary bootstrap cluster, and destroys the infrastructure.

**Uninstall options:**

| Flag | Description |
|------|-------------|
| `-k, --kubeconfig` | Path to kubeconfig for the cluster to uninstall (required) |
| `-n, --name` | Cluster name (if multiple clusters exist) |
| `-y, --yes` | Skip confirmation prompt |
| `--keep-bootstrap-on-failure` | Don't delete the Kind cluster on failure (for debugging) |
| `--run-id` | Unique ID for this uninstall session (env: `LATTICE_RUN_ID`) |

The operator runs in one of three modes depending on the cluster's role:

| Mode | Detected By | Description |
|------|-------------|-------------|
| **Cluster** (Cell) | Self-referencing LatticeCluster with `parentConfig` | Parent cluster that provisions and manages children. Runs the gRPC server, bootstrap webhook, and K8s API proxy. |
| **Service** | Self-referencing LatticeCluster without `parentConfig` | Cluster that runs LatticeService/LatticeJob/LatticeModel workloads. Manages mesh policies and service compilation. |
| **Agent** | Presence of `lattice-parent-config` Secret in lattice-system | Installed on child clusters during provisioning. Establishes an outbound gRPC stream to the parent and handles pivot. |

A single cluster can run both Cluster and Service mode simultaneously.

## Creating Your First Managed Cluster

### Step 1: Configure an Infrastructure Provider

Create an `InfraProvider` that holds credentials for your cloud provider:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: InfraProvider
metadata:
  name: my-aws-provider
  namespace: lattice-system
spec:
  type: AWS
  region: us-east-1
  credentialsSecretRef:
    name: aws-credentials
    namespace: lattice-system
  aws:
    sshKeyName: my-ssh-key
```

For local development with Docker (CAPD):

```yaml
apiVersion: lattice.dev/v1alpha1
kind: InfraProvider
metadata:
  name: docker-provider
  namespace: lattice-system
spec:
  type: Docker
```

### Step 2: Create a LatticeCluster

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: my-workload-cluster
  namespace: lattice-system
spec:
  providerRef: my-aws-provider
  provider:
    kubernetes:
      version: "v1.30.2"
      bootstrap: kubeadm
    config:
      aws:
        instanceType: m5.xlarge
        sshKeyName: my-ssh-key
  nodes:
    controlPlane:
      replicas: 3
    workerPools:
      general:
        replicas: 3
        instanceType:
          name: m5.2xlarge
        labels:
          workload-type: general
      gpu:
        replicas: 2
        instanceType:
          name: p3.2xlarge
        labels:
          workload-type: gpu
        taints:
          - key: nvidia.com/gpu
            effect: NoSchedule
  services: true
  gpu: true
  monitoring:
    enabled: true
    ha: true
```

### Step 3: Watch the Cluster Progress

```bash
# Watch cluster phase transitions
kubectl get latticecluster my-workload-cluster -n lattice-system -w

# Check detailed status
kubectl describe latticecluster my-workload-cluster -n lattice-system
```

The cluster progresses through these phases:

```
Pending → Provisioning → Pivoting → Pivoted → Ready
```

Additional phases exist for error and teardown states: `Failed`, `Deleting`, `Unpivoting`.

Once `Ready`, the cluster is fully self-managing. Lattice writes a kubeconfig for the new cluster:

```bash
# Get the kubeconfig for the new cluster
kubectl get secret my-workload-cluster-kubeconfig -n lattice-system -o jsonpath='{.data.value}' | base64 -d > /tmp/my-workload-cluster.kubeconfig

# Verify access
kubectl --kubeconfig /tmp/my-workload-cluster.kubeconfig get nodes
```

### Step 4: Deploy a Service

Once the workload cluster is ready, deploy a LatticeService:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: my-api
  namespace: default
spec:
  replicas: 3
  workload:
    containers:
      main:
        image: my-registry.io/my-api:latest
        variables:
          PORT: "8080"
        resources:
          requests:
            cpu: 500m
            memory: 512Mi
          limits:
            cpu: "1"
            memory: 1Gi
    service:
      ports:
        http:
          port: 8080
```

Apply it to the workload cluster:

```bash
kubectl --kubeconfig /tmp/my-workload-cluster.kubeconfig apply -f my-api.yaml
```

## What Happens Next

With this basic setup, Lattice has:

- Provisioned cloud infrastructure via CAPI
- Bootstrapped the cluster with Cilium, Istio, and the Lattice agent
- Pivoted CAPI resources so the cluster is self-managing
- Created a default-deny network posture (Cilium L4 + Istio L7)
- Compiled your LatticeService into a Deployment, Service, and mesh policies

From here you can:

- [Add mesh networking between services](./mesh-networking.md)
- [Configure secrets from Vault or other providers](./secrets-management.md)
- [Set up GPU workloads and model serving](./gpu-workloads.md)
- [Configure backups](./backup-restore.md)
- [Set up OIDC authentication](./security.md)

## Local Development with Docker

For local development, Lattice supports Docker (CAPD) as an infrastructure provider. This creates Kind clusters managed by CAPI:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: dev-cluster
  namespace: lattice-system
spec:
  providerRef: docker-provider
  provider:
    kubernetes:
      version: "v1.30.2"
      bootstrap: kubeadm
    config:
      docker: {}
  nodes:
    controlPlane:
      replicas: 1
    workerPools:
      default:
        replicas: 2
```

The Docker provider is fully functional and runs the complete Lattice stack — it is not a mock. E2E tests use this provider exclusively.
