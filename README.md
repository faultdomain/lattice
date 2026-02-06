<p align="center">
  <img src="docs/lattice.svg" alt="Lattice" width="720"/>
</p>

<h3 align="center">Multi-cluster Kubernetes management with zero-trust networking</h3>

<p align="center">
  Lattice provisions fully self-managing Kubernetes clusters and enforces bilateral service agreements across your fleet.
</p>

---

## What is Lattice?

Lattice is a Kubernetes operator and CLI that solves two problems at once:

**1. Clusters that survive their parent.** Traditional management clusters are a single point of failure. Lattice pivots CAPI resources into each workload cluster after provisioning so every cluster owns its own lifecycle. Delete the parent — child clusters keep running, scaling, and healing.

**2. Networking that requires mutual consent.** Default-allow network policies are a liability. Lattice enforces bilateral service agreements: traffic only flows when both the caller and callee explicitly declare the dependency. Remove either side and traffic stops immediately. No forgotten allow rules.

## Key Features

- **Self-managing clusters** — CAPI resources pivot into the workload cluster. Scale, upgrade, and heal independently of any parent.
- **Outbound-only architecture** — Child clusters never accept inbound connections. All communication is outbound gRPC to the parent. Zero attack surface.
- **Bilateral service mesh** — Mutual dependency declarations compile to CiliumNetworkPolicy (L4 eBPF) and Istio AuthorizationPolicy (L7 mTLS).
- **Multi-provider** — Docker, Proxmox, AWS, OpenStack. Same workflow everywhere.
- **FIPS 140-2 cryptography** — All TLS and signing uses AWS-LC via rustls. RKE2 bootstrap available for FIPS Kubernetes.
- **CLI-first workflow** — Install, inspect, and manage entire cluster hierarchies from the terminal.

## Quick Start

```bash
# Provision a self-managing cluster
lattice install -f cluster.yaml
```

That's it. Lattice creates a temporary bootstrap cluster, provisions your infrastructure via CAPI, pivots the resources in, and tears down the bootstrap. Your cluster is fully self-managing.

## Manage Your Fleet

```bash
$ lattice get clusters

NAME       PHASE   PROVIDER  K8S     CP   WORKERS  ROLE    AGE
mgmt       Ready   aws       1.32.0  3/3  10/10    parent  45d
prod       Ready   aws       1.32.0  3/3  20/20    parent  30d
staging    Ready   proxmox   1.32.0  1/1  5/5      parent  15d
edge       Ready   docker    1.32.0  1/1  2/2      leaf    7d
```

```bash
$ lattice get hierarchy

Cluster Hierarchy:

mgmt  [Ready] (parent)
├── prod  [Ready] (parent)
│   ├── us-east  [Ready]
│   └── us-west  [Ready]
├── edge  [Ready]
└── staging  [Ready] (parent)
    ├── dev-1  [Ready]
    └── dev-2  [Ready]
```

```bash
$ lattice get services

NAMESPACE   NAME          PHASE  INBOUND  OUTBOUND  AGE
default     api-gateway   Ready  1        2         30d
default     auth-service  Ready  1        1         30d
payments    stripe-proxy  Ready  0        1         15d
```

> All `get` commands support `-o table` (default) and `-o json`.

## Cluster Definition

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: production
spec:
  providerRef: aws-prod
  provider:
    kubernetes:
      version: "1.32.0"
      bootstrap: kubeadm         # or rke2 for FIPS
    config:
      aws:
        region: us-west-2
        cpInstanceType: m5.xlarge
        workerInstanceType: m5.large
        sshKeyName: lattice-key
  nodes:
    controlPlane: 3
    workerPools:
      general:
        replicas: 10
      gpu:
        replicas: 2
        nodeClass: p3.2xlarge
        min: 1                   # Cluster autoscaler
        max: 8
  parentConfig:                  # Enables this cluster to provision children
    service:
      type: LoadBalancer
```

### Supported Providers

| Provider | Infrastructure | Use Case |
|----------|---------------|----------|
| **Docker** | CAPD / kind | Local development and CI |
| **Proxmox** | CAPMOX + kube-vip | On-premises bare metal |
| **AWS** | CAPA + NLB | Public cloud |
| **OpenStack** | CAPO | Private cloud |

## Service Networking

Services declare their dependencies. Lattice compiles them into enforced network policy.

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: api-gateway
spec:
  containers:
    main:
      image: myorg/api:v1.2.3
  service:
    ports:
      http:
        port: 8080
  resources:
    auth-service:
      type: service
      direction: outbound        # "I call auth-service"
    web-frontend:
      type: service
      direction: inbound         # "web-frontend can call me"
```

Both sides must agree. If `auth-service` doesn't declare `api-gateway` as an allowed caller, the connection is denied at L4 **and** L7.

### External Services

Control egress to third-party APIs:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeExternalService
metadata:
  name: stripe-api
spec:
  endpoints:
    api: "https://api.stripe.com:443"
  allowed_requesters:
    - payment-service
```

## How It Works

### Pivot Architecture

```
1. lattice install creates a temporary kind bootstrap cluster
2. CAPI provisions the target infrastructure
3. Nodes call back to the parent's bootstrap webhook
4. Lattice agent installed, establishes outbound gRPC stream
5. CAPI resources pivot into the new cluster via clusterctl move
6. Bootstrap cluster deleted — target is now self-managing
```

After pivot, the cluster owns its CAPI resources and operates independently. The parent can be deleted without affecting any child cluster.

### Architecture Overview

```
                    ┌──────────────────────────────────────┐
                    │          Lattice Operator             │
                    ├──────────────────────────────────────┤
                    │  ClusterController   CAPI lifecycle   │
                    │  ServiceController   Policy compiler  │
                    │  AgentServer         gRPC streams     │
                    │  BootstrapWebhook    Node bootstrap   │
                    │  K8s API Proxy       Child visibility │
                    └──────────┬───────────────┬───────────┘
                               │               │
                       ┌───────▼───┐    ┌──────▼──────┐
                       │  Cilium   │    │Istio Ambient│
                       │  L4 eBPF  │    │  L7 mTLS    │
                       └───────────┘    └─────────────┘
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `lattice install -f <file>` | Provision a self-managing cluster |
| `lattice uninstall -k <kubeconfig>` | Reverse pivot and tear down a cluster |
| `lattice get clusters` | List all clusters across kubeconfig contexts |
| `lattice get cluster <name>` | Detailed view of a single cluster |
| `lattice get services [-n <ns>]` | List LatticeService resources |
| `lattice get hierarchy` | ASCII tree of the cluster hierarchy |
| `lattice token` | ServiceAccount token (exec credential plugin) |

## Development

```bash
cargo build              # Build all crates
cargo test               # Unit tests
cargo clippy             # Lint
cargo fmt -- --check     # Format check

# E2E tests (requires Docker)
cargo test --features provider-e2e --test e2e
```

### Project Structure

```
crates/
├── lattice-cli/        CLI (install, uninstall, get)
├── lattice-operator/   Kubernetes operator and controllers
├── lattice-common/     Shared CRDs and utilities
├── lattice-service/    Service policy compilation
├── lattice-cluster/    Cluster provisioning
├── lattice-agent/      Child cluster agent
├── lattice-cell/       Parent cluster cell server
└── lattice-proto/      gRPC protocol definitions
```

## License

See [LICENSE](LICENSE).
