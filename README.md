# Lattice

Kubernetes multi-cluster management with zero-trust service networking.

## The Problem

Managing Kubernetes at scale has two hard problems:

1. **Cluster lifecycle** - Management clusters become single points of failure. If the parent dies, child clusters can't scale or heal.

2. **Service networking** - Default-allow policies require constant vigilance. One misconfigured service exposes your network.

## How Lattice Solves It

### Self-Managing Clusters

Lattice provisions clusters that own their own lifecycle. After provisioning, CAPI resources pivot into the workload cluster itself. The parent can be deleted - the cluster keeps running and can scale, upgrade, and heal independently.

```
Parent Cluster                    Workload Cluster
┌─────────────┐                  ┌─────────────┐
│  CAPI       │ ── provision ──> │             │
│  Resources  │                  │             │
│             │ ── pivot ──────> │  CAPI       │
│  (deleted)  │                  │  Resources  │
└─────────────┘                  └─────────────┘
                                       │
                                 self-managing
```

Child clusters connect to parents via outbound gRPC only - no inbound ports, no attack surface.

### Bilateral Service Agreements

Traffic only flows when **both sides agree**:

```yaml
# api-gateway declares: "I call auth-service"
resources:
  auth-service:
    type: service
    direction: outbound

# auth-service declares: "api-gateway can call me"
resources:
  api-gateway:
    type: service
    direction: inbound
```

If either side removes their declaration, traffic stops. This compiles to:
- **CiliumNetworkPolicy** - L4 eBPF enforcement
- **Istio AuthorizationPolicy** - L7 mTLS identity enforcement

No YAML sprawl. No forgotten allow rules. The service graph is the policy.

## Quick Start

```bash
# Build
cargo build --release

# Install a self-managing cluster
lattice install -f cluster.yaml
```

The installer creates a temporary kind cluster, provisions your cluster via CAPI, pivots the resources in, then deletes kind. Your cluster is now self-managing.

## Cluster Definition

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: production
spec:
  provider:
    kubernetes:
      version: "1.32.0"
      bootstrap: kubeadm  # or rke2 for FIPS
    config:
      proxmox:
        template_id: 9000
        cp_cores: 4
        cp_memory_mib: 8192
  nodes:
    controlPlane: 3
    workers: 10
```

### Supported Providers

| Provider | Use Case |
|----------|----------|
| Docker | Local development (CAPD) |
| Proxmox | On-premises with kube-vip HA |
| AWS | Cloud via CAPA |
| OpenStack | Private cloud via CAPO |

## Service Definition

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: api-gateway
spec:
  containers:
    main:
      image: myorg/api:v1.2.3
      resources:
        requests:
          cpu: 100m
          memory: 256Mi
  service:
    ports:
      http:
        port: 8080
  resources:
    # Outbound: I call these services
    auth-service:
      type: service
      direction: outbound
    postgres:
      type: service
      direction: outbound
    # Inbound: These services call me
    web-frontend:
      type: service
      direction: inbound
```

### External Services

Control egress to external APIs:

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

### Shared Volumes

Services can share volumes with automatic pod co-location:

```yaml
# Owner declares the volume with size
resources:
  media-storage:
    type: volume
    id: shared-media
    params:
      size: 1Ti

# Consumer references without size (gets co-located)
resources:
  media-storage:
    type: volume
    id: shared-media
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Lattice Operator                         │
├─────────────────────────────────────────────────────────────┤
│  ClusterController    - Provisions clusters via CAPI       │
│  ServiceController    - Compiles service graph to policies │
│  AgentServer          - Accepts gRPC from child clusters   │
│  BootstrapWebhook     - Handles kubeadm postKubeadmCommands│
└─────────────────────────────────────────────────────────────┘
         │                              │
         ▼                              ▼
┌─────────────────┐           ┌─────────────────┐
│  Cilium         │           │  Istio Ambient  │
│  L4 eBPF        │           │  L7 mTLS        │
└─────────────────┘           └─────────────────┘
```

## FIPS Compliance

All cryptography uses FIPS 140-2 validated implementations via AWS-LC:

- TLS: rustls with aws-lc-rs backend
- Hashing: SHA-256/384/512
- Signatures: ECDSA P-256/P-384, RSA 2048+

For full FIPS compliance, use RKE2 bootstrap which provides FIPS-validated Kubernetes components.

## Development

```bash
cargo build
cargo test
cargo clippy

# Run E2E tests (requires Docker)
cargo test --features provider-e2e --test e2e
```

## Project Structure

```
crates/
├── lattice-operator/   # Kubernetes operator (controllers, gRPC server)
├── lattice-cli/        # CLI (install, uninstall commands)
├── lattice-common/     # Shared CRD definitions
├── lattice-service/    # Service compilation (policies, workloads)
├── lattice-cluster/    # Cluster provisioning
└── lattice-proto/      # gRPC protocol definitions
```

## Status

Pre-release. APIs may change.

## License

See [LICENSE](LICENSE).
