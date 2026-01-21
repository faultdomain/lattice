# Lattice

A Kubernetes operator for multi-cluster management with service mesh integration.

## What It Does

Lattice manages two things:

1. **Clusters** - Provisions Kubernetes clusters via Cluster API (CAPI) and makes them self-managing through a pivot process
2. **Services** - Compiles service dependency declarations into Cilium and Istio network policies

## Cluster Management

Lattice provisions clusters that own their own lifecycle. After provisioning, CAPI resources are pivoted into the cluster itself, so it can scale, upgrade, and heal without depending on a parent.

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

Workload clusters communicate with their parent via outbound gRPC streams only. No inbound connections required.

### Supported Providers

| Provider | Notes |
|----------|-------|
| Docker | Local development via CAPD |
| Proxmox | On-premises with kube-vip HA |
| AWS | Via CAPA |
| OpenStack | Via CAPO |

### Cluster Definition

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: production
spec:
  provider:
    kubernetes:
      version: "1.32.0"
      bootstrap: kubeadm  # or rke2
    config:
      proxmox:
        template_id: 9000
        cp_cores: 4
        cp_memory_mib: 8192
        worker_cores: 8
        worker_memory_mib: 32768
  nodes:
    controlPlane: 3
    workers: 10
```

## Service Graph

Services declare their dependencies and allowed callers. Lattice compiles these into network policies.

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: api-gateway
spec:
  environment: production
  containers:
    api:
      image: myorg/api:v1.2.3
  resources:
    # I call auth-service
    auth:
      type: service
      direction: outbound
      id: auth-service
    # frontend calls me
    frontend-caller:
      type: service
      direction: inbound
      id: frontend
```

Traffic only flows when **both sides agree**:
- Caller declares `direction: outbound`
- Callee declares `direction: inbound`

This generates:
- **CiliumNetworkPolicy** - L4 eBPF enforcement
- **Istio AuthorizationPolicy** - L7 mTLS identity enforcement

### External Services

Control egress to external APIs:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeExternalService
metadata:
  name: stripe-api
spec:
  environment: production
  endpoints:
    api: "https://api.stripe.com:443"
  allowed_requesters:
    - payment-service
```

## Installation

Prerequisites:
- Docker
- kind
- clusterctl

```bash
cargo build --release

# From a git repo containing cluster.yaml
lattice install --git-repo https://github.com/myorg/infrastructure

# Or from a local file
lattice install -f cluster.yaml
```

The installer:
1. Creates a temporary kind cluster
2. Installs CAPI providers and the Lattice operator
3. Provisions your management cluster
4. Pivots CAPI resources into it
5. Deletes the kind cluster

After installation, the management cluster is self-managing.

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

Cryptography uses FIPS-validated implementations via AWS-LC:

- TLS: rustls with aws-lc-rs backend
- Hashing: SHA-256/384/512
- Signatures: ECDSA P-256/P-384, RSA 2048+

For full FIPS compliance, use RKE2 bootstrap:

```yaml
spec:
  provider:
    kubernetes:
      bootstrap: rke2
```

## Development

```bash
cargo build
cargo test
cargo clippy
```

## Project Structure

```
crates/
├── lattice-operator/   # Kubernetes operator
├── lattice-cli/        # CLI (install command)
├── lattice-common/     # Shared CRD definitions
└── lattice-proto/      # gRPC protocol definitions
```

## Status

This is pre-release software. APIs may change.

## License

See [LICENSE](LICENSE).
