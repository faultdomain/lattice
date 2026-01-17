<p align="center">
  <img src="https://raw.githubusercontent.com/lattice-dev/lattice/main/docs/assets/lattice-logo.svg" alt="Lattice Logo" width="400">
</p>

<h1 align="center">Lattice</h1>

<p align="center">
  <strong>Service Graphs for Kubernetes</strong>
</p>

<p align="center">
  <em>Define service dependencies declaratively. Get zero-trust networking automatically.</em>
</p>

<p align="center">
  <a href="https://github.com/lattice-dev/lattice/actions"><img src="https://img.shields.io/github/actions/workflow/status/lattice-dev/lattice/ci.yml?branch=main&style=for-the-badge&logo=github&label=Build" alt="Build Status"></a>
  <a href="https://codecov.io/gh/lattice-dev/lattice"><img src="https://img.shields.io/codecov/c/github/lattice-dev/lattice?style=for-the-badge&logo=codecov&label=Coverage" alt="Coverage"></a>
  <a href="https://github.com/lattice-dev/lattice/releases"><img src="https://img.shields.io/github/v/release/lattice-dev/lattice?style=for-the-badge&logo=semantic-release&label=Release" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Source_Available-red?style=for-the-badge" alt="License"></a>
</p>

<p align="center">
  <a href="https://kubernetes.io"><img src="https://img.shields.io/badge/Kubernetes-1.32+-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white" alt="Kubernetes"></a>
  <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/Rust-2021-DEA584?style=for-the-badge&logo=rust&logoColor=white" alt="Rust"></a>
  <a href="https://cilium.io"><img src="https://img.shields.io/badge/Cilium-Powered-F8C517?style=for-the-badge&logo=cilium&logoColor=black" alt="Cilium"></a>
  <a href="#fips-compliance"><img src="https://img.shields.io/badge/FIPS_140--3-Validated-00843D?style=for-the-badge&logo=nist&logoColor=white" alt="FIPS"></a>
</p>

---

## What is Lattice?

Lattice is a **service graph** platform. You declare which services talk to each other, and Lattice generates the network policies to enforce it.

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: api-gateway
spec:
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

This generates:
- **Cilium NetworkPolicy** (L4 eBPF enforcement)
- **Istio AuthorizationPolicy** (L7 mTLS identity)

Traffic only flows when **both sides agree**. No YAML gymnastics. No drift between intent and enforcement.

---

## Why Lattice?

### The Problem with Network Policies

Writing Kubernetes NetworkPolicies is error-prone:
- Policies are one-sided (callee defines who can connect)
- No validation that the caller actually needs access
- Easy to over-permission with broad selectors
- Policies drift from actual service dependencies

### Bilateral Agreements

Lattice requires **both sides** to declare the relationship:

```
api-gateway                          auth-service
    │                                     │
    │  resources:                         │  resources:
    │    auth:                            │    api-gateway-caller:
    │      direction: outbound ──────────────  direction: inbound
    │      id: auth-service               │      id: api-gateway
    │                                     │
```

If either side doesn't declare it, traffic is blocked. This catches:
- Stale permissions (service removed but policy remains)
- Unauthorized access attempts
- Configuration drift

### Defense in Depth

Lattice enforces at two layers:

| Layer | Technology | Enforcement |
|-------|------------|-------------|
| L7 | Istio | mTLS identity (SPIFFE principals) |
| L4 | Cilium | eBPF kernel-level filtering |

Both layers must allow traffic. Compromise of one doesn't bypass the other.

---

## Service Definition

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: payment-service
spec:
  containers:
    app:
      image: myorg/payment:v2.0.0
      variables:
        STRIPE_KEY: "${resources.stripe.api_key}"

  resources:
    # Outbound: I call these
    stripe:
      type: external_service
      direction: outbound
      id: stripe-api

    db:
      type: postgres
      class: production

    # Inbound: These call me
    order-service-caller:
      type: service
      direction: inbound
      id: order-service

  service:
    ports:
      grpc:
        port: 9090
```

The `resources` block is the service graph. Lattice compiles it to network policies automatically.

---

## External Services

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
    - billing-service
```

Only `payment-service` and `billing-service` can reach Stripe. Everything else is blocked.

---

## Self-Managing Clusters

Lattice provisions Kubernetes clusters that **own their own lifecycle**. Each cluster receives its CAPI (Cluster API) resources through a pivot process, eliminating dependency on a central management plane.

```
1. PROVISION           2. PIVOT              3. SELF-MANAGE

┌──────────┐          ┌──────────┐          ┌──────────┐
│  Parent  │ ──CAPI──>│ Workload │ <─CAPI──>│ Workload │
│  Cluster │          │ Cluster  │          │ Cluster  │
└──────────┘          └──────────┘          └──────────┘
      │                     │                     │
 Holds CAPI state      Receives CAPI         Owns its own
 temporarily           resources             lifecycle
```

After pivot:
- Clusters scale, upgrade, and heal independently
- Parent can be deleted without affecting children
- Works in air-gapped environments

### Outbound-Only Networking

Workload clusters never accept inbound connections. All communication is outbound via gRPC streams. No firewall rules, no VPNs, no attack surface.

---

## Quick Start

```bash
# Build
cargo build --release

# Bootstrap a cluster
lattice install --config cluster.yaml
```

### Cluster Configuration

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: production
spec:
  provider:
    kubernetes:
      version: "1.32.0"
      bootstrap: kubeadm
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

---

## Providers

| Provider | Status | Notes |
|----------|--------|-------|
| Docker | Stable | Local development |
| Proxmox | Stable | On-premises with kube-vip HA |
| AWS | Stable | Self-managed clusters |
| OpenStack | Stable | Private cloud |

---

## CLI

```bash
# Services
lattice service register api --git-url https://github.com/myorg/api
lattice service list

# Placements
lattice placement create api --cluster production --replicas 3
lattice placement scale api --cluster production --replicas 10

# Clusters
lattice cluster list
lattice cluster scale production --workers 20
```

---

## FIPS 140-3 Compliance

All cryptography uses FIPS-validated implementations via AWS-LC:

- TLS: rustls with aws-lc-rs
- Hashing: SHA-256/384/512 only
- Signatures: ECDSA P-256/P-384, RSA 2048+

Use RKE2 bootstrap for full FIPS compliance:

```yaml
spec:
  provider:
    kubernetes:
      bootstrap: rke2
```

---

## Development

```bash
cargo build           # Build
cargo test            # Unit tests
cargo clippy          # Lint
./scripts/e2e-test.sh # E2E tests
```

---

## License

Source Available - All Rights Reserved. See [LICENSE](LICENSE) for details.

