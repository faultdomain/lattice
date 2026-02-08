<p align="center">
  <img src="docs/lattice.svg" alt="Lattice" width="720"/>
</p>

<h3 align="center">Self-managing Kubernetes clusters with zero-trust networking</h3>

<p align="center">
  <em>Fully self-managing clusters. Bilateral service mesh. Multi-provider. FIPS-ready.</em>
</p>

---

## Why Lattice

Your management cluster goes down. With traditional tools, **everything goes down**.

Lattice takes a different approach. Every cluster provisioned by Lattice becomes fully self-managing — it owns its own CAPI resources, scales its own nodes, and survives the deletion of its parent. There is no single point of failure.

Networking follows the same philosophy: default-deny everywhere, traffic only flows when **both** the caller and callee explicitly declare the dependency. No forgotten allow rules, no audit surprises.

---

## What You Get

**Self-managing clusters** — CAPI resources pivot into each cluster after provisioning. Scale, upgrade, and self-heal with zero dependency on any parent. Delete the parent; children don't notice.

**Bilateral service mesh** — Dependency declarations compile to CiliumNetworkPolicy (L4 eBPF) + Istio AuthorizationPolicy (L7 mTLS). Both sides must agree or traffic is denied.

**Outbound-only architecture** — Child clusters never accept inbound connections. All communication is outbound gRPC. Zero attack surface on workload clusters.

**Multi-provider** — Docker, Proxmox, AWS, OpenStack. Same CLI, same CRDs, same workflow everywhere.

**K8s API proxy** — Access any cluster in your hierarchy from a single kubectl context. Requests travel through existing gRPC tunnels with Cedar policy authorization. No VPN required.

**LatticeService** — One CRD replaces Deployment + Service + ScaledObject + PVC + ExternalSecret + NetworkPolicy + AuthorizationPolicy + Gateway + HTTPRoute. Score-compatible `${...}` templates resolve dependencies automatically.

**Cedar access control** — Fine-grained policies for proxy access (who can reach which clusters) and secret access (which services can use which Vault paths). Default-deny for secrets.

**FIPS 140-2 cryptography** — All TLS and signing uses `aws-lc-rs` via `rustls`. RKE2 bootstrap available for FIPS Kubernetes distributions.

---

## Quick Start

```bash
# Provision a fully self-managing cluster
lattice install -f cluster.yaml

# See your fleet
lattice get clusters

NAME       PHASE   PROVIDER  K8S     CP   WORKERS  ROLE    AGE
mgmt       Ready   aws       1.32.0  3/3  10/10    parent  45d
prod       Ready   aws       1.32.0  3/3  20/20    parent  30d
staging    Ready   proxmox   1.32.0  1/1  5/5      parent  15d

# Visualize the hierarchy
lattice get hierarchy

mgmt  [Ready] (parent)
├── prod  [Ready] (parent)
│   ├── us-east  [Ready]
│   └── us-west  [Ready]
└── staging  [Ready] (parent)
    ├── dev-1  [Ready]
    └── dev-2  [Ready]
```

---

## Infrastructure

### CloudProvider

Registers cloud credentials that clusters reference via `providerRef`. Supports two credential modes:

**Manual** — you create a Kubernetes Secret and reference it directly:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: CloudProvider
metadata:
  name: aws-prod
spec:
  type: aws
  region: us-east-1
  credentialsSecretRef:             # manual mode
    name: aws-prod-creds
  aws:
    vpcId: vpc-0abc123def456
    subnetIds: [subnet-a, subnet-b]
```

**ESO** — credentials are synced from a ClusterSecretStore via External Secrets Operator:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: CloudProvider
metadata:
  name: aws-prod
spec:
  type: aws
  region: us-east-1
  credentials:                      # ESO mode
    type: secret
    id: infrastructure/aws/prod
    params:
      provider: vault-prod
      keys: [access_key_id, secret_access_key]
  aws:
    vpcId: vpc-0abc123def456
    subnetIds: [subnet-a, subnet-b]
```

Supported providers: `aws`, `proxmox`, `openstack`, `docker`.

### SecretProvider

Wraps an ESO `ClusterSecretStore` provider configuration. The `spec.provider` field is passed through verbatim — you write native ESO provider YAML and Lattice manages the ClusterSecretStore lifecycle.

```yaml
apiVersion: lattice.dev/v1alpha1
kind: SecretProvider
metadata:
  name: vault-prod
spec:
  provider:
    vault:
      server: https://vault.example.com
      path: secret
      version: v2
      auth:
        tokenSecretRef:
          name: vault-token
          namespace: lattice-system
          key: token
```

Any ESO-supported provider works: `vault`, `aws`, `webhook`, `barbican`, etc.

### LatticeCluster

Defines a cluster's infrastructure, node topology, and lifecycle. After provisioning via Cluster API, the cluster pivots to own its own resources and becomes self-managing.

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
      bootstrap: kubeadm            # or rke2 for FIPS
    config:
      aws:
        region: us-west-2
        cpInstanceType: m5.xlarge
        workerInstanceType: m5.large
  nodes:
    controlPlane: 3
    workerPools:
      general:
        replicas: 10
      gpu:
        replicas: 2
        min: 1
        max: 8
  services: true                    # Istio ambient mesh
  monitoring: true                  # VictoriaMetrics + KEDA
  backups: true                     # Velero
  externalSecrets: true             # ESO for Vault integration
  gpu: false                        # NFD + NVIDIA device plugin
  parentConfig:                     # enables this cluster to provision children
    service:
      type: LoadBalancer
```

---

## Workloads

### LatticeService

One CRD that compiles into everything your service needs:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: api-gateway
  namespace: platform
spec:
  containers:
    main:
      image: myorg/api:v2.1.0
      variables:
        AUTH_URL: ${resources.auth-service.url}
        DB_PASS: ${resources.db-creds.password}

  service:
    ports:
      http:
        port: 8080

  resources:
    auth-service:
      type: service
      direction: outbound            # "I call auth-service"
    web-frontend:
      type: service
      direction: inbound             # "web-frontend can call me"
    db-creds:
      type: secret
      id: database/prod/creds
      params:
        provider: vault-prod
        keys: [username, password]

  replicas:
    min: 2
    max: 10
```

Generates: Deployment, Service, ScaledObject, CiliumNetworkPolicy, AuthorizationPolicy, ExternalSecret, ServiceAccount — all wired together, default-deny enforced.

### Bilateral Service Mesh

Traffic requires mutual consent:

```
 api-gateway                        auth-service
 ┌─────────────────┐                ┌─────────────────┐
 │   auth-service:  │───────────────▶│   api-gateway:   │
 │     direction:   │   ALLOWED      │     direction:   │
 │       outbound   │                │       inbound    │
 └─────────────────┘                └─────────────────┘

 api-gateway                        payment-service
 ┌─────────────────┐                ┌─────────────────┐
 │   payment-svc:   │───────X───────▶│ (no declaration) │
 │     direction:   │   DENIED       │                  │
 │       outbound   │                │                  │
 └─────────────────┘                └─────────────────┘
```

Enforced at two layers simultaneously: Cilium L4 eBPF + Istio L7 mTLS. Remove either side's declaration and traffic stops immediately.

---

## Architecture

```
 lattice install -f cluster.yaml
          │
          ▼
 ┌─────────────────┐
 │  Bootstrap       │  Temporary kind cluster (cluster-only mode)
 │  Cluster         │  CAPI + Lattice operator, no extra infra
 └────────┬────────┘
          │
          ▼
 ┌─────────────────┐
 │  Provision       │  CAPI creates infrastructure
 │  Target          │  Nodes boot and join
 └────────┬────────┘
          │
          ▼
 ┌─────────────────┐
 │  Pivot           │  CAPI resources move into target
 │                  │  via distributed move protocol
 └────────┬────────┘
          │
          ▼
 ┌─────────────────┐
 │  Self-Managing   │  Bootstrap deleted
 │                  │  Cluster owns its own lifecycle forever
 └─────────────────┘
```

After pivot, the cluster is independent. The parent can be deleted without affecting any child.

---

## CLI

| Command | Description |
|---------|-------------|
| `lattice login` | Authenticate with a Lattice cluster |
| `lattice logout` | Clear saved credentials and proxy kubeconfig |
| `lattice use <cluster>` | Switch active cluster context |
| `lattice install -f cluster.yaml` | Provision a self-managing cluster |
| `lattice uninstall -k kubeconfig` | Tear down a cluster (reverse pivot) |
| `lattice token` | ServiceAccount token (exec credential plugin) |
| `lattice get clusters` | List your fleet |
| `lattice get cluster <name>` | Detail view of one cluster |
| `lattice get hierarchy` | ASCII tree of parent-child topology |
| `lattice get health` | Fleet health with node counts and heartbeats |

---

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
├── lattice-cli/            CLI (login, logout, use, install, uninstall, get, token)
├── lattice-operator/       Kubernetes operator and controller dispatch
├── lattice-common/         Shared CRDs, types, and utilities
├── lattice-service/        Service dependency -> network policy compiler
├── lattice-cluster/        Cluster provisioning and pivot coordination
├── lattice-agent/          Child cluster agent (outbound gRPC)
├── lattice-cell/           Parent cluster cell (gRPC + bootstrap + proxy)
├── lattice-api/            Auth proxy with Cedar access control
├── lattice-cedar/          Cedar policy engine
├── lattice-capi/           CAPI provider resource templating
├── lattice-infra/          PKI, infrastructure manifests, FIPS crypto
├── lattice-backup/         Velero backup/restore controllers
├── lattice-cloud-provider/ Cloud account validation
├── lattice-secret-provider/ ESO integration
├── lattice-move/           CAPI resource move for pivot operations
└── lattice-proto/          gRPC protobuf definitions
```

---

## License

See [LICENSE](LICENSE).
