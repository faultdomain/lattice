<p align="center">
  <img src="docs/lattice.svg" alt="Lattice" width="720"/>
</p>

<h3 align="center">Self-managing Kubernetes clusters with zero-trust networking</h3>

<p align="center">
  <em>Provision entire cluster hierarchies that survive their parent, enforce bilateral service agreements, and manage your fleet from a single CLI.</em>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#cli-reference">CLI Reference</a> &bull;
  <a href="#service-networking">Service Mesh</a> &bull;
  <a href="#how-it-works">Architecture</a> &bull;
  <a href="#development">Development</a>
</p>

---

## The Problem

You have 50 Kubernetes clusters. Your management cluster goes down. **Everything goes down.**

Traditional multi-cluster tools create a single point of failure. They also ship with default-allow network policies — every service can talk to every other service until someone writes a deny rule. That's backwards.

## The Lattice Approach

**Clusters that own themselves.** Lattice pivots CAPI resources *into* each workload cluster after provisioning. Every cluster manages its own lifecycle — scaling, upgrades, node replacement — independently. Delete the parent. Child clusters don't notice.

**Networking that requires mutual consent.** Traffic only flows when *both* the caller and callee explicitly declare the dependency. Remove either side and traffic stops immediately. No forgotten allow rules, no audit surprises.

## Key Features

| | Feature | Description |
|---|---|---|
| **&nearr;** | **Self-managing clusters** | CAPI resources pivot into each cluster. Scale, upgrade, and self-heal with zero dependency on any parent. |
| **&orarr;** | **Outbound-only architecture** | Child clusters never accept inbound connections. All communication is outbound gRPC. Zero attack surface on workload clusters. |
| **&harr;** | **Bilateral service mesh** | Dependency declarations compile to CiliumNetworkPolicy (L4 eBPF) + Istio AuthorizationPolicy (L7 mTLS). Both sides must agree. |
| **&origof;** | **Multi-provider** | Docker, Proxmox, AWS, OpenStack. Same workflow, same CLI, same CRDs everywhere. |
| **&oplus;** | **FIPS 140-2 cryptography** | All TLS and signing uses `aws-lc-rs` via `rustls`. RKE2 bootstrap available for FIPS Kubernetes distributions. |
| **>\_** | **CLI-first** | Install, inspect, and manage entire cluster hierarchies from your terminal. No dashboard required. |

---

## Quick Start

```bash
# Provision a fully self-managing cluster in one command
lattice install -f cluster.yaml
```

Lattice creates a temporary bootstrap cluster, provisions your infrastructure via CAPI, pivots the resources into the new cluster, and tears down the bootstrap. Your cluster is fully self-managing from the moment the command completes.

```bash
# See what you just built
lattice get clusters

NAME       PHASE   PROVIDER  K8S     CP   WORKERS  ROLE    AGE
mgmt       Ready   aws       1.32.0  3/3  10/10    parent  45d
prod       Ready   aws       1.32.0  3/3  20/20    parent  30d
staging    Ready   proxmox   1.32.0  1/1  5/5      parent  15d
edge       Ready   docker    1.32.0  1/1  2/2      leaf    7d
```

---

## CLI Reference

### `lattice install` — Provision a Self-Managing Cluster

The flagship command. Takes a `LatticeCluster` CRD and turns it into a running, self-managing Kubernetes cluster.

**What happens under the hood:**
1. Spins up a temporary kind bootstrap cluster
2. Installs CAPI providers and the Lattice operator
3. Provisions your target infrastructure from the CRD spec
4. Waits for the cluster to become healthy
5. Pivots all CAPI resources into the new cluster via `clusterctl move`
6. Tears down the bootstrap cluster
7. Writes out a kubeconfig for immediate access

```bash
lattice install -f cluster.yaml
```

| Flag | Description | Default |
|------|-------------|---------|
| `-f, --file <PATH>` | Path to LatticeCluster YAML file | **(required)** |
| `--image <IMAGE>` | Lattice container image | `ghcr.io/evan-hines-js/lattice:latest` |
| `--registry-credentials-file <PATH>` | Docker config JSON for private registries | — |
| `--bootstrap <PROVIDER>` | Kubernetes bootstrap provider: `kubeadm` or `rke2` | From CRD spec |
| `--kubeconfig-out <PATH>` | Write the resulting kubeconfig to this path | — |
| `--dry-run` | Show what would be done without making changes | `false` |
| `--keep-bootstrap-on-failure` | Keep the kind cluster on failure for debugging | `false` |
| `--run-id <ID>` | Unique run ID for this session (auto-generated if omitted) | Auto |

**Environment variables:** `LATTICE_IMAGE`, `REGISTRY_CREDENTIALS_FILE`, `LATTICE_RUN_ID`

**Examples:**

```bash
# Production cluster on AWS with RKE2 (FIPS-compliant)
lattice install -f prod-cluster.yaml --bootstrap rke2

# Dry run to validate before provisioning
lattice install -f cluster.yaml --dry-run

# Save kubeconfig for immediate use
lattice install -f cluster.yaml --kubeconfig-out ~/.kube/prod.yaml

# Debug a failed installation
lattice install -f cluster.yaml --keep-bootstrap-on-failure
```

---

### `lattice uninstall` — Tear Down a Cluster

Safely reverse-pivots CAPI resources out of a self-managing cluster and deletes the infrastructure. The inverse of `install`.

**What happens under the hood:**
1. Creates a temporary kind cluster
2. Installs matching CAPI providers
3. Removes the LatticeCluster CRD (prevents operator from recreating resources)
4. Reverse-pivots CAPI resources from the target into kind
5. Deletes the Cluster resource (CAPI tears down infrastructure)
6. Waits for infrastructure deletion to complete
7. Deletes the kind cluster

```bash
lattice uninstall -k /path/to/kubeconfig
```

| Flag | Description | Default |
|------|-------------|---------|
| `-k, --kubeconfig <PATH>` | Kubeconfig of the cluster to destroy | **(required)** |
| `-n, --name <NAME>` | Cluster name (if different from kubeconfig context) | From context |
| `-y, --yes` | Skip the confirmation prompt | `false` |
| `--keep-bootstrap-on-failure` | Keep the kind cluster on failure for debugging | `false` |
| `--run-id <ID>` | Unique run ID for this session | Auto |

**Examples:**

```bash
# Tear down with confirmation prompt
lattice uninstall -k ~/.kube/staging.yaml

# Non-interactive teardown (CI/CD pipelines)
lattice uninstall -k ~/.kube/staging.yaml -y

# Specify cluster name explicitly
lattice uninstall -k ~/.kube/config -n production
```

---

### `lattice get clusters` — List Your Fleet

Displays every Lattice cluster discovered across all kubeconfig contexts in a single unified view. See the health of your entire fleet at a glance.

```bash
$ lattice get clusters

NAME       PHASE   PROVIDER  K8S     CP   WORKERS  ROLE    AGE
mgmt       Ready   aws       1.32.0  3/3  10/10    parent  45d
prod       Ready   aws       1.32.0  3/3  20/20    parent  30d
staging    Ready   proxmox   1.32.0  1/1  5/5      parent  15d
edge       Ready   docker    1.32.0  1/1  2/2      leaf    7d
```

| Column | Meaning |
|--------|---------|
| **PHASE** | Cluster lifecycle phase: `Pending`, `Provisioning`, `Pivoting`, `Ready`, `Failed` |
| **CP** | Control plane nodes: ready / total |
| **WORKERS** | Worker nodes: ready / total |
| **ROLE** | `parent` (can provision children) or `leaf` (no children) |

| Flag | Description | Default |
|------|-------------|---------|
| `--kubeconfig <PATH>` | Path to kubeconfig file | `$KUBECONFIG` or `~/.kube/config` |
| `-o, --output <FORMAT>` | Output format: `table` or `json` | `table` |

```bash
# JSON output for scripting
lattice get clusters -o json | jq '.[].name'
```

---

### `lattice get cluster <name>` — Deep Dive on a Single Cluster

Comprehensive detail view of one cluster: node status, worker pools, autoscaler config, conditions, parent-child relationships, and more.

```bash
$ lattice get cluster prod

Name:           prod
Phase:          Ready
Provider:       aws
K8s Version:    1.32.0
Role:           parent
Control Plane:  3/3
Workers:        20/20
Endpoint:       https://prod-nlb.us-west-2.elb.amazonaws.com:6443
Pivot:          complete
Bootstrap:      complete
Age:            30d
Context:        prod-admin@prod
Children:       us-east, us-west

Worker Pools:
  general       15/15
  gpu           5/5  (autoscaling: min=2, max=10)

Conditions:
  Ready                True    ClusterReady         All components healthy
  ControlPlaneReady    True    ControlPlaneRunning  3/3 nodes ready
  InfrastructureReady  True    InfraReady           AWS infrastructure reconciled
```

| Flag | Description | Default |
|------|-------------|---------|
| `--kubeconfig <PATH>` | Path to kubeconfig file | `$KUBECONFIG` or `~/.kube/config` |
| `-o, --output <FORMAT>` | Output format: `table` or `json` | `table` |

```bash
# Get full cluster detail as JSON
lattice get cluster prod -o json
```

---

### `lattice get hierarchy` — Visualize Your Cluster Tree

Renders the entire parent-child cluster topology as an ASCII tree. Instantly see how your fleet is organized and which clusters are parents.

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

| Marker | Meaning |
|--------|---------|
| `[Ready]` | Cluster phase |
| `(parent)` | Can provision child clusters |
| `(disconnected)` | Agent gRPC stream is not connected |

| Flag | Description | Default |
|------|-------------|---------|
| `--kubeconfig <PATH>` | Path to kubeconfig file | `$KUBECONFIG` or `~/.kube/config` |
| `-o, --output <FORMAT>` | Output format: `table` (ASCII tree) or `json` | `table` |

---

### `lattice get services` — Inspect Service Mesh Policies

Lists all `LatticeService` resources with their declared inbound and outbound dependencies. Quickly audit which services talk to what.

```bash
$ lattice get services

NAMESPACE   NAME          PHASE  INBOUND  OUTBOUND  AGE
default     api-gateway   Ready  1        2         30d
default     auth-service  Ready  1        1         30d
payments    stripe-proxy  Ready  0        1         15d
```

| Flag | Description | Default |
|------|-------------|---------|
| `--namespace <NS>` | Filter to a specific namespace | All namespaces |
| `--kubeconfig <PATH>` | Path to kubeconfig file | `$KUBECONFIG` or `~/.kube/config` |
| `-o, --output <FORMAT>` | Output format: `table` or `json` | `table` |

```bash
# Services in the payments namespace only
lattice get services -n payments

# JSON for CI policy auditing
lattice get services -o json
```

---

### `lattice kubeconfig` — Fetch Multi-Cluster Kubeconfig

Connects to a Lattice parent cluster, discovers all accessible clusters through the proxy, and generates a multi-context kubeconfig with every cluster in the hierarchy.

```bash
lattice kubeconfig --kubeconfig ~/.kube/mgmt.yaml -o ~/.kube/fleet.yaml
```

| Flag | Description | Default |
|------|-------------|---------|
| `--kubeconfig <PATH>` | Management cluster kubeconfig (auto-discovers proxy URL) | `$KUBECONFIG` |
| `--server <URL>` | Lattice proxy URL (overrides auto-discovery) | — |
| `--token <TOKEN>` | Bearer token (overrides auto-generated SA token) | — |
| `--namespace <NS>` | ServiceAccount namespace | `lattice-system` |
| `--service-account <NAME>` | ServiceAccount name | `default` |
| `-o, --output <PATH>` | Output file path | stdout |
| `--insecure` | Skip TLS verification (development only) | `false` |

**Auto-discovery:** When given only `--kubeconfig`, Lattice reads the `LatticeCluster` CRD to find the proxy endpoint, creates a ServiceAccount token, and fetches the kubeconfig automatically. Override individual pieces with `--server` or `--token`.

```bash
# Auto-discover everything from the management cluster
lattice kubeconfig --kubeconfig ~/.kube/mgmt.yaml

# Explicit server + token (no cluster access needed)
lattice kubeconfig --server https://proxy.example.com --token eyJhbG...

# Output to file for kubectl
lattice kubeconfig --kubeconfig ~/.kube/mgmt.yaml -o ~/.kube/fleet.yaml
export KUBECONFIG=~/.kube/fleet.yaml
kubectl get pods --context us-east
```

---

### `lattice token` — ServiceAccount Token (Exec Credential Plugin)

Generates a fresh Kubernetes ServiceAccount token in `ExecCredential` format. Designed to be used as a credential plugin inside kubeconfig files so tokens auto-refresh on expiry.

```bash
lattice token --kubeconfig ~/.kube/cluster.yaml
```

| Flag | Description | Default |
|------|-------------|---------|
| `--kubeconfig <PATH>` | Kubeconfig for the cluster with the ServiceAccount | **(required)** |
| `-n, --namespace <NS>` | ServiceAccount namespace | `lattice-system` |
| `-s, --service-account <NAME>` | ServiceAccount name | `default` |
| `-d, --duration <DURATION>` | Token lifetime (`1h`, `8h`, `24h`) | `1h` |

**Kubeconfig exec plugin usage:**

```yaml
users:
- name: lattice-proxy
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: lattice
      args:
      - token
      - --kubeconfig=/path/to/cluster-kubeconfig
      - --namespace=lattice-system
      - --service-account=default
```

This gives you auto-refreshing tokens without manual rotation. `kubectl` calls `lattice token` transparently whenever credentials expire.

---

## Cluster Definition

Define your infrastructure as a `LatticeCluster` CRD:

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

---

## Service Networking

Services declare their dependencies. Lattice compiles them into enforced network policy at two layers simultaneously.

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

Both sides must agree. If `auth-service` doesn't declare `api-gateway` as an allowed caller, the connection is denied at **L4 (Cilium eBPF)** and **L7 (Istio mTLS)**.

### External Services

Control egress to third-party APIs with the same bilateral model:

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

---

## How It Works

### Pivot Architecture

```
 lattice install -f cluster.yaml
          │
          ▼
 ┌─────────────────┐
 │  1. Bootstrap    │  Temporary kind cluster
 │     Cluster      │  CAPI + Lattice operator installed
 └────────┬────────┘
          │
          ▼
 ┌─────────────────┐
 │  2. Provision    │  CAPI creates infrastructure
 │     Target       │  Nodes boot and join the cluster
 └────────┬────────┘
          │
          ▼
 ┌─────────────────┐
 │  3. Bootstrap    │  kubeadm/rke2 calls parent webhook
 │     Callback     │  Lattice agent installed on target
 └────────┬────────┘
          │
          ▼
 ┌─────────────────┐
 │  4. Agent        │  Outbound gRPC stream to parent
 │     Connect      │  mTLS authenticated, never inbound
 └────────┬────────┘
          │
          ▼
 ┌─────────────────┐
 │  5. Pivot        │  CAPI resources move into target
 │                  │  via clusterctl move
 └────────┬────────┘
          │
          ▼
 ┌─────────────────┐
 │  6. Self-        │  Bootstrap deleted
 │     Managing     │  Cluster owns its own lifecycle
 └─────────────────┘
```

After pivot, the cluster owns its CAPI resources and operates independently. The parent can be deleted without affecting any child cluster.

### Operator Components

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

### Agent-Cell Protocol

All communication between parent (Cell) and child (Agent) flows over a single outbound gRPC stream with mTLS:

| Direction | Message | Purpose |
|-----------|---------|---------|
| Agent &rarr; Cell | `AgentReady` | Agent registration after bootstrap |
| Agent &rarr; Cell | `PivotComplete` | Confirms CAPI resources imported |
| Agent &rarr; Cell | `Heartbeat` | Periodic health signal |
| Cell &rarr; Agent | `PivotCommand` | Sends CAPI resources for import |
| Cell &rarr; Agent | `KubernetesRequest` | Proxied K8s API calls (get, list, watch, create, update, delete) |

The parent can access any child's Kubernetes API through the gRPC stream — no inbound ports, no VPN, no firewall rules needed.

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
├── lattice-cli/            CLI binary (install, uninstall, get, token, kubeconfig)
├── lattice-operator/       Kubernetes operator and controllers
├── lattice-common/         Shared CRDs, types, and utilities
├── lattice-service/        Service dependency → network policy compiler
├── lattice-cluster/        Cluster provisioning and pivot coordination
├── lattice-agent/          Child cluster agent (outbound gRPC client)
├── lattice-cell/           Parent cluster cell server (gRPC + API proxy)
├── lattice-api/            Auth proxy with Cedar-based access control
├── lattice-capi/           CAPI provider resource templating
├── lattice-infra/          PKI, bootstrap manifests, FIPS crypto setup
├── lattice-cloud-provider/ Cloud account validation and resources
├── lattice-secrets-provider/ Secret provisioning for cluster setup
├── lattice-move/           clusterctl move helper for pivot operations
└── lattice-proto/          gRPC protocol definitions (protobuf)
```

---

## License

See [LICENSE](LICENSE).
