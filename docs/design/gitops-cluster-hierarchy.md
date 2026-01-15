# GitOps Cluster Hierarchy Design

## Overview

Lattice provides a GitOps-native approach to multi-cluster Kubernetes management. Clusters are defined declaratively in a git repository, with folder structure expressing the parent-child hierarchy. Each cluster provisions its children, creating a self-similar, recursive architecture where every cluster is both managed and a potential manager.

**Key Insight:** The hierarchical folder structure provides optimal technical properties (Flux scoping, scaling, clear relationships), while CLI/UI tooling abstracts the complexity for day-to-day operations.

### Core Principles

1. **Git is the source of truth** - Cluster definitions live in git, not a database
2. **Folder structure = hierarchy** - Parent-child relationships expressed through directories
3. **Self-managing clusters** - After pivot, each cluster owns its lifecycle
4. **Recursive provisioning** - Parents provision children, who provision grandchildren
5. **Same binary everywhere** - One Lattice binary, behavior determined by position in hierarchy
6. **Managed complexity** - CLI/UI handles folder structure, humans review PRs

### Unique Value Proposition

Unlike traditional cluster management (Rancher, OpenShift ACM):

- **No central control plane dependency** - Parent can die, children continue operating
- **Infinite hierarchy depth** - Cells can have sub-cells, not just hub-spoke
- **GitOps-native** - Git commits drive all changes, full audit trail
- **Provider-agnostic** - Same model works for AWS, OpenStack, Proxmox, bare metal
- **Flux-native** - Built on Flux, not fighting it

---

## Architecture

```
                         ┌─────────────────────┐
                         │    Git Repository   │
                         │   (Source of Truth) │
                         └──────────┬──────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
       ┌─────────────┐       ┌─────────────┐       ┌─────────────┐
       │  CLI Tool   │       │   Web UI    │       │ Direct Edit │
       │  (primary)  │       │  (future)   │       │   (PRs)     │
       └──────┬──────┘       └──────┬──────┘       └──────┬──────┘
              │                     │                     │
              └─────────────────────┼─────────────────────┘
                                    │
                            Writes to Git
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │    Git Repository   │
                         └──────────┬──────────┘
                                    │
                         Flux watches & syncs
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │    Root Cell        │
                         │  - Flux installed   │
                         │  - Lattice operator │
                         └──────────┬──────────┘
                                    │
                    Lattice provisions via CAPI
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
         ┌─────────────────────┐         ┌─────────────────────┐
         │    US Cell          │         │    EU Cell          │
         │  - Flux (own path)  │         │  - Flux (own path)  │
         │  - Lattice operator │         │  - Lattice operator │
         └──────────┬──────────┘         └──────────┬──────────┘
                    │                               │
         ┌──────────┴──────────┐                    │
         ▼                     ▼                    ▼
   ┌───────────┐         ┌───────────┐        ┌───────────┐
   │ us-prod-1 │         │ us-prod-2 │        │ eu-prod-1 │
   │  (leaf)   │         │  (leaf)   │        │  (leaf)   │
   └───────────┘         └───────────┘        └───────────┘
```

---

## Git Repository Structure

### Complete Structure

Each level requires a `kustomization.yaml` for Flux to know what to apply. The CLI generates these automatically.

```
lattice-clusters/
├── README.md
├── .lattice/                             # Lattice metadata
│   └── config.yaml                       # Repo-level config
│
├── cluster.yaml                          # Root cell definition
├── kustomization.yaml                    # What root applies
│
├── registrations/                        # Global service catalog
│   ├── kustomization.yaml
│   ├── payments.yaml
│   ├── orders.yaml
│   ├── monitoring.yaml
│   └── logging.yaml
│
└── children/
    ├── kustomization.yaml                # Lists child cluster.yamls
    │
    ├── us/
    │   ├── cluster.yaml                  # US cell (applied by root)
    │   ├── kustomization.yaml            # What US applies
    │   ├── registrations/                # US-specific services
    │   │   ├── kustomization.yaml
    │   │   └── us-compliance.yaml
    │   │
    │   └── children/
    │       ├── kustomization.yaml        # Lists child cluster.yamls
    │       │
    │       ├── us-prod-1/
    │       │   ├── cluster.yaml          # Applied by US cell
    │       │   ├── kustomization.yaml    # What us-prod-1 applies
    │       │   └── placements/
    │       │       ├── kustomization.yaml
    │       │       ├── payments.yaml
    │       │       ├── orders.yaml
    │       │       └── monitoring.yaml
    │       │
    │       ├── us-prod-2/
    │       │   ├── cluster.yaml
    │       │   ├── kustomization.yaml
    │       │   └── placements/
    │       │       ├── kustomization.yaml
    │       │       ├── payments.yaml
    │       │       └── monitoring.yaml
    │       │
    │       └── us-staging/
    │           ├── cluster.yaml
    │           ├── kustomization.yaml
    │           └── placements/
    │               ├── kustomization.yaml
    │               └── payments.yaml
    │
    └── eu/
        ├── cluster.yaml                  # EU cell (applied by root)
        ├── kustomization.yaml            # What EU applies
        ├── registrations/
        │   ├── kustomization.yaml
        │   └── gdpr-agent.yaml
        │
        └── children/
            ├── kustomization.yaml
            └── eu-prod-1/
                ├── cluster.yaml
                ├── kustomization.yaml
                └── placements/
                    ├── kustomization.yaml
                    ├── payments.yaml
                    └── gdpr-agent.yaml
```

### Kustomization Files

Each `kustomization.yaml` tells Flux what resources to apply at that level.

**Root kustomization.yaml** (root cell applies this):
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - registrations
  - children
```

**children/kustomization.yaml** (lists direct children):
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - us/cluster.yaml
  - eu/cluster.yaml
```

**children/us/kustomization.yaml** (US cell applies this):
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - registrations
  - children
```

**children/us/children/kustomization.yaml**:
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - us-prod-1/cluster.yaml
  - us-prod-2/cluster.yaml
  - us-staging/cluster.yaml
```

**children/us/children/us-prod-1/kustomization.yaml** (leaf applies this):
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - placements
```

**children/us/children/us-prod-1/placements/kustomization.yaml**:
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - payments.yaml
  - orders.yaml
  - monitoring.yaml
```

The CLI auto-generates and updates these files. Manual editing is possible but requires updating the parent's kustomization.yaml when adding resources.

### Lattice Config (.lattice/config.yaml)

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeRepoConfig
metadata:
  name: config
spec:
  # Git repository settings
  git:
    defaultBranch: main
    requirePR: true                       # Require PRs for changes

  # Flux settings (inherited by all clusters)
  flux:
    version: "2.2.0"                      # Flux version for all clusters
    interval: 1m                          # Sync interval

  # Default provider settings
  defaults:
    provider:
      kubernetes:
        version: "1.31.0"
        bootstrap: rke2
```

---

## CRD Definitions

### LatticeCluster

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: us-prod-1
  labels:
    env: prod
    region: us-west
    tier: "1"
spec:
  # Provider configuration
  provider:
    kubernetes:
      version: "1.31.0"
      bootstrap: rke2                     # kubeadm | rke2
      certSANs:
        - "us-prod-1.example.com"
    config:
      # One of: aws, openstack, proxmox, docker
      aws:
        region: us-west-2
        cpInstanceType: t3.large
        workerInstanceType: t3.xlarge
        cpRootVolumeSize: 100
        workerRootVolumeSize: 200
        sshKeyName: lattice-key

  # Node counts
  nodes:
    controlPlane: 3
    workers: 10

  # Cell configuration (omit for leaf clusters)
  cell:
    enabled: false

  # Flux configuration (optional, inherits from parent)
  flux:
    version: "2.2.0"                      # Override Flux version
    interval: 5m                          # Override sync interval
    suspend: false                        # Pause syncing

status:
  phase: Ready                            # Pending | Provisioning | Pivoting | Ready | Failed
  kubernetesVersion: "1.31.0"
  fluxVersion: "2.2.0"
  nodes:
    ready: 13
    total: 13
  lastReconciled: "2024-01-15T10:30:00Z"
```

### LatticeServiceRegistration

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeServiceRegistration
metadata:
  name: payments
spec:
  # Source repository containing service definition
  source:
    git:
      url: https://github.com/acme/payments
      path: ./deploy
      branch: main
      # Or pin to tag:
      # tag: v1.2.3

  # Default values (can be overridden by placements)
  defaults:
    replicas: 1
    resources:
      requests:
        cpu: "100m"
        memory: "128Mi"
```

### LatticeServicePlacement

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeServicePlacement
metadata:
  name: payments
spec:
  # Reference to registration (resolved from ancestors)
  serviceRef: payments

  # Override source (e.g., pin to specific version in prod)
  sourceOverride:
    tag: v2.1.0

  # Cluster-specific overrides
  overrides:
    replicas: 10
    resources:
      requests:
        cpu: "500m"
        memory: "512Mi"
      limits:
        cpu: "2"
        memory: "2Gi"
    env:
      DATABASE_URL: "postgres://prod-db.internal:5432/payments"
      LOG_LEVEL: "info"
```

---

## Flux Management

### Flux Version Control

Lattice manages Flux installation and upgrades on all clusters. This is critical for:
- Security patches
- Feature consistency
- Avoiding version drift

### Flux Installation Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     Parent Cluster                              │
│                                                                 │
│  1. Provisions child cluster via CAPI                          │
│  2. Waits for child API server ready                           │
│  3. Agent connects from child                                  │
│  4. Sends FluxInstallCommand with:                             │
│     - Flux version (from config or cluster spec)               │
│     - Git repo URL                                             │
│     - Git credentials                                          │
│     - Watch path (child's folder in git)                       │
│  5. Agent installs Flux components                             │
│  6. Agent configures GitRepository + Kustomization             │
│  7. Reports FluxReady                                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Flux Components Installed

```yaml
# Installed on every cluster by Lattice agent

# 1. Flux controllers (versioned)
flux-system/
├── source-controller          # Watches git repos
├── kustomize-controller       # Applies manifests
├── helm-controller            # (optional) Helm releases
└── notification-controller    # (optional) Alerts

# 2. GitRepository for cluster repo
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata:
  name: lattice-clusters
  namespace: flux-system
spec:
  interval: 1m
  url: https://github.com/acme/lattice-clusters
  ref:
    branch: main
  secretRef:
    name: git-credentials

# 3. Kustomization for this cluster's path
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: cluster-config
  namespace: flux-system
spec:
  interval: 10m
  sourceRef:
    kind: GitRepository
    name: lattice-clusters
  path: ./children/us/children/us-prod-1  # This cluster's path
  prune: true
  wait: true
```

### Flux Version Upgrade Flow

```
1. Platform team updates .lattice/config.yaml:
   flux:
     version: "2.3.0"  # was 2.2.0

2. Git push / PR merge

3. Each cluster's Flux syncs the config change

4. Lattice operator on each cluster:
   a. Detects flux.version changed
   b. Downloads new Flux manifests
   c. Applies updated controllers
   d. Verifies controllers healthy
   e. Updates status.fluxVersion

5. Upgrade rolls through hierarchy:
   Root → Cells → Leaves (natural Flux sync order)
```

### Per-Cluster Flux Override

```yaml
# children/us/children/us-prod-1/cluster.yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: us-prod-1
spec:
  # ... provider config ...

  flux:
    version: "2.2.0"    # Pin this cluster to older version
    interval: 30s       # Faster sync for this cluster
```

### Flux Health Monitoring

```yaml
# LatticeCluster status includes Flux health
status:
  phase: Ready
  flux:
    version: "2.2.0"
    installed: true
    healthy: true
    lastSync: "2024-01-15T10:30:00Z"
    controllers:
      source-controller: Running
      kustomize-controller: Running
      helm-controller: Running
      notification-controller: Running
```

### Agent Protocol for Flux

```protobuf
// Added to agent.proto

message FluxInstallCommand {
  string version = 1;                    // e.g., "2.2.0"
  string repo_url = 2;                   // Git repo URL
  string branch = 3;                     // Branch to watch
  string path = 4;                       // Path in repo for this cluster
  bytes git_credentials = 5;             // Git auth (deploy key or token)
  repeated string components = 6;        // Which controllers to install
  string interval = 7;                   // Sync interval (e.g., "1m")
}

message FluxUpgradeCommand {
  string version = 1;                    // Target version
  bool force = 2;                        // Force even if unhealthy
}

message FluxStatusResponse {
  string version = 1;
  bool healthy = 2;
  string last_sync = 3;
  map<string, string> controller_status = 4;
  repeated string errors = 5;
}

message AgentMessage {
  oneof payload {
    // ... existing ...
    FluxStatusResponse flux_status = 10;
  }
}

message CellCommand {
  oneof command {
    // ... existing ...
    FluxInstallCommand install_flux = 10;
    FluxUpgradeCommand upgrade_flux = 11;
  }
}
```

---

## Provisioning Flow

### Initial Bootstrap (Root Cell)

```bash
# User runs installer
lattice install \
  --git-repo https://github.com/acme/lattice-clusters \
  --git-credentials ./deploy-key \
  --provider aws \
  --region us-west-2
```

```
1. Lattice installer:
   a. Creates bootstrap kind cluster locally
   b. Installs CAPI controllers
   c. Installs Lattice operator
   d. Reads cluster.yaml from git repo root
   e. Creates LatticeCluster CRD for root

2. Root cluster provisioning:
   a. CAPI provisions AWS infrastructure
   b. Control plane comes up
   c. kubeadm/rke2 runs postKubeadmCommands
   d. Lattice agent installed, connects to bootstrap

3. Pivot:
   a. Bootstrap sends StartPivotCommand
   b. CAPI resources moved to root cluster
   c. Root now self-managing

4. Flux installation:
   a. Bootstrap sends FluxInstallCommand
   b. Agent installs Flux controllers
   c. Agent configures GitRepository (watching repo root)
   d. Agent reports FluxReady

5. Cleanup:
   a. Bootstrap cluster deleted
   b. Root cluster is now autonomous
```

### Child Cluster Provisioning

```
1. Flux on root syncs children/us/cluster.yaml
   → LatticeCluster CRD "us" created on root

2. Root Lattice operator reconciles:
   a. Detects new LatticeCluster "us"
   b. Validates spec
   c. Generates CAPI manifests
   d. Applies to root cluster
   e. Updates status: Provisioning

3. CAPI provisions infrastructure:
   a. Creates VPC, subnets (AWS)
   b. Creates control plane machines
   c. Creates worker machines

4. Bootstrap webhook:
   a. kubeadm/rke2 postKubeadmCommands calls webhook
   b. Lattice agent binary downloaded
   c. Agent installed as systemd service
   d. Agent connects to root (outbound gRPC)

5. Pivot:
   a. Root sends StartPivotCommand to agent
   b. Agent prepares local cluster
   c. Root runs clusterctl move through tunnel
   d. CAPI resources transferred
   e. Agent reports PivotComplete
   f. Status updated: Pivoting → Ready

6. Flux installation:
   a. Root sends FluxInstallCommand:
      - version: from config
      - repo_url: same repo
      - path: children/us/
   b. Agent installs Flux
   c. Agent configures GitRepository + Kustomization
   d. Reports FluxReady

7. US cell now autonomous:
   a. Owns its CAPI resources
   b. Flux watching children/us/
   c. Will see children/us/children/*/cluster.yaml
   d. Will provision its children
```

### Sequence Diagram

```
     Git              Root Cell           US Cell            us-prod-1
      │                   │                  │                   │
      │   Push us/        │                  │                   │
      │   cluster.yaml    │                  │                   │
      │                   │                  │                   │
      │   Flux sync       │                  │                   │
      │──────────────────▶│                  │                   │
      │                   │                  │                   │
      │              LatticeCluster          │                   │
      │              CRD created             │                   │
      │                   │                  │                   │
      │              Provision via           │                   │
      │              CAPI                    │                   │
      │                   │─────────────────▶│                   │
      │                   │                  │                   │
      │                   │   Agent connects │                   │
      │                   │◀─────────────────│                   │
      │                   │                  │                   │
      │                   │   Pivot CAPI     │                   │
      │                   │─────────────────▶│                   │
      │                   │                  │                   │
      │                   │   Install Flux   │                   │
      │                   │─────────────────▶│                   │
      │                   │                  │                   │
      │                   │   FluxReady      │                   │
      │                   │◀─────────────────│                   │
      │                   │                  │                   │
      │                Flux sync             │                   │
      │─────────────────────────────────────▶│                   │
      │                   │                  │                   │
      │                   │             LatticeCluster           │
      │                   │             us-prod-1 created        │
      │                   │                  │                   │
      │                   │             Provision via CAPI       │
      │                   │                  │──────────────────▶│
      │                   │                  │                   │
      │                   │                  │  Agent connects   │
      │                   │                  │◀──────────────────│
      │                   │                  │                   │
      │                   │                  │  Pivot + Flux     │
      │                   │                  │──────────────────▶│
      │                   │                  │                   │
```

---

## CLI Tool

The CLI is a simple YAML generator and validator. It works on a local git checkout — git operations (pull, commit, push) are handled by the developer using standard git commands.

### Installation

```bash
# Install CLI
curl -sSL https://lattice.dev/install.sh | sh

# Or via cargo
cargo install lattice-cli
```

### Workflow

```bash
# 1. Clone the repo (standard git)
git clone https://github.com/acme/lattice-clusters
cd lattice-clusters

# 2. Use CLI to generate/edit files
lattice cluster create us-prod-3 --parent us --provider aws ...

# 3. Review changes (standard git)
git status
git diff

# 4. Commit and push (standard git)
git add .
git commit -m "Add us-prod-3 cluster"
git push

# Or create PR
gh pr create --title "Add us-prod-3 cluster"
```

### Cluster Commands

```bash
# List all clusters (reads from local files)
lattice cluster list
NAME         PARENT   PROVIDER   K8S      WORKERS
root         -        aws        1.31.0   2
us           root     aws        1.31.0   2
us-prod-1    us       aws        1.31.0   10
us-prod-2    us       aws        1.31.0   8
eu           root     aws        1.31.0   2
eu-prod-1    eu       aws        1.31.0   5

# Show hierarchy
lattice cluster tree
root
├── us
│   ├── us-prod-1
│   ├── us-prod-2
│   └── us-staging
└── eu
    └── eu-prod-1

# Create cluster (generates files, updates kustomization.yaml)
lattice cluster create us-prod-3 \
  --parent us \
  --provider aws \
  --region us-west-2 \
  --control-plane-nodes 3 \
  --worker-nodes 10 \
  --instance-type t3.xlarge \
  --k8s-version 1.31.0

# Output:
# Created children/us/children/us-prod-3/cluster.yaml
# Created children/us/children/us-prod-3/kustomization.yaml
# Created children/us/children/us-prod-3/placements/kustomization.yaml
# Updated children/us/children/kustomization.yaml

# Scale cluster (edits existing file)
lattice cluster scale us-prod-1 --workers 20
# Output: Updated children/us/children/us-prod-1/cluster.yaml

# Upgrade kubernetes version
lattice cluster upgrade us-prod-1 --k8s-version 1.32.0

# Delete cluster (removes files, updates kustomization.yaml)
lattice cluster delete us-prod-3
# Output:
# Removed children/us/children/us-prod-3/
# Updated children/us/children/kustomization.yaml

# Show cluster details
lattice cluster get us-prod-1
Name:         us-prod-1
Parent:       us
Provider:     aws (us-west-2)
K8s Version:  1.31.0
Nodes:
  Control Plane: 3
  Workers:       10
Path:         children/us/children/us-prod-1/cluster.yaml
```

### Service Commands

```bash
# List registrations
lattice service list
NAME         SOURCE                              PATH
payments     github.com/acme/payments            ./deploy
orders       github.com/acme/orders              ./deploy
monitoring   github.com/platform/monitoring      ./charts

# Register a service
lattice service register payments \
  --git-url https://github.com/acme/payments \
  --git-path ./deploy \
  --branch main \
  --default-replicas 1

# Output:
# Created registrations/payments.yaml
# Updated registrations/kustomization.yaml

# List placements for a cluster
lattice placement list --cluster us-prod-1
SERVICE      REF        TAG/BRANCH   REPLICAS
payments     payments   v2.1.0       10
orders       orders     main         5
monitoring   monitoring v1.0.0       1

# Create placement
lattice placement create payments \
  --cluster us-prod-1 \
  --tag v2.1.0 \
  --replicas 10 \
  --env DATABASE_URL=postgres://prod:5432/payments

# Output:
# Created children/us/children/us-prod-1/placements/payments.yaml
# Updated children/us/children/us-prod-1/placements/kustomization.yaml

# Scale placement
lattice placement scale payments --cluster us-prod-1 --replicas 20

# Remove placement
lattice placement delete payments --cluster us-prod-1
```

### Flux Commands

```bash
# Set global Flux version
lattice flux set-version 2.3.0
# Output: Updated .lattice/config.yaml

# Override Flux version for specific cluster
lattice flux set-version 2.2.0 --cluster us-prod-1
# Output: Updated children/us/children/us-prod-1/cluster.yaml

# Suspend Flux on cluster
lattice flux suspend us-prod-1
# Output: Updated children/us/children/us-prod-1/cluster.yaml (flux.suspend: true)

# Resume Flux
lattice flux resume us-prod-1
```

### Validation

```bash
# Validate entire repo
lattice validate
✓ cluster.yaml valid
✓ children/us/cluster.yaml valid
✓ children/us/children/us-prod-1/cluster.yaml valid
✓ registrations/payments.yaml valid
✓ All placements reference valid registrations
✓ No circular parent references
✓ All kustomization.yaml files are consistent

# Validate specific file
lattice validate children/us/children/us-prod-1/cluster.yaml
✓ Schema valid
✓ Parent 'us' exists
✓ Provider config valid
✓ K8s version supported

# Use as pre-commit hook
# .git/hooks/pre-commit
#!/bin/sh
lattice validate
```

### Typical Developer Workflow

```bash
# Morning: sync with remote
git pull

# Add a new cluster
lattice cluster create us-prod-3 --parent us --provider aws --workers 5

# Deploy a service to it
lattice placement create payments --cluster us-prod-3 --replicas 3

# Validate before committing
lattice validate

# Commit and push
git add .
git commit -m "Add us-prod-3 with payments service"
git push

# Or create PR for review
gh pr create --title "Add us-prod-3 with payments service"
```

---

## Future: Web UI

A web UI may be added later to provide visibility and simplified operations. The UI would:

- Read cluster hierarchy from git
- Show real-time status from agent connections
- Provide forms for common operations (create cluster, deploy service)
- Write changes back to git (commit + push or create PR)

The UI is optional — all operations are available via CLI and direct git.

---

## Security

### Git Repository Access

```yaml
# Recommended: Deploy keys per environment
# Root cell has read/write key
# Child clusters have read-only keys (they don't write to git)

# .lattice/config.yaml
spec:
  git:
    # For private repos
    credentialsSecret: git-credentials
    # Secret contains:
    # - ssh-privatekey: deploy key
    # - or token: GitHub PAT
```

### Credential Flow

```
1. Platform team creates deploy key for git repo
2. lattice install stores key as Secret on root
3. Root passes read-only key to children during Flux setup
4. Children can sync from git but not write

Write operations only through:
- CLI (with user's git credentials)
- UI (with user's git credentials or service account)
```

### Network Security

- Agents only connect outbound to parent
- No inbound connections to child clusters
- mTLS on all gRPC connections
- Parent issues certificates to children

### RBAC

```yaml
# Lattice operator ServiceAccount needs:
# - cluster-admin on its own cluster (for CAPI)
# - Ability to create Flux resources
# - Secret access for git credentials

# UI needs:
# - Read access to git repo
# - Write access to git repo (for changes)
# - Agent connection for live status
```

---

## Implementation Phases

### Phase 1: Core Infrastructure
- [ ] Update LatticeCluster CRD with `cell` and `flux` fields
- [ ] Add FluxInstallCommand to agent protocol
- [ ] Implement Flux installation in agent
- [ ] Implement Flux version management
- [ ] Test single-level hierarchy (root → leaf)

### Phase 2: Recursive Provisioning
- [ ] Controller watches LatticeCluster CRDs from Flux
- [ ] Cells provision children automatically
- [ ] Children install Flux with correct path
- [ ] Test 3-level hierarchy (root → cell → leaf)

### Phase 3: Service Placement
- [ ] Implement LatticeServiceRegistration CRD
- [ ] Implement LatticeServicePlacement CRD
- [ ] Registration resolution (walk up hierarchy)
- [ ] Generate Flux GitRepository + Kustomization

### Phase 4: CLI Tool
- [ ] `lattice cluster list/tree/get` - Read cluster info from local files
- [ ] `lattice cluster create` - Generate cluster.yaml + kustomization files
- [ ] `lattice cluster scale/upgrade/delete` - Edit/remove cluster files
- [ ] `lattice service register` - Create registration files
- [ ] `lattice placement create/scale/delete` - Manage placement files
- [ ] `lattice flux set-version/suspend/resume` - Edit flux config
- [ ] `lattice validate` - Validate repo structure and references
- [ ] Auto-update kustomization.yaml on create/delete

### Phase 5: Production Hardening
- [ ] Flux health monitoring and alerts
- [ ] Automatic Flux recovery
- [ ] Upgrade rollback on failure
- [ ] Multi-repo support (for large orgs)
- [ ] Audit logging

### Phase 6: Web UI (Future)
- [ ] API server for git operations
- [ ] Real-time cluster status via agent connections
- [ ] Web frontend (technology TBD)

---

## Example Workflows

### Platform Team: Add New Region

```bash
cd lattice-clusters
git pull

# Create EU cell
lattice cluster create eu \
  --parent root \
  --cell \
  --provider aws \
  --region eu-west-1

# Create first cluster in EU
lattice cluster create eu-prod-1 \
  --parent eu \
  --provider aws \
  --region eu-west-1 \
  --workers 5

# Deploy services
lattice placement create payments --cluster eu-prod-1 --replicas 5
lattice placement create monitoring --cluster eu-prod-1

# Review and commit
lattice validate
git add .
git commit -m "Add EU region with eu-prod-1 cluster"
gh pr create --title "Add EU region"
```

### App Team: Deploy to New Cluster

```bash
cd lattice-clusters
git pull

# Check available clusters
lattice cluster list

# Deploy our service
lattice placement create orders \
  --cluster us-prod-3 \
  --tag v1.5.0 \
  --replicas 3

# Commit and push
git add .
git commit -m "Deploy orders v1.5.0 to us-prod-3"
git push
```

### Platform Team: Upgrade Flux Everywhere

```bash
cd lattice-clusters
git pull

# Upgrade globally
lattice flux set-version 2.3.0

# Commit and push (will roll out to all clusters)
git add .
git commit -m "Upgrade Flux to 2.3.0"
gh pr create --title "Upgrade Flux to 2.3.0"
```

### Emergency: Pause Cluster Syncing

```bash
cd lattice-clusters

# Suspend Flux
lattice flux suspend us-prod-1

# Commit immediately
git add .
git commit -m "EMERGENCY: Suspend Flux on us-prod-1"
git push
```

---

## Summary

This design provides:

1. **GitOps-native cluster management** - All state in git, Flux syncs
2. **Hierarchical structure** - Natural Flux scoping, scales well
3. **Managed complexity** - CLI/UI abstracts folder structure
4. **Flux lifecycle management** - Version control, upgrades, monitoring
5. **Self-managing clusters** - Independence after pivot
6. **Manual escape hatch** - Direct git/PR access always available

The key insight: **hierarchical folders provide optimal technical properties, while tooling provides optimal UX**. Users get both.
