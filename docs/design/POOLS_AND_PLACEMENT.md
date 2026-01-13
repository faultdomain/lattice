# Pools, Clusters, and Service Placement

## Hierarchy

```
Pools (Infra Team)           →  "Here's capacity you can use"
    │
    ▼
Clusters (Platform Team)     →  "Here's how we organize it"
    │
    ▼
Services (Devs + Solver)     →  "Put my app somewhere appropriate"
```

| Layer | Owner | Defines | CRD |
|-------|-------|---------|-----|
| Pool | Infra/Cloud team | Raw capacity, credentials, budget | `CloudPool`, `StaticPool` |
| Cluster | Platform team | Topology, labels, policies | `LatticeCluster` |
| Service | Developers | App requirements | `LatticeService` |

---

## CloudPool

Pay-as-you-go cloud infrastructure. Constraint is budget.

```yaml
apiVersion: lattice.dev/v1alpha1
kind: CloudPool
metadata:
  name: aws-prod
spec:
  provider: aws

  credentialsRef:
    name: aws-creds
    namespace: lattice-system

  budget:
    monthly: 50000          # USD
    alertAt: 80             # Percent
    hardLimit: false        # Allow overage with alerts

  regions:
    us-east-1:
      enabled: true
      compliance: [SOC2, HIPAA]
      capabilities: [gpu]
    us-west-2:
      enabled: true
      compliance: [SOC2]
    eu-west-1:
      enabled: true
      compliance: [SOC2, GDPR]

status:
  spend:
    currentMonth: 32000
    projected: 48000
  conditions:
    - type: Ready
      status: "True"
    - type: BudgetWarning
      status: "False"
```

---

## StaticPool

Fixed capacity infrastructure. Constraint is capacity.

```yaml
apiVersion: lattice.dev/v1alpha1
kind: StaticPool
metadata:
  name: dc-chicago
spec:
  provider: openstack

  credentialsRef:
    name: openstack-creds
    namespace: lattice-system

  providerConfig:
    cloud: chicago-prod
    externalNetwork: ext-net

  location:
    region: us-central
    country: US
    facility: Equinix CH1

  capacity:
    cores: 2560             # 10 hypervisors × 256
    memory: 10Ti
    storage: 100Ti

  machineTypes:
    - name: small
      cores: 4
      memory: 16Gi
    - name: medium
      cores: 8
      memory: 32Gi
    - name: large
      cores: 16
      memory: 64Gi

  compliance: [SOC2, HIPAA, PCI]
  capabilities: [nvme]

status:
  used:
    cores: 800
    memory: 3.2Ti
  available:
    cores: 1760
    memory: 6.8Ti
  conditions:
    - type: Ready
      status: "True"
    - type: CapacityPressure
      status: "False"
```

---

## LatticeCluster

Platform team creates clusters on pools.

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: prod-critical
  labels:
    environment: production
    tier: critical
    compliance: hipaa
spec:
  # Which pool to provision on
  pool: dc-chicago

  kubernetes:
    version: "1.31"
    bootstrap: rke2

  controlPlane:
    replicas: 3
    machineType: medium

  workers:
    replicas: 10
    machineType: large

  # Cluster-level policies
  policies:
    maxServices: 100
    reservedCapacity: true
```

---

## LatticeService

Developers define services. Solver places them.

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: patient-api
spec:
  containers:
    main:
      image: hospital/patient-api:v2

  resources:
    patient-db:
      type: service
      direction: outbound

  requirements:
    # CEL expression against cluster labels
    placement: "cluster.labels.compliance == 'hipaa'"
```

Solver:
1. Evaluates `placement` against all clusters
2. Filters to `prod-critical` (only one with `compliance=hipaa`)
3. Places service there

---

## Example: Full OpenStack DC Setup

```yaml
# Infra team provides the pool
apiVersion: lattice.dev/v1alpha1
kind: StaticPool
metadata:
  name: dc-chicago
spec:
  provider: openstack
  credentialsRef: {name: openstack-creds}
  providerConfig: {cloud: chicago}
  capacity: {cores: 2560, memory: 10Ti}
  machineTypes:
    - {name: small, cores: 4, memory: 16Gi}
    - {name: medium, cores: 8, memory: 32Gi}
    - {name: large, cores: 16, memory: 64Gi}
  compliance: [SOC2, HIPAA]
---
# Platform team creates clusters
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: prod-critical
  labels: {environment: prod, compliance: hipaa}
spec:
  pool: dc-chicago
  controlPlane: {replicas: 3, machineType: medium}
  workers: {replicas: 10, machineType: large}
---
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: prod-general
  labels: {environment: prod}
spec:
  pool: dc-chicago
  controlPlane: {replicas: 3, machineType: medium}
  workers: {replicas: 30, machineType: large}
---
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: staging
  labels: {environment: staging}
spec:
  pool: dc-chicago
  controlPlane: {replicas: 3, machineType: small}
  workers: {replicas: 10, machineType: medium}
---
# Developers write services
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: patient-api
spec:
  containers:
    main: {image: hospital/api:v2}
  requirements:
    placement: "cluster.labels.compliance == 'hipaa'"
# → Solver places on prod-critical
---
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: website
spec:
  containers:
    main: {image: company/web:v1}
# → Solver places on prod-general (most capacity, no constraints)
```

---

## Solver Flow

```
1. Service created/updated
           │
           ▼
2. Evaluate placement CEL against all clusters
           │
           ▼
3. Filter to matching clusters
           │
           ▼
4. Score by: capacity, locality to dependencies, cost
           │
           ▼
5. Assign to best cluster
           │
           ▼
6. Update service status: cluster=prod-critical
```

If no cluster matches:
```
status:
  phase: Unschedulable
  conditions:
    - type: Scheduled
      status: "False"
      reason: NoMatchingCluster
      message: "No cluster with labels.compliance=hipaa"
```

Platform team sees this, creates appropriate cluster.

---

## Pool → Cluster Capacity Tracking

Each cluster consumes pool capacity:

```yaml
# StaticPool status shows allocation
status:
  used:
    cores: 800
    memory: 3.2Ti
  allocatedTo:
    - cluster: prod-critical
      cores: 184
      memory: 736Gi
    - cluster: prod-general
      cores: 504
      memory: 2Ti
    - cluster: staging
      cores: 92
      memory: 368Gi
```

Pool controller prevents over-allocation.
