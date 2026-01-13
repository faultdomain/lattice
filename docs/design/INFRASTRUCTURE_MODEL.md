# Infrastructure Model Design

## Overview

Lattice needs to know what infrastructure is available before the solver can place services. Two fundamentally different models:

| Aspect | Metered (Cloud) | Static (On-prem/Reserved) |
|--------|-----------------|---------------------------|
| Constraint | Budget ($/month) | Capacity (nodes, cores) |
| Capacity | Elastic | Fixed/pre-purchased |
| Goal | Minimize spend | Maximize utilization |
| Scaling | Automatic | Manual/planned |
| Examples | AWS on-demand, GCP, Azure | vSphere, OpenStack, Metal3, AWS Reserved Instances |

**Note:** "Static" refers to the cost/capacity model, not the provisioning method. Both types use CAPI providers to provision clusters. A "static" AWS deployment with reserved instances still uses the AWS CAPI provider.

---

## CloudInfrastructure CRD

For AWS, GCP, Azure, and other pay-as-you-go providers.

```yaml
apiVersion: lattice.dev/v1alpha1
kind: CloudInfrastructure
metadata:
  name: aws-production
spec:
  # Cloud provider
  provider: aws  # aws | gcp | azure

  # Credentials for provisioning
  credentialsRef:
    name: aws-credentials
    namespace: lattice-system

  # Budget constraints
  budget:
    monthly: 50000        # USD
    alertThreshold: 80    # Percentage - alert when exceeded
    hardLimit: true       # If true, refuse to provision when exceeded

  # Default settings for all regions (can be overridden per-region)
  defaults:
    compliance: []
    capabilities: []
    maxClustersPerRegion: 5
    maxNodesPerCluster: 50

  # Enabled regions with optional overrides
  regions:
    us-east-1:
      # Override budget for this region
      budget:
        monthly: 20000
      # Compliance certifications available in this region
      compliance:
        - SOC2
        - HIPAA
        - FedRAMP
      # Special capabilities
      capabilities:
        - gpu
        - arm64
      # Resource quotas
      quotas:
        maxClusters: 10
        maxNodesPerCluster: 100

    us-west-2:
      compliance:
        - SOC2
      # Uses defaults for everything else

    eu-west-1:
      compliance:
        - SOC2
        - GDPR
      # Data sovereignty - some workloads MUST stay here
      dataResidency: eu

status:
  # Current spend tracking
  currentSpend:
    monthly: 32450
    byRegion:
      us-east-1: 18200
      us-west-2: 8500
      eu-west-1: 5750

  # Provisioned resources
  clusters:
    total: 8
    byRegion:
      us-east-1: 4
      us-west-2: 2
      eu-west-1: 2

  # Health
  conditions:
    - type: Ready
      status: "True"
    - type: BudgetExceeded
      status: "False"
    - type: CredentialsValid
      status: "True"
```

### Cost Tracking

The controller periodically queries cloud billing APIs to update `status.currentSpend`. When approaching limits:

1. **80% threshold**: Alert (Kubernetes event + optional webhook)
2. **100% soft limit**: Warn but allow provisioning
3. **100% hard limit**: Block new provisioning, set `BudgetExceeded` condition

---

## StaticInfrastructure CRD

For on-prem data centers, colocation, bare metal, or any fixed-capacity infrastructure.

```yaml
apiVersion: lattice.dev/v1alpha1
kind: StaticInfrastructure
metadata:
  name: dc-east
spec:
  # Infrastructure provider for CAPI provisioning
  # Static capacity doesn't mean static provisioning - we still need CAPI
  provider: vsphere  # vsphere | openstack | metal3 | aws | gcp | azure | docker

  # Credentials for the provider
  credentialsRef:
    name: vsphere-credentials
    namespace: lattice-system

  # Provider-specific configuration
  providerConfig:
    # vSphere example
    server: vcenter.example.com
    datacenter: DC1
    datastore: datastore1
    network: VM Network
    resourcePool: /DC1/host/Cluster/Resources
    # OR OpenStack example:
    # cloud: my-openstack
    # OR AWS reserved instances:
    # reservationId: ri-abc123

  # Location identifier
  location:
    name: us-east-dc1
    region: us-east           # Logical region for grouping
    zone: zone-a              # Availability zone equivalent

    # Physical location (for compliance/latency)
    address:
      country: US
      state: Virginia
      city: Ashburn
      facility: Equinix DC5

  # Total capacity at this location
  capacity:
    nodes: 100
    cores: 800
    memory: 3200Gi
    storage: 500Ti

    # GPU/accelerator capacity
    accelerators:
      - type: nvidia-a100
        count: 16
      - type: nvidia-t4
        count: 32

  # Network connectivity
  network:
    # Bandwidth to internet
    egress: 10Gbps

    # Latency to other locations (for solver)
    latencyTo:
      us-west-dc1: 65ms
      eu-west-dc1: 85ms
      aws-us-east-1: 2ms  # Direct connect

  # Compliance/certifications for this facility
  compliance:
    - SOC2
    - HIPAA
    - PCI-DSS

  # Capabilities
  capabilities:
    - gpu
    - nvme
    - arm64

  # Reservation policy
  reservation:
    # Reserve capacity for critical workloads
    reserved:
      cores: 100
      memory: 400Gi
    # What can use reserved capacity
    reservedFor:
      - labelSelector:
          priority: critical

status:
  # Current utilization
  utilization:
    nodes:
      total: 100
      used: 72
      available: 28
    cores:
      total: 800
      used: 580
      available: 220
    memory:
      total: 3200Gi
      used: 2100Gi
      available: 1100Gi

  # Clusters running at this location
  clusters:
    total: 5
    names:
      - prod-api
      - prod-data
      - staging
      - dev-1
      - dev-2

  # Health
  conditions:
    - type: Ready
      status: "True"
    - type: CapacityPressure
      status: "False"
      message: "28% capacity available"
```

### Capacity Management

Unlike cloud, static infrastructure requires proactive capacity planning:

1. **Utilization alerts**: Warn when approaching capacity (e.g., 80%)
2. **Reservation**: Critical workloads get guaranteed capacity
3. **Bin packing**: Solver optimizes placement to maximize utilization
4. **Overflow policy**: Can optionally burst to cloud when full

---

## Hybrid: Overflow to Cloud

Static infrastructure can reference cloud infrastructure for overflow:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: StaticInfrastructure
metadata:
  name: dc-east
spec:
  location:
    name: us-east-dc1
  capacity:
    nodes: 100
    # ...

  # When capacity exhausted, overflow to cloud
  overflow:
    enabled: true
    target: aws-production    # CloudInfrastructure name
    regions:
      - us-east-1            # Prefer low-latency region

    # Conditions for overflow
    trigger:
      capacityThreshold: 90   # Overflow when 90% full

    # Limits on overflow
    limits:
      maxClusters: 3
      maxMonthlySpend: 10000
```

---

## Solver Integration

The solver uses infrastructure definitions to:

### 1. Filter Valid Placements

```
Service requires: compliance=[HIPAA], capabilities=[gpu]
                           ↓
Filter infrastructure where:
  - compliance contains HIPAA
  - capabilities contains gpu
  - budget/capacity available
                           ↓
Valid options: [us-east-1 (cloud), us-east-dc1 (static)]
```

### 2. Optimize Placement

**For cloud (minimize cost):**
- Prefer cheaper regions
- Colocate services to reduce cross-region traffic
- Stay within budget

**For static (maximize utilization):**
- Bin-pack efficiently
- Respect reservations
- Use overflow only when necessary

### 3. Handle Failures

```
No valid placement found
                           ↓
Generate requirements for new infrastructure:
  requiredProperties:
    compliance: [HIPAA]
    capabilities: [gpu]
    region: us-*
                           ↓
Platform engineer reviews and:
  a) Adds new region to CloudInfrastructure, OR
  b) Provisions new StaticInfrastructure
```

---

## Example: Multi-Cloud + On-Prem

```yaml
# Primary on-prem
apiVersion: lattice.dev/v1alpha1
kind: StaticInfrastructure
metadata:
  name: dc-east
spec:
  location:
    name: us-east-dc1
  capacity:
    nodes: 100
  overflow:
    enabled: true
    target: aws-production
---
# AWS for burst/DR
apiVersion: lattice.dev/v1alpha1
kind: CloudInfrastructure
metadata:
  name: aws-production
spec:
  provider: aws
  budget:
    monthly: 20000
    hardLimit: true
  regions:
    us-east-1:
      compliance: [SOC2]
---
# GCP for ML workloads (TPUs)
apiVersion: lattice.dev/v1alpha1
kind: CloudInfrastructure
metadata:
  name: gcp-ml
spec:
  provider: gcp
  budget:
    monthly: 30000
  regions:
    us-central1:
      capabilities: [tpu-v4]
```

Solver priority:
1. Place on `dc-east` (no incremental cost)
2. If full or capabilities missing, use cloud
3. ML workloads with TPU requirement → `gcp-ml`
4. General overflow → `aws-production`

---

## Implementation Notes

### Cost Estimation (Cloud)

Need pricing data for solver to estimate costs:
- Instance types and hourly rates
- Storage costs
- Network egress
- Could use cloud pricing APIs or embedded lookup tables

### Capacity Tracking (Static)

Need to aggregate from actual cluster usage:
- Query Kubernetes metrics from each cluster
- Sum up node/pod resource usage
- Update status periodically

### Latency Data

For placement decisions based on latency:
- Cloud regions: Use published inter-region latencies
- Static: Measure actual latency between locations
- Cross-type: Measure cloud↔on-prem latency

---

## Status Conditions

Both CRDs share common conditions:

| Condition | Meaning |
|-----------|---------|
| Ready | Infrastructure is usable for placement |
| CredentialsValid | Can authenticate to provider (cloud) |
| BudgetExceeded | Monthly spend >= limit (cloud) |
| CapacityPressure | Utilization > threshold (static) |
| Degraded | Partial functionality available |
