# CRD Reference

All Lattice CRDs use the API group `lattice.dev/v1alpha1`.

## Cluster Management

### LatticeCluster

Defines a Kubernetes cluster provisioned and managed by Lattice.

| Field | Type | Description |
|-------|------|-------------|
| `spec.providerRef` | string | Reference to an InfraProvider for credentials |
| `spec.provider.kubernetes.version` | string | Kubernetes version (e.g., `"v1.30.2"`) |
| `spec.provider.kubernetes.bootstrap` | enum | `kubeadm` or `rke2` |
| `spec.provider.kubernetes.certSANs` | []string | Additional API server SANs |
| `spec.provider.config.aws` | object | AWS-specific config (instanceType, sshKeyName) |
| `spec.provider.config.proxmox` | object | Proxmox-specific config |
| `spec.provider.config.openstack` | object | OpenStack-specific config |
| `spec.provider.config.docker` | object | Docker/CAPD config (empty for defaults) |
| `spec.nodes.controlPlane.replicas` | int | Control plane node count (must be odd) |
| `spec.nodes.controlPlane.instanceType.name` | string | Instance type for control plane |
| `spec.nodes.controlPlane.rootVolume.sizeGb` | int | Root volume size |
| `spec.nodes.workerPools.<name>.replicas` | int | Worker count |
| `spec.nodes.workerPools.<name>.instanceType.name` | string | Instance type |
| `spec.nodes.workerPools.<name>.labels` | map | Node labels |
| `spec.nodes.workerPools.<name>.taints` | []taint | Node taints |
| `spec.nodes.workerPools.<name>.min` | int | Autoscaling minimum |
| `spec.nodes.workerPools.<name>.max` | int | Autoscaling maximum |
| `spec.services` | bool | Enable LatticeService mesh support |
| `spec.gpu` | bool | Enable GPU infrastructure |
| `spec.monitoring.enabled` | bool | Enable VictoriaMetrics + KEDA |
| `spec.monitoring.ha` | bool | HA mode for VictoriaMetrics |
| `spec.backups.enabled` | bool | Enable Velero backup infrastructure |
| `spec.parentConfig.grpcPort` | int | Agent connection port (Cell mode) |
| `spec.parentConfig.bootstrapPort` | int | Bootstrap webhook port |
| `spec.parentConfig.proxyPort` | int | K8s API proxy port |
| `spec.parentConfig.service.type` | string | Service type (LoadBalancer, NodePort, ClusterIP) |
| `spec.registryMirrors` | []RegistryMirror | Container image registry redirects |

**Status Phases:** `Pending` → `Provisioning` → `Pivoting` → `Pivoted` → `Ready` → `Deleting` / `Unpivoting` / `Failed`

**Key Status Fields:**
- `phase`, `message`, `conditions`
- `observedGeneration`
- `pivotComplete`, `bootstrapComplete`
- `readyControlPlane`, `readyWorkers`
- `workerPools` (per-pool replica counts and resources)
- `childrenHealth` (child cluster health reports)
- `infrastructure` (per-component upgrade status)

---

### InfraProvider

Holds cloud provider credentials for cluster provisioning.

| Field | Type | Description |
|-------|------|-------------|
| `spec.type` | enum | `AWS`, `Proxmox`, `OpenStack`, `Docker` |
| `spec.region` | string | Cloud region (AWS, OpenStack) |
| `spec.credentialsSecretRef.name` | string | Secret name with credentials |
| `spec.credentialsSecretRef.namespace` | string | Secret namespace |
| `spec.aws.sshKeyName` | string | EC2 SSH key pair name |
| `spec.aws.vpcId` | string | Existing VPC ID (optional) |
| `spec.aws.subnetIds` | []string | Existing subnet IDs (optional) |
| `spec.aws.roleArn` | string | IAM role to assume (optional) |
| `spec.proxmox.serverUrl` | string | Proxmox API URL |
| `spec.proxmox.node` | string | Proxmox node name |
| `spec.proxmox.storage` | string | Storage pool name |
| `spec.openstack.authUrl` | string | Keystone auth URL |
| `spec.openstack.networkId` | string | Existing network ID (optional) |
| `spec.openstack.floatingIpPool` | string | Floating IP pool (optional) |

**Status Phases:** `Pending` → `Ready` / `Failed`

---

## Workload CRDs

### LatticeService

Long-running services (web APIs, backends, workers).

| Field | Type | Description |
|-------|------|-------------|
| `spec.replicas` | int | Desired replica count |
| `spec.workload.containers.<name>.image` | string | Container image |
| `spec.workload.containers.<name>.variables` | map | Environment variables (supports `${secret.*}` refs) |
| `spec.workload.containers.<name>.resources` | ResourceRequirements | CPU/memory/GPU requests and limits |
| `spec.workload.containers.<name>.readinessProbe` | probe | Readiness probe configuration |
| `spec.workload.containers.<name>.livenessProbe` | probe | Liveness probe configuration |
| `spec.workload.containers.<name>.files` | map | File mounts (path → content) |
| `spec.workload.containers.<name>.volumes` | map | Volume mounts (name → mount config) |
| `spec.workload.containers.<name>.args` | []string | Container arguments |
| `spec.workload.containers.<name>.command` | []string | Container command override |
| `spec.workload.service.ports.<name>.port` | int | Service port number |
| `spec.workload.service.ports.<name>.targetPort` | int | Target port (defaults to port) |
| `spec.workload.service.ports.<name>.protocol` | string | TCP or UDP |
| `spec.workload.resources.<name>` | ResourceDependency | External dependencies (secrets, services, external) |
| `spec.imagePullSecrets` | []string | Secret resource names for registry auth (flattened from RuntimeSpec) |
| `spec.autoscaling.max` | int | Maximum replicas |
| `spec.autoscaling.metrics` | []metric | Scaling metrics (metric name + target value) |
| `spec.deploy.strategy` | string | `rolling` or `canary` |
| `spec.deploy.canary.interval` | string | Canary step interval |
| `spec.deploy.canary.threshold` | int | Canary error threshold |
| `spec.deploy.canary.maxWeight` | int | Max canary traffic weight |
| `spec.deploy.canary.stepWeight` | int | Weight increment per step |
| `spec.ingress.gatewayClass` | string | Gateway class name |
| `spec.ingress.routes.<name>.kind` | enum | `HTTPRoute`, `GRPCRoute`, or `TCPRoute` |
| `spec.ingress.routes.<name>.hosts` | []string | External hostnames |
| `spec.ingress.routes.<name>.port` | string | Port name reference |
| `spec.ingress.routes.<name>.listenPort` | int | Gateway listener port |
| `spec.ingress.routes.<name>.tls.secretName` | string | TLS secret name |
| `spec.ingress.routes.<name>.tls.issuerRef.name` | string | cert-manager issuer name |
| `spec.ingress.routes.<name>.rules` | []RouteRule | Path/header matching rules |
| `spec.observability.metrics.port` | string | Port name to scrape |
| `spec.observability.metrics.mappings` | map | KEDA metric name → PromQL query |
| `spec.backup` | BackupSpec | Service-level backup configuration |

**Status Phases:** `Pending` → `Compiling` → `Ready` / `Failed`

---

### LatticeJob

Batch jobs and distributed training (Volcano-backed).

| Field | Type | Description |
|-------|------|-------------|
| `spec.schedulerName` | string | Scheduler name (default: `volcano`) |
| `spec.minAvailable` | int | Minimum pods for gang scheduling |
| `spec.training.framework` | string | Training framework (`PyTorch`, `DeepSpeed`, `Jax`) |
| `spec.training.coordinatorTask` | string | Task name for coordinator (e.g., `master`) |
| `spec.training.nccl.netIf` | string | Network interface for NCCL |
| `spec.training.nccl.ibHca` | string | InfiniBand HCA device |
| `spec.training.nccl.gdr` | bool | Enable GPU Direct RDMA |
| `spec.training.nccl.debug` | string | NCCL debug level |
| `spec.training.nccl.extraEnv` | map | Additional NCCL environment variables |
| `spec.tasks.<name>.replicas` | int | Task replica count |
| `spec.tasks.<name>.workload` | WorkloadSpec | Same container spec as LatticeService |
| `spec.tasks.<name>.restartPolicy` | string | `OnFailure`, `Never`, `Always` |
| `spec.tasks.<name>.policies` | []policy | Per-task lifecycle policies |
| `spec.defaults.restartPolicy` | string | Default restart policy for all tasks |
| `spec.schedule` | string | Cron expression (makes this a CronJob) |
| `spec.concurrencyPolicy` | string | `Allow`, `Forbid`, `Replace` |
| `spec.successfulJobsHistoryLimit` | int | Retained successful job count |
| `spec.failedJobsHistoryLimit` | int | Retained failed job count |
| `spec.startingDeadlineSeconds` | int | Deadline for starting missed jobs |
| `spec.suspend` | bool | Pause the cron schedule |
| `spec.policies` | []policy | Lifecycle policies (event → action) |
| `spec.maxRetry` | int | Maximum retry count |
| `spec.queue` | string | Volcano queue name |
| `spec.priorityClassName` | string | Kubernetes PriorityClass name |

**Status Phases:** `Pending` → `Running` → `Succeeded` / `Failed`

**Status Fields:** `phase`, `message`, `observedGeneration`, `startTime`, `completionTime`

---

### LatticeModel

LLM model serving with optional prefill/decode disaggregation.

| Field | Type | Description |
|-------|------|-------------|
| `spec.schedulerName` | string | Scheduler name (default: `volcano`) |
| `spec.routing.inferenceEngine` | string | `VLlm` or `SGLang` |
| `spec.routing.model` | string | Model identifier (e.g., `meta-llama/Llama-3-70B`) |
| `spec.routing.port` | int | Inference server port |
| `spec.routing.protocol` | string | Protocol (optional) |
| `spec.routing.routes.<name>.rules` | []ModelRouteRule | Model routing rules |
| `spec.routing.routes.<name>.modelName` | string | Model name override |
| `spec.routing.routes.<name>.loraAdapters` | []string | LoRA adapter names |
| `spec.routing.routes.<name>.rateLimit` | RateLimit | Token rate limiting |
| `spec.routing.routes.<name>.parentRefs` | []ref | Gateway parent references |
| `spec.routing.kvConnector.type` | string | `Nixl`, `Mooncake`, or `Lmcache` |
| `spec.routing.kvConnector.port` | int | KV connector port |
| `spec.routing.trafficPolicy.retry.attempts` | int | Retry attempts |
| `spec.modelSource.uri` | string | Model source URI |
| `spec.modelSource.cacheUri` | string | Cache location URI |
| `spec.modelSource.cacheSize` | string | Cache storage size |
| `spec.modelSource.mountPath` | string | Model mount path |
| `spec.modelSource.tokenSecret.name` | string | Auth token secret name |
| `spec.modelSource.downloaderImage` | string | Custom downloader image |
| `spec.roles.<name>.replicas` | int | Role replica count |
| `spec.roles.<name>.entryWorkload` | WorkloadSpec | Container spec for this role |
| `spec.roles.<name>.workerReplicas` | int | Worker replicas per entry |
| `spec.roles.<name>.workerWorkload` | WorkloadSpec | Worker container spec |
| `spec.roles.<name>.autoscaling.max` | int | Maximum replicas |
| `spec.roles.<name>.autoscaling.metrics` | []metric | Scaling metrics |
| `spec.roles.<name>.autoscaling.tolerancePercent` | int | Scaling tolerance |
| `spec.roles.<name>.autoscaling.behavior` | behavior | Scale up/down behavior with panic mode |
| `spec.recoveryPolicy` | string | `ServingGroupRecreate` |
| `spec.restartGracePeriodSeconds` | int | Grace period before restart |

**Roles:** `serving` (single role), or `prefill` + `decode` (P/D disaggregation)

**Status Phases:** `Pending` → `Loading` → `Serving` / `Failed`

**Status Fields:** `phase`, `message`, `observedGeneration`, `conditions`, `appliedRoles`

---

## Mesh & Security

### LatticeMeshMember

Defines mesh policy for a workload (auto-generated by LatticeService, or created directly).

| Field | Type | Description |
|-------|------|-------------|
| `spec.target.selector` | map | Pod label selector |
| `spec.target.namespace` | string | Target namespace (alternative to selector) |
| `spec.ports` | []MeshMemberPort | Exposed ports with mTLS modes |
| `spec.ports[].peerAuth` | enum | `Strict`, `Permissive`, or `Webhook` |
| `spec.allowedCallers` | []ServiceRef | Services allowed to call this member |
| `spec.dependencies` | []ServiceRef | Services this member depends on |
| `spec.egress` | []EgressRule | Non-mesh egress (entity, CIDR, FQDN) |
| `spec.allowPeerTraffic` | bool | Allow pods of same service to communicate |
| `spec.dependsAll` | bool | Wildcard outbound dependency |
| `spec.ambient` | bool | Enable Istio ambient (L7). Default: `true` |
| `spec.serviceAccount` | string | Override ServiceAccount for SPIFFE identity |

---

### CedarPolicy

Authorization policies for secret access.

| Field | Type | Description |
|-------|------|-------------|
| `spec.description` | string | Human-readable description |
| `spec.policies` | string | Cedar policy language text |
| `spec.priority` | int | Evaluation priority (higher = first) |
| `spec.enabled` | bool | Enable/disable without deleting |
| `spec.propagate` | bool | Distribute to child clusters |

**Status Phases:** `Pending` → `Valid` / `Invalid`

**Status Fields:** `permitCount`, `forbidCount`, `validationErrors`

---

### OIDCProvider

OIDC authentication configuration.

| Field | Type | Description |
|-------|------|-------------|
| `spec.issuerUrl` | string | OIDC issuer URL |
| `spec.clientId` | string | OIDC client ID |
| `spec.clientSecret` | SecretRef | Token introspection secret (optional) |
| `spec.usernameClaim` | string | JWT claim for username (default: `sub`) |
| `spec.groupsClaim` | string | JWT claim for groups (default: `groups`) |
| `spec.usernamePrefix` | string | Username prefix (optional) |
| `spec.groupsPrefix` | string | Groups prefix (optional) |
| `spec.audiences` | []string | Allowed token audiences |
| `spec.requiredClaims` | []RequiredClaim | Required JWT claims (each has `name` and optional `value`) |
| `spec.caBundle` | string | PEM CA cert for self-signed IdPs |
| `spec.jwksRefreshIntervalSeconds` | int | JWKS cache refresh interval (default: 3600) |
| `spec.propagate` | bool | Distribute to children (default: `true`) |
| `spec.allowChildOverride` | bool | Allow child clusters to override (default: `false`) |

**Status Phases:** `Pending` → `Ready` / `Failed`

**Status Fields:** `phase`, `message`, `lastJwksFetch`, `jwksUri`

---

## Secrets

### SecretProvider

External secret backend configuration (creates ESO ClusterSecretStore).

| Field | Type | Description |
|-------|------|-------------|
| `spec.provider` | object | ESO provider config (one top-level key: `vault`, `aws`, `webhook`, `barbican`, etc.) |

**Status Phases:** `Pending` → `Ready` / `Failed`

**Status Fields:** `providerType`, `lastValidated`

---

## Backup & Restore

### BackupStore

Backup storage location (creates Velero BackupStorageLocation).

| Field | Type | Description |
|-------|------|-------------|
| `spec.default` | bool | Use as default store when none specified |
| `spec.storage.provider` | string | `s3`, `s3Compatible`, `gcs`, `azure` |
| `spec.storage.s3.bucket` | string | S3 bucket name |
| `spec.storage.s3.region` | string | AWS region |
| `spec.storage.s3.endpoint` | string | Custom endpoint (MinIO) |
| `spec.storage.s3.forcePathStyle` | bool | Path-style access (required for MinIO) |
| `spec.storage.gcs.bucket` | string | GCS bucket name |
| `spec.storage.azure.container` | string | Azure container name |
| `spec.storage.azure.storageAccount` | string | Azure storage account |
| `spec.storage.cloudProviderRef` | string | InfraProvider reference for credentials |
| `spec.storage.credentialsSecretRef` | string | Direct Secret reference for credentials |

**Status Phases:** `Pending` → `Ready` / `Failed`

---

### LatticeClusterBackup

Scheduled cluster-wide backups.

| Field | Type | Description |
|-------|------|-------------|
| `spec.schedule` | string | Cron expression |
| `spec.storeRef` | string | BackupStore name (optional, uses default) |
| `spec.scope.controlPlane` | bool | Include Lattice CRDs |
| `spec.scope.gpuPaasResources` | bool | Include GPU PaaS resources |
| `spec.scope.workloadNamespaces` | labelSelector | Namespace label selector |
| `spec.scope.includeNamespaces` | []string | Explicit namespace inclusion |
| `spec.scope.excludeNamespaces` | []string | Explicit namespace exclusion |
| `spec.retention.daily` | int | Daily backup retention count |
| `spec.retention.ttl` | string | Time-to-live (e.g., `"720h"`) |
| `spec.paused` | bool | Pause the schedule |

**Status Phases:** `Pending` → `Active` → `Paused` / `Failed`

---

### LatticeRestore

Restore from a Velero backup.

| Field | Type | Description |
|-------|------|-------------|
| `spec.backupName` | string | Velero backup name to restore from |
| `spec.clusterBackupRef` | string | LatticeClusterBackup that created this backup (optional) |
| `spec.restoreVolumes` | bool | Restore persistent volumes (default: `true`) |

**Status Phases:** `Pending` → `InProgress` → `Completed` / `Failed`
