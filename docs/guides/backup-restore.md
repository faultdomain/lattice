# Backup & Restore

Lattice provides backup and restore capabilities backed by Velero. Backups can be configured at the cluster level (scheduled, broad scope) or at the service level (application-aware with hooks).

## BackupStore

A `BackupStore` defines where backups are stored. It creates a Velero `BackupStorageLocation`.

### S3

```yaml
apiVersion: lattice.dev/v1alpha1
kind: BackupStore
metadata:
  name: production-s3
  namespace: lattice-system
spec:
  default: true
  storage:
    provider: s3
    s3:
      bucket: lattice-backups
      region: us-east-1
    cloudProviderRef: aws-prod     # Reference to InfraProvider for credentials
```

### S3-Compatible (MinIO)

```yaml
apiVersion: lattice.dev/v1alpha1
kind: BackupStore
metadata:
  name: minio-store
  namespace: lattice-system
spec:
  default: false
  storage:
    provider: s3Compatible
    s3:
      bucket: lattice-backups
      endpoint: "http://minio.svc:9000"
      forcePathStyle: true
    credentialsSecretRef: minio-credentials
```

### GCS

```yaml
apiVersion: lattice.dev/v1alpha1
kind: BackupStore
metadata:
  name: gcs-store
  namespace: lattice-system
spec:
  storage:
    provider: gcs
    gcs:
      bucket: my-gcs-bucket
    credentialsSecretRef: gcp-credentials
```

### Azure

```yaml
apiVersion: lattice.dev/v1alpha1
kind: BackupStore
metadata:
  name: azure-store
  namespace: lattice-system
spec:
  storage:
    provider: azure
    azure:
      container: backups
      storageAccount: myaccount
    credentialsSecretRef: azure-credentials
```

### Credentials

BackupStore supports two credential sources:

| Field | Description |
|-------|-------------|
| `cloudProviderRef` | Reference to an InfraProvider CRD (uses the same cloud credentials) |
| `credentialsSecretRef` | Direct reference to a Kubernetes Secret |

If `default: true` is set, this store is used when no explicit `storeRef` is specified in backup definitions.

## Cluster Backups

`LatticeClusterBackup` schedules cluster-wide backups with configurable scope and retention.

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeClusterBackup
metadata:
  name: daily-backup
  namespace: lattice-system
spec:
  schedule: "0 2 * * *"               # Daily at 2 AM UTC
  storeRef: production-s3              # Optional: uses default BackupStore if omitted

  scope:
    controlPlane: true                 # Backup Lattice CRDs
    gpuPaasResources: true             # Backup GPU PaaS resources
    workloadNamespaces:
      matchLabels:
        environment: production
    includeNamespaces:
      - payments
      - orders
    excludeNamespaces:
      - dev
      - test

  retention:
    daily: 30                          # Keep 30 daily backups
    ttl: "720h"                        # 30-day TTL

  paused: false
```

### Scope Configuration

| Field | Description |
|-------|-------------|
| `controlPlane` | Include Lattice control-plane CRDs (LatticeCluster, LatticeService, etc.) |
| `gpuPaasResources` | Include GPU PaaS resources (GPUPool, InferenceEndpoint, ModelCache, etc.) |
| `workloadNamespaces.matchLabels` | Select namespaces by labels |
| `workloadNamespaces.matchExpressions` | Select namespaces by label expressions |
| `includeNamespaces` | Explicitly include specific namespaces |
| `excludeNamespaces` | Explicitly exclude specific namespaces |

### Lifecycle

| Phase | Description |
|-------|-------------|
| `Pending` | Waiting for Velero Schedule CRD |
| `Active` | Schedule running |
| `Paused` | Schedule exists but disabled |
| `Failed` | Configuration error |

### Pausing a Schedule

Set `paused: true` to temporarily disable backups without deleting the schedule:

```bash
kubectl patch latticeclusterbackup daily-backup -n lattice-system \
  --type merge -p '{"spec":{"paused":true}}'
```

## Service-Level Backups

LatticeService resources can define their own backup schedule with application-aware hooks:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: my-database
  namespace: production
spec:
  replicas: 3
  workload:
    containers:
      main:
        image: my-registry.io/postgres:15
  backup:
    schedule: "0 */1 * * *"           # Hourly
    storeRef: production-s3
    retention:
      daily: 7
      ttl: "168h"

    hooks:
      pre:
        - name: freeze
          container: main
          command: ["/bin/sh", "-c", "pg_dump > /backup/dump.sql"]
          timeout: "600s"
          onError: Fail
      post:
        - name: cleanup
          container: main
          command: ["/bin/sh", "-c", "rm /backup/dump.sql"]
          timeout: "300s"
          onError: Continue

    volumes:
      defaultPolicy: opt-out
      include:
        - data-pvc
      exclude:
        - cache-pvc
        - temp
```

### Backup Hooks

Hooks run inside the container to ensure application-consistent backups:

| Field | Description |
|-------|-------------|
| `name` | Hook identifier |
| `container` | Container to execute in |
| `command` | Command array (must use absolute paths) |
| `timeout` | Maximum execution time (e.g., `"600s"`, `"10m"`) |
| `onError` | `Fail` (abort backup) or `Continue` (proceed despite hook failure) |

**Pre-hooks** run before the backup snapshot (e.g., freeze writes, dump database).
**Post-hooks** run after the snapshot completes (e.g., cleanup, resume writes).

### Volume Policy

| Field | Description |
|-------|-------------|
| `defaultPolicy` | `opt-out` (backup all unless excluded) or `opt-in` (backup none unless included) |
| `include` | Explicitly include specific PVC names |
| `exclude` | Explicitly exclude specific PVC names |

## Restoring from Backup

Create a `LatticeRestore` to restore from a Velero backup:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeRestore
metadata:
  name: restore-20260205
  namespace: lattice-system
spec:
  backupName: lattice-daily-backup-20260205020012
  clusterBackupRef: daily-backup
  restoreVolumes: true
```

### Spec Fields

| Field | Description |
|-------|-------------|
| `backupName` | Name of the Velero backup to restore from |
| `clusterBackupRef` | Optional reference to the LatticeClusterBackup that created this backup |
| `restoreVolumes` | Whether to restore persistent volumes (default: `true`) |

### Restore Lifecycle

| Phase | Description |
|-------|-------------|
| `Pending` | Velero Restore not yet created |
| `InProgress` | Restore in progress |
| `Completed` | Restore finished successfully |
| `Failed` | Restore encountered an error |

### Monitoring a Restore

```bash
# Watch restore progress
kubectl get latticerestore restore-20260205 -n lattice-system -w

# Check detailed status
kubectl describe latticerestore restore-20260205 -n lattice-system
```

## Listing Available Backups

Velero backups created by Lattice follow the naming convention `lattice-<backup-name>-<timestamp>`:

```bash
# List all Velero backups
kubectl get backups -n velero

# List backups from a specific schedule
kubectl get backups -n velero -l velero.io/schedule-name=lattice-daily-backup
```
