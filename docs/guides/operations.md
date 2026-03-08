# Operations

## Monitoring

Lattice deploys VictoriaMetrics for metrics collection and storage, with KEDA for metrics-driven autoscaling.

### VictoriaMetrics

**Single-node mode** (`monitoring.ha: false`):
- Deploys a single VMSingle instance handling both reads and writes
- Service: `vmsingle-lattice-metrics.monitoring.svc:8428`

**HA mode** (`monitoring.ha: true`):
- Deploys a VMCluster with separate components (2 replicas each):
  - **VMInsert** (port 8480): Write path, receives scraped metrics
  - **VMSelect** (port 8481): Read path, queried by KEDA
  - **VMStorage**: Persistent storage layer
- Read endpoint: `vmselect-lattice-metrics.monitoring.svc:8481/select/0/prometheus`
- Write endpoint: `vminsert-lattice-metrics.monitoring.svc:8480`

**VMAgent** scrapes metrics from all services at 30-second intervals.

### Service Metrics

LatticeService can expose custom metrics:

```yaml
spec:
  observability:
    metrics:
      port: http
      mappings:
        requests_per_second: "rate(http_requests_total[1m])"
```

Mappings are a key-value map where keys are KEDA metric names and values are PromQL queries. This generates a `VMServiceScrape` that configures VMAgent to collect metrics from your service.

### KEDA Autoscaling

KEDA queries VictoriaMetrics to drive autoscaling decisions. The autoscaling spec on LatticeService:

```yaml
spec:
  autoscaling:
    max: 20
    metrics:
      - metric: cpu
        target: 70
```

For custom Prometheus metrics:

```yaml
spec:
  autoscaling:
    max: 50
    metrics:
      - metric: http_requests_per_second
        target: 100
```

If no metrics are specified, KEDA defaults to CPU at 80%. The `replicas` field on LatticeService sets the initial/minimum replica count.

## Multi-Cluster API Proxy

The parent cluster (Cell mode) can access child cluster Kubernetes APIs through the gRPC tunnel, without requiring direct network access to the child.

### How It Works

1. The parent exposes a K8s API proxy on `proxy_port` (default: 8081)
2. Requests are routed through the gRPC stream to the child's agent
3. The agent executes the request against the local API server and returns the result
4. Watch requests are streamed in real-time

### Configuration

Enable the proxy in your cluster's `parentConfig`:

```yaml
spec:
  parentConfig:
    grpcPort: 50051
    bootstrapPort: 8443
    proxyPort: 8081
    service:
      type: LoadBalancer
```

### Hierarchical Routing

For multi-level cluster hierarchies (parent → child → grandchild), requests use hop-by-hop routing via `targetPath`:

- `target_path: "child-a"` — route to child-a
- `target_path: "child-a/grandchild-b"` — route through child-a to grandchild-b

Each hop strips the first path segment and forwards the remainder.

### Supported Operations

All Kubernetes API verbs are supported: `get`, `list`, `watch`, `create`, `update`, `delete`, `patch`.

## Registry Mirrors

Redirect container image pulls through internal mirrors, useful for air-gapped environments or reducing external bandwidth:

```yaml
spec:
  registryMirrors:
    - upstream: "docker.io"
      mirror: "harbor.corp.com"
    - upstream: "@infra"
      mirror: "mirrors.corp.com"
    - upstream: "*"
      mirror: "internal-mirror.local"
      credentialsRef:
        name: mirror-credentials
        namespace: lattice-system
```

### Upstream Matching

| Pattern | Description |
|---------|-------------|
| `"docker.io"` | Exact registry match |
| `"@infra"` | All Lattice infrastructure registries (Cilium, Istio, cert-manager, etc.) not covered by explicit entries |
| `"*"` | Catch-all for any registry not matched above |

Precedence: Explicit host → `@infra` → `*`

### Credentials

Optional `credentials_ref` points to a Kubernetes Secret with a `.dockerconfigjson` key for authenticated mirror access.

## Troubleshooting

### Cluster Status

```bash
# Watch cluster phase transitions
kubectl get latticecluster -n lattice-system -w

# Detailed status with conditions
kubectl describe latticecluster my-cluster -n lattice-system

# Check worker pool status
kubectl get latticecluster my-cluster -n lattice-system \
  -o jsonpath='{.status.workerPools}' | jq

# Check child cluster health (from parent)
kubectl get latticecluster -n lattice-system \
  -o jsonpath='{.items[0].status.childrenHealth}' | jq
```

### Key Status Fields

| Field | What to Check |
|-------|---------------|
| `phase` | Current lifecycle phase (Pending → Provisioning → Pivoting → Pivoted → Ready). Also: Failed, Deleting, Unpivoting |
| `observedGeneration` | Compare to `metadata.generation` — if older, controller is stalled |
| `conditions` | Array of Kubernetes-style conditions with reason/message |
| `pivotComplete` | Whether CAPI pivot succeeded |
| `readyControlPlane` / `readyWorkers` | Node counts |
| `childrenHealth.lastHeartbeat` | Stale heartbeat indicates agent disconnection |

### Service Status

```bash
# Check service phase
kubectl get latticeservice -n default

# Detailed compilation status
kubectl describe latticeservice my-api -n default
```

Service phases: `Pending` → `Compiling` → `Ready` or `Failed`

Failed services retry automatically every 30 seconds. Transient errors (webhook down, API server blip) self-heal without requiring a spec change.

### Mesh Connectivity Issues

Always check ztunnel logs first:

```bash
kubectl logs -n istio-system -l app=ztunnel --tail=100 | grep -i "denied\|RBAC\|allow"
```

Check generated policies:

```bash
# Cilium policies
kubectl get ciliumnetworkpolicy -n default

# Istio authorization policies
kubectl get authorizationpolicy -n default

# Mesh members
kubectl get latticemeshmember -n default
```

### Secret Sync Issues

```bash
# Check ExternalSecret status
kubectl get externalsecret -n default

# Check ClusterSecretStore health
kubectl get clustersecretstore

# Check SecretProvider status
kubectl get secretprovider -n lattice-system
```

### Common Issues

**Cluster stuck in Provisioning:**
- Check CAPI resources: `kubectl get cluster,machine -n lattice-system`
- Check cloud provider quotas and credentials
- Check InfraProvider status: `kubectl get infraprovider -n lattice-system`

**Service stuck in Failed:**
- Check the status message: `kubectl describe latticeservice <name>`
- Common causes: missing secret provider, Cedar policy denial, invalid container spec
- The controller retries every 30 seconds — transient errors self-heal

**Secrets not syncing:**
- Verify SecretProvider is `Ready`
- Check ExternalSecret status for sync errors
- Verify Cedar policies permit the access (if Cedar is configured)
- For local webhook: verify source secrets have `lattice.dev/secret-source: "true"` label

**Agent disconnected from parent:**
- Check agent logs: `kubectl logs -n lattice-system -l app=lattice-operator`
- Verify parent endpoint is reachable from the child (outbound connection)
- Agent automatically reconnects — disconnection doesn't affect cluster self-management
