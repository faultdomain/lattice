# Service Deployment

Lattice provides three workload CRDs for different use cases:

| CRD | Purpose |
|-----|---------|
| **LatticeService** | Long-running services (web APIs, backends, workers) |
| **LatticeJob** | Batch jobs and distributed training (Volcano-backed) |
| **LatticeModel** | LLM model serving with P/D disaggregation |

All three share the same `WorkloadSpec` for defining containers, and benefit from the same mesh, secret, and monitoring infrastructure.

## LatticeService

### Basic Service

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: my-api
  namespace: default
spec:
  replicas: 3
  workload:
    containers:
      main:
        image: my-registry.io/my-api:v1.2.0
        variables:
          PORT: "8080"
          LOG_LEVEL: info
        resources:
          requests:
            cpu: 500m
            memory: 512Mi
          limits:
            cpu: "1"
            memory: 1Gi
        readinessProbe:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
    service:
      ports:
        http:
          port: 8080
```

The Lattice compiler transforms this into:
- A Kubernetes Deployment with the specified containers
- A Service exposing the declared ports
- A LatticeMeshMember for network policy enforcement
- Optionally: ScaledObject (KEDA), PodDisruptionBudget, VMServiceScrape (monitoring)

### Multiple Containers

```yaml
workload:
  containers:
    app:
      image: my-registry.io/my-api:v1.2.0
      resources:
        requests:
          cpu: 500m
          memory: 512Mi
    sidecar:
      image: my-registry.io/log-shipper:latest
      resources:
        requests:
          cpu: 100m
          memory: 128Mi
  service:
    ports:
      http:
        port: 8080
```

### Environment Variables

```yaml
workload:
  containers:
    main:
      image: my-app:latest
      variables:
        # Plain text values
        PORT: "8080"
        LOG_LEVEL: info

        # Secret references (pure secret env var)
        DB_PASSWORD: "${secret.database.password}"

        # Mixed content (string interpolation with secrets)
        DATABASE_URL: "postgres://user:${secret.database.password}@db.svc:5432/mydb"
```

Secret references use the syntax `${secret.<resource-name>.<key>}` where `<resource-name>` references a secret resource declared in `spec.workload.resources`.

### File Mounts

```yaml
workload:
  containers:
    main:
      image: my-app:latest
      files:
        /etc/app/config.yaml:
          content: |
            database:
              host: db.svc
              password: ${secret.database.password}
        /etc/app/cert.pem:
          content: "${secret.tls.cert}"
```

Files with secret references are compiled through ESO's template engine.

### Volumes

```yaml
workload:
  containers:
    main:
      image: my-app:latest
      volumes:
        data:
          mountPath: /data
          claimName: my-data-pvc
```

Volumes are a `BTreeMap<String, VolumeMount>` where each key is the volume name.

### Resource Declarations

Resources declare external dependencies — secrets, other services, and external endpoints:

```yaml
workload:
  resources:
    # Secret resource (routes through ESO)
    database:
      type: secret
      id: database/prod/credentials    # Remote path (e.g., Vault path)
      params:
        provider: vault-prod           # SecretProvider name
        keys:
          - password
          - username
      direction: inbound               # This service consumes the secret

    # Service dependency (generates mesh policies)
    backend-api:
      type: service
      direction: outbound              # This service calls backend-api

    # External endpoint (named map of URLs)
    external-api:
      type: external-service
      direction: outbound
      params:
        endpoints:
          api: api.external.com:443
```

### Autoscaling

```yaml
spec:
  replicas: 3                       # Initial replicas
  autoscaling:
    max: 20
    metrics:
      - metric: cpu
        target: 70
      - metric: memory
        target: 80
```

Autoscaling is backed by KEDA, which creates a ScaledObject targeting the Deployment. If no metrics are specified, KEDA defaults to CPU at 80%.

For custom Prometheus metrics:

```yaml
spec:
  autoscaling:
    max: 50
    metrics:
      - metric: http_requests_per_second
        target: 100
```

### Deployment Strategy

```yaml
spec:
  deploy:
    strategy: rolling
```

Supported strategies are `rolling` and `canary`. For canary deployments:

```yaml
spec:
  deploy:
    strategy: canary
    canary:
      interval: 60s
      threshold: 5
      maxWeight: 50
      stepWeight: 10
```

### Gateway API Ingress

Expose a service externally via Gateway API. Routes are a named map:

```yaml
spec:
  ingress:
    gatewayClass: istio              # Optional: Gateway class
    routes:
      public:
        kind: HTTPRoute
        hosts:
          - api.example.com
        port: http                   # References a port name from workload.service.ports
        listenPort: 443
        tls:
          issuerRef:
            name: letsencrypt-prod   # cert-manager ClusterIssuer
        rules:
          - matches:
              - path:
                  type: PathPrefix
                  value: /api
```

This generates:
- A Gateway resource (if not already created for the namespace)
- An HTTPRoute routing traffic to the service
- A Certificate (via cert-manager) for TLS termination

Supported route kinds: `HTTPRoute`, `GRPCRoute`, `TCPRoute`.

### Observability

```yaml
spec:
  observability:
    metrics:
      port: http                     # Port name to scrape
      mappings:
        requests_per_second: "rate(http_requests_total[1m])"
        error_rate: "rate(http_errors_total[1m]) / rate(http_requests_total[1m])"
```

Mappings are a `BTreeMap<String, String>` where keys are KEDA metric names and values are PromQL queries.

### Backup

```yaml
spec:
  backup:
    schedule: "0 */1 * * *"         # Hourly
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

### Service Lifecycle

| Phase | Description |
|-------|-------------|
| `Pending` | Initial state, waiting for first reconciliation |
| `Compiling` | Compiler is generating Kubernetes resources |
| `Ready` | All resources applied successfully |
| `Failed` | Compilation or apply failed (automatically retries every 30s) |

Failed services always retry. Transient errors (webhook down, API server blip) self-heal without requiring a spec change. The controller requeues every 30 seconds and re-enters the compile path for Failed services.

## LatticeJob

LatticeJob wraps Volcano's VCJob for batch workloads and distributed training.

### Simple Job

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeJob
metadata:
  name: data-pipeline
  namespace: default
spec:
  schedulerName: volcano
  tasks:
    worker:
      replicas: 4
      workload:
        containers:
          main:
            image: my-registry.io/data-pipeline:latest
            resources:
              requests:
                cpu: "2"
                memory: 4Gi
      restartPolicy: OnFailure
```

### Distributed Training (PyTorch)

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeJob
metadata:
  name: train-llm
  namespace: default
spec:
  schedulerName: volcano
  minAvailable: 4
  training:
    framework: PyTorch
    coordinatorTask: master
    nccl:
      netIf: eth0
      gdr: true
      debug: WARN
  tasks:
    master:
      replicas: 1
      workload:
        containers:
          main:
            image: my-registry.io/train:latest
            resources:
              requests:
                nvidia.com/gpu: "8"
                cpu: "32"
                memory: 256Gi
    worker:
      replicas: 3
      workload:
        containers:
          main:
            image: my-registry.io/train:latest
            resources:
              requests:
                nvidia.com/gpu: "8"
                cpu: "32"
                memory: 256Gi
  defaults:
    restartPolicy: OnFailure
```

The training config automatically injects environment variables for distributed training:
- `MASTER_ADDR`, `MASTER_PORT` for PyTorch distributed
- `WORLD_SIZE`, `RANK`, `LOCAL_RANK`
- NCCL configuration variables

### Cron Jobs

```yaml
spec:
  schedule: "0 2 * * *"            # Run daily at 2 AM
  concurrencyPolicy: Forbid        # Don't overlap runs
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 1
  suspend: false
```

### Lifecycle Policies

```yaml
spec:
  policies:
    - event: PodFailed
      action: RestartTask
    - event: TaskCompleted
      action: CompleteJob
  maxRetry: 3
```

### Job Lifecycle

| Phase | Description |
|-------|-------------|
| `Pending` | Job created, waiting for scheduling |
| `Running` | At least `minAvailable` pods are running |
| `Succeeded` | All tasks completed successfully |
| `Failed` | Job failed after max retries |

## LatticeModel

LatticeModel manages LLM inference serving with advanced features like prefill/decode disaggregation.

### Basic Model Serving

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeModel
metadata:
  name: llama-70b
  namespace: default
spec:
  routing:
    inferenceEngine: VLlm
    model: meta-llama/Llama-3-70B
    port: 8000
    routes:
      chat:
        rules:
          - name: default
            targetModels:
              - modelServerName: llama-70b
        parentRefs:
          - name: inference-gateway
  roles:
    serving:
      replicas: 2
      entryWorkload:
        containers:
          main:
            image: vllm/vllm-openai:latest
            args:
              - --model
              - meta-llama/Llama-3-70B
              - --tensor-parallel-size
              - "4"
            resources:
              requests:
                nvidia.com/gpu: "4"
                cpu: "16"
                memory: 128Gi
```

### Prefill/Decode Disaggregation (P/D)

For high-throughput inference, separate prefill (prompt processing) from decode (token generation):

```yaml
spec:
  routing:
    inferenceEngine: VLlm
    model: meta-llama/Llama-3-70B
    kvConnector:
      type: Nixl                   # KV cache transfer protocol
    routes:
      chat:
        rules:
          - name: default
            targetModels:
              - modelServerName: llama-70b
  roles:
    prefill:
      replicas: 2
      entryWorkload:
        containers:
          main:
            image: vllm/vllm-openai:latest
            args:
              - --model
              - meta-llama/Llama-3-70B
              - --kv-transfer-role
              - prefill
            resources:
              requests:
                nvidia.com/gpu: "4"
    decode:
      replicas: 4
      entryWorkload:
        containers:
          main:
            image: vllm/vllm-openai:latest
            args:
              - --model
              - meta-llama/Llama-3-70B
              - --kv-transfer-role
              - decode
            resources:
              requests:
                nvidia.com/gpu: "4"
```

The routing compiler generates:
- A Kubernetes Service per role
- An Istio VirtualService for traffic routing between prefill and decode
- KV connector configuration for cache transfer

### Model Autoscaling

```yaml
roles:
  serving:
    replicas: 2
    autoscaling:
      max: 8
      metrics:
        - metric: vllm_requests_running
          target: 50
      tolerancePercent: 10
      behavior:
        scaleUp:
          panicThresholdPercent: 200   # Spike detection
          panicModeHold: 5m
          stabilizationWindow: 2m
        scaleDown:
          stabilizationWindow: 10m
```

### KV Connector Types

| Type | Description |
|------|-------------|
| `Nixl` | NVIDIA NVLink-based KV cache transfer |
| `Mooncake` | Mooncake distributed KV cache |
| `Lmcache` | LMCache for KV cache management |

### Model Lifecycle

| Phase | Description |
|-------|-------------|
| `Pending` | Model created, waiting for scheduling |
| `Loading` | Model weights being loaded into GPU memory |
| `Serving` | Model serving inference requests |
| `Failed` | Model failed to load or serve |
