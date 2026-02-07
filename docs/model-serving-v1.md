# Model Serving for LatticeService

> **Native model serving compiled from LatticeService — no KServe, no new controllers fighting
> over HPA/Gateway/mesh. The ServiceCompiler gains a `model` field that injects model-loading
> infrastructure into the existing Deployment pipeline. All models are pre-fetched to nodes
> via a ModelCache controller + ModelArtifact CRD — one loading strategy, no size-based branching.**

---

## Why Not KServe

KServe is a full serving platform — it creates and manages its own Deployment, Service, HPA,
Gateway, and autoscaler. Lattice's `ServiceCompiler` already owns all of these, and does so
with bilateral mesh agreements that KServe has no concept of.

Integrating KServe would mean either:
1. **Disabling KServe's sub-resource management** — fragile, incomplete flags, breaks on upgrades
2. **Letting KServe own everything when `model` is present** — two divergent deployment paths,
   lose Lattice's HPA logic, GPU-aware scaling, bilateral ingress, and policy compilation

Instead, we take the two things KServe does that are genuinely hard to build:
- **Model artifact loading** (download from S3/GCS/HuggingFace into the serving container)
- **Serving runtime catalog** (know how to configure vLLM, TorchServe, Triton, etc.)

And compile them directly into the existing `ServiceCompiler` output. Everything else —
HPA, Gateway API, Cilium/Istio policies, canary deploys — stays exactly as-is.

---

## Architecture

```
LatticeService                    LatticeService
(spec.model present)              (spec.model absent — unchanged)
        │                                 │
        ▼                                 ▼
   ServiceCompiler                   ServiceCompiler
   ┌──────────────────────┐         ┌──────────────────────┐
   │ ModelCompiler (NEW)  │         │ WorkloadCompiler     │
   │  ↓ injects:          │         │ PolicyCompiler       │
   │  - runtime container │         │ IngressCompiler      │
   │  - hostPath volume   │         │ WaypointCompiler     │
   │  - scheduling gate   │         └──────────────────────┘
   │                      │
   │ WorkloadCompiler     │
   │ PolicyCompiler       │  ← identical, no changes
   │ IngressCompiler      │
   │ WaypointCompiler     │
   └──────────────────────┘

ModelCache Controller (separate, watches LatticeService + Nodes)
        │
        ▼
   ModelArtifact CRD (per model-per-node cache status)
        │
        ▼
   Pre-fetch Jobs (pull models to /var/lattice/models/{hash})
```

### What changes

| Component | Change |
|---|---|
| `LatticeServiceSpec` | Add optional `model: ModelSpec` field |
| `ServiceCompiler` | When `model` present: inject hostPath mount + scheduling gate, generate runtime container |
| `ModelArtifact` CRD | New — tracks cache state per model per node |
| `ModelCacheController` | New — watches LatticeServices with `model`, creates pre-fetch Jobs |
| `WorkloadCompiler` | No change — receives the same inputs |
| `PolicyCompiler` | No change — bilateral agreements work identically |
| `IngressCompiler` | No change |
| `HPA` | No change — same `replicas.autoscaling` field |

---

## 1. ModelSpec on LatticeServiceSpec

### User-Facing YAML

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: llama-70b-serve
  namespace: ml-team
spec:
  model:
    framework: vllm
    uri: huggingface://meta-llama/Llama-3.3-70B-Instruct
    args:
      - "--tensor-parallel-size=4"
      - "--max-model-len=8192"

  gpu:
    count: 4
    model: H100

  replicas:
    min: 1
    max: 4
    autoscaling:
      - metric: vllm_num_requests_waiting
        target: 10

  service:
    ports:
      http:
        port: 8000

  resources:
    from-api-gateway:
      type: service
      direction: inbound
      id: api-gateway
```

When `spec.model` is present, the compiler:
1. Sets the container image from the framework's runtime catalog
2. Generates framework-specific command/args (model path, port, user args)
3. Injects model loading infrastructure (init container or hostPath)
4. Sets a default health endpoint for startup probe

When `spec.model` is absent, compilation is completely unchanged.

### Shorthand Forms

```yaml
# Minimal — framework defaults handle everything
model:
  framework: vllm
  uri: huggingface://meta-llama/Llama-3.1-8B-Instruct

# S3-hosted model with credentials
model:
  framework: triton
  uri: s3://my-models/fraud-detector/v3
  secretRef: model-s3-creds

# Custom container (user provides image, model just handles loading)
model:
  framework: custom
  uri: huggingface://BAAI/bge-base-en-v1.5
  image: ghcr.io/huggingface/text-embeddings-inference:1.5
  mountPath: /models

# HuggingFace with specific revision
model:
  framework: vllm
  uri: huggingface://meta-llama/Llama-3.3-70B-Instruct
  revision: "a1b2c3d"
```

### CRD Struct

```rust
/// Model serving specification
///
/// When present on a LatticeService, the compiler generates a serving
/// runtime container and model-loading infrastructure instead of
/// requiring the user to specify containers manually.
///
/// The `containers` field on LatticeServiceSpec becomes optional when
/// `model` is present — the compiler populates it from the framework's
/// runtime catalog.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelSpec {
    /// Serving framework — determines container image, ports, and arguments
    pub framework: ModelFramework,

    /// Model artifact URI
    ///
    /// Supported schemes:
    /// - `huggingface://org/model` — HuggingFace Hub
    /// - `s3://bucket/path` — AWS S3 (or S3-compatible)
    /// - `gs://bucket/path` — Google Cloud Storage
    /// - `az://container/path` — Azure Blob Storage
    /// - `file:///path` — Local path (for testing)
    pub uri: String,

    /// HuggingFace revision (branch, tag, or commit hash)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,

    /// Additional arguments passed to the serving runtime
    ///
    /// Appended after the framework's default arguments.
    /// Example: ["--tensor-parallel-size=4", "--max-model-len=8192"]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,

    /// Custom container image (only for framework: custom)
    ///
    /// When framework is not `custom`, this is ignored — the runtime
    /// catalog determines the image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    /// Mount path for model artifacts inside the container
    ///
    /// Defaults per framework:
    /// - vllm: /models
    /// - triton: /models
    /// - torchserve: /models
    /// - tgi: /models
    /// - custom: /models (override with this field)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_path: Option<String>,

    /// Secret reference for model artifact credentials
    ///
    /// Required for private S3/GCS/Azure models. References a Kubernetes
    /// Secret in the same namespace containing provider-specific credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<String>,

    /// Expected size of the model artifacts
    ///
    /// Used by the ModelCache controller for disk space management and
    /// progress reporting. Format: Kubernetes quantity (e.g., "5Gi", "140Gi")
    /// If omitted, the controller estimates from the model registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
}

/// Supported model serving frameworks
///
/// Each framework maps to a specific container image, default port,
/// health endpoint, and argument format.
#[non_exhaustive]
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ModelFramework {
    /// vLLM — high-throughput LLM serving with PagedAttention
    /// Image: vllm/vllm-openai:<version>
    /// Port: 8000, Health: /health, Protocol: OpenAI-compatible
    Vllm,

    /// NVIDIA Triton Inference Server — multi-framework, multi-model
    /// Image: nvcr.io/nvidia/tritonserver:<version>
    /// Port: 8000 (HTTP) / 8001 (gRPC), Health: /v2/health/ready
    Triton,

    /// TorchServe — PyTorch native serving
    /// Image: pytorch/torchserve:<version>
    /// Port: 8080 (inference) / 8081 (management), Health: /ping
    TorchServe,

    /// HuggingFace Text Generation Inference
    /// Image: ghcr.io/huggingface/text-generation-inference:<version>
    /// Port: 8080, Health: /health, Protocol: OpenAI-compatible
    Tgi,

    /// Custom — user provides container image, model spec handles loading only
    Custom,
}
```

### Extend LatticeServiceSpec

```rust
pub struct LatticeServiceSpec {
    // ... existing fields unchanged ...

    /// Model serving specification
    ///
    /// When present, the compiler generates a serving runtime container
    /// and model-loading infrastructure. The `containers` field becomes
    /// optional — the framework's runtime catalog populates it.
    ///
    /// All other fields (resources, replicas, deploy, ingress, gpu, etc.)
    /// work identically whether `model` is present or not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<ModelSpec>,
}
```

### Validation

```rust
impl LatticeServiceSpec {
    pub fn validate(&self) -> Result<(), Error> {
        // Existing validation ...

        if let Some(model) = &self.model {
            model.validate()?;

            // When model is present, containers may be empty
            // (compiler populates from framework catalog)
            if matches!(model.framework, ModelFramework::Custom) && model.image.is_none() {
                return Err(Error::validation(
                    "model.image is required when framework is 'custom'"
                ));
            }
        } else {
            // Without model, containers must be non-empty (existing rule)
            if self.containers.is_empty() {
                return Err(Error::validation(
                    "service must have at least one container"
                ));
            }
        }

        Ok(())
    }
}

impl ModelSpec {
    pub fn validate(&self) -> Result<(), Error> {
        // URI must have a recognized scheme
        let valid_schemes = ["huggingface://", "s3://", "gs://", "az://", "file:///"];
        if !valid_schemes.iter().any(|s| self.uri.starts_with(s)) {
            return Err(Error::validation(format!(
                "model.uri must start with one of: {}",
                valid_schemes.join(", ")
            )));
        }

        // Custom framework requires image
        if matches!(self.framework, ModelFramework::Custom) && self.image.is_none() {
            return Err(Error::validation(
                "model.image is required when framework is 'custom'"
            ));
        }

        Ok(())
    }
}
```

---

## 2. Serving Runtime Catalog

A pure function mapping `ModelFramework` to container configuration. No external state.

```rust
/// Runtime configuration for a model serving framework
pub struct RuntimeConfig {
    /// Container image (tag pinned in versions.toml)
    pub image: String,
    /// Default serving port
    pub port: u16,
    /// Health check endpoint path
    pub health_path: String,
    /// Health check port (usually same as port)
    pub health_port: u16,
    /// Default model mount path inside the container
    pub model_path: String,
    /// Function to generate command + args from ModelSpec
    pub args_fn: fn(&ModelSpec, &str) -> (Option<Vec<String>>, Vec<String>),
}

pub fn runtime_config(framework: &ModelFramework) -> RuntimeConfig {
    match framework {
        ModelFramework::Vllm => RuntimeConfig {
            image: format!("vllm/vllm-openai:{}", env!("VLLM_VERSION")),
            port: 8000,
            health_path: "/health".into(),
            health_port: 8000,
            model_path: "/models".into(),
            args_fn: vllm_args,
        },
        ModelFramework::Triton => RuntimeConfig {
            image: format!("nvcr.io/nvidia/tritonserver:{}", env!("TRITON_VERSION")),
            port: 8000,
            health_path: "/v2/health/ready".into(),
            health_port: 8000,
            model_path: "/models".into(),
            args_fn: triton_args,
        },
        ModelFramework::TorchServe => RuntimeConfig {
            image: format!("pytorch/torchserve:{}", env!("TORCHSERVE_VERSION")),
            port: 8080,
            health_path: "/ping".into(),
            health_port: 8080,
            model_path: "/models".into(),
            args_fn: torchserve_args,
        },
        ModelFramework::Tgi => RuntimeConfig {
            image: format!(
                "ghcr.io/huggingface/text-generation-inference:{}",
                env!("TGI_VERSION")
            ),
            port: 8080,
            health_path: "/health".into(),
            health_port: 8080,
            model_path: "/models".into(),
            args_fn: tgi_args,
        },
        ModelFramework::Custom => unreachable!("custom framework uses user-provided image"),
    }
}

fn vllm_args(model: &ModelSpec, model_path: &str) -> (Option<Vec<String>>, Vec<String>) {
    let model_name = parse_model_name(&model.uri);
    let mut args = vec![
        "--model".into(),
        format!("{}/{}", model_path, model_name),
        "--port".into(),
        "8000".into(),
    ];
    args.extend(model.args.clone());
    (None, args) // no command override, just args
}

fn tgi_args(model: &ModelSpec, model_path: &str) -> (Option<Vec<String>>, Vec<String>) {
    let model_name = parse_model_name(&model.uri);
    let mut args = vec![
        "--model-id".into(),
        format!("{}/{}", model_path, model_name),
        "--port".into(),
        "8080".into(),
    ];
    args.extend(model.args.clone());
    (None, args)
}

// triton_args, torchserve_args follow same pattern
```

### Version Pinning

Runtime image tags are pinned in `versions.toml` and injected at compile time:

```toml
[versions]
VLLM_VERSION = "v0.7.3"
TGI_VERSION = "3.1.1"
TRITON_VERSION = "25.01-py3"
TORCHSERVE_VERSION = "0.12.0-gpu"
```

---

## 3. Model Loading: Always Pre-fetch

Every model — regardless of size — is pre-fetched to node-local storage via the
ModelCache controller. The compiler always emits a hostPath mount + scheduling gate.
No init container strategy, no size-based branching.

```
LatticeService created with spec.model
    → ModelCache controller sees it
    → Creates ModelArtifact + pre-fetch Job per eligible node
    → Job downloads model to /var/lattice/models/{model-name}/
    → ModelArtifact status → Ready
    → Controller removes scheduling gate from Deployment
    → Pods schedule, mount model read-only from hostPath
```

### Why not init containers

An init container with emptyDir re-downloads on every pod restart, reschedule, and
scale-up event. Even a 2GB embedding model re-downloading on every HPA scale-out is
wasted time and bandwidth. Pre-fetching once to the node and sharing read-only across
all pods eliminates this entirely.

| | Init container (emptyDir) | Always pre-fetch (hostPath) |
|---|---|---|
| **Pod restart** | Re-downloads | Instant (model on disk) |
| **HPA scale-up** | Re-downloads per new pod | Instant (shared read-only) |
| **Node reschedule** | Re-downloads on new node | Pre-fetch Job runs on new node once |
| **Multiple services, same model** | Each downloads independently | Shared cache, downloaded once |
| **Code paths** | Two strategies + size branching | One strategy |
| **Disk usage** | Ephemeral per-pod copies | One copy per node, shared |

### Compiled Output

Every LatticeService with `spec.model` compiles to the same Deployment shape:

```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      schedulingGates:
        - name: lattice.dev/model-ready
      containers:
        - name: vllm
          image: vllm/vllm-openai:v0.7.3
          args:
            - "--model=/models/meta-llama/Llama-3.3-70B-Instruct"
            - "--port=8000"
          volumeMounts:
            - name: model-cache
              mountPath: /models
              readOnly: true
      volumes:
        - name: model-cache
          hostPath:
            path: /var/lattice/models
            type: Directory
```

The scheduling gate `lattice.dev/model-ready` is removed by the ModelCache controller
once a `ModelArtifact` for this model reaches `Ready` status on at least one eligible node.
For small models this gate clears in seconds; for large models it may take minutes — but
the mechanism is identical either way.

---

## 4. ModelArtifact CRD

Tracks the cache state of a specific model on a specific node. Created and managed
exclusively by the ModelCache controller.

```yaml
apiVersion: lattice.dev/v1alpha1
kind: ModelArtifact
metadata:
  name: meta-llama-llama-3-3-70b-instruct-gpu-node-01
  namespace: lattice-system
  labels:
    lattice.dev/model-hash: "a1b2c3d4"     # content-addressable
    lattice.dev/model-uri: "huggingface://meta-llama/Llama-3.3-70B-Instruct"
    lattice.dev/node: gpu-node-01
  ownerReferences:
    - kind: Node
      name: gpu-node-01
spec:
  uri: "huggingface://meta-llama/Llama-3.3-70B-Instruct"
  revision: "main"
  node: gpu-node-01
  path: /var/lattice/models/meta-llama/Llama-3.3-70B-Instruct
  sizeBytes: 150323855360
status:
  phase: Ready       # Pending | Downloading | Ready | Failed | Evicting
  downloadedBytes: 150323855360
  completedAt: "2025-01-15T10:30:00Z"
  conditions:
    - type: Available
      status: "True"
      lastTransitionTime: "2025-01-15T10:30:00Z"
```

### CRD Struct

```rust
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "ModelArtifact",
    plural = "modelartifacts",
    shortname = "ma",
    namespaced,
    status = "ModelArtifactStatus",
    printcolumn = r#"{"name":"Model","type":"string","jsonPath":".spec.uri"}"#,
    printcolumn = r#"{"name":"Node","type":"string","jsonPath":".spec.node"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Size","type":"string","jsonPath":".spec.sizeBytes"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ModelArtifactSpec {
    /// Model artifact URI (same format as ModelSpec.uri)
    pub uri: String,

    /// Revision (HuggingFace branch/tag/commit)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,

    /// Target node name
    pub node: String,

    /// Local filesystem path on the node
    pub path: String,

    /// Expected size in bytes (for progress tracking)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ModelArtifactStatus {
    pub phase: ModelArtifactPhase,
    pub downloaded_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub enum ModelArtifactPhase {
    #[default]
    Pending,
    Downloading,
    Ready,
    Failed,
    Evicting,
}
```

---

## 5. ModelCache Controller

A controller that runs in the Lattice operator, watches LatticeService resources with
`spec.model`, and ensures models are pre-fetched to eligible nodes.

### Reconciliation Loop

```
Watch: LatticeService (with spec.model)
Watch: Node (GPU nodes — labeled nvidia.com/gpu: true)
Watch: ModelArtifact (own status updates)

On LatticeService create/update:
  1. Parse spec.model.uri → determine model identity (URI + revision)
  2. Determine eligible nodes (GPU nodes matching spec.gpu.model if set)
  3. For each eligible node:
     a. Check if ModelArtifact exists for (model, node)
     b. If not, create ModelArtifact + pre-fetch Job
  4. Once any ModelArtifact is Ready, remove scheduling gate from Deployment

On LatticeService delete:
  1. Check if any other LatticeService references this model
  2. If not, mark ModelArtifacts as Evicting → cleanup Job removes files

On ModelArtifact status change:
  1. If Ready: check if any gated Deployments can be unblocked
  2. If Failed: retry with backoff (create new Job)
```

### Pre-fetch Job

The controller creates a one-shot Job (not a DaemonSet pod) on each target node:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: prefetch-llama-70b-gpu-node-01
  namespace: lattice-system
  ownerReferences:
    - kind: ModelArtifact
      name: meta-llama-llama-3-3-70b-instruct-gpu-node-01
spec:
  backoffLimit: 3
  ttlSecondsAfterFinished: 300
  template:
    spec:
      nodeSelector:
        kubernetes.io/hostname: gpu-node-01
      tolerations:
        - key: nvidia.com/gpu
          operator: Exists
          effect: NoSchedule
      containers:
        - name: loader
          image: ghcr.io/lattice-cloud/model-loader:v1
          command: ["model-loader"]
          args:
            - "--source=huggingface"
            - "--model=meta-llama/Llama-3.3-70B-Instruct"
            - "--dest=/var/lattice/models"
          volumeMounts:
            - name: model-store
              mountPath: /var/lattice/models
          # secretRef credentials as env vars if present
      volumes:
        - name: model-store
          hostPath:
            path: /var/lattice/models
            type: DirectoryOrCreate
      restartPolicy: OnFailure
```

### Why Jobs Over a DaemonSet

| | DaemonSet | Jobs (per-model-per-node) |
|---|---|---|
| **Targeting** | Runs on all GPU nodes, even those that don't need the model | Only runs on nodes where the model is needed |
| **Lifecycle** | Runs forever, needs ConfigMap for model list | Runs once, completes, gets cleaned up |
| **Eviction** | Cannot garbage-collect unused models | Controller tracks references, evicts when zero |
| **Node awareness** | No concept of which models go where | Respects nodeSelector/affinity from LatticeService |
| **Observability** | One pod with unclear model status | One ModelArtifact per model per node with phase |
| **Cost** | Permanent resource consumption | Zero cost when idle |

### Cache Eviction (LRU)

The controller maintains a reference count per model URI:

```
model_refs: HashMap<ModelURI, HashSet<LatticeServiceRef>>
```

When a LatticeService is deleted or its `model.uri` changes:
1. Decrement reference count for old URI
2. If count reaches zero, mark all ModelArtifacts for that URI as `Evicting`
3. Create cleanup Jobs that delete the model files from each node
4. Delete ModelArtifact CRs after cleanup completes

When disk pressure is detected (reported by kubelet or a configurable threshold):
1. Sort unreferenced models by `completedAt` (oldest first)
2. Evict until disk usage drops below threshold

### Scheduling Gate Management

The controller removes the `lattice.dev/model-ready` scheduling gate from a Deployment's
pod template when at least one ModelArtifact for the required model is `Ready` on an
eligible node.

```rust
async fn maybe_ungate_deployment(
    &self,
    service: &LatticeService,
    model: &ModelSpec,
) -> Result<()> {
    let model_uri = &model.uri;
    let revision = model.revision.as_deref().unwrap_or("main");

    // Find Ready ModelArtifacts for this model
    let ready_artifacts = self.list_model_artifacts(model_uri, revision)
        .await?
        .into_iter()
        .filter(|ma| ma.status.phase == ModelArtifactPhase::Ready)
        .count();

    if ready_artifacts == 0 {
        return Ok(()); // Not ready yet
    }

    // Remove scheduling gate from the Deployment
    let name = service.metadata.name.as_deref().unwrap();
    let namespace = service.metadata.namespace.as_deref().unwrap();
    let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), namespace);

    let patch = json!({
        "spec": {
            "template": {
                "spec": {
                    "schedulingGates": null
                }
            }
        }
    });
    deployments.patch(name, &PatchParams::apply("lattice"), &Patch::Merge(&patch)).await?;

    Ok(())
}
```

---

## 6. Compiler Changes

### ModelCompiler

New compiler module that sits alongside WorkloadCompiler, PolicyCompiler, etc.

```rust
// crates/lattice-service/src/model/mod.rs

/// Compiles ModelSpec into container and volume specifications
///
/// This compiler runs BEFORE WorkloadCompiler. It produces a ContainerSpec
/// and volume configuration that WorkloadCompiler then includes in the
/// Deployment.
pub struct ModelCompiler;

impl ModelCompiler {
    /// Compile a ModelSpec into container and volume configuration
    ///
    /// Returns:
    /// - Primary container (serving runtime, populated from framework catalog)
    /// - Volumes (hostPath to node-local model cache)
    /// - Scheduling gate (blocks until ModelArtifact is Ready)
    pub fn compile(
        model: &ModelSpec,
        gpu: Option<&GPUSpec>,
    ) -> Result<ModelCompilation, CompileError> {
        let model_name = parse_model_name(&model.uri);
        let mount_path = model.mount_path.as_deref()
            .unwrap_or_else(|| default_mount_path(&model.framework));

        let container = if matches!(model.framework, ModelFramework::Custom) {
            // Custom: user provides image, we just add model volume mount
            compile_custom_container(model, mount_path)?
        } else {
            // Catalog: generate container from runtime config
            let config = runtime_config(&model.framework);
            compile_catalog_container(model, &config, mount_path)?
        };

        // Always pre-fetch: hostPath mount + scheduling gate
        let volumes = vec![hostpath_volume("model-cache", "/var/lattice/models")];
        let scheduling_gates = vec![scheduling_gate("lattice.dev/model-ready")];

        Ok(ModelCompilation {
            container,
            volumes,
            scheduling_gates,
        })
    }
}

pub struct ModelCompilation {
    pub container: ContainerSpec,
    pub volumes: Vec<PodVolume>,
    pub scheduling_gates: Vec<SchedulingGate>,
}
```

### ServiceCompiler Integration

The `ServiceCompiler::compile()` method gains a model compilation step:

```rust
// In ServiceCompiler::compile()
pub async fn compile(&self, service: &LatticeService) -> Result<CompiledService, CompileError> {
    let name = /* ... existing ... */;
    let namespace = /* ... existing ... */;

    // NEW: Compile model spec if present
    let model_compilation = if let Some(ref model) = service.spec.model {
        Some(ModelCompiler::compile(
            model,
            service.spec.gpu.as_ref(),
        )?)
    } else {
        None
    };

    // Compile volumes (existing)
    let compiled_volumes = VolumeCompiler::compile(name, namespace, &service.spec)?;

    // Compile secrets (existing)
    let compiled_secrets = SecretsCompiler::compile(name, namespace, &service.spec)?;

    // Authorize secrets (existing)
    self.authorize_secrets(name, namespace, &service.spec).await?;

    // Delegate to WorkloadCompiler — passes model_compilation through
    let mut workloads = WorkloadCompiler::compile(
        name,
        service,
        namespace,
        &compiled_volumes,
        self.provider_type,
        model_compilation.as_ref(), // NEW parameter
    );

    // ... rest unchanged ...
}
```

### WorkloadCompiler Changes

WorkloadCompiler receives the optional `ModelCompilation` and merges it into the
Deployment:

```rust
// In WorkloadCompiler::compile()
pub fn compile(
    name: &str,
    service: &LatticeService,
    namespace: &str,
    volumes: &GeneratedVolumes,
    provider_type: ProviderType,
    model: Option<&ModelCompilation>, // NEW
) -> GeneratedWorkloads {
    // If model compilation present:
    // 1. Use model.container as the primary container (ignore spec.containers if empty)
    // 2. Add model.volumes to pod volumes (hostPath to /var/lattice/models)
    // 3. Add model.scheduling_gates to pod scheduling gates
    //
    // If model compilation absent:
    // Existing behavior, completely unchanged
}
```

### Default Startup Probe

When `spec.model` is present and the user hasn't defined a startup probe, the compiler
injects one based on the framework's health endpoint:

```rust
if service.spec.model.is_some() && container.startup_probe.is_none() {
    let config = runtime_config(&model.framework);
    container.startup_probe = Some(Probe {
        http_get: Some(HttpGetProbe {
            path: config.health_path,
            port: config.health_port,
        }),
        period_seconds: Some(10),
        failure_threshold: Some(60), // 10 minutes for large models
        ..Default::default()
    });
}
```

---

## 7. model-loader Container Image

A small, purpose-built container that downloads model artifacts. Used by
pre-fetch Jobs created by the ModelCache controller.

### Supported Sources

| Scheme | Backend | Auth |
|---|---|---|
| `huggingface://` | HuggingFace Hub API | `HF_TOKEN` env var or secret |
| `s3://` | AWS S3 SDK | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` or IRSA |
| `gs://` | Google Cloud Storage SDK | `GOOGLE_APPLICATION_CREDENTIALS` or Workload Identity |
| `az://` | Azure Blob SDK | `AZURE_STORAGE_ACCOUNT` + `AZURE_STORAGE_KEY` or Managed Identity |

### Behavior

```
model-loader --source huggingface --model meta-llama/Llama-3.3-70B-Instruct --dest /models
```

1. Parse source and model identifier
2. Check if model already exists at destination (hash comparison)
3. If not, download with resume support and progress reporting
4. Write a `.complete` marker file on success
5. Exit 0 on success, non-zero on failure

Resume support is critical — if a 140GB download fails at 120GB, the next Job attempt
resumes from 120GB rather than starting over.

### Image Build

```dockerfile
FROM rust:1.84-slim AS builder
WORKDIR /build
COPY crates/model-loader/ .
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /build/target/release/model-loader /model-loader
ENTRYPOINT ["/model-loader"]
```

Small image (~15MB), no Python runtime. Uses Rust S3/GCS/HF client libraries with
aws-lc-rs for FIPS-compliant TLS.

---

## 8. What Stays Unchanged

The entire point of this design is that model serving composes with existing Lattice
features with zero changes to those features:

| Feature | Why unchanged |
|---|---|
| **Bilateral agreements** | `resources` field works identically — callers/callees declare direction |
| **CiliumNetworkPolicy** | PolicyCompiler sees same ServiceGraph edges, generates same L4 rules |
| **AuthorizationPolicy** | Same SPIFFE identity, same L7 mTLS rules |
| **Autoscaling** | Same `replicas.autoscaling` field, same KEDA ScaledObject triggers |
| **Ingress** | Same `ingress` field, same Gateway/HTTPRoute compilation |
| **Canary deploys** | Same `deploy.canary` field |
| **GPU spec** | Same `gpu` field — `model` adds model loading, `gpu` adds GPU resources |
| **Secrets** | `model.secretRef` loads credentials; Cedar authorization unchanged |
| **Backup** | Same `backup` field — Velero hooks work on model serving Deployments |
| **Waypoint** | Same Istio ambient mesh enrollment |

### Example: Full-Featured Model Serving

All features compose in a single LatticeService:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: fraud-detector
  namespace: platform
spec:
  # Model serving (NEW)
  model:
    framework: vllm
    uri: s3://models/fraud-detector/v3
    secretRef: model-s3-creds
    size: 30Gi
    args: ["--max-model-len=4096"]

  # GPU allocation (existing)
  gpu:
    count: 2
    model: A100

  # Bilateral mesh agreements (existing, unchanged)
  resources:
    from-transaction-api:
      type: service
      direction: inbound
      id: transaction-api
      namespace: payments
    from-risk-engine:
      type: service
      direction: inbound
      id: risk-engine
    to-feature-store:
      type: service
      direction: outbound
      id: feature-store
      namespace: data

  # Autoscaling (existing, unchanged)
  replicas:
    min: 2
    max: 8
    autoscaling:
      - metric: vllm_num_requests_waiting
        target: 5
      - metric: cpu
        target: 70

  # Canary deploys (existing, unchanged)
  deploy:
    strategy: canary
    canary:
      weight: 20
      interval: 5m

  # External access (existing, unchanged)
  ingress:
    hosts: ["fraud-api.internal.example.com"]
    tls:
      mode: auto
      issuerRef:
        name: internal-ca

  service:
    ports:
      http:
        port: 8000
```

Compiled output: a Deployment with vLLM runtime container, hostPath model cache volume,
scheduling gate (removed when model is cached), GPU resources, SHM volume, HPA, Gateway,
HTTPRoute, Certificate, AuthorizationPolicy (3 inbound principals allowed), CiliumNetworkPolicy (bilateral L4),
ServiceEntry (for feature-store outbound), Waypoint Gateway.

Same `ServiceCompiler.compile()` call. Same `CompiledService` output struct.

---

## 9. File Changes

### New Files

| File | Description |
|---|---|
| `crates/lattice-common/src/crd/model.rs` | `ModelSpec`, `ModelFramework`, `ModelArtifactSpec`, `ModelArtifactStatus` |
| `crates/lattice-service/src/model/mod.rs` | `ModelCompiler` — compiles ModelSpec into container + volume config |
| `crates/lattice-service/src/model/catalog.rs` | `RuntimeConfig`, `runtime_config()` — framework → container mapping |
| `crates/lattice-service/src/model/volume.rs` | hostPath volume and scheduling gate helpers |
| `crates/lattice-model-cache/` | New crate: ModelCache controller |
| `crates/lattice-model-cache/src/controller.rs` | Watches LatticeService + Node, creates ModelArtifacts + Jobs |
| `crates/lattice-model-cache/src/eviction.rs` | LRU eviction logic, reference counting |
| `crates/lattice-model-cache/src/gate.rs` | Scheduling gate management (add/remove) |
| `crates/model-loader/` | New crate: model-loader container binary |
| `crates/model-loader/src/main.rs` | CLI: download from HuggingFace/S3/GCS/Azure |
| `crates/model-loader/src/huggingface.rs` | HuggingFace Hub download with resume |
| `crates/model-loader/src/s3.rs` | S3 download with resume |

### Modified Files

| File | Change |
|---|---|
| `crates/lattice-common/src/crd/mod.rs` | Add `pub mod model;` |
| `crates/lattice-common/src/crd/service.rs` | Add `model: Option<ModelSpec>` to `LatticeServiceSpec`, update `validate()` |
| `crates/lattice-service/src/compiler/mod.rs` | Call `ModelCompiler::compile()` when `spec.model` present, pass to WorkloadCompiler |
| `crates/lattice-service/src/workload/mod.rs` | Accept `ModelCompilation`, merge into Deployment |
| `crates/lattice-operator/src/startup/crds.rs` | Register `ModelArtifact` CRD |
| `crates/lattice-operator/src/controller.rs` | Start ModelCache controller |
| `versions.toml` | Add `VLLM_VERSION`, `TGI_VERSION`, `TRITON_VERSION`, `TORCHSERVE_VERSION` |
| `Cargo.toml` (workspace) | Add `lattice-model-cache` and `model-loader` to workspace members |

---

## 10. Implementation Phases

### Phase 1: ModelSpec + Runtime Catalog + ModelCache Controller

Add the `ModelSpec` field, compile it into Deployments, and build the pre-fetch
controller. This is the minimum viable feature — everything ships together because
the compiler always emits hostPath + scheduling gate, so the controller must exist
to ungate pods.

1. Define `ModelSpec`, `ModelFramework` in `lattice-common/src/crd/model.rs`
2. Define `ModelArtifactSpec`, `ModelArtifactStatus` CRD
3. Add `model: Option<ModelSpec>` to `LatticeServiceSpec`
4. Implement `RuntimeConfig` catalog (vllm, tgi, triton, torchserve, custom)
5. Implement `ModelCompiler` (always hostPath + scheduling gate)
6. Integrate into `ServiceCompiler` → `WorkloadCompiler` pipeline
7. Add default startup probe when `model` present
8. Build `model-loader` binary with HuggingFace support
9. Build `lattice-model-cache` controller (watch LatticeService, create ModelArtifacts + Jobs, manage scheduling gates)
10. Reference counting and LRU eviction
11. Pin runtime versions in `versions.toml`
12. Update `LatticeServiceSpec::validate()` — containers optional when model present

**Tests:**
- Unit: `ModelSpec::validate()` — URI schemes, custom requires image
- Unit: `runtime_config()` — all frameworks return correct image/port/health
- Unit: `ModelCompiler::compile()` — hostPath volume, scheduling gate, correct args
- Unit: reference counting (add/remove services, verify artifact lifecycle)
- Unit: eviction ordering (LRU by completedAt)
- Compiler integration: `model: { framework: vllm, uri: ... }` → correct Deployment
- Compiler integration: `model` + `gpu` + `resources` compose correctly
- Compiler integration: service without `model` unchanged (regression)
- Controller: LatticeService with model → ModelArtifact created
- Controller: ModelArtifact Ready → scheduling gate removed
- Controller: LatticeService deleted → ModelArtifact evicted (when zero refs)
- Controller: Job failure → retry with backoff

**Result:** Users can deploy model serving with `spec.model`. Models are pre-fetched
to nodes, pods are gated until cache is warm, scale-up is instant from shared cache.
Existing LatticeServices are completely unaffected.

### Phase 2: model-loader S3/GCS/Azure Support

Extend the model-loader binary to support cloud storage backends.

1. Add S3 download with multipart resume
2. Add GCS download
3. Add Azure Blob download
4. Secret mounting for credentials (from `model.secretRef`)
5. Hash verification (SHA-256 of downloaded artifacts)

**Tests:**
- Unit: URI parsing for each scheme
- Integration: download from mock S3 (localstack)
- Integration: resume after partial download

**Result:** Models can be loaded from any supported storage backend.

### Phase 3: CLI

User-facing commands for model serving workflows.

1. `lattice serve` — generate + apply LatticeService with `spec.model`
2. `lattice get models` — list ModelArtifacts with cache status per node
3. Update `lattice get services` — show model framework + URI in output

```bash
lattice serve llama-70b \
  --framework vllm \
  --model huggingface://meta-llama/Llama-3.3-70B-Instruct \
  --gpu 4 --gpu-model H100 \
  --namespace ml-team

lattice get models
# MODEL                                    NODES   PHASE    SIZE     AGE
# meta-llama/Llama-3.3-70B-Instruct       3/4     Ready    140Gi    2d
# BAAI/bge-base-en-v1.5                    4/4     Ready    1.2Gi    5d

lattice get services -n ml-team
# NAME         REPLICAS  GPU       MODEL                          PHASE   AGE
# llama-70b    2/4       4x H100   vllm/Llama-3.3-70B-Instruct   Ready   2d
# embeddings   4/4       1x 2Gi    custom/bge-base-en-v1.5        Ready   5d
```

**Result:** Complete CLI experience for model serving workflows.

---

## What This Does NOT Include

| Deferred | Why | When |
|---|---|---|
| **Model versioning / A-B serving** | Canary between model versions via `deploy.canary` is sufficient for v1 | v2: dedicated model version CRD |
| **Inference graph (chaining)** | Bilateral agreements already handle service-to-service chaining | v2: if pipeline serving needed |
| **Scale-to-zero** | GPU cold starts (30-120s) make it impractical | v2: if customer demand |
| **KV-cache-aware routing** | Requires integration with vLLM internals (llm-d) | v2+: advanced inference |
| **OCI Image Volumes** | K8s alpha feature for mounting models as OCI artifacts | When K8s promotes to GA |
| **Model registry integration** | Direct URI is sufficient for v1 | v2: MLflow/Weights&Biases integration |
| **Automatic size detection** | `size` hint is manual in v1; controller could query HF API | v1.1: quality of life |
