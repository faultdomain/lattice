# Inference Gateway

## Problem

Lattice deploys and scales model serving workloads (LatticeModel with Kthena routing), but there is no tenant-facing control plane for model consumption. Teams that deploy models need to expose them to internal consumers with rate limits, usage tracking, request queuing, and version-based routing — all of which currently require bespoke application code.

Kthena provides model-level traffic routing (A/B between model versions, prefill/decode disaggregation), but it operates at the infrastructure layer. There is no tenant-aware layer that answers: "Which team sent this request? Have they exceeded their quota? How many tokens did they consume?"

## Goals

- Provide a `LatticeInferenceGateway` CRD for tenant-facing model access control
- Per-tenant rate limiting (requests/minute, tokens/minute)
- Token-level usage metering (input/output tokens per request, per tenant)
- Request queuing during scale-up (return position in queue instead of 503)
- Model version routing (A/B testing at the tenant level)
- Integration with existing Cedar authorization for model access control
- Metrics exported to VictoriaMetrics for dashboarding and chargeback

## Non-Goals

- Replacing Kthena (Kthena handles model-level routing; this sits in front of it)
- Prompt filtering / content safety (separate concern)
- Model registry / versioning (models are deployed via LatticeModel)
- External-facing API gateway (this is for internal platform consumers)

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Consumer Teams                                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                          │
│  │ Team A   │  │ Team B   │  │ Team C   │                          │
│  │ API key  │  │ API key  │  │ API key  │                          │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘                          │
└───────┼──────────────┼──────────────┼───────────────────────────────┘
        │              │              │
        ▼              ▼              ▼
┌──────────────────────────────────────────────────────────────────────┐
│              LatticeInferenceGateway (Envoy + ext_proc)             │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  1. Authenticate (API key → tenant identity)                  │ │
│  │  2. Authorize (Cedar: can tenant access this model?)          │ │
│  │  3. Rate limit (per-tenant token/request budgets)             │ │
│  │  4. Queue (if model scaling up, hold request)                 │ │
│  │  5. Route (tenant → model version mapping)                    │ │
│  │  6. Meter (count input/output tokens, record latency)         │ │
│  └────────────────────────────────────────────────────────────────┘ │
└────────────────────────────┬─────────────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    Kthena ModelServer / ModelRoute                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │
│  │ model-v1     │  │ model-v2     │  │ model-v3     │             │
│  │ (LatticeModel│  │ (LatticeModel│  │ (LatticeModel│             │
│  │  serving)    │  │  canary)     │  │  shadow)     │             │
│  └──────────────┘  └──────────────┘  └──────────────┘             │
└──────────────────────────────────────────────────────────────────────┘
```

## Detailed Design

### CRD: LatticeInferenceGateway

```rust
pub struct LatticeInferenceGatewaySpec {
    /// The LatticeModel(s) this gateway fronts.
    pub model_refs: Vec<ModelRef>,

    /// Gateway replicas (the proxy layer itself).
    pub replicas: u32,                          // default: 2

    /// Autoscaling for the gateway pods.
    pub autoscaling: Option<AutoscalingSpec>,

    /// Tenant definitions and their access policies.
    pub tenants: BTreeMap<String, TenantSpec>,

    /// Default rate limits applied when a tenant has no override.
    pub default_rate_limit: Option<RateLimitSpec>,

    /// Request queue configuration for handling scale-up latency.
    pub queue: Option<QueueSpec>,

    /// Port the gateway listens on.
    pub port: Option<u16>,                      // default: 8080

    /// OpenAI-compatible API mode. When enabled, the gateway speaks
    /// the /v1/chat/completions and /v1/completions protocol.
    pub openai_compatible: bool,                // default: true
}

pub struct ModelRef {
    /// Name of the LatticeModel resource.
    pub name: String,

    /// Namespace (defaults to same namespace as gateway).
    pub namespace: Option<String>,

    /// Version tag for routing (e.g., "v1", "canary").
    pub version: Option<String>,
}

pub struct TenantSpec {
    /// Display name for dashboards.
    pub display_name: Option<String>,

    /// API key hash (bcrypt). The raw key is distributed out-of-band.
    /// Multiple keys supported for rotation.
    pub api_key_hashes: Vec<String>,

    /// Rate limits for this tenant (overrides default_rate_limit).
    pub rate_limit: Option<RateLimitSpec>,

    /// Model version routing. Maps model name to version preference.
    /// If omitted, routes to the primary (first) model_ref.
    pub routing: Option<TenantRoutingSpec>,

    /// Whether this tenant is active. Disabled tenants get 403.
    pub enabled: bool,                          // default: true
}

pub struct RateLimitSpec {
    /// Maximum requests per time window.
    pub requests_per_minute: Option<u32>,

    /// Maximum input tokens per time window.
    pub input_tokens_per_minute: Option<u32>,

    /// Maximum output tokens per time window.
    pub output_tokens_per_minute: Option<u32>,

    /// Maximum concurrent requests (in-flight at any time).
    pub max_concurrent: Option<u32>,

    /// Behavior when limit is hit.
    pub on_limit: RateLimitAction,              // default: Reject
}

pub enum RateLimitAction {
    Reject,    // Return 429 immediately
    Queue,     // Hold in queue until budget available
}

pub struct TenantRoutingSpec {
    /// Route traffic to specific model versions with weights.
    pub routes: Vec<TenantRoute>,
}

pub struct TenantRoute {
    /// Model version tag (must match a model_ref.version).
    pub version: String,

    /// Traffic weight (0-100). Weights across routes must sum to 100.
    pub weight: u32,
}

pub struct QueueSpec {
    /// Maximum number of requests to hold in queue.
    pub max_size: u32,                          // default: 1000

    /// Maximum time a request can wait in queue before being dropped.
    pub timeout: String,                        // default: "60s"

    /// Whether to return queue position in response headers.
    pub report_position: bool,                  // default: true
}

pub enum InferenceGatewayPhase {
    Pending,
    Ready,
    Degraded,   // some model backends unavailable
    Failed,
}

pub struct LatticeInferenceGatewayStatus {
    pub phase: InferenceGatewayPhase,
    pub message: Option<String>,
    pub conditions: Vec<Condition>,
    pub observed_generation: Option<i64>,
    pub endpoint: Option<String>,              // internal service URL
    pub active_tenants: u32,
    pub active_models: u32,
    pub queue_depth: u32,
}
```

### Compilation: Gateway -> Deployment + Service + Mesh

The inference gateway controller compiles the CRD into:

**Deployment** — Envoy proxy with an external processing (ext_proc) filter pointing to a Lattice-built sidecar that handles auth, rate limiting, metering, and queuing.

**Service** — ClusterIP service for internal access.

**LatticeMeshMember** — Enrolled in the mesh with:
- Inbound: allowed from tenant service accounts (or all, if no mesh enforcement needed)
- Outbound: dependency on the target LatticeModel's service

**ConfigMap** — Tenant configuration, rate limits, routing rules (watched by the ext_proc sidecar for hot-reload).

### Component: ext_proc Sidecar

The core gateway logic runs as an Envoy ext_proc gRPC service. This is a Rust binary (part of the Lattice operator image) that handles the request lifecycle:

```
Request flow through ext_proc:

1. request_headers phase:
   ├─ Extract API key from Authorization header
   ├─ Hash and lookup tenant
   ├─ Cedar authorization check
   ├─ Check rate limits (requests + concurrent)
   ├─ If rate limited and on_limit=Queue → hold request
   ├─ Set routing headers (X-Model-Version → Kthena route)
   └─ Return: continue (with modified headers) or deny (429/403)

2. request_body phase:
   ├─ Parse request body (OpenAI format: messages array)
   ├─ Count input tokens (tiktoken or model-specific tokenizer)
   ├─ Check input token rate limit
   └─ Return: continue or deny (429)

3. response_body phase:
   ├─ Parse response body (choices, usage field)
   ├─ Extract output token count from response usage field
   ├─ Record metrics: input_tokens, output_tokens, latency, model_version
   ├─ Decrement concurrent request counter
   └─ Return: continue (with metering headers injected)
```

**Why ext_proc instead of a standalone proxy:**
- Envoy handles TLS, HTTP/2, connection pooling, retries — we don't reimplement
- ext_proc is a standard Envoy filter, not a fork
- Hot-reloadable config without proxy restart
- Lattice already runs Envoy via Istio ambient mesh

### Token Counting

For metering accuracy, the gateway needs token counts. Two strategies:

**Strategy A (preferred): Trust the model response.** OpenAI-compatible APIs return a `usage` field:
```json
{"usage": {"prompt_tokens": 42, "completion_tokens": 128, "total_tokens": 170}}
```
The ext_proc response phase reads this field. Zero overhead, exact count.

**Strategy B (fallback): Estimate from request.** For streaming responses or non-OpenAI APIs, estimate input tokens from the request body using a fast tokenizer approximation (word count * 1.3 for English). Output tokens counted from SSE chunk count. Less accurate but works universally.

The gateway defaults to Strategy A and falls back to Strategy B when the response lacks a `usage` field.

### Rate Limiting Implementation

Rate limits use a sliding window counter stored in the ext_proc sidecar's memory (not Redis — no external dependency). Each gateway replica maintains independent counters.

**Per-replica vs global rate limits:**
- With N replicas, each replica enforces `limit / N` per window
- This is approximate but avoids cross-replica coordination latency
- Acceptable for internal platform use (not billing-grade)
- ConfigMap reload recalculates per-replica limits when replicas change

**Token-based rate limiting:**
- Input tokens checked at request time (pre-inference)
- Output tokens checked at response time (post-inference) and debited against next window
- If output tokens exceed budget, the request is already complete — the overage is logged and counted against the next window

### Request Queue

When a model is scaling up (KEDA triggered, pods not yet ready) or a tenant hits a rate limit with `on_limit: Queue`, requests enter a bounded in-memory queue.

```
Queue behavior:
- FIFO ordering per tenant
- Total queue bounded by spec.queue.max_size across all tenants
- Per-request timeout from spec.queue.timeout
- Response headers when queued:
    X-Queue-Position: 5
    X-Queue-Estimated-Wait: 12s
    Retry-After: 12
- If queue is full, returns 503 with Retry-After header
- Queue drains as model pods become ready or rate limit window resets
```

**Health-aware queuing:** The ext_proc sidecar watches the target model's endpoint health. If all model pods are down (not just scaling), requests are rejected immediately rather than queued.

### Cedar Integration

Model access control uses the existing Cedar policy engine:

```cedar
// Allow the "ml-team" tenant to access the "llama-70b" model
permit(
  principal == Lattice::Tenant::"ml-team",
  action == Lattice::Action::"InferenceRequest",
  resource == Lattice::Model::"default/llama-70b"
);

// Deny the "intern-team" tenant from using expensive models
forbid(
  principal == Lattice::Tenant::"intern-team",
  action == Lattice::Action::"InferenceRequest",
  resource == Lattice::Model::"default/llama-70b"
);
```

New Cedar entity types:
- `Lattice::Tenant::"{tenant-name}"` — maps from gateway tenant spec
- `Lattice::Model::"{namespace}/{model-name}"` — maps from LatticeModel
- `Lattice::Action::"InferenceRequest"` — new action type

### Metrics & Metering

The ext_proc sidecar exposes a `/metrics` endpoint (Prometheus format) scraped by vmagent via a VMServiceScrape (same pattern as LatticeService metrics).

```
# Per-tenant request metrics
lattice_inference_requests_total{tenant, model, version, status_code}
lattice_inference_request_duration_seconds{tenant, model, version}  # histogram

# Per-tenant token metrics
lattice_inference_input_tokens_total{tenant, model, version}
lattice_inference_output_tokens_total{tenant, model, version}

# Rate limiting metrics
lattice_inference_rate_limited_total{tenant, model, reason}  # reason: requests|tokens|concurrent
lattice_inference_queued_total{tenant, model}
lattice_inference_queue_timeout_total{tenant, model}

# Queue metrics
lattice_inference_queue_depth{model}
lattice_inference_queue_wait_seconds{tenant, model}  # histogram
```

**Cost attribution query example:**

```promql
# Total tokens consumed by tenant "ml-team" on model "llama-70b" in the last 24h
sum(increase(lattice_inference_input_tokens_total{tenant="ml-team", model="llama-70b"}[24h]))
+
sum(increase(lattice_inference_output_tokens_total{tenant="ml-team", model="llama-70b"}[24h]))
```

Combined with GPU-hours from the GPU Observability feature, this enables full cost attribution: GPU-hours per model + tokens per tenant per model.

### Recording Rules

```yaml
apiVersion: operator.victoriametrics.com/v1beta1
kind: VMRule
metadata:
  name: inference-gateway-rollups
  namespace: monitoring
spec:
  groups:
    - name: inference.tenant_rollups
      interval: 1m
      rules:
        # Tokens per tenant per hour (for chargeback)
        - record: lattice:inference:tenant_tokens_per_hour
          expr: |
            sum by (tenant, model) (
              rate(lattice_inference_input_tokens_total[1h])
              + rate(lattice_inference_output_tokens_total[1h])
            ) * 3600

        # P99 latency per model (for SLO tracking)
        - record: lattice:inference:model_p99_latency
          expr: |
            histogram_quantile(0.99,
              sum by (model, le) (
                rate(lattice_inference_request_duration_seconds_bucket[5m])
              )
            )

        # Error rate per model (for health)
        - record: lattice:inference:model_error_rate
          expr: |
            sum by (model) (rate(lattice_inference_requests_total{status_code=~"5.."}[5m]))
            / sum by (model) (rate(lattice_inference_requests_total[5m]))
```

## Implementation Plan

### Step 1: CRD & Types (lattice-common)

- Add `crd/inference_gateway.rs` with full spec/status types
- Register in `CrdRegistry`
- Add `CrdKind::InferenceGateway` variant
- Add Cedar entity types for `Tenant` and `Model`

### Step 2: ext_proc Binary (new crate: lattice-inference-gateway)

- Create `crates/lattice-inference-gateway/`
- Implement Envoy ext_proc gRPC service in Rust
- API key authentication and tenant lookup
- Cedar policy evaluation for model access
- Sliding window rate limiter (in-memory)
- Request queue with bounded size and timeout
- Token counting from OpenAI-compatible response `usage` field
- Prometheus metrics endpoint

### Step 3: Controller (lattice-inference-gateway or lattice-service)

- Watch `LatticeInferenceGateway` resources
- Compile to: Deployment (Envoy + ext_proc sidecar), Service, ConfigMap
- Generate LatticeMeshMember with bilateral agreements
- Generate VMServiceScrape for metrics collection
- Generate recording rules for tenant rollups

### Step 4: Tenant Management

- API key generation utility (CLI command: `lattice gateway create-key`)
- Key hash storage in the CRD spec
- Key rotation support (multiple hashes per tenant)
- Tenant enable/disable without key regeneration

### Step 5: Testing

- Unit tests: rate limiter, token counter, queue behavior
- Integration test: deploy gateway + mock model, verify auth and rate limiting
- Integration test: verify metrics emission and VictoriaMetrics scraping
- Integration test: Cedar policy enforcement (permit/forbid tenant access)
- E2E test: gateway + LatticeModel with real inference traffic

## CRD Changes

New CRD: `LatticeInferenceGateway` (apiVersion: `lattice.io/v1alpha1`, kind: `LatticeInferenceGateway`)

Extended Cedar schema:
- New entity type: `Lattice::Tenant`
- New entity type: `Lattice::Model`
- New action: `Lattice::Action::"InferenceRequest"`

No changes to existing CRDs.

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Per-replica rate limits are approximate | Acceptable for internal use; document the N-replica dilution behavior; add global mode via Redis later if needed |
| Token counting adds latency on response path | Parsing `usage` field is negligible; fallback estimation is O(1) approximation |
| ext_proc failure blocks all requests | Deploy with PodDisruptionBudget; Envoy can be configured with ext_proc failure_mode_allow for degraded operation |
| Queue memory pressure under load | Bounded queue size + request timeout; reject when full rather than OOM |
| API key in CRD spec (even hashed) | bcrypt hashes are safe to store; raw keys never stored; rotation via multiple hashes |
| Streaming responses lack usage field | Fall back to chunk-count estimation; document accuracy tradeoff |
