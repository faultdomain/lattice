# Canary Deployment Strategy for LatticeServices

## Status: Draft

## Problem

The `DeployStrategy::Canary` variant and `CanarySpec` fields (`interval`, `threshold`, `maxWeight`, `stepWeight`) are declared in the CRD and documented in `service-deployment.md`, but no implementation exists. Today, selecting `strategy: canary` only changes the Deployment's RollingUpdate parameters (0% maxUnavailable, 100% maxSurge) — no traffic shifting, metric analysis, or automated rollback occurs.

## Current State

**What exists:**
- `DeploySpec` / `CanarySpec` types in `crates/lattice-common/src/crd/workload/deploy.rs`
- `CompilerPhase` trait designed to emit arbitrary `DynamicResource` entries (Flagger, Argo, etc.)
- `VMServiceScrapePhase` as a working reference implementation of a compiler phase
- Istio Ambient mode (ztunnel L4 + waypoint L7) — no sidecars
- Gateway API (HTTPRoute, GRPCRoute, TCPRoute) for ingress
- Weighted routing already implemented in the model-serving subsystem (LatticeModel → Volcano ModelRoute)
- VictoriaMetrics for metrics collection

**What's missing:**
- Traffic splitting between canary and stable pod sets
- Metric-driven progression / automated rollback
- A controller or external tool that orchestrates the rollout

## Requirements

- Progressive traffic shifting from 0% → `maxWeight` in `stepWeight` increments
- Automatic rollback when error rate exceeds `threshold` within an `interval`
- Works with Istio Ambient mode (no sidecar injection)
- Integrates with existing bilateral mesh agreements (AuthorizationPolicy + CiliumNetworkPolicy)
- Observable: canary status visible on the LatticeService status subresource
- No new inbound connections on workload clusters (outbound-only architecture)

---

## Option A: Flagger

[Flagger](https://flagger.app/) is a CNCF project that automates canary, A/B, and blue-green deployments on Kubernetes.

### How It Works

Flagger watches a target Deployment. When it detects a change (image tag, config, etc.), it:
1. Scales up a canary Deployment (`<name>-canary`)
2. Creates/updates an HTTPRoute (or VirtualService) with weighted backends
3. Queries a metrics provider (Prometheus/VictoriaMetrics) at each `interval`
4. Increments traffic weight by `stepWeight` if metrics pass
5. Rolls back if the error threshold is breached
6. Promotes by swapping the stable Deployment to the new version

### Integration with Lattice

**Compiler phase:** A new `FlaggerCanaryPhase` implementing `CompilerPhase` would:
- Check `spec.deploy.strategy == Canary`
- Emit a Flagger `Canary` CR as a `DynamicResource`
- Map `CanarySpec` fields directly to Flagger's `spec.analysis`

```yaml
apiVersion: flagger.app/v1beta1
kind: Canary
metadata:
  name: my-service
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: my-service
  service:
    port: 8080
    targetPort: 8080
    gatewayRefs:                     # Gateway API integration
      - name: mesh
        namespace: istio-system
        group: gateway.networking.k8s.io
        kind: Gateway
  analysis:
    interval: 60s                    # from CanarySpec.interval
    threshold: 5                     # from CanarySpec.threshold
    maxWeight: 50                    # from CanarySpec.max_weight
    stepWeight: 10                   # from CanarySpec.step_weight
    metrics:
      - name: request-success-rate
        thresholdRange:
          min: 99
        interval: 1m
      - name: request-duration
        thresholdRange:
          max: 500
        interval: 1m
    webhooks: []                     # Optional: conformance tests, load tests
```

**Mesh compatibility:** Flagger supports Istio Ambient mode via Gateway API since v1.37. It creates HTTPRoute resources with `backendRef` weights pointing at `<name>-primary` and `<name>-canary` Services. This works with waypoint proxies for L7 traffic management.

**Metric provider:** Flagger supports Prometheus-compatible APIs. VictoriaMetrics exposes a Prometheus-compatible query endpoint, so no adapter is needed. Configure via Flagger's `--metrics-server` flag.

### What We'd Need to Build

- `FlaggerCanaryPhase` (CompilerPhase impl) — ~200 lines
- Register Flagger `Canary` CRD kind in `crd_registry.rs`
- Flagger Helm chart added to cluster bootstrap (lattice-infra)
- Map `CanarySpec` fields to Flagger analysis config
- Status propagation: watch Flagger Canary status → update LatticeService status

### Pros

- Mature, battle-tested (CNCF graduated project)
- Native Gateway API + Istio Ambient support
- Built-in metrics analysis (Prometheus/VictoriaMetrics compatible)
- Handles the hard parts: replica management, traffic splitting, rollback
- Webhook extensibility for conformance testing and load generation
- Small integration surface — just emit the right CR

### Cons

- Another operator to deploy and maintain (Flagger controller)
- Flagger creates its own `-primary` and `-canary` Services, which may conflict with our mesh policy generation (AuthorizationPolicy targets Service names)
- Limited customization of the analysis pipeline
- Flagger's Service-renaming behavior (`my-service` → `my-service-primary`) requires mesh policy awareness
- CRD version coupling — Flagger CRD changes could break our emitted resources

### Mesh Policy Concern (Critical)

Flagger renames the original Service to `<name>-primary` and creates a new Service with the original name as a "virtual" router. This means:
- `AuthorizationPolicy` rules targeting `my-service` would hit Flagger's virtual Service (correct for traffic flow)
- `CiliumNetworkPolicy` pod selectors need to match both primary and canary pods
- The `LatticeMeshMember` controller would need to be aware of Flagger's naming convention

**Mitigation:** The mesh-member controller already generates policies based on pod labels, not Service names. If Flagger preserves the `app: my-service` label on both pod sets (which it does by default), existing L4 policies continue to work. L7 AuthorizationPolicies using Service targetRefs would need adjustment to target the Flagger virtual Service.

---

## Option B: Argo Rollouts

[Argo Rollouts](https://argoproj.github.io/rollouts/) is a Kubernetes controller for progressive delivery.

### How It Works

Replaces the Deployment with a `Rollout` resource that natively supports canary and blue-green strategies. It manages ReplicaSets directly and integrates with traffic routers (Istio, Gateway API, etc.) for weighted splitting.

### Integration with Lattice

Would require the `ServiceCompiler` to emit a `Rollout` instead of a `Deployment` when `strategy: canary`. This is a more invasive change than Flagger since Flagger wraps an existing Deployment.

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: my-service
spec:
  replicas: 3
  strategy:
    canary:
      steps:
        - setWeight: 10
        - pause: { duration: 60s }
        - setWeight: 20
        - pause: { duration: 60s }
        - setWeight: 50
        - pause: { duration: 60s }
      trafficRouting:
        plugins:
          argoproj-labs/gatewayAPI:
            httpRoute: my-service
            namespace: default
      analysis:
        templates:
          - templateName: success-rate
        startingStep: 2
        args:
          - name: service-name
            value: my-service
```

### What We'd Need to Build

- Replace Deployment generation with Rollout when canary is selected — invasive change to `WorkloadCompiler`
- Register Rollout CRD in `crd_registry.rs`
- Argo Rollouts controller + Gateway API plugin deployed to cluster
- `AnalysisTemplate` resources for metrics queries
- Convert `CanarySpec` step-based config into Argo's explicit step list

### Pros

- Very flexible analysis and step definitions
- First-class Gateway API support via plugin
- Active community and development
- Can define arbitrary step sequences (pause, setWeight, analysis)
- No Service renaming — uses the original Service with injected routing

### Cons

- Replaces Deployment with Rollout CRD — much more invasive than Flagger
- Everything that consumes Deployment objects (PDBs, HPA/KEDA ScaledObject, monitoring) needs to target Rollout instead
- Gateway API support is via a separate plugin (not built-in)
- Heavier footprint: controller + plugin + AnalysisTemplate CRDs
- Step-based config doesn't map cleanly from our `stepWeight`/`maxWeight` model (need to generate explicit step lists)

---

## Option C: Build It Ourselves

Implement canary orchestration as a native Lattice controller.

### How It Would Work

A new `CanaryController` watches LatticeServices with `strategy: canary`. On Deployment change:

1. **Detect**: Deployment spec changed (image, env, configmap hash)
2. **Create canary**: Scale a second Deployment (`<name>-canary`) with the new spec
3. **Shift traffic**: Create/update HTTPRoute with weighted `backendRefs` pointing at stable and canary Services
4. **Analyze**: Query VictoriaMetrics for error rate on canary pods
5. **Progress or rollback**: Increment weight or revert based on metrics
6. **Promote**: Update the primary Deployment, delete canary resources

### Architecture

```
LatticeService (strategy: canary)
  │
  ├── ServiceCompiler emits:
  │   ├── Deployment (primary, pinned to current spec)
  │   ├── Service (primary)
  │   ├── Deployment (canary, new spec) — only during rollout
  │   ├── Service (canary) — only during rollout
  │   └── HTTPRoute with weighted backendRefs
  │
  └── CanaryController:
      ├── Watches LatticeService + Deployment
      ├── Detects spec drift → starts rollout
      ├── Manages weight progression via HTTPRoute
      ├── Queries VictoriaMetrics for analysis
      └── Updates LatticeService status with canary state
```

### Traffic Splitting with Gateway API + Istio Ambient

Istio Ambient's waypoint proxy respects Gateway API HTTPRoute weights natively:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-service
spec:
  parentRefs:
    - kind: Service
      name: my-service
      port: 8080
  rules:
    - backendRefs:
        - name: my-service-primary
          port: 8080
          weight: 90
        - name: my-service-canary
          port: 8080
          weight: 10
```

This works because in Ambient mode, any Service-to-Service traffic that passes through a waypoint evaluates HTTPRoute rules. No VirtualService or DestinationRule needed.

### What We'd Need to Build

- **CanaryController** (~800-1200 lines): reconcile loop managing rollout state machine
- **Rollout state machine**: Pending → Progressing → Paused → Promoting → Completed / RolledBack
- **Metrics client**: VictoriaMetrics query client for success rate / latency analysis
- **HTTPRoute generation**: Weighted backend refs, integrated into compiler or controller
- **Canary Deployment generation**: Clone primary Deployment with new spec
- **Status subresource**: `LatticeServiceStatus.canary` field with weight, phase, last analysis
- **CRD update**: Add canary status fields to LatticeService

### Pros

- Full control over behavior — no external CRD coupling
- No Service renaming — we control the naming convention
- Native integration with bilateral mesh agreements
- Canary-aware mesh policies from the start
- No additional operators to deploy
- Status directly on LatticeService (no cross-resource status propagation)
- Can leverage existing VictoriaMetrics integration
- Simpler operational model (one operator, not two)

### Cons

- Significant engineering effort (state machine, metrics analysis, edge cases)
- Must handle all failure modes ourselves (controller crash during rollout, partial state)
- Must implement analysis that Flagger/Argo get for free
- Testing complexity — canary rollouts have many edge cases
- Risk of bugs in traffic shifting logic that are already solved in mature tools

---

## Comparison Matrix

| Criteria | Flagger | Argo Rollouts | Build Ourselves |
|---|---|---|---|
| **Integration effort** | Low (~200 lines) | High (replace Deployment) | High (~1200 lines) |
| **Mesh policy compatibility** | Medium (Service renaming) | Good (no renaming) | Best (native) |
| **Istio Ambient support** | Yes (Gateway API) | Yes (plugin) | Yes (Gateway API) |
| **Operational overhead** | +1 operator | +1 operator + plugin | None |
| **Customization** | Limited | High | Full |
| **Maturity** | High (CNCF) | High (Argo ecosystem) | None — we build it |
| **Metrics integration** | Built-in (Prometheus compat) | Built-in (AnalysisTemplate) | Must build |
| **CRD coupling** | Flagger CRD versions | Rollout CRD versions | Our own CRD |
| **Time to MVP** | ~1-2 weeks | ~3-4 weeks | ~4-6 weeks |
| **Maintenance burden** | Low (upstream fixes) | Low (upstream fixes) | High (all on us) |

---

## Recommendation: Flagger (Option A)

Flagger is the best fit for Lattice because:

- **Minimal integration surface**: A single `CompilerPhase` emitting a Flagger `Canary` CR. The `CompilerPhase` architecture was literally designed for this use case.
- **Gateway API + Istio Ambient**: Flagger has first-class support for exactly our traffic management stack. It generates HTTPRoute resources with weighted backends that waypoint proxies evaluate natively.
- **VictoriaMetrics compatible**: Flagger queries a Prometheus-compatible endpoint. VictoriaMetrics exposes one. Zero adapter work.
- **CanarySpec maps 1:1**: Our existing `interval`, `threshold`, `maxWeight`, `stepWeight` fields map directly to Flagger's `spec.analysis` — no CRD changes needed.
- **Battle-tested edge cases**: Controller crash recovery, partial rollout cleanup, metric query failures — all handled by a mature codebase.

The Service-renaming concern is manageable: Flagger preserves pod labels, so L4 CiliumNetworkPolicy continues to work. L7 AuthorizationPolicy needs minor adjustment in the mesh-member controller to account for Flagger's virtual Service pattern.

### Implementation Plan

**Phase 1: Core Integration**
- Add Flagger Helm chart to cluster bootstrap in `lattice-infra`
- Register `Canary` CRD kind in `crd_registry.rs`
- Implement `FlaggerCanaryPhase` as a `CompilerPhase`
- Map `CanarySpec` → Flagger `Canary` CR with VictoriaMetrics metrics
- Emit Canary as a `DynamicResource` with `ApplyLayer::Workload`

**Phase 2: Mesh Awareness**
- Update mesh-member controller to handle Flagger's `-primary` / `-canary` Service pattern
- Ensure AuthorizationPolicy targets are correct during canary rollouts
- Verify CiliumNetworkPolicy covers both primary and canary pod selectors

**Phase 3: Status & Observability**
- Watch Flagger Canary status → propagate to `LatticeServiceStatus`
- Add canary weight, phase, and last analysis result to status
- Surface canary state in `lattice` CLI

**Phase 4: Testing**
- Unit tests for `FlaggerCanaryPhase` compilation
- Integration test: deploy canary, verify HTTPRoute weights, verify rollback on bad metrics
- E2E test: full canary lifecycle with mesh traffic verification

### Escape Hatch

If Flagger's constraints become limiting (e.g., Ambient mode regressions, Service renaming causes unforeseen mesh issues), we can replace `FlaggerCanaryPhase` with a native controller (Option C) without changing the CRD or user-facing API. The `CanarySpec` fields and `DeployStrategy::Canary` enum remain the same — only the implementation behind the `CompilerPhase` changes. This is the key advantage of the compiler phase architecture.
