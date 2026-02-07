# Lattice Autoscaling v1

> **Generalized HPA with custom metrics for LatticeService workloads.**
>
> Today, every LatticeService with `replicas.max` gets an HPA hardcoded to CPU 80%.
> This is wrong for GPU inference (scale on queue depth), memory-bound workloads,
> and anything where CPU utilization is not the right signal. v1 generalizes the
> autoscaling spec so users declare what to scale on and at what threshold.

---

## Problem

The service compiler hardcodes a single HPA metric:

```rust
// crates/lattice-service/src/workload/mod.rs:1359-1367
metrics: vec![MetricSpec {
    type_: "Resource".to_string(),
    resource: Some(ResourceMetricSource {
        name: "cpu".to_string(),
        target: MetricTarget {
            type_: "Utilization".to_string(),
            average_utilization: Some(80),
        },
    }),
}],
```

Users cannot:
- Change the CPU threshold (80% is too aggressive for bursty workloads)
- Scale on memory pressure
- Scale on custom metrics (vLLM queue depth, request latency, active connections)
- Use multiple signals (scale on CPU *or* queue depth, whichever triggers first)

## Solution

1. Add an `autoscaling` field to `ReplicaSpec` with user-defined metrics
2. The compiler translates each metric into the correct HPA v2 metric type
3. Default to CPU 80% when `autoscaling` is empty (backwards compatible)
4. Deploy KEDA on GPU-enabled clusters for custom metrics

KEDA ScaledObjects query Prometheus directly and manage scaling for custom
metrics like vLLM inference queue depth, token throughput, and latency.

---

## CRD Changes

### ReplicaSpec (extended)

```rust
// crates/lattice-common/src/crd/service.rs

/// Replica scaling specification
pub struct ReplicaSpec {
    /// Minimum replicas (default: 1)
    pub min: u32,

    /// Maximum replicas (enables HPA when set)
    pub max: Option<u32>,

    /// Autoscaling metrics. Defaults to [{metric: "cpu", target: 80}] if empty.
    /// HPA scales when ANY metric exceeds its target (OR logic).
    pub autoscaling: Vec<AutoscalingMetric>,
}

/// A single autoscaling metric
pub struct AutoscalingMetric {
    /// Metric name: "cpu", "memory", or a custom metric name
    /// (e.g. "vllm_num_requests_waiting", "http_requests_per_second")
    pub metric: String,

    /// Target value:
    /// - For "cpu" and "memory": percentage (e.g. 80 = 80% utilization)
    /// - For custom metrics: average value per pod (e.g. 5 = scale when avg > 5)
    pub target: u32,
}
```

### YAML Examples

```yaml
# Existing behavior (no change needed, fully backwards compatible)
replicas:
  min: 1
  max: 4
# → HPA with CPU 80% (default)

# Lower CPU threshold for bursty workloads
replicas:
  min: 2
  max: 10
  autoscaling:
    - metric: cpu
      target: 60

# GPU inference — scale on vLLM queue depth
replicas:
  min: 1
  max: 8
  autoscaling:
    - metric: vllm_num_requests_waiting
      target: 5

# Multi-signal: scale on CPU or queue depth (whichever fires first)
replicas:
  min: 1
  max: 8
  autoscaling:
    - metric: cpu
      target: 70
    - metric: vllm_num_requests_waiting
      target: 5

# Memory-bound workload
replicas:
  min: 2
  max: 6
  autoscaling:
    - metric: memory
      target: 75
```

---

## Compiler Changes

### Metric Type Mapping

The compiler maps metric names to HPA v2 metric types:

| Metric Name | HPA Type | Target Field | Example |
|---|---|---|---|
| `cpu` | `Resource` | `averageUtilization` (%) | 80 → scale at 80% CPU |
| `memory` | `Resource` | `averageUtilization` (%) | 75 → scale at 75% memory |
| anything else | `Pods` | `averageValue` (absolute) | 5 → scale when avg > 5 |

`Resource` metrics are built into Kubernetes (metrics-server). `Pods` metrics
are handled by KEDA ScaledObjects with Prometheus triggers.

### compile_hpa Changes

```rust
// crates/lattice-service/src/workload/mod.rs

fn compile_hpa(
    name: &str,
    namespace: &str,
    spec: &LatticeServiceSpec,
) -> HorizontalPodAutoscaler {
    // Default to CPU 80% if no autoscaling metrics specified
    let metrics = if spec.replicas.autoscaling.is_empty() {
        vec![AutoscalingMetric {
            metric: "cpu".to_string(),
            target: 80,
        }]
    } else {
        spec.replicas.autoscaling.clone()
    };

    let hpa_metrics = metrics.iter().map(|m| match m.metric.as_str() {
        "cpu" | "memory" => MetricSpec {
            type_: "Resource".to_string(),
            resource: Some(ResourceMetricSource {
                name: m.metric.clone(),
                target: MetricTarget {
                    type_: "Utilization".to_string(),
                    average_utilization: Some(m.target),
                },
            }),
            pods: None,
        },
        _ => MetricSpec {
            type_: "Pods".to_string(),
            resource: None,
            pods: Some(PodsMetricSource {
                metric: MetricIdentifier {
                    name: m.metric.clone(),
                },
                target: MetricTarget {
                    type_: "AverageValue".to_string(),
                    average_value: Some(m.target.to_string()),
                    average_utilization: None,
                },
            }),
        },
    }).collect();

    HorizontalPodAutoscaler {
        // ... existing fields ...
        spec: HpaSpec {
            scale_target_ref: /* unchanged */,
            min_replicas: spec.replicas.min,
            max_replicas: spec.replicas.max.unwrap_or(spec.replicas.min),
            metrics: hpa_metrics,
        },
    }
}
```

### New Structs in workload/mod.rs

```rust
/// Pods metric source (for custom metrics)
pub struct PodsMetricSource {
    pub metric: MetricIdentifier,
    pub target: MetricTarget,
}

/// Metric identifier
pub struct MetricIdentifier {
    pub name: String,
}
```

### MetricSpec Extension

```rust
// Extend existing MetricSpec
pub struct MetricSpec {
    pub type_: String,
    pub resource: Option<ResourceMetricSource>,
    pub pods: Option<PodsMetricSource>,  // NEW
}

// Extend existing MetricTarget
pub struct MetricTarget {
    pub type_: String,
    pub average_utilization: Option<u32>,
    pub average_value: Option<String>,   // NEW — for Pods metrics
}
```

---

## Infrastructure: KEDA

Custom metrics (anything besides `cpu`/`memory`) are handled by KEDA ScaledObjects,
which query Prometheus directly and manage scaling. KEDA is deployed automatically on
GPU-enabled clusters (where vLLM metrics are the primary use case).

### Default Metrics

For vLLM / TGI workloads, KEDA ScaledObjects query the following Prometheus metrics:

| Prometheus Metric | ScaledObject Trigger Metric | What It Measures |
|---|---|---|
| `vllm:num_requests_waiting` | `vllm_num_requests_waiting` | Requests queued for inference |
| `vllm:avg_prompt_throughput_toks_per_s` | `vllm_prompt_throughput` | Token throughput |
| `vllm:avg_generation_throughput_toks_per_s` | `vllm_generation_throughput` | Generation speed |
| `tgi_queue_size` | `tgi_queue_size` | TGI request queue |

Users can also expose their own application metrics via Prometheus and reference
them in the `autoscaling` spec — no Lattice changes needed.

---

## Validation

```rust
// In LatticeServiceSpec::validate()

// Validate autoscaling metrics
for metric in &self.replicas.autoscaling {
    if metric.target == 0 {
        return Err(anyhow!("autoscaling target must be > 0"));
    }
    if (metric.metric == "cpu" || metric.metric == "memory") && metric.target > 100 {
        return Err(anyhow!(
            "autoscaling target for {} must be <= 100 (percentage)",
            metric.metric
        ));
    }
}

// Autoscaling without max replicas is a no-op (warn? error?)
if !self.replicas.autoscaling.is_empty() && self.replicas.max.is_none() {
    return Err(anyhow!(
        "autoscaling metrics require replicas.max to be set"
    ));
}
```

---

## Files Changed

| File | Change |
|---|---|
| `crates/lattice-common/src/crd/service.rs` | Add `autoscaling: Vec<AutoscalingMetric>` to `ReplicaSpec`, add `AutoscalingMetric` struct |
| `crates/lattice-service/src/workload/mod.rs` | Generalize `compile_hpa`, add `PodsMetricSource`, `MetricIdentifier`, extend `MetricSpec`/`MetricTarget` |
| `crates/lattice-infra/src/bootstrap/mod.rs` | Add `pub mod keda;` (GPU clusters only) |
| `crates/lattice-infra/src/bootstrap/keda.rs` | New — helm template for KEDA |
| `versions.toml` | Pin `KEDA_VERSION` |

---

## What v1 Does NOT Include

- **Scale-to-zero** — Min replicas is always >= 1. Cold starts on GPU workloads
  (30-120s model load) make scale-to-zero impractical for production inference.
  Revisit with Knative if demand emerges.
- **KEDA on non-GPU clusters** — v1 deploys KEDA on GPU clusters only.
  Non-GPU services use built-in `cpu`/`memory` metrics (no KEDA needed).
  Easy to extend later.
- **Custom KEDA trigger rules** — v1 ships with sensible defaults for vLLM/TGI.
  Advanced users who need custom metric triggers can configure KEDA ScaledObjects
  directly. A `metricsConfig` CRD field is a v2 concern.

---

## Implementation Phases

### Phase A: CRD + Compiler (no new infra)

1. Add `AutoscalingMetric` struct and `autoscaling` field to `ReplicaSpec`
2. Add `PodsMetricSource`, `MetricIdentifier` to workload module
3. Extend `MetricSpec` and `MetricTarget` with pods metric fields
4. Generalize `compile_hpa` to iterate user-defined metrics
5. Default to CPU 80% when `autoscaling` is empty
6. Add validation rules
7. Update tests

**Result**: Users can configure CPU/memory thresholds. Custom metrics compile
correctly but require KEDA to actually resolve at runtime.

### Phase B: KEDA Bootstrap (GPU clusters)

1. Add `keda.rs` to bootstrap module
2. Pin version in `versions.toml`
3. Include in GPU cluster bootstrap path
4. Configure default KEDA ScaledObject triggers for vLLM/TGI

**Result**: GPU clusters get KEDA automatically. Custom metrics
like `vllm_num_requests_waiting` work end-to-end with KEDA ScaledObjects.
