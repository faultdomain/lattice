//! Metrics registry for Lattice observability
//!
//! Provides OpenTelemetry metrics for:
//! - Cluster lifecycle (provisioning, ready)
//! - K8s API proxy (request counts, latency)
//! - Cedar authorization (decision counts)
//! - GPU health (node state, cordon operations)

use once_cell::sync::Lazy;
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Gauge, Histogram, Meter};

/// Global meter for Lattice metrics
static METER: Lazy<Meter> = Lazy::new(|| global::meter("lattice"));

// ============================================================================
// Cluster Lifecycle Metrics
// ============================================================================

/// Gauge tracking total clusters by phase
///
/// Labels:
/// - `phase`: pending, provisioning, pivoting, ready, failed, deleting
pub static CLUSTERS_TOTAL: Lazy<Gauge<i64>> = Lazy::new(|| {
    METER
        .i64_gauge("lattice_clusters_total")
        .with_description("Total number of clusters by phase")
        .with_unit("{clusters}")
        .build()
});

/// Histogram of cluster reconciliation duration
///
/// Labels:
/// - `cluster`: cluster name
/// - `result`: success, error
pub static CLUSTER_RECONCILE_DURATION: Lazy<Histogram<f64>> = Lazy::new(|| {
    METER
        .f64_histogram("lattice_cluster_reconcile_duration_seconds")
        .with_description("Duration of cluster reconciliation in seconds")
        .with_unit("s")
        .build()
});

/// Counter of cluster reconciliation errors
///
/// Labels:
/// - `cluster`: cluster name
/// - `error_type`: transient, permanent
pub static CLUSTER_RECONCILE_ERRORS: Lazy<Counter<u64>> = Lazy::new(|| {
    METER
        .u64_counter("lattice_cluster_reconcile_errors_total")
        .with_description("Total number of cluster reconciliation errors")
        .with_unit("{errors}")
        .build()
});

// ============================================================================
// Agent Connection Metrics
// ============================================================================

/// Gauge of agent heartbeat age in seconds
///
/// Labels:
/// - `cluster`: cluster name
pub static AGENT_HEARTBEAT_AGE: Lazy<Gauge<f64>> = Lazy::new(|| {
    METER
        .f64_gauge("lattice_agent_heartbeat_age_seconds")
        .with_description("Age of last agent heartbeat in seconds")
        .with_unit("s")
        .build()
});

// ============================================================================
// K8s API Proxy Metrics
// ============================================================================

/// Counter of proxy requests
///
/// Labels:
/// - `method`: GET, POST, PUT, DELETE, WATCH
/// - `status`: 2xx, 4xx, 5xx
/// - `cluster`: target cluster name
pub static PROXY_REQUESTS: Lazy<Counter<u64>> = Lazy::new(|| {
    METER
        .u64_counter("lattice_proxy_requests_total")
        .with_description("Total number of K8s API proxy requests")
        .with_unit("{requests}")
        .build()
});

/// Histogram of proxy request duration
///
/// Labels:
/// - `method`: GET, POST, PUT, DELETE, WATCH
/// - `cluster`: target cluster name
pub static PROXY_REQUEST_DURATION: Lazy<Histogram<f64>> = Lazy::new(|| {
    METER
        .f64_histogram("lattice_proxy_request_duration_seconds")
        .with_description("Duration of K8s API proxy requests in seconds")
        .with_unit("s")
        .build()
});

// ============================================================================
// Authorization Metrics
// ============================================================================

/// Counter of Cedar authorization decisions
///
/// Labels:
/// - `decision`: allow, deny
/// - `action`: get, list, watch, create, update, delete
pub static CEDAR_DECISIONS: Lazy<Counter<u64>> = Lazy::new(|| {
    METER
        .u64_counter("lattice_cedar_decisions_total")
        .with_description("Total number of Cedar authorization decisions")
        .with_unit("{decisions}")
        .build()
});

/// Counter of Cedar policy engine load failures.
///
/// Incremented when the operator falls back to default-deny because Cedar
/// policies could not be loaded from CRDs. A non-zero value indicates the
/// operator is running without configured Cedar policies.
pub static CEDAR_LOAD_FAILURES: Lazy<Counter<u64>> = Lazy::new(|| {
    METER
        .u64_counter("lattice_cedar_load_failures_total")
        .with_description("Total failures loading Cedar policies from CRDs (fallback to default-deny)")
        .with_unit("{failures}")
        .build()
});

/// Record a Cedar policy engine load failure
pub fn record_cedar_load_failure() {
    CEDAR_LOAD_FAILURES.add(1, &[]);
}

// ============================================================================
// GPU Health Metrics
// ============================================================================

/// Gauge: total GPU nodes in cluster
pub static GPU_NODES_TOTAL: Lazy<Gauge<i64>> = Lazy::new(|| {
    METER
        .i64_gauge("lattice_gpu_nodes_total")
        .with_description("Total number of GPU nodes in cluster")
        .with_unit("{nodes}")
        .build()
});

/// Gauge: currently cordoned GPU nodes
pub static GPU_NODES_CORDONED: Lazy<Gauge<i64>> = Lazy::new(|| {
    METER
        .i64_gauge("lattice_gpu_nodes_cordoned")
        .with_description("Number of currently cordoned GPU nodes")
        .with_unit("{nodes}")
        .build()
});

/// Counter: cordon operations performed
pub static GPU_CORDONS_TOTAL: Lazy<Counter<u64>> = Lazy::new(|| {
    METER
        .u64_counter("lattice_gpu_cordons_total")
        .with_description("Total cordon operations performed on GPU nodes")
        .with_unit("{operations}")
        .build()
});

/// Counter: uncordon operations performed
pub static GPU_UNCORDONS_TOTAL: Lazy<Counter<u64>> = Lazy::new(|| {
    METER
        .u64_counter("lattice_gpu_uncordons_total")
        .with_description("Total uncordon operations performed on GPU nodes")
        .with_unit("{operations}")
        .build()
});

/// Counter: cordon threshold hit (suppressed cordons)
pub static GPU_CORDON_THRESHOLD_HITS: Lazy<Counter<u64>> = Lazy::new(|| {
    METER
        .u64_counter("lattice_gpu_cordon_threshold_hits_total")
        .with_description("Times the GPU cordon threshold was hit (>50% cordoned)")
        .with_unit("{hits}")
        .build()
});

/// Gauge: max pending GPU request (0 if none)
pub static GPU_PENDING_REQUEST_MAX: Lazy<Gauge<i64>> = Lazy::new(|| {
    METER
        .i64_gauge("lattice_gpu_pending_request_max")
        .with_description("Maximum pending GPU request size (0 if none)")
        .with_unit("{gpus}")
        .build()
});

/// Record GPU health reconciliation results
pub fn record_gpu_health(
    total_nodes: i64,
    cordoned_nodes: i64,
    cordons: u64,
    uncordons: u64,
    threshold_hit: bool,
    max_pending_request: i64,
) {
    GPU_NODES_TOTAL.record(total_nodes, &[]);
    GPU_NODES_CORDONED.record(cordoned_nodes, &[]);
    if cordons > 0 {
        GPU_CORDONS_TOTAL.add(cordons, &[]);
    }
    if uncordons > 0 {
        GPU_UNCORDONS_TOTAL.add(uncordons, &[]);
    }
    if threshold_hit {
        GPU_CORDON_THRESHOLD_HITS.add(1, &[]);
    }
    GPU_PENDING_REQUEST_MAX.record(max_pending_request, &[]);
}

// ============================================================================
// Helper Types
// ============================================================================

/// Labels for cluster phase metric
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterPhase {
    /// Cluster is pending creation
    Pending,
    /// Cluster is being provisioned
    Provisioning,
    /// Cluster is pivoting to self-management
    Pivoting,
    /// Cluster is ready and self-managing
    Ready,
    /// Cluster has failed
    Failed,
    /// Cluster is being deleted
    Deleting,
}

impl ClusterPhase {
    /// Convert to label value
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Provisioning => "provisioning",
            Self::Pivoting => "pivoting",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Deleting => "deleting",
        }
    }
}

/// Labels for authorization decision
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthDecision {
    /// Request was allowed
    Allow,
    /// Request was denied
    Deny,
}

impl AuthDecision {
    /// Convert to label value
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// Labels for proxy request status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyStatus {
    /// 2xx success
    Success,
    /// 4xx client error
    ClientError,
    /// 5xx server error
    ServerError,
}

impl ProxyStatus {
    /// Convert to label value
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "2xx",
            Self::ClientError => "4xx",
            Self::ServerError => "5xx",
        }
    }

    /// Create from HTTP status code
    pub fn from_status_code(code: u16) -> Self {
        match code {
            200..=299 => Self::Success,
            400..=499 => Self::ClientError,
            _ => Self::ServerError,
        }
    }
}

// ============================================================================
// Metric Recording Helpers
// ============================================================================

/// Record a cluster reconciliation with timing
pub struct ReconcileTimer {
    cluster: String,
    start: std::time::Instant,
}

impl ReconcileTimer {
    /// Start timing a reconciliation
    pub fn start(cluster: impl Into<String>) -> Self {
        Self {
            cluster: cluster.into(),
            start: std::time::Instant::now(),
        }
    }

    /// Record successful completion
    pub fn success(self) {
        let duration = self.start.elapsed().as_secs_f64();
        CLUSTER_RECONCILE_DURATION.record(
            duration,
            &[
                opentelemetry::KeyValue::new("cluster", self.cluster),
                opentelemetry::KeyValue::new("result", "success"),
            ],
        );
    }

    /// Record error completion
    pub fn error(self, error_type: &str) {
        let duration = self.start.elapsed().as_secs_f64();
        CLUSTER_RECONCILE_DURATION.record(
            duration,
            &[
                opentelemetry::KeyValue::new("cluster", self.cluster.clone()),
                opentelemetry::KeyValue::new("result", "error"),
            ],
        );
        CLUSTER_RECONCILE_ERRORS.add(
            1,
            &[
                opentelemetry::KeyValue::new("cluster", self.cluster),
                opentelemetry::KeyValue::new("error_type", error_type.to_string()),
            ],
        );
    }
}

/// Record a proxy request with timing
pub struct ProxyTimer {
    cluster: String,
    method: String,
    start: std::time::Instant,
}

impl ProxyTimer {
    /// Start timing a proxy request
    pub fn start(cluster: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            cluster: cluster.into(),
            method: method.into(),
            start: std::time::Instant::now(),
        }
    }

    /// Complete with status
    pub fn complete(self, status: ProxyStatus) {
        let duration = self.start.elapsed().as_secs_f64();

        PROXY_REQUESTS.add(
            1,
            &[
                opentelemetry::KeyValue::new("cluster", self.cluster.clone()),
                opentelemetry::KeyValue::new("method", self.method.clone()),
                opentelemetry::KeyValue::new("status", status.as_str().to_string()),
            ],
        );

        PROXY_REQUEST_DURATION.record(
            duration,
            &[
                opentelemetry::KeyValue::new("cluster", self.cluster),
                opentelemetry::KeyValue::new("method", self.method),
            ],
        );
    }
}

/// Record a Cedar authorization decision
pub fn record_cedar_decision(decision: AuthDecision, action: &str) {
    CEDAR_DECISIONS.add(
        1,
        &[
            opentelemetry::KeyValue::new("decision", decision.as_str().to_string()),
            opentelemetry::KeyValue::new("action", action.to_string()),
        ],
    );
}

/// Update cluster phase gauge
pub fn set_cluster_phase_count(phase: ClusterPhase, count: i64) {
    CLUSTERS_TOTAL.record(
        count,
        &[opentelemetry::KeyValue::new(
            "phase",
            phase.as_str().to_string(),
        )],
    );
}

/// Update agent heartbeat age
pub fn set_agent_heartbeat_age(cluster: &str, age_seconds: f64) {
    AGENT_HEARTBEAT_AGE.record(
        age_seconds,
        &[opentelemetry::KeyValue::new("cluster", cluster.to_string())],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cluster_phase_as_str() {
        assert_eq!(ClusterPhase::Pending.as_str(), "pending");
        assert_eq!(ClusterPhase::Ready.as_str(), "ready");
    }

    #[test]
    fn test_proxy_status_from_code() {
        assert_eq!(ProxyStatus::from_status_code(200), ProxyStatus::Success);
        assert_eq!(ProxyStatus::from_status_code(201), ProxyStatus::Success);
        assert_eq!(ProxyStatus::from_status_code(404), ProxyStatus::ClientError);
        assert_eq!(ProxyStatus::from_status_code(500), ProxyStatus::ServerError);
    }

    #[test]
    fn test_auth_decision_as_str() {
        assert_eq!(AuthDecision::Allow.as_str(), "allow");
        assert_eq!(AuthDecision::Deny.as_str(), "deny");
    }

    #[test]
    fn test_reconcile_timer() {
        let timer = ReconcileTimer::start("test-cluster");
        assert_eq!(timer.cluster, "test-cluster");
        timer.success();
    }

    #[test]
    fn test_proxy_timer() {
        let timer = ProxyTimer::start("test-cluster", "GET");
        timer.complete(ProxyStatus::Success);
    }

    #[test]
    fn test_record_gpu_health() {
        record_gpu_health(4, 1, 1, 0, false, 2);
        record_gpu_health(4, 3, 0, 0, true, 0);
    }
}
