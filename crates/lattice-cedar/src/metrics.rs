//! Prometheus metrics for Cedar authorization
//!
//! Provides observability into policy evaluation performance and outcomes.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Cedar authorization metrics
#[derive(Debug, Default)]
pub struct CedarMetrics {
    /// Total authorization requests
    pub requests_total: AtomicU64,
    /// Allowed requests
    pub allowed_total: AtomicU64,
    /// Denied requests
    pub denied_total: AtomicU64,
    /// Errors during evaluation
    pub errors_total: AtomicU64,
    /// JWT validation failures
    pub jwt_failures_total: AtomicU64,
    /// Policy cache hits
    pub cache_hits_total: AtomicU64,
    /// Policy cache misses
    pub cache_misses_total: AtomicU64,
    /// Total evaluation time in microseconds
    pub evaluation_time_us_total: AtomicU64,
    /// Total JWT validation time in microseconds
    pub jwt_time_us_total: AtomicU64,
}

impl CedarMetrics {
    /// Create new metrics instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful authorization (allowed)
    pub fn record_allowed(&self, evaluation_time: std::time::Duration) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.allowed_total.fetch_add(1, Ordering::Relaxed);
        self.evaluation_time_us_total
            .fetch_add(evaluation_time.as_micros() as u64, Ordering::Relaxed);
    }

    /// Record a denied authorization
    pub fn record_denied(&self, evaluation_time: std::time::Duration) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.denied_total.fetch_add(1, Ordering::Relaxed);
        self.evaluation_time_us_total
            .fetch_add(evaluation_time.as_micros() as u64, Ordering::Relaxed);
    }

    /// Record an error during evaluation
    pub fn record_error(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.errors_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a JWT validation failure
    pub fn record_jwt_failure(&self) {
        self.jwt_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record JWT validation time
    pub fn record_jwt_time(&self, duration: std::time::Duration) {
        self.jwt_time_us_total
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    /// Record a policy cache hit
    pub fn record_cache_hit(&self) {
        self.cache_hits_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a policy cache miss
    pub fn record_cache_miss(&self) {
        self.cache_misses_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total requests
    pub fn requests(&self) -> u64 {
        self.requests_total.load(Ordering::Relaxed)
    }

    /// Get allowed requests
    pub fn allowed(&self) -> u64 {
        self.allowed_total.load(Ordering::Relaxed)
    }

    /// Get denied requests
    pub fn denied(&self) -> u64 {
        self.denied_total.load(Ordering::Relaxed)
    }

    /// Get error count
    pub fn errors(&self) -> u64 {
        self.errors_total.load(Ordering::Relaxed)
    }

    /// Get average evaluation time in microseconds
    pub fn avg_evaluation_time_us(&self) -> u64 {
        let total = self.evaluation_time_us_total.load(Ordering::Relaxed);
        let count = self.allowed() + self.denied();
        if count > 0 {
            total / count
        } else {
            0
        }
    }

    /// Get cache hit rate (0.0 to 1.0)
    pub fn cache_hit_rate(&self) -> f64 {
        let hits = self.cache_hits_total.load(Ordering::Relaxed);
        let misses = self.cache_misses_total.load(Ordering::Relaxed);
        let total = hits + misses;
        if total > 0 {
            hits as f64 / total as f64
        } else {
            0.0
        }
    }

    /// Reset all metrics to zero
    pub fn reset(&self) {
        self.requests_total.store(0, Ordering::Relaxed);
        self.allowed_total.store(0, Ordering::Relaxed);
        self.denied_total.store(0, Ordering::Relaxed);
        self.errors_total.store(0, Ordering::Relaxed);
        self.jwt_failures_total.store(0, Ordering::Relaxed);
        self.cache_hits_total.store(0, Ordering::Relaxed);
        self.cache_misses_total.store(0, Ordering::Relaxed);
        self.evaluation_time_us_total.store(0, Ordering::Relaxed);
        self.jwt_time_us_total.store(0, Ordering::Relaxed);
    }
}

/// Timer for measuring operation duration
pub struct Timer {
    start: Instant,
}

impl Timer {
    /// Start a new timer
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Get elapsed duration
    pub fn elapsed(&self) -> std::time::Duration {
        self.start.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_metrics_recording() {
        let metrics = CedarMetrics::new();

        metrics.record_allowed(Duration::from_micros(100));
        metrics.record_allowed(Duration::from_micros(200));
        metrics.record_denied(Duration::from_micros(150));
        metrics.record_error();

        assert_eq!(metrics.requests(), 4);
        assert_eq!(metrics.allowed(), 2);
        assert_eq!(metrics.denied(), 1);
        assert_eq!(metrics.errors(), 1);
    }

    #[test]
    fn test_average_evaluation_time() {
        let metrics = CedarMetrics::new();

        metrics.record_allowed(Duration::from_micros(100));
        metrics.record_allowed(Duration::from_micros(200));
        metrics.record_denied(Duration::from_micros(300));

        // Average of 100, 200, 300 = 200
        assert_eq!(metrics.avg_evaluation_time_us(), 200);
    }

    #[test]
    fn test_cache_hit_rate() {
        let metrics = CedarMetrics::new();

        metrics.record_cache_hit();
        metrics.record_cache_hit();
        metrics.record_cache_hit();
        metrics.record_cache_miss();

        // 3 hits out of 4 = 0.75
        assert!((metrics.cache_hit_rate() - 0.75).abs() < 0.001);
    }

    #[test]
    fn test_metrics_reset() {
        let metrics = CedarMetrics::new();

        metrics.record_allowed(Duration::from_micros(100));
        metrics.record_cache_hit();

        metrics.reset();

        assert_eq!(metrics.requests(), 0);
        assert_eq!(metrics.allowed(), 0);
        assert!((metrics.cache_hit_rate() - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_timer() {
        let timer = Timer::start();
        std::thread::sleep(Duration::from_millis(10));
        let elapsed = timer.elapsed();

        assert!(elapsed >= Duration::from_millis(10));
    }
}
