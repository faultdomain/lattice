//! Generic resource polling utilities
//!
//! Provides a reusable helper for polling Kubernetes resources with timeout.

use std::future::Future;
use std::time::{Duration, Instant};

/// Poll for a resource until a condition is met or timeout expires.
///
/// This is a generic helper that consolidates the common pattern of:
/// - Polling in a loop with a delay
/// - Having a timeout to avoid infinite waits
/// - Handling transient errors gracefully
///
/// # Arguments
/// * `description` - Human-readable description for logging
/// * `timeout` - Maximum time to wait
/// * `poll_interval` - Time between poll attempts
/// * `poll_fn` - Async function that returns `Ok(Some(T))` when ready,
///   `Ok(None)` to keep waiting, or `Err(msg)` on failure
///
/// # Returns
/// * `Ok(T)` - The resource when found
/// * `Err(String)` - Error message if timeout or poll error
pub async fn wait_for_resource<T, F, Fut>(
    description: &str,
    timeout: Duration,
    poll_interval: Duration,
    mut poll_fn: F,
) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Option<T>, String>>,
{
    let start = Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err(format!(
                "Timeout after {:?} waiting for {}",
                timeout, description
            ));
        }

        match poll_fn().await {
            Ok(Some(value)) => return Ok(value),
            Ok(None) => {
                // Not ready yet, keep waiting
            }
            Err(e) => {
                tracing::warn!(error = %e, "Poll error for {}, retrying...", description);
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

/// Default timeout for resource polling (10 minutes)
pub const DEFAULT_RESOURCE_TIMEOUT: Duration = Duration::from_secs(600);

/// Default poll interval for resource polling (2 seconds)
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Longer poll interval for slower resources like LoadBalancers (5 seconds)
pub const LOAD_BALANCER_POLL_INTERVAL: Duration = Duration::from_secs(5);
