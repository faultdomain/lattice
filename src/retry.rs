//! Retry utilities with exponential backoff and jitter.
//!
//! This module provides a general-purpose retry mechanism for any async operation
//! that may fail transiently. It uses exponential backoff with jitter to avoid
//! thundering herd problems.
//!
//! # Example
//!
//! ```ignore
//! use lattice::retry::{retry_with_backoff, RetryConfig};
//!
//! let result = retry_with_backoff(
//!     &RetryConfig::default(),
//!     "fetch_secret",
//!     || async { kube_client.get::<Secret>("my-secret").await },
//! ).await?;
//! ```

use std::time::Duration;

use rand::Rng;
use tracing::{error, warn};

/// Configuration for operations that may fail transiently.
///
/// Used for all external calls (K8s API, HTTP, etc.) to handle transient failures
/// with exponential backoff and jitter.
#[derive(Clone, Debug)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (0 = infinite)
    pub max_attempts: u32,
    /// Initial delay between retries
    pub initial_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Multiplier for exponential backoff
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 0, // infinite
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
        }
    }
}

impl RetryConfig {
    /// Create a config with a maximum number of attempts
    pub fn with_max_attempts(attempts: u32) -> Self {
        Self {
            max_attempts: attempts,
            ..Default::default()
        }
    }

    /// Create a config that retries forever (infinite attempts)
    pub fn infinite() -> Self {
        Self::default()
    }
}

/// Execute an async operation with exponential backoff and jitter.
///
/// Retries indefinitely (or up to max_attempts if set) until success.
/// Uses exponential backoff with jitter to avoid thundering herd.
///
/// # Arguments
/// * `config` - Retry configuration
/// * `operation_name` - Name for logging purposes
/// * `operation` - The async operation to retry
///
/// # Returns
/// The result of the operation, or the last error if max_attempts is exhausted.
pub async fn retry_with_backoff<F, Fut, T, E>(
    config: &RetryConfig,
    operation_name: &str,
    mut operation: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut attempt = 0u32;
    let mut delay = config.initial_delay;

    loop {
        attempt += 1;

        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                // Check if we've exhausted retries
                if config.max_attempts > 0 && attempt >= config.max_attempts {
                    error!(
                        operation = %operation_name,
                        attempt = attempt,
                        error = %e,
                        "Operation failed after max retries"
                    );
                    return Err(e);
                }

                // Add jitter: 0.5x to 1.5x of the delay
                let jitter = rand::thread_rng().gen_range(0.5..1.5);
                let jittered_delay = Duration::from_secs_f64(delay.as_secs_f64() * jitter);

                warn!(
                    operation = %operation_name,
                    attempt = attempt,
                    error = %e,
                    delay_ms = jittered_delay.as_millis(),
                    "Operation failed, retrying"
                );

                tokio::time::sleep(jittered_delay).await;

                // Exponential backoff, capped at max_delay
                delay = Duration::from_secs_f64(
                    (delay.as_secs_f64() * config.backoff_multiplier)
                        .min(config.max_delay.as_secs_f64()),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_succeeds_immediately() {
        let config = RetryConfig::with_max_attempts(3);
        let result: Result<i32, &str> =
            retry_with_backoff(&config, "op", || async { Ok(42) }).await;
        assert_eq!(result, Ok(42));
    }

    #[tokio::test]
    async fn test_succeeds_after_failures() {
        let count = Arc::new(AtomicU32::new(0));
        let c = count.clone();

        let config = RetryConfig {
            max_attempts: 5,
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
            backoff_multiplier: 2.0,
        };

        let result: Result<i32, &str> = retry_with_backoff(&config, "op", || {
            let c = c.clone();
            async move {
                if c.fetch_add(1, Ordering::SeqCst) < 2 {
                    Err("fail")
                } else {
                    Ok(42)
                }
            }
        })
        .await;

        assert_eq!(result, Ok(42));
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_exhausts_max_attempts() {
        let count = Arc::new(AtomicU32::new(0));
        let c = count.clone();

        let config = RetryConfig {
            max_attempts: 3,
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
            backoff_multiplier: 2.0,
        };

        let result: Result<i32, &str> = retry_with_backoff(&config, "op", || {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err("always fails")
            }
        })
        .await;

        assert_eq!(result, Err("always fails"));
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }
}
