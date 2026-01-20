//! Retry and backoff utilities for handling transient errors
//!
//! This module provides exponential backoff retry logic for handling
//! rate limiting (HTTP 429) and other transient errors when interacting
//! with external APIs like crates.io.

use std::time::Duration;
use tracing::{debug, info, warn};

/// Default initial delay for exponential backoff (1 second)
const DEFAULT_INITIAL_DELAY_MS: u64 = 1000;

/// Default maximum delay for exponential backoff (60 seconds)
const DEFAULT_MAX_DELAY_MS: u64 = 60_000;

/// Default maximum number of retry attempts
const DEFAULT_MAX_RETRIES: u32 = 5;

/// Default backoff multiplier (doubles delay each retry)
const DEFAULT_MULTIPLIER: f64 = 2.0;

/// Configuration for exponential backoff retry behavior
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Initial delay before first retry (milliseconds)
    pub initial_delay_ms: u64,
    /// Maximum delay between retries (milliseconds)
    pub max_delay_ms: u64,
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Multiplier for exponential backoff (e.g., 2.0 doubles delay each retry)
    pub multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            initial_delay_ms: DEFAULT_INITIAL_DELAY_MS,
            max_delay_ms: DEFAULT_MAX_DELAY_MS,
            max_retries: DEFAULT_MAX_RETRIES,
            multiplier: DEFAULT_MULTIPLIER,
        }
    }
}

impl RetryConfig {
    /// Create a new retry configuration
    pub fn new(
        initial_delay_ms: u64,
        max_delay_ms: u64,
        max_retries: u32,
        multiplier: f64,
    ) -> Self {
        Self {
            initial_delay_ms,
            max_delay_ms,
            max_retries,
            multiplier,
        }
    }

    /// Calculate the delay for a given attempt number (0-indexed)
    ///
    /// Uses exponential backoff: delay = initial_delay * (multiplier ^ attempt)
    /// Capped at max_delay
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let base_delay = self.initial_delay_ms as f64;
        let delay = base_delay * self.multiplier.powi(attempt as i32);
        let capped_delay = delay.min(self.max_delay_ms as f64) as u64;
        Duration::from_millis(capped_delay)
    }
}

/// Trait for errors that can indicate rate limiting
pub trait RateLimitError {
    /// Returns true if this error indicates a rate limit (429 response)
    fn is_rate_limited(&self) -> bool;

    /// Returns true if this error is transient and can be retried
    fn is_transient(&self) -> bool;
}

/// Result of a retry operation
#[derive(Debug)]
pub enum RetryResult<T, E> {
    /// Operation succeeded
    Success(T),
    /// Operation failed after all retries
    Failed {
        error: E,
        attempts: u32,
        total_delay_ms: u64,
    },
}

impl<T, E> RetryResult<T, E> {
    /// Returns true if the operation succeeded
    pub fn is_success(&self) -> bool {
        matches!(self, RetryResult::Success(_))
    }

    /// Converts into a Result, using the final error if failed
    pub fn into_result(self) -> Result<T, E> {
        match self {
            RetryResult::Success(value) => Ok(value),
            RetryResult::Failed { error, .. } => Err(error),
        }
    }
}

/// Execute an async operation with exponential backoff retry
///
/// This function will retry the operation if it returns a rate limit error (429),
/// using exponential backoff between attempts.
///
/// # Type Parameters
///
/// * `F` - The async function to execute
/// * `Fut` - The future returned by F
/// * `T` - The success type
/// * `E` - The error type (must implement RateLimitError)
///
/// # Arguments
///
/// * `config` - Retry configuration
/// * `operation_name` - Name of the operation for logging
/// * `f` - The async function to execute
///
/// # Returns
///
/// * `RetryResult::Success(T)` - If the operation succeeds
/// * `RetryResult::Failed` - If all retries are exhausted
pub async fn retry_with_backoff<F, Fut, T, E>(
    config: &RetryConfig,
    operation_name: &str,
    mut f: F,
) -> RetryResult<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: RateLimitError + std::fmt::Display,
{
    let mut attempt = 0u32;
    let mut total_delay_ms = 0u64;

    loop {
        match f().await {
            Ok(value) => {
                if attempt > 0 {
                    info!(
                        "{}: succeeded after {} retries (total backoff: {}ms)",
                        operation_name, attempt, total_delay_ms
                    );
                }
                return RetryResult::Success(value);
            }
            Err(e) => {
                if !e.is_rate_limited() && !e.is_transient() {
                    // Non-retryable error
                    debug!("{}: non-retryable error: {}", operation_name, e);
                    return RetryResult::Failed {
                        error: e,
                        attempts: attempt + 1,
                        total_delay_ms,
                    };
                }

                if attempt >= config.max_retries {
                    warn!(
                        "{}: exhausted {} retries (total backoff: {}ms), final error: {}",
                        operation_name, config.max_retries, total_delay_ms, e
                    );
                    return RetryResult::Failed {
                        error: e,
                        attempts: attempt + 1,
                        total_delay_ms,
                    };
                }

                let delay = config.delay_for_attempt(attempt);
                total_delay_ms += delay.as_millis() as u64;

                if e.is_rate_limited() {
                    warn!(
                        "{}: rate limited (429), backing off for {:?} (attempt {}/{})",
                        operation_name,
                        delay,
                        attempt + 1,
                        config.max_retries
                    );
                } else {
                    debug!(
                        "{}: transient error, retrying in {:?} (attempt {}/{}): {}",
                        operation_name,
                        delay,
                        attempt + 1,
                        config.max_retries,
                        e
                    );
                }

                tokio::time::sleep(delay).await;
                attempt += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[derive(Debug, Clone)]
    struct TestError {
        rate_limited: bool,
        transient: bool,
        message: String,
    }

    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.message)
        }
    }

    impl RateLimitError for TestError {
        fn is_rate_limited(&self) -> bool {
            self.rate_limited
        }

        fn is_transient(&self) -> bool {
            self.transient
        }
    }

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.initial_delay_ms, DEFAULT_INITIAL_DELAY_MS);
        assert_eq!(config.max_delay_ms, DEFAULT_MAX_DELAY_MS);
        assert_eq!(config.max_retries, DEFAULT_MAX_RETRIES);
        assert_eq!(config.multiplier, DEFAULT_MULTIPLIER);
    }

    #[test]
    fn test_delay_for_attempt_exponential() {
        let config = RetryConfig::new(1000, 60_000, 5, 2.0);

        // Attempt 0: 1000ms
        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(1000));
        // Attempt 1: 2000ms
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(2000));
        // Attempt 2: 4000ms
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(4000));
        // Attempt 3: 8000ms
        assert_eq!(config.delay_for_attempt(3), Duration::from_millis(8000));
    }

    #[test]
    fn test_delay_for_attempt_capped() {
        let config = RetryConfig::new(1000, 5000, 5, 2.0);

        // Attempt 0: 1000ms
        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(1000));
        // Attempt 1: 2000ms
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(2000));
        // Attempt 2: 4000ms
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(4000));
        // Attempt 3: capped at 5000ms
        assert_eq!(config.delay_for_attempt(3), Duration::from_millis(5000));
        // Attempt 4: still capped at 5000ms
        assert_eq!(config.delay_for_attempt(4), Duration::from_millis(5000));
    }

    #[tokio::test]
    async fn test_retry_success_first_attempt() {
        let config = RetryConfig::new(10, 100, 3, 2.0);

        let result: RetryResult<i32, TestError> =
            retry_with_backoff(&config, "test", || async { Ok(42) }).await;

        assert!(result.is_success());
        assert_eq!(result.into_result().unwrap(), 42);
    }

    #[tokio::test]
    async fn test_retry_success_after_rate_limit() {
        let config = RetryConfig::new(10, 100, 3, 2.0);
        let attempt_count = AtomicU32::new(0);

        let result: RetryResult<i32, TestError> = retry_with_backoff(&config, "test", || {
            let count = attempt_count.fetch_add(1, Ordering::SeqCst);
            async move {
                if count < 2 {
                    Err(TestError {
                        rate_limited: true,
                        transient: false,
                        message: "429 Too Many Requests".to_string(),
                    })
                } else {
                    Ok(42)
                }
            }
        })
        .await;

        assert!(result.is_success());
        assert_eq!(result.into_result().unwrap(), 42);
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_retry_exhausted() {
        let config = RetryConfig::new(10, 100, 3, 2.0);

        let result: RetryResult<i32, TestError> = retry_with_backoff(&config, "test", || async {
            Err(TestError {
                rate_limited: true,
                transient: false,
                message: "429 Too Many Requests".to_string(),
            })
        })
        .await;

        assert!(!result.is_success());
        match result {
            RetryResult::Failed { attempts, .. } => {
                assert_eq!(attempts, 4); // 1 initial + 3 retries
            }
            _ => panic!("Expected Failed"),
        }
    }

    #[tokio::test]
    async fn test_retry_non_retryable_error() {
        let config = RetryConfig::new(10, 100, 3, 2.0);
        let attempt_count = AtomicU32::new(0);

        let result: RetryResult<i32, TestError> = retry_with_backoff(&config, "test", || {
            attempt_count.fetch_add(1, Ordering::SeqCst);
            async {
                Err(TestError {
                    rate_limited: false,
                    transient: false,
                    message: "404 Not Found".to_string(),
                })
            }
        })
        .await;

        assert!(!result.is_success());
        // Should only try once for non-retryable errors
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_retry_result_into_result() {
        let success: RetryResult<i32, TestError> = RetryResult::Success(42);
        assert_eq!(success.into_result().unwrap(), 42);

        let failed: RetryResult<i32, TestError> = RetryResult::Failed {
            error: TestError {
                rate_limited: true,
                transient: false,
                message: "error".to_string(),
            },
            attempts: 3,
            total_delay_ms: 100,
        };
        assert!(failed.into_result().is_err());
    }
}
