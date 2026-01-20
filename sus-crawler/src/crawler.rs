//! Core crawler logic for parallel crate processing
//!
//! This module provides the main Crawler struct that orchestrates
//! fetching crate metadata from crates.io, downloading sources,
//! and storing the results in the database.
//!
//! ## Rate Limiting
//!
//! The crawler implements rate limiting to be a polite citizen when
//! accessing the crates.io API. Configure the delay between requests
//! using `CrawlerConfig::rate_limit_delay_ms`.
//!
//! ## Retry with Exponential Backoff
//!
//! When the crates.io API returns a 429 (Too Many Requests) response,
//! the crawler will automatically retry with exponential backoff.
//! Configure retry behavior using `RetryConfig`.

use futures::stream::{self, StreamExt};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sus_core::Database;
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, error, info, instrument, warn};

use crate::crates_io::{CrateMetadata, CratesIoClient};
use crate::downloader::CrateDownloader;
use crate::retry::{retry_with_backoff, RetryConfig};

/// Default maximum concurrent crate processing
const DEFAULT_MAX_CONCURRENT: usize = 10;

/// Default rate limit delay in milliseconds (1 second = 1000ms)
/// This ensures we don't overwhelm the crates.io API
const DEFAULT_RATE_LIMIT_DELAY_MS: u64 = 1000;

/// Result of processing a single crate
#[derive(Debug)]
pub struct CrateProcessResult {
    /// Crate name
    pub name: String,
    /// Version processed
    pub version: String,
    /// Whether processing succeeded
    pub success: bool,
    /// Error message if processing failed
    pub error: Option<String>,
    /// Database ID of the stored crate
    pub crate_id: Option<i64>,
    /// Database ID of the stored version
    pub version_id: Option<i64>,
    /// Whether the crate was skipped because it was already analyzed
    pub skipped: bool,
}

/// Configuration for the crawler
#[derive(Debug, Clone)]
pub struct CrawlerConfig {
    /// Maximum number of concurrent crate downloads/processing
    pub max_concurrent: usize,
    /// Delay between API requests in milliseconds (rate limiting)
    /// This helps be a polite citizen when accessing crates.io
    pub rate_limit_delay_ms: u64,
    /// Retry configuration for handling rate limiting (429 errors)
    pub retry_config: RetryConfig,
}

impl Default for CrawlerConfig {
    fn default() -> Self {
        Self {
            max_concurrent: DEFAULT_MAX_CONCURRENT,
            rate_limit_delay_ms: DEFAULT_RATE_LIMIT_DELAY_MS,
            retry_config: RetryConfig::default(),
        }
    }
}

impl CrawlerConfig {
    /// Create a new config with custom settings
    pub fn new(max_concurrent: usize, rate_limit_delay_ms: u64) -> Self {
        Self {
            max_concurrent,
            rate_limit_delay_ms,
            retry_config: RetryConfig::default(),
        }
    }

    /// Set the rate limit delay (builder pattern)
    pub fn with_rate_limit_delay_ms(mut self, delay_ms: u64) -> Self {
        self.rate_limit_delay_ms = delay_ms;
        self
    }

    /// Set the retry configuration (builder pattern)
    pub fn with_retry_config(mut self, retry_config: RetryConfig) -> Self {
        self.retry_config = retry_config;
        self
    }
}

/// Tracks the last request time for rate limiting
struct RateLimiter {
    last_request: Instant,
    delay: Duration,
}

impl RateLimiter {
    fn new(delay_ms: u64) -> Self {
        Self {
            // Initialize to past so first request can proceed immediately
            last_request: Instant::now() - Duration::from_secs(10),
            delay: Duration::from_millis(delay_ms),
        }
    }

    /// Wait if necessary to respect the rate limit, then record the request time
    async fn wait_and_record(&mut self) {
        let elapsed = self.last_request.elapsed();
        if elapsed < self.delay {
            let wait_time = self.delay - elapsed;
            debug!("Rate limiting: waiting {:?} before next request", wait_time);
            tokio::time::sleep(wait_time).await;
        }
        self.last_request = Instant::now();
    }
}

/// The main crawler struct for parallel crate processing
pub struct Crawler {
    db: Arc<Database>,
    crates_io_client: Arc<CratesIoClient>,
    downloader: Arc<CrateDownloader>,
    config: CrawlerConfig,
    semaphore: Arc<Semaphore>,
    /// Rate limiter for API requests (shared via Mutex for async access)
    rate_limiter: Arc<Mutex<RateLimiter>>,
}

impl Crawler {
    /// Create a new crawler instance
    ///
    /// # Arguments
    ///
    /// * `db` - Database connection for storing results
    /// * `crates_io_client` - Client for fetching crate metadata
    /// * `downloader` - Downloader for fetching crate sources
    /// * `config` - Crawler configuration (includes rate limiting settings)
    pub fn new(
        db: Database,
        crates_io_client: CratesIoClient,
        downloader: CrateDownloader,
        config: CrawlerConfig,
    ) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent));
        let rate_limiter = Arc::new(Mutex::new(RateLimiter::new(config.rate_limit_delay_ms)));
        Self {
            db: Arc::new(db),
            crates_io_client: Arc::new(crates_io_client),
            downloader: Arc::new(downloader),
            config,
            semaphore,
            rate_limiter,
        }
    }

    /// Create a new crawler instance from Arc-wrapped components
    ///
    /// This is useful when you already have Arc-wrapped components from shared state.
    ///
    /// # Arguments
    ///
    /// * `db` - Arc-wrapped database connection
    /// * `crates_io_client` - Arc-wrapped crates.io API client
    /// * `downloader` - Arc-wrapped crate downloader
    /// * `config` - Crawler configuration (includes rate limiting settings)
    pub fn from_arc(
        db: Arc<Database>,
        crates_io_client: Arc<CratesIoClient>,
        downloader: Arc<CrateDownloader>,
        config: CrawlerConfig,
    ) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent));
        let rate_limiter = Arc::new(Mutex::new(RateLimiter::new(config.rate_limit_delay_ms)));
        Self {
            db,
            crates_io_client,
            downloader,
            config,
            semaphore,
            rate_limiter,
        }
    }

    /// Process multiple crates in parallel with rate limiting
    ///
    /// This method processes a list of crate names concurrently, respecting
    /// the configured maximum concurrency limit and rate limit delays.
    /// Each crate is:
    /// 1. Fetched from crates.io API for metadata (with rate limiting)
    /// 2. Downloaded and extracted for analysis
    /// 3. Stored in the database
    ///
    /// Rate limiting ensures we don't overwhelm the crates.io API by spacing
    /// out requests according to the configured delay.
    ///
    /// # Arguments
    ///
    /// * `crate_names` - List of crate names to process
    ///
    /// # Returns
    ///
    /// A vector of results, one for each crate processed
    #[instrument(skip(self, crate_names), fields(count = crate_names.len()))]
    pub async fn process_crates(&self, crate_names: Vec<String>) -> Vec<CrateProcessResult> {
        info!(
            "Starting parallel processing of {} crates with max {} concurrent, rate limit {}ms",
            crate_names.len(),
            self.config.max_concurrent,
            self.config.rate_limit_delay_ms
        );

        let retry_config = Arc::new(self.config.retry_config.clone());

        let results: Vec<CrateProcessResult> = stream::iter(crate_names)
            .map(|name| {
                let db = Arc::clone(&self.db);
                let client = Arc::clone(&self.crates_io_client);
                let downloader = Arc::clone(&self.downloader);
                let semaphore = Arc::clone(&self.semaphore);
                let rate_limiter = Arc::clone(&self.rate_limiter);
                let retry_config = Arc::clone(&retry_config);

                async move {
                    // Acquire semaphore permit to limit concurrency
                    let _permit = semaphore.acquire().await.expect("Semaphore closed");

                    // Apply rate limiting before making API request
                    {
                        let mut limiter = rate_limiter.lock().await;
                        limiter.wait_and_record().await;
                    }

                    Self::process_single_crate(db, client, downloader, name, retry_config).await
                }
            })
            .buffer_unordered(self.config.max_concurrent)
            .collect()
            .await;

        let success_count = results.iter().filter(|r| r.success).count();
        let failure_count = results.len() - success_count;

        info!(
            "Completed processing {} crates: {} succeeded, {} failed",
            results.len(),
            success_count,
            failure_count
        );

        results
    }

    /// Process a single crate: fetch metadata, download, and store
    ///
    /// Uses exponential backoff retry for rate limiting (429) errors.
    /// Implements incremental crawling: skips crate versions that have already
    /// been analyzed (have last_analyzed timestamp with status 'completed').
    #[instrument(skip(db, client, downloader, retry_config), fields(crate_name = %name))]
    async fn process_single_crate(
        db: Arc<Database>,
        client: Arc<CratesIoClient>,
        downloader: Arc<CrateDownloader>,
        name: String,
        retry_config: Arc<RetryConfig>,
    ) -> CrateProcessResult {
        info!("Processing crate: {}", name);

        // Step 1: Fetch metadata from crates.io with retry/backoff for rate limiting
        let fetch_name = name.clone();
        let metadata: CrateMetadata =
            match retry_with_backoff(&retry_config, &format!("fetch_metadata:{}", name), || {
                let client = Arc::clone(&client);
                let crate_name = fetch_name.clone();
                async move { client.get_crate(&crate_name).await.map(CrateMetadata::from) }
            })
            .await
            .into_result()
            {
                Ok(metadata) => metadata,
                Err(e) => {
                    error!("Failed to fetch metadata for {}: {}", name, e);
                    return CrateProcessResult {
                        name,
                        version: String::new(),
                        success: false,
                        error: Some(format!("Failed to fetch metadata: {}", e)),
                        crate_id: None,
                        version_id: None,
                        skipped: false,
                    };
                }
            };

        let version = metadata.max_version.clone();

        // Step 1.5: Check if this version has already been analyzed (incremental crawling)
        match db.is_version_analyzed(&name, &version).await {
            Ok(true) => {
                info!(
                    "Skipping {}@{}: already analyzed (incremental crawling)",
                    name, version
                );
                return CrateProcessResult {
                    name,
                    version,
                    success: true,
                    error: None,
                    crate_id: None,
                    version_id: None,
                    skipped: true,
                };
            }
            Ok(false) => {
                debug!("{}@{} has not been analyzed yet, proceeding", name, version);
            }
            Err(e) => {
                warn!(
                    "Failed to check if {}@{} is already analyzed: {} - proceeding with analysis",
                    name, version, e
                );
            }
        }

        // Step 2: Download and extract the latest version with retry/backoff for rate limiting
        let download_name = name.clone();
        let download_version = version.clone();
        let (has_build_rs, is_proc_macro) = match retry_with_backoff(
            &retry_config,
            &format!("download:{}@{}", name, version),
            || {
                let downloader = Arc::clone(&downloader);
                let crate_name = download_name.clone();
                let crate_version = download_version.clone();
                async move {
                    downloader
                        .download_and_extract(&crate_name, &crate_version)
                        .await
                }
            },
        )
        .await
        .into_result()
        {
            Ok(extracted) => (extracted.has_build_rs, extracted.is_proc_macro),
            Err(e) => {
                warn!(
                    "Failed to download {}@{}: {} - storing with defaults",
                    name, version, e
                );
                // Continue with defaults if download fails
                (false, false)
            }
        };

        // Step 3: Store crate in database
        let crate_id = match db
            .upsert_crate(
                &metadata.name,
                metadata.repo_url.as_deref(),
                metadata.description.as_deref(),
                metadata.download_count,
            )
            .await
        {
            Ok(id) => id,
            Err(e) => {
                error!("Failed to store crate {}: {}", name, e);
                return CrateProcessResult {
                    name,
                    version,
                    success: false,
                    error: Some(format!("Failed to store crate: {}", e)),
                    crate_id: None,
                    version_id: None,
                    skipped: false,
                };
            }
        };

        // Step 4: Store version in database
        let version_id = match db
            .upsert_version(crate_id, &version, has_build_rs, is_proc_macro)
            .await
        {
            Ok(id) => id,
            Err(e) => {
                warn!("Failed to store version for {}: {}", name, e);
                0
            }
        };

        // Step 5: Mark the version as analyzed (for incremental crawling)
        if version_id > 0 {
            if let Err(e) = db.mark_version_analyzed(version_id).await {
                warn!(
                    "Failed to mark {}@{} as analyzed: {} - will be re-analyzed next time",
                    name, version, e
                );
            }
        }

        info!(
            "Successfully processed {}@{}: crate_id={}, version_id={}",
            name, version, crate_id, version_id
        );

        CrateProcessResult {
            name,
            version,
            success: true,
            error: None,
            crate_id: Some(crate_id),
            version_id: Some(version_id),
            skipped: false,
        }
    }

    /// Get the current configuration
    pub fn config(&self) -> &CrawlerConfig {
        &self.config
    }

    /// Get the configured rate limit delay in milliseconds
    pub fn rate_limit_delay_ms(&self) -> u64 {
        self.config.rate_limit_delay_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CrawlerConfig::default();
        assert_eq!(config.max_concurrent, DEFAULT_MAX_CONCURRENT);
        assert_eq!(config.rate_limit_delay_ms, DEFAULT_RATE_LIMIT_DELAY_MS);
    }

    #[test]
    fn test_custom_config() {
        let config = CrawlerConfig::new(5, 500);
        assert_eq!(config.max_concurrent, 5);
        assert_eq!(config.rate_limit_delay_ms, 500);
    }

    #[test]
    fn test_config_builder() {
        let config = CrawlerConfig::default().with_rate_limit_delay_ms(2000);
        assert_eq!(config.max_concurrent, DEFAULT_MAX_CONCURRENT);
        assert_eq!(config.rate_limit_delay_ms, 2000);
    }

    #[tokio::test]
    async fn test_rate_limiter_delays() {
        let mut limiter = RateLimiter::new(100); // 100ms delay

        // First request should be immediate
        let start = Instant::now();
        limiter.wait_and_record().await;
        let first_elapsed = start.elapsed();
        assert!(
            first_elapsed < Duration::from_millis(50),
            "First request should be immediate"
        );

        // Second request should be delayed by ~100ms
        let start = Instant::now();
        limiter.wait_and_record().await;
        let second_elapsed = start.elapsed();
        assert!(
            second_elapsed >= Duration::from_millis(90),
            "Second request should be delayed by ~100ms, was {:?}",
            second_elapsed
        );
    }

    #[test]
    fn test_crate_process_result_success() {
        let result = CrateProcessResult {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            success: true,
            error: None,
            crate_id: Some(1),
            version_id: Some(1),
            skipped: false,
        };
        assert!(result.success);
        assert!(result.error.is_none());
        assert!(!result.skipped);
    }

    #[test]
    fn test_crate_process_result_failure() {
        let result = CrateProcessResult {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            success: false,
            error: Some("Test error".to_string()),
            crate_id: None,
            version_id: None,
            skipped: false,
        };
        assert!(!result.success);
        assert!(result.error.is_some());
        assert!(!result.skipped);
    }

    #[test]
    fn test_crate_process_result_skipped() {
        let result = CrateProcessResult {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            success: true,
            error: None,
            crate_id: None,
            version_id: None,
            skipped: true,
        };
        assert!(result.success);
        assert!(result.error.is_none());
        assert!(result.skipped);
    }
}
