//! Core crawler logic for parallel crate processing
//!
//! This module provides the main Crawler struct that orchestrates
//! fetching crate metadata from crates.io, downloading sources,
//! and storing the results in the database.

use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::sync::Arc;
use sus_core::Database;
use tokio::sync::Semaphore;
use tracing::{error, info, instrument, warn};

use crate::crates_io::{CrateMetadata, CratesIoClient};
use crate::downloader::CrateDownloader;

/// Default maximum concurrent crate processing
const DEFAULT_MAX_CONCURRENT: usize = 10;

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
}

/// Configuration for the crawler
#[derive(Debug, Clone)]
pub struct CrawlerConfig {
    /// Maximum number of concurrent crate downloads/processing
    pub max_concurrent: usize,
}

impl Default for CrawlerConfig {
    fn default() -> Self {
        Self {
            max_concurrent: DEFAULT_MAX_CONCURRENT,
        }
    }
}

/// The main crawler struct for parallel crate processing
pub struct Crawler {
    db: Arc<Database>,
    crates_io_client: Arc<CratesIoClient>,
    downloader: Arc<CrateDownloader>,
    config: CrawlerConfig,
    semaphore: Arc<Semaphore>,
}

impl Crawler {
    /// Create a new crawler instance
    ///
    /// # Arguments
    ///
    /// * `db` - Database connection for storing results
    /// * `crates_io_client` - Client for fetching crate metadata
    /// * `downloader` - Downloader for fetching crate sources
    /// * `config` - Crawler configuration
    pub fn new(
        db: Database,
        crates_io_client: CratesIoClient,
        downloader: CrateDownloader,
        config: CrawlerConfig,
    ) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent));
        Self {
            db: Arc::new(db),
            crates_io_client: Arc::new(crates_io_client),
            downloader: Arc::new(downloader),
            config,
            semaphore,
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
    /// * `config` - Crawler configuration
    pub fn from_arc(
        db: Arc<Database>,
        crates_io_client: Arc<CratesIoClient>,
        downloader: Arc<CrateDownloader>,
        config: CrawlerConfig,
    ) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent));
        Self {
            db,
            crates_io_client,
            downloader,
            config,
            semaphore,
        }
    }

    /// Process multiple crates in parallel
    ///
    /// This method processes a list of crate names concurrently, respecting
    /// the configured maximum concurrency limit. Each crate is:
    /// 1. Fetched from crates.io API for metadata
    /// 2. Downloaded and extracted for analysis
    /// 3. Stored in the database
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
            "Starting parallel processing of {} crates with max {} concurrent",
            crate_names.len(),
            self.config.max_concurrent
        );

        let results: Vec<CrateProcessResult> = stream::iter(crate_names)
            .map(|name| {
                let db = Arc::clone(&self.db);
                let client = Arc::clone(&self.crates_io_client);
                let downloader = Arc::clone(&self.downloader);
                let semaphore = Arc::clone(&self.semaphore);

                async move {
                    // Acquire semaphore permit to limit concurrency
                    let _permit = semaphore.acquire().await.expect("Semaphore closed");
                    Self::process_single_crate(db, client, downloader, name).await
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
    #[instrument(skip(db, client, downloader), fields(crate_name = %name))]
    async fn process_single_crate(
        db: Arc<Database>,
        client: Arc<CratesIoClient>,
        downloader: Arc<CrateDownloader>,
        name: String,
    ) -> CrateProcessResult {
        info!("Processing crate: {}", name);

        // Step 1: Fetch metadata from crates.io
        let metadata: CrateMetadata = match client.get_crate(&name).await {
            Ok(response) => response.into(),
            Err(e) => {
                error!("Failed to fetch metadata for {}: {}", name, e);
                return CrateProcessResult {
                    name,
                    version: String::new(),
                    success: false,
                    error: Some(format!("Failed to fetch metadata: {}", e)),
                    crate_id: None,
                    version_id: None,
                };
            }
        };

        let version = metadata.max_version.clone();

        // Step 2: Download and extract the latest version
        let (has_build_rs, is_proc_macro) =
            match downloader.download_and_extract(&name, &version).await {
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
        }
    }

    /// Get the current configuration
    pub fn config(&self) -> &CrawlerConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CrawlerConfig::default();
        assert_eq!(config.max_concurrent, DEFAULT_MAX_CONCURRENT);
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
        };
        assert!(result.success);
        assert!(result.error.is_none());
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
        };
        assert!(!result.success);
        assert!(result.error.is_some());
    }
}
