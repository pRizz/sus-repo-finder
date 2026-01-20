//! Crate source download and extraction module
//!
//! This module provides functionality to download crate source tarballs from
//! crates.io and extract them to a local directory for analysis.

use flate2::read::GzDecoder;
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::Archive;
use thiserror::Error;

/// Base URL for downloading crate sources from crates.io
const CRATES_IO_DOWNLOAD_URL: &str = "https://crates.io/api/v1/crates";

/// User-Agent header required by crates.io API
const USER_AGENT: &str = "sus-repo-finder (https://github.com/example/sus-repo-finder)";

/// Errors that can occur during download and extraction
#[derive(Error, Debug)]
pub enum DownloadError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("Crate not found: {crate_name}@{version}")]
    NotFound { crate_name: String, version: String },

    #[error("Rate limited by crates.io")]
    RateLimited,

    #[error("HTTP error: {status} - {message}")]
    HttpError { status: u16, message: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to extract tarball: {0}")]
    Extraction(String),

    #[error("Invalid extraction path: {0}")]
    InvalidPath(String),
}

/// Result of a successful crate extraction
#[derive(Debug, Clone)]
pub struct ExtractedCrate {
    /// Path to the extracted crate directory
    pub path: PathBuf,
    /// Crate name
    pub crate_name: String,
    /// Version number
    pub version: String,
    /// Whether a build.rs file exists
    pub has_build_rs: bool,
    /// Path to build.rs if it exists
    pub build_rs_path: Option<PathBuf>,
    /// Whether this is a proc-macro crate
    pub is_proc_macro: bool,
}

/// Crate source downloader and extractor
#[derive(Clone)]
pub struct CrateDownloader {
    client: reqwest::Client,
    cache_dir: PathBuf,
}

impl CrateDownloader {
    /// Create a new downloader with a cache directory
    ///
    /// # Arguments
    ///
    /// * `cache_dir` - Directory where downloaded crates will be extracted
    pub fn new(cache_dir: impl AsRef<Path>) -> Result<Self, DownloadError> {
        let client = reqwest::Client::builder().user_agent(USER_AGENT).build()?;

        let cache_dir = cache_dir.as_ref().to_path_buf();

        // Create cache directory if it doesn't exist
        std::fs::create_dir_all(&cache_dir)?;

        Ok(Self { client, cache_dir })
    }

    /// Get the download URL for a specific crate version
    fn get_download_url(&self, crate_name: &str, version: &str) -> String {
        format!(
            "{}/{}/{}/download",
            CRATES_IO_DOWNLOAD_URL, crate_name, version
        )
    }

    /// Get the expected extraction directory for a crate
    fn get_extraction_dir(&self, crate_name: &str, version: &str) -> PathBuf {
        self.cache_dir.join(format!("{}-{}", crate_name, version))
    }

    /// Download and extract a crate source
    ///
    /// Downloads the crate tarball from crates.io and extracts it to the cache directory.
    /// If the crate is already extracted, returns the existing path.
    ///
    /// # Arguments
    ///
    /// * `crate_name` - Name of the crate to download
    /// * `version` - Version of the crate to download
    ///
    /// # Returns
    ///
    /// * `Ok(ExtractedCrate)` - Information about the extracted crate
    /// * `Err(DownloadError)` - If download or extraction fails
    pub async fn download_and_extract(
        &self,
        crate_name: &str,
        version: &str,
    ) -> Result<ExtractedCrate, DownloadError> {
        let extraction_dir = self.get_extraction_dir(crate_name, version);

        // Check if already extracted
        if extraction_dir.exists() {
            tracing::debug!(
                "Crate {}@{} already extracted at {:?}",
                crate_name,
                version,
                extraction_dir
            );
            return self.analyze_extracted_crate(&extraction_dir, crate_name, version);
        }

        // Download the tarball
        let tarball_data = self.download_tarball(crate_name, version).await?;

        // Extract the tarball
        self.extract_tarball(&tarball_data, crate_name, version)?;

        // Analyze the extracted crate
        self.analyze_extracted_crate(&extraction_dir, crate_name, version)
    }

    /// Download the crate tarball from crates.io
    async fn download_tarball(
        &self,
        crate_name: &str,
        version: &str,
    ) -> Result<Vec<u8>, DownloadError> {
        let url = self.get_download_url(crate_name, version);

        tracing::info!("Downloading {}@{} from {}", crate_name, version, url);

        let response = self.client.get(&url).send().await?;

        match response.status() {
            status if status.is_success() => {
                let bytes = response.bytes().await?;
                tracing::info!(
                    "Downloaded {}@{}: {} bytes",
                    crate_name,
                    version,
                    bytes.len()
                );
                Ok(bytes.to_vec())
            }
            reqwest::StatusCode::NOT_FOUND => {
                tracing::warn!("Crate not found: {}@{}", crate_name, version);
                Err(DownloadError::NotFound {
                    crate_name: crate_name.to_string(),
                    version: version.to_string(),
                })
            }
            reqwest::StatusCode::TOO_MANY_REQUESTS => {
                tracing::warn!("Rate limited by crates.io");
                Err(DownloadError::RateLimited)
            }
            status => {
                let error_text = response.text().await.unwrap_or_default();
                tracing::error!("Download error ({}): {}", status, error_text);
                Err(DownloadError::HttpError {
                    status: status.as_u16(),
                    message: error_text,
                })
            }
        }
    }

    /// Extract a gzipped tarball to the cache directory
    fn extract_tarball(
        &self,
        tarball_data: &[u8],
        crate_name: &str,
        version: &str,
    ) -> Result<(), DownloadError> {
        let extraction_dir = self.get_extraction_dir(crate_name, version);

        tracing::info!(
            "Extracting {}@{} to {:?}",
            crate_name,
            version,
            extraction_dir
        );

        // Decompress gzip
        let mut decoder = GzDecoder::new(tarball_data);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| DownloadError::Extraction(format!("Failed to decompress gzip: {}", e)))?;

        // Extract tar archive
        let mut archive = Archive::new(decompressed.as_slice());

        // Create temporary directory for extraction
        let temp_dir = self
            .cache_dir
            .join(format!(".tmp-{}-{}", crate_name, version));
        std::fs::create_dir_all(&temp_dir)?;

        // Extract to temporary directory first
        archive.unpack(&temp_dir).map_err(|e| {
            // Clean up temp dir on error
            let _ = std::fs::remove_dir_all(&temp_dir);
            DownloadError::Extraction(format!("Failed to extract tar: {}", e))
        })?;

        // Find the extracted directory (should be crate_name-version)
        let expected_inner_dir = temp_dir.join(format!("{}-{}", crate_name, version));

        if expected_inner_dir.exists() {
            // Move the inner directory to the final location
            std::fs::rename(&expected_inner_dir, &extraction_dir).map_err(|e| {
                let _ = std::fs::remove_dir_all(&temp_dir);
                DownloadError::Io(e)
            })?;
        } else {
            // Check if files were extracted directly (no inner directory)
            // Move temp_dir contents to extraction_dir
            std::fs::rename(&temp_dir, &extraction_dir)?;
        }

        // Clean up temp directory if it still exists
        let _ = std::fs::remove_dir_all(&temp_dir);

        tracing::info!(
            "Successfully extracted {}@{} to {:?}",
            crate_name,
            version,
            extraction_dir
        );

        Ok(())
    }

    /// Analyze an extracted crate to find build.rs and check for proc-macro
    fn analyze_extracted_crate(
        &self,
        extraction_dir: &Path,
        crate_name: &str,
        version: &str,
    ) -> Result<ExtractedCrate, DownloadError> {
        let build_rs_path = extraction_dir.join("build.rs");
        let has_build_rs = build_rs_path.exists();

        // Check Cargo.toml for proc-macro
        let is_proc_macro = self.check_is_proc_macro(extraction_dir);

        Ok(ExtractedCrate {
            path: extraction_dir.to_path_buf(),
            crate_name: crate_name.to_string(),
            version: version.to_string(),
            has_build_rs,
            build_rs_path: if has_build_rs {
                Some(build_rs_path)
            } else {
                None
            },
            is_proc_macro,
        })
    }

    /// Check if a crate is a proc-macro by reading Cargo.toml
    fn check_is_proc_macro(&self, extraction_dir: &Path) -> bool {
        let cargo_toml_path = extraction_dir.join("Cargo.toml");

        if let Ok(content) = std::fs::read_to_string(&cargo_toml_path) {
            // Simple check for proc-macro = true in [lib] section
            // This is a basic check; a full TOML parser would be more robust
            content.contains("proc-macro = true") || content.contains("proc-macro=true")
        } else {
            false
        }
    }

    /// Remove an extracted crate from the cache
    ///
    /// # Arguments
    ///
    /// * `crate_name` - Name of the crate
    /// * `version` - Version of the crate
    pub fn remove_extracted(&self, crate_name: &str, version: &str) -> Result<(), DownloadError> {
        let extraction_dir = self.get_extraction_dir(crate_name, version);

        if extraction_dir.exists() {
            std::fs::remove_dir_all(&extraction_dir)?;
            tracing::info!("Removed extracted crate: {}@{}", crate_name, version);
        }

        Ok(())
    }

    /// Clear all cached crates
    pub fn clear_cache(&self) -> Result<(), DownloadError> {
        if self.cache_dir.exists() {
            // Remove all subdirectories
            for entry in std::fs::read_dir(&self.cache_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    std::fs::remove_dir_all(&path)?;
                }
            }
            tracing::info!("Cleared crate cache at {:?}", self.cache_dir);
        }

        Ok(())
    }

    /// Get the cache directory path
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_download_url_generation() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let downloader =
            CrateDownloader::new(temp_dir.path()).expect("Failed to create downloader");

        let url = downloader.get_download_url("serde", "1.0.0");
        assert_eq!(url, "https://crates.io/api/v1/crates/serde/1.0.0/download");
    }

    #[test]
    fn test_extraction_dir_generation() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let downloader =
            CrateDownloader::new(temp_dir.path()).expect("Failed to create downloader");

        let extraction_dir = downloader.get_extraction_dir("serde", "1.0.0");
        assert_eq!(extraction_dir, temp_dir.path().join("serde-1.0.0"));
    }

    #[test]
    fn test_cache_dir_created() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let cache_path = temp_dir.path().join("crate_cache");

        assert!(!cache_path.exists());

        let downloader = CrateDownloader::new(&cache_path).expect("Failed to create downloader");

        assert!(cache_path.exists());
        assert_eq!(downloader.cache_dir(), cache_path);
    }

    #[test]
    fn test_check_is_proc_macro_true() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let crate_dir = temp_dir.path().join("test-crate-1.0.0");
        std::fs::create_dir_all(&crate_dir).expect("Failed to create crate dir");

        let cargo_toml = r#"
[package]
name = "test-crate"
version = "1.0.0"

[lib]
proc-macro = true
"#;
        std::fs::write(crate_dir.join("Cargo.toml"), cargo_toml)
            .expect("Failed to write Cargo.toml");

        let downloader =
            CrateDownloader::new(temp_dir.path()).expect("Failed to create downloader");

        assert!(downloader.check_is_proc_macro(&crate_dir));
    }

    #[test]
    fn test_check_is_proc_macro_false() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let crate_dir = temp_dir.path().join("test-crate-1.0.0");
        std::fs::create_dir_all(&crate_dir).expect("Failed to create crate dir");

        let cargo_toml = r#"
[package]
name = "test-crate"
version = "1.0.0"

[lib]
crate-type = ["cdylib"]
"#;
        std::fs::write(crate_dir.join("Cargo.toml"), cargo_toml)
            .expect("Failed to write Cargo.toml");

        let downloader =
            CrateDownloader::new(temp_dir.path()).expect("Failed to create downloader");

        assert!(!downloader.check_is_proc_macro(&crate_dir));
    }

    #[test]
    fn test_analyze_extracted_crate_with_build_rs() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let crate_dir = temp_dir.path().join("test-crate-1.0.0");
        std::fs::create_dir_all(&crate_dir).expect("Failed to create crate dir");

        // Create build.rs
        std::fs::write(crate_dir.join("build.rs"), "fn main() {}")
            .expect("Failed to write build.rs");

        // Create Cargo.toml
        std::fs::write(
            crate_dir.join("Cargo.toml"),
            "[package]\nname = \"test-crate\"\nversion = \"1.0.0\"",
        )
        .expect("Failed to write Cargo.toml");

        let downloader =
            CrateDownloader::new(temp_dir.path()).expect("Failed to create downloader");

        let result = downloader
            .analyze_extracted_crate(&crate_dir, "test-crate", "1.0.0")
            .expect("Failed to analyze crate");

        assert_eq!(result.crate_name, "test-crate");
        assert_eq!(result.version, "1.0.0");
        assert!(result.has_build_rs);
        assert!(result.build_rs_path.is_some());
        assert!(!result.is_proc_macro);
    }

    #[test]
    fn test_analyze_extracted_crate_without_build_rs() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let crate_dir = temp_dir.path().join("simple-crate-1.0.0");
        std::fs::create_dir_all(&crate_dir).expect("Failed to create crate dir");

        // Create Cargo.toml but no build.rs
        std::fs::write(
            crate_dir.join("Cargo.toml"),
            "[package]\nname = \"simple-crate\"\nversion = \"1.0.0\"",
        )
        .expect("Failed to write Cargo.toml");

        let downloader =
            CrateDownloader::new(temp_dir.path()).expect("Failed to create downloader");

        let result = downloader
            .analyze_extracted_crate(&crate_dir, "simple-crate", "1.0.0")
            .expect("Failed to analyze crate");

        assert_eq!(result.crate_name, "simple-crate");
        assert_eq!(result.version, "1.0.0");
        assert!(!result.has_build_rs);
        assert!(result.build_rs_path.is_none());
        assert!(!result.is_proc_macro);
    }

    /// Integration test: download and extract a real crate
    #[tokio::test]
    #[ignore] // Ignore by default since it makes network calls
    async fn test_download_and_extract_real_crate() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let downloader =
            CrateDownloader::new(temp_dir.path()).expect("Failed to create downloader");

        // Download a small, simple crate
        let result = downloader
            .download_and_extract("once_cell", "1.19.0")
            .await
            .expect("Failed to download and extract crate");

        assert_eq!(result.crate_name, "once_cell");
        assert_eq!(result.version, "1.19.0");
        assert!(result.path.exists());

        // Check that expected files exist
        assert!(result.path.join("Cargo.toml").exists());
        assert!(result.path.join("src").exists());

        // Clean up
        downloader
            .remove_extracted("once_cell", "1.19.0")
            .expect("Failed to remove extracted crate");
        assert!(!result.path.exists());
    }
}
