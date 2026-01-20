//! Crates.io API client for fetching crate metadata
//!
//! This module provides a client for interacting with the crates.io API
//! to fetch information about crates, including names, versions, descriptions,
//! download counts, and repository URLs.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Base URL for the crates.io API
const CRATES_IO_API_URL: &str = "https://crates.io/api/v1";

/// User-Agent header required by crates.io API
const USER_AGENT: &str = "sus-repo-finder (https://github.com/example/sus-repo-finder)";

/// Errors that can occur when interacting with crates.io API
#[derive(Error, Debug)]
pub enum CratesIoError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("Crate not found: {0}")]
    NotFound(String),

    #[error("Rate limited by crates.io API")]
    RateLimited,

    #[error("API returned error: {0}")]
    ApiError(String),
}

/// Response from the crates.io API for a single crate
#[derive(Debug, Clone, Deserialize)]
pub struct CrateResponse {
    #[serde(rename = "crate")]
    pub crate_data: CrateData,
    pub versions: Vec<VersionData>,
}

/// Crate metadata from crates.io
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateData {
    /// Crate ID from crates.io
    pub id: String,
    /// Crate name
    pub name: String,
    /// Description of the crate
    pub description: Option<String>,
    /// Repository URL
    pub repository: Option<String>,
    /// Homepage URL
    pub homepage: Option<String>,
    /// Documentation URL
    pub documentation: Option<String>,
    /// Total download count
    pub downloads: i64,
    /// Recent download count
    pub recent_downloads: Option<i64>,
    /// Maximum version number
    pub max_version: String,
    /// Maximum stable version number (excluding pre-releases)
    pub max_stable_version: Option<String>,
    /// Date when the crate was created
    pub created_at: String,
    /// Date when the crate was last updated
    pub updated_at: String,
}

/// Version metadata from crates.io
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionData {
    /// Version ID from crates.io
    pub id: i64,
    /// Crate name
    #[serde(rename = "crate")]
    pub crate_name: String,
    /// Version number (semver)
    #[serde(rename = "num")]
    pub version: String,
    /// Download count for this version
    pub downloads: i64,
    /// Whether this is a yanked version
    pub yanked: bool,
    /// Date when this version was published
    pub created_at: String,
    /// Date when this version was last updated
    pub updated_at: String,
    /// License information
    pub license: Option<String>,
    /// Size of the crate in bytes
    pub crate_size: Option<i64>,
    /// Features available in this version
    pub features: Option<serde_json::Value>,
    /// Dependencies count
    #[serde(default)]
    pub links: VersionLinks,
}

/// Links associated with a version
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VersionLinks {
    /// Link to the authors endpoint
    pub authors: Option<String>,
    /// Link to the dependencies endpoint
    pub dependencies: Option<String>,
    /// Link to the version download
    pub version_downloads: Option<String>,
}

/// Client for interacting with the crates.io API
#[derive(Clone)]
pub struct CratesIoClient {
    client: reqwest::Client,
    base_url: String,
}

impl CratesIoClient {
    /// Create a new crates.io API client
    pub fn new() -> Result<Self, CratesIoError> {
        let client = reqwest::Client::builder().user_agent(USER_AGENT).build()?;

        Ok(Self {
            client,
            base_url: CRATES_IO_API_URL.to_string(),
        })
    }

    /// Create a new client with a custom base URL (useful for testing)
    #[allow(dead_code)]
    pub fn with_base_url(base_url: &str) -> Result<Self, CratesIoError> {
        let client = reqwest::Client::builder().user_agent(USER_AGENT).build()?;

        Ok(Self {
            client,
            base_url: base_url.to_string(),
        })
    }

    /// Fetch crate metadata from crates.io
    ///
    /// Returns the crate data including name, description, download count,
    /// repository URL, and all versions.
    ///
    /// # Arguments
    ///
    /// * `crate_name` - The name of the crate to fetch
    ///
    /// # Returns
    ///
    /// * `Ok(CrateResponse)` - The crate metadata and versions
    /// * `Err(CratesIoError)` - If the request fails or the crate is not found
    pub async fn get_crate(&self, crate_name: &str) -> Result<CrateResponse, CratesIoError> {
        let url = format!("{}/crates/{}", self.base_url, crate_name);

        tracing::debug!("Fetching crate metadata from: {}", url);

        let response = self.client.get(&url).send().await?;

        match response.status() {
            status if status.is_success() => {
                let crate_response: CrateResponse = response.json().await?;
                tracing::info!(
                    "Fetched crate '{}': {} versions, {} downloads",
                    crate_response.crate_data.name,
                    crate_response.versions.len(),
                    crate_response.crate_data.downloads
                );
                Ok(crate_response)
            }
            reqwest::StatusCode::NOT_FOUND => {
                tracing::warn!("Crate not found: {}", crate_name);
                Err(CratesIoError::NotFound(crate_name.to_string()))
            }
            reqwest::StatusCode::TOO_MANY_REQUESTS => {
                tracing::warn!("Rate limited by crates.io API");
                Err(CratesIoError::RateLimited)
            }
            status => {
                let error_text = response.text().await.unwrap_or_default();
                tracing::error!("API error ({}): {}", status, error_text);
                Err(CratesIoError::ApiError(format!(
                    "HTTP {}: {}",
                    status, error_text
                )))
            }
        }
    }

    /// Get the download URL for a specific crate version
    ///
    /// Returns the URL to download the crate source tarball.
    pub fn get_download_url(&self, crate_name: &str, version: &str) -> String {
        format!(
            "https://crates.io/api/v1/crates/{}/{}/download",
            crate_name, version
        )
    }
}

impl Default for CratesIoClient {
    fn default() -> Self {
        Self::new().expect("Failed to create crates.io client")
    }
}

/// Simplified crate metadata for internal use
#[derive(Debug, Clone)]
pub struct CrateMetadata {
    /// Crate name
    pub name: String,
    /// Description of the crate
    pub description: Option<String>,
    /// Repository URL
    pub repo_url: Option<String>,
    /// Total download count
    pub download_count: i64,
    /// All available versions
    pub versions: Vec<String>,
    /// Maximum (latest) version
    pub max_version: String,
}

impl From<CrateResponse> for CrateMetadata {
    fn from(response: CrateResponse) -> Self {
        let versions: Vec<String> = response
            .versions
            .iter()
            .filter(|v| !v.yanked)
            .map(|v| v.version.clone())
            .collect();

        Self {
            name: response.crate_data.name,
            description: response.crate_data.description,
            repo_url: response.crate_data.repository,
            download_count: response.crate_data.downloads,
            versions,
            max_version: response.crate_data.max_version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_creation() {
        let client = CratesIoClient::new();
        assert!(client.is_ok());
    }

    #[test]
    fn test_download_url() {
        let client = CratesIoClient::new().expect("Failed to create client");
        let url = client.get_download_url("serde", "1.0.0");
        assert_eq!(url, "https://crates.io/api/v1/crates/serde/1.0.0/download");
    }

    /// Integration test: fetch the 'serde' crate from crates.io API
    /// This test verifies that:
    /// 1. We can fetch metadata for a known crate
    /// 2. Name, versions, and description are returned
    /// 3. Download count is retrieved
    /// 4. Repository URL is extracted
    #[tokio::test]
    #[ignore] // Ignore by default since it makes network calls
    async fn test_fetch_serde_crate() {
        let client = CratesIoClient::new().expect("Failed to create client");
        let response = client
            .get_crate("serde")
            .await
            .expect("Failed to fetch serde");

        // Step 1: Verify name
        assert_eq!(response.crate_data.name, "serde");

        // Step 2: Verify description is returned
        assert!(
            response.crate_data.description.is_some(),
            "Description should be present"
        );
        let description = response.crate_data.description.as_ref().unwrap();
        assert!(!description.is_empty(), "Description should not be empty");

        // Step 3: Verify versions are returned
        assert!(!response.versions.is_empty(), "Versions should be returned");
        // serde is a popular crate with many versions
        assert!(
            response.versions.len() > 10,
            "serde should have many versions"
        );

        // Step 4: Verify download count is retrieved
        assert!(
            response.crate_data.downloads > 0,
            "Download count should be positive"
        );
        // serde is one of the most downloaded crates
        assert!(
            response.crate_data.downloads > 100_000_000,
            "serde should have over 100M downloads"
        );

        // Step 5: Verify repo URL is extracted
        assert!(
            response.crate_data.repository.is_some(),
            "Repository URL should be present"
        );
        let repo_url = response.crate_data.repository.as_ref().unwrap();
        assert!(
            repo_url.contains("github.com/serde-rs/serde"),
            "Repo URL should point to serde-rs/serde"
        );

        // Verify max_version is set
        assert!(
            !response.crate_data.max_version.is_empty(),
            "Max version should be set"
        );

        // Convert to CrateMetadata and verify
        let metadata: CrateMetadata = response.into();
        assert_eq!(metadata.name, "serde");
        assert!(metadata.description.is_some());
        assert!(metadata.repo_url.is_some());
        assert!(metadata.download_count > 0);
        assert!(!metadata.versions.is_empty());
        assert!(!metadata.max_version.is_empty());
    }

    /// Test that fetching a non-existent crate returns NotFound error
    #[tokio::test]
    #[ignore] // Ignore by default since it makes network calls
    async fn test_fetch_nonexistent_crate() {
        let client = CratesIoClient::new().expect("Failed to create client");
        let result = client
            .get_crate("this-crate-definitely-does-not-exist-12345")
            .await;

        assert!(result.is_err());
        match result {
            Err(CratesIoError::NotFound(name)) => {
                assert_eq!(name, "this-crate-definitely-does-not-exist-12345");
            }
            _ => panic!("Expected NotFound error"),
        }
    }
}
