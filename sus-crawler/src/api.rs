//! API routes for the crawler web portal

use askama::Template;
use axum::{
    extract::Path,
    http::StatusCode,
    response::{Html, IntoResponse, Json, Response},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use sus_core::Database;

use crate::templates::StatusTemplate;
use sus_crawler::{CrateDownloader, Crawler, CrawlerConfig, CratesIoClient};
use sus_detector::Detector;

/// Wrapper for rendering Askama templates as HTML responses
pub struct HtmlTemplate<T>(pub T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template: {}", err),
            )
                .into_response(),
        }
    }
}

/// Application state shared across handlers
pub struct AppState {
    /// Database connection (Arc-wrapped for sharing with Crawler)
    pub db: Arc<Database>,
    /// Crates.io API client (Arc-wrapped for sharing with Crawler)
    pub crates_io_client: Arc<CratesIoClient>,
    /// Crate downloader for source extraction (Arc-wrapped for sharing with Crawler)
    pub crate_downloader: Arc<CrateDownloader>,
}

/// Create the API router
pub fn create_router(db: Database) -> Router {
    let crates_io_client = CratesIoClient::new().expect("Failed to create crates.io client");

    // Create cache directory for downloaded crates
    let cache_dir = std::env::var("CRATE_CACHE_DIR")
        .unwrap_or_else(|_| "./data/crate_cache".to_string());
    let crate_downloader = CrateDownloader::new(&cache_dir)
        .expect("Failed to create crate downloader");

    let state = Arc::new(AppState {
        db: Arc::new(db),
        crates_io_client: Arc::new(crates_io_client),
        crate_downloader: Arc::new(crate_downloader),
    });

    Router::new()
        .route("/", get(index))
        .route("/detailed", get(detailed))
        .route("/errors", get(errors))
        .route("/api/crawler/status", get(status))
        .route("/api/crawler/stats", get(stats))
        .route("/api/crawler/queue", get(queue))
        .route("/api/crawler/errors", get(api_errors))
        .route("/api/crawler/pause", axum::routing::post(pause))
        .route("/api/crawler/resume", axum::routing::post(resume))
        // Test endpoint to fetch crate metadata from crates.io
        .route("/api/crawler/test-crate/{name}", get(test_crate))
        // Test endpoint to download and extract a crate
        .route("/api/crawler/test-download/{name}/{version}", get(test_download))
        // Crawl and store endpoint: fetches from crates.io and stores in database
        .route("/api/crawler/crawl-and-store/{name}", axum::routing::post(crawl_and_store))
        // Add a version to an existing crate (for testing)
        .route("/api/crawler/add-version", axum::routing::post(add_version))
        // Get stored crate endpoint: retrieves a crate from the database
        .route("/api/crawler/stored-crate/{name}", get(get_stored_crate))
        // Store an analysis result (finding) in the database
        .route("/api/crawler/store-finding", axum::routing::post(store_finding))
        // Get all findings for a specific crate version
        .route("/api/crawler/findings/{crate_name}/{version}", get(get_findings))
        // Analyze a crate's build.rs file for suspicious patterns
        .route("/api/crawler/analyze/{name}/{version}", get(analyze_crate))
        // Test the detector on inline code
        .route("/api/crawler/test-detector", axum::routing::post(test_detector))
        .with_state(state)
}

/// Crawler status page (main page)
async fn index() -> impl IntoResponse {
    // TODO: Fetch real stats from database when crawler is implemented
    let template = StatusTemplate::new(
        "idle",
        0,     // crates_scanned
        0,     // findings_count
        0,     // errors_count
        0,     // queue_size
        None,  // current_crate
        0.0,   // progress_percent
    );

    HtmlTemplate(template)
}

async fn detailed() -> &'static str {
    "Crawler Portal - Detailed View (TODO: implement template)"
}

async fn errors() -> &'static str {
    "Crawler Portal - Errors Page (TODO: implement template)"
}

async fn status() -> impl IntoResponse {
    // Return JSON status for API consumers
    Json(json!({
        "status": "idle",
        "current_crate": null,
        "crates_scanned": 0,
        "findings_count": 0,
        "errors_count": 0,
        "queue_size": 0,
        "progress_percent": 0.0
    }))
}

async fn stats() -> impl IntoResponse {
    Json(json!({
        "crates_scanned": 0,
        "findings_count": 0,
        "errors_count": 0,
        "queue_size": 0
    }))
}

async fn queue() -> impl IntoResponse {
    Json(json!({
        "pending": 0,
        "items": []
    }))
}

async fn api_errors() -> impl IntoResponse {
    Json(json!({
        "errors": [],
        "total": 0
    }))
}

async fn pause() -> impl IntoResponse {
    Json(json!({
        "success": true,
        "status": "paused"
    }))
}

async fn resume() -> impl IntoResponse {
    Json(json!({
        "success": true,
        "status": "running"
    }))
}

/// Test endpoint to fetch crate metadata from crates.io API
/// GET /api/crawler/test-crate/{name}
///
/// This endpoint demonstrates that the crates.io API client works correctly.
/// It fetches metadata for the specified crate and returns:
/// - name: crate name
/// - description: crate description
/// - downloads: total download count
/// - repository: repository URL
/// - max_version: latest version
/// - version_count: number of versions
async fn test_crate(
    Path(name): Path<String>,
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> impl IntoResponse {
    match state.crates_io_client.get_crate(&name).await {
        Ok(response) => {
            let metadata: sus_crawler::CrateMetadata = response.clone().into();
            Json(json!({
                "success": true,
                "crate": {
                    "name": metadata.name,
                    "description": metadata.description,
                    "downloads": metadata.download_count,
                    "repository": metadata.repo_url,
                    "max_version": metadata.max_version,
                    "version_count": metadata.versions.len(),
                    "versions": metadata.versions.iter().take(10).collect::<Vec<_>>()
                }
            }))
            .into_response()
        }
        Err(e) => {
            let error_message = e.to_string();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": error_message
                })),
            )
                .into_response()
        }
    }
}

/// Test endpoint to download and extract a crate source
/// GET /api/crawler/test-download/{name}/{version}
///
/// This endpoint demonstrates that the crate downloader works correctly.
/// It downloads the specified crate version from crates.io, extracts it,
/// and returns information about the extracted contents:
/// - path: path to the extracted directory
/// - crate_name: crate name
/// - version: version number
/// - has_build_rs: whether build.rs exists
/// - is_proc_macro: whether this is a proc-macro crate
async fn test_download(
    Path((name, version)): Path<(String, String)>,
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> impl IntoResponse {
    match state.crate_downloader.download_and_extract(&name, &version).await {
        Ok(extracted) => {
            Json(json!({
                "success": true,
                "extracted": {
                    "crate_name": extracted.crate_name,
                    "version": extracted.version,
                    "path": extracted.path.to_string_lossy(),
                    "has_build_rs": extracted.has_build_rs,
                    "build_rs_path": extracted.build_rs_path.map(|p| p.to_string_lossy().to_string()),
                    "is_proc_macro": extracted.is_proc_macro
                }
            }))
            .into_response()
        }
        Err(e) => {
            let error_message = e.to_string();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": error_message
                })),
            )
                .into_response()
        }
    }
}

/// Crawl and store a crate from crates.io into the database
/// POST /api/crawler/crawl-and-store/{name}
///
/// This endpoint:
/// 1. Fetches crate metadata from crates.io
/// 2. Downloads and extracts the latest version to detect build.rs and proc-macro
/// 3. Stores the crate and its versions in the database
///
/// Returns:
/// - crate_id: database ID of the stored crate
/// - versions_stored: number of versions stored
/// - name, description, repo_url, download_count: stored metadata
async fn crawl_and_store(
    Path(name): Path<String>,
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> impl IntoResponse {
    // Step 1: Fetch crate metadata from crates.io
    let crate_response = match state.crates_io_client.get_crate(&name).await {
        Ok(response) => response,
        Err(e) => {
            let error_message = e.to_string();
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "error": format!("Failed to fetch from crates.io: {}", error_message)
                })),
            )
                .into_response();
        }
    };

    let metadata: sus_crawler::CrateMetadata = crate_response.clone().into();

    // Step 2: Store the crate in the database
    let crate_id = match state
        .db
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
            let error_message = e.to_string();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": format!("Failed to store crate: {}", error_message)
                })),
            )
                .into_response();
        }
    };

    // Step 3: Download and analyze the latest version to get has_build_rs and is_proc_macro
    let latest_version = &metadata.max_version;
    let (has_build_rs, is_proc_macro) =
        match state.crate_downloader.download_and_extract(&name, latest_version).await {
            Ok(extracted) => (extracted.has_build_rs, extracted.is_proc_macro),
            Err(_) => {
                // If download fails, store with defaults (we still have the metadata)
                (false, false)
            }
        };

    // Step 4: Store the latest version in the database
    let version_id = match state
        .db
        .upsert_version(crate_id, latest_version, has_build_rs, is_proc_macro)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            // Log but don't fail - we still stored the crate
            tracing::warn!("Failed to store version: {}", e);
            0
        }
    };

    // Return success response with stored data
    Json(json!({
        "success": true,
        "crate_id": crate_id,
        "version_id": version_id,
        "stored": {
            "name": metadata.name,
            "description": metadata.description,
            "repo_url": metadata.repo_url,
            "download_count": metadata.download_count,
            "latest_version": latest_version,
            "has_build_rs": has_build_rs,
            "is_proc_macro": is_proc_macro
        }
    }))
    .into_response()
}

/// Get a stored crate from the database
/// GET /api/crawler/stored-crate/{name}
///
/// Retrieves a crate that was previously stored using crawl-and-store.
/// Returns 404 if the crate doesn't exist in the database.
async fn get_stored_crate(
    Path(name): Path<String>,
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> impl IntoResponse {
    match state.db.get_crate_by_name(&name).await {
        Ok(Some(crate_info)) => {
            Json(json!({
                "success": true,
                "crate": {
                    "id": crate_info.id,
                    "name": crate_info.name,
                    "description": crate_info.description,
                    "repo_url": crate_info.repo_url,
                    "download_count": crate_info.download_count,
                    "finding_count": crate_info.finding_count,
                    "max_severity": crate_info.max_severity,
                    "created_at": crate_info.created_at,
                    "updated_at": crate_info.updated_at
                }
            }))
            .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": format!("Crate '{}' not found in database", name)
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Database error: {}", e)
            })),
        )
            .into_response(),
    }
}

/// Request body for adding a version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddVersionRequest {
    /// Crate name (must already exist in the database)
    pub crate_name: String,
    /// Version number to add
    pub version: String,
    /// Whether this version has a build.rs (optional, defaults to false)
    pub has_build_rs: Option<bool>,
    /// Whether this is a proc-macro crate (optional, defaults to false)
    pub is_proc_macro: Option<bool>,
}

/// Add a version to an existing crate (for testing)
/// POST /api/crawler/add-version
///
/// This endpoint adds a version to an existing crate without downloading from crates.io.
/// Useful for testing version comparison features.
async fn add_version(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    axum::extract::Json(request): axum::extract::Json<AddVersionRequest>,
) -> impl IntoResponse {
    // Step 1: Look up the crate by name
    let crate_info = match state.db.get_crate_by_name(&request.crate_name).await {
        Ok(Some(info)) => info,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "success": false,
                    "error": format!("Crate '{}' not found. Use crawl-and-store first.", request.crate_name)
                })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": format!("Database error: {}", e)
                })),
            )
                .into_response();
        }
    };

    // Step 2: Add the version
    let has_build_rs = request.has_build_rs.unwrap_or(false);
    let is_proc_macro = request.is_proc_macro.unwrap_or(false);

    let version_id = match state
        .db
        .upsert_version(crate_info.id, &request.version, has_build_rs, is_proc_macro)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": format!("Failed to add version: {}", e)
                })),
            )
                .into_response();
        }
    };

    Json(json!({
        "success": true,
        "crate_id": crate_info.id,
        "version_id": version_id,
        "crate_name": request.crate_name,
        "version": request.version,
        "has_build_rs": has_build_rs,
        "is_proc_macro": is_proc_macro
    }))
    .into_response()
}

/// Request body for storing an analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreAnalysisResultRequest {
    /// Crate name (used to look up version_id)
    pub crate_name: String,
    /// Version number (used with crate_name to look up version_id)
    pub version: String,
    /// Type of issue detected
    pub issue_type: String,
    /// Severity level (low, medium, high)
    pub severity: String,
    /// Path to the file containing the issue
    pub file_path: String,
    /// Starting line number (optional)
    pub line_start: Option<i32>,
    /// Ending line number (optional)
    pub line_end: Option<i32>,
    /// Code snippet containing the issue (optional)
    pub code_snippet: Option<String>,
    /// Context before the code snippet (optional)
    pub context_before: Option<String>,
    /// Context after the code snippet (optional)
    pub context_after: Option<String>,
    /// Summary of the finding (optional)
    pub summary: Option<String>,
    /// Detailed information as JSON (optional)
    pub details: Option<String>,
}

/// Store an analysis result (finding) in the database
/// POST /api/crawler/store-finding
///
/// This endpoint stores a single analysis finding for a specific crate version.
/// The crate and version must already exist in the database (use crawl-and-store first).
///
/// Request body (JSON):
/// - crate_name: name of the crate
/// - version: version number
/// - issue_type: type of issue (network, file_access, shell_command, etc.)
/// - severity: severity level (low, medium, high)
/// - file_path: path to the file containing the issue
/// - line_start, line_end: optional line numbers
/// - code_snippet: optional code excerpt
/// - context_before, context_after: optional surrounding context
/// - summary: optional human-readable summary
/// - details: optional JSON details
///
/// Returns:
/// - finding_id: database ID of the stored finding
/// - version_id: version ID the finding is associated with
async fn store_finding(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    axum::extract::Json(request): axum::extract::Json<StoreAnalysisResultRequest>,
) -> impl IntoResponse {
    // Step 1: Look up the version_id by crate name and version number
    let version_id = match state
        .db
        .get_version_id(&request.crate_name, &request.version)
        .await
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "success": false,
                    "error": format!(
                        "Version '{}' for crate '{}' not found. Use crawl-and-store first.",
                        request.version, request.crate_name
                    )
                })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": format!("Database error: {}", e)
                })),
            )
                .into_response();
        }
    };

    // Step 2: Insert the analysis result
    let finding_id = match state
        .db
        .insert_analysis_result(
            version_id,
            &request.issue_type,
            &request.severity,
            &request.file_path,
            request.line_start,
            request.line_end,
            request.code_snippet.as_deref(),
            request.context_before.as_deref(),
            request.context_after.as_deref(),
            request.summary.as_deref(),
            request.details.as_deref(),
        )
        .await
    {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": format!("Failed to store finding: {}", e)
                })),
            )
                .into_response();
        }
    };

    // Return success response
    Json(json!({
        "success": true,
        "finding_id": finding_id,
        "version_id": version_id,
        "stored": {
            "crate_name": request.crate_name,
            "version": request.version,
            "issue_type": request.issue_type,
            "severity": request.severity,
            "file_path": request.file_path,
            "line_start": request.line_start,
            "line_end": request.line_end
        }
    }))
    .into_response()
}

/// Get all findings for a specific crate version
/// GET /api/crawler/findings/{crate_name}/{version}
///
/// Returns all analysis results (findings) for the specified crate version.
async fn get_findings(
    Path((crate_name, version)): Path<(String, String)>,
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> impl IntoResponse {
    // Step 1: Look up the version_id
    let version_id = match state.db.get_version_id(&crate_name, &version).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "success": false,
                    "error": format!(
                        "Version '{}' for crate '{}' not found",
                        version, crate_name
                    )
                })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": format!("Database error: {}", e)
                })),
            )
                .into_response();
        }
    };

    // Step 2: Get all findings for this version
    let findings = match state.db.get_findings_by_version(version_id).await {
        Ok(findings) => findings,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": format!("Failed to retrieve findings: {}", e)
                })),
            )
                .into_response();
        }
    };

    Json(json!({
        "success": true,
        "crate_name": crate_name,
        "version": version,
        "version_id": version_id,
        "count": findings.len(),
        "findings": findings
    }))
    .into_response()
}

/// Request body for parallel crate processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessParallelRequest {
    /// List of crate names to process
    pub crate_names: Vec<String>,
    /// Maximum concurrent downloads (optional, defaults to 10)
    pub max_concurrent: Option<usize>,
}

/// Process multiple crates in parallel
/// POST /api/crawler/process-parallel
///
/// This endpoint fetches metadata and stores multiple crates concurrently.
/// It uses a semaphore to limit concurrent requests to crates.io.
///
/// Request body (JSON):
/// - crate_names: array of crate names to process
/// - max_concurrent: optional max concurrent requests (default: 10)
///
/// Returns:
/// - total: total number of crates processed
/// - successful: number of successful operations
/// - failed: number of failed operations
/// - results: detailed results for each crate
async fn process_parallel(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    axum::extract::Json(request): axum::extract::Json<ProcessParallelRequest>,
) -> impl IntoResponse {
    let max_concurrent = request.max_concurrent.unwrap_or(10);

    // Create a Crawler instance with the configured concurrency
    let config = CrawlerConfig { max_concurrent };
    let crawler = Crawler::from_arc(
        Arc::clone(&state.db),
        Arc::clone(&state.crates_io_client),
        Arc::clone(&state.crate_downloader),
        config,
    );

    // Process the crates in parallel
    let results = crawler.process_crates(request.crate_names).await;

    // Count successes and failures
    let successful = results.iter().filter(|r| r.success).count();
    let failed = results.iter().filter(|r| !r.success).count();

    // Build results array
    let result_json: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            json!({
                "name": r.name,
                "version": r.version,
                "success": r.success,
                "error": r.error,
                "crate_id": r.crate_id,
                "version_id": r.version_id
            })
        })
        .collect();

    Json(json!({
        "success": true,
        "total": results.len(),
        "successful": successful,
        "failed": failed,
        "results": result_json
    }))
}

/// Analyze a crate's build.rs file for suspicious patterns
/// GET /api/crawler/analyze/{name}/{version}
///
/// This endpoint downloads a crate, extracts it, and runs the pattern detector
/// on its build.rs file (if present). Returns all detected findings.
///
/// Returns:
/// - success: true if analysis completed
/// - crate_name: name of the analyzed crate
/// - version: version that was analyzed
/// - has_build_rs: whether the crate has a build.rs file
/// - findings: array of detected suspicious patterns
async fn analyze_crate(
    Path((name, version)): Path<(String, String)>,
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> impl IntoResponse {
    // Step 1: Download and extract the crate
    let extracted = match state.crate_downloader.download_and_extract(&name, &version).await {
        Ok(extracted) => extracted,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": format!("Failed to download crate: {}", e)
                })),
            )
                .into_response();
        }
    };

    // Step 2: Check if build.rs exists
    if !extracted.has_build_rs {
        return Json(json!({
            "success": true,
            "crate_name": name,
            "version": version,
            "has_build_rs": false,
            "findings": [],
            "message": "No build.rs file found in this crate"
        }))
        .into_response();
    }

    // Step 3: Read the build.rs file
    let build_rs_path = extracted
        .build_rs_path
        .expect("has_build_rs is true but no path");
    let source = match std::fs::read_to_string(&build_rs_path) {
        Ok(content) => content,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": format!("Failed to read build.rs: {}", e)
                })),
            )
                .into_response();
        }
    };

    // Step 4: Run the detector
    let detector = Detector::new();
    let findings = detector.analyze(&source, "build.rs");

    // Step 5: Convert findings to JSON
    let findings_json: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            json!({
                "issue_type": f.issue_type.to_string(),
                "severity": f.severity.to_string(),
                "file_path": f.file_path,
                "line_start": f.line_start,
                "line_end": f.line_end,
                "code_snippet": f.code_snippet,
                "context_before": f.context_before,
                "context_after": f.context_after,
                "summary": f.summary,
                "details": f.details
            })
        })
        .collect();

    Json(json!({
        "success": true,
        "crate_name": name,
        "version": version,
        "has_build_rs": true,
        "findings_count": findings.len(),
        "findings": findings_json
    }))
    .into_response()
}

/// Request body for testing the detector on inline code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestDetectorRequest {
    /// The Rust source code to analyze
    pub source: String,
    /// Optional file path (defaults to "test.rs")
    pub file_path: Option<String>,
}

/// Test the pattern detector on inline code
/// POST /api/crawler/test-detector
///
/// This endpoint allows testing the pattern detector on arbitrary Rust code
/// without downloading a crate. Useful for development and testing.
///
/// Request body (JSON):
/// - source: The Rust source code to analyze
/// - file_path: Optional file path (defaults to "test.rs")
///
/// Returns:
/// - success: true if analysis completed
/// - findings_count: number of findings detected
/// - findings: array of detected suspicious patterns
async fn test_detector(
    axum::extract::Json(request): axum::extract::Json<TestDetectorRequest>,
) -> impl IntoResponse {
    let file_path = request.file_path.unwrap_or_else(|| "test.rs".to_string());

    let detector = Detector::new();
    let findings = detector.analyze(&request.source, &file_path);

    // Convert findings to JSON
    let findings_json: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            json!({
                "issue_type": f.issue_type.to_string(),
                "severity": f.severity.to_string(),
                "file_path": f.file_path,
                "line_start": f.line_start,
                "line_end": f.line_end,
                "code_snippet": f.code_snippet,
                "context_before": f.context_before,
                "context_after": f.context_after,
                "summary": f.summary,
                "details": f.details
            })
        })
        .collect();

    Json(json!({
        "success": true,
        "file_path": file_path,
        "source_length": request.source.len(),
        "findings_count": findings.len(),
        "findings": findings_json
    }))
}
