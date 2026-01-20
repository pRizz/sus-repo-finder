//! API routes for the crawler web portal

use askama::Template;
use axum::{
    extract::Path,
    http::StatusCode,
    response::{Html, IntoResponse, Json, Response},
    routing::get,
    Router,
};
use serde_json::json;
use std::sync::Arc;
use sus_core::Database;

use crate::templates::StatusTemplate;
use sus_crawler::{CrateDownloader, CratesIoClient};

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
    /// Database connection - will be used once API handlers are implemented
    #[allow(dead_code)]
    pub db: Database,
    /// Crates.io API client
    pub crates_io_client: CratesIoClient,
    /// Crate downloader for source extraction
    pub crate_downloader: CrateDownloader,
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
        db,
        crates_io_client,
        crate_downloader,
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
