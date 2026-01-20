//! API routes for the crawler web portal

use axum::{
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde_json::json;
use std::sync::Arc;
use sus_core::Database;

use sus_crawler::CratesIoClient;

/// Application state shared across handlers
pub struct AppState {
    /// Database connection - will be used once API handlers are implemented
    #[allow(dead_code)]
    pub db: Database,
    /// Crates.io API client
    pub crates_io_client: CratesIoClient,
}

/// Create the API router
pub fn create_router(db: Database) -> Router {
    let crates_io_client = CratesIoClient::new().expect("Failed to create crates.io client");
    let state = Arc::new(AppState {
        db,
        crates_io_client,
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
        .with_state(state)
}

async fn index() -> &'static str {
    "Crawler Portal - Status Page (TODO: implement template)"
}

async fn detailed() -> &'static str {
    "Crawler Portal - Detailed View (TODO: implement template)"
}

async fn errors() -> &'static str {
    "Crawler Portal - Errors Page (TODO: implement template)"
}

async fn status() -> &'static str {
    r#"{"status": "idle", "current_crate": null}"#
}

async fn stats() -> &'static str {
    r#"{"crates_scanned": 0, "findings_count": 0, "errors_count": 0}"#
}

async fn queue() -> &'static str {
    r#"{"pending": 0, "items": []}"#
}

async fn api_errors() -> &'static str {
    r#"{"errors": []}"#
}

async fn pause() -> &'static str {
    r#"{"success": true, "status": "paused"}"#
}

async fn resume() -> &'static str {
    r#"{"success": true, "status": "running"}"#
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
