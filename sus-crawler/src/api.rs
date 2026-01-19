//! API routes for the crawler web portal

use axum::{Router, routing::get};
use sus_core::Database;
use std::sync::Arc;

/// Application state shared across handlers
pub struct AppState {
    pub db: Database,
}

/// Create the API router
pub fn create_router(db: Database) -> Router {
    let state = Arc::new(AppState { db });

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
