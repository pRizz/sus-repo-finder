//! API routes for the dashboard

use askama::Template;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use std::sync::Arc;
use sus_core::Database;

use crate::templates::CrateListTemplate;

/// Application state shared across handlers
pub struct AppState {
    /// Database connection
    pub db: Database,
}

/// Create the API router
pub fn create_router(db: Database) -> Router {
    let state = Arc::new(AppState { db });

    Router::new()
        // Pages
        .route("/", get(index))
        .route("/crates", get(crate_list))
        .route("/crates/{name}", get(crate_detail))
        .route("/crates/{name}/compare", get(crate_compare))
        // API
        .route("/api/stats", get(stats))
        .route("/api/crates", get(api_crates))
        .route("/api/crates/{name}", get(api_crate_detail))
        .route(
            "/api/crates/{name}/versions/{version}",
            get(api_version_detail),
        )
        .route("/api/crates/{name}/compare", get(api_compare))
        .route("/api/findings/recent", get(api_recent_findings))
        .route("/api/findings/interesting", get(api_interesting))
        .with_state(state)
}

/// Wrapper for HTML responses from Askama templates
struct HtmlTemplate<T>(T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => {
                tracing::error!("Template error: {}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Template error: {}", err),
                )
                    .into_response()
            }
        }
    }
}

async fn index() -> &'static str {
    "Sus Dashboard - Landing Page (TODO: implement template)"
}

async fn crate_list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.db.get_crates().await {
        Ok(crates) => {
            let total_crates = crates.len() as i64;
            HtmlTemplate(CrateListTemplate {
                crates,
                total_crates,
            })
            .into_response()
        }
        Err(err) => {
            tracing::error!("Database error: {}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", err),
            )
                .into_response()
        }
    }
}

async fn crate_detail() -> &'static str {
    "Sus Dashboard - Crate Detail (TODO: implement template)"
}

async fn crate_compare() -> &'static str {
    "Sus Dashboard - Version Comparison (TODO: implement template)"
}

async fn stats() -> &'static str {
    r#"{"total_crates": 0, "total_findings": 0, "by_severity": {"high": 0, "medium": 0, "low": 0}}"#
}

async fn api_crates() -> &'static str {
    r#"{"crates": [], "total": 0, "page": 1, "per_page": 20}"#
}

async fn api_crate_detail() -> &'static str {
    r#"{"error": "Crate not found"}"#
}

async fn api_version_detail() -> &'static str {
    r#"{"error": "Version not found"}"#
}

async fn api_compare() -> &'static str {
    r#"{"versions": [], "diff": null}"#
}

async fn api_recent_findings() -> &'static str {
    r#"{"findings": []}"#
}

async fn api_interesting() -> &'static str {
    r#"{"most_flagged": null, "most_common_pattern": null}"#
}
