//! API routes for the dashboard

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json, Response},
    routing::get,
    Router,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use sus_core::Database;

use crate::templates::{CrateDetailTemplate, CrateListTemplate, LandingTemplate, NotFoundTemplate};

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
        .fallback(not_found_handler)
        .with_state(state)
}

/// Handler for 404 Not Found pages
async fn not_found_handler() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, HtmlTemplate(NotFoundTemplate))
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

async fn index(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Fetch dashboard stats and recent findings from database
    let stats_result = state.db.get_dashboard_stats().await;
    let findings_result = state.db.get_recent_findings(10).await;

    match (stats_result, findings_result) {
        (Ok(stats), Ok(recent_findings)) => {
            HtmlTemplate(LandingTemplate {
                stats,
                recent_findings,
            })
            .into_response()
        }
        (Err(err), _) | (_, Err(err)) => {
            tracing::error!("Database error loading dashboard: {}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", err),
            )
                .into_response()
        }
    }
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

/// Query parameters for crate detail page
#[derive(Debug, Deserialize)]
pub struct CrateDetailQuery {
    pub version: Option<String>,
}

async fn crate_detail(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Query(query): Query<CrateDetailQuery>,
) -> impl IntoResponse {
    // Get crate info
    let crate_result = state.db.get_crate_by_name(&name).await;

    match crate_result {
        Ok(Some(crate_info)) => {
            // Get versions for this crate
            let versions = state
                .db
                .get_versions_for_crate(crate_info.id)
                .await
                .unwrap_or_default();

            // Determine which version to show findings for
            let selected_version = query.version.clone();
            let version_id = if let Some(ref ver_num) = selected_version {
                // Find the version ID for the selected version
                versions
                    .iter()
                    .find(|v| &v.version_number == ver_num)
                    .map(|v| v.id)
            } else {
                // Default to the latest version (first in the list since sorted by id DESC)
                versions.first().map(|v| v.id)
            };

            // Get findings for the selected version
            let findings = if let Some(vid) = version_id {
                state
                    .db
                    .get_findings_by_version(vid)
                    .await
                    .unwrap_or_default()
            } else {
                Vec::new()
            };

            HtmlTemplate(CrateDetailTemplate {
                crate_info,
                versions,
                findings,
                selected_version,
            })
            .into_response()
        }
        Ok(None) => {
            // Crate not found
            (
                StatusCode::NOT_FOUND,
                format!("Crate '{}' not found", name),
            )
                .into_response()
        }
        Err(err) => {
            tracing::error!("Database error loading crate '{}': {}", name, err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", err),
            )
                .into_response()
        }
    }
}

async fn crate_compare() -> &'static str {
    "Sus Dashboard - Version Comparison (TODO: implement template)"
}

async fn stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.db.get_dashboard_stats().await {
        Ok(stats) => Json(json!({
            "total_crates": stats.total_crates,
            "total_findings": stats.total_findings,
            "by_severity": {
                "high": stats.high_severity,
                "medium": stats.medium_severity,
                "low": stats.low_severity
            }
        }))
        .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": format!("Database error: {}", err),
                "message": "Failed to fetch dashboard statistics"
            })),
        )
            .into_response(),
    }
}

/// Query parameters for crate list API
#[derive(Debug, Deserialize)]
pub struct CrateListQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub severity: Option<String>,
    pub issue_type: Option<String>,
    pub search: Option<String>,
    pub sort: Option<String>,
}

async fn api_crates(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CrateListQuery>,
) -> impl IntoResponse {
    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20).min(100); // Cap at 100

    match state.db.get_crates().await {
        Ok(crates) => {
            let total = crates.len() as u32;
            let start = ((page - 1) * per_page) as usize;
            let end = (start + per_page as usize).min(crates.len());
            let page_crates = if start < crates.len() {
                &crates[start..end]
            } else {
                &[]
            };

            Json(json!({
                "crates": page_crates.iter().map(|c| json!({
                    "id": c.id,
                    "name": c.name,
                    "description": c.description,
                    "repo_url": c.repo_url,
                    "download_count": c.download_count,
                    "finding_count": c.finding_count,
                    "max_severity": c.max_severity
                })).collect::<Vec<_>>(),
                "total": total,
                "page": page,
                "per_page": per_page
            }))
            .into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": format!("Database error: {}", err),
                "message": "Failed to fetch crate list"
            })),
        )
            .into_response(),
    }
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
