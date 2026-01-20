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

use crate::templates::{
    CrateDetailTemplate, CrateListTemplate, LandingTemplate, NotFoundTemplate, PageNumber,
};

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
        (Ok(stats), Ok(recent_findings)) => HtmlTemplate(LandingTemplate {
            stats,
            recent_findings,
        })
        .into_response(),
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

/// Query parameters for crate list page
#[derive(Debug, Deserialize)]
pub struct CrateListPageQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

async fn crate_list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CrateListPageQuery>,
) -> impl IntoResponse {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(10).clamp(1, 100);

    // Get total count for pagination
    let total_crates = match state.db.get_crate_count().await {
        Ok(count) => count,
        Err(err) => {
            tracing::error!("Database error getting count: {}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", err),
            )
                .into_response();
        }
    };

    // Calculate total pages
    let total_pages = (total_crates as u32).div_ceil(per_page);
    let total_pages = total_pages.max(1);

    // Ensure page is within bounds
    let page = page.min(total_pages);

    // Pre-compute pagination values
    let showing_start = (page - 1) * per_page + 1;
    let showing_end = (page * per_page).min(total_crates as u32);
    let has_prev = page > 1;
    let has_next = page < total_pages;
    let prev_page = if has_prev { page - 1 } else { 1 };
    let next_page = if has_next { page + 1 } else { total_pages };

    // Generate page numbers for pagination UI
    let page_numbers: Vec<PageNumber> = (1..=total_pages)
        .map(|n| PageNumber {
            number: n,
            is_current: n == page,
        })
        .collect();

    // Get paginated crates
    match state.db.get_crates_paginated(page, per_page).await {
        Ok(crates) => HtmlTemplate(CrateListTemplate {
            crates,
            total_crates,
            page,
            per_page,
            total_pages,
            showing_start,
            showing_end,
            prev_page,
            next_page,
            has_prev,
            has_next,
            page_numbers,
        })
        .into_response(),
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

            // Get findings with comparison to previous version (shows removed patterns)
            let findings = if let Some(vid) = version_id {
                state
                    .db
                    .get_findings_with_comparison(crate_info.id, vid)
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
            (StatusCode::NOT_FOUND, format!("Crate '{}' not found", name)).into_response()
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
#[allow(dead_code)]
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

async fn api_crate_detail(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    match state.db.get_crate_by_name(&name).await {
        Ok(Some(crate_info)) => {
            // Get versions for this crate
            let versions = state
                .db
                .get_versions_for_crate(crate_info.id)
                .await
                .unwrap_or_default();

            Json(json!({
                "crate": {
                    "id": crate_info.id,
                    "name": crate_info.name,
                    "description": crate_info.description,
                    "repo_url": crate_info.repo_url,
                    "download_count": crate_info.download_count,
                    "finding_count": crate_info.finding_count,
                    "max_severity": crate_info.max_severity
                },
                "versions": versions.iter().map(|v| json!({
                    "id": v.id,
                    "version_number": v.version_number,
                    "has_build_rs": v.has_build_rs,
                    "is_proc_macro": v.is_proc_macro,
                    "finding_count": v.finding_count,
                    "last_analyzed": v.last_analyzed
                })).collect::<Vec<_>>()
            }))
            .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": format!("Crate '{}' not found", name),
                "message": "The requested crate does not exist in the database"
            })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": format!("Database error: {}", err),
                "message": "Failed to fetch crate details"
            })),
        )
            .into_response(),
    }
}

async fn api_version_detail(
    State(state): State<Arc<AppState>>,
    Path((name, version)): Path<(String, String)>,
) -> impl IntoResponse {
    // First get the crate to get its ID
    let crate_info = match state.db.get_crate_by_name(&name).await {
        Ok(Some(info)) => info,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": format!("Crate '{}' not found", name),
                    "message": "The requested crate does not exist in the database"
                })),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": format!("Database error: {}", err),
                    "message": "Failed to fetch crate information"
                })),
            )
                .into_response();
        }
    };

    // Get all versions for this crate
    let versions = match state.db.get_versions_for_crate(crate_info.id).await {
        Ok(v) => v,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": format!("Database error: {}", err),
                    "message": "Failed to fetch versions"
                })),
            )
                .into_response();
        }
    };

    // Find the specific version
    let version_info = versions.iter().find(|v| v.version_number == version);

    match version_info {
        Some(ver) => {
            // Get findings for this version
            let findings = state
                .db
                .get_findings_by_version(ver.id)
                .await
                .unwrap_or_default();

            Json(json!({
                "crate": {
                    "id": crate_info.id,
                    "name": crate_info.name
                },
                "version": {
                    "id": ver.id,
                    "version_number": ver.version_number,
                    "has_build_rs": ver.has_build_rs,
                    "is_proc_macro": ver.is_proc_macro,
                    "finding_count": ver.finding_count,
                    "last_analyzed": ver.last_analyzed
                },
                "findings": findings.iter().map(|f| json!({
                    "id": f.id,
                    "issue_type": f.issue_type,
                    "severity": f.severity,
                    "file_path": f.file_path,
                    "line_start": f.line_start,
                    "line_end": f.line_end,
                    "code_snippet": f.code_snippet,
                    "context_before": f.context_before,
                    "context_after": f.context_after,
                    "summary": f.summary
                })).collect::<Vec<_>>(),
                "findings_count": findings.len()
            }))
            .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": format!("Version '{}' not found for crate '{}'", version, name),
                "message": "The requested version does not exist for this crate"
            })),
        )
            .into_response(),
    }
}

async fn api_compare(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    // Get the crate
    let crate_info = match state.db.get_crate_by_name(&name).await {
        Ok(Some(info)) => info,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": format!("Crate '{}' not found", name),
                    "message": "The requested crate does not exist in the database"
                })),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": format!("Database error: {}", err),
                    "message": "Failed to fetch crate information"
                })),
            )
                .into_response();
        }
    };

    // Get versions for comparison
    let versions = match state.db.get_versions_for_crate(crate_info.id).await {
        Ok(v) => v,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": format!("Database error: {}", err),
                    "message": "Failed to fetch versions for comparison"
                })),
            )
                .into_response();
        }
    };

    Json(json!({
        "crate": {
            "id": crate_info.id,
            "name": crate_info.name
        },
        "versions": versions.iter().map(|v| json!({
            "id": v.id,
            "version_number": v.version_number,
            "has_build_rs": v.has_build_rs,
            "is_proc_macro": v.is_proc_macro,
            "finding_count": v.finding_count
        })).collect::<Vec<_>>(),
        "diff": null
    }))
    .into_response()
}

async fn api_recent_findings(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.db.get_recent_findings(10).await {
        Ok(findings) => Json(json!({
            "findings": findings.iter().map(|f| json!({
                "id": f.id,
                "crate_name": f.crate_name,
                "version": f.version,
                "issue_type": f.issue_type,
                "severity": f.severity,
                "summary": f.summary
            })).collect::<Vec<_>>(),
            "count": findings.len()
        }))
        .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": format!("Database error: {}", err),
                "message": "Failed to fetch recent findings"
            })),
        )
            .into_response(),
    }
}

async fn api_interesting(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Try to get interesting stats - these are best-effort, return defaults if unavailable
    match state.db.get_crates().await {
        Ok(crates) => {
            // Find most flagged crate (highest finding_count)
            let most_flagged = crates
                .iter()
                .filter(|c| c.finding_count > 0)
                .max_by_key(|c| c.finding_count)
                .map(|c| {
                    json!({
                        "name": c.name,
                        "finding_count": c.finding_count,
                        "max_severity": c.max_severity
                    })
                });

            Json(json!({
                "most_flagged": most_flagged,
                "most_common_pattern": null,
                "total_crates_with_findings": crates.iter().filter(|c| c.finding_count > 0).count()
            }))
            .into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": format!("Database error: {}", err),
                "message": "Failed to fetch interesting facts"
            })),
        )
            .into_response(),
    }
}
