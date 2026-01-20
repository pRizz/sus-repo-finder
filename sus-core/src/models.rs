//! Database models for Sus Repo Finder

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// A crate from crates.io
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Crate {
    pub id: i64,
    pub name: String,
    pub repo_url: Option<String>,
    pub description: Option<String>,
    pub download_count: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A crate with additional stats for display
/// Note: Uses String for timestamps because SQLite returns TEXT format
/// and this struct derives FromRow for direct database queries.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CrateWithStats {
    pub id: i64,
    pub name: String,
    pub repo_url: Option<String>,
    pub description: Option<String>,
    pub download_count: i64,
    /// Created timestamp as stored in SQLite (TEXT format)
    pub created_at: String,
    /// Updated timestamp as stored in SQLite (TEXT format)
    pub updated_at: String,
    pub finding_count: i64,
    pub max_severity: Option<String>,
}

/// A version of a crate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub id: i64,
    pub crate_id: i64,
    pub version_number: String,
    pub release_date: Option<DateTime<Utc>>,
    pub last_analyzed: Option<DateTime<Utc>>,
    pub analysis_status: String,
    pub has_build_rs: bool,
    pub is_proc_macro: bool,
}

/// An analysis result (finding)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub id: i64,
    pub version_id: i64,
    pub issue_type: String,
    pub severity: String,
    pub file_path: String,
    pub line_start: Option<i32>,
    pub line_end: Option<i32>,
    pub code_snippet: Option<String>,
    pub context_before: Option<String>,
    pub context_after: Option<String>,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Crawler state for checkpointing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlerState {
    pub id: i64,
    pub run_id: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub last_checkpoint: Option<DateTime<Utc>>,
    pub crates_processed: i32,
    pub crates_total: i32,
    pub current_crate: Option<String>,
    pub queue_position: i32,
    pub errors_count: i32,
    pub findings_count: i32,
}

/// Crawler error record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlerError {
    pub id: i64,
    pub run_id: String,
    pub crate_name: Option<String>,
    pub version: Option<String>,
    pub error_type: Option<String>,
    pub error_message: Option<String>,
    pub occurred_at: DateTime<Utc>,
    pub retry_count: i32,
}

/// Crawler queue item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueItem {
    pub id: i64,
    pub crate_name: String,
    pub version: String,
    pub priority: i32,
    pub status: String,
    pub added_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Dashboard statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStats {
    pub total_crates: i64,
    pub total_findings: i64,
    pub high_severity: i64,
    pub medium_severity: i64,
    pub low_severity: i64,
}

/// A recent finding for the dashboard
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RecentFinding {
    pub id: i64,
    pub crate_name: String,
    pub version: String,
    pub issue_type: String,
    pub severity: String,
    pub summary: Option<String>,
    pub created_at: String,
}

/// An analysis result row from the database
/// Note: Uses String for timestamps because SQLite returns TEXT format
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AnalysisResultRow {
    pub id: i64,
    pub version_id: i64,
    pub issue_type: String,
    pub severity: String,
    pub file_path: String,
    pub line_start: Option<i32>,
    pub line_end: Option<i32>,
    pub code_snippet: Option<String>,
    pub context_before: Option<String>,
    pub context_after: Option<String>,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub created_at: String,
}

/// A version row from the database with finding count
/// Note: Uses String for timestamps because SQLite returns TEXT format
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct VersionWithStats {
    pub id: i64,
    pub crate_id: i64,
    pub version_number: String,
    pub has_build_rs: bool,
    pub is_proc_macro: bool,
    pub last_analyzed: Option<String>,
    pub finding_count: i64,
}

/// Status of a finding when comparing versions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingStatus {
    /// Finding exists in the current version
    Current,
    /// Finding is new in this version (didn't exist in previous version)
    New,
    /// Finding was removed/fixed in this version (existed in previous version)
    Removed,
}

/// A finding with status indicator for version comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingWithStatus {
    pub id: i64,
    pub version_id: i64,
    pub issue_type: String,
    pub severity: String,
    pub file_path: String,
    pub line_start: Option<i32>,
    pub line_end: Option<i32>,
    pub code_snippet: Option<String>,
    pub context_before: Option<String>,
    pub context_after: Option<String>,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub created_at: String,
    /// Status of this finding (current, new, or removed)
    pub status: FindingStatus,
    /// The version this finding is from (useful for removed findings)
    pub from_version: Option<String>,
}

/// Input struct for creating a new analysis result
///
/// This struct groups all parameters needed to insert a new finding,
/// reducing the number of function arguments.
#[derive(Debug, Clone)]
pub struct NewAnalysisResult<'a> {
    pub version_id: i64,
    pub issue_type: &'a str,
    pub severity: &'a str,
    pub file_path: &'a str,
    pub line_start: Option<i32>,
    pub line_end: Option<i32>,
    pub code_snippet: Option<&'a str>,
    pub context_before: Option<&'a str>,
    pub context_after: Option<&'a str>,
    pub summary: Option<&'a str>,
    pub details: Option<&'a str>,
}

/// A queue item row from the database
/// Note: Uses String for timestamps because SQLite returns TEXT format
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct QueueItemRow {
    pub id: i64,
    pub crate_name: String,
    pub version: String,
    pub priority: i32,
    pub status: String,
    pub added_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
}
