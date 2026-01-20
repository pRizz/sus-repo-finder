//! HTML templates for the dashboard

use askama::Template;
use sus_core::{
    CrateWithStats, DashboardStats, FindingStatus, FindingWithStatus, RecentFinding,
    VersionWithStats,
};

/// Filter to format download counts with K/M suffixes
pub mod filters {
    pub fn format_downloads(count: &i64) -> askama::Result<String> {
        let count = *count;
        if count >= 1_000_000 {
            Ok(format!("{:.1}M", count as f64 / 1_000_000.0))
        } else if count >= 1_000 {
            Ok(format!("{:.1}K", count as f64 / 1_000.0))
        } else {
            Ok(count.to_string())
        }
    }

    /// Format a date string (from SQLite timestamp) to a shorter format
    /// Accepts ISO 8601 format like "2025-01-19 17:58:00"
    pub fn format_date(date: &str) -> askama::Result<String> {
        // SQLite timestamps are already in a readable format
        // Just extract the date portion (first 10 characters)
        if date.len() >= 10 {
            Ok(date[..10].to_string())
        } else {
            Ok(date.to_string())
        }
    }

    pub fn pluralize(count: &i64) -> askama::Result<&'static str> {
        if *count == 1 {
            Ok("")
        } else {
            Ok("s")
        }
    }

    /// Format issue type for display
    pub fn format_issue_type(issue_type: &str) -> askama::Result<String> {
        match issue_type {
            "network" => Ok("Network Call".to_string()),
            "file_access" => Ok("File Access".to_string()),
            "shell_command" => Ok("Shell Command".to_string()),
            "process_spawn" => Ok("Process Spawn".to_string()),
            "env_access" => Ok("Env Access".to_string()),
            "dynamic_lib" => Ok("Dynamic Library".to_string()),
            "unsafe_block" => Ok("Unsafe Block".to_string()),
            "build_download" => Ok("Build Download".to_string()),
            "sensitive_path" => Ok("Sensitive Path".to_string()),
            "obfuscation" => Ok("Obfuscation".to_string()),
            "compiler_flags" => Ok("Compiler Flags".to_string()),
            "macro_codegen" => Ok("Macro Codegen".to_string()),
            other => Ok(other.to_string()),
        }
    }
}

/// Landing page template
#[derive(Template)]
#[template(path = "landing.html")]
pub struct LandingTemplate {
    pub stats: DashboardStats,
    pub recent_findings: Vec<RecentFinding>,
}

/// Helper struct for page numbers in pagination
#[allow(dead_code)]
pub struct PageNumber {
    pub number: u32,
    pub is_current: bool,
}

/// Crate list page template
#[derive(Template)]
#[template(path = "crate_list.html")]
#[allow(dead_code)]
pub struct CrateListTemplate {
    pub crates: Vec<CrateWithStats>,
    pub total_crates: i64,
    pub page: u32,
    pub per_page: u32,
    pub total_pages: u32,
    // Pre-computed pagination values for the template
    pub showing_start: u32,
    pub showing_end: u32,
    pub prev_page: u32,
    pub next_page: u32,
    pub has_prev: bool,
    pub has_next: bool,
    pub page_numbers: Vec<PageNumber>,
}

/// Crate detail page template
#[derive(Template)]
#[template(path = "crate_detail.html")]
pub struct CrateDetailTemplate {
    pub crate_info: CrateWithStats,
    pub versions: Vec<VersionWithStats>,
    pub findings: Vec<FindingWithStatus>,
    pub selected_version: Option<String>,
}

/// 404 Not Found page template
#[derive(Template)]
#[template(path = "not_found.html")]
pub struct NotFoundTemplate;
