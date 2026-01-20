//! HTML templates for the crawler portal

use askama::Template;
use serde::{Deserialize, Serialize};

/// A simplified error item for display in templates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDisplay {
    /// Crate name
    pub crate_name: String,
    /// Version
    pub version: String,
    /// Error type (e.g., "download_failed", "parse_error")
    pub error_type: String,
    /// Error message
    pub error_message: String,
    /// When the error occurred
    pub occurred_at: String,
    /// Number of retry attempts
    pub retry_count: i32,
}

/// A simplified queue item for display in templates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueItemDisplay {
    /// Crate name
    pub crate_name: String,
    /// Version
    pub version: String,
    /// Priority level
    pub priority: i32,
}

/// Crawler status page template
#[derive(Template)]
#[template(path = "status.html")]
pub struct StatusTemplate {
    /// Current crawler status (running, paused, idle)
    pub status: String,
    /// Display version of status (capitalized)
    pub status_display: String,
    /// Total crates scanned
    pub crates_scanned: i64,
    /// Total findings detected
    pub findings_count: i64,
    /// Total errors encountered
    pub errors_count: i64,
    /// Number of crates in queue
    pub queue_size: i64,
    /// Whether there's a crate currently being processed
    pub has_current_crate: bool,
    /// Name of currently processing crate (if any)
    pub current_crate_name: String,
    /// Progress percentage (0-100)
    pub progress_percent: f64,
    /// Formatted progress display (e.g., "45.5")
    pub progress_display: String,
    /// List of pending queue items for display
    pub queue_items: Vec<QueueItemDisplay>,
    /// Number of items being shown (for display)
    pub queue_items_shown: i64,
    /// Whether there are more queue items than displayed
    pub has_more_queue_items: bool,
}

impl StatusTemplate {
    /// Create a new status template with the given values
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        status: &str,
        crates_scanned: i64,
        findings_count: i64,
        errors_count: i64,
        queue_size: i64,
        current_crate: Option<&str>,
        progress_percent: f64,
        queue_items: Vec<QueueItemDisplay>,
    ) -> Self {
        // Capitalize status for display
        let status_display = {
            let mut chars = status.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        };

        let queue_items_shown = queue_items.len() as i64;
        let has_more_queue_items = queue_size > queue_items_shown;

        Self {
            status: status.to_string(),
            status_display,
            crates_scanned,
            findings_count,
            errors_count,
            queue_size,
            has_current_crate: current_crate.is_some(),
            current_crate_name: current_crate.unwrap_or("").to_string(),
            progress_percent,
            progress_display: format!("{:.1}", progress_percent),
            queue_items,
            queue_items_shown,
            has_more_queue_items,
        }
    }
}

/// Crawler detailed view template with live logs
#[derive(Template)]
#[template(path = "detailed.html")]
pub struct DetailedTemplate {
    /// Current crawler status (running, paused, idle)
    pub status: String,
    /// Display version of status (capitalized)
    pub status_display: String,
    /// Total crates scanned
    pub crates_scanned: i64,
    /// Total findings detected
    pub findings_count: i64,
    /// Total errors encountered
    pub errors_count: i64,
    /// Number of crates in queue
    pub queue_size: i64,
    /// Whether there's a crate currently being processed
    pub has_current_crate: bool,
    /// Name of currently processing crate (if any)
    pub current_crate_name: String,
    /// Progress percentage (0-100)
    pub progress_percent: f64,
}

impl DetailedTemplate {
    /// Create a new detailed template with the given values
    pub fn new(
        status: &str,
        crates_scanned: i64,
        findings_count: i64,
        errors_count: i64,
        queue_size: i64,
        current_crate: Option<&str>,
        progress_percent: f64,
    ) -> Self {
        // Capitalize status for display
        let status_display = {
            let mut chars = status.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        };

        Self {
            status: status.to_string(),
            status_display,
            crates_scanned,
            findings_count,
            errors_count,
            queue_size,
            has_current_crate: current_crate.is_some(),
            current_crate_name: current_crate.unwrap_or("").to_string(),
            progress_percent,
        }
    }
}

/// Crawler errors page template
#[derive(Template)]
#[template(path = "errors.html")]
pub struct ErrorsTemplate {
    /// Current crawler status (running, paused, idle)
    pub status: String,
    /// Display version of status (capitalized)
    pub status_display: String,
    /// Total number of errors in database
    pub total_errors: i64,
    /// Count of download_failed errors
    pub download_failed_count: i64,
    /// Count of parse_error errors
    pub parse_error_count: i64,
    /// Count of analysis_failed errors
    pub analysis_failed_count: i64,
    /// List of errors to display
    pub errors: Vec<ErrorDisplay>,
}

impl ErrorsTemplate {
    /// Create a new errors template with the given values
    pub fn new(
        status: &str,
        total_errors: i64,
        download_failed_count: i64,
        parse_error_count: i64,
        analysis_failed_count: i64,
        errors: Vec<ErrorDisplay>,
    ) -> Self {
        // Capitalize status for display
        let status_display = {
            let mut chars = status.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        };

        Self {
            status: status.to_string(),
            status_display,
            total_errors,
            download_failed_count,
            parse_error_count,
            analysis_failed_count,
            errors,
        }
    }
}
