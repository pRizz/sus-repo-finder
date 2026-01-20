//! HTML templates for the crawler portal

use askama::Template;

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
}

impl StatusTemplate {
    /// Create a new status template with the given values
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
            progress_display: format!("{:.1}", progress_percent),
        }
    }
}
