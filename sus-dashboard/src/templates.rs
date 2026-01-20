//! HTML templates for the dashboard

use askama::Template;
use sus_core::CrateWithStats;

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
}

/// Crate list page template
#[derive(Template)]
#[template(path = "crate_list.html")]
pub struct CrateListTemplate {
    pub crates: Vec<CrateWithStats>,
    pub total_crates: i64,
}
