//! Pattern definitions and finding structures

use serde::{Deserialize, Serialize};
use sus_core::{IssueType, Severity};

/// A detected suspicious pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub issue_type: IssueType,
    pub severity: Severity,
    pub file_path: String,
    pub line_start: usize,
    pub line_end: usize,
    pub code_snippet: String,
    pub context_before: String,
    pub context_after: String,
    pub summary: String,
    pub details: Option<serde_json::Value>,
}

impl Finding {
    /// Create a new finding
    pub fn new(
        issue_type: IssueType,
        severity: Severity,
        file_path: String,
        line_start: usize,
        line_end: usize,
        code_snippet: String,
        summary: String,
    ) -> Self {
        Self {
            issue_type,
            severity,
            file_path,
            line_start,
            line_end,
            code_snippet,
            context_before: String::new(),
            context_after: String::new(),
            summary,
            details: None,
        }
    }

    /// Add context lines around the finding
    pub fn with_context(mut self, before: String, after: String) -> Self {
        self.context_before = before;
        self.context_after = after;
        self
    }

    /// Add detailed information as JSON
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// Extract code snippet with context from source
pub fn extract_snippet(
    source: &str,
    line_start: usize,
    line_end: usize,
    context_lines: usize,
) -> (String, String, String) {
    let lines: Vec<&str> = source.lines().collect();
    let total_lines = lines.len();

    // Calculate context ranges (1-indexed to 0-indexed)
    let start_idx = line_start.saturating_sub(1);
    let end_idx = line_end.min(total_lines);

    let context_start = start_idx.saturating_sub(context_lines);
    let context_end = (end_idx + context_lines).min(total_lines);

    let context_before = lines[context_start..start_idx].join("\n");
    let snippet = lines[start_idx..end_idx].join("\n");
    let context_after = lines[end_idx..context_end].join("\n");

    (context_before, snippet, context_after)
}

/// Get default severity for an issue type
pub fn default_severity(issue_type: IssueType) -> Severity {
    match issue_type {
        IssueType::SensitivePath => Severity::High,
        IssueType::BuildDownload => Severity::High,
        IssueType::Obfuscation => Severity::High,
        IssueType::Network => Severity::Medium,
        IssueType::ShellCommand => Severity::Medium,
        IssueType::ProcessSpawn => Severity::Medium,
        IssueType::FileAccess => Severity::Medium,
        IssueType::DynamicLib => Severity::Medium,
        IssueType::CompilerFlags => Severity::Medium,
        IssueType::MacroCodegen => Severity::Medium,
        IssueType::EnvAccess => Severity::Low,
        IssueType::UnsafeBlock => Severity::Low,
    }
}
