//! Sus Core - Shared types, database models, and queries
//!
//! This crate provides the foundational types and database access layer
//! used by both the crawler and dashboard applications.
//!
//! # Exported Types
//!
//! ## Database Access
//! - [`Database`] - Connection pool wrapper for SQLite
//!
//! ## Enums (from types module)
//! - [`Severity`] - Low, Medium, High severity levels
//! - [`IssueType`] - Categories of suspicious patterns (Network, FileAccess, etc.)
//! - [`AnalysisStatus`] - Status of crate version analysis
//! - [`CrawlerStatus`] - Status of the crawler process
//!
//! ## Models (from models module)
//! - [`Crate`] - A crate from crates.io
//! - [`CrateWithStats`] - A crate with additional stats (finding count, max severity)
//! - [`Version`] - A version of a crate
//! - [`AnalysisResult`] - A finding/analysis result
//! - [`CrawlerState`] - Crawler state for checkpointing
//! - [`CrawlerError`] - Crawler error record
//! - [`QueueItem`] - Crawler queue item
//!
//! # Example
//!
//! ```rust,no_run
//! use sus_core::{Database, Severity, IssueType, Crate, Version, AnalysisResult};
//!
//! // All shared types are available at the crate root
//! let severity = Severity::High;
//! let issue_type = IssueType::Network;
//! ```

pub mod db;
pub mod models;
pub mod types;

pub use db::Database;
pub use models::*;
pub use types::*;

#[cfg(test)]
mod tests {
    //! Tests to verify that all expected types are properly exported from sus-core.
    //! These tests serve as both documentation and compile-time verification.

    use super::*;

    /// Verify that all enum types from the types module are exported
    #[test]
    fn test_enum_types_exported() {
        // Severity enum
        let _low = Severity::Low;
        let _medium = Severity::Medium;
        let _high = Severity::High;

        // IssueType enum - all 12 variants
        let _network = IssueType::Network;
        let _file_access = IssueType::FileAccess;
        let _shell_command = IssueType::ShellCommand;
        let _process_spawn = IssueType::ProcessSpawn;
        let _env_access = IssueType::EnvAccess;
        let _dynamic_lib = IssueType::DynamicLib;
        let _unsafe_block = IssueType::UnsafeBlock;
        let _build_download = IssueType::BuildDownload;
        let _sensitive_path = IssueType::SensitivePath;
        let _obfuscation = IssueType::Obfuscation;
        let _compiler_flags = IssueType::CompilerFlags;
        let _macro_codegen = IssueType::MacroCodegen;

        // AnalysisStatus enum
        let _pending = AnalysisStatus::Pending;
        let _in_progress = AnalysisStatus::InProgress;
        let _completed = AnalysisStatus::Completed;
        let _failed = AnalysisStatus::Failed;

        // CrawlerStatus enum
        let _running = CrawlerStatus::Running;
        let _paused = CrawlerStatus::Paused;
        let _crawler_completed = CrawlerStatus::Completed;
        let _crashed = CrawlerStatus::Crashed;
    }

    /// Verify that all model structs are exported and have expected fields
    #[test]
    fn test_model_types_exported() {
        use chrono::Utc;

        // Crate struct - verify fields exist by constructing
        let _crate_model = Crate {
            id: 1,
            name: "test-crate".to_string(),
            repo_url: Some("https://github.com/test/test".to_string()),
            description: Some("A test crate".to_string()),
            download_count: 1000,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // CrateWithStats struct - includes additional stats
        // Note: CrateWithStats uses String for timestamps (for SQLite compatibility)
        let _crate_with_stats = CrateWithStats {
            id: 1,
            name: "test-crate".to_string(),
            repo_url: Some("https://github.com/test/test".to_string()),
            description: Some("A test crate".to_string()),
            download_count: 1000,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
            finding_count: 5,
            max_severity: Some("high".to_string()),
        };

        // Version struct
        let _version = Version {
            id: 1,
            crate_id: 1,
            version_number: "1.0.0".to_string(),
            release_date: Some(Utc::now()),
            last_analyzed: None,
            analysis_status: "pending".to_string(),
            has_build_rs: true,
            is_proc_macro: false,
        };

        // AnalysisResult struct
        let _result = AnalysisResult {
            id: 1,
            version_id: 1,
            issue_type: "network".to_string(),
            severity: "high".to_string(),
            file_path: "build.rs".to_string(),
            line_start: Some(10),
            line_end: Some(15),
            code_snippet: Some("reqwest::get(...)".to_string()),
            context_before: Some("// Build script".to_string()),
            context_after: Some("// End".to_string()),
            summary: Some("Network call detected".to_string()),
            details: None,
            created_at: Utc::now(),
        };

        // CrawlerState struct
        let _state = CrawlerState {
            id: 1,
            run_id: "run-123".to_string(),
            status: "running".to_string(),
            started_at: Utc::now(),
            last_checkpoint: None,
            crates_processed: 100,
            crates_total: 1000,
            current_crate: Some("serde".to_string()),
            queue_position: 101,
            errors_count: 5,
            findings_count: 42,
        };

        // CrawlerError struct
        let _error = CrawlerError {
            id: 1,
            run_id: "run-123".to_string(),
            crate_name: Some("bad-crate".to_string()),
            version: Some("1.0.0".to_string()),
            error_type: Some("download_failed".to_string()),
            error_message: Some("Connection refused".to_string()),
            occurred_at: Utc::now(),
            retry_count: 3,
        };

        // QueueItem struct
        let _queue_item = QueueItem {
            id: 1,
            crate_name: "serde".to_string(),
            version: "1.0.0".to_string(),
            priority: 1,
            status: "pending".to_string(),
            added_at: Utc::now(),
            started_at: None,
            completed_at: None,
        };
    }

    /// Verify that Database type is exported
    #[test]
    fn test_database_type_exported() {
        // Just verify the type exists and can be referenced
        fn _takes_database(_db: &Database) {}
    }

    /// Verify that Severity implements required traits
    #[test]
    fn test_severity_traits() {
        let severity = Severity::High;

        // Display trait
        assert_eq!(severity.to_string(), "high");

        // FromStr trait
        let parsed: Severity = "medium".parse().expect("Failed to parse severity");
        assert_eq!(parsed, Severity::Medium);

        // Debug trait
        let _debug = format!("{:?}", severity);

        // Copy trait (Severity implements Copy, so clone is redundant)
        let _copied = severity;

        // PartialEq trait
        assert_eq!(Severity::Low, Severity::Low);
        assert_ne!(Severity::Low, Severity::High);
    }

    /// Verify that IssueType implements required traits
    #[test]
    fn test_issue_type_traits() {
        let issue = IssueType::Network;

        // Display trait
        assert_eq!(issue.to_string(), "network");

        // FromStr trait
        let parsed: IssueType = "file_access".parse().expect("Failed to parse issue type");
        assert_eq!(parsed, IssueType::FileAccess);

        // Debug trait
        let _debug = format!("{:?}", issue);

        // Copy trait (IssueType implements Copy, so clone is redundant)
        let _copied = issue;

        // PartialEq trait
        assert_eq!(IssueType::Network, IssueType::Network);
    }

    /// Verify that models implement Serialize and Deserialize
    #[test]
    fn test_models_serde() {
        use chrono::Utc;

        let crate_model = Crate {
            id: 1,
            name: "test".to_string(),
            repo_url: None,
            description: None,
            download_count: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Serialize to JSON
        let json = serde_json::to_string(&crate_model).expect("Failed to serialize Crate");
        assert!(json.contains("\"name\":\"test\""));

        // Deserialize back
        let _deserialized: Crate =
            serde_json::from_str(&json).expect("Failed to deserialize Crate");
    }
}
