//! Database connection and query functions

use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use std::time::Duration;
use tracing::{info, instrument};

/// The SQL schema for initializing the database
const INIT_SCHEMA: &str = include_str!("../migrations/001_initial_schema.sql");

/// The SQL for reversing/dropping the schema
const REVERSE_SCHEMA: &str = include_str!("../migrations/001_initial_schema_down.sql");

/// Database connection pool wrapper
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Create a new database connection pool
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = SqlitePoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(30))
            .connect(database_url)
            .await?;

        Ok(Self { pool })
    }

    /// Create a new database connection pool and initialize the schema
    ///
    /// This is the recommended way to create a database connection when starting
    /// the application, as it ensures the schema is always up to date.
    #[instrument(skip_all)]
    pub async fn new_with_init(database_url: &str) -> Result<Self, sqlx::Error> {
        let db = Self::new(database_url).await?;
        db.init_schema().await?;
        Ok(db)
    }

    /// Initialize the database schema
    ///
    /// This method runs all schema migrations to ensure the database structure
    /// is up to date. It's safe to call multiple times as the migrations use
    /// `CREATE TABLE IF NOT EXISTS`.
    #[instrument(skip(self))]
    pub async fn init_schema(&self) -> Result<(), sqlx::Error> {
        info!("Initializing database schema");

        // Split schema into individual statements and execute them
        // SQLite doesn't support multiple statements in a single query
        for statement in INIT_SCHEMA.split(';') {
            // Remove SQL comments (lines starting with --)
            let cleaned: String = statement
                .lines()
                .filter(|line| !line.trim().starts_with("--"))
                .collect::<Vec<_>>()
                .join("\n");

            let trimmed = cleaned.trim();
            if !trimmed.is_empty() {
                sqlx::query(trimmed).execute(&self.pool).await?;
            }
        }

        info!("Database schema initialized successfully");
        Ok(())
    }

    /// Reverse/drop the database schema
    ///
    /// This method runs the reverse migration to drop all tables and indexes.
    /// Use this for rolling back migrations or resetting the database.
    /// **Warning:** This will delete all data in the database.
    #[instrument(skip(self))]
    pub async fn reverse_schema(&self) -> Result<(), sqlx::Error> {
        info!("Reversing database schema (dropping all tables)");

        // Split schema into individual statements and execute them
        for statement in REVERSE_SCHEMA.split(';') {
            // Remove SQL comments (lines starting with --)
            let cleaned: String = statement
                .lines()
                .filter(|line| !line.trim().starts_with("--"))
                .collect::<Vec<_>>()
                .join("\n");

            let trimmed = cleaned.trim();
            if !trimmed.is_empty() {
                sqlx::query(trimmed).execute(&self.pool).await?;
            }
        }

        info!("Database schema reversed successfully");
        Ok(())
    }

    /// Check if the database has been initialized with the schema
    ///
    /// Returns true if the core tables exist.
    pub async fn is_initialized(&self) -> Result<bool, sqlx::Error> {
        let result: Option<(i32,)> =
            sqlx::query_as("SELECT 1 FROM sqlite_master WHERE type='table' AND name='crates'")
                .fetch_optional(&self.pool)
                .await?;

        Ok(result.is_some())
    }

    /// Get a reference to the underlying pool
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Get all crates with basic info
    pub async fn get_crates(&self) -> Result<Vec<crate::models::CrateWithStats>, sqlx::Error> {
        let crates = sqlx::query_as::<_, crate::models::CrateWithStats>(
            r#"
            SELECT
                c.id,
                c.name,
                c.repo_url,
                c.description,
                c.download_count,
                c.created_at,
                c.updated_at,
                (SELECT COUNT(*) FROM analysis_results ar
                 JOIN versions v ON ar.version_id = v.id
                 WHERE v.crate_id = c.id) as finding_count,
                (SELECT MAX(ar.severity) FROM analysis_results ar
                 JOIN versions v ON ar.version_id = v.id
                 WHERE v.crate_id = c.id) as max_severity
            FROM crates c
            ORDER BY c.updated_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(crates)
    }

    /// Get the count of all crates
    pub async fn get_crate_count(&self) -> Result<i64, sqlx::Error> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM crates")
            .fetch_one(&self.pool)
            .await?;
        Ok(count.0)
    }

    /// Get crates with pagination support
    ///
    /// Returns crates ordered by updated_at DESC, with LIMIT and OFFSET for pagination.
    ///
    /// # Arguments
    /// * `page` - The page number (1-indexed)
    /// * `per_page` - Number of items per page
    pub async fn get_crates_paginated(
        &self,
        page: u32,
        per_page: u32,
    ) -> Result<Vec<crate::models::CrateWithStats>, sqlx::Error> {
        let offset = (page.saturating_sub(1)) * per_page;
        let crates = sqlx::query_as::<_, crate::models::CrateWithStats>(
            r#"
            SELECT
                c.id,
                c.name,
                c.repo_url,
                c.description,
                c.download_count,
                c.created_at,
                c.updated_at,
                (SELECT COUNT(*) FROM analysis_results ar
                 JOIN versions v ON ar.version_id = v.id
                 WHERE v.crate_id = c.id) as finding_count,
                (SELECT MAX(ar.severity) FROM analysis_results ar
                 JOIN versions v ON ar.version_id = v.id
                 WHERE v.crate_id = c.id) as max_severity
            FROM crates c
            ORDER BY c.updated_at DESC
            LIMIT ? OFFSET ?
            "#,
        )
        .bind(per_page as i32)
        .bind(offset as i32)
        .fetch_all(&self.pool)
        .await?;

        Ok(crates)
    }

    /// Get dashboard statistics
    pub async fn get_dashboard_stats(&self) -> Result<crate::models::DashboardStats, sqlx::Error> {
        let total_crates: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM crates")
            .fetch_one(&self.pool)
            .await?;

        let total_findings: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM analysis_results")
            .fetch_one(&self.pool)
            .await?;

        let high_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM analysis_results WHERE severity = 'high'")
                .fetch_one(&self.pool)
                .await?;

        let medium_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM analysis_results WHERE severity = 'medium'")
                .fetch_one(&self.pool)
                .await?;

        let low_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM analysis_results WHERE severity = 'low'")
                .fetch_one(&self.pool)
                .await?;

        Ok(crate::models::DashboardStats {
            total_crates: total_crates.0,
            total_findings: total_findings.0,
            high_severity: high_count.0,
            medium_severity: medium_count.0,
            low_severity: low_count.0,
        })
    }

    /// Get recent findings for the dashboard
    pub async fn get_recent_findings(
        &self,
        limit: i32,
    ) -> Result<Vec<crate::models::RecentFinding>, sqlx::Error> {
        let findings = sqlx::query_as::<_, crate::models::RecentFinding>(
            r#"
            SELECT
                ar.id,
                c.name as crate_name,
                v.version_number as version,
                ar.issue_type,
                ar.severity,
                ar.summary,
                ar.created_at
            FROM analysis_results ar
            JOIN versions v ON ar.version_id = v.id
            JOIN crates c ON v.crate_id = c.id
            ORDER BY ar.created_at DESC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(findings)
    }

    /// Insert or update a crate in the database
    ///
    /// If the crate already exists (by name), updates its metadata.
    /// Returns the crate ID.
    #[instrument(skip(self))]
    pub async fn upsert_crate(
        &self,
        name: &str,
        repo_url: Option<&str>,
        description: Option<&str>,
        download_count: i64,
    ) -> Result<i64, sqlx::Error> {
        // Use INSERT OR REPLACE to handle upserts
        // First check if the crate exists
        let existing: Option<(i64,)> = sqlx::query_as("SELECT id FROM crates WHERE name = ?")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;

        let crate_id = if let Some((id,)) = existing {
            // Update existing crate
            sqlx::query(
                r#"
                UPDATE crates
                SET repo_url = ?,
                    description = ?,
                    download_count = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                "#,
            )
            .bind(repo_url)
            .bind(description)
            .bind(download_count)
            .bind(id)
            .execute(&self.pool)
            .await?;

            info!("Updated crate '{}' (id: {})", name, id);
            id
        } else {
            // Insert new crate
            let result = sqlx::query(
                r#"
                INSERT INTO crates (name, repo_url, description, download_count)
                VALUES (?, ?, ?, ?)
                "#,
            )
            .bind(name)
            .bind(repo_url)
            .bind(description)
            .bind(download_count)
            .execute(&self.pool)
            .await?;

            let id = result.last_insert_rowid();
            info!("Inserted new crate '{}' (id: {})", name, id);
            id
        };

        Ok(crate_id)
    }

    /// Insert or update a version for a crate
    ///
    /// If the version already exists, updates its metadata.
    /// Returns the version ID.
    #[instrument(skip(self))]
    pub async fn upsert_version(
        &self,
        crate_id: i64,
        version_number: &str,
        has_build_rs: bool,
        is_proc_macro: bool,
    ) -> Result<i64, sqlx::Error> {
        // Check if the version exists
        let existing: Option<(i64,)> =
            sqlx::query_as("SELECT id FROM versions WHERE crate_id = ? AND version_number = ?")
                .bind(crate_id)
                .bind(version_number)
                .fetch_optional(&self.pool)
                .await?;

        let version_id = if let Some((id,)) = existing {
            // Update existing version
            sqlx::query(
                r#"
                UPDATE versions
                SET has_build_rs = ?,
                    is_proc_macro = ?
                WHERE id = ?
                "#,
            )
            .bind(has_build_rs)
            .bind(is_proc_macro)
            .bind(id)
            .execute(&self.pool)
            .await?;

            info!(
                "Updated version '{}' for crate_id {} (id: {})",
                version_number, crate_id, id
            );
            id
        } else {
            // Insert new version
            let result = sqlx::query(
                r#"
                INSERT INTO versions (crate_id, version_number, has_build_rs, is_proc_macro)
                VALUES (?, ?, ?, ?)
                "#,
            )
            .bind(crate_id)
            .bind(version_number)
            .bind(has_build_rs)
            .bind(is_proc_macro)
            .execute(&self.pool)
            .await?;

            let id = result.last_insert_rowid();
            info!(
                "Inserted new version '{}' for crate_id {} (id: {})",
                version_number, crate_id, id
            );
            id
        };

        Ok(version_id)
    }

    /// Get a crate by name
    pub async fn get_crate_by_name(
        &self,
        name: &str,
    ) -> Result<Option<crate::models::CrateWithStats>, sqlx::Error> {
        let crate_info = sqlx::query_as::<_, crate::models::CrateWithStats>(
            r#"
            SELECT
                c.id,
                c.name,
                c.repo_url,
                c.description,
                c.download_count,
                c.created_at,
                c.updated_at,
                (SELECT COUNT(*) FROM analysis_results ar
                 JOIN versions v ON ar.version_id = v.id
                 WHERE v.crate_id = c.id) as finding_count,
                (SELECT MAX(ar.severity) FROM analysis_results ar
                 JOIN versions v ON ar.version_id = v.id
                 WHERE v.crate_id = c.id) as max_severity
            FROM crates c
            WHERE c.name = ?
            "#,
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        Ok(crate_info)
    }

    /// Get the version ID for a crate by name and version number
    ///
    /// Returns None if the crate or version doesn't exist
    pub async fn get_version_id(
        &self,
        crate_name: &str,
        version_number: &str,
    ) -> Result<Option<i64>, sqlx::Error> {
        let result: Option<(i64,)> = sqlx::query_as(
            r#"
            SELECT v.id
            FROM versions v
            JOIN crates c ON v.crate_id = c.id
            WHERE c.name = ? AND v.version_number = ?
            "#,
        )
        .bind(crate_name)
        .bind(version_number)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(|(id,)| id))
    }

    /// Insert an analysis result (finding) into the database
    ///
    /// Returns the ID of the inserted record.
    #[instrument(skip(self, input))]
    pub async fn insert_analysis_result(
        &self,
        input: &crate::models::NewAnalysisResult<'_>,
    ) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO analysis_results (
                version_id, issue_type, severity, file_path,
                line_start, line_end, code_snippet,
                context_before, context_after, summary, details
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(input.version_id)
        .bind(input.issue_type)
        .bind(input.severity)
        .bind(input.file_path)
        .bind(input.line_start)
        .bind(input.line_end)
        .bind(input.code_snippet)
        .bind(input.context_before)
        .bind(input.context_after)
        .bind(input.summary)
        .bind(input.details)
        .execute(&self.pool)
        .await?;

        let id = result.last_insert_rowid();
        info!(
            "Inserted analysis result id={} for version_id={} (type: {}, severity: {})",
            id, input.version_id, input.issue_type, input.severity
        );
        Ok(id)
    }

    /// Get all analysis results (findings) for a specific version
    pub async fn get_findings_by_version(
        &self,
        version_id: i64,
    ) -> Result<Vec<crate::models::AnalysisResultRow>, sqlx::Error> {
        let findings = sqlx::query_as::<_, crate::models::AnalysisResultRow>(
            r#"
            SELECT
                id, version_id, issue_type, severity, file_path,
                line_start, line_end, code_snippet,
                context_before, context_after, summary, details, created_at
            FROM analysis_results
            WHERE version_id = ?
            ORDER BY created_at DESC
            "#,
        )
        .bind(version_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(findings)
    }

    /// Get total findings count
    pub async fn get_findings_count(&self) -> Result<i64, sqlx::Error> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM analysis_results")
            .fetch_one(&self.pool)
            .await?;
        Ok(count.0)
    }

    /// Get all versions for a crate with finding counts
    pub async fn get_versions_for_crate(
        &self,
        crate_id: i64,
    ) -> Result<Vec<crate::models::VersionWithStats>, sqlx::Error> {
        let versions = sqlx::query_as::<_, crate::models::VersionWithStats>(
            r#"
            SELECT
                v.id,
                v.crate_id,
                v.version_number,
                v.has_build_rs,
                v.is_proc_macro,
                v.last_analyzed,
                (SELECT COUNT(*) FROM analysis_results ar WHERE ar.version_id = v.id) as finding_count
            FROM versions v
            WHERE v.crate_id = ?
            ORDER BY v.id DESC
            "#,
        )
        .bind(crate_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(versions)
    }

    /// Get findings for a version with comparison to previous version
    ///
    /// Returns findings for the selected version, plus any findings that existed
    /// in older versions but were removed/fixed in this version.
    /// Each finding is tagged with its status: Current, New, or Removed.
    pub async fn get_findings_with_comparison(
        &self,
        crate_id: i64,
        current_version_id: i64,
    ) -> Result<Vec<crate::models::FindingWithStatus>, sqlx::Error> {
        use crate::models::{FindingStatus, FindingWithStatus};

        // Get all versions for this crate, ordered by id DESC (newest first)
        let versions = self.get_versions_for_crate(crate_id).await?;

        // Find the position of the current version
        let current_pos = versions.iter().position(|v| v.id == current_version_id);

        // Get current version's findings
        let current_findings = self.get_findings_by_version(current_version_id).await?;

        // If there's no previous version, all current findings are just "Current"
        let Some(current_idx) = current_pos else {
            return Ok(current_findings
                .into_iter()
                .map(|f| FindingWithStatus {
                    id: f.id,
                    version_id: f.version_id,
                    issue_type: f.issue_type,
                    severity: f.severity,
                    file_path: f.file_path,
                    line_start: f.line_start,
                    line_end: f.line_end,
                    code_snippet: f.code_snippet,
                    context_before: f.context_before,
                    context_after: f.context_after,
                    summary: f.summary,
                    details: f.details,
                    created_at: f.created_at,
                    status: FindingStatus::Current,
                    from_version: None,
                })
                .collect());
        };

        // Get the previous version (older = higher index)
        let previous_version = if current_idx + 1 < versions.len() {
            Some(&versions[current_idx + 1])
        } else {
            None
        };

        let mut result = Vec::new();

        // Get previous version's findings if exists
        let previous_findings = if let Some(prev_ver) = previous_version {
            self.get_findings_by_version(prev_ver.id).await?
        } else {
            Vec::new()
        };

        // Create a key function to identify similar findings (issue_type + file_path + code_snippet)
        let make_key =
            |issue_type: &str, file_path: &str, code_snippet: &Option<String>| -> String {
                format!(
                    "{}:{}:{}",
                    issue_type,
                    file_path,
                    code_snippet.as_deref().unwrap_or("")
                )
            };

        // Create a set of previous finding keys
        let previous_keys: std::collections::HashSet<String> = previous_findings
            .iter()
            .map(|f| make_key(&f.issue_type, &f.file_path, &f.code_snippet))
            .collect();

        // Create a set of current finding keys
        let current_keys: std::collections::HashSet<String> = current_findings
            .iter()
            .map(|f| make_key(&f.issue_type, &f.file_path, &f.code_snippet))
            .collect();

        // Add current findings with status
        for f in current_findings {
            let key = make_key(&f.issue_type, &f.file_path, &f.code_snippet);
            let status = if previous_keys.contains(&key) {
                FindingStatus::Current
            } else {
                FindingStatus::New
            };

            result.push(FindingWithStatus {
                id: f.id,
                version_id: f.version_id,
                issue_type: f.issue_type,
                severity: f.severity,
                file_path: f.file_path,
                line_start: f.line_start,
                line_end: f.line_end,
                code_snippet: f.code_snippet,
                context_before: f.context_before,
                context_after: f.context_after,
                summary: f.summary,
                details: f.details,
                created_at: f.created_at,
                status,
                from_version: None,
            });
        }

        // Add removed findings (existed in previous but not in current)
        if let Some(prev_ver) = previous_version {
            for f in previous_findings {
                let key = make_key(&f.issue_type, &f.file_path, &f.code_snippet);
                if !current_keys.contains(&key) {
                    result.push(FindingWithStatus {
                        id: f.id,
                        version_id: f.version_id,
                        issue_type: f.issue_type,
                        severity: f.severity,
                        file_path: f.file_path,
                        line_start: f.line_start,
                        line_end: f.line_end,
                        code_snippet: f.code_snippet,
                        context_before: f.context_before,
                        context_after: f.context_after,
                        summary: f.summary,
                        details: f.details,
                        created_at: f.created_at,
                        status: FindingStatus::Removed,
                        from_version: Some(prev_ver.version_number.clone()),
                    });
                }
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that the database schema initializes correctly
    #[tokio::test]
    async fn test_database_init_schema() {
        // Create an in-memory database for testing
        let db = Database::new("sqlite::memory:")
            .await
            .expect("Failed to create database");

        // Initially the database should not be initialized
        let initialized_before = db
            .is_initialized()
            .await
            .expect("Failed to check initialization");
        assert!(
            !initialized_before,
            "Database should not be initialized before init_schema"
        );

        // Initialize the schema
        db.init_schema().await.expect("Failed to initialize schema");

        // Now the database should be initialized
        let initialized_after = db
            .is_initialized()
            .await
            .expect("Failed to check initialization");
        assert!(
            initialized_after,
            "Database should be initialized after init_schema"
        );
    }

    /// Test that init_schema is idempotent (can be called multiple times)
    #[tokio::test]
    async fn test_database_init_schema_idempotent() {
        let db = Database::new("sqlite::memory:")
            .await
            .expect("Failed to create database");

        // Initialize twice - should not fail
        db.init_schema().await.expect("First init failed");
        db.init_schema().await.expect("Second init failed");

        let initialized = db
            .is_initialized()
            .await
            .expect("Failed to check initialization");
        assert!(initialized, "Database should be initialized");
    }

    /// Test that new_with_init creates and initializes the database
    #[tokio::test]
    async fn test_database_new_with_init() {
        let db = Database::new_with_init("sqlite::memory:")
            .await
            .expect("Failed to create and initialize database");

        let initialized = db
            .is_initialized()
            .await
            .expect("Failed to check initialization");
        assert!(initialized, "Database should be initialized");
    }

    /// Test that all expected tables are created
    #[tokio::test]
    async fn test_database_all_tables_created() {
        let db = Database::new_with_init("sqlite::memory:")
            .await
            .expect("Failed to create and initialize database");

        let expected_tables = [
            "crates",
            "versions",
            "analysis_results",
            "crawler_state",
            "crawler_errors",
            "crawler_queue",
        ];

        for table_name in expected_tables {
            let result: Option<(i32,)> =
                sqlx::query_as("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?")
                    .bind(table_name)
                    .fetch_optional(db.pool())
                    .await
                    .expect("Failed to query table existence");

            assert!(result.is_some(), "Table '{}' should exist", table_name);
        }
    }

    /// Test that migrations can be reversed (rolled back)
    #[tokio::test]
    async fn test_database_reverse_schema() {
        let db = Database::new_with_init("sqlite::memory:")
            .await
            .expect("Failed to create and initialize database");

        // Verify tables exist first
        let initialized = db
            .is_initialized()
            .await
            .expect("Failed to check initialization");
        assert!(
            initialized,
            "Database should be initialized before reversal"
        );

        // Reverse the schema
        db.reverse_schema().await.expect("Failed to reverse schema");

        // Verify tables no longer exist
        let initialized_after = db
            .is_initialized()
            .await
            .expect("Failed to check initialization after reversal");
        assert!(
            !initialized_after,
            "Database should not be initialized after reversal"
        );

        // Verify all tables are gone
        let tables = [
            "crates",
            "versions",
            "analysis_results",
            "crawler_state",
            "crawler_errors",
            "crawler_queue",
        ];

        for table_name in tables {
            let result: Option<(i32,)> =
                sqlx::query_as("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?")
                    .bind(table_name)
                    .fetch_optional(db.pool())
                    .await
                    .expect("Failed to query table existence");

            assert!(
                result.is_none(),
                "Table '{}' should not exist after reversal",
                table_name
            );
        }
    }

    /// Test that migrations can be applied, reversed, and reapplied (full cycle)
    #[tokio::test]
    async fn test_database_migration_full_cycle() {
        let db = Database::new("sqlite::memory:")
            .await
            .expect("Failed to create database");

        // Initially not initialized
        assert!(
            !db.is_initialized().await.expect("Failed to check"),
            "Should not be initialized initially"
        );

        // Apply migration (up)
        db.init_schema().await.expect("Failed to init schema");
        assert!(
            db.is_initialized().await.expect("Failed to check"),
            "Should be initialized after init"
        );

        // Reverse migration (down)
        db.reverse_schema().await.expect("Failed to reverse schema");
        assert!(
            !db.is_initialized().await.expect("Failed to check"),
            "Should not be initialized after reversal"
        );

        // Reapply migration (up again)
        db.init_schema().await.expect("Failed to reinit schema");
        assert!(
            db.is_initialized().await.expect("Failed to check"),
            "Should be initialized after reinit"
        );
    }

    /// Test that reverse migration drops indexes as well
    #[tokio::test]
    async fn test_database_reverse_drops_indexes() {
        let db = Database::new_with_init("sqlite::memory:")
            .await
            .expect("Failed to create and initialize database");

        // Verify some indexes exist before reversal
        let index_result: Option<(i32,)> = sqlx::query_as(
            "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_crates_name'",
        )
        .fetch_optional(db.pool())
        .await
        .expect("Failed to query index existence");
        assert!(
            index_result.is_some(),
            "Index 'idx_crates_name' should exist before reversal"
        );

        // Reverse the schema
        db.reverse_schema().await.expect("Failed to reverse schema");

        // Verify indexes are gone
        let expected_indexes = [
            "idx_crates_name",
            "idx_crates_downloads",
            "idx_versions_crate_id",
            "idx_versions_status",
            "idx_results_version_id",
            "idx_results_severity",
            "idx_results_issue_type",
            "idx_results_created_at",
            "idx_crawler_state_started",
            "idx_crawler_errors_run_id",
            "idx_crawler_errors_occurred",
            "idx_queue_status",
            "idx_queue_priority",
        ];

        for index_name in expected_indexes {
            let result: Option<(i32,)> =
                sqlx::query_as("SELECT 1 FROM sqlite_master WHERE type='index' AND name=?")
                    .bind(index_name)
                    .fetch_optional(db.pool())
                    .await
                    .expect("Failed to query index existence");

            assert!(
                result.is_none(),
                "Index '{}' should not exist after reversal",
                index_name
            );
        }
    }
}
