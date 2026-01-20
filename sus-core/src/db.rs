//! Database connection and query functions

use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use std::time::Duration;
use tracing::{info, instrument};

/// The SQL schema for initializing the database
const INIT_SCHEMA: &str = include_str!("../migrations/001_initial_schema.sql");

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
        let existing: Option<(i64,)> =
            sqlx::query_as("SELECT id FROM crates WHERE name = ?")
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
        let existing: Option<(i64,)> = sqlx::query_as(
            "SELECT id FROM versions WHERE crate_id = ? AND version_number = ?",
        )
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
    #[instrument(skip(self))]
    pub async fn insert_analysis_result(
        &self,
        version_id: i64,
        issue_type: &str,
        severity: &str,
        file_path: &str,
        line_start: Option<i32>,
        line_end: Option<i32>,
        code_snippet: Option<&str>,
        context_before: Option<&str>,
        context_after: Option<&str>,
        summary: Option<&str>,
        details: Option<&str>,
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
        .bind(version_id)
        .bind(issue_type)
        .bind(severity)
        .bind(file_path)
        .bind(line_start)
        .bind(line_end)
        .bind(code_snippet)
        .bind(context_before)
        .bind(context_after)
        .bind(summary)
        .bind(details)
        .execute(&self.pool)
        .await?;

        let id = result.last_insert_rowid();
        info!(
            "Inserted analysis result id={} for version_id={} (type: {}, severity: {})",
            id, version_id, issue_type, severity
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
}
