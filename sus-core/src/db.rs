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
