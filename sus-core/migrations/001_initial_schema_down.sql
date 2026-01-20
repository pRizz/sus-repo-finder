-- Reverse migration for 001_initial_schema.sql
-- Drops all tables and indexes in reverse order of creation
-- (child tables before parent tables to respect foreign key constraints)

-- Drop indexes first (optional but cleaner)
DROP INDEX IF EXISTS idx_queue_priority;
DROP INDEX IF EXISTS idx_queue_status;
DROP INDEX IF EXISTS idx_crawler_errors_occurred;
DROP INDEX IF EXISTS idx_crawler_errors_run_id;
DROP INDEX IF EXISTS idx_crawler_state_started;
DROP INDEX IF EXISTS idx_results_created_at;
DROP INDEX IF EXISTS idx_results_issue_type;
DROP INDEX IF EXISTS idx_results_severity;
DROP INDEX IF EXISTS idx_results_version_id;
DROP INDEX IF EXISTS idx_versions_status;
DROP INDEX IF EXISTS idx_versions_crate_id;
DROP INDEX IF EXISTS idx_crates_downloads;
DROP INDEX IF EXISTS idx_crates_name;

-- Drop tables in reverse order (child tables first to respect foreign keys)
DROP TABLE IF EXISTS crawler_queue;
DROP TABLE IF EXISTS crawler_errors;
DROP TABLE IF EXISTS crawler_state;
DROP TABLE IF EXISTS analysis_results;
DROP TABLE IF EXISTS versions;
DROP TABLE IF EXISTS crates;
