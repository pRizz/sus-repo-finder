-- Initial database schema for Sus Repo Finder
-- Creates all tables needed for the crawler and dashboard

-- Crates table: stores metadata about crates from crates.io
CREATE TABLE IF NOT EXISTS crates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    repo_url TEXT,
    description TEXT,
    download_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Index for crate name lookups
CREATE INDEX IF NOT EXISTS idx_crates_name ON crates(name);
-- Index for sorting by downloads
CREATE INDEX IF NOT EXISTS idx_crates_downloads ON crates(download_count DESC);

-- Versions table: stores version information for each crate
CREATE TABLE IF NOT EXISTS versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    crate_id INTEGER NOT NULL,
    version_number TEXT NOT NULL,
    release_date TIMESTAMP,
    last_analyzed TIMESTAMP,
    analysis_status TEXT NOT NULL DEFAULT 'pending',
    has_build_rs INTEGER NOT NULL DEFAULT 0,
    is_proc_macro INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (crate_id) REFERENCES crates(id) ON DELETE CASCADE,
    UNIQUE(crate_id, version_number)
);

-- Index for version lookups
CREATE INDEX IF NOT EXISTS idx_versions_crate_id ON versions(crate_id);
-- Index for finding unanalyzed versions
CREATE INDEX IF NOT EXISTS idx_versions_status ON versions(analysis_status);

-- Analysis results table: stores findings from analyzing crate code
CREATE TABLE IF NOT EXISTS analysis_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER NOT NULL,
    issue_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_start INTEGER,
    line_end INTEGER,
    code_snippet TEXT,
    context_before TEXT,
    context_after TEXT,
    summary TEXT,
    details TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (version_id) REFERENCES versions(id) ON DELETE CASCADE
);

-- Index for finding results by version
CREATE INDEX IF NOT EXISTS idx_results_version_id ON analysis_results(version_id);
-- Index for filtering by severity
CREATE INDEX IF NOT EXISTS idx_results_severity ON analysis_results(severity);
-- Index for filtering by issue type
CREATE INDEX IF NOT EXISTS idx_results_issue_type ON analysis_results(issue_type);
-- Index for recent findings
CREATE INDEX IF NOT EXISTS idx_results_created_at ON analysis_results(created_at DESC);

-- Crawler state table: tracks crawler run status and checkpoints
CREATE TABLE IF NOT EXISTS crawler_state (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',
    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_checkpoint TIMESTAMP,
    crates_processed INTEGER NOT NULL DEFAULT 0,
    crates_total INTEGER NOT NULL DEFAULT 0,
    current_crate TEXT,
    queue_position INTEGER NOT NULL DEFAULT 0,
    errors_count INTEGER NOT NULL DEFAULT 0,
    findings_count INTEGER NOT NULL DEFAULT 0
);

-- Index for finding the latest run
CREATE INDEX IF NOT EXISTS idx_crawler_state_started ON crawler_state(started_at DESC);

-- Crawler errors table: tracks errors encountered during crawling
CREATE TABLE IF NOT EXISTS crawler_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    crate_name TEXT,
    version TEXT,
    error_type TEXT,
    error_message TEXT,
    occurred_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retry_count INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (run_id) REFERENCES crawler_state(run_id) ON DELETE CASCADE
);

-- Index for finding errors by run
CREATE INDEX IF NOT EXISTS idx_crawler_errors_run_id ON crawler_errors(run_id);
-- Index for recent errors
CREATE INDEX IF NOT EXISTS idx_crawler_errors_occurred ON crawler_errors(occurred_at DESC);

-- Crawler queue table: manages the queue of crates to process
CREATE TABLE IF NOT EXISTS crawler_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    crate_name TEXT NOT NULL,
    version TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    added_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    UNIQUE(crate_name, version)
);

-- Index for finding pending items
CREATE INDEX IF NOT EXISTS idx_queue_status ON crawler_queue(status);
-- Index for priority ordering
CREATE INDEX IF NOT EXISTS idx_queue_priority ON crawler_queue(priority DESC, added_at ASC);
