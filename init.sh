#!/usr/bin/env bash
set -euo pipefail

# Sus Repo Finder - Development Environment Setup
# This script sets up the development environment for the Sus Repo Finder project

echo "🦀 Setting up Sus Repo Finder development environment..."

# Check for required tools
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo "❌ Error: $1 is required but not installed."
        echo "   Please install $1 and try again."
        exit 1
    fi
}

echo "Checking required tools..."
check_command rustc
check_command cargo
check_command sqlite3
check_command node
check_command npm

echo "✅ All required tools found"

# Display versions
echo ""
echo "Tool versions:"
echo "  Rust: $(rustc --version)"
echo "  Cargo: $(cargo --version)"
echo "  SQLite: $(sqlite3 --version)"
echo "  Node: $(node --version)"
echo "  npm: $(npm --version)"

# Set up the database directory
DB_DIR="./data"
DB_PATH="$DB_DIR/sus-repo-finder.db"

echo ""
echo "Setting up database..."
mkdir -p "$DB_DIR"

if [ ! -f "$DB_PATH" ]; then
    echo "Creating new database at $DB_PATH..."
    sqlite3 "$DB_PATH" <<'EOF'
-- Crates table
CREATE TABLE IF NOT EXISTS crates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    repo_url TEXT,
    description TEXT,
    download_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Versions table
CREATE TABLE IF NOT EXISTS versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    crate_id INTEGER NOT NULL,
    version_number TEXT NOT NULL,
    release_date TIMESTAMP,
    last_analyzed TIMESTAMP,
    analysis_status TEXT DEFAULT 'pending',
    has_build_rs BOOLEAN DEFAULT FALSE,
    is_proc_macro BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (crate_id) REFERENCES crates(id) ON DELETE CASCADE,
    UNIQUE(crate_id, version_number)
);

-- Analysis results table
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (version_id) REFERENCES versions(id) ON DELETE CASCADE
);

-- Crawler state table
CREATE TABLE IF NOT EXISTS crawler_state (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT UNIQUE NOT NULL,
    status TEXT DEFAULT 'running',
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_checkpoint TIMESTAMP,
    crates_processed INTEGER DEFAULT 0,
    crates_total INTEGER DEFAULT 0,
    current_crate TEXT,
    queue_position INTEGER DEFAULT 0,
    errors_count INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0
);

-- Crawler errors table
CREATE TABLE IF NOT EXISTS crawler_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    crate_name TEXT,
    version TEXT,
    error_type TEXT,
    error_message TEXT,
    occurred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    retry_count INTEGER DEFAULT 0,
    FOREIGN KEY (run_id) REFERENCES crawler_state(run_id) ON DELETE CASCADE
);

-- Crawler queue table
CREATE TABLE IF NOT EXISTS crawler_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    crate_name TEXT NOT NULL,
    version TEXT NOT NULL,
    priority INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending',
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_versions_crate_id ON versions(crate_id);
CREATE INDEX IF NOT EXISTS idx_analysis_version_id ON analysis_results(version_id);
CREATE INDEX IF NOT EXISTS idx_analysis_severity ON analysis_results(severity);
CREATE INDEX IF NOT EXISTS idx_analysis_issue_type ON analysis_results(issue_type);
CREATE INDEX IF NOT EXISTS idx_crates_name ON crates(name);
CREATE INDEX IF NOT EXISTS idx_crates_download_count ON crates(download_count);
CREATE INDEX IF NOT EXISTS idx_crawler_queue_status ON crawler_queue(status);
CREATE INDEX IF NOT EXISTS idx_crawler_errors_run_id ON crawler_errors(run_id);
EOF
    echo "✅ Database created successfully"
else
    echo "✅ Database already exists at $DB_PATH"
fi

# Install Tailwind CSS if package.json exists
if [ -f "package.json" ]; then
    echo ""
    echo "Installing Node.js dependencies..."
    npm install
    echo "✅ Node.js dependencies installed"
fi

# Build the Rust project
echo ""
echo "Building Rust project..."
cargo build --all-targets

echo ""
echo "✅ Build completed successfully"

# Print helpful information
echo ""
echo "=========================================="
echo "🎉 Setup complete!"
echo "=========================================="
echo ""
echo "Project structure:"
echo "  sus-crawler/  - Crawler application with embedded web portal"
echo "  sus-dashboard/ - Read-only findings dashboard"
echo "  sus-core/     - Shared database models and types"
echo "  sus-detector/ - Pattern detection logic"
echo ""
echo "To run the crawler:"
echo "  cargo run -p sus-crawler"
echo "  Then open http://localhost:3001 for the crawler portal"
echo ""
echo "To run the dashboard:"
echo "  cargo run -p sus-dashboard"
echo "  Then open http://localhost:3000 for the dashboard"
echo ""
echo "Environment variables:"
echo "  DATABASE_URL=sqlite:./data/sus-repo-finder.db"
echo "  CRAWLER_PORT=3001 (default)"
echo "  DASHBOARD_PORT=3000 (default)"
echo ""
