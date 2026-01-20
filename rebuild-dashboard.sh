#!/bin/bash
# Rebuild and restart the dashboard on a new port
set -euo pipefail

echo "Building sus-dashboard..."
cargo build --package sus-dashboard

# Find an available port starting from 3009
PORT=3009
while lsof -i :$PORT > /dev/null 2>&1; do
    PORT=$((PORT + 1))
done

echo "Starting dashboard on port $PORT..."
DATABASE_URL=sqlite:./data/sus-repo-finder.db DASHBOARD_PORT=$PORT ./target/debug/sus-dashboard &
echo "Dashboard running at http://localhost:$PORT"
