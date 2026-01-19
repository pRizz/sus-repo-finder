#!/usr/bin/env bash
set -euo pipefail

export DATABASE_URL="sqlite:./data/sus-repo-finder.db"
export DASHBOARD_PORT="${DASHBOARD_PORT:-3002}"

echo "Starting Sus Dashboard on port $DASHBOARD_PORT..."
exec ./target/debug/sus-dashboard
