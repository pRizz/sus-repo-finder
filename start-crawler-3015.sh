#!/usr/bin/env bash
set -euo pipefail

export DATABASE_URL="sqlite:./data/sus-repo-finder.db"
export CRAWLER_PORT="3015"

echo "Starting Sus Crawler on port $CRAWLER_PORT..."
exec ./target/debug/sus-crawler
