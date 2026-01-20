#!/usr/bin/env bash
set -euo pipefail

echo "Running all sus-crawler tests..."
cd /Users/peterryszkiewicz/Repos/sus-repo-finder

cargo test --package sus-crawler 2>&1
