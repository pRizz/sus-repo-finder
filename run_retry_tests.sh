#!/usr/bin/env bash
set -euo pipefail

echo "Running sus-crawler retry module tests..."
cd /Users/peterryszkiewicz/Repos/sus-repo-finder

# Run only the retry module tests
cargo test --package sus-crawler retry:: 2>&1
