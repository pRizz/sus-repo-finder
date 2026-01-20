#!/usr/bin/env bash
set -euo pipefail

# Run tests for sus-detector crate
cd /Users/peterryszkiewicz/Repos/sus-repo-finder
cargo test --package sus-detector 2>&1
