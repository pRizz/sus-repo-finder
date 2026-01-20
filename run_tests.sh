#!/usr/bin/env bash
set -euo pipefail

echo "Running cargo test --all-features..."
cargo test --all-features
echo "Tests passed!"
