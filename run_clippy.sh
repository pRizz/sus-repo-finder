#!/usr/bin/env bash
set -euo pipefail

echo "Running cargo clippy --all-targets --all-features -- -D warnings..."
cargo clippy --all-targets --all-features -- -D warnings
echo "Clippy passed!"
