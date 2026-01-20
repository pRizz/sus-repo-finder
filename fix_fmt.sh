#!/usr/bin/env bash
set -euo pipefail

echo "Running cargo fmt --all to fix formatting..."
cargo fmt --all
echo "✅ Formatting complete!"

echo ""
echo "Verifying formatting is correct..."
cargo fmt --all -- --check
echo "✅ Formatting check passed!"
