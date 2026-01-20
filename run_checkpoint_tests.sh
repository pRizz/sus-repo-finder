#!/usr/bin/env bash
set -euo pipefail
~/.cargo/bin/cargo test --package sus-core --lib -- crawler 2>&1
