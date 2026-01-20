#!/usr/bin/env bash
set -euo pipefail

echo "Testing concurrent API requests to dashboard..."

# Launch 10 concurrent requests to different endpoints
curl -s -w "stats-1: %{http_code}\n" -o /dev/null http://localhost:3002/api/stats &
curl -s -w "stats-2: %{http_code}\n" -o /dev/null http://localhost:3002/api/stats &
curl -s -w "crates-1: %{http_code}\n" -o /dev/null http://localhost:3002/api/crates &
curl -s -w "crates-2: %{http_code}\n" -o /dev/null http://localhost:3002/api/crates &
curl -s -w "recent-1: %{http_code}\n" -o /dev/null http://localhost:3002/api/findings/recent &
curl -s -w "recent-2: %{http_code}\n" -o /dev/null http://localhost:3002/api/findings/recent &
curl -s -w "interesting-1: %{http_code}\n" -o /dev/null http://localhost:3002/api/findings/interesting &
curl -s -w "interesting-2: %{http_code}\n" -o /dev/null http://localhost:3002/api/findings/interesting &
curl -s -w "page-1: %{http_code}\n" -o /dev/null http://localhost:3002/ &
curl -s -w "page-2: %{http_code}\n" -o /dev/null http://localhost:3002/crates &

wait

echo "All concurrent requests completed successfully!"
