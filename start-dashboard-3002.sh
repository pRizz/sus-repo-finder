#!/usr/bin/env bash
cd /Users/peterryszkiewicz/Repos/sus-repo-finder
export DATABASE_URL="sqlite:./data/sus-repo-finder.db"
export DASHBOARD_PORT=3002
exec ./target/debug/sus-dashboard
