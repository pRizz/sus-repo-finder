#!/bin/bash
cd /Users/peterryszkiewicz/Repos/sus-repo-finder
export DATABASE_URL="sqlite:./data/sus-repo-finder.db"
export DASHBOARD_PORT=3003
exec ./target/debug/sus-dashboard
