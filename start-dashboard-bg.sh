#!/bin/bash
cd /Users/peterryszkiewicz/Repos/sus-repo-finder
DATABASE_URL="sqlite:./data/sus-repo-finder.db" DASHBOARD_PORT=3002 ./target/debug/sus-dashboard &
echo $!
