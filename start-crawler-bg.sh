#!/bin/bash
cd /Users/peterryszkiewicz/Repos/sus-repo-finder
DATABASE_URL="sqlite:./data/sus-repo-finder.db" ./target/debug/sus-crawler &
echo $!
