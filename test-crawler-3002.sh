#!/bin/bash
cd /Users/peterryszkiewicz/Repos/sus-repo-finder
DATABASE_URL="sqlite:./data/sus-repo-finder.db" CRAWLER_PORT=3003 ./target/debug/sus-crawler &
echo $!
