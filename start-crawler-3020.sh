#!/usr/bin/env bash
DATABASE_URL="sqlite:./data/sus-repo-finder.db" CRAWLER_PORT=3020 ./target/debug/sus-crawler
