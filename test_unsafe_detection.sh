#!/bin/bash
# Test script to verify unsafe block detection works

# Test 1: Basic unsafe block
echo "Test 1: Basic unsafe block"
./target/debug/sus-crawler &
CRAWLER_PID=$!
sleep 2

curl -s -X POST http://localhost:3001/api/crawler/test-detector \
  -H "Content-Type: application/json" \
  -d '{"source": "fn main() { unsafe { let x = 5; } }"}' | jq .

kill $CRAWLER_PID 2>/dev/null
