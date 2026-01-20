#!/bin/bash
# Test script for graceful shutdown feature #36

set -e

PORT=3016
CRAWLER_PID=""
LOG_FILE="./data/shutdown_test_output.log"

echo "=== Testing Graceful Shutdown (Feature #36) ==="

# Clean up any existing process on the test port
cleanup() {
    if [ -n "$CRAWLER_PID" ]; then
        echo "Cleaning up crawler PID $CRAWLER_PID"
        kill -9 "$CRAWLER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Step 1: Create a test crawler run in the database to have something to checkpoint
echo "Step 1: Setting up test crawler run..."
node -e "
const Database = require('better-sqlite3');
const db = new Database('./data/sus-repo-finder.db');
const runId = 'graceful-shutdown-test-' + Date.now();
db.exec(\`
    INSERT OR REPLACE INTO crawler_state (run_id, status, started_at, crates_processed, crates_total, current_crate, queue_position, errors_count, findings_count)
    VALUES ('\${runId}', 'running', datetime('now'), 5, 50, 'test-crate', 4, 0, 10)
\`);
console.log('Created test run:', runId);
const row = db.prepare('SELECT * FROM crawler_state WHERE run_id = ?').get(runId);
console.log('Verified state:', JSON.stringify(row, null, 2));
db.close();
"

# Step 2: Start the crawler in the background
echo ""
echo "Step 2: Starting crawler on port $PORT..."
DATABASE_URL="sqlite:./data/sus-repo-finder.db" CRAWLER_PORT=$PORT ./target/debug/sus-crawler > "$LOG_FILE" 2>&1 &
CRAWLER_PID=$!
echo "Crawler started with PID $CRAWLER_PID"

# Wait for server to be ready
sleep 2

# Check if it started successfully
if ! kill -0 $CRAWLER_PID 2>/dev/null; then
    echo "ERROR: Crawler failed to start"
    cat "$LOG_FILE"
    exit 1
fi

echo "Crawler is running, checking status..."
curl -s "http://localhost:$PORT/api/crawler/status" | head -c 200
echo ""

# Step 3: Send SIGINT (Ctrl-C equivalent)
echo ""
echo "Step 3: Sending SIGINT to PID $CRAWLER_PID..."
kill -INT $CRAWLER_PID

# Wait for graceful shutdown
sleep 3

# Step 4: Check if process exited cleanly
if kill -0 $CRAWLER_PID 2>/dev/null; then
    echo "WARNING: Process still running after SIGINT"
else
    echo "✅ Process exited after SIGINT"
    CRAWLER_PID=""  # Clear so cleanup doesn't try to kill again
fi

# Step 5: Check log output for shutdown messages
echo ""
echo "Step 4: Checking log output for shutdown messages..."
echo "--- Log output ---"
cat "$LOG_FILE"
echo "--- End log output ---"

# Step 5: Verify state was checkpointed (should be paused)
echo ""
echo "Step 5: Verifying crawler state was checkpointed..."
node -e "
const Database = require('better-sqlite3');
const db = new Database('./data/sus-repo-finder.db');
const rows = db.prepare('SELECT run_id, status FROM crawler_state ORDER BY started_at DESC LIMIT 3').all();
console.log('Recent crawler states:');
rows.forEach(r => console.log('  ', r.run_id, '->', r.status));

// Check if our test run was paused
const testRuns = rows.filter(r => r.run_id.startsWith('graceful-shutdown-test-'));
if (testRuns.length > 0) {
    const state = testRuns[0].status;
    if (state === 'paused') {
        console.log('✅ Test run was correctly paused during shutdown');
    } else {
        console.log('⚠️ Test run status is:', state, '(expected: paused)');
    }
}
db.close();
"

echo ""
echo "=== Test Complete ==="
