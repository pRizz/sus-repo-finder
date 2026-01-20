// Verify Feature #36: Graceful shutdown on SIGINT
// This script verifies that the graceful shutdown feature works correctly

const Database = require('better-sqlite3');
const { spawn } = require('child_process');
const http = require('http');

const db = new Database('./data/sus-repo-finder.db');

console.log('=== Feature #36 Verification: Graceful shutdown on SIGINT ===\n');

// Step 1: Create a test crawler run in "running" state
const runId = `feature-36-test-${Date.now()}`;
console.log('Step 1: Creating test crawler run in "running" state...');
db.exec(`
    INSERT OR REPLACE INTO crawler_state (run_id, status, started_at, crates_processed, crates_total, current_crate, queue_position, errors_count, findings_count)
    VALUES ('${runId}', 'running', datetime('now'), 10, 100, 'test-crate-being-processed', 9, 0, 5)
`);
console.log(`  Created run: ${runId}`);

// Verify the state was created
const initialState = db.prepare('SELECT * FROM crawler_state WHERE run_id = ?').get(runId);
console.log(`  Initial status: ${initialState.status}`);
console.log(`  Crates processed: ${initialState.crates_processed}/${initialState.crates_total}`);
console.log(`  Current crate: ${initialState.current_crate}`);

// Step 2: Start the crawler
console.log('\nStep 2: Starting crawler on port 3017...');
const PORT = 3017;
const env = {
    ...process.env,
    DATABASE_URL: 'sqlite:./data/sus-repo-finder.db',
    CRAWLER_PORT: PORT.toString()
};

const crawler = spawn('./target/debug/sus-crawler', [], {
    env,
    stdio: ['pipe', 'pipe', 'pipe']
});

let stdout = '';
let stderr = '';
crawler.stdout.on('data', (data) => { stdout += data.toString(); });
crawler.stderr.on('data', (data) => { stderr += data.toString(); });

// Wait for server to start
setTimeout(() => {
    console.log('  Crawler process started, PID:', crawler.pid);

    // Step 3: Verify server is responding
    console.log('\nStep 3: Verifying server is responding...');
    http.get(`http://localhost:${PORT}/api/crawler/status`, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
            console.log('  Server response:', data.substring(0, 100));

            // Step 4: Send SIGINT
            console.log('\nStep 4: Sending SIGINT (simulating Ctrl-C)...');
            crawler.kill('SIGINT');

            // Step 5: Wait and verify
            setTimeout(() => {
                console.log('\nStep 5: Verifying graceful shutdown...');

                // Check if process exited
                if (crawler.killed) {
                    console.log('  ✅ Process received signal and is shutting down');
                }

                // Check log output
                const allOutput = stdout + stderr;
                const checks = {
                    'Received SIGINT': allOutput.includes('Received SIGINT'),
                    'Checkpointing crawler state': allOutput.includes('Checkpointing crawler state'),
                    'Pausing active crawler run': allOutput.includes('Pausing active crawler run'),
                    'paused successfully': allOutput.includes('paused successfully'),
                    'Graceful shutdown complete': allOutput.includes('Graceful shutdown complete'),
                    'Server has shut down cleanly': allOutput.includes('Server has shut down cleanly')
                };

                console.log('\n  Log message verification:');
                let allPassed = true;
                for (const [message, found] of Object.entries(checks)) {
                    const status = found ? '✅' : '❌';
                    console.log(`    ${status} "${message}": ${found}`);
                    if (!found) allPassed = false;
                }

                // Step 6: Verify database state
                console.log('\nStep 6: Verifying database state was checkpointed...');
                const finalState = db.prepare('SELECT * FROM crawler_state WHERE run_id = ?').get(runId);
                if (finalState) {
                    console.log(`  Run ID: ${finalState.run_id}`);
                    console.log(`  Status: ${finalState.status} (expected: paused)`);
                    console.log(`  Status correct: ${finalState.status === 'paused' ? '✅' : '❌'}`);

                    if (finalState.status === 'paused' && allPassed) {
                        console.log('\n=== FEATURE #36 VERIFICATION: PASSED ===');
                    } else {
                        console.log('\n=== FEATURE #36 VERIFICATION: FAILED ===');
                    }
                } else {
                    console.log('  ❌ Could not find crawler state in database');
                    console.log('\n=== FEATURE #36 VERIFICATION: FAILED ===');
                }

                db.close();
                process.exit(0);
            }, 3000);
        });
    }).on('error', (err) => {
        console.log('  ❌ Server not responding:', err.message);
        crawler.kill('SIGKILL');
        db.close();
        process.exit(1);
    });
}, 2000);
