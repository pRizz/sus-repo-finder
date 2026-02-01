// Test setup for Feature #48: Crawler pause control works
const Database = require('better-sqlite3');
const db = new Database('./data/sus-repo-finder.db');

// Create a crawler run in "running" state
const runId = 'test-pause-run-' + Date.now();

// First, insert a crawler state record
db.prepare(`
  INSERT OR REPLACE INTO crawler_state (run_id, status, started_at, last_checkpoint, crates_processed, crates_total, current_crate, queue_position, errors_count, findings_count)
  VALUES (?, 'running', datetime('now'), datetime('now'), 5, 50, 'test-crate-in-progress', 5, 0, 10)
`).run(runId);

console.log('Created crawler run:', runId);

// Verify the state
const state = db.prepare('SELECT * FROM crawler_state WHERE run_id = ?').get(runId);
console.log('Crawler state:', JSON.stringify(state, null, 2));

// Also add some queue items to make it look like a real crawl
for (let i = 1; i <= 10; i++) {
  db.prepare(`
    INSERT OR REPLACE INTO crawler_queue (crate_name, version, priority, status, added_at)
    VALUES (?, '1.0.0', 0, 'pending', datetime('now'))
  `).run(`test-pause-crate-${i}`);
}

// Add one in-progress
db.prepare(`
  UPDATE crawler_queue SET status = 'in_progress', started_at = datetime('now')
  WHERE crate_name = 'test-pause-crate-1'
`).run();

console.log('Added 10 queue items (1 in-progress, 9 pending)');

// Check queue
const queueCount = db.prepare('SELECT COUNT(*) as count FROM crawler_queue WHERE status = ?').get('pending');
console.log('Pending queue items:', queueCount.count);

const inProgress = db.prepare('SELECT * FROM crawler_queue WHERE status = ?').get('in_progress');
console.log('In-progress item:', inProgress);

db.close();
console.log('Setup complete. Run ID:', runId);
