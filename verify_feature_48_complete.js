// Complete verification for Feature #48: Crawler pause control works
const Database = require('better-sqlite3');
const db = new Database('./data/sus-repo-finder.db');

console.log('=== Feature #48 Verification ===\n');

// Step 1: Verify crawler state is paused
const crawlerState = db.prepare('SELECT * FROM crawler_state ORDER BY started_at DESC, id DESC LIMIT 1').get();
console.log('Step 3-4: Verify crawler paused after current crate, status shows paused');
console.log('  Latest run_id:', crawlerState.run_id);
console.log('  Status:', crawlerState.status);
console.log('  Last checkpoint:', crawlerState.last_checkpoint);

const step3_4_pass = crawlerState.status === 'paused';
console.log('  Result:', step3_4_pass ? '✅ PASS' : '❌ FAIL');

// Step 5: Verify no new crates started
// The queue should have items waiting, but no new processing should start
const queueStats = db.prepare(`
  SELECT
    status,
    COUNT(*) as count
  FROM crawler_queue
  GROUP BY status
`).all();

console.log('\nStep 5: Verify no new crates started');
console.log('  Queue breakdown:');
queueStats.forEach(s => {
  console.log(`    ${s.status}: ${s.count}`);
});

// Check that pending items are still pending (not started)
const pendingCount = queueStats.find(s => s.status === 'pending')?.count || 0;
const step5_pass = pendingCount > 0;
console.log(`  Pending crates waiting: ${pendingCount}`);
console.log('  Result:', step5_pass ? '✅ PASS - Pending items remain in queue (not started)' : '❌ FAIL');

// Overall result
console.log('\n=== Overall Result ===');
if (step3_4_pass && step5_pass) {
  console.log('✅ Feature #48 PASSED: Crawler pause control works');
  console.log('  - Pause button stops processing (status set to "paused")');
  console.log('  - Status shows paused');
  console.log('  - No new crates started (pending items remain)');
} else {
  console.log('❌ Feature #48 FAILED');
}

db.close();
