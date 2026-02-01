// Verify no new crates started after pause
const Database = require('better-sqlite3');
const db = new Database('./data/sus-repo-finder.db');

// Check queue state
const pendingCount = db.prepare("SELECT COUNT(*) as count FROM crawler_queue WHERE status = 'pending'").get();
const inProgressCount = db.prepare("SELECT COUNT(*) as count FROM crawler_queue WHERE status = 'in_progress'").get();
const completedCount = db.prepare("SELECT COUNT(*) as count FROM crawler_queue WHERE status = 'completed'").get();

console.log('Queue State:');
console.log('  Pending:', pendingCount.count);
console.log('  In Progress:', inProgressCount.count);
console.log('  Completed:', completedCount.count);

// The in-progress item should still be the same (test-crate-0025)
const inProgress = db.prepare("SELECT * FROM crawler_queue WHERE status = 'in_progress'").get();
if (inProgress) {
  console.log('\nIn-progress item:', inProgress.crate_name, inProgress.version);
}

// Verify crawler state is still paused
const crawlerState = db.prepare('SELECT * FROM crawler_state ORDER BY started_at DESC, id DESC LIMIT 1').get();
console.log('\nCrawler State:');
console.log('  Status:', crawlerState.status);

if (crawlerState.status === 'paused' && pendingCount.count === 83) {
  console.log('\n✅ VERIFICATION PASSED: Crawler is paused and no new crates started');
} else {
  console.log('\n❌ VERIFICATION FAILED');
}

db.close();
