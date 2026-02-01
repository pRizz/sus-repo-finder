// Verify crawler state was updated to paused
const Database = require('better-sqlite3');
const db = new Database('./data/sus-repo-finder.db');

// Get the latest crawler state
const state = db.prepare('SELECT * FROM crawler_state ORDER BY started_at DESC, id DESC LIMIT 1').get();
console.log('Latest crawler state:');
console.log('  run_id:', state.run_id);
console.log('  status:', state.status);
console.log('  last_checkpoint:', state.last_checkpoint);

// Check if status is paused
if (state.status === 'paused') {
  console.log('\n✅ SUCCESS: Crawler state is now "paused"');
} else {
  console.log('\n❌ FAIL: Expected status "paused", got:', state.status);
}

db.close();
