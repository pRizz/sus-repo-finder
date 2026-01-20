const Database = require('better-sqlite3');
const db = new Database('/Users/peterryszkiewicz/Repos/sus-repo-finder/data/sus-repo-finder.db');

// First, let's check current queue status
const totalCount = db.prepare('SELECT COUNT(*) as count FROM crawler_queue').get();
const pendingCount = db.prepare("SELECT COUNT(*) as count FROM crawler_queue WHERE status = 'pending'").get();
const completedCount = db.prepare("SELECT COUNT(*) as count FROM crawler_queue WHERE status = 'completed'").get();
const inProgressCount = db.prepare("SELECT COUNT(*) as count FROM crawler_queue WHERE status = 'in_progress'").get();

console.log('Current queue status:');
console.log(`  Total: ${totalCount.count}`);
console.log(`  Pending: ${pendingCount.count}`);
console.log(`  Completed: ${completedCount.count}`);
console.log(`  In Progress: ${inProgressCount.count}`);

// Clear old queue items and create a clean test scenario
console.log('\nClearing existing queue...');
db.prepare('DELETE FROM crawler_queue').run();

// Add 100 queue items (simulating queued crates)
console.log('Adding 100 queue items...');
const insertQueue = db.prepare(`
  INSERT INTO crawler_queue (crate_name, version, priority, status, added_at)
  VALUES (?, ?, ?, ?, datetime('now'))
`);

for (let i = 0; i < 100; i++) {
  const crateName = `test-crate-${i.toString().padStart(4, '0')}`;
  const version = '1.0.0';
  const priority = Math.floor(Math.random() * 100);
  // First 25 are completed, 1 is in_progress, rest are pending
  let status;
  if (i < 25) {
    status = 'completed';
  } else if (i === 25) {
    status = 'in_progress';
  } else {
    status = 'pending';
  }
  insertQueue.run(crateName, version, priority, status);
}

// Update the in_progress item to have started_at timestamp
db.prepare("UPDATE crawler_queue SET started_at = datetime('now') WHERE status = 'in_progress'").run();

// Update completed items to have completed_at timestamp
db.prepare("UPDATE crawler_queue SET completed_at = datetime('now') WHERE status = 'completed'").run();

// Verify the setup
const newTotalCount = db.prepare('SELECT COUNT(*) as count FROM crawler_queue').get();
const newPendingCount = db.prepare("SELECT COUNT(*) as count FROM crawler_queue WHERE status = 'pending'").get();
const newCompletedCount = db.prepare("SELECT COUNT(*) as count FROM crawler_queue WHERE status = 'completed'").get();
const newInProgressCount = db.prepare("SELECT COUNT(*) as count FROM crawler_queue WHERE status = 'in_progress'").get();

console.log('\nNew queue status:');
console.log(`  Total: ${newTotalCount.count}`);
console.log(`  Pending: ${newPendingCount.count}`);
console.log(`  Completed: ${newCompletedCount.count}`);
console.log(`  In Progress: ${newInProgressCount.count}`);

// Calculate expected progress
const expectedProgress = (newCompletedCount.count / newTotalCount.count * 100).toFixed(1);
console.log(`\nExpected progress: ${expectedProgress}%`);

// Show the in-progress item
const inProgressItem = db.prepare("SELECT crate_name, version FROM crawler_queue WHERE status = 'in_progress' LIMIT 1").get();
if (inProgressItem) {
  console.log(`\nCurrently processing: ${inProgressItem.crate_name} v${inProgressItem.version}`);
}

db.close();
console.log('\nTest data setup complete!');
