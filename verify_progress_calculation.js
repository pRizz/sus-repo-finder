const Database = require('better-sqlite3');
const db = new Database('/Users/peterryszkiewicz/Repos/sus-repo-finder/data/sus-repo-finder.db');

// Verify the queries that our Rust code uses
console.log('Verifying progress calculation queries...\n');

// Total queue count (matches get_total_queue_count)
const totalCount = db.prepare('SELECT COUNT(*) as count FROM crawler_queue').get();
console.log(`Total queue count: ${totalCount.count}`);

// Completed queue count (matches get_completed_queue_count)
const completedCount = db.prepare("SELECT COUNT(*) as count FROM crawler_queue WHERE status = 'completed'").get();
console.log(`Completed queue count: ${completedCount.count}`);

// In-progress queue count (matches get_in_progress_queue_count)
const inProgressCount = db.prepare("SELECT COUNT(*) as count FROM crawler_queue WHERE status = 'in_progress'").get();
console.log(`In-progress queue count: ${inProgressCount.count}`);

// Pending queue count (matches get_pending_queue_count)
const pendingCount = db.prepare("SELECT COUNT(*) as count FROM crawler_queue WHERE status = 'pending'").get();
console.log(`Pending queue count: ${pendingCount.count}`);

// Get in-progress item (matches get_in_progress_queue_item)
const inProgressItem = db.prepare(`
  SELECT id, crate_name, version, priority, status, added_at, started_at, completed_at
  FROM crawler_queue
  WHERE status = 'in_progress'
  ORDER BY started_at ASC
  LIMIT 1
`).get();

if (inProgressItem) {
  console.log(`\nCurrently processing: ${inProgressItem.crate_name} v${inProgressItem.version}`);
} else {
  console.log('\nNo crate currently being processed');
}

// Calculate progress percentage (matches API handler logic)
let progressPercent = 0.0;
if (totalCount.count > 0) {
  progressPercent = (completedCount.count / totalCount.count) * 100.0;
}

console.log(`\n=== Progress Calculation ===`);
console.log(`Completed: ${completedCount.count} / Total: ${totalCount.count}`);
console.log(`Progress: ${progressPercent.toFixed(1)}%`);

// What should be displayed
console.log(`\n=== Expected UI Display ===`);
if (inProgressItem) {
  console.log(`Status: Running`);
  console.log(`Currently processing: ${inProgressItem.crate_name} v${inProgressItem.version}`);
} else if (pendingCount.count > 0) {
  console.log(`Status: Paused`);
} else {
  console.log(`Status: Idle`);
}

if (progressPercent > 0) {
  console.log(`Progress bar: ${progressPercent.toFixed(1)}% complete`);
  console.log(`(Progress bar should be visible with width style of ${progressPercent.toFixed(1)}%)`);
} else {
  console.log(`Progress bar: Hidden (no completed items)`);
}

db.close();
console.log('\nVerification complete!');
